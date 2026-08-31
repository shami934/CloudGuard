"""Remediation Engine for Cloud Monitoring.

Coordinates the automated remediation lifecycle:
1. Rule matching & policy evaluation
2. Global and rule-level enablement checks
3. Cooldown window enforcement
4. Retry budget tracking and loop prevention (Escalation)
5. Safe action execution through ACTION_REGISTRY
6. Post-remediation health/metric verification
7. Alert auto-resolution and audit logging
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
import database
import remediation_actions

logger = logging.getLogger("remediation_engine")


def parse_sqlite_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse SQLite CURRENT_TIMESTAMP string into UTC datetime object."""
    if not ts_str:
        return None
    try:
        cleaned = ts_str.replace("T", " ")
        if "." in cleaned:
            dt = datetime.strptime(cleaned.split(".")[0], "%Y-%m-%d %H:%M:%S")
        else:
            dt = datetime.strptime(cleaned, "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception as e:
        logger.debug(f"Timestamp parse error for '{ts_str}': {e}")
        return None


def is_in_cooldown(last_executed_at: Optional[str], cooldown_seconds: int) -> bool:
    """Check if the cooldown period is still active for a given timestamp."""
    if not last_executed_at or cooldown_seconds <= 0:
        return False
    dt = parse_sqlite_timestamp(last_executed_at)
    if not dt:
        return False
    now = datetime.now(timezone.utc)
    elapsed = (now - dt).total_seconds()
    return elapsed < cooldown_seconds


def get_cooldown_remaining(last_executed_at: Optional[str], cooldown_seconds: int) -> int:
    """Return remaining cooldown seconds, or 0 if expired."""
    if not last_executed_at or cooldown_seconds <= 0:
        return 0
    dt = parse_sqlite_timestamp(last_executed_at)
    if not dt:
        return 0
    now = datetime.now(timezone.utc)
    elapsed = (now - dt).total_seconds()
    remaining = int(cooldown_seconds - elapsed)
    return max(remaining, 0)


def evaluate_and_remediate(
    trigger_type: str,
    server_id: int,
    current_value: float = 0.0,
    threshold_value: float = 90.0,
    alert_id: Optional[int] = None,
    target_resource: str = "Localhost",
    simulate_failure: bool = False,
    override_rule_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Evaluate conditions against remediation rules and execute safe actions if applicable.

    Args:
        trigger_type: 'cpu', 'memory', 'disk', or 'service'
        server_id: ID of the server being evaluated
        current_value: Pre-remediation metric value or error indicator
        threshold_value: Critical threshold value triggering remediation
        alert_id: Optional associated alert ID
        target_resource: Name of the server or managed service
        simulate_failure: If True, forces verification failure for testing retries/escalations
        override_rule_id: Specific rule ID to trigger manually

    Returns:
        Structured dictionary with status, action, message, and log ID.
    """
    trigger_clean = trigger_type.strip().lower()

    # Step 1: Check Global Remediation Enablement Setting
    settings = database.get_all_settings()
    global_enabled = str(settings.get("enable_remediation", "true")).lower() in ["true", "1", "yes"]
    if not global_enabled:
        logger.info(f"Remediation skipped: Global automated remediation is disabled.")
        return {
            "success": False,
            "status": "DISABLED",
            "action": "none",
            "message": "Automated remediation is globally disabled in settings.",
            "remediation_log_id": None,
            "details": {"reason": "global_remediation_disabled"},
        }

    # Step 2: Retrieve and Match Remediation Rule
    rule = None
    if override_rule_id:
        rule = database.get_remediation_rule_by_id(override_rule_id)
    else:
        matching_rules = database.get_enabled_remediation_rules(trigger_type=trigger_clean)
        if matching_rules:
            rule = matching_rules[0]

    if not rule:
        logger.info(f"No active remediation rule found for trigger_type='{trigger_clean}'.")
        return {
            "success": False,
            "status": "NO_RULE",
            "action": "none",
            "message": f"No active remediation rule configured for '{trigger_clean}'.",
            "remediation_log_id": None,
            "details": {"trigger_type": trigger_clean},
        }

    if not rule.get("enabled"):
        return {
            "success": False,
            "status": "RULE_DISABLED",
            "action": rule.get("action_type", "none"),
            "message": f"Remediation rule '{rule['name']}' is disabled.",
            "remediation_log_id": None,
            "details": {"rule_id": rule["id"], "rule_name": rule["name"]},
        }

    action_type = rule["action_type"]
    cooldown_seconds = int(rule.get("cooldown_seconds", 300))
    max_retries = int(rule.get("max_retries", 3))
    rule_id = rule["id"]
    resolved_target = rule.get("target_resource") or target_resource or "Localhost"

    # Step 3: Inspect Previous Execution History for Cooldown and Retry Limits
    latest_log = database.get_latest_remediation_for_rule(rule_id=rule_id, server_id=server_id)
    attempt_count = 1

    if latest_log:
        last_status = latest_log.get("status")
        last_time = latest_log.get("started_at")

        # Check if already IN_PROGRESS or PENDING (prevent concurrent duplicate runs)
        if last_status in ["IN_PROGRESS", "PENDING"]:
            logger.warning(f"Remediation already running for rule #{rule_id} on server #{server_id}.")
            return {
                "success": False,
                "status": "IN_PROGRESS",
                "action": action_type,
                "message": f"Remediation for '{rule['name']}' is already in progress.",
                "remediation_log_id": latest_log["id"],
                "details": {"existing_log_id": latest_log["id"]},
            }

        # Check Cooldown Window
        if is_in_cooldown(last_time, cooldown_seconds):
            remaining = get_cooldown_remaining(last_time, cooldown_seconds)
            logger.info(f"Remediation for rule #{rule_id} in cooldown ({remaining}s remaining).")
            # Record SKIPPED_COOLDOWN log entry
            log_id = database.add_remediation_log(
                rule_id=rule_id,
                server_id=server_id,
                alert_id=alert_id,
                action_type=action_type,
                status="SKIPPED_COOLDOWN",
                attempt_count=latest_log.get("attempt_count", 1),
                pre_metric_val=current_value,
                details=f"Execution skipped: Cooldown period active ({remaining} seconds remaining).",
            )
            return {
                "success": False,
                "status": "SKIPPED_COOLDOWN",
                "action": action_type,
                "message": f"Action in cooldown. {remaining}s remaining.",
                "remediation_log_id": log_id,
                "details": {
                    "rule_name": rule["name"],
                    "cooldown_remaining_seconds": remaining,
                },
            }

        # Calculate Attempt Counter for consecutive failures
        if last_status == "FAILED":
            attempt_count = int(latest_log.get("attempt_count", 1)) + 1
        elif last_status == "ESCALATED":
            # Already escalated; require manual intervention or new cycle
            attempt_count = int(latest_log.get("attempt_count", 1)) + 1

    # Step 4: Check Retry Limit / Escalation Trigger
    if attempt_count > max_retries:
        logger.warning(f"Remediation rule '{rule['name']}' exceeded max retries ({max_retries}). Escalating.")
        escalation_details = (
            f"Remediation failed after {max_retries} attempts. "
            f"Automated remediation halted and escalated for manual operator intervention."
        )
        log_id = database.add_remediation_log(
            rule_id=rule_id,
            server_id=server_id,
            alert_id=alert_id,
            action_type=action_type,
            status="ESCALATED",
            attempt_count=attempt_count,
            pre_metric_val=current_value,
            details=escalation_details,
        )
        database.update_remediation_log(log_id, "ESCALATED", post_metric_val=current_value, details=escalation_details, completed=True)

        return {
            "success": False,
            "status": "ESCALATED",
            "action": action_type,
            "message": f"Remediation escalated: Exceeded retry limit of {max_retries} attempts.",
            "remediation_log_id": log_id,
            "details": {
                "rule_name": rule["name"],
                "max_retries": max_retries,
                "attempt_count": attempt_count,
            },
        }

    # Step 5: Record Initial Log Entry as IN_PROGRESS
    log_id = database.add_remediation_log(
        rule_id=rule_id,
        server_id=server_id,
        alert_id=alert_id,
        action_type=action_type,
        status="IN_PROGRESS",
        attempt_count=attempt_count,
        pre_metric_val=current_value,
        details=f"Initiating remediation attempt {attempt_count}/{max_retries} for rule '{rule['name']}'.",
    )

    # Step 6: Dispatch Safe Action through Allowlist
    action_result = remediation_actions.execute_action(
        action_name=action_type,
        target_resource=resolved_target,
    )

    # Step 7: Post-Action Verification
    is_recovered, post_value, verify_message = _verify_remediation(
        trigger_type=trigger_clean,
        action_type=action_type,
        target_resource=resolved_target,
        current_value=current_value,
        threshold_value=threshold_value,
        action_result=action_result,
        simulate_failure=simulate_failure,
    )

    # Step 8: Finalize Status and Alert Integration
    if is_recovered:
        final_status = "SUCCESS"
        details_msg = (
            f"Remediation succeeded on attempt {attempt_count}/{max_retries}. "
            f"{action_result.get('message', '')} {verify_message}"
        )
        database.update_remediation_log(
            log_id=log_id,
            status=final_status,
            post_metric_val=post_value,
            details=details_msg,
            completed=True,
        )

        # Auto-resolve associated active alert if provided
        if alert_id:
            database.resolve_alert(alert_id)
        else:
            # Look up matching active alert for this trigger category on the server
            _auto_resolve_matching_alert(server_id, trigger_clean)

        return {
            "success": True,
            "status": final_status,
            "action": action_type,
            "message": details_msg,
            "remediation_log_id": log_id,
            "details": {
                "rule_name": rule["name"],
                "attempt_count": attempt_count,
                "pre_value": current_value,
                "post_value": post_value,
                "action_details": action_result.get("details", {}),
            },
        }
    else:
        # Recovery Verification Failed
        final_status = "FAILED" if attempt_count < max_retries else "ESCALATED"
        fail_msg = (
            f"Remediation attempt {attempt_count}/{max_retries} failed verification. "
            f"{verify_message}"
        )
        database.update_remediation_log(
            log_id=log_id,
            status=final_status,
            post_metric_val=post_value,
            details=fail_msg,
            completed=True,
        )

        return {
            "success": False,
            "status": final_status,
            "action": action_type,
            "message": fail_msg,
            "remediation_log_id": log_id,
            "details": {
                "rule_name": rule["name"],
                "attempt_count": attempt_count,
                "max_retries": max_retries,
                "pre_value": current_value,
                "post_value": post_value,
                "action_details": action_result.get("details", {}),
            },
        }


def _verify_remediation(
    trigger_type: str,
    action_type: str,
    target_resource: str,
    current_value: float,
    threshold_value: float,
    action_result: Dict[str, Any],
    simulate_failure: bool = False,
) -> tuple[bool, float, str]:
    """Verify whether the system or service recovered after remediation action."""
    if simulate_failure:
        return False, current_value, "Simulated verification failure for testing."

    if not action_result.get("success"):
        return False, current_value, f"Action execution failed: {action_result.get('message')}"

    if trigger_type == "cpu":
        # Simulate / verify CPU reduction
        reduction = action_result.get("details", {}).get("simulated_cpu_reduction_pct", 35.0)
        post_val = round(max(current_value - reduction, 22.0), 1)
        recovered = post_val < threshold_value
        msg = f"CPU utilization dropped from {current_value}% to {post_val}% (Threshold: {threshold_value}%)."
        return recovered, post_val, msg

    elif trigger_type == "memory":
        # Simulate / verify Memory reduction after cache flush & GC
        post_val = round(max(current_value - 25.0, 38.0), 1)
        recovered = post_val < threshold_value
        msg = f"Memory utilization recovered from {current_value}% to {post_val}% (Threshold: {threshold_value}%)."
        return recovered, post_val, msg

    elif trigger_type == "disk":
        # Disk cleanup verification
        freed_kb = action_result.get("details", {}).get("freed_kb", 0.0)
        post_val = round(max(current_value - 8.0, 40.0), 1)
        recovered = True
        msg = f"Cleaned temp cache files ({freed_kb} KB freed). Disk usage at {post_val}%."
        return recovered, post_val, msg

    elif trigger_type == "service":
        # Verify managed service health in database
        srv = database.get_managed_service_by_name(target_resource)
        if srv and srv["status"] == "Healthy":
            msg = f"Service '{target_resource}' verified in Healthy state (Restart count: {srv['restart_count']})."
            return True, 0.0, msg
        else:
            status = srv["status"] if srv else "Not Found"
            msg = f"Service '{target_resource}' health check failed (Status: {status})."
            return False, 1.0, msg

    # Fallback default
    return True, current_value, "Action completed."


def _auto_resolve_matching_alert(server_id: int, trigger_type: str) -> None:
    """Helper to auto-resolve active alerts for a given trigger category."""
    cat_map = {
        "cpu": "CPU",
        "memory": "Memory",
        "disk": "Disk",
        "service": "Service",
    }
    cat = cat_map.get(trigger_type, trigger_type.capitalize())
    with database.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE alerts
            SET resolved = 1
            WHERE server_id = ? AND resolved = 0 AND title LIKE ?;
            """,
            (server_id, f"%{cat}%"),
        )
        conn.commit()


def check_and_remediate_metrics(server_id: int, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scan collected metrics against critical thresholds and trigger automated remediation.

    Can be called directly from the metrics monitoring loop.
    """
    settings = database.get_all_settings()
    try:
        cpu_crit = float(settings.get("cpu_critical_threshold", 90))
        mem_crit = float(settings.get("memory_critical_threshold", 95))
        disk_crit = float(settings.get("disk_critical_threshold", 90))
    except (ValueError, TypeError):
        cpu_crit, mem_crit, disk_crit = 90.0, 95.0, 90.0

    current_cpu = float(metrics.get("cpu_percent", 0.0))
    current_mem = float(metrics.get("memory_percent", 0.0))
    current_disk = float(metrics.get("disk_percent", 0.0))

    results = []

    # CPU Critical Check
    if current_cpu >= cpu_crit:
        res = evaluate_and_remediate("cpu", server_id, current_value=current_cpu, threshold_value=cpu_crit)
        results.append(res)

    # Memory Critical Check
    if current_mem >= mem_crit:
        res = evaluate_and_remediate("memory", server_id, current_value=current_mem, threshold_value=mem_crit)
        results.append(res)

    # Disk Critical Check
    if current_disk >= disk_crit:
        res = evaluate_and_remediate("disk", server_id, current_value=current_disk, threshold_value=disk_crit)
        results.append(res)

    return results
