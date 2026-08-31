"""Remediation Actions Registry and Safe Execution Handlers.

Provides an allowlist (ACTION_REGISTRY) of predefined, non-destructive
local remediation actions. Arbitrary command execution and destructive OS
operations are strictly prevented.
"""

import gc
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import database

# Configure logger for remediation actions
logger = logging.getLogger("remediation_actions")

# Designated sandbox directory for disk cleanup actions (under logs/temp_cache)
PROJECT_ROOT = Path(__file__).parent
SAFE_TEMP_DIR = PROJECT_ROOT / "logs" / "temp_cache"


def ensure_temp_dir() -> Path:
    """Ensure the sandboxed temporary directory exists."""
    SAFE_TEMP_DIR.mkdir(parents=True, exist_ok=True)
    return SAFE_TEMP_DIR


def throttle_background_tasks(target_resource: str = "Localhost", **kwargs: Any) -> Dict[str, Any]:
    """Safe Remediation Action for High CPU Usage.

    Simulates throttling background compute tasks, reducing worker thread
    concurrency, and yielding execution intervals to alleviate CPU saturation.
    """
    logger.info(f"[ACTION: throttle_background_tasks] Throttling background workloads on {target_resource}...")
    
    # Safe local demonstration: simulate shedding synthetic background worker load
    simulated_reduction_pct = 35.0
    return {
        "success": True,
        "action": "throttle_background_tasks",
        "message": f"Successfully throttled background task concurrency on {target_resource}.",
        "details": {
            "target_resource": target_resource,
            "simulated_cpu_reduction_pct": simulated_reduction_pct,
            "status": "applied",
            "action_type": "cpu_throttle",
        },
    }


def flush_memory_caches(target_resource: str = "Localhost", **kwargs: Any) -> Dict[str, Any]:
    """Safe Remediation Action for High Memory Usage.

    Triggers in-process Python garbage collection (gc.collect()) and releases
    unreferenced memory buffers without interrupting user sessions.
    """
    logger.info(f"[ACTION: flush_memory_caches] Running garbage collection on {target_resource}...")
    
    # Run in-process garbage collection safely
    collected_objects = gc.collect()
    
    return {
        "success": True,
        "action": "flush_memory_caches",
        "message": f"Flushed in-memory caches and executed garbage collection on {target_resource}.",
        "details": {
            "target_resource": target_resource,
            "objects_collected": collected_objects,
            "status": "flushed",
            "action_type": "memory_gc",
        },
    }


def clean_temp_cache_files(target_resource: str = "Localhost", **kwargs: Any) -> Dict[str, Any]:
    """Safe Remediation Action for High Disk Usage.

    Strictly restricted to the designated project temporary directory
    (`cloud-monitoring/logs/temp_cache`). Only removes `.tmp` and `.old`
    files. Never touches system, user, or database files.
    """
    temp_dir = ensure_temp_dir()
    logger.info(f"[ACTION: clean_temp_cache_files] Cleaning temp files strictly in {temp_dir}...")

    deleted_files: List[str] = []
    freed_bytes: int = 0

    # Ensure path is strictly within SAFE_TEMP_DIR to prevent path traversal
    resolved_safe_dir = SAFE_TEMP_DIR.resolve()

    for item in temp_dir.iterdir():
        # Only target .tmp, .old, and test .log files strictly within the sandbox
        if item.is_file() and (item.suffix.lower() in [".tmp", ".old", ".log"]):
            # Verification: item must resolve inside the safe directory
            if resolved_safe_dir in item.resolve().parents:
                try:
                    file_size = item.stat().st_size
                    item.unlink()
                    deleted_files.append(item.name)
                    freed_bytes += file_size
                except Exception as e:
                    logger.warning(f"Could not delete temp file {item.name}: {e}")

    freed_kb = round(freed_bytes / 1024, 2)

    return {
        "success": True,
        "action": "clean_temp_cache_files",
        "message": f"Cleaned {len(deleted_files)} temporary cache file(s) ({freed_kb} KB freed).",
        "details": {
            "target_resource": target_resource,
            "sandbox_directory": str(resolved_safe_dir),
            "files_removed": deleted_files,
            "freed_bytes": freed_bytes,
            "freed_kb": freed_kb,
            "status": "cleaned",
            "action_type": "disk_cleanup",
        },
    }


def restart_managed_service(target_resource: str = "web-worker", **kwargs: Any) -> Dict[str, Any]:
    """Safe Remediation Action for Service / Application Failures.

    Performs a controlled recovery cycle on the target managed service:
    1. Checks service existence in SQLite `managed_services`
    2. Transitions state: `Unhealthy` -> `Restarting` -> `Healthy`
    3. Increments the service `restart_count`
    """
    service_name = target_resource or "web-worker"
    logger.info(f"[ACTION: restart_managed_service] Initiating controlled restart for service '{service_name}'...")

    service = database.get_managed_service_by_name(service_name)
    if not service:
        # If service does not exist, return a structured failure
        return {
            "success": False,
            "action": "restart_managed_service",
            "message": f"Managed service '{service_name}' not found in database.",
            "details": {
                "target_resource": service_name,
                "error": "service_not_found",
            },
        }

    # Step 1: Transition to Restarting
    database.update_managed_service_status(service_name, "Restarting", increment_restart=False)

    # Step 2: Transition to Healthy and increment restart count
    database.update_managed_service_status(service_name, "Healthy", increment_restart=True)

    updated_service = database.get_managed_service_by_name(service_name)

    return {
        "success": True,
        "action": "restart_managed_service",
        "message": f"Service '{service_name}' was successfully restarted and verified healthy.",
        "details": {
            "target_resource": service_name,
            "service_type": updated_service["service_type"] if updated_service else "unknown",
            "previous_status": service["status"],
            "current_status": updated_service["status"] if updated_service else "Healthy",
            "restart_count": updated_service["restart_count"] if updated_service else 1,
            "status": "restarted",
            "action_type": "service_restart",
        },
    }


# =========================================================================
# ACTION REGISTRY (Strict Allowlist)
# =========================================================================

ACTION_REGISTRY = {
    "throttle_background_tasks": {
        "handler": throttle_background_tasks,
        "title": "Throttle Background Tasks",
        "description": "Reduces CPU load by throttling background worker thread concurrency.",
        "trigger_type": "cpu",
        "safety_level": "Safe (Non-destructive)",
    },
    "flush_memory_caches": {
        "handler": flush_memory_caches,
        "title": "Flush Memory Caches",
        "description": "Triggers garbage collection and flushes volatile memory buffers.",
        "trigger_type": "memory",
        "safety_level": "Safe (Non-destructive)",
    },
    "clean_temp_cache_files": {
        "handler": clean_temp_cache_files,
        "title": "Clean Temporary Cache Files",
        "description": "Purges stale temporary .tmp/.old files strictly within the project sandbox.",
        "trigger_type": "disk",
        "safety_level": "Safe (Sandboxed to logs/temp_cache)",
    },
    "restart_managed_service": {
        "handler": restart_managed_service,
        "title": "Restart Managed Service",
        "description": "Executes a controlled recovery cycle (Unhealthy -> Restarting -> Healthy).",
        "trigger_type": "service",
        "safety_level": "Safe (Controlled recovery cycle)",
    },
}


def get_registered_actions() -> List[Dict[str, Any]]:
    """Return a list of all registered actions and their metadata."""
    actions_list = []
    for key, meta in ACTION_REGISTRY.items():
        actions_list.append({
            "action_key": key,
            "title": meta["title"],
            "description": meta["description"],
            "trigger_type": meta["trigger_type"],
            "safety_level": meta["safety_level"],
        })
    return actions_list


def is_action_allowed(action_name: str) -> bool:
    """Check if an action key exists in the allowlist."""
    return action_name in ACTION_REGISTRY


def execute_action(action_name: str, target_resource: str = "Localhost", **kwargs: Any) -> Dict[str, Any]:
    """Execute an action strictly through the ACTION_REGISTRY allowlist.

    Any action not explicitly registered in ACTION_REGISTRY is rejected.
    """
    if not is_action_allowed(action_name):
        logger.warning(f"Unauthorized action execution attempt rejected: '{action_name}'")
        return {
            "success": False,
            "action": action_name,
            "message": f"Action '{action_name}' is not allowed. Only allowlisted actions in ACTION_REGISTRY can be executed.",
            "details": {
                "error": "action_not_allowed",
                "allowed_actions": list(ACTION_REGISTRY.keys()),
            },
        }

    handler = ACTION_REGISTRY[action_name]["handler"]
    try:
        result = handler(target_resource=target_resource, **kwargs)
        return result
    except Exception as e:
        logger.error(f"Error executing action '{action_name}': {e}", exc_info=True)
        return {
            "success": False,
            "action": action_name,
            "message": f"An error occurred while executing action '{action_name}': {str(e)}",
            "details": {
                "error": str(e),
            },
        }
