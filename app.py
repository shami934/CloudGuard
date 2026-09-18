"""Main Flask application for CloudGuard: Intelligent Cloud Monitoring & Automated Remediation System.

Routes render HTML pages and serve API endpoints for live metrics and remediation engine.
"""

import os
import time
import logging
from datetime import datetime, timedelta, timezone
from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
import database
import monitor
import remediation_actions
import remediation_engine

# Configure AWS SDK / IMDS defaults for reliable EC2 IAM Role resolution
os.environ.setdefault("AWS_METADATA_SERVICE_TIMEOUT", "10")
os.environ.setdefault("AWS_METADATA_SERVICE_NUM_ATTEMPTS", "5")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "false")

# Prevent HTTP proxy from intercepting link-local EC2 IMDS calls (169.254.169.254)
_existing_no_proxy = os.environ.get("NO_PROXY", os.environ.get("no_proxy", ""))
if "169.254.169.254" not in _existing_no_proxy:
    _merged_no_proxy = f"{_existing_no_proxy},169.254.169.254".strip(",") if _existing_no_proxy else "169.254.169.254"
    os.environ["NO_PROXY"] = _merged_no_proxy
    os.environ["no_proxy"] = _merged_no_proxy

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
except ImportError:
    boto3 = None
    Config = None
    BotoCoreError = ClientError = NoCredentialsError = Exception

logger = logging.getLogger("cloudguard_aws")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cloud-monitoring-secret-key")

# AWS CloudWatch EC2 Configuration
AWS_REGION = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "ap-southeast-2"))
AWS_EC2_INSTANCE_ID = os.environ.get("AWS_EC2_INSTANCE_ID", "i-076ce4fc220f4f297")

os.environ.setdefault("AWS_DEFAULT_REGION", AWS_REGION)
os.environ.setdefault("AWS_REGION", AWS_REGION)

_cw_client = None
_aws_cache = {
    "cpu_percent": None,
    "last_fetched": 0,
    "last_datapoint_time": None,
    "status": "initializing",
    "error": None,
    "instance_id": AWS_EC2_INSTANCE_ID,
    "region": AWS_REGION,
}


def _get_cloudwatch_client():
    """Create or return a CloudWatch client using the EC2 IAM role / IMDS provider chain.
    
    Uses an explicit boto3.Session to ensure proper credential loading from the EC2
    Instance Metadata Service without poisoning the client on transient latency.
    """
    global _cw_client
    if _cw_client is not None:
        return _cw_client

    if boto3 is None:
        return None

    try:
        session = boto3.Session(region_name=AWS_REGION)
        creds = session.get_credentials()

        cfg = Config(
            region_name=AWS_REGION,
            connect_timeout=5,
            read_timeout=10,
            retries={"max_attempts": 3, "mode": "standard"},
        ) if Config else None

        client = session.client("cloudwatch", config=cfg) if cfg else session.client("cloudwatch")
        if creds is not None:
            _cw_client = client
        return client
    except Exception as e:
        logger.warning(f"Failed to initialize AWS CloudWatch client: {e}")
        _cw_client = None
        return None


def get_aws_cloudwatch_cpu(force_refresh=False):
    """Retrieve AWS EC2 CPUUtilization from CloudWatch using the EC2 IAM role.
    
    Uses boto3 default credential chain (EC2 IAM role CloudGuardEC2Role).
    Caches the metric for 60 seconds to respect CloudWatch's 5-minute aggregation
    cadence and avoid unnecessary API requests during rapid 5-second polling.
    On transient errors, retries after 5 seconds to ensure fast recovery upon credential availability.
    Safely handles missing credentials, network delays, and empty datapoints.
    """
    global _cw_client, _aws_cache
    now_ts = time.time()

    # Cache hit check:
    # On success ('available' or 'no_datapoints'), cache for 60 seconds to respect CloudWatch 5m cadence.
    # On error, retry after 5 seconds to guarantee fast recovery once IAM role/IMDS credentials resolve.
    is_cached_success = _aws_cache.get("status") in ("available", "no_datapoints")
    cache_ttl = 60 if is_cached_success else 5
    if not force_refresh and (now_ts - _aws_cache.get("last_fetched", 0)) < cache_ttl and _aws_cache.get("last_fetched", 0) > 0:
        return _aws_cache

    if boto3 is None:
        _aws_cache.update({
            "last_fetched": now_ts,
            "status": "boto3_missing",
            "error": "boto3 is not installed",
            "instance_id": AWS_EC2_INSTANCE_ID,
            "region": AWS_REGION,
        })
        return _aws_cache

    try:
        client = _get_cloudwatch_client()
        if client is None:
            _aws_cache.update({
                "last_fetched": now_ts,
                "status": "error",
                "error": "Unable to locate credentials (EC2 IAM role pending)",
                "instance_id": AWS_EC2_INSTANCE_ID,
                "region": AWS_REGION,
            })
            return _aws_cache

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=120)

        response = client.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": AWS_EC2_INSTANCE_ID}],
            StartTime=start_time,
            EndTime=end_time,
            Period=300,
            Statistics=["Average"],
        )

        # Successful call - safe to cache client if not already cached
        _cw_client = client

        datapoints = response.get("Datapoints", [])
        if datapoints:
            latest = sorted(datapoints, key=lambda x: x["Timestamp"])[-1]
            cpu_val = round(float(latest["Average"]), 1)
            dp_time = latest["Timestamp"].strftime("%H:%M:%S UTC")
            _aws_cache.update({
                "cpu_percent": cpu_val,
                "last_fetched": now_ts,
                "last_datapoint_time": dp_time,
                "status": "available",
                "error": None,
                "instance_id": AWS_EC2_INSTANCE_ID,
                "region": AWS_REGION,
            })
        else:
            _aws_cache.update({
                "cpu_percent": None,
                "last_fetched": now_ts,
                "status": "no_datapoints",
                "error": "No 5-minute CloudWatch datapoints found in the last 120 minutes.",
                "instance_id": AWS_EC2_INSTANCE_ID,
                "region": AWS_REGION,
            })
    except Exception as e:
        logger.warning(f"CloudWatch query notice: {e}")
        _cw_client = None  # Reset client on failure so next cycle retries with a fresh session
        _aws_cache.update({
            "cpu_percent": None,
            "last_fetched": now_ts,
            "status": "error",
            "error": str(e),
            "instance_id": AWS_EC2_INSTANCE_ID,
            "region": AWS_REGION,
        })

    return _aws_cache


# Initialize database tables on app startup
database.init_database()


@app.route("/")
def dashboard():
    """Show the main dashboard."""
    return render_template("dashboard.html", active_page="dashboard")


@app.route("/api/metrics")
def api_metrics():
    """Collect current system metrics, save to SQLite, evaluate threshold alerts, and return JSON."""
    try:
        # Ensure default server exists
        server_id = database.get_or_create_default_server("Localhost")

        # Collect live metrics from monitor.py
        current = monitor.get_system_metrics()

        # Save to SQLite database
        database.add_metric(
            server_id=server_id,
            cpu_usage=current["cpu_percent"],
            memory_usage=current["memory_percent"],
            storage_usage=current["disk_percent"],
            network_inbound=current["bytes_recv"],
            network_outbound=current["bytes_sent"],
        )

        # Evaluate metrics against saved thresholds & update alerts / server status
        server_status = database.evaluate_and_update_alerts(server_id, current)

        # Get saved monitoring interval setting
        settings = database.get_all_settings()
        try:
            interval_sec = int(float(settings.get("monitoring_interval", 5)))
        except (ValueError, TypeError):
            interval_sec = 5

        # Fetch recent history for chart display
        recent_history = database.get_recent_metrics(server_id=server_id, limit=12)

        # Retrieve AWS EC2 CloudWatch CPU metric safely
        aws_info = get_aws_cloudwatch_cpu()
        aws_cpu_val = aws_info.get("cpu_percent")

        return jsonify({
            "status": "success",
            "current": current,
            "history": recent_history,
            "server_status": server_status,
            "interval_seconds": interval_sec,
            "aws_cpu_percent": aws_cpu_val,
            "aws_cloudwatch": aws_info,
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
        }), 500


@app.route("/resources")
def resources():
    """Display monitored cloud resources and servers."""
    server_resources = database.get_all_servers_with_latest_metrics()
    return render_template(
        "resources.html",
        active_page="resources",
        resources=server_resources,
    )


@app.route("/alerts")
def alerts():
    """Display system alerts with filtering capabilities."""
    filter_by = request.args.get("filter", "all").lower()
    alerts_list = database.get_alerts(filter_by=filter_by)
    return render_template(
        "alerts.html",
        active_page="alerts",
        alerts=alerts_list,
        active_filter=filter_by,
    )


@app.route("/remediation")
def remediation_page():
    """Display Automated Remediation Center."""
    rules = database.get_remediation_rules()
    actions = remediation_actions.get_registered_actions()
    logs = database.get_remediation_logs(limit=40)
    services = database.get_managed_services()
    settings_map = database.get_all_settings()

    return render_template(
        "remediation.html",
        active_page="remediation",
        rules=rules,
        actions=actions,
        logs=logs,
        services=services,
        settings=settings_map,
    )


@app.route("/api/remediation/rules")
def api_remediation_rules():
    """Return JSON list of configured remediation rules and allowed actions."""
    try:
        rules = database.get_remediation_rules()
        actions = remediation_actions.get_registered_actions()
        return jsonify({
            "status": "success",
            "rules": rules,
            "actions": actions,
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
        }), 500


@app.route("/api/remediation/logs")
def api_remediation_logs():
    """Return JSON list of recent remediation execution logs."""
    try:
        limit = int(request.args.get("limit", 40))
        status_filter = request.args.get("status")
        logs = database.get_remediation_logs(limit=limit, status=status_filter)
        return jsonify({
            "status": "success",
            "logs": logs,
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
        }), 500


@app.route("/api/remediation/simulate", methods=["POST"])
def api_remediation_simulate():
    """Safe local demonstration endpoint for the 4 core remediation scenarios.
    
    Accepts scenario: 'cpu', 'memory', 'disk', or 'service'.
    Executes through the safe remediation engine and returns structured result.
    """
    try:
        data = request.get_json(silent=True) or request.form.to_dict() or {}
        scenario = str(data.get("scenario", "cpu")).strip().lower()
        simulate_failure = str(data.get("simulate_failure", "false")).lower() in ["true", "1", "yes"]
        target_resource = data.get("target_resource")
        rule_id = data.get("rule_id")

        server_id = database.get_or_create_default_server("Localhost")

        # Configure safe simulation parameters
        if scenario == "cpu":
            target = target_resource or "Localhost"
            current_val = float(data.get("current_value", 94.5))
            threshold_val = 90.0
            # Ensure an active alert exists to demonstrate resolution
            alert_id = database.add_alert(
                server_id,
                "Critical",
                "CPU Spike Alert (Simulation)",
                f"Localhost CPU usage spiked to {current_val}%."
            )
        elif scenario == "memory":
            target = target_resource or "Localhost"
            current_val = float(data.get("current_value", 96.8))
            threshold_val = 95.0
            alert_id = database.add_alert(
                server_id,
                "Critical",
                "High Memory Consumption Alert (Simulation)",
                f"RAM usage exceeded {current_val}%."
            )
        elif scenario == "disk":
            target = target_resource or "Localhost"
            current_val = float(data.get("current_value", 93.2))
            threshold_val = 90.0
            # Create a sample safe temp file to demonstrate cleanup
            temp_dir = remediation_actions.ensure_temp_dir()
            (temp_dir / "simulated_cache_log.tmp").write_text("Simulated disk cache temporary data for cleanup test.")
            alert_id = database.add_alert(
                server_id,
                "Critical",
                "Storage Space Critical Alert (Simulation)",
                f"Disk space partition reached {current_val}% capacity."
            )
        elif scenario == "service":
            target = target_resource or "web-worker"
            current_val = 1.0
            threshold_val = 0.0
            # Set service to Unhealthy before recovery cycle
            database.update_managed_service_status(target, "Unhealthy")
            alert_id = database.add_alert(
                server_id,
                "Critical",
                f"Service {target} Unhealthy (Simulation)",
                f"Managed service '{target}' stopped responding to heartbeat probes."
            )
        else:
            return jsonify({
                "status": "error",
                "message": f"Unknown simulation scenario '{scenario}'. Allowed: 'cpu', 'memory', 'disk', 'service'."
            }), 400

        # Execute safe remediation through engine
        result = remediation_engine.evaluate_and_remediate(
            trigger_type=scenario,
            server_id=server_id,
            current_value=current_val,
            threshold_value=threshold_val,
            alert_id=alert_id,
            target_resource=target,
            simulate_failure=simulate_failure,
            override_rule_id=int(rule_id) if rule_id else None,
        )

        return jsonify(result)
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Remediation simulation error: {str(e)}",
        }), 500


@app.route("/history")
def history():
    """Display historical monitoring metrics and usage trends."""
    timeframe = request.args.get("timeframe", "all").lower()
    metrics_list = database.get_historical_metrics(timeframe=timeframe)
    return render_template(
        "history.html",
        active_page="history",
        metrics=metrics_list,
        active_timeframe=timeframe,
    )


@app.route("/settings", methods=["GET", "POST"])
def settings():
    """View and update cloud monitoring configuration settings."""
    if request.method == "POST":
        # Form values
        form_data = {
            "cpu_warning_threshold": request.form.get("cpu_warning_threshold", "70").strip(),
            "cpu_critical_threshold": request.form.get("cpu_critical_threshold", "90").strip(),
            "memory_warning_threshold": request.form.get("memory_warning_threshold", "80").strip(),
            "memory_critical_threshold": request.form.get("memory_critical_threshold", "95").strip(),
            "disk_warning_threshold": request.form.get("disk_warning_threshold", "75").strip(),
            "disk_critical_threshold": request.form.get("disk_critical_threshold", "90").strip(),
            "monitoring_interval": request.form.get("monitoring_interval", "5").strip(),
            "enable_alerts": "true" if request.form.get("enable_alerts") else "false",
            "enable_remediation": "true" if request.form.get("enable_remediation") else "false",
        }

        # Validation
        errors = []
        parsed = {}

        # Validate numeric ranges for thresholds
        threshold_keys = [
            ("cpu_warning_threshold", "CPU Warning Threshold"),
            ("cpu_critical_threshold", "CPU Critical Threshold"),
            ("memory_warning_threshold", "Memory Warning Threshold"),
            ("memory_critical_threshold", "Memory Critical Threshold"),
            ("disk_warning_threshold", "Disk Warning Threshold"),
            ("disk_critical_threshold", "Disk Critical Threshold"),
        ]

        for key, name in threshold_keys:
            val_str = form_data.get(key, "")
            try:
                val = float(val_str)
                if val < 0 or val > 100:
                    errors.append(f"{name} must be between 0% and 100%.")
                else:
                    parsed[key] = val
            except ValueError:
                errors.append(f"{name} must be a valid number.")

        # Validate monitoring interval
        try:
            interval = float(form_data.get("monitoring_interval", ""))
            if interval <= 0:
                errors.append("Monitoring interval must be a positive number of seconds (greater than 0).")
            else:
                parsed["monitoring_interval"] = interval
        except ValueError:
            errors.append("Monitoring interval must be a valid number.")

        # Validate critical >= warning
        if "cpu_warning_threshold" in parsed and "cpu_critical_threshold" in parsed:
            if parsed["cpu_critical_threshold"] < parsed["cpu_warning_threshold"]:
                errors.append("CPU Critical threshold cannot be lower than CPU Warning threshold.")

        if "memory_warning_threshold" in parsed and "memory_critical_threshold" in parsed:
            if parsed["memory_critical_threshold"] < parsed["memory_warning_threshold"]:
                errors.append("Memory Critical threshold cannot be lower than Memory Warning threshold.")

        if "disk_warning_threshold" in parsed and "disk_critical_threshold" in parsed:
            if parsed["disk_critical_threshold"] < parsed["disk_warning_threshold"]:
                errors.append("Disk Critical threshold cannot be lower than Disk Warning threshold.")

        if errors:
            for err in errors:
                flash(err, "error")
            return render_template(
                "settings.html",
                active_page="settings",
                settings=form_data,
            )

        # Save settings if valid
        database.save_settings(form_data)
        flash("Settings updated successfully!", "success")
        return render_template(
            "settings.html",
            active_page="settings",
            settings=form_data,
        )

    # GET request
    current_settings = database.get_all_settings()
    return render_template(
        "settings.html",
        active_page="settings",
        settings=current_settings,
    )


@app.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
def resolve_alert_route(alert_id):
    """Mark an alert as resolved and redirect back to alerts view."""
    filter_by = request.form.get("filter", "all")
    database.resolve_alert(alert_id)
    flash("Alert marked as resolved.", "success")
    return redirect(url_for("alerts", filter=filter_by))


@app.errorhandler(404)
def page_not_found(e):
    """Render placeholder / 404 page for missing endpoints."""
    return render_template("placeholder.html", active_page="", page_title="Page Not Found"), 404


@app.errorhandler(500)
def server_error(e):
    """Render placeholder / 500 page for internal errors."""
    return render_template("placeholder.html", active_page="", page_title="Internal Server Error"), 500


if __name__ == "__main__":
    app.run(debug=True)

