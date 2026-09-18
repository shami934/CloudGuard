"""Database Cleanup and Reset Utility for CloudGuard.

Used for development and demo preparation.
Safely resets test telemetry, simulation alerts, and execution logs while
preserving database schemas, configuration settings, core remediation rules,
and managed service definitions.

Usage:
    python reset_demo_data.py
    python reset_demo_data.py --clean-all-metrics
"""

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import sys

# Ensure repository root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import database
import remediation_actions


def cleanup_demo_data(seed_baseline_metrics: bool = True) -> dict:
    """Safely reset test data in SQLite and return summary report.

    Args:
        seed_baseline_metrics: If True, populates 12 clean baseline metric records
                               so dashboard trend curves render smoothly.

    Returns:
        dict: Summary of records cleaned and preserved across all tables.
    """
    summary = {}

    with database.get_connection() as conn:
        cursor = conn.cursor()

        # 1. Ensure Localhost server exists and is Online
        cursor.execute("SELECT id FROM servers WHERE name = 'Localhost';")
        server_row = cursor.fetchone()
        if server_row:
            server_id = server_row["id"]
            cursor.execute("UPDATE servers SET status = 'Online' WHERE id = ?;", (server_id,))
        else:
            cursor.execute("INSERT INTO servers (name, status) VALUES ('Localhost', 'Online');")
            server_id = cursor.lastrowid
        summary["server_id"] = server_id

        # 2. Reset Managed Services to clean baseline (Healthy, 0 restarts)
        cursor.execute("""
            UPDATE managed_services
            SET status = 'Healthy', restart_count = 0, last_check = CURRENT_TIMESTAMP;
        """)
        # Ensure default services exist
        cursor.execute("SELECT name FROM managed_services;")
        existing_services = {row["name"] for row in cursor.fetchall()}
        default_services = [
            ("web-worker", "background_processor"),
            ("cache-daemon", "in_memory_cache"),
        ]
        for name, stype in default_services:
            if name not in existing_services:
                cursor.execute(
                    "INSERT INTO managed_services (name, service_type, status, restart_count) VALUES (?, ?, 'Healthy', 0);",
                    (name, stype),
                )
        cursor.execute("SELECT COUNT(*) AS cnt FROM managed_services;")
        summary["managed_services_count"] = cursor.fetchone()["cnt"]

        # 3. Preserve Core Remediation Rules & Clean Temporary Test Rules
        cursor.execute("DELETE FROM remediation_rules WHERE name LIKE '%Test%';")
        # Ensure 4 core production rules exist
        core_rules = [
            ("High CPU Auto-Throttle", "cpu", "Critical", "throttle_background_tasks", "Localhost", 300, 3, 1),
            ("High Memory Cache Flush", "memory", "Critical", "flush_memory_caches", "Localhost", 300, 3, 1),
            ("High Disk Space Cleanup", "disk", "Critical", "clean_temp_cache_files", "Localhost", 600, 2, 1),
            ("Service Health Auto-Recovery", "service", "Critical", "restart_managed_service", "web-worker", 180, 3, 1),
        ]
        for name, trig, lvl, act, tgt, cool, retries, en in core_rules:
            cursor.execute("SELECT id FROM remediation_rules WHERE name = ?;", (name,))
            if not cursor.fetchone():
                cursor.execute(
                    """
                    INSERT INTO remediation_rules (name, trigger_type, threshold_level, action_type, target_resource, cooldown_seconds, max_retries, enabled)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (name, trig, lvl, act, tgt, cool, retries, en),
                )
            else:
                cursor.execute(
                    "UPDATE remediation_rules SET enabled = 1, cooldown_seconds = ?, max_retries = ? WHERE name = ?;",
                    (cool, retries, name),
                )
        cursor.execute("SELECT COUNT(*) AS cnt FROM remediation_rules;")
        summary["remediation_rules_count"] = cursor.fetchone()["cnt"]

        # 4. Clean Remediation Logs
        cursor.execute("SELECT COUNT(*) AS cnt FROM remediation_logs;")
        deleted_logs = cursor.fetchone()["cnt"]
        cursor.execute("DELETE FROM remediation_logs;")
        summary["remediation_logs_deleted"] = deleted_logs

        # 5. Clean Alerts & Re-seed Clean Sample Baseline
        cursor.execute("SELECT COUNT(*) AS cnt FROM alerts;")
        deleted_alerts = cursor.fetchone()["cnt"]
        cursor.execute("DELETE FROM alerts;")
        
        sample_alerts = [
            (server_id, "Critical", "CPU Spike Alert", "Localhost CPU usage spiked above 90% threshold for 5 minutes.", 0),
            (server_id, "Warning", "High Memory Consumption", "RAM usage exceeded 80% of total available capacity.", 0),
            (server_id, "Warning", "Storage Space Threshold", "Disk space partition /dev/sda1 reaches 75% capacity.", 1),
            (server_id, "Info", "System Backup Completed", "Scheduled automated database backup finished successfully.", 1),
        ]
        cursor.executemany(
            "INSERT INTO alerts (server_id, level, title, message, resolved) VALUES (?, ?, ?, ?, ?);",
            sample_alerts,
        )
        cursor.execute("SELECT COUNT(*) AS cnt FROM alerts;")
        summary["alerts_deleted"] = deleted_alerts
        summary["alerts_seeded"] = cursor.fetchone()["cnt"]

        # 6. Ensure Settings are preserved with monitoring_interval = 5
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('monitoring_interval', '5');")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_alerts', 'true');")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_remediation', 'true');")
        cursor.execute("SELECT COUNT(*) AS cnt FROM settings;")
        summary["settings_count"] = cursor.fetchone()["cnt"]

        # 7. Clean Metrics Table & Optionally Seed Clean Baseline Points
        cursor.execute("SELECT COUNT(*) AS cnt FROM metrics;")
        deleted_metrics = cursor.fetchone()["cnt"]
        cursor.execute("DELETE FROM metrics;")

        if seed_baseline_metrics:
            now = datetime.now(timezone.utc)
            # Create 12 historical points spaced across the last hour
            baseline_records = []
            for i in range(12, 0, -1):
                ts = (now - timedelta(minutes=i * 5)).strftime("%Y-%m-%d %H:%M:%S")
                # Realistic baseline usage
                cpu = round(28.0 + (i % 4) * 4.2, 1)
                mem = round(64.0 + (i % 3) * 2.1, 1)
                disk = 42.0
                net_in = 10485760 + i * 524288
                net_out = 5242880 + i * 262144
                baseline_records.append((server_id, cpu, mem, disk, net_in, net_out, ts))

            cursor.executemany(
                """
                INSERT INTO metrics (server_id, cpu_usage, memory_usage, storage_usage, network_inbound, network_outbound, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                baseline_records,
            )
            summary["metrics_seeded"] = len(baseline_records)
        else:
            summary["metrics_seeded"] = 0

        summary["metrics_deleted"] = deleted_metrics

        conn.commit()

    # 8. Clean Sandboxed Temp Cache Files (e.g. simulated_cache_log.tmp)
    temp_dir = remediation_actions.SAFE_TEMP_DIR
    removed_temp_files = []
    if temp_dir.exists():
        for file in temp_dir.iterdir():
            if file.is_file() and file.suffix.lower() in [".tmp", ".old"]:
                try:
                    file.unlink()
                    removed_temp_files.append(file.name)
                except Exception:
                    pass
    summary["temp_files_removed"] = removed_temp_files

    return summary


def main():
    parser = argparse.ArgumentParser(description="CloudGuard Database Demo Reset Utility")
    parser.add_argument(
        "--clean-all-metrics",
        action="store_true",
        help="Clear all metrics without seeding initial 12 baseline data points.",
    )
    args = parser.parse_args()

    print("=====================================================")
    print(" CloudGuard Demo Database Reset Utility")
    print("=====================================================")
    print(f"Target Database: {database.DATABASE_PATH}")

    seed_baseline = not args.clean_all_metrics
    summary = cleanup_demo_data(seed_baseline_metrics=seed_baseline)

    print("\n--- Reset Summary ---")
    print(f"• Remediation Logs cleared : {summary['remediation_logs_deleted']} records removed (now 0)")
    print(f"• Test Alerts cleaned      : {summary['alerts_deleted']} removed, {summary['alerts_seeded']} baseline alerts restored")
    print(f"• Metrics records cleaned  : {summary['metrics_deleted']} removed, {summary['metrics_seeded']} baseline points populated")
    print(f"• Managed Services reset   : {summary['managed_services_count']} services set to Healthy (0 restarts)")
    print(f"• Remediation Rules active : {summary['remediation_rules_count']} core policies verified")
    print(f"• Settings preserved       : {summary['settings_count']} settings (monitoring_interval: 5s)")
    print(f"• Sandboxed temp files     : {len(summary['temp_files_removed'])} cleaned")
    print("=====================================================")
    print("Database reset completed successfully. Ready for demonstration!")


if __name__ == "__main__":
    main()
