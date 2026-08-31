"""SQLite database setup and helpers for Cloud Monitoring.

Defines schemas for servers, metrics, and alerts, and provides
functions for database connection, initialization, and data operations.
"""

from contextlib import contextmanager
import sqlite3
from pathlib import Path

# SQLite file lives in the database/ folder
DATABASE_PATH = Path(__file__).parent / "database" / "cloud_monitoring.db"


# Default configuration settings
DEFAULT_SETTINGS = {
    "cpu_warning_threshold": "70",
    "cpu_critical_threshold": "90",
    "memory_warning_threshold": "80",
    "memory_critical_threshold": "95",
    "disk_warning_threshold": "75",
    "disk_critical_threshold": "90",
    "monitoring_interval": "5",
    "enable_alerts": "true",
}


@contextmanager
def get_connection():
    """Open a connection to the SQLite database with row factory, foreign keys, and automatic connection closing."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON;")
    try:
        yield connection
    finally:
        connection.close()


def init_database():
    """Initialize database tables for servers, metrics, alerts, and settings."""
    with get_connection() as conn:
        cursor = conn.cursor()

        # Create settings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)

        # Create servers table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'Online',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Create metrics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                cpu_usage REAL NOT NULL,
                memory_usage REAL NOT NULL,
                storage_usage REAL NOT NULL,
                network_inbound REAL DEFAULT 0.0,
                network_outbound REAL DEFAULT 0.0,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
            );
        """)

        # Create alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER,
                level TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved INTEGER DEFAULT 0,
                FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE SET NULL
            );
        """)

        # Create remediation_rules table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS remediation_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                trigger_type TEXT NOT NULL,
                threshold_level TEXT NOT NULL DEFAULT 'Critical',
                action_type TEXT NOT NULL,
                target_resource TEXT NOT NULL DEFAULT 'Localhost',
                cooldown_seconds INTEGER NOT NULL DEFAULT 300,
                max_retries INTEGER NOT NULL DEFAULT 3,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Create remediation_logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS remediation_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER,
                server_id INTEGER,
                alert_id INTEGER,
                action_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                attempt_count INTEGER DEFAULT 1,
                pre_metric_val REAL,
                post_metric_val REAL,
                details TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (rule_id) REFERENCES remediation_rules(id) ON DELETE SET NULL,
                FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE SET NULL,
                FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL
            );
        """)

        # Create managed_services table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS managed_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                service_type TEXT NOT NULL DEFAULT 'web_worker',
                status TEXT NOT NULL DEFAULT 'Healthy',
                last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                restart_count INTEGER DEFAULT 0
            );
        """)

        # Ensure default server exists
        cursor.execute("SELECT id FROM servers WHERE name = 'Localhost';")
        if not cursor.fetchone():
            cursor.execute("INSERT INTO servers (name, status) VALUES ('Localhost', 'Online');")

        # Seed initial alerts if empty
        cursor.execute("SELECT COUNT(*) AS count FROM alerts;")
        if cursor.fetchone()["count"] == 0:
            cursor.execute("SELECT id FROM servers WHERE name = 'Localhost';")
            s_row = cursor.fetchone()
            server_id = s_row["id"] if s_row else None
            sample_alerts = [
                (server_id, "Critical", "CPU Spike Alert", "Localhost CPU usage spiked above 90% threshold for 5 minutes.", 0),
                (server_id, "Warning", "High Memory Consumption", "RAM usage exceeded 80% of total available capacity.", 0),
                (server_id, "Warning", "Storage Space Threshold", "Disk space partition /dev/sda1 reaches 75% capacity.", 1),
                (server_id, "Info", "System Backup Completed", "Scheduled automated database backup finished successfully.", 1),
            ]
            cursor.executemany(
                "INSERT INTO alerts (server_id, level, title, message, resolved) VALUES (?, ?, ?, ?, ?)",
                sample_alerts,
            )

        # Seed initial remediation rules if empty
        cursor.execute("SELECT COUNT(*) AS count FROM remediation_rules;")
        if cursor.fetchone()["count"] == 0:
            sample_rules = [
                ("High CPU Auto-Throttle", "cpu", "Critical", "throttle_background_tasks", "Localhost", 300, 3, 1),
                ("High Memory Cache Flush", "memory", "Critical", "flush_memory_caches", "Localhost", 300, 3, 1),
                ("High Disk Space Cleanup", "disk", "Critical", "clean_temp_cache_files", "Localhost", 600, 2, 1),
                ("Service Health Auto-Recovery", "service", "Critical", "restart_managed_service", "web-worker", 180, 3, 1),
            ]
            cursor.executemany(
                """
                INSERT INTO remediation_rules (name, trigger_type, threshold_level, action_type, target_resource, cooldown_seconds, max_retries, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                sample_rules,
            )

        # Seed initial managed services if empty
        cursor.execute("SELECT COUNT(*) AS count FROM managed_services;")
        if cursor.fetchone()["count"] == 0:
            sample_services = [
                ("web-worker", "background_processor", "Healthy", 0),
                ("cache-daemon", "in_memory_cache", "Healthy", 0),
            ]
            cursor.executemany(
                "INSERT INTO managed_services (name, service_type, status, restart_count) VALUES (?, ?, ?, ?)",
                sample_services,
            )

        conn.commit()


def add_server(name, status='Online'):
    """Add a new server using parameterized SQL."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO servers (name, status) VALUES (?, ?)",
            (name, status),
        )
        conn.commit()
        return cursor.lastrowid


def add_metric(server_id, cpu_usage, memory_usage, storage_usage, network_inbound=0.0, network_outbound=0.0):
    """Add metric data for a server using parameterized SQL."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO metrics (server_id, cpu_usage, memory_usage, storage_usage, network_inbound, network_outbound)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (server_id, cpu_usage, memory_usage, storage_usage, network_inbound, network_outbound),
        )
        conn.commit()
        return cursor.lastrowid


def add_alert(server_id, level, title, message=None):
    """Add an alert using parameterized SQL."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (server_id, level, title, message) VALUES (?, ?, ?, ?)",
            (server_id, level, title, message),
        )
        conn.commit()
        return cursor.lastrowid


def get_or_create_default_server(name="Localhost"):
    """Get the default server ID, creating it if it doesn't exist."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM servers WHERE name = ?", (name,))
        row = cursor.fetchone()
        if row:
            return row["id"]
        
        cursor.execute("INSERT INTO servers (name, status) VALUES (?, ?)", (name, "Online"))
        conn.commit()
        return cursor.lastrowid


def get_recent_metrics(server_id=None, limit=12):
    """Get recent metric history for dashboard charts."""
    with get_connection() as conn:
        cursor = conn.cursor()
        if server_id:
            cursor.execute(
                """
                SELECT * FROM metrics WHERE server_id = ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (server_id, limit),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM metrics
                ORDER BY timestamp DESC LIMIT ?
                """,
                (limit,),
            )
        rows = cursor.fetchall()
        # Return in chronological order
        return [dict(row) for row in reversed(rows)]


def get_all_servers_with_latest_metrics():
    """Get all monitored servers along with their latest metric reading."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT 
                s.id,
                s.name,
                s.status,
                s.created_at,
                m.cpu_usage,
                m.memory_usage,
                m.storage_usage,
                m.network_inbound,
                m.network_outbound,
                m.timestamp AS last_updated
            FROM servers s
            LEFT JOIN metrics m ON m.id = (
                SELECT id FROM metrics 
                WHERE server_id = s.id 
                ORDER BY timestamp DESC, id DESC 
                LIMIT 1
            )
            ORDER BY s.id ASC;
            """
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_alerts(filter_by="all"):
    """Get system alerts with optional filtering by severity (critical, warning, info) or status (resolved, unresolved)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT 
                a.id,
                a.server_id,
                a.level,
                a.title,
                a.message,
                a.timestamp,
                a.resolved,
                COALESCE(s.name, 'Localhost') AS server_name
            FROM alerts a
            LEFT JOIN servers s ON a.server_id = s.id
        """
        params = []
        filter_clean = (filter_by or "all").lower()

        if filter_clean in ["critical", "warning", "info"]:
            query += " WHERE LOWER(a.level) = ?"
            params.append(filter_clean)
        elif filter_clean == "resolved":
            query += " WHERE a.resolved = 1"
        elif filter_clean == "unresolved":
            query += " WHERE a.resolved = 0"

        query += " ORDER BY a.timestamp DESC, a.id DESC;"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def resolve_alert(alert_id):
    """Mark an alert as resolved by ID using parameterized SQL."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE alerts SET resolved = 1 WHERE id = ?;", (alert_id,))
        conn.commit()
        return cursor.rowcount > 0


def get_historical_metrics(timeframe="all", limit=100):
    """Get historical metrics with optional timeframe filtering ('1h', '6h', '24h', 'all')."""
    with get_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT 
                m.id,
                m.server_id,
                m.cpu_usage,
                m.memory_usage,
                m.storage_usage,
                m.network_inbound,
                m.network_outbound,
                m.timestamp,
                COALESCE(s.name, 'Localhost') AS server_name
            FROM metrics m
            LEFT JOIN servers s ON m.server_id = s.id
        """
        tf = (timeframe or "all").lower()
        params = []

        if tf == "1h":
            query += " WHERE m.timestamp >= datetime('now', '-1 hour') OR m.timestamp >= datetime((SELECT MAX(timestamp) FROM metrics), '-1 hour')"
        elif tf == "6h":
            query += " WHERE m.timestamp >= datetime('now', '-6 hours') OR m.timestamp >= datetime((SELECT MAX(timestamp) FROM metrics), '-6 hours')"
        elif tf == "24h":
            query += " WHERE m.timestamp >= datetime('now', '-24 hours') OR m.timestamp >= datetime((SELECT MAX(timestamp) FROM metrics), '-24 hours')"

        query += " ORDER BY m.timestamp DESC, m.id DESC LIMIT ?;"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_all_settings():
    """Retrieve all configuration settings as a dictionary with default fallbacks."""
    settings = dict(DEFAULT_SETTINGS)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM settings;")
        rows = cursor.fetchall()
        for row in rows:
            settings[row["key"]] = row["value"]
    return settings


def save_settings(settings_dict):
    """Save a dictionary of key-value settings into the SQLite settings table."""
    with get_connection() as conn:
        cursor = conn.cursor()
        for key, val in settings_dict.items():
            cursor.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?);",
                (str(key), str(val)),
            )
        conn.commit()


def evaluate_and_update_alerts(server_id, metrics):
    """Evaluate live metrics against saved threshold settings.

    Creates Warning or Critical alerts when thresholds are breached,
    prevents duplicate unresolved alerts for identical conditions,
    auto-resolves alerts when metrics return to normal, and updates
    overall server status.
    """
    settings = get_all_settings()
    enable_alerts = str(settings.get("enable_alerts", "true")).lower() in ["true", "1", "yes"]

    try:
        cpu_warn = float(settings.get("cpu_warning_threshold", 70))
        cpu_crit = float(settings.get("cpu_critical_threshold", 90))
        mem_warn = float(settings.get("memory_warning_threshold", 80))
        mem_crit = float(settings.get("memory_critical_threshold", 95))
        disk_warn = float(settings.get("disk_warning_threshold", 75))
        disk_crit = float(settings.get("disk_critical_threshold", 90))
    except (ValueError, TypeError):
        cpu_warn, cpu_crit = 70.0, 90.0
        mem_warn, mem_crit = 80.0, 95.0
        disk_warn, disk_crit = 75.0, 90.0

    current_cpu = float(metrics.get("cpu_percent", 0.0))
    current_mem = float(metrics.get("memory_percent", 0.0))
    current_disk = float(metrics.get("disk_percent", 0.0))

    evaluations = [
        ("CPU", current_cpu, cpu_warn, cpu_crit),
        ("Memory", current_mem, mem_warn, mem_crit),
        ("Disk", current_disk, disk_warn, disk_crit),
    ]

    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM servers WHERE id = ?;", (server_id,))
        s_row = cursor.fetchone()
        server_name = s_row["name"] if s_row else "Localhost"

        worst_state = "Online"

        for cat, val, warn, crit in evaluations:
            if val >= crit:
                severity = "Critical"
            elif val >= warn:
                severity = "Warning"
            else:
                severity = "Normal"

            if severity == "Critical":
                worst_state = "Offline"
            elif severity == "Warning" and worst_state != "Offline":
                worst_state = "Warning"

            # Look for existing active (unresolved) alert for this category on this server
            cursor.execute(
                """
                SELECT id, level, title 
                FROM alerts 
                WHERE server_id = ? AND resolved = 0 AND title LIKE ?
                LIMIT 1;
                """,
                (server_id, f"%{cat}%"),
            )
            existing = cursor.fetchone()

            if severity == "Normal":
                # Auto-resolve if active alert exists
                if existing:
                    cursor.execute(
                        "UPDATE alerts SET resolved = 1 WHERE id = ?;",
                        (existing["id"],),
                    )
            elif enable_alerts:
                title = f"{cat} Usage {severity} Alert"
                message = f"{server_name} {cat} usage ({val}%) reached {severity.lower()} threshold."

                if not existing:
                    # Insert NEW alert record
                    cursor.execute(
                        """
                        INSERT INTO alerts (server_id, level, title, message, resolved)
                        VALUES (?, ?, ?, ?, 0);
                        """,
                        (server_id, severity, title, message),
                    )
                elif existing["level"] != severity:
                    # Severity level changed (e.g. Warning -> Critical)
                    cursor.execute(
                        """
                        UPDATE alerts 
                        SET level = ?, title = ?, message = ?, timestamp = CURRENT_TIMESTAMP 
                        WHERE id = ?;
                        """,
                        (severity, title, message, existing["id"]),
                    )

        # Update server status in servers table
        cursor.execute(
            "UPDATE servers SET status = ? WHERE id = ?;",
            (worst_state, server_id),
        )
        conn.commit()

    return worst_state


# ==========================================
# Automated Remediation Database Helpers
# ==========================================

def get_remediation_rules():
    """Retrieve all remediation rules ordered by ID."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, name, trigger_type, threshold_level, action_type, target_resource,
                   cooldown_seconds, max_retries, enabled, created_at
            FROM remediation_rules
            ORDER BY id ASC;
        """)
        return [dict(row) for row in cursor.fetchall()]


def get_enabled_remediation_rules(trigger_type=None):
    """Retrieve all enabled remediation rules, optionally filtered by trigger_type."""
    with get_connection() as conn:
        cursor = conn.cursor()
        if trigger_type:
            cursor.execute("""
                SELECT id, name, trigger_type, threshold_level, action_type, target_resource,
                       cooldown_seconds, max_retries, enabled, created_at
                FROM remediation_rules
                WHERE enabled = 1 AND trigger_type = ?
                ORDER BY id ASC;
            """, (trigger_type,))
        else:
            cursor.execute("""
                SELECT id, name, trigger_type, threshold_level, action_type, target_resource,
                       cooldown_seconds, max_retries, enabled, created_at
                FROM remediation_rules
                WHERE enabled = 1
                ORDER BY id ASC;
            """)
        return [dict(row) for row in cursor.fetchall()]


def get_remediation_rule_by_id(rule_id):
    """Get a single remediation rule by ID."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, name, trigger_type, threshold_level, action_type, target_resource,
                   cooldown_seconds, max_retries, enabled, created_at
            FROM remediation_rules
            WHERE id = ?;
        """, (rule_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def add_remediation_rule(name, trigger_type, action_type, threshold_level="Critical",
                         target_resource="Localhost", cooldown_seconds=300, max_retries=3, enabled=1):
    """Add a new remediation rule using parameterized SQL."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO remediation_rules (name, trigger_type, threshold_level, action_type,
                                           target_resource, cooldown_seconds, max_retries, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, (name, trigger_type, threshold_level, action_type, target_resource, cooldown_seconds, max_retries, enabled))
        conn.commit()
        return cursor.lastrowid


def update_remediation_rule(rule_id, name=None, trigger_type=None, action_type=None,
                            threshold_level=None, target_resource=None,
                            cooldown_seconds=None, max_retries=None, enabled=None):
    """Update fields of an existing remediation rule using parameterized SQL."""
    with get_connection() as conn:
        cursor = conn.cursor()
        fields = []
        params = []
        if name is not None:
            fields.append("name = ?")
            params.append(name)
        if trigger_type is not None:
            fields.append("trigger_type = ?")
            params.append(trigger_type)
        if action_type is not None:
            fields.append("action_type = ?")
            params.append(action_type)
        if threshold_level is not None:
            fields.append("threshold_level = ?")
            params.append(threshold_level)
        if target_resource is not None:
            fields.append("target_resource = ?")
            params.append(target_resource)
        if cooldown_seconds is not None:
            fields.append("cooldown_seconds = ?")
            params.append(int(cooldown_seconds))
        if max_retries is not None:
            fields.append("max_retries = ?")
            params.append(int(max_retries))
        if enabled is not None:
            fields.append("enabled = ?")
            params.append(1 if enabled else 0)

        if not fields:
            return False

        params.append(rule_id)
        query = f"UPDATE remediation_rules SET {', '.join(fields)} WHERE id = ?;"
        cursor.execute(query, params)
        conn.commit()
        return cursor.rowcount > 0


def toggle_remediation_rule(rule_id, enabled):
    """Enable or disable a remediation rule."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE remediation_rules SET enabled = ? WHERE id = ?;", (1 if enabled else 0, rule_id))
        conn.commit()
        return cursor.rowcount > 0


def add_remediation_log(rule_id, server_id, alert_id, action_type, status="PENDING",
                        attempt_count=1, pre_metric_val=None, post_metric_val=None, details=None):
    """Create a remediation log entry using parameterized SQL."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO remediation_logs (rule_id, server_id, alert_id, action_type, status,
                                          attempt_count, pre_metric_val, post_metric_val, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (rule_id, server_id, alert_id, action_type, status, attempt_count, pre_metric_val, post_metric_val, details))
        conn.commit()
        return cursor.lastrowid


def update_remediation_log(log_id, status, post_metric_val=None, details=None, completed=True):
    """Update the status and result of a remediation log execution."""
    with get_connection() as conn:
        cursor = conn.cursor()
        if completed:
            cursor.execute("""
                UPDATE remediation_logs
                SET status = ?, post_metric_val = COALESCE(?, post_metric_val),
                    details = COALESCE(?, details), completed_at = CURRENT_TIMESTAMP
                WHERE id = ?;
            """, (status, post_metric_val, details, log_id))
        else:
            cursor.execute("""
                UPDATE remediation_logs
                SET status = ?, post_metric_val = COALESCE(?, post_metric_val),
                    details = COALESCE(?, details)
                WHERE id = ?;
            """, (status, post_metric_val, details, log_id))
        conn.commit()
        return cursor.rowcount > 0


def get_remediation_logs(limit=50, status=None):
    """Read recent remediation logs with joined server and rule information."""
    with get_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT 
                l.id,
                l.rule_id,
                l.server_id,
                l.alert_id,
                l.action_type,
                l.status,
                l.attempt_count,
                l.pre_metric_val,
                l.post_metric_val,
                l.details,
                l.started_at,
                l.completed_at,
                COALESCE(r.name, 'Manual / Direct') AS rule_name,
                COALESCE(r.trigger_type, 'unknown') AS trigger_type,
                COALESCE(s.name, 'Localhost') AS server_name,
                a.title AS alert_title
            FROM remediation_logs l
            LEFT JOIN remediation_rules r ON l.rule_id = r.id
            LEFT JOIN servers s ON l.server_id = s.id
            LEFT JOIN alerts a ON l.alert_id = a.id
        """
        params = []
        if status:
            query += " WHERE LOWER(l.status) = ?"
            params.append(status.lower())

        query += " ORDER BY l.started_at DESC, l.id DESC LIMIT ?;"
        params.append(limit)

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]


def get_latest_remediation_for_rule(rule_id, server_id=None):
    """Get the most recent remediation log for a specific rule to evaluate cooldown and retry status."""
    with get_connection() as conn:
        cursor = conn.cursor()
        if server_id:
            cursor.execute("""
                SELECT * FROM remediation_logs
                WHERE rule_id = ? AND server_id = ?
                ORDER BY started_at DESC, id DESC LIMIT 1;
            """, (rule_id, server_id))
        else:
            cursor.execute("""
                SELECT * FROM remediation_logs
                WHERE rule_id = ?
                ORDER BY started_at DESC, id DESC LIMIT 1;
            """, (rule_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_managed_services():
    """Retrieve all managed services and their current status."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, name, service_type, status, last_check, restart_count
            FROM managed_services
            ORDER BY id ASC;
        """)
        return [dict(row) for row in cursor.fetchall()]


def get_managed_service_by_name(name):
    """Retrieve a single managed service by its unique name."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, name, service_type, status, last_check, restart_count
            FROM managed_services
            WHERE name = ?;
        """, (name,))
        row = cursor.fetchone()
        return dict(row) if row else None


def update_managed_service_status(name_or_id, status, increment_restart=False):
    """Update managed service status, timestamp, and optional restart count."""
    with get_connection() as conn:
        cursor = conn.cursor()
        if isinstance(name_or_id, int) or (isinstance(name_or_id, str) and name_or_id.isdigit()):
            field = "id"
            val = int(name_or_id)
        else:
            field = "name"
            val = str(name_or_id)

        if increment_restart:
            cursor.execute(f"""
                UPDATE managed_services
                SET status = ?, last_check = CURRENT_TIMESTAMP, restart_count = restart_count + 1
                WHERE {field} = ?;
            """, (status, val))
        else:
            cursor.execute(f"""
                UPDATE managed_services
                SET status = ?, last_check = CURRENT_TIMESTAMP
                WHERE {field} = ?;
            """, (status, val))
        conn.commit()
        return cursor.rowcount > 0


if __name__ == "__main__":
    print("Initializing database...")
    init_database()
    print("Database initialized successfully at:", DATABASE_PATH)



