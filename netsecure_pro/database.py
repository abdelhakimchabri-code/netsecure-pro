from __future__ import annotations

import sqlite3
from pathlib import Path

from .auth import hash_password
from .models import Alert, Device, EventLogEntry, PortScanResult, ScanRun, SecuritySettings


class DatabaseManager:
    def __init__(self, db_path: str | Path = "netsecure_pro.db") -> None:
        self.db_path = Path(db_path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _translate_legacy_text(value: str) -> str:
        if not value:
            return value

        replacements = (
            ("Pic de trafic", "Traffic Spike"),
            ("Nouvel equipement", "New Device"),
            ("Equipement inconnu", "Unknown Device"),
            ("Service non securise", "Insecure Service"),
            ("Port sensible", "Sensitive Port"),
            ("Capacite reseau", "Network Capacity"),
            ("Reseau important", "Large Network"),
            ("Scan reseau", "Network Scan"),
            ("Analyse ports", "Port Scan"),
            ("Nouvel appareil detecte sur le reseau: ", "New device detected on the network: "),
            ("L'hote ", "Host "),
            (" n'a pas pu etre clairement identifie.", " could not be clearly identified."),
            ("Le service Telnet est actif sur ", "The Telnet service is active on "),
            ("Le service FTP est actif sur ", "The FTP service is active on "),
            ("Le port ", "Port "),
            (" est expose sur ", " is exposed on "),
            ("L'interface ", "Interface "),
            (" depasse le seuil de ", " exceeds the threshold of "),
            (" avec ", " with "),
            ("Le nombre d'hotes detectes (", "The number of detected hosts ("),
            (" depasse la limite maitrisee ", " exceeds the managed limit "),
            (" depasse le seuil reseau important ", " exceeds the large-network threshold "),
            ("Aucun equipement detecte", "No devices detected"),
            ("Aucun port ouvert detecte sur le dernier scan", "No open ports were detected in the latest scan"),
            ("Aucune alerte recente", "No recent alerts"),
            (" hote(s) actif(s) detectes | ", " active host(s) detected | "),
            (" port(s) ouvert(s) | ", " open port(s) | "),
            ("Rapport PDF genere", "PDF report generated"),
        )

        text = value
        for source, target in replacements:
            text = text.replace(source, target)
        return text

    def _initialize(self) -> None:
        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    role TEXT DEFAULT 'Viewer',
                    active INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    mac_address TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    discovery_method TEXT,
                    device_type TEXT,
                    os_guess TEXT,
                    status TEXT,
                    last_seen TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS port_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    service TEXT,
                    state TEXT,
                    risk_level TEXT,
                    banner TEXT,
                    scanned_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(device_id) REFERENCES devices(id)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type_alert TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_name TEXT NOT NULL,
                    generated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    score INTEGER NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS event_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            user_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(users)").fetchall()
            }
            if "role" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'Viewer'")
            if "active" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN active INTEGER DEFAULT 1")
            if "created_at" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN created_at TEXT")

            cursor.execute(
                """
                INSERT OR IGNORE INTO users(username, password, role, active, created_at)
                VALUES (?, ?, ?, ?, datetime('now'))
                """,
                ("admin", hash_password("admin123"), "Admin", 1),
            )
            connection.execute(
                """
                UPDATE users
                SET role = COALESCE(NULLIF(role, ''), 'Viewer'),
                    active = COALESCE(active, 1),
                    created_at = COALESCE(created_at, datetime('now'))
                """
            )
            connection.execute(
                """
                UPDATE users
                SET role = 'Admin'
                WHERE username = 'admin'
                """
            )
            cursor.execute(
                """
                INSERT OR IGNORE INTO settings(key, value)
                VALUES ('theme', 'light')
                """
            )
            cursor.execute(
                """
                INSERT OR IGNORE INTO settings(key, value)
                VALUES ('bandwidth_alert_threshold_bps', '5000000')
                """
            )
            cursor.execute(
                """
                INSERT OR IGNORE INTO settings(key, value)
                VALUES ('managed_hosts_limit', '20')
                """
            )
            cursor.execute(
                """
                INSERT OR IGNORE INTO settings(key, value)
                VALUES ('large_network_threshold', '50')
                """
            )
            port_scan_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(port_scans)").fetchall()
            }
            if "banner" not in port_scan_columns:
                connection.execute("ALTER TABLE port_scans ADD COLUMN banner TEXT DEFAULT ''")
            device_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(devices)").fetchall()
            }
            if "vendor" not in device_columns:
                connection.execute("ALTER TABLE devices ADD COLUMN vendor TEXT DEFAULT 'Unknown'")
            if "discovery_method" not in device_columns:
                connection.execute("ALTER TABLE devices ADD COLUMN discovery_method TEXT DEFAULT 'Unknown'")
            if "device_type" not in device_columns:
                connection.execute("ALTER TABLE devices ADD COLUMN device_type TEXT DEFAULT 'Unknown'")
            if "os_guess" not in device_columns:
                connection.execute("ALTER TABLE devices ADD COLUMN os_guess TEXT DEFAULT 'Unknown'")
            for key, value in (
                ("company_name", "NetSecure Enterprise"),
                ("department", "Security Operations Center"),
                ("site", "Head Office"),
                ("owner", "Infrastructure & Cybersecurity Team"),
                ("classification", "Internal Use Only"),
                ("support_email", "soc@netsecure-enterprise.local"),
                ("support_phone", "+212 5 00 00 00 00"),
                ("primary_color", "#0ea5a8"),
                ("accent_color", "#54b8ff"),
                ("logo_text", "NSE"),
                ("logo_path", ""),
                ("openrouter_api_key", ""),
                ("openrouter_model", "openai/gpt-4o-mini"),
                ("openrouter_mode", "scan-aware"),
            ):
                connection.execute(
                    """
                    INSERT OR IGNORE INTO settings(key, value)
                    VALUES (?, ?)
                    """,
                    (key, value),
                )
            connection.commit()

    def verify_user(self, username: str, password: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT password FROM users WHERE username = ? AND COALESCE(active, 1) = 1",
                (username,),
            ).fetchone()
        return bool(row and row["password"] == hash_password(password))

    def fetch_users(self) -> list[sqlite3.Row]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, username, COALESCE(role, 'Viewer') AS role,
                       CASE WHEN COALESCE(active, 1) = 1 THEN 'Yes' ELSE 'No' END AS active,
                       COALESCE(created_at, datetime('now')) AS created_at
                FROM users
                ORDER BY id
                """
            ).fetchall()
        return list(rows)

    def add_user(self, username: str, password: str, role: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO users(username, password, role, active, created_at)
                VALUES (?, ?, ?, 1, datetime('now'))
                """,
                (username, hash_password(password), role),
            )
            connection.commit()

    def set_user_active(self, username: str, active: bool) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE users
                SET active = ?
                WHERE username = ?
                """,
                (1 if active else 0, username),
            )
            connection.commit()

    def fetch_devices(self) -> list[Device]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT ip_address, COALESCE(mac_address, '') AS mac_address,
                       COALESCE(hostname, '') AS hostname,
                       COALESCE(vendor, 'Unknown') AS vendor,
                       COALESCE(discovery_method, 'Unknown') AS discovery_method,
                       COALESCE(device_type, 'Unknown') AS device_type,
                       COALESCE(os_guess, 'Unknown') AS os_guess,
                       COALESCE(status, 'unknown') AS status,
                       COALESCE(last_seen, '') AS last_seen
                FROM devices
                ORDER BY ip_address
                """
            ).fetchall()
        return [
            Device(
                ip_address=row["ip_address"],
                mac_address=row["mac_address"] or "Unknown",
                hostname=row["hostname"] or "Unknown",
                status=row["status"],
                last_seen=row["last_seen"],
                is_known=bool(
                    (row["hostname"] and row["hostname"] != "Unknown")
                    or (row["mac_address"] and row["mac_address"] != "Unknown")
                ),
                vendor=row["vendor"] or "Unknown",
                discovery_method=row["discovery_method"] or "Unknown",
                device_type=row["device_type"] or "Unknown",
                os_guess=row["os_guess"] or "Unknown",
            )
            for row in rows
        ]

    def record_devices(self, devices: list[Device]) -> None:
        with self._connect() as connection:
            for device in devices:
                connection.execute(
                    """
                    INSERT INTO devices(
                        ip_address, mac_address, hostname, vendor, discovery_method, device_type, os_guess, status, last_seen
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip_address) DO UPDATE SET
                        mac_address=excluded.mac_address,
                        hostname=excluded.hostname,
                        vendor=excluded.vendor,
                        discovery_method=excluded.discovery_method,
                        device_type=excluded.device_type,
                        os_guess=excluded.os_guess,
                        status=excluded.status,
                        last_seen=excluded.last_seen
                    """,
                    (
                        device.ip_address,
                        device.mac_address,
                        device.hostname,
                        device.vendor,
                        device.discovery_method,
                        device.device_type,
                        device.os_guess,
                        device.status,
                        device.last_seen,
                    ),
                )
            connection.commit()

    def _device_id(self, connection: sqlite3.Connection, ip_address: str) -> int | None:
        row = connection.execute(
            "SELECT id FROM devices WHERE ip_address = ?",
            (ip_address,),
        ).fetchone()
        return None if row is None else int(row["id"])

    def record_port_scan(self, device_ip: str, results: list[PortScanResult]) -> None:
        with self._connect() as connection:
            device_id = self._device_id(connection, device_ip)
            if device_id is None:
                connection.execute(
                    """
                    INSERT INTO devices(
                        ip_address, mac_address, hostname, vendor, discovery_method, device_type, os_guess, status, last_seen
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                    """,
                    (device_ip, "Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "active"),
                )
                device_id = self._device_id(connection, device_ip)
            connection.execute("DELETE FROM port_scans WHERE device_id = ?", (device_id,))
            for result in results:
                connection.execute(
                    """
                    INSERT INTO port_scans(device_id, port, service, state, risk_level, banner)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        device_id,
                        result.port,
                        result.service,
                        result.state,
                        result.risk_level,
                        result.banner,
                    ),
                )
            connection.commit()

    def fetch_port_scan_summary(self) -> list[sqlite3.Row]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT d.ip_address, p.port, p.service, p.state, p.risk_level, COALESCE(p.banner, '') AS banner
                FROM port_scans p
                JOIN devices d ON d.id = p.device_id
                ORDER BY d.ip_address, p.port
                """
            ).fetchall()
        return list(rows)

    def add_alerts(self, alerts: list[Alert]) -> None:
        if not alerts:
            return
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO alerts(type_alert, description, severity, created_at)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (
                        alert.type_alert,
                        alert.description,
                        alert.severity,
                        alert.created_at,
                    )
                    for alert in alerts
                ],
            )
            connection.commit()

    def fetch_alerts(self, limit: int = 10) -> list[Alert]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT type_alert, description, severity, created_at
                FROM alerts
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            Alert(
                type_alert=self._translate_legacy_text(row["type_alert"]),
                description=self._translate_legacy_text(row["description"]),
                severity=row["severity"],
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def record_report(self, report_name: str, score: int) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO reports(report_name, generated_at, score)
                VALUES (?, datetime('now'), ?)
                """,
                (report_name, score),
            )
            connection.commit()

    def fetch_reports(self, limit: int = 10) -> list[sqlite3.Row]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT report_name, generated_at, score
                FROM reports
                ORDER BY generated_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return list(rows)

    def record_scan_run(self, scan_type: str, target: str, summary: str, score: int) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO scan_runs(scan_type, target, summary, score, created_at)
                VALUES (?, ?, ?, ?, datetime('now'))
                """,
                (scan_type, target, summary, score),
            )
            connection.commit()

    def fetch_scan_runs(self, limit: int = 30) -> list[ScanRun]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT scan_type, target, summary, score, created_at
                FROM scan_runs
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            ScanRun(
                scan_type=self._translate_legacy_text(row["scan_type"]),
                target=row["target"],
                summary=self._translate_legacy_text(row["summary"]),
                score=row["score"],
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def add_event_log(self, category: str, level: str, message: str) -> None:
        self.add_event_logs([EventLogEntry(category=category, level=level, message=message)])

    def add_event_logs(self, entries: list[EventLogEntry]) -> None:
        if not entries:
            return
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO event_logs(category, level, message, created_at)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (
                        entry.category,
                        entry.level,
                        entry.message,
                        entry.created_at,
                    )
                    for entry in entries
                ],
            )
            connection.commit()

    def fetch_event_logs(self, limit: int = 50) -> list[EventLogEntry]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT category, level, message, created_at
                FROM event_logs
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            EventLogEntry(
                category=self._translate_legacy_text(row["category"]),
                level=row["level"],
                message=self._translate_legacy_text(row["message"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def get_setting(self, key: str, default: str = "") -> str:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM settings WHERE key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return default
        return str(row["value"])

    def set_setting(self, key: str, value: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO settings(key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (key, value),
            )
            connection.commit()

    def fetch_company_profile(self) -> dict[str, str]:
        defaults = {
            "company_name": "NetSecure Enterprise",
            "department": "Security Operations Center",
            "site": "Head Office",
            "owner": "Infrastructure & Cybersecurity Team",
            "classification": "Internal Use Only",
            "support_email": "soc@netsecure-enterprise.local",
            "support_phone": "+212 5 00 00 00 00",
            "primary_color": "#0ea5a8",
            "accent_color": "#54b8ff",
            "logo_text": "NSE",
            "logo_path": "",
        }
        return {key: self.get_setting(key, value) for key, value in defaults.items()}

    def get_int_setting(self, key: str, default: int) -> int:
        try:
            return int(self.get_setting(key, str(default)))
        except ValueError:
            return default

    def fetch_security_settings(self) -> SecuritySettings:
        return SecuritySettings(
            bandwidth_alert_threshold_bps=self.get_int_setting("bandwidth_alert_threshold_bps", 5_000_000),
            managed_hosts_limit=self.get_int_setting("managed_hosts_limit", 20),
            large_network_threshold=self.get_int_setting("large_network_threshold", 50),
        )
