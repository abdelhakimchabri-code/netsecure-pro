from __future__ import annotations

import csv
from pathlib import Path

from .models import Device, EventLogEntry, PortScanResult, ScanRun


class CSVExporter:
    def __init__(self, output_dir: str | Path = "exports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_devices(self, devices: list[Device]) -> Path:
        rows = [
            {
                "ip_address": device.ip_address,
                "mac_address": device.mac_address,
                "hostname": device.hostname,
                "vendor": device.vendor,
                "discovery_method": device.discovery_method,
                "device_type": device.device_type,
                "os_guess": device.os_guess,
                "status": device.status,
                "trust": "Connu" if device.is_known else "Inconnu",
                "last_seen": device.last_seen,
            }
            for device in devices
        ]
        return self._write_csv("devices_export.csv", rows)

    def export_ports(self, port_results: list[PortScanResult]) -> Path:
        rows = [
            {
                "device_ip": result.device_ip,
                "port": result.port,
                "service": result.service,
                "state": result.state,
                "risk_level": result.risk_level,
                "banner": result.banner,
            }
            for result in port_results
        ]
        return self._write_csv("ports_export.csv", rows)

    def export_history(self, scan_runs: list[ScanRun]) -> Path:
        rows = [
            {
                "scan_type": run.scan_type,
                "target": run.target,
                "summary": run.summary,
                "score": run.score,
                "created_at": run.created_at,
            }
            for run in scan_runs
        ]
        return self._write_csv("history_export.csv", rows)

    def export_events(self, events: list[EventLogEntry]) -> Path:
        rows = [
            {
                "category": event.category,
                "level": event.level,
                "message": event.message,
                "created_at": event.created_at,
            }
            for event in events
        ]
        return self._write_csv("events_export.csv", rows)

    def export_reports(self, reports: list[dict[str, str]]) -> Path:
        return self._write_csv("reports_export.csv", reports)

    def _write_csv(self, filename: str, rows: list[dict[str, object]]) -> Path:
        output_path = self.output_dir / filename
        fieldnames = list(rows[0].keys()) if rows else ["empty"]
        with output_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            if rows:
                writer.writerows(rows)
            else:
                writer.writerow({"empty": "no data"})
        return output_path
