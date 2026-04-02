from __future__ import annotations

import csv
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from .models import Alert, Device, EventLogEntry, PortScanResult, ScanRun, SecurityAssessment


class CSVExporter:
    def __init__(self, output_dir: str | Path = "exports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_devices(self, devices: list[Device]) -> Path:
        rows = [self._device_row(device) for device in devices]
        return self._write_csv("devices_export.csv", rows)

    def export_ports(self, port_results: list[PortScanResult]) -> Path:
        rows = [self._port_row(result) for result in port_results]
        return self._write_csv("ports_export.csv", rows)

    def export_history(self, scan_runs: list[ScanRun]) -> Path:
        rows = [self._history_row(run) for run in scan_runs]
        return self._write_csv("history_export.csv", rows)

    def export_events(self, events: list[EventLogEntry]) -> Path:
        rows = [self._event_row(event) for event in events]
        return self._write_csv("events_export.csv", rows)

    def export_reports(self, reports: list[dict[str, str]]) -> Path:
        return self._write_csv("reports_export.csv", reports)

    def export_snapshot_json(
        self,
        devices: list[Device],
        port_results: list[PortScanResult],
        alerts: list[Alert],
        scan_runs: list[ScanRun],
        assessment: SecurityAssessment,
        company_profile: dict[str, str],
        comparison_summary: str = "",
    ) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        payload = {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "company_profile": company_profile,
            "comparison_summary": comparison_summary,
            "assessment": asdict(assessment),
            "devices": [asdict(device) for device in devices],
            "port_results": [asdict(result) for result in port_results],
            "alerts": [asdict(alert) for alert in alerts],
            "history": [asdict(run) for run in scan_runs],
        }
        return self._write_json(f"network_snapshot_{timestamp}.json", payload)

    def _device_row(self, device: Device) -> dict[str, object]:
        return {
            "ip_address": device.ip_address,
            "mac_address": device.mac_address,
            "hostname": device.hostname,
            "vendor": device.vendor,
            "discovery_method": device.discovery_method,
            "device_type": device.device_type,
            "os_guess": device.os_guess,
            "status": device.status,
            "trust": "Known" if device.is_known else "Unknown",
            "last_seen": device.last_seen,
        }

    def _port_row(self, result: PortScanResult) -> dict[str, object]:
        return {
            "device_ip": result.device_ip,
            "port": result.port,
            "service": result.service,
            "state": result.state,
            "risk_level": result.risk_level,
            "banner": result.banner,
        }

    def _history_row(self, run: ScanRun) -> dict[str, object]:
        return {
            "scan_type": run.scan_type,
            "target": run.target,
            "summary": run.summary,
            "score": run.score,
            "created_at": run.created_at,
        }

    def _event_row(self, event: EventLogEntry) -> dict[str, object]:
        return {
            "category": event.category,
            "level": event.level,
            "message": event.message,
            "created_at": event.created_at,
        }

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

    def _write_json(self, filename: str, payload: dict[str, object]) -> Path:
        output_path = self.output_dir / filename
        output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return output_path
