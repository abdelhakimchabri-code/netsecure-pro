from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


def utc_now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@dataclass(slots=True)
class Device:
    ip_address: str
    mac_address: str
    hostname: str
    status: str = "active"
    last_seen: str = field(default_factory=utc_now)
    is_known: bool = True
    vendor: str = "Unknown"
    discovery_method: str = "Unknown"
    device_type: str = "Unknown"
    os_guess: str = "Unknown"


@dataclass(slots=True)
class PortScanResult:
    device_ip: str
    port: int
    service: str
    state: str
    risk_level: str
    banner: str = ""


@dataclass(slots=True)
class Alert:
    type_alert: str
    description: str
    severity: str
    created_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class MonitoringSnapshot:
    interface: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    upload_bps: float
    download_bps: float
    total_bandwidth_bps: float


@dataclass(slots=True)
class SecurityAssessment:
    score: int
    label: str
    observations: list[str]
    recommendations: list[str]
    risk_factors: list[str]


@dataclass(slots=True)
class ScanRun:
    scan_type: str
    target: str
    summary: str
    score: int
    created_at: str


@dataclass(slots=True)
class EventLogEntry:
    category: str
    level: str
    message: str
    created_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class SecuritySettings:
    bandwidth_alert_threshold_bps: int = 5_000_000
    managed_hosts_limit: int = 20
    large_network_threshold: int = 50
