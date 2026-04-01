from __future__ import annotations

import time

import psutil

from .models import MonitoringSnapshot


class NetworkMonitor:
    def __init__(self) -> None:
        self._previous: dict[str, tuple[float, object]] = {}

    def available_interfaces(self) -> list[str]:
        return sorted(psutil.net_io_counters(pernic=True).keys())

    def sample(self, interface: str | None = None) -> MonitoringSnapshot:
        counters = psutil.net_io_counters(pernic=True)
        if interface and interface in counters:
            current = counters[interface]
            selected_interface = interface
        else:
            current = psutil.net_io_counters()
            selected_interface = "All interfaces"

        now = time.time()
        previous_time, previous_counter = self._previous.get(selected_interface, (now, current))
        elapsed = max(now - previous_time, 1.0)

        upload_bps = (current.bytes_sent - previous_counter.bytes_sent) / elapsed
        download_bps = (current.bytes_recv - previous_counter.bytes_recv) / elapsed

        self._previous[selected_interface] = (now, current)

        return MonitoringSnapshot(
            interface=selected_interface,
            bytes_sent=current.bytes_sent,
            bytes_recv=current.bytes_recv,
            packets_sent=current.packets_sent,
            packets_recv=current.packets_recv,
            upload_bps=max(upload_bps, 0.0),
            download_bps=max(download_bps, 0.0),
            total_bandwidth_bps=max(upload_bps + download_bps, 0.0),
        )
