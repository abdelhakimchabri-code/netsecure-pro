from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import PortScanResult


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
}

SCAN_MODES = {
    "quick": [21, 22, 23, 80, 443, 445, 3389],
    "common": list(COMMON_PORTS),
    "extended": list(range(1, 1025)),
}


class PortScanner:
    def __init__(self, timeout: float = 0.35) -> None:
        self.timeout = timeout

    def scan_host(
        self,
        ip_address: str,
        mode: str = "common",
        custom_ports: str = "",
        ports: list[int] | None = None,
        progress_callback=None,
        should_cancel=None,
    ) -> list[PortScanResult]:
        target_ports = ports or self._resolve_ports(mode, custom_ports)
        results: list[PortScanResult] = []
        executor = ThreadPoolExecutor(max_workers=min(128, max(8, len(target_ports))))
        try:
            future_map = {executor.submit(self._probe_port, ip_address, port): port for port in target_ports}
            completed_count = 0
            for future in as_completed(future_map):
                if should_cancel and should_cancel():
                    for pending in future_map:
                        pending.cancel()
                    executor.shutdown(wait=False, cancel_futures=True)
                    return sorted(results, key=lambda item: item.port)
                result = future.result()
                if result is not None:
                    results.append(result)
                completed_count += 1
                if progress_callback is not None:
                    progress_callback(completed_count, len(target_ports), len(results), future_map[future])
        finally:
            try:
                executor.shutdown(wait=True, cancel_futures=False)
            except Exception:
                pass
        return sorted(results, key=lambda item: item.port)

    def _resolve_ports(self, mode: str, custom_ports: str) -> list[int]:
        if custom_ports.strip():
            return self.parse_ports_expression(custom_ports)
        return SCAN_MODES.get(mode, SCAN_MODES["common"])

    def parse_ports_expression(self, expression: str) -> list[int]:
        ports: set[int] = set()
        for chunk in expression.split(","):
            item = chunk.strip()
            if not item:
                continue
            if "-" in item:
                start_text, end_text = item.split("-", maxsplit=1)
                start = int(start_text)
                end = int(end_text)
                if start > end:
                    raise ValueError("The port range is invalid.")
                for port in range(start, end + 1):
                    self._validate_port(port)
                    ports.add(port)
            else:
                port = int(item)
                self._validate_port(port)
                ports.add(port)
        if not ports:
            raise ValueError("Please enter at least one valid port.")
        if len(ports) > 4096:
            raise ValueError("To keep the scan responsive, limit a custom scan to 4096 ports.")
        return sorted(ports)

    def _validate_port(self, port: int) -> None:
        if port < 1 or port > 65535:
            raise ValueError("Ports must be between 1 and 65535.")

    def _probe_port(self, ip_address: str, port: int) -> PortScanResult | None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            state = sock.connect_ex((ip_address, port))
            if state != 0:
                return None
            service = COMMON_PORTS.get(port, "Unknown")
            banner = self._grab_banner(sock, ip_address, port, service)
        return PortScanResult(
            device_ip=ip_address,
            port=port,
            service=service,
            state="open",
            risk_level=self._risk_level(port, service),
            banner=banner,
        )

    def _risk_level(self, port: int, service: str) -> str:
        if port in {23, 445, 3389}:
            return "Critical"
        if service in {"FTP", "POP3", "IMAP", "NetBIOS"}:
            return "High"
        if service in {"HTTP", "SMTP"}:
            return "Medium"
        return "Low"

    def _grab_banner(self, sock: socket.socket, ip_address: str, port: int, service: str) -> str:
        try:
            if service in {"HTTP", "HTTPS"} or port in {8080, 8000, 8443}:
                request = f"HEAD / HTTP/1.0\r\nHost: {ip_address}\r\n\r\n".encode("ascii", errors="ignore")
                sock.sendall(request)
            data = sock.recv(256)
            banner = data.decode("utf-8", errors="ignore").strip().replace("\r", " ").replace("\n", " ")
            return banner[:120]
        except OSError:
            return ""
