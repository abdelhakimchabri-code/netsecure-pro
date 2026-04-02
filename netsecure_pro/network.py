from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil

from .models import Device, utc_now


MAC_PATTERN = re.compile(r"([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})")
PING_HOSTNAME_PATTERN = re.compile(r"Pinging\s+([^\s\[]+)\s+\[", re.IGNORECASE)
TCP_DISCOVERY_PORTS = [80, 443, 445, 22, 3389, 139, 53]
SCAN_MODES = {
    "quick": {"ping_timeout_ms": 250, "tcp_ports": [80, 443, 445], "tcp_timeout": 0.18},
    "balanced": {"ping_timeout_ms": 400, "tcp_ports": TCP_DISCOVERY_PORTS, "tcp_timeout": 0.22},
    "deep": {"ping_timeout_ms": 650, "tcp_ports": TCP_DISCOVERY_PORTS, "tcp_timeout": 0.35},
}
VIRTUAL_INTERFACE_KEYWORDS = (
    "virtual",
    "vbox",
    "vmware",
    "hyper-v",
    "loopback",
    "wi-fi direct",
    "bluetooth",
    "host-only",
    "tunnel",
    "vethernet",
    "wsl",
)

OUI_VENDOR_MAP = {
    "00-0C-29": "VMware",
    "00-50-56": "VMware",
    "08-00-27": "Oracle VirtualBox",
    "00-15-5D": "Microsoft Hyper-V",
    "3C-52-82": "Hewlett Packard",
    "B8-27-EB": "Raspberry Pi",
    "DC-A6-32": "Raspberry Pi",
    "F4-F2-6D": "Ubiquiti",
    "00-1B-63": "Apple",
    "00-1C-B3": "Apple",
    "FC-F1-36": "Apple",
    "00-25-9C": "Cisco",
    "00-1A-A2": "Cisco",
    "84-16-F9": "TP-Link",
    "F4-EC-38": "TP-Link",
    "00-1F-3B": "Dell",
    "A4-BA-DB": "Dell",
    "00-1E-67": "Intel",
    "A8-9C-ED": "Xiaomi",
    "F8-32-E4": "Samsung",
    "BC-76-70": "Samsung",
    "9C-4F-DA": "Huawei",
    "2C-AB-A4": "Google",
}


class NetworkScanner:
    def suggest_target(self) -> str:
        candidates = self._interface_candidates()
        preferred_ip = self._default_route_interface_ip()

        if preferred_ip:
            for candidate in candidates:
                if candidate["ip"] == preferred_ip:
                    return str(candidate["network"])

        if candidates:
            return str(candidates[0]["network"])
        return "192.168.1.0/24"

    def _default_route_interface_ip(self) -> str | None:
        completed = subprocess.run(
            ["route", "print", "-4"],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            return None

        best_metric: int | None = None
        preferred_ip: str | None = None
        for raw_line in completed.stdout.splitlines():
            parts = raw_line.split()
            if len(parts) < 5:
                continue
            if parts[0] != "0.0.0.0" or parts[1] != "0.0.0.0":
                continue

            interface_ip = parts[3]
            if interface_ip.startswith("127.") or interface_ip.startswith("169.254."):
                continue

            try:
                metric = int(parts[4])
            except ValueError:
                metric = 10_000

            if best_metric is None or metric < best_metric:
                best_metric = metric
                preferred_ip = interface_ip
        return preferred_ip

    def _interface_candidates(self) -> list[dict[str, object]]:
        stats = psutil.net_if_stats()
        candidates: list[dict[str, object]] = []

        for name, addresses in psutil.net_if_addrs().items():
            stat = stats.get(name)
            lowered_name = name.lower()
            is_virtual = self._is_virtual_interface(name)

            for address in addresses:
                if getattr(address, "family", None) != socket.AF_INET:
                    continue

                ip = address.address
                netmask = address.netmask
                if not ip or ip.startswith("127.") or ip.startswith("169.254.") or not netmask:
                    continue

                try:
                    network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                except ValueError:
                    continue

                if not network.is_private:
                    continue

                score = 0
                if stat and stat.isup:
                    score += 100
                if not is_virtual:
                    score += 50
                if any(token in lowered_name for token in ("wi-fi", "wifi", "wireless")):
                    score += 20
                if any(token in lowered_name for token in ("ethernet", "lan")):
                    score += 20
                if network.prefixlen >= 24:
                    score += 5

                candidates.append(
                    {
                        "name": name,
                        "ip": ip,
                        "network": network,
                        "score": score,
                    }
                )

        candidates.sort(key=lambda item: int(item["score"]), reverse=True)
        return candidates

    def _is_virtual_interface(self, name: str) -> bool:
        lowered_name = name.lower()
        return any(keyword in lowered_name for keyword in VIRTUAL_INTERFACE_KEYWORDS)

    def scan(self, target: str, mode: str = "balanced", progress_callback=None, should_cancel=None) -> list[Device]:
        hosts = self._expand_hosts(target)
        if should_cancel and should_cancel():
            return []
        self._warm_arp_cache(hosts, mode, should_cancel)
        arp_cache = self._load_arp_cache()
        active_devices: list[Device] = []
        max_workers = min(96, max(8, len(hosts)))
        executor = ThreadPoolExecutor(max_workers=max_workers)
        try:
            future_map = {executor.submit(self._probe_host, ip, mode, arp_cache): ip for ip in hosts}
            completed_count = 0
            for future in as_completed(future_map):
                if should_cancel and should_cancel():
                    for pending in future_map:
                        pending.cancel()
                    executor.shutdown(wait=False, cancel_futures=True)
                    return sorted(active_devices, key=lambda item: tuple(int(part) for part in item.ip_address.split(".")))
                device = future.result()
                if device is not None:
                    active_devices.append(device)
                completed_count += 1
                if progress_callback is not None:
                    progress_callback(completed_count, len(hosts), len(active_devices), future_map[future])
        finally:
            try:
                executor.shutdown(wait=True, cancel_futures=False)
            except Exception:
                pass

        if not active_devices:
            refreshed_cache = self._load_arp_cache()
            for ip_address in hosts:
                if should_cancel and should_cancel():
                    break
                if ip_address in refreshed_cache:
                    active_devices.append(self._build_device_from_cache(ip_address, refreshed_cache[ip_address], "ARP cache"))

        unique_devices = {device.ip_address: device for device in active_devices}
        return sorted(unique_devices.values(), key=lambda item: tuple(int(part) for part in item.ip_address.split(".")))

    def _expand_hosts(self, target: str) -> list[str]:
        target = target.strip()
        if not target:
            raise ValueError("Please enter an IP range or a CIDR network.")
        if "-" in target and "/" not in target:
            start_ip, end_ip = [part.strip() for part in target.split("-", maxsplit=1)]
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            if int(end) < int(start):
                raise ValueError("The IP range is invalid.")
            host_count = int(end) - int(start) + 1
            if host_count > 254:
                raise ValueError("To keep the app responsive, limit the scan to 254 hosts.")
            return [str(ipaddress.ip_address(int(start) + offset)) for offset in range(host_count)]
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(host) for host in network.hosts()]
        if len(hosts) > 254:
            raise ValueError("To keep the app responsive, limit the scan to a /24 maximum.")
        return hosts

    def _warm_arp_cache(self, hosts: list[str], mode: str, should_cancel=None) -> None:
        timeout_ms = SCAN_MODES.get(mode, SCAN_MODES["balanced"])["ping_timeout_ms"]
        max_workers = min(64, max(4, len(hosts)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(self._run_ping, ip, timeout_ms): ip for ip in hosts}
            for future in as_completed(future_map):
                if should_cancel and should_cancel():
                    for pending in future_map:
                        pending.cancel()
                    break
                try:
                    future.result()
                except Exception:
                    continue

    def _probe_host(self, ip_address: str, mode: str, arp_cache: dict[str, str]) -> Device | None:
        config = SCAN_MODES.get(mode, SCAN_MODES["balanced"])
        ping_completed = self._run_ping(ip_address, int(config["ping_timeout_ms"]))
        ping_ok = ping_completed.returncode == 0

        hostname = self._lookup_hostname(ip_address, ping_completed.stdout if ping_ok else "")
        arp_mac = arp_cache.get(ip_address, "")
        tcp_details = self._tcp_probe(ip_address, list(config["tcp_ports"]), float(config["tcp_timeout"]))

        active = ping_ok or bool(arp_mac) or bool(tcp_details)
        if not active:
            return None

        mac_address = arp_mac or self._lookup_mac(ip_address)
        vendor = self._infer_vendor(mac_address)
        discovery_method = self._build_discovery_method(ping_ok, bool(arp_mac), tcp_details)
        device_type, os_guess = self._fingerprint_device(
            ip_address,
            hostname,
            vendor,
            tcp_details,
            mac_address or "Unknown",
        )
        return Device(
            ip_address=ip_address,
            mac_address=mac_address or "Unknown",
            hostname=hostname,
            status="active",
            last_seen=utc_now(),
            is_known=(hostname != "Unknown") or bool(mac_address),
            vendor=vendor,
            discovery_method=discovery_method,
            device_type=device_type,
            os_guess=os_guess,
        )

    def _run_ping(self, ip_address: str, timeout_ms: int) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip_address],
            capture_output=True,
            text=True,
            check=False,
        )

    def _lookup_hostname(self, ip_address: str, ping_stdout: str = "") -> str:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            if hostname:
                return hostname
        except OSError:
            pass

        if ping_stdout:
            match = PING_HOSTNAME_PATTERN.search(ping_stdout)
            if match:
                candidate = match.group(1).strip()
                if candidate and candidate.lower() != ip_address.lower():
                    return candidate

        completed = subprocess.run(
            ["ping", "-a", "-n", "1", "-w", "300", ip_address],
            capture_output=True,
            text=True,
            check=False,
        )
        match = PING_HOSTNAME_PATTERN.search(completed.stdout)
        if match:
            candidate = match.group(1).strip()
            if candidate and candidate.lower() != ip_address.lower():
                return candidate
        return "Unknown"

    def _load_arp_cache(self) -> dict[str, str]:
        completed = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            check=False,
        )
        cache: dict[str, str] = {}
        for line in completed.stdout.splitlines():
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            mac_match = MAC_PATTERN.search(line)
            if ip_match and mac_match:
                cache[ip_match.group(1)] = mac_match.group(1).replace(":", "-").upper()
        return cache

    def _lookup_mac(self, ip_address: str) -> str:
        completed = subprocess.run(
            ["arp", "-a", ip_address],
            capture_output=True,
            text=True,
            check=False,
        )
        match = MAC_PATTERN.search(completed.stdout)
        if not match:
            return "Unknown"
        return match.group(1).replace(":", "-").upper()

    def _tcp_probe(self, ip_address: str, ports: list[int], timeout: float) -> list[int]:
        open_ports: list[int] = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    if sock.connect_ex((ip_address, port)) == 0:
                        open_ports.append(port)
            except OSError:
                continue
        return open_ports

    def _infer_vendor(self, mac_address: str) -> str:
        if not mac_address or mac_address == "Unknown":
            return "Unknown"
        oui = mac_address.upper().replace(":", "-")[:8]
        if oui in OUI_VENDOR_MAP:
            return OUI_VENDOR_MAP[oui]
        if self._is_randomized_mac(mac_address):
            return "Private / Randomized MAC"
        return "Unknown"

    def _build_discovery_method(self, ping_ok: bool, arp_ok: bool, tcp_ports: list[int]) -> str:
        methods: list[str] = []
        if ping_ok:
            methods.append("Ping")
        if arp_ok:
            methods.append("ARP")
        if tcp_ports:
            methods.append("TCP:" + ",".join(str(port) for port in tcp_ports[:3]))
        return " + ".join(methods) if methods else "Unknown"

    def _build_device_from_cache(self, ip_address: str, mac_address: str, method: str) -> Device:
        hostname = self._lookup_hostname(ip_address)
        vendor = self._infer_vendor(mac_address)
        device_type, os_guess = self._fingerprint_device(ip_address, hostname, vendor, [], mac_address)
        return Device(
            ip_address=ip_address,
            mac_address=mac_address,
            hostname=hostname,
            status="active",
            last_seen=utc_now(),
            is_known=(hostname != "Unknown") or (mac_address != "Unknown"),
            vendor=vendor,
            discovery_method=method,
            device_type=device_type,
            os_guess=os_guess,
        )

    def refine_device_with_services(self, device: Device, port_results: list[object]) -> Device:
        services = {getattr(result, "service", "Unknown") for result in port_results}
        banners = " ".join(getattr(result, "banner", "") for result in port_results).lower()
        ports = {int(getattr(result, "port", 0)) for result in port_results}

        device_type = device.device_type
        os_guess = device.os_guess

        if {"SMB", "RDP"} & services or {445, 3389} & ports:
            device_type = "Workstation" if device_type == "Unknown" else device_type
            os_guess = "Windows"
        if {"SMTP", "POP3", "IMAP"} & services:
            device_type = "Server"
            if os_guess == "Unknown":
                os_guess = "Linux"
        if "OpenSSH".lower() in banners or 22 in ports:
            if device_type == "Unknown":
                device_type = "Server"
            if os_guess == "Unknown":
                os_guess = "Linux"
        if any(keyword in banners for keyword in ["microsoft", "windows", "iis"]):
            device_type = "Workstation" if device_type == "Unknown" else device_type
            os_guess = "Windows"
        if any(keyword in banners for keyword in ["ubuntu", "debian", "nginx", "apache", "openssh", "linux"]):
            device_type = "Server" if device_type == "Unknown" else device_type
            os_guess = "Linux"
        if any(keyword in banners for keyword in ["mikrotik", "routeros", "openwrt", "ubnt", "ubiquiti"]) or (
            {"DNS", "HTTP"} <= services or {"DNS", "HTTPS"} <= services
        ):
            device_type = "Router"
            os_guess = "Network OS"
        if device.ip_address.endswith(".1") and ({80, 443, 53} & ports):
            device_type = "Router"
            if os_guess == "Unknown":
                os_guess = "Network OS"
        if device.vendor == "Private / Randomized MAC" and not ports:
            device_type = "Mobile" if device_type == "Unknown" else device_type
            os_guess = "Android/iOS" if os_guess == "Unknown" else os_guess
        if any(keyword in banners for keyword in ["android", "samsung", "xiaomi"]) and device_type == "Unknown":
            device_type = "Mobile"
            os_guess = "Android"
        if "apple" in device.vendor.lower() and device_type == "Unknown":
            if any(keyword in banners for keyword in ["iphone", "ipad", "ios"]):
                device_type = "Mobile"
                os_guess = "iOS"
            elif os_guess == "Unknown":
                os_guess = "macOS"
        return Device(
            ip_address=device.ip_address,
            mac_address=device.mac_address,
            hostname=device.hostname,
            status=device.status,
            last_seen=device.last_seen,
            is_known=device.is_known,
            vendor=device.vendor,
            discovery_method=device.discovery_method,
            device_type=device_type,
            os_guess=os_guess,
        )

    def _fingerprint_device(
        self,
        ip_address: str,
        hostname: str,
        vendor: str,
        open_ports: list[int],
        mac_address: str,
    ) -> tuple[str, str]:
        host = hostname.lower()
        vendor_lower = vendor.lower()
        ports = set(open_ports)
        is_gateway_candidate = ip_address.endswith(".1") or ip_address.endswith(".254")
        is_random_mac = self._is_randomized_mac(mac_address)

        if any(keyword in host for keyword in ["iphone", "ipad", "ios"]):
            return "Mobile", "iOS"
        if any(keyword in host for keyword in ["android", "galaxy", "redmi", "xiaomi", "huawei-mobile"]):
            return "Mobile", "Android"
        if "apple" in vendor_lower:
            if any(keyword in host for keyword in ["iphone", "ipad"]):
                return "Mobile", "iOS"
            if any(keyword in host for keyword in ["macbook", "imac", "mac"]):
                return "Workstation", "macOS"
        if any(keyword in host for keyword in ["windows", "desktop-", "win-", "pc-", "laptop-"]) or {445, 3389} & ports:
            return "Workstation", "Windows"
        if any(keyword in host for keyword in ["ubuntu", "debian", "linux", "raspberry", "pi-", "server"]) or 22 in ports:
            return ("Server" if 22 in ports else "Workstation", "Linux")
        if any(keyword in host for keyword in ["router", "gateway", "ap", "wifi", "tplink", "cisco", "ubiquiti"]):
            return "Router", "Network OS"
        if is_gateway_candidate and ({80, 443} & ports or 53 in ports):
            return "Router", "Network OS"
        if vendor in {"Cisco", "TP-Link", "Ubiquiti"} or ({53, 80} <= ports) or ({53, 443} <= ports):
            return "Router", "Network OS"
        if ports and ports.issubset({80, 443}) and not ({445, 3389, 22} & ports):
            return ("Router" if is_gateway_candidate else "IoT"), ("Network OS" if is_gateway_candidate else "Embedded Linux")
        if any(keyword in vendor_lower for keyword in ["samsung", "xiaomi", "huawei", "google"]):
            return "Mobile", "Android"
        if vendor == "Raspberry Pi":
            return "IoT", "Linux"
        if is_random_mac and hostname == "Unknown" and not ports:
            return "Mobile", "Android/iOS"
        if is_random_mac and ports.issubset({80, 443}) and ports:
            return "Mobile", "Android/iOS"
        return "Unknown", "Unknown"

    def _is_randomized_mac(self, mac_address: str) -> bool:
        if not mac_address or mac_address == "Unknown":
            return False
        try:
            first_octet = int(mac_address.replace(":", "-").split("-")[0], 16)
        except ValueError:
            return False
        return bool(first_octet & 0b00000010)
