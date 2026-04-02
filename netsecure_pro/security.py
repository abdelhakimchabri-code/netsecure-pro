from __future__ import annotations

from .models import Alert, Device, MonitoringSnapshot, PortScanResult, SecurityAssessment, SecuritySettings


class SecurityAnalyzer:
    def assess(
        self,
        devices: list[Device],
        port_results: list[PortScanResult],
        monitoring_snapshot: MonitoringSnapshot | None = None,
        settings: SecuritySettings | None = None,
    ) -> SecurityAssessment:
        settings = settings or SecuritySettings()
        score = 100
        observations: list[str] = []
        recommendations: list[str] = []
        risk_factors: list[str] = []

        port_map = self._port_map(port_results)
        device_map = {device.ip_address: device for device in devices}
        unknown_devices = [device for device in devices if not device.is_known]
        dangerous_ports = [result for result in port_results if result.port in {23, 445, 3389}]
        insecure_services = [
            result for result in port_results if result.service in {"FTP", "Telnet", "POP3", "IMAP", "NetBIOS"}
        ]
        host_count = len(devices)

        router_telnet_hosts = [
            ip_address
            for ip_address, results in port_map.items()
            if device_map.get(ip_address, Device(ip_address, "", "")).device_type == "Router"
            and any(result.port == 23 or result.service == "Telnet" for result in results)
        ]
        exposed_admin_hosts = [
            ip_address
            for ip_address, results in port_map.items()
            if {445, 3389}.issubset({result.port for result in results})
        ]
        plaintext_web_hosts = [
            ip_address
            for ip_address, results in port_map.items()
            if 80 in {result.port for result in results} and 443 not in {result.port for result in results}
        ]
        unknown_high_risk_hosts = [
            device.ip_address
            for device in unknown_devices
            if any(result.risk_level in {"Critical", "High"} for result in port_map.get(device.ip_address, []))
        ]

        if dangerous_ports:
            score -= min(40, len(dangerous_ports) * 10)
            risk_factors.append(f"{len(dangerous_ports)} high-risk port(s) exposed")
            observations.append("High-risk ports were detected on the network.")
            self._append_unique(recommendations, "Close or filter unnecessary RDP, SMB, and Telnet services.")

        if insecure_services:
            score -= min(30, len(insecure_services) * 8)
            risk_factors.append(f"{len(insecure_services)} insecure service(s) detected")
            observations.append("Services using weak protocols are still active.")
            self._append_unique(recommendations, "Replace weak protocols with encrypted alternatives.")

        if router_telnet_hosts:
            score -= min(25, 12 + (len(router_telnet_hosts) * 4))
            risk_factors.append(f"Router management over Telnet detected on {len(router_telnet_hosts)} host(s)")
            observations.append("At least one router exposes Telnet for remote administration.")
            self._append_unique(recommendations, "Disable Telnet on routers and use encrypted administration channels such as HTTPS or SSH.")

        if exposed_admin_hosts:
            score -= min(24, 10 + (len(exposed_admin_hosts) * 4))
            risk_factors.append(f"Windows administrative exposure detected on {len(exposed_admin_hosts)} host(s)")
            observations.append("Some hosts expose SMB and RDP together, which increases administrative attack surface.")
            self._append_unique(recommendations, "Restrict SMB and RDP exposure to trusted admin segments or VPN access only.")

        if plaintext_web_hosts:
            score -= min(12, len(plaintext_web_hosts) * 3)
            risk_factors.append(f"Unencrypted web management detected on {len(plaintext_web_hosts)} host(s)")
            observations.append("HTTP is exposed without a matching HTTPS service on one or more hosts.")
            self._append_unique(recommendations, "Enable HTTPS for administrative web services and disable plain HTTP when possible.")

        if unknown_devices:
            score -= min(20, len(unknown_devices) * 5)
            risk_factors.append(f"{len(unknown_devices)} unknown device(s)")
            observations.append("Some devices could not be clearly identified.")
            self._append_unique(recommendations, "Review unknown devices and update the network inventory.")

        if unknown_high_risk_hosts:
            score -= min(18, 6 + (len(unknown_high_risk_hosts) * 4))
            risk_factors.append(f"Unknown devices with high-risk exposure detected on {len(unknown_high_risk_hosts)} host(s)")
            observations.append("At least one unknown device exposes high-risk services or ports.")
            self._append_unique(recommendations, "Isolate or inspect unknown devices that expose critical or high-risk services.")

        if monitoring_snapshot and monitoring_snapshot.total_bandwidth_bps > settings.bandwidth_alert_threshold_bps:
            overload_ratio = monitoring_snapshot.total_bandwidth_bps / max(settings.bandwidth_alert_threshold_bps, 1)
            bandwidth_penalty = min(20, max(10, int(overload_ratio * 6)))
            score -= bandwidth_penalty
            risk_factors.append(
                "High bandwidth spike "
                f"({monitoring_snapshot.total_bandwidth_bps / (1024 * 1024):.2f} MB/s)"
            )
            observations.append(
                "Current network traffic exceeds the configured critical threshold "
                f"({settings.bandwidth_alert_threshold_bps / (1024 * 1024):.2f} MB/s)."
            )
            self._append_unique(recommendations, "Monitor traffic spikes and verify unexpected flows.")

        if 1 <= host_count <= settings.managed_hosts_limit:
            score += 10
            observations.append(
                "The number of detected hosts remains within the managed range "
                f"({host_count}/{settings.managed_hosts_limit})."
            )
        elif settings.managed_hosts_limit < host_count <= settings.large_network_threshold:
            overflow = host_count - settings.managed_hosts_limit
            score -= min(18, 6 + overflow)
            risk_factors.append(
                "The number of hosts exceeds the managed limit "
                f"({host_count}>{settings.managed_hosts_limit})"
            )
            observations.append("The network contains more devices than the managed limit defined in the settings.")
            self._append_unique(recommendations, "Verify that all detected devices are expected, or raise the managed network limit.")
        elif host_count > settings.large_network_threshold:
            overflow = host_count - settings.large_network_threshold
            score -= min(30, 14 + overflow)
            risk_factors.append(
                "Large number of hosts in the local network "
                f"({host_count}>{settings.large_network_threshold})"
            )
            observations.append("The network exceeded the configured large-network threshold.")
            self._append_unique(recommendations, "Segment the network, review the inventory, and adjust the large-network threshold if needed.")

        if devices:
            score += 5
        else:
            observations.append("No active hosts were detected during the latest analysis cycle.")

        score = max(0, min(100, score))
        if score >= 80:
            label = "Secure Network"
        elif score >= 50:
            label = "Moderately Secure Network"
        else:
            label = "At-Risk Network"

        if not observations:
            observations.append("No major risk indicators were detected during this cycle.")
        if not recommendations:
            recommendations.append("Maintain regular network monitoring and security updates.")

        return SecurityAssessment(
            score=score,
            label=label,
            observations=observations,
            recommendations=recommendations,
            risk_factors=risk_factors,
        )

    def generate_alerts(
        self,
        devices: list[Device],
        port_results: list[PortScanResult],
        known_ips: set[str] | None = None,
        monitoring_snapshot: MonitoringSnapshot | None = None,
        settings: SecuritySettings | None = None,
    ) -> list[Alert]:
        alerts: list[Alert] = []
        known_ips = known_ips or set()
        settings = settings or SecuritySettings()
        host_count = len(devices)
        port_map = self._port_map(port_results)
        device_map = {device.ip_address: device for device in devices}

        for device in devices:
            if device.ip_address not in known_ips:
                alerts.append(
                    Alert(
                        type_alert="New Device",
                        description=f"New device detected on the network: {device.ip_address}",
                        severity="Medium",
                    )
                )
            if not device.is_known:
                alerts.append(
                    Alert(
                        type_alert="Unknown Device",
                        description=f"Host {device.ip_address} could not be clearly identified.",
                        severity="Medium",
                    )
                )

        for result in port_results:
            if result.service == "Telnet":
                alerts.append(
                    Alert(
                        type_alert="Insecure Service",
                        description=f"The Telnet service is active on {result.device_ip}:{result.port}.",
                        severity="Critical",
                    )
                )
            elif result.service == "FTP":
                alerts.append(
                    Alert(
                        type_alert="Insecure Service",
                        description=f"The FTP service is active on {result.device_ip}:{result.port}.",
                        severity="High",
                    )
                )
            elif result.port in {445, 3389}:
                alerts.append(
                    Alert(
                        type_alert="Sensitive Port",
                        description=f"Port {result.port} ({result.service}) is exposed on {result.device_ip}.",
                        severity="High",
                    )
                )

        for ip_address, results in port_map.items():
            ports = {result.port for result in results}
            device = device_map.get(ip_address)
            if device and device.device_type == "Router" and 23 in ports:
                alerts.append(
                    Alert(
                        type_alert="Insecure Router Management",
                        description=f"Router {ip_address} exposes Telnet remote administration.",
                        severity="Critical",
                    )
                )
            if {445, 3389}.issubset(ports):
                alerts.append(
                    Alert(
                        type_alert="Exposed Admin Surface",
                        description=f"Host {ip_address} exposes SMB and RDP together.",
                        severity="High",
                    )
                )
            if 80 in ports and 443 not in ports:
                alerts.append(
                    Alert(
                        type_alert="Unencrypted Web Service",
                        description=f"Host {ip_address} exposes HTTP without HTTPS.",
                        severity="Medium",
                    )
                )
            if device and not device.is_known and any(result.risk_level in {"Critical", "High"} for result in results):
                alerts.append(
                    Alert(
                        type_alert="Unknown High-Risk Device",
                        description=f"Unknown host {ip_address} exposes high-risk services.",
                        severity="High",
                    )
                )

        if settings.managed_hosts_limit < host_count <= settings.large_network_threshold:
            alerts.append(
                Alert(
                    type_alert="Network Capacity",
                    description=(
                        f"The number of detected hosts ({host_count}) exceeds the managed limit "
                        f"({settings.managed_hosts_limit})."
                    ),
                    severity="Medium",
                )
            )
        elif host_count > settings.large_network_threshold:
            alerts.append(
                Alert(
                    type_alert="Large Network",
                    description=(
                        f"The number of detected hosts ({host_count}) exceeds the large-network threshold "
                        f"({settings.large_network_threshold})."
                    ),
                    severity="High",
                )
            )

        if monitoring_snapshot and monitoring_snapshot.total_bandwidth_bps > settings.bandwidth_alert_threshold_bps:
            overload_ratio = monitoring_snapshot.total_bandwidth_bps / max(settings.bandwidth_alert_threshold_bps, 1)
            severity = "Critical" if overload_ratio >= 1.5 else "High"
            alerts.append(
                Alert(
                    type_alert="Traffic Spike",
                    description=(
                        f"Interface {monitoring_snapshot.interface} exceeds the threshold of "
                        f"{settings.bandwidth_alert_threshold_bps / (1024 * 1024):.2f} MB/s "
                        f"with {monitoring_snapshot.total_bandwidth_bps / (1024 * 1024):.2f} MB/s."
                    ),
                    severity=severity,
                )
            )

        return alerts

    def _append_unique(self, items: list[str], value: str) -> None:
        if value not in items:
            items.append(value)

    def _port_map(self, port_results: list[PortScanResult]) -> dict[str, list[PortScanResult]]:
        mapping: dict[str, list[PortScanResult]] = {}
        for result in port_results:
            mapping.setdefault(result.device_ip, []).append(result)
        return mapping
