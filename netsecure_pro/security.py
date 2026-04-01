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

        unknown_devices = [device for device in devices if not device.is_known]
        dangerous_ports = [result for result in port_results if result.port in {23, 445, 3389}]
        insecure_services = [
            result for result in port_results if result.service in {"FTP", "Telnet", "POP3", "IMAP", "NetBIOS"}
        ]
        host_count = len(devices)

        if dangerous_ports:
            score -= min(40, len(dangerous_ports) * 10)
            risk_factors.append(f"{len(dangerous_ports)} high-risk port(s) exposed")
            observations.append("High-risk ports were detected on the network.")
            recommendations.append("Close or filter unnecessary RDP, SMB, and Telnet services.")

        if insecure_services:
            score -= min(30, len(insecure_services) * 8)
            risk_factors.append(f"{len(insecure_services)} insecure service(s) detected")
            observations.append("Services using weak protocols are still active.")
            recommendations.append("Replace weak protocols with encrypted alternatives.")

        if unknown_devices:
            score -= min(20, len(unknown_devices) * 5)
            risk_factors.append(f"{len(unknown_devices)} unknown device(s)")
            observations.append("Some devices could not be clearly identified.")
            recommendations.append("Review unknown devices and update the network inventory.")

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
            recommendations.append("Monitor traffic spikes and verify unexpected flows.")

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
            observations.append(
                "The network contains more devices than the managed limit defined in the settings."
            )
            recommendations.append(
                "Verify that all detected devices are expected, or raise the managed network limit."
            )
        elif host_count > settings.large_network_threshold:
            overflow = host_count - settings.large_network_threshold
            score -= min(30, 14 + overflow)
            risk_factors.append(
                "Large number of hosts in the local network "
                f"({host_count}>{settings.large_network_threshold})"
            )
            observations.append("The network exceeded the configured large-network threshold.")
            recommendations.append(
                "Segment the network, review the inventory, and adjust the large-network threshold if needed."
            )

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
