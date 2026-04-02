from __future__ import annotations

import json
import re
from urllib import error, request

from .models import Alert, Device, PortScanResult, SecurityAssessment


class OpenRouterAssistant:
    endpoint = "https://openrouter.ai/api/v1/chat/completions"

    def __init__(self, app_name: str = "NetSecure Pro") -> None:
        self.app_name = app_name

    def analyze_network(
        self,
        api_key: str,
        model: str,
        mode: str,
        question: str,
        devices: list[Device],
        port_results: list[PortScanResult],
        assessment: SecurityAssessment,
        alerts: list[Alert],
        company_profile: dict[str, str] | None = None,
        conversation_history: list[dict[str, str]] | None = None,
        comparison_summary: str = "",
    ) -> str:
        api_key = api_key.strip()
        model = model.strip() or "openai/gpt-4o-mini"
        mode = mode.strip() or "scan-aware"
        question = question.strip() or "Analyze this network and tell me the most important risks and actions."
        response_language = self._detect_response_language(question)
        if not api_key:
            raise ValueError("OpenRouter API key is required.")

        payload = {
            "model": model,
            "temperature": 0.2,
            "messages": self._build_messages(
                model,
                mode,
                question,
                response_language,
                devices,
                port_results,
                assessment,
                alerts,
                company_profile or {},
                conversation_history or [],
                comparison_summary,
            ),
        }

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://netsecure-pro.local",
            "X-Title": self.app_name,
        }
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(self.endpoint, data=body, headers=headers, method="POST")

        try:
            with request.urlopen(req, timeout=45) as response:
                raw = response.read().decode("utf-8")
        except error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"OpenRouter HTTP {exc.code}: {details}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"OpenRouter connection error: {exc.reason}") from exc

        data = json.loads(raw)
        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError("OpenRouter returned no choices.")
        message = choices[0].get("message") or {}
        content = message.get("content")
        if isinstance(content, list):
            chunks = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    chunks.append(item.get("text", ""))
            content = "\n".join(chunk for chunk in chunks if chunk)
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("OpenRouter returned an empty response.")
        return content.strip()

    def _build_messages(
        self,
        model: str,
        mode: str,
        question: str,
        response_language: str,
        devices: list[Device],
        port_results: list[PortScanResult],
        assessment: SecurityAssessment,
        alerts: list[Alert],
        company_profile: dict[str, str],
        conversation_history: list[dict[str, str]],
        comparison_summary: str,
    ) -> list[dict[str, str]]:
        messages = [
            {"role": "system", "content": self._system_prompt_for_mode(mode)},
            {
                "role": "user",
                "content": self._build_context_prompt(
                    mode,
                    response_language,
                    devices,
                    port_results,
                    assessment,
                    alerts,
                    company_profile,
                    comparison_summary,
                ),
            },
        ]
        if self._supports_history(model):
            messages.extend(self._sanitize_history(conversation_history))
        messages.append({"role": "user", "content": question})
        return messages

    def _build_context_prompt(
        self,
        mode: str,
        response_language: str,
        devices: list[Device],
        port_results: list[PortScanResult],
        assessment: SecurityAssessment,
        alerts: list[Alert],
        company_profile: dict[str, str],
        comparison_summary: str,
    ) -> str:
        if mode == "general":
            return self._build_general_prompt(
                response_language,
                devices,
                port_results,
                assessment,
                alerts,
                company_profile,
                comparison_summary,
            )
        return self._build_scan_aware_prompt(
            response_language,
            devices,
            port_results,
            assessment,
            alerts,
            company_profile,
            comparison_summary,
        )

    def _system_prompt_for_mode(self, mode: str) -> str:
        if mode == "general":
            return (
                "You are a defensive cybersecurity and network administration assistant embedded in a desktop app. "
                "You can answer general questions about ports, firewalls, IP blocking, service hardening, monitoring, "
                "incident triage, and secure administration. "
                "Stay practical, accurate, and defensive only. Do not help with intrusion, bypass, exploitation, malware, "
                "credential theft, or unauthorized access. "
                "Answer in the same language as the user's question. If the question is in Darija, answer in clear Moroccan Darija."
            )
        return (
            "You are a cybersecurity network analyst embedded in a desktop monitoring app. "
            "You must answer ONLY from the provided network data. "
            "Do not invent devices, ports, vendors, incidents, attacks, CVEs, or recommendations that are not supported "
            "by the scan results. If data is missing, explicitly say that the current scan does not provide enough evidence. "
            "Always cite exact IPs, ports, services, alert names, and score values when relevant. "
            "Answer in the same language as the user's question. If the question is in Darija, answer in clear Moroccan Darija."
        )

    def _build_general_prompt(
        self,
        response_language: str,
        devices: list[Device],
        port_results: list[PortScanResult],
        assessment: SecurityAssessment,
        alerts: list[Alert],
        company_profile: dict[str, str],
        comparison_summary: str,
    ) -> str:
        company_name = company_profile.get("company_name", "NetSecure Pro")
        language_instruction = self._language_instruction(response_language)
        lines = [
            f"Company: {company_name}",
            f"Response language: {response_language}",
            "",
            "Current app context (optional, use only if relevant to the user's question):",
            f"- Active devices: {len(devices)}",
            f"- Open ports: {len(port_results)}",
            f"- Alerts: {len(alerts)}",
            f"- Security score: {assessment.score}/100",
        ]
        if comparison_summary:
            lines.append(f"- Latest scan comparison: {comparison_summary}")
        lines.extend(
            [
                "",
                "Important response rules:",
                "- Answer as a defensive network/security assistant.",
                "- Give practical steps, explanations, and safe admin guidance.",
                "- If the user refers to the current scan but the question is vague, say that Scan-Aware mode will give a more precise answer.",
                f"- {language_instruction}",
                "",
                "Preferred answer format: 1) Direct answer 2) Steps 3) Admin tip.",
            ]
        )
        return "\n".join(lines)

    def _build_scan_aware_prompt(
        self,
        response_language: str,
        devices: list[Device],
        port_results: list[PortScanResult],
        assessment: SecurityAssessment,
        alerts: list[Alert],
        company_profile: dict[str, str],
        comparison_summary: str,
    ) -> str:
        company_name = company_profile.get("company_name", "NetSecure Pro")
        department = company_profile.get("department", "Security Operations Center")
        site = company_profile.get("site", "Head Office")

        risky_ports = [result for result in port_results if result.risk_level in {"Critical", "High"}]
        recent_alerts = alerts[:12]
        top_devices = devices[:20]
        top_ports = port_results[:40]
        suspicious_devices = self._rank_suspicious_devices(devices, port_results, alerts)[:8]
        language_instruction = self._language_instruction(response_language)

        lines = [
            f"Company: {company_name}",
            f"Department: {department}",
            f"Site: {site}",
            f"Response language: {response_language}",
            "",
            "Current network summary:",
            f"- Active devices: {len(devices)}",
            f"- Open ports found: {len(port_results)}",
            f"- High/Critical ports: {len(risky_ports)}",
            f"- Security score: {assessment.score}/100",
            f"- Security label: {assessment.label}",
        ]
        if comparison_summary:
            lines.append(f"- Latest comparison: {comparison_summary}")
        lines.extend([
            "",
            "Observations:",
        ])
        lines.extend(f"- {item}" for item in assessment.observations[:8])
        lines.append("")
        lines.append("Recommendations already generated by the app:")
        lines.extend(f"- {item}" for item in assessment.recommendations[:8])
        lines.append("")
        lines.append("Detected devices:")
        if top_devices:
            for device in top_devices:
                lines.append(
                    f"- {device.ip_address} | Hostname={device.hostname} | Type={device.device_type} | "
                    f"OS={device.os_guess} | Vendor={device.vendor} | Method={device.discovery_method} | "
                    f"Known={'Yes' if device.is_known else 'No'}"
                )
        else:
            lines.append("- No devices detected.")

        lines.append("")
        lines.append("Most suspicious devices according to the current scan:")
        if suspicious_devices:
            for item in suspicious_devices:
                lines.append(f"- {item}")
        else:
            lines.append("- No suspicious-device ranking available.")

        lines.append("")
        lines.append("Open port results:")
        if top_ports:
            for result in top_ports:
                banner = f" | Banner={result.banner[:60]}" if result.banner else ""
                lines.append(
                    f"- {result.device_ip}:{result.port} | Service={result.service} | Risk={result.risk_level}{banner}"
                )
        else:
            lines.append("- No port scan results available.")

        lines.append("")
        lines.append("Recent alerts:")
        if recent_alerts:
            for alert in recent_alerts:
                lines.append(f"- [{alert.severity}] {alert.type_alert}: {alert.description}")
        else:
            lines.append("- No recent alerts.")

        lines.append("")
        lines.append("Important response rules:")
        lines.append("- Use only the data listed above.")
        lines.append("- If the answer is uncertain, say that the current scan is insufficient.")
        lines.append("- Mention exact IPs and ports when naming risks.")
        lines.append("- If no device clearly matches the question, say so explicitly.")
        lines.append(f"- {language_instruction}")
        lines.append("")
        lines.append(
            "Please answer with these sections: 1) Overall assessment 2) Top risks 3) Most suspicious device(s) "
            "4) Immediate actions 5) Short admin note."
        )
        return "\n".join(lines)

    def _sanitize_history(self, conversation_history: list[dict[str, str]]) -> list[dict[str, str]]:
        sanitized: list[dict[str, str]] = []
        for item in conversation_history[-8:]:
            role = item.get("role", "").strip()
            content = item.get("content", "").strip()
            if role not in {"user", "assistant"} or not content:
                continue
            sanitized.append({"role": role, "content": content[:4000]})
        return sanitized

    def _supports_history(self, model: str) -> bool:
        return bool(model.strip())

    def _rank_suspicious_devices(
        self,
        devices: list[Device],
        port_results: list[PortScanResult],
        alerts: list[Alert],
    ) -> list[str]:
        port_map: dict[str, list[PortScanResult]] = {}
        for result in port_results:
            port_map.setdefault(result.device_ip, []).append(result)

        alert_map: dict[str, int] = {}
        for alert in alerts:
            for device in devices:
                if device.ip_address in alert.description:
                    alert_map[device.ip_address] = alert_map.get(device.ip_address, 0) + 1

        ranked: list[tuple[int, str]] = []
        for device in devices:
            device_ports = port_map.get(device.ip_address, [])
            risky_count = sum(1 for result in device_ports if result.risk_level in {"Critical", "High"})
            unknown_bonus = 2 if not device.is_known else 0
            alert_count = alert_map.get(device.ip_address, 0)
            score = risky_count * 3 + unknown_bonus + alert_count
            if score <= 0 and not device_ports and device.is_known:
                continue

            service_text = ", ".join(
                f"{result.port}/{result.service}" for result in device_ports[:4]
            ) or "no open ports recorded"
            summary = (
                f"{device.ip_address} | type={device.device_type} | os={device.os_guess} | "
                f"known={'No' if not device.is_known else 'Yes'} | risky_ports={risky_count} | "
                f"alerts={alert_count} | services={service_text}"
            )
            ranked.append((score, summary))

        ranked.sort(key=lambda item: item[0], reverse=True)
        return [summary for _, summary in ranked]

    def _detect_response_language(self, question: str) -> str:
        text = question.strip().lower()
        if not text:
            return "English"
        if re.search(r"[\u0600-\u06FF]", question):
            return "Arabic"

        darija_tokens = {
            "chno", "wach", "bghit", "kifach", "daba", "3la", "3and", "fin",
            "machi", "rah", "ana", "ndir", "n9ra", "mzyan", "safi", "kayna", "kayn",
            "bzaaf", "l3ib", "kats", "kat", "ha9i9i",
        }
        french_tokens = {
            "analyse", "reseau", "risque", "securite", "pourquoi", "comment", "bonjour",
            "merci", "appareil", "ports", "alertes", "donne", "donnees", "quelle", "quels",
        }
        english_tokens = {
            "analyze", "network", "risk", "security", "device", "devices", "what", "why",
            "how", "which", "alerts", "ports", "host", "hosts",
        }

        words = set(re.findall(r"[a-z0-9']+", text))
        if words & darija_tokens:
            return "Darija"
        if words & french_tokens:
            return "French"
        if words & english_tokens:
            return "English"
        return "English"

    def _language_instruction(self, response_language: str) -> str:
        instructions = {
            "Arabic": "Write in Arabic only.",
            "Darija": "Write in Moroccan Darija using clear, simple wording.",
            "French": "Write in French only.",
            "English": "Write in English only.",
        }
        return instructions.get(response_language, "Write in the user's language.")
