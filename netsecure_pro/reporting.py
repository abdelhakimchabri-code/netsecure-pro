from __future__ import annotations

from datetime import datetime
from pathlib import Path
from textwrap import wrap

from .models import Alert, Device, PortScanResult, SecurityAssessment


class ReportGenerator:
    PAGE_WIDTH = 595.0
    PAGE_HEIGHT = 842.0
    MARGIN_X = 42.0
    CONTENT_WIDTH = PAGE_WIDTH - (MARGIN_X * 2)
    TOP_Y = 798.0
    BOTTOM_Y = 64.0

    COLORS = {
        "navy": (0.07, 0.12, 0.20),
        "navy_soft": (0.12, 0.19, 0.29),
        "teal": (0.10, 0.55, 0.52),
        "green": (0.18, 0.62, 0.39),
        "amber": (0.88, 0.58, 0.12),
        "red": (0.82, 0.27, 0.27),
        "blue": (0.22, 0.48, 0.78),
        "white": (1.0, 1.0, 1.0),
        "surface": (0.97, 0.98, 0.99),
        "surface_alt": (0.94, 0.96, 0.98),
        "border": (0.84, 0.88, 0.92),
        "text": (0.14, 0.19, 0.25),
        "muted": (0.43, 0.49, 0.57),
        "mist": (0.83, 0.89, 0.94),
    }

    def __init__(self, output_dir: str | Path = "reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        devices: list[Device],
        port_results: list[PortScanResult],
        assessment: SecurityAssessment,
        alerts: list[Alert],
        company_profile: dict[str, str] | None = None,
    ) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        company_name = (company_profile or {}).get("company_name", "netsecure").strip().lower().replace(" ", "_")
        safe_company = "".join(character for character in company_name if character.isalnum() or character == "_") or "netsecure"
        pdf_path = self.output_dir / f"{safe_company}_report_{timestamp}.pdf"
        page_streams = self._build_pages(devices, port_results, assessment, alerts, company_profile or {})
        self._write_pdf(pdf_path, page_streams)
        return pdf_path

    def _build_pages(
        self,
        devices: list[Device],
        port_results: list[PortScanResult],
        assessment: SecurityAssessment,
        alerts: list[Alert],
        company_profile: dict[str, str],
    ) -> list[bytes]:
        company_name = company_profile.get("company_name", "NetSecure Pro")
        department = company_profile.get("department", "Security Operations Center")
        site = company_profile.get("site", "Head Office")
        owner = company_profile.get("owner", "Infrastructure & Cybersecurity Team")
        support_email = company_profile.get("support_email", "soc@netsecure-enterprise.local")
        support_phone = company_profile.get("support_phone", "+212 5 00 00 00 00")

        pages = [self._new_page(1, company_name, show_top_band=False)]
        first_page = pages[0]

        risk_ports = sum(1 for result in port_results if result.risk_level.lower() in {"high", "critical"})
        insight = self._build_insight(assessment, alerts, port_results)
        score_color = self._score_color(assessment.score)
        findings = self._compact_list(assessment.risk_factors, 4, "No significant risk factors were registered.")
        recommendations = self._compact_list(
            assessment.recommendations,
            5,
            "Continue hardening exposed services and monitor newly detected assets.",
        )

        self._draw_cover_page(
            first_page,
            company_name=company_name,
            department=department,
            site=site,
            owner=owner,
            support_email=support_email,
            support_phone=support_phone,
            assessment=assessment,
            score_color=score_color,
            metrics=[
                ("Active Hosts", str(len(devices)), self.COLORS["blue"]),
                ("Open Ports", str(len(port_results)), self.COLORS["teal"]),
                ("Recent Alerts", str(len(alerts)), self.COLORS["amber"]),
                ("High Risk", str(risk_ports), self.COLORS["red"]),
            ],
            insight=insight,
            findings=findings,
            recommendations=recommendations,
        )

        pages.append(self._new_page(2, company_name))
        device_rows = [
            [
                device.ip_address,
                device.hostname or "Unknown",
                device.device_type or "Unknown",
                device.os_guess or "Unknown",
                device.vendor or "Unknown",
                device.status or "Unknown",
            ]
            for device in sorted(devices, key=lambda item: item.ip_address)
        ]
        self._draw_table_section(
            pages,
            "Detected Assets",
            "Inventory of hosts discovered during the latest network scan.",
            [("IP Address", 82.0), ("Hostname", 104.0), ("Type", 72.0), ("OS", 66.0), ("Vendor", 118.0), ("Status", 69.0)],
            device_rows,
            "No active devices were detected in the latest scan.",
            self._device_fill,
        )

        port_rows = [
            [
                result.device_ip,
                str(result.port),
                result.service or "Unknown",
                result.state or "Unknown",
                result.risk_level or "Unknown",
                (result.banner or "-").replace("\r", " ").replace("\n", " "),
            ]
            for result in sorted(port_results, key=lambda item: (item.device_ip, item.port))
        ]
        self._draw_table_section(
            pages,
            "Open Service Exposure",
            "Reachable ports and service banners identified during port analysis.",
            [("Host", 86.0), ("Port", 38.0), ("Service", 78.0), ("State", 55.0), ("Risk", 58.0), ("Banner", 196.0)],
            port_rows,
            "No open ports were recorded for the latest scan set.",
            self._port_fill,
        )

        alert_rows = [[alert.created_at, alert.severity, alert.type_alert, alert.description] for alert in alerts]
        self._draw_table_section(
            pages,
            "Recent Alerts",
            "Latest security-relevant events generated by monitoring and analysis.",
            [("Time", 108.0), ("Severity", 68.0), ("Category", 98.0), ("Description", 237.0)],
            alert_rows,
            "No recent alerts were recorded.",
            self._alert_fill,
        )

        self._draw_notes(
            pages,
            left_title="Observations",
            left_items=self._compact_list(assessment.observations, 6, "No additional observations were generated."),
            right_title="Risk Factors",
            right_items=self._compact_list(assessment.risk_factors, 6, "No explicit risk factors were registered."),
        )

        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_pages = len(pages)
        for page in pages:
            self._draw_footer(page, company_name, generated_at, total_pages)
        return [self._page_stream(page) for page in pages]

    def _new_page(self, number: int, company_name: str, show_top_band: bool = True) -> dict[str, object]:
        page: dict[str, object] = {"number": number, "commands": [], "y": 768.0 if show_top_band else self.TOP_Y, "brand": company_name}
        if show_top_band:
            self._text(page, self.MARGIN_X, 804.0, company_name, font="F2", size=10.5, color=self.COLORS["navy"])
            self._text(
                page,
                self.PAGE_WIDTH - self.MARGIN_X,
                804.0,
                "Network Security Assessment Report",
                size=9.5,
                color=self.COLORS["muted"],
                align="right",
            )
            self._line(page, self.MARGIN_X, 794.0, self.PAGE_WIDTH - self.MARGIN_X, 794.0, self.COLORS["border"])
        return page

    def _draw_cover_page(
        self,
        page: dict[str, object],
        *,
        company_name: str,
        department: str,
        site: str,
        owner: str,
        support_email: str,
        support_phone: str,
        assessment: SecurityAssessment,
        score_color: tuple[float, float, float],
        metrics: list[tuple[str, str, tuple[float, float, float]]],
        insight: str,
        findings: list[str],
        recommendations: list[str],
    ) -> None:
        self._rect(page, self.MARGIN_X, 660.0, self.CONTENT_WIDTH, 142.0, fill=self.COLORS["navy"])
        self._rect(page, 414.0, 682.0, 120.0, 96.0, fill=self.COLORS["navy_soft"], stroke=(0.20, 0.42, 0.49))
        self._text(page, 60.0, 776.0, company_name, font="F2", size=17.0, color=self.COLORS["white"])
        self._text(page, 60.0, 746.0, "Network Security Assessment Report", font="F2", size=24.0, color=self.COLORS["white"])
        self._wrapped_text(
            page,
            60.0,
            724.0,
            316.0,
            "Professional overview of detected assets, exposed services, alert activity, and remediation priorities.",
            size=10.0,
            color=self.COLORS["mist"],
        )
        self._text(page, 60.0, 690.0, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", size=10.0, color=self.COLORS["mist"])
        self._text(page, 60.0, 672.0, f"{department} | {site}", size=10.0, color=self.COLORS["mist"])
        self._text(page, 60.0, 654.0, f"Owner: {owner}", size=10.0, color=self.COLORS["mist"])
        self._text(page, 474.0, 755.0, "POSTURE", font="F2", size=9.0, color=self.COLORS["mist"], align="center")
        self._text(page, 474.0, 728.0, assessment.label, font="F2", size=12.5, color=score_color, align="center")
        self._text(page, 474.0, 698.0, f"{assessment.score}/100", font="F2", size=24.0, color=self.COLORS["white"], align="center")
        self._metric_row(page, metrics, top_y=560.0)
        self._panel(page, self.MARGIN_X, 430.0, self.CONTENT_WIDTH, 108.0, "Executive Summary", [insight, f"Support: {support_email}", f"Contact: {support_phone}"])
        half_width = (self.CONTENT_WIDTH - 15.0) / 2.0
        self._panel(page, self.MARGIN_X, 302.0, half_width, 110.0, "Key Findings", findings, compact=True)
        self._panel(page, self.MARGIN_X + half_width + 15.0, 302.0, half_width, 110.0, "Priority Actions", recommendations, compact=True)

    def _metric_row(
        self,
        page: dict[str, object],
        metrics: list[tuple[str, str, tuple[float, float, float]]],
        *,
        top_y: float,
    ) -> None:
        gap = 9.0
        card_width = (self.CONTENT_WIDTH - (gap * (len(metrics) - 1))) / len(metrics)
        for index, (label, value, accent) in enumerate(metrics):
            x = self.MARGIN_X + (index * (card_width + gap))
            self._rect(page, x, top_y, card_width, 60.0, fill=self.COLORS["surface"], stroke=self.COLORS["border"])
            self._rect(page, x, top_y + 54.0, card_width, 6.0, fill=accent)
            self._text(page, x + 12.0, top_y + 36.0, label.upper(), font="F2", size=8.2, color=self.COLORS["muted"])
            self._text(page, x + 12.0, top_y + 14.0, value, font="F2", size=22.0, color=self.COLORS["navy"])

    def _panel(
        self,
        page: dict[str, object],
        x: float,
        y: float,
        width: float,
        height: float,
        title: str,
        lines: list[str],
        compact: bool = False,
    ) -> None:
        self._rect(page, x, y, width, height, fill=self.COLORS["surface"], stroke=self.COLORS["border"])
        self._text(page, x + 14.0, y + height - 22.0, title, font="F2", size=12.0, color=self.COLORS["navy"])
        self._line(page, x + 14.0, y + height - 28.0, x + width - 14.0, y + height - 28.0, self.COLORS["border"])
        font_size = 8.9 if compact else 9.5
        line_gap = 13.0 if compact else 15.0
        current_y = y + height - 48.0
        visible_lines = 2 if compact else 3
        for line in lines:
            for wrapped_line in self._wrap(line, width - 28.0, font_size)[:visible_lines]:
                self._text(page, x + 14.0, current_y, wrapped_line, size=font_size, color=self.COLORS["text"])
                current_y -= line_gap
            if current_y < y + 14.0:
                break

    def _draw_table_section(
        self,
        pages: list[dict[str, object]],
        title: str,
        subtitle: str,
        columns: list[tuple[str, float]],
        rows: list[list[str]],
        empty_message: str,
        fill_builder,
    ) -> None:
        page = self._ensure_space(pages, 74.0)
        self._section_header(page, title, subtitle)
        page["y"] = float(page["y"]) - 6.0

        if not rows:
            page = self._ensure_space(pages, 44.0)
            self._rect(page, self.MARGIN_X, float(page["y"]) - 28.0, self.CONTENT_WIDTH, 28.0, fill=self.COLORS["surface"], stroke=self.COLORS["border"])
            self._text(page, self.MARGIN_X + 12.0, float(page["y"]) - 18.0, empty_message, size=9.2, color=self.COLORS["muted"])
            page["y"] = float(page["y"]) - 46.0
            return

        row_index = 0
        while row_index < len(rows):
            page = self._ensure_space(pages, 34.0)
            self._table_header(page, columns)
            page["y"] = float(page["y"]) - 28.0
            while row_index < len(rows):
                if float(page["y"]) - 24.0 < self.BOTTOM_Y:
                    page = self._new_page(len(pages) + 1, str(page.get("brand", "")))
                    pages.append(page)
                    break
                self._table_row(page, columns, rows[row_index], fill_builder(rows[row_index], row_index))
                page["y"] = float(page["y"]) - 24.0
                row_index += 1
        pages[-1]["y"] = float(pages[-1]["y"]) - 16.0

    def _draw_notes(
        self,
        pages: list[dict[str, object]],
        *,
        left_title: str,
        left_items: list[str],
        right_title: str,
        right_items: list[str],
    ) -> None:
        page = self._ensure_space(pages, 170.0)
        self._section_header(page, "Assessment Notes", "Additional narrative captured from the latest automated assessment.")
        page["y"] = float(page["y"]) - 8.0
        gap = 15.0
        width = (self.CONTENT_WIDTH - gap) / 2.0
        bottom_y = float(page["y"]) - 118.0
        self._panel(page, self.MARGIN_X, bottom_y, width, 118.0, left_title, left_items, compact=True)
        self._panel(page, self.MARGIN_X + width + gap, bottom_y, width, 118.0, right_title, right_items, compact=True)
        page["y"] = bottom_y - 18.0

    def _section_header(self, page: dict[str, object], title: str, subtitle: str) -> None:
        current_y = float(page["y"])
        self._rect(page, self.MARGIN_X, current_y - 18.0, 5.0, 18.0, fill=self.COLORS["teal"])
        self._text(page, self.MARGIN_X + 12.0, current_y - 4.0, title, font="F2", size=13.0, color=self.COLORS["navy"])
        self._text(page, self.MARGIN_X + 12.0, current_y - 19.0, subtitle, size=8.8, color=self.COLORS["muted"])
        page["y"] = current_y - 34.0

    def _table_header(self, page: dict[str, object], columns: list[tuple[str, float]]) -> None:
        current_y = float(page["y"])
        self._rect(page, self.MARGIN_X, current_y - 24.0, self.CONTENT_WIDTH, 24.0, fill=self.COLORS["navy"])
        x = self.MARGIN_X
        for label, width in columns:
            self._text(page, x + 6.0, current_y - 15.5, label, font="F2", size=8.2, color=self.COLORS["white"])
            x += width

    def _table_row(
        self,
        page: dict[str, object],
        columns: list[tuple[str, float]],
        values: list[str],
        fill: tuple[float, float, float],
    ) -> None:
        current_y = float(page["y"])
        self._rect(page, self.MARGIN_X, current_y - 24.0, self.CONTENT_WIDTH, 24.0, fill=fill, stroke=self.COLORS["border"])
        x = self.MARGIN_X
        for (label, width), value in zip(columns, values):
            text = self._fit(value, width - 12.0, 8.7)
            font = "F2" if label in {"Severity", "Risk"} else "F1"
            color = self._cell_color(label, value)
            self._text(page, x + 6.0, current_y - 15.2, text, font=font, size=8.7, color=color)
            x += width

    def _ensure_space(self, pages: list[dict[str, object]], needed: float) -> dict[str, object]:
        page = pages[-1]
        if float(page["y"]) - needed < self.BOTTOM_Y:
            page = self._new_page(len(pages) + 1, str(page.get("brand", "")))
            pages.append(page)
        return page

    def _draw_footer(self, page: dict[str, object], company_name: str, generated_at: str, total_pages: int) -> None:
        self._line(page, self.MARGIN_X, 44.0, self.PAGE_WIDTH - self.MARGIN_X, 44.0, self.COLORS["border"])
        self._text(page, self.MARGIN_X, 30.0, company_name, font="F2", size=8.4, color=self.COLORS["muted"])
        self._text(page, self.PAGE_WIDTH / 2.0, 30.0, f"Generated {generated_at}", size=8.0, color=self.COLORS["muted"], align="center")
        self._text(
            page,
            self.PAGE_WIDTH - self.MARGIN_X,
            30.0,
            f"Page {page['number']} of {total_pages}",
            size=8.0,
            color=self.COLORS["muted"],
            align="right",
        )

    def _page_stream(self, page: dict[str, object]) -> bytes:
        return "\n".join(page["commands"]).encode("latin-1", errors="replace")

    def _rect(
        self,
        page: dict[str, object],
        x: float,
        y: float,
        width: float,
        height: float,
        *,
        fill: tuple[float, float, float] | None = None,
        stroke: tuple[float, float, float] | None = None,
        line_width: float = 0.8,
    ) -> None:
        commands = page["commands"]
        if fill is not None:
            commands.append(f"{self._rgb(fill)} rg")
        if stroke is not None:
            commands.append(f"{self._rgb(stroke)} RG")
            commands.append(f"{line_width:.2f} w")
        paint = "B" if fill is not None and stroke is not None else "f" if fill is not None else "S"
        commands.append(f"{x:.2f} {y:.2f} {width:.2f} {height:.2f} re {paint}")

    def _line(
        self,
        page: dict[str, object],
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        color: tuple[float, float, float],
        width: float = 0.8,
    ) -> None:
        commands = page["commands"]
        commands.append(f"{self._rgb(color)} RG")
        commands.append(f"{width:.2f} w")
        commands.append(f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")

    def _text(
        self,
        page: dict[str, object],
        x: float,
        y: float,
        text: str,
        *,
        font: str = "F1",
        size: float = 10.0,
        color: tuple[float, float, float] | None = None,
        align: str = "left",
    ) -> None:
        commands = page["commands"]
        actual_x = x
        if align == "center":
            actual_x -= self._estimate_width(text, size, font) / 2.0
        elif align == "right":
            actual_x -= self._estimate_width(text, size, font)
        commands.extend(
            [
                "BT",
                f"/{font} {size:.2f} Tf",
                f"{self._rgb(color or self.COLORS['text'])} rg",
                f"1 0 0 1 {actual_x:.2f} {y:.2f} Tm",
                f"({self._escape(text)}) Tj",
                "ET",
            ]
        )

    def _wrapped_text(
        self,
        page: dict[str, object],
        x: float,
        y: float,
        width: float,
        text: str,
        *,
        font: str = "F1",
        size: float = 10.0,
        color: tuple[float, float, float] | None = None,
        line_gap: float = 13.0,
    ) -> None:
        for index, line in enumerate(self._wrap(text, width, size)):
            self._text(page, x, y - (index * line_gap), line, font=font, size=size, color=color)

    def _write_pdf(self, output_path: Path, page_streams: list[bytes]) -> None:
        objects: list[bytes] = [
            b"",
            b"",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
        ]
        page_numbers: list[int] = []
        for stream in page_streams or [b"BT /F1 12 Tf 50 760 Td (Empty report) Tj ET"]:
            content_number = len(objects) + 1
            page_number = len(objects) + 2
            page_numbers.append(page_number)
            objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream")
            objects.append(
                (
                    f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.PAGE_WIDTH:.0f} {self.PAGE_HEIGHT:.0f}] "
                    f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_number} 0 R >>"
                ).encode("latin-1")
            )

        kids = " ".join(f"{number} 0 R" for number in page_numbers)
        objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
        objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_numbers)} >>".encode("latin-1")

        pdf = bytearray()
        pdf.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for index, obj in enumerate(objects, start=1):
            offsets.append(len(pdf))
            pdf.extend(f"{index} 0 obj\n".encode("latin-1"))
            pdf.extend(obj)
            pdf.extend(b"\nendobj\n")

        xref = len(pdf)
        pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
        pdf.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            pdf.extend(f"{offset:010} 00000 n \n".encode("latin-1"))
        pdf.extend(
            (
                f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
                f"startxref\n{xref}\n%%EOF"
            ).encode("latin-1")
        )
        output_path.write_bytes(pdf)

    def _build_insight(
        self,
        assessment: SecurityAssessment,
        alerts: list[Alert],
        port_results: list[PortScanResult],
    ) -> str:
        critical_ports = sum(1 for result in port_results if result.risk_level.lower() == "critical")
        critical_alerts = sum(1 for alert in alerts if alert.severity.lower() == "critical")
        if critical_ports or critical_alerts:
            return f"{critical_ports + critical_alerts} critical issue(s) detected. Immediate remediation is recommended."
        if any(result.risk_level.lower() == "high" for result in port_results):
            return "Elevated service exposure detected. Prioritize hardening and review accessible services."
        if assessment.score >= 80:
            return "Network posture is stable with no major threats detected in the latest assessment."
        if assessment.score >= 50:
            return "Network posture is moderate and should be improved through routine hardening actions."
        return "Network posture is at risk and requires immediate review of exposed assets and controls."

    def _compact_list(self, items: list[str], limit: int, fallback: str) -> list[str]:
        cleaned = [item.strip() for item in items if item and item.strip()]
        return cleaned[:limit] if cleaned else [fallback]

    def _wrap(self, text: str, width: float, size: float) -> list[str]:
        normalized = " ".join(str(text).split())
        if not normalized:
            return [""]
        max_chars = max(14, int(width / (size * 0.56)))
        return wrap(normalized, width=max_chars, break_long_words=False, break_on_hyphens=False) or [normalized]

    def _fit(self, text: str, width: float, size: float) -> str:
        normalized = " ".join(str(text).split())
        if self._estimate_width(normalized, size, "F1") <= width:
            return normalized
        trimmed = normalized
        while trimmed and self._estimate_width(f"{trimmed}...", size, "F1") > width:
            trimmed = trimmed[:-1]
        return f"{trimmed.rstrip()}..." if trimmed else "..."

    def _estimate_width(self, text: str, size: float, font: str) -> float:
        factor = 0.55 if font == "F1" else 0.58
        return len(text) * size * factor

    def _device_fill(self, row: list[str], index: int) -> tuple[float, float, float]:
        return self.COLORS["surface"] if index % 2 == 0 else self.COLORS["surface_alt"]

    def _port_fill(self, row: list[str], index: int) -> tuple[float, float, float]:
        risk = row[4].lower()
        if risk == "critical":
            return (0.99, 0.91, 0.91)
        if risk == "high":
            return (1.0, 0.95, 0.88)
        if risk == "medium":
            return (1.0, 0.98, 0.92)
        return self.COLORS["surface"] if index % 2 == 0 else self.COLORS["surface_alt"]

    def _alert_fill(self, row: list[str], index: int) -> tuple[float, float, float]:
        severity = row[1].lower()
        if severity == "critical":
            return (0.99, 0.90, 0.90)
        if severity == "high":
            return (1.0, 0.94, 0.89)
        if severity == "medium":
            return (1.0, 0.98, 0.92)
        if severity == "low":
            return (0.92, 0.98, 0.95)
        return self.COLORS["surface"] if index % 2 == 0 else self.COLORS["surface_alt"]

    def _cell_color(self, label: str, value: str) -> tuple[float, float, float]:
        normalized = str(value).lower()
        if label in {"Severity", "Risk"}:
            if normalized == "critical":
                return self.COLORS["red"]
            if normalized == "high":
                return self.COLORS["amber"]
            if normalized == "medium":
                return (0.72, 0.54, 0.06)
            if normalized == "low":
                return self.COLORS["green"]
        return self.COLORS["text"]

    def _score_color(self, score: int) -> tuple[float, float, float]:
        if score >= 80:
            return self.COLORS["green"]
        if score >= 50:
            return self.COLORS["amber"]
        return self.COLORS["red"]

    def _rgb(self, color: tuple[float, float, float]) -> str:
        return f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f}"

    def _escape(self, value: str) -> str:
        return (
            value.replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .encode("latin-1", errors="replace")
            .decode("latin-1")
        )
