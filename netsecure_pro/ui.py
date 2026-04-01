from __future__ import annotations

from datetime import datetime
from html import escape
import math
from pathlib import Path

from PyQt6.QtCore import QRectF, QSize, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGraphicsDropShadowEffect,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QStyle,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from .database import DatabaseManager
from .exports import CSVExporter
from .ai_assistant import OpenRouterAssistant
from .models import (
    Alert,
    Device,
    EventLogEntry,
    MonitoringSnapshot,
    PortScanResult,
    ScanRun,
    SecurityAssessment,
    SecuritySettings,
)
from .monitor import NetworkMonitor
from .network import NetworkScanner
from .ports import PortScanner
from .reporting import ReportGenerator
from .security import SecurityAnalyzer


LIGHT_STYLE = """
QWidget {
    background: #f4f7fb;
    color: #172033;
    font-family: Segoe UI;
    font-size: 10pt;
}
QMainWindow, QDialog {
    background: #eef3f9;
}
QLabel {
    background: transparent;
}
QFrame#Card {
    background: white;
    border: 1px solid #d6e1ee;
    border-radius: 16px;
}
QPushButton {
    background: #0f766e;
    color: white;
    border: none;
    border-radius: 10px;
    padding: 8px 16px;
    font-weight: 600;
}
QPushButton:hover {
    background: #0d9488;
}
QPushButton:disabled {
    background: #9fb7c8;
    color: white;
}
QLineEdit, QComboBox, QTextEdit, QTableWidget, QListWidget {
    background: white;
    border: 1px solid #cad7e6;
    border-radius: 10px;
    padding: 5px 10px;
}
QTabWidget::pane {
    border: 1px solid #d7deea;
    border-radius: 16px;
    background: white;
    top: -1px;
}
QTabBar::tab {
    background: #e7eef7;
    color: #334155;
    border: 1px solid #cad7e6;
    border-bottom: none;
    border-top-left-radius: 12px;
    border-top-right-radius: 12px;
    padding: 10px 18px;
    margin-right: 6px;
    font-weight: 700;
}
QTabBar::tab:selected {
    background: white;
    color: #0f172a;
}
QTabBar::tab:hover {
    background: #f8fafc;
}
QHeaderView::section {
    background: #e6eef8;
    color: #172033;
    border: none;
    padding: 8px;
    font-weight: 700;
}
QListWidget::item:selected {
    background: #d7f3f0;
    color: #0f172a;
    border-radius: 10px;
}
QProgressBar {
    border: 1px solid #d1d9e6;
    border-radius: 12px;
    background: white;
    text-align: center;
}
QProgressBar::chunk {
    background: #22c55e;
    border-radius: 12px;
}
"""


DARK_STYLE = """
QWidget {
    background: #0d1628;
    color: #e5eefb;
    font-family: Segoe UI;
    font-size: 10pt;
}
QMainWindow, QDialog {
    background: #091120;
}
QLabel {
    background: transparent;
}
QFrame#Card {
    background: #132036;
    border: 1px solid #22324a;
    border-radius: 16px;
}
QPushButton {
    background: #0f766e;
    color: white;
    border: none;
    border-radius: 10px;
    padding: 8px 16px;
    font-weight: 600;
}
QPushButton:hover {
    background: #0d9488;
}
QPushButton:disabled {
    background: #314962;
    color: #a9bdd1;
}
QLineEdit, QComboBox, QTextEdit, QTableWidget, QListWidget {
    background: #0f1b2f;
    color: #e5eefb;
    border: 1px solid #2d405b;
    border-radius: 10px;
    padding: 5px 10px;
}
QTabWidget::pane {
    border: 1px solid #22324a;
    border-radius: 16px;
    background: #0f1b2f;
    top: -1px;
}
QTabBar::tab {
    background: #132036;
    color: #cbd5e1;
    border: 1px solid #22324a;
    border-bottom: none;
    border-top-left-radius: 12px;
    border-top-right-radius: 12px;
    padding: 10px 18px;
    margin-right: 6px;
    font-weight: 700;
}
QTabBar::tab:selected {
    background: #0f1b2f;
    color: #ffffff;
}
QTabBar::tab:hover {
    background: #18314b;
}
QHeaderView::section {
    background: #16253a;
    color: #e5eefb;
    border: none;
    padding: 8px;
    font-weight: 700;
}
QListWidget::item:selected {
    background: #103d45;
    color: #ecfeff;
    border-radius: 10px;
}
QProgressBar {
    border: 1px solid #2d405b;
    border-radius: 12px;
    background: #0f1b2f;
    text-align: center;
}
QProgressBar::chunk {
    background: #22c55e;
    border-radius: 12px;
}
"""


class WorkerThread(QThread):
    result_ready = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, callback, *args) -> None:
        super().__init__()
        self.callback = callback
        self.args = args

    def run(self) -> None:
        try:
            result = self.callback(*self.args)
        except Exception as exc:  # pragma: no cover
            self.error.emit(str(exc))
        else:
            self.result_ready.emit(result)


class NetworkScanThread(QThread):
    result_ready = pyqtSignal(object)
    progress = pyqtSignal(int, int, int, str)
    error = pyqtSignal(str)
    cancelled = pyqtSignal(object)

    def __init__(self, scanner: NetworkScanner, target: str, mode: str) -> None:
        super().__init__()
        self.scanner = scanner
        self.target = target
        self.mode = mode
        self._cancel_requested = False

    def cancel(self) -> None:
        self._cancel_requested = True

    def _is_cancel_requested(self) -> bool:
        return self._cancel_requested

    def run(self) -> None:
        try:
            result = self.scanner.scan(self.target, self.mode, self.progress.emit, self._is_cancel_requested)
        except Exception as exc:  # pragma: no cover
            self.error.emit(str(exc))
        else:
            if self._cancel_requested:
                self.cancelled.emit(result)
            else:
                self.result_ready.emit(result)


class PortScanThread(QThread):
    result_ready = pyqtSignal(object)
    progress = pyqtSignal(int, int, int, int)
    error = pyqtSignal(str)
    cancelled = pyqtSignal(object)

    def __init__(self, scanner: PortScanner, ip_address: str, mode: str, custom_ports: str) -> None:
        super().__init__()
        self.scanner = scanner
        self.ip_address = ip_address
        self.mode = mode
        self.custom_ports = custom_ports
        self._cancel_requested = False

    def cancel(self) -> None:
        self._cancel_requested = True

    def _is_cancel_requested(self) -> bool:
        return self._cancel_requested

    def run(self) -> None:
        try:
            result = self.scanner.scan_host(
                self.ip_address,
                self.mode,
                self.custom_ports,
                None,
                self.progress.emit,
                self._is_cancel_requested,
            )
        except Exception as exc:  # pragma: no cover
            self.error.emit(str(exc))
        else:
            if self._cancel_requested:
                self.cancelled.emit(result)
            else:
                self.result_ready.emit(result)


class MetricCard(QFrame):
    def __init__(self, title: str, accent: str, icon_name: QStyle.StandardPixmap, icon_bg: str | None = None) -> None:
        super().__init__()
        self.setObjectName("Card")
        self.accent = accent
        self.icon_bg = icon_bg or accent
        self._shadow = QGraphicsDropShadowEffect(self)
        self._shadow.setBlurRadius(22)
        self._shadow.setOffset(0, 8)
        self._shadow.setColor(QColor(15, 23, 42, 24))
        self.setGraphicsEffect(self._shadow)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        top_row = QHBoxLayout()
        top_row.setSpacing(10)
        self.icon_badge = QLabel()
        self.icon_badge.setFixedSize(34, 34)
        self.icon_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_badge.setStyleSheet(
            f"background: {self.icon_bg}; color: white; border-radius: 10px;"
        )
        self.icon_badge.setPixmap(self.style().standardIcon(icon_name).pixmap(QSize(16, 16)))

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet(f"color: {accent}; font-weight: 700; font-size: 10.5pt;")
        self.value_label = QLabel("0")
        self.value_label.setStyleSheet(f"font-size: 22pt; font-weight: 800; color: {accent};")
        self.caption_label = QLabel("")
        self.caption_label.setStyleSheet("color: #6b7280;")
        self.caption_label.setWordWrap(True)

        top_row.addWidget(self.icon_badge)
        top_row.addWidget(self.title_label)
        top_row.addStretch(1)

        layout.addLayout(top_row)
        layout.addWidget(self.value_label)
        layout.addWidget(self.caption_label)
        layout.addStretch(1)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def enterEvent(self, event) -> None:  # pragma: no cover
        self._shadow.setBlurRadius(28)
        self._shadow.setOffset(0, 10)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # pragma: no cover
        self._shadow.setBlurRadius(22)
        self._shadow.setOffset(0, 8)
        super().leaveEvent(event)

    def update_content(self, value: str, caption: str) -> None:
        self.value_label.setText(value)
        self.caption_label.setText(caption)


class TrafficChartWidget(QFrame):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("Card")
        self.setMinimumHeight(220)
        self.history: list[float] = []
        self.theme = "light"

    def set_history(self, history: list[float]) -> None:
        self.history = history[-30:]
        self.update()

    def set_theme(self, theme: str) -> None:
        self.theme = theme
        self.update()

    def paintEvent(self, event) -> None:  # pragma: no cover
        super().paintEvent(event)
        if not self.history:
            return

        frame_color = "#cbd5e1" if self.theme == "light" else "#334155"
        text_color = "#475569" if self.theme == "light" else "#cbd5e1"
        line_color = "#0f766e" if self.theme == "light" else "#14b8a6"
        fill_start = QColor("#2dd4bf" if self.theme == "light" else "#14b8a6")
        fill_end = QColor("#2dd4bf" if self.theme == "light" else "#14b8a6")
        fill_start.setAlpha(80)
        fill_end.setAlpha(6)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(18, 18, -18, -22)
        painter.setPen(QPen(QColor(frame_color), 1))
        painter.drawRoundedRect(rect, 10, 10)

        max_value = max(max(self.history), 1.0)
        step_x = rect.width() / max(1, len(self.history) - 1)
        points: list[tuple[float, float]] = []

        for index, value in enumerate(self.history):
            x = rect.left() + index * step_x
            y = rect.bottom() - (value / max_value) * (rect.height() - 26) - 8
            points.append((x, y))

        area_path = QPainterPath()
        first_x, first_y = points[0]
        area_path.moveTo(first_x, rect.bottom())
        area_path.lineTo(first_x, first_y)
        for x, y in points[1:]:
            area_path.lineTo(x, y)
        area_path.lineTo(points[-1][0], rect.bottom())
        area_path.closeSubpath()

        fill_gradient = QLinearGradient(rect.left(), rect.top(), rect.left(), rect.bottom())
        fill_gradient.setColorAt(0.0, fill_start)
        fill_gradient.setColorAt(1.0, fill_end)
        painter.fillPath(area_path, fill_gradient)

        line_path = QPainterPath()
        line_path.moveTo(points[0][0], points[0][1])
        for x, y in points[1:]:
            line_path.lineTo(x, y)
        painter.setPen(QPen(QColor(line_color), 3))
        painter.drawPath(line_path)

        painter.setBrush(QColor(line_color))
        painter.setPen(QPen(QColor("#ffffff" if self.theme == "dark" else "#f8fafc"), 1))
        for x, y in points:
            painter.drawEllipse(QRectF(x - 3, y - 3, 6, 6))

        painter.setPen(QPen(QColor(text_color), 1))
        painter.drawText(rect.left() + 8, rect.top() + 18, "Bandwidth history")
        painter.drawText(rect.right() - 98, rect.top() + 18, f"Peak {max_value:.0f} KB/s")
        painter.drawText(rect.left() + 8, rect.bottom() - 4, "30s ago")
        painter.drawText(rect.right() - 28, rect.bottom() - 4, "Now")
        painter.end()


class TopologyWidget(QFrame):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("Card")
        self.setMinimumHeight(360)
        self.devices: list[Device] = []
        self.port_results_by_ip: dict[str, list[PortScanResult]] = {}
        self.theme = "light"
        self._node_regions: list[tuple[QRectF, str]] = []
        self.setMouseTracking(True)

    def set_data(self, devices: list[Device], port_results_by_ip: dict[str, list[PortScanResult]]) -> None:
        self.devices = sorted(devices[:12], key=lambda device: (device.device_type, device.ip_address))
        self.port_results_by_ip = port_results_by_ip
        self.update()

    def set_theme(self, theme: str) -> None:
        self.theme = theme
        self.update()

    def paintEvent(self, event) -> None:  # pragma: no cover
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(20, 20, -20, -20)
        self._node_regions = []

        frame_color = "#cbd5e1" if self.theme == "light" else "#334155"
        text_color = "#334155" if self.theme == "light" else "#e2e8f0"
        center_fill = "#2563eb" if self.theme == "light" else "#1d4ed8"

        painter.setPen(QPen(QColor(frame_color), 1))
        painter.drawRoundedRect(rect, 12, 12)
        painter.setPen(QColor(text_color))
        painter.drawText(rect.left() + 10, rect.top() + 20, "Simplified network topology")

        center_x = rect.center().x()
        center_y = rect.center().y()
        center_radius = 34

        painter.setBrush(QColor(center_fill))
        painter.setPen(QPen(QColor(center_fill), 1))
        painter.drawEllipse(int(center_x - center_radius), int(center_y - center_radius), center_radius * 2, center_radius * 2)
        painter.setPen(QColor("#ffffff"))
        painter.drawText(int(center_x - 22), int(center_y + 4), "LAN")

        if not self.devices:
            painter.setPen(QColor(text_color))
            painter.drawText(rect.left() + 10, rect.bottom() - 10, "No devices detected to render the topology.")
            painter.end()
            return

        orbit_radius = min(rect.width(), rect.height()) / 2 - 60
        label_font = painter.font()
        label_font.setPointSize(8)
        for index, device in enumerate(self.devices):
            angle = (2 * math.pi / max(1, len(self.devices))) * index
            node_x = center_x + orbit_radius * math.cos(angle)
            node_y = center_y + orbit_radius * math.sin(angle)
            node_color = self._device_topology_color(device)
            outline_color = self._device_outline_color(device)

            painter.setPen(QPen(QColor(frame_color), 2))
            painter.drawLine(int(center_x), int(center_y), int(node_x), int(node_y))

            painter.setBrush(QColor(node_color))
            painter.setPen(QPen(QColor(outline_color), 3))
            self._draw_device_icon(painter, device, int(node_x), int(node_y), QColor(node_color), QColor(outline_color))
            painter.setPen(QColor(text_color))
            painter.setFont(label_font)
            painter.drawText(int(node_x - 24), int(node_y + 36), self._device_primary_label(device))
            painter.drawText(int(node_x - 24), int(node_y + 50), self._device_caption(device))
            self._node_regions.append((QRectF(node_x - 22, node_y - 22, 44, 44), self._tooltip_text(device)))

        painter.end()

    def _device_topology_color(self, device: Device) -> str:
        if device.device_type == "Router":
            return "#f59e0b" if self.theme == "light" else "#fbbf24"
        if device.device_type == "Server":
            return "#16a34a" if self.theme == "light" else "#4ade80"
        if device.device_type == "Mobile":
            return "#2563eb" if self.theme == "light" else "#60a5fa"
        if device.device_type == "IoT":
            return "#0ea5e9" if self.theme == "light" else "#22d3ee"
        return "#64748b" if self.theme == "light" else "#94a3b8"

    def _device_outline_color(self, device: Device) -> str:
        risky_ports = any(
            result.risk_level in {"Critical", "High"}
            for result in self.port_results_by_ip.get(device.ip_address, [])
        )
        if risky_ports:
            return "#dc2626" if self.theme == "light" else "#f87171"
        if not device.is_known:
            return "#d97706" if self.theme == "light" else "#fbbf24"
        return "#334155" if self.theme == "light" else "#cbd5e1"

    def _device_caption(self, device: Device) -> str:
        primary_service = self._primary_service(device.ip_address)
        label = device.device_type if device.device_type != "Unknown" else (device.os_guess or "Unknown")
        if primary_service:
            return f"{label} | {primary_service}"[:18]
        return label[:18]

    def _device_primary_label(self, device: Device) -> str:
        if device.hostname and device.hostname != "Unknown":
            return device.hostname[:14]
        return device.ip_address

    def _tooltip_text(self, device: Device) -> str:
        port_results = self.port_results_by_ip.get(device.ip_address, [])
        open_ports = ", ".join(f"{result.port} ({result.service})" for result in port_results[:4]) or "No open ports"
        highest_risk = next((result.risk_level for result in port_results if result.risk_level in {"Critical", "High"}), "Low")
        return (
            f"IP: {device.ip_address}\n"
            f"Type: {device.device_type}\n"
            f"OS: {device.os_guess}\n"
            f"Open ports: {open_ports}\n"
            f"Risk: {highest_risk}"
        )

    def mouseMoveEvent(self, event) -> None:  # pragma: no cover
        position = event.position()
        for rect, tooltip in self._node_regions:
            if rect.contains(position.x(), position.y()):
                QToolTip.showText(event.globalPosition().toPoint(), tooltip, self)
                return
        QToolTip.hideText()
        super().mouseMoveEvent(event)

    def _primary_service(self, ip_address: str) -> str:
        services = [result.service for result in self.port_results_by_ip.get(ip_address, []) if result.service != "Unknown"]
        if not services:
            return ""
        return services[0]

    def _draw_device_icon(self, painter: QPainter, device: Device, x: int, y: int, fill: QColor, outline: QColor) -> None:
        painter.setBrush(fill)
        painter.setPen(QPen(outline, 2))
        device_type = device.device_type

        if device_type == "Router":
            painter.drawRoundedRect(x - 20, y - 11, 40, 22, 5, 5)
            painter.drawLine(x - 13, y + 15, x - 6, y + 4)
            painter.drawLine(x, y + 15, x, y + 4)
            painter.drawLine(x + 13, y + 15, x + 6, y + 4)
            painter.drawLine(x - 9, y - 15, x, y - 4)
            painter.drawLine(x + 9, y - 15, x, y - 4)
            return

        if device_type == "Server":
            painter.drawRoundedRect(x - 18, y - 20, 36, 12, 3, 3)
            painter.drawRoundedRect(x - 18, y - 3, 36, 12, 3, 3)
            painter.drawRoundedRect(x - 18, y + 14, 36, 12, 3, 3)
            return

        if device_type == "Mobile":
            painter.drawRoundedRect(x - 11, y - 20, 22, 40, 5, 5)
            painter.drawLine(x - 4, y - 13, x + 4, y - 13)
            painter.drawPoint(x, y + 14)
            return

        if device_type == "IoT":
            painter.drawRoundedRect(x - 13, y - 13, 26, 26, 4, 4)
            for offset in (-11, -4, 3, 10):
                painter.drawLine(x - 19, y + offset, x - 13, y + offset)
                painter.drawLine(x + 13, y + offset, x + 19, y + offset)
            return

        painter.drawRoundedRect(x - 18, y - 13, 36, 22, 4, 4)
        painter.drawRect(x - 9, y + 11, 18, 2)
        painter.drawRect(x - 4, y + 13, 8, 3)


class LoginDialog(QDialog):
    def __init__(self, database: DatabaseManager) -> None:
        super().__init__()
        self.database = database
        self.username = ""
        profile = self.database.fetch_company_profile()
        company_name = profile.get("company_name", "NetSecure Pro")
        self.setWindowTitle(f"{company_name} - Login")
        self.resize(420, 280)

        root = QVBoxLayout(self)
        title = QLabel(company_name)
        title.setStyleSheet("font-size: 22pt; font-weight: 800; color: #0f172a;")
        subtitle = QLabel(
            f"{profile.get('department', 'Security Operations Center')} - {profile.get('site', 'Head Office')}"
        )
        subtitle.setStyleSheet("color: #475569;")

        card = QFrame()
        card.setObjectName("Card")
        form = QFormLayout(card)
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Username", self.username_input)
        form.addRow("Password", self.password_input)

        login_button = QPushButton("Sign In")
        login_button.clicked.connect(self._handle_login)
        hint = QLabel("Default account: admin / admin123")
        hint.setStyleSheet("color: #64748b;")

        root.addWidget(title)
        root.addWidget(subtitle)
        root.addSpacing(10)
        root.addWidget(card)
        root.addWidget(login_button)
        root.addWidget(hint)
        root.addStretch(1)

    def _handle_login(self) -> None:
        username = self.username_input.text().strip()
        password = self.password_input.text()
        if self.database.verify_user(username, password):
            self.username = username
            self.accept()
            return
        QMessageBox.warning(self, "Authentication", "Incorrect username or password.")


class MainWindow(QMainWindow):
    def __init__(
        self,
        username: str,
        database: DatabaseManager,
        network_scanner: NetworkScanner,
        port_scanner: PortScanner,
        monitor: NetworkMonitor,
        analyzer: SecurityAnalyzer,
        reporter: ReportGenerator,
        exporter: CSVExporter,
    ) -> None:
        super().__init__()
        self.username = username
        self.database = database
        self.network_scanner = network_scanner
        self.port_scanner = port_scanner
        self.monitor = monitor
        self.analyzer = analyzer
        self.reporter = reporter
        self.exporter = exporter
        self.ai_assistant = OpenRouterAssistant()

        self.devices: list[Device] = database.fetch_devices()
        self.port_results_by_ip: dict[str, list[PortScanResult]] = {}
        self.latest_snapshot: MonitoringSnapshot | None = None
        self.latest_assessment = SecurityAssessment(
            score=100,
            label="Secure Network",
            observations=["No analysis has been run yet."],
            recommendations=["Run a network scan, then perform a port scan."],
            risk_factors=[],
        )
        self.traffic_history: list[float] = []
        self.alert_cache: set[tuple[str, str]] = set()
        self._workers: list[QThread] = []
        self.ai_chat_history: list[dict[str, str]] = []
        self.pending_ai_question = ""
        self.pending_ai_mode = "scan-aware"
        self.current_theme = self.database.get_setting("theme", "light") or "light"
        self.security_settings = self.database.fetch_security_settings()
        self.company_profile = self.database.fetch_company_profile()
        self.active_network_scan_thread: NetworkScanThread | None = None
        self.active_port_scan_thread: PortScanThread | None = None

        self.setWindowTitle(self._app_window_title())
        self.resize(1460, 900)

        container = QWidget()
        self.setCentralWidget(container)
        root = QHBoxLayout(container)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(16)

        self.sidebar = QListWidget()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(236)
        self.sidebar.setIconSize(QSize(18, 18))
        self.sidebar.setSpacing(4)
        self.sidebar.setUniformItemSizes(True)
        self._build_sidebar_items()
        self._apply_sidebar_style()
        self.sidebar.setCurrentRow(0)
        self.sidebar.currentRowChanged.connect(self._change_page)

        content = QVBoxLayout()
        content.addWidget(self._build_header())
        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_dashboard_page())
        self.stack.addWidget(self._build_scan_page())
        self.stack.addWidget(self._build_ports_page())
        self.stack.addWidget(self._build_monitor_page())
        self.stack.addWidget(self._build_topology_page())
        self.stack.addWidget(self._build_history_page())
        self.stack.addWidget(self._build_journal_page())
        self.stack.addWidget(self._build_reports_page())
        self.stack.addWidget(self._build_ai_page())
        self.stack.addWidget(self._build_settings_page())
        content.addWidget(self.stack)

        root.addWidget(self.sidebar)
        root.addLayout(content)

        self.toast_label = QLabel(self)
        self.toast_label.hide()
        self.toast_label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

        self.monitor_timer = self.startTimer(1000)
        self._load_initial_state()
        self._apply_theme(self.current_theme, persist=False)

    def _build_header(self) -> QWidget:
        wrapper = QFrame()
        wrapper.setObjectName("Card")
        layout = QHBoxLayout(wrapper)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(14)

        self.header_logo = QLabel()
        self.header_logo.setFixedSize(52, 52)
        self.header_logo.setStyleSheet(
            "border-radius: 26px; background: #0f766e; color: white; font-size: 15pt; font-weight: 800;"
        )

        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)
        self.header_title = QLabel(self.company_profile.get("company_name", "NetSecure Pro"))
        self.header_title.setStyleSheet("font-size: 18pt; font-weight: 800;")
        self.header_subtitle = QLabel("")
        self.header_subtitle.setStyleSheet("color: #60748a;")
        title_layout.addWidget(self.header_title)
        title_layout.addWidget(self.header_subtitle)

        right_cluster = QVBoxLayout()
        right_cluster.setSpacing(8)
        right_cluster.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.header_welcome = QLabel(f"Welcome back, {self.username.title()}")
        self.header_welcome.setStyleSheet("font-weight: 600; color: #60748a;")

        action_row = QHBoxLayout()
        self.theme_button = QPushButton("Dark Mode")
        self.theme_button.setMinimumHeight(36)
        self.theme_button.clicked.connect(self._toggle_theme)
        self.score_badge = QLabel("Secure | 100")
        self.score_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.score_badge.setMinimumHeight(34)
        action_row.addWidget(self.theme_button)
        action_row.addWidget(self.score_badge)
        action_row.setSpacing(16)

        right_cluster.addWidget(self.header_welcome, alignment=Qt.AlignmentFlag.AlignRight)
        right_cluster.addLayout(action_row)

        layout.addWidget(self.header_logo)
        layout.addLayout(title_layout)
        layout.addStretch(1)
        layout.addLayout(right_cluster)
        return wrapper

    def _build_dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(14)

        self.dashboard_insight_card = QFrame()
        self.dashboard_insight_card.setObjectName("Card")
        insight_layout = QHBoxLayout(self.dashboard_insight_card)
        insight_layout.setContentsMargins(16, 12, 16, 12)
        self.dashboard_insight_label = QLabel("No major threats detected yet. Run a scan to generate an intelligent summary.")
        self.dashboard_insight_label.setWordWrap(True)
        self.dashboard_insight_label.setStyleSheet("font-weight: 700;")
        insight_layout.addWidget(self.dashboard_insight_label)

        cards_layout = QGridLayout()
        cards_layout.setHorizontalSpacing(14)
        cards_layout.setVerticalSpacing(14)
        self.hosts_card = MetricCard("Active Hosts", "#2563eb", QStyle.StandardPixmap.SP_DesktopIcon, "#dbeafe")
        self.ports_card = MetricCard("Open Ports", "#ea580c", QStyle.StandardPixmap.SP_FileDialogDetailedView, "#ffedd5")
        self.alerts_card = MetricCard("Alerts", "#dc2626", QStyle.StandardPixmap.SP_MessageBoxWarning, "#fee2e2")
        self.bandwidth_card = MetricCard("Bandwidth", "#0f766e", QStyle.StandardPixmap.SP_BrowserReload, "#ccfbf1")
        cards_layout.addWidget(self.hosts_card, 0, 0)
        cards_layout.addWidget(self.ports_card, 0, 1)
        cards_layout.addWidget(self.alerts_card, 0, 2)
        cards_layout.addWidget(self.bandwidth_card, 0, 3)

        split = QHBoxLayout()

        security_box = QGroupBox("Security Analysis")
        security_layout = QVBoxLayout(security_box)
        self.score_progress = QProgressBar()
        self.score_progress.setRange(0, 100)
        self.score_label = QLabel(self.latest_assessment.label)
        self.last_scan_label = QLabel("Last scan: no history available yet.")
        self.last_scan_label.setStyleSheet("color: #64748b;")
        self.observations_box = QTextEdit()
        self.observations_box.setReadOnly(True)
        self.recommendations_box = QTextEdit()
        self.recommendations_box.setReadOnly(True)
        security_layout.addWidget(self.score_progress)
        security_layout.addWidget(self.score_label)
        security_layout.addWidget(self.last_scan_label)
        security_layout.addWidget(QLabel("Observations"))
        security_layout.addWidget(self.observations_box)
        security_layout.addWidget(QLabel("Recommendations"))
        security_layout.addWidget(self.recommendations_box)

        alerts_box = QGroupBox("Recent Alerts")
        alerts_layout = QVBoxLayout(alerts_box)
        self.alerts_table = QTableWidget(0, 3)
        self.alerts_table.setHorizontalHeaderLabels(["Severity", "Description", "Date"])
        self._prepare_table(self.alerts_table)
        alerts_layout.addWidget(self.alerts_table)

        split.addWidget(security_box, 2)
        split.addWidget(alerts_box, 3)
        layout.addWidget(self.dashboard_insight_card)
        layout.addLayout(cards_layout)
        layout.addLayout(split)
        return page

    def _build_scan_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)
        self.target_input = QLineEdit(self.network_scanner.suggest_target())
        self.target_input.setMinimumHeight(38)
        self.target_input.setPlaceholderText("Example: 192.168.1.0/24 or 192.168.1.10-192.168.1.40")
        self.network_mode_selector = QComboBox()
        self.network_mode_selector.setMinimumHeight(38)
        self.network_mode_selector.addItem("Quick", "quick")
        self.network_mode_selector.addItem("Balanced", "balanced")
        self.network_mode_selector.addItem("Deep", "deep")
        self.scan_button = QPushButton("Scan Network")
        self.scan_button.setMinimumHeight(40)
        self.scan_button.clicked.connect(self._launch_network_scan)
        self.cancel_scan_button = QPushButton("Cancel")
        self.cancel_scan_button.setMinimumHeight(40)
        self.cancel_scan_button.clicked.connect(self._cancel_network_scan)
        self.cancel_scan_button.setEnabled(False)
        self.export_devices_button = QPushButton("Export CSV")
        self.export_devices_button.setMinimumHeight(40)
        self.export_devices_button.clicked.connect(self._export_devices_csv)
        self.scan_status = QLabel("Ready")
        self.scan_status.setStyleSheet("color: #64748b;")
        self.scan_status.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.scan_status_badge = QLabel("READY")
        self.scan_status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scan_status_badge.setMinimumHeight(32)
        toolbar.addWidget(QLabel("IP Range"))
        toolbar.addWidget(self.target_input, 1)
        toolbar.addWidget(QLabel("Mode"))
        toolbar.addWidget(self.network_mode_selector)
        scan_actions = QHBoxLayout()
        scan_actions.setSpacing(8)
        scan_actions.addWidget(self.scan_button)
        scan_actions.addWidget(self.cancel_scan_button)
        scan_actions.addWidget(self.export_devices_button)
        toolbar.addLayout(scan_actions)
        toolbar.addWidget(self.scan_status_badge)
        toolbar.addWidget(self.scan_status, 1)

        self.scan_progress = QProgressBar()
        self.scan_progress.setRange(0, 100)
        self.scan_progress.setValue(0)
        self.scan_progress.hide()
        self.scan_progress_detail = QLabel("No scan in progress.")
        self.scan_progress_detail.setStyleSheet("color: #64748b;")

        filters = QHBoxLayout()
        filters.setSpacing(10)
        self.device_search_input = QLineEdit()
        self.device_search_input.setMinimumHeight(38)
        self.device_search_input.setPlaceholderText("Search by IP, MAC, or hostname")
        self.device_search_input.addAction(
            self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogContentsView),
            QLineEdit.ActionPosition.LeadingPosition,
        )
        self.device_search_input.textChanged.connect(self._refresh_scan_table)
        self.device_filter_combo = QComboBox()
        self.device_filter_combo.setMinimumHeight(38)
        self.device_filter_combo.addItems(["All", "Known", "Unknown"])
        self.device_filter_combo.currentTextChanged.connect(self._refresh_scan_table)
        filters.addWidget(QLabel("Search"))
        filters.addWidget(self.device_search_input, 1)
        filters.addWidget(QLabel("Filter"))
        filters.addWidget(self.device_filter_combo)

        self.scan_table = QTableWidget(0, 9)
        self.scan_table.setHorizontalHeaderLabels(
            ["IP", "MAC", "Hostname", "Type", "OS", "Vendor", "Method", "Status", "Confidence"]
        )
        self._prepare_table(self.scan_table)
        self.scan_table.setSortingEnabled(True)
        self.scan_table.itemSelectionChanged.connect(self._refresh_ai_context_panel)

        layout.addLayout(toolbar)
        layout.addWidget(self.scan_progress)
        layout.addWidget(self.scan_progress_detail)
        layout.addLayout(filters)
        layout.addWidget(self.scan_table)
        return page

    def _build_ports_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)
        self.host_selector = QComboBox()
        self.host_selector.setMinimumHeight(38)
        self.host_selector.currentTextChanged.connect(self._refresh_port_table)
        self.host_selector.currentTextChanged.connect(self._refresh_ai_context_panel)
        self.port_mode_selector = QComboBox()
        self.port_mode_selector.setMinimumHeight(38)
        self.port_mode_selector.addItem("Quick", "quick")
        self.port_mode_selector.addItem("Common", "common")
        self.port_mode_selector.addItem("Extended 1-1024", "extended")
        self.custom_ports_input = QLineEdit()
        self.custom_ports_input.setMinimumHeight(38)
        self.custom_ports_input.setPlaceholderText("Custom ports e.g. 20-25,53,80,443")
        self.port_scan_button = QPushButton("Scan Ports")
        self.port_scan_button.setMinimumHeight(40)
        self.port_scan_button.clicked.connect(self._launch_port_scan)
        self.cancel_port_scan_button = QPushButton("Cancel")
        self.cancel_port_scan_button.setMinimumHeight(40)
        self.cancel_port_scan_button.clicked.connect(self._cancel_port_scan)
        self.cancel_port_scan_button.setEnabled(False)
        self.export_ports_button = QPushButton("Export CSV")
        self.export_ports_button.setMinimumHeight(40)
        self.export_ports_button.clicked.connect(self._export_ports_csv)
        self.port_status = QLabel("Select a host after running a network scan.")
        self.port_status.setStyleSheet("color: #64748b;")
        self.port_status.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.port_status_badge = QLabel("READY")
        self.port_status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.port_status_badge.setMinimumHeight(32)
        toolbar.addWidget(QLabel("Host"))
        toolbar.addWidget(self.host_selector, 1)
        toolbar.addWidget(QLabel("Mode"))
        toolbar.addWidget(self.port_mode_selector)
        toolbar.addWidget(self.custom_ports_input, 1)
        port_actions = QHBoxLayout()
        port_actions.setSpacing(8)
        port_actions.addWidget(self.port_scan_button)
        port_actions.addWidget(self.cancel_port_scan_button)
        port_actions.addWidget(self.export_ports_button)
        toolbar.addLayout(port_actions)
        toolbar.addWidget(self.port_status_badge)
        toolbar.addWidget(self.port_status, 1)

        self.port_table = QTableWidget(0, 5)
        self.port_table.setHorizontalHeaderLabels(["Port", "Service", "State", "Risk", "Banner"])
        self._prepare_table(self.port_table)
        self.port_table.setSortingEnabled(True)
        self.port_table.itemSelectionChanged.connect(self._refresh_ai_context_panel)
        self.port_table.itemSelectionChanged.connect(self._refresh_port_details_panel)

        self.port_details_card = QFrame()
        self.port_details_card.setObjectName("Card")
        details_layout = QVBoxLayout(self.port_details_card)
        details_layout.setContentsMargins(14, 12, 14, 12)
        details_title = QLabel("Port Details")
        details_title.setStyleSheet("font-weight: 800; font-size: 10.5pt;")
        self.port_details_label = QLabel("Select a port to inspect its service, risk, and banner.")
        self.port_details_label.setWordWrap(True)
        self.port_details_label.setStyleSheet("color: #64748b;")
        details_layout.addWidget(details_title)
        details_layout.addWidget(self.port_details_label)

        layout.addLayout(toolbar)
        layout.addWidget(self.port_table)
        layout.addWidget(self.port_details_card)
        return page

    def _build_monitor_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        top = QHBoxLayout()
        self.interface_selector = QComboBox()
        self.interface_selector.addItem("All interfaces")
        self.interface_selector.addItems(self.monitor.available_interfaces())
        self.monitor_hint = QLabel("Monitoring updates every second.")
        self.monitor_hint.setStyleSheet("color: #64748b;")
        top.addWidget(QLabel("Interface"))
        top.addWidget(self.interface_selector)
        top.addStretch(1)
        top.addWidget(self.monitor_hint)

        stats = QGridLayout()
        self.upload_label = QLabel("Upload: 0 KB/s")
        self.download_label = QLabel("Download: 0 KB/s")
        self.packets_label = QLabel("Packets: 0 / 0")
        self.bytes_label = QLabel("Bytes: 0 / 0")
        for index, widget in enumerate([self.upload_label, self.download_label, self.packets_label, self.bytes_label]):
            card = QFrame()
            card.setObjectName("Card")
            card_layout = QVBoxLayout(card)
            card_layout.addWidget(widget)
            stats.addWidget(card, index // 2, index % 2)

        self.chart = TrafficChartWidget()
        self.chart.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.average_bandwidth_label = QLabel("Average throughput: 0 KB/s")
        self.average_bandwidth_label.setStyleSheet("color: #64748b; font-weight: 600;")
        self.monitor_alert_label = QLabel("Traffic status normal.")
        self.monitor_alert_label.setStyleSheet("color: #16a34a; font-weight: 700;")

        layout.addLayout(top)
        layout.addLayout(stats)
        layout.addWidget(self.average_bandwidth_label)
        layout.addWidget(self.monitor_alert_label)
        layout.addWidget(self.chart)
        return page

    def _build_topology_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        top = QHBoxLayout()
        self.topology_status = QLabel("Simplified visual map of detected devices.")
        self.topology_status.setStyleSheet("color: #64748b;")
        refresh_button = QPushButton("Refresh Topology")
        refresh_button.clicked.connect(self._refresh_topology)
        top.addWidget(self.topology_status)
        top.addStretch(1)
        top.addWidget(refresh_button)

        self.topology_widget = TopologyWidget()
        layout.addLayout(top)
        layout.addWidget(self.topology_widget)
        return page

    def _build_history_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        top = QHBoxLayout()
        self.history_status = QLabel("Scan and analysis history.")
        self.history_status.setStyleSheet("color: #64748b;")
        refresh_button = QPushButton("Refresh History")
        refresh_button.clicked.connect(self._refresh_history_table)
        export_button = QPushButton("Export CSV")
        export_button.clicked.connect(self._export_history_csv)
        top.addWidget(self.history_status)
        top.addStretch(1)
        top.addWidget(export_button)
        top.addWidget(refresh_button)

        self.history_table = QTableWidget(0, 5)
        self.history_table.setHorizontalHeaderLabels(["Type", "Target", "Summary", "Score", "Date"])
        self._prepare_table(self.history_table)
        self.history_table.setSortingEnabled(True)

        layout.addLayout(top)
        layout.addWidget(self.history_table)
        return page

    def _build_journal_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        top = QHBoxLayout()
        self.journal_status = QLabel("Internal application event log.")
        self.journal_status.setStyleSheet("color: #64748b;")
        refresh_button = QPushButton("Refresh Event Log")
        refresh_button.clicked.connect(self._refresh_events_table)
        export_button = QPushButton("Export CSV")
        export_button.clicked.connect(self._export_events_csv)
        top.addWidget(self.journal_status)
        top.addStretch(1)
        top.addWidget(export_button)
        top.addWidget(refresh_button)

        self.events_table = QTableWidget(0, 4)
        self.events_table.setHorizontalHeaderLabels(["Category", "Level", "Message", "Date"])
        self._prepare_table(self.events_table)
        self.events_table.setSortingEnabled(True)

        layout.addLayout(top)
        layout.addWidget(self.events_table)
        return page

    def _build_reports_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        top = QHBoxLayout()
        self.generate_report_button = QPushButton("Generate PDF Report")
        self.generate_report_button.clicked.connect(self._generate_report)
        self.export_reports_button = QPushButton("Export CSV")
        self.export_reports_button.clicked.connect(self._export_reports_csv)
        self.report_status = QLabel("No reports generated yet.")
        self.report_status.setStyleSheet("color: #64748b;")
        top.addWidget(self.generate_report_button)
        top.addWidget(self.export_reports_button)
        top.addWidget(self.report_status)
        top.addStretch(1)

        self.reports_table = QTableWidget(0, 3)
        self.reports_table.setHorizontalHeaderLabels(["Name", "Date", "Score"])
        self._prepare_table(self.reports_table)
        self.reports_table.setSortingEnabled(True)

        layout.addLayout(top)
        layout.addWidget(self.reports_table)
        return page

    def _build_ai_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(16)

        hero_card = QFrame()
        hero_card.setObjectName("Card")
        hero_card.setStyleSheet(
            "QFrame#Card {"
            "background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0f172a, stop:0.55 #10233c, stop:1 #0f766e);"
            "border: 1px solid #164e63; border-radius: 20px; }"
        )
        hero_layout = QHBoxLayout(hero_card)
        hero_layout.setContentsMargins(20, 16, 20, 16)
        hero_layout.setSpacing(16)

        hero_text = QVBoxLayout()
        hero_text.setSpacing(4)
        hero_title = QLabel("AI Security Copilot")
        hero_title.setStyleSheet("font-size: 18pt; font-weight: 800; color: white;")
        hero_subtitle = QLabel(
            "Two minds in one panel: general cyber guidance and scan-aware answers powered by your current results."
        )
        hero_subtitle.setWordWrap(True)
        hero_subtitle.setStyleSheet("color: #c7d2fe; font-size: 9.5pt;")
        hero_text.addWidget(hero_title)
        hero_text.addWidget(hero_subtitle)

        hero_stats = QHBoxLayout()
        hero_stats.setSpacing(10)
        self.ai_summary_hosts = QLabel("Hosts\n0")
        self.ai_summary_ports = QLabel("Open Ports\n0")
        self.ai_summary_score = QLabel("Score\n100")
        for badge in (self.ai_summary_hosts, self.ai_summary_ports, self.ai_summary_score):
            badge.setMinimumWidth(94)
            badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            badge.setStyleSheet(
                "background: rgba(15, 23, 42, 0.55); color: white; border: 1px solid rgba(148, 163, 184, 0.25); "
                "border-radius: 14px; padding: 10px; font-size: 9.5pt; font-weight: 700;"
            )
            hero_stats.addWidget(badge)
        hero_stats.addStretch(1)

        hero_text.addLayout(hero_stats)

        hero_side = QVBoxLayout()
        hero_side.setSpacing(8)
        self.ai_mode_badge = QLabel("SCAN-AWARE")
        self.ai_mode_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ai_mode_badge.setMinimumWidth(136)
        self.ai_mode_badge.setStyleSheet(
            "background: rgba(125, 211, 252, 0.16); color: #e0f2fe; border: 1px solid rgba(125, 211, 252, 0.35); "
            "border-radius: 14px; padding: 7px 12px; font-weight: 800; letter-spacing: 1px;"
        )
        self.ai_status = QLabel("AI credentials are managed in Settings. Run an analysis when you're ready.")
        self.ai_status.setWordWrap(True)
        self.ai_status.setStyleSheet("color: #dbeafe; font-size: 9pt;")
        hero_side.addWidget(self.ai_mode_badge)
        hero_side.addWidget(self.ai_status)
        hero_side.addStretch(1)

        hero_layout.addLayout(hero_text, 3)
        hero_layout.addLayout(hero_side, 2)

        content_layout = QHBoxLayout()
        content_layout.setSpacing(16)

        left_panel = QWidget()
        left_column = QVBoxLayout(left_panel)
        left_column.setSpacing(14)
        left_column.setContentsMargins(0, 0, 0, 0)

        self.ai_mode_selector = QComboBox()
        self.ai_mode_selector.addItem("General Chat", "general")
        self.ai_mode_selector.addItem("Scan-Aware Chat", "scan-aware")
        self.ai_mode_selector.currentIndexChanged.connect(self._sync_ai_mode_ui)
        self.ai_mode_selector.setMinimumHeight(38)
        self.ai_question_input = QTextEdit()
        self.ai_question_input.setMinimumHeight(120)
        self.ai_question_input.setStyleSheet(
            "QTextEdit { border-radius: 14px; padding: 10px 12px; font-size: 10pt; }"
        )
        self.ai_model_hint = QLabel("Model and API key are managed in Settings.")
        self.ai_model_hint.setWordWrap(True)
        self.ai_model_hint.setStyleSheet("color: #64748b;")

        config_card = QFrame()
        config_card.setObjectName("Card")
        config_card.setMinimumHeight(224)
        config_layout = QFormLayout(config_card)
        config_layout.setHorizontalSpacing(16)
        config_layout.setVerticalSpacing(12)
        config_layout.addRow("Mode", self.ai_mode_selector)
        config_layout.addRow("Question", self.ai_question_input)
        config_layout.addRow("", self.ai_model_hint)

        actions = QHBoxLayout()
        self.ai_analyze_button = QPushButton("Send")
        self.ai_analyze_button.clicked.connect(self._launch_ai_analysis)
        self.ai_analyze_button.setMinimumHeight(40)
        actions.addWidget(self.ai_analyze_button)
        actions.addStretch(1)
        self.ai_typing_label = QLabel("")
        self.ai_typing_label.setStyleSheet("color: #64748b; font-weight: 600;")

        quick_card = QFrame()
        quick_card.setObjectName("Card")
        quick_card.setStyleSheet("QFrame#Card { border-radius: 18px; }")
        quick_card.setMinimumHeight(220)
        quick_layout = QGridLayout(quick_card)
        quick_layout.setHorizontalSpacing(10)
        quick_layout.setVerticalSpacing(10)
        quick_title = QLabel("Quick Actions")
        quick_title.setStyleSheet("font-size: 12pt; font-weight: 800;")
        quick_note = QLabel("Launch precise prompts instantly from the current scan context.")
        quick_note.setStyleSheet("color: #64748b;")
        quick_note.setWordWrap(True)
        quick_layout.addWidget(quick_title, 0, 0, 1, 3)
        quick_layout.addWidget(quick_note, 1, 0, 1, 3)

        self.ai_top_risks_button = QPushButton("Top Risks")
        self.ai_top_risks_button.clicked.connect(self._ask_ai_top_risks)
        self.ai_fix_first_button = QPushButton("Fix First")
        self.ai_fix_first_button.clicked.connect(self._ask_ai_fix_first)
        self.ai_suspicious_host_button = QPushButton("Suspicious Host")
        self.ai_suspicious_host_button.clicked.connect(self._ask_ai_suspicious_host)
        self.ai_explain_score_button = QPushButton("Explain Score")
        self.ai_explain_score_button.clicked.connect(self._ask_ai_explain_score)
        self.ai_close_port_button = QPushButton("Close Selected Port")
        self.ai_close_port_button.clicked.connect(self._ask_ai_close_selected_port)
        self.ai_block_ip_button = QPushButton("Block Selected IP")
        self.ai_block_ip_button.clicked.connect(self._ask_ai_block_selected_ip)

        self.ai_top_risks_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning))
        self.ai_fix_first_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))
        self.ai_suspicious_host_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogInfoView))
        self.ai_explain_score_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation))
        self.ai_close_port_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogCloseButton))
        self.ai_block_ip_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserStop))

        for button in (
            self.ai_top_risks_button,
            self.ai_fix_first_button,
            self.ai_suspicious_host_button,
            self.ai_explain_score_button,
            self.ai_close_port_button,
            self.ai_block_ip_button,
        ):
            button.setMinimumHeight(52)
            button.setIconSize(QSize(16, 16))
            button.setStyleSheet("text-align: left; padding-left: 14px;")

        quick_layout.addWidget(self.ai_top_risks_button, 2, 0)
        quick_layout.addWidget(self.ai_fix_first_button, 2, 1)
        quick_layout.addWidget(self.ai_suspicious_host_button, 2, 2)
        quick_layout.addWidget(self.ai_explain_score_button, 3, 0)
        quick_layout.addWidget(self.ai_close_port_button, 3, 1)
        quick_layout.addWidget(self.ai_block_ip_button, 3, 2)

        context_card = QFrame()
        context_card.setObjectName("Card")
        context_card.setMinimumHeight(170)
        context_layout = QVBoxLayout(context_card)
        context_layout.setSpacing(8)
        context_title = QLabel("Live Context")
        context_title.setStyleSheet("font-size: 12pt; font-weight: 800;")
        context_caption = QLabel("The copilot reads the latest host, port, and score context from your app.")
        context_caption.setStyleSheet("color: #64748b;")
        context_caption.setWordWrap(True)
        self.ai_context_hosts = QLabel("")
        self.ai_context_ports = QLabel("")
        self.ai_context_score = QLabel("")
        self.ai_context_focus = QLabel("")
        for label in (
            self.ai_context_hosts,
            self.ai_context_ports,
            self.ai_context_score,
            self.ai_context_focus,
        ):
            label.setStyleSheet("color: #cbd5e1;" if self.current_theme == "dark" else "color: #334155;")
            label.setWordWrap(True)
        context_layout.addWidget(context_title)
        context_layout.addWidget(context_caption)
        context_layout.addWidget(self.ai_context_hosts)
        context_layout.addWidget(self.ai_context_ports)
        context_layout.addWidget(self.ai_context_score)
        context_layout.addWidget(self.ai_context_focus)

        left_column.addWidget(config_card)
        left_column.addLayout(actions)
        left_column.addWidget(self.ai_typing_label)
        left_column.addWidget(quick_card)
        left_column.addWidget(context_card)
        left_column.addStretch(1)

        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setFrameShape(QFrame.Shape.NoFrame)
        left_scroll.setMinimumWidth(450)
        left_scroll.setWidget(left_panel)

        output_card = QFrame()
        output_card.setObjectName("Card")
        output_card.setStyleSheet("QFrame#Card { border-radius: 22px; }")
        output_layout = QVBoxLayout(output_card)
        output_layout.setContentsMargins(18, 18, 18, 18)
        output_layout.setSpacing(12)
        output_top = QHBoxLayout()
        transcript_title = QLabel("Conversation")
        transcript_title.setStyleSheet("font-size: 12pt; font-weight: 800;")
        transcript_note = QLabel("Chat history, replies, and tactical recommendations appear here.")
        transcript_note.setStyleSheet("color: #64748b;")
        transcript_stack = QVBoxLayout()
        transcript_stack.addWidget(transcript_title)
        transcript_stack.addWidget(transcript_note)
        output_top.addLayout(transcript_stack)
        self.ai_clear_button = QPushButton("Clear Chat")
        self.ai_clear_button.clicked.connect(self._clear_ai_chat)
        self.ai_clear_button.setMinimumHeight(38)
        output_top.addStretch(1)
        output_top.addWidget(self.ai_clear_button)
        output_layout.addLayout(output_top)
        self.ai_output = QTextEdit()
        self.ai_output.setReadOnly(True)
        self.ai_output.setMinimumHeight(420)
        self.ai_output.setPlaceholderText("The AI response will appear here after analysis.")
        self.ai_output.setStyleSheet(
            "QTextEdit { border-radius: 18px; padding: 16px; font-family: Segoe UI; font-size: 10.5pt; }"
        )
        output_layout.addWidget(self.ai_output)

        content_layout.addWidget(left_scroll, 2)
        content_layout.addWidget(output_card, 3)

        layout.addWidget(hero_card)
        layout.addLayout(content_layout, 1)
        self._apply_ai_page_theme()
        self._sync_ai_mode_ui()
        self._refresh_ai_context_panel()
        self._render_ai_empty_state()
        return page

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        intro = QLabel("Configure company identity, manage local users, and tune security thresholds.")
        intro.setStyleSheet("color: #64748b;")

        tabs = QTabWidget()

        company_content = QWidget()
        company_layout = QVBoxLayout(company_content)
        company_layout.setContentsMargins(14, 14, 14, 14)
        company_layout.setSpacing(18)

        company_section_label = QLabel("Company Info")
        company_section_label.setStyleSheet("font-size: 11pt; font-weight: 800;")

        company_card = QFrame()
        company_card.setObjectName("Card")
        company_form = QFormLayout(company_card)
        company_form.setHorizontalSpacing(16)
        company_form.setVerticalSpacing(18)
        company_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self.company_name_input = QLineEdit()
        self.department_input = QLineEdit()
        self.site_input = QLineEdit()
        self.owner_input = QLineEdit()
        self.support_email_input = QLineEdit()
        self.support_phone_input = QLineEdit()
        self.logo_path_input = QLineEdit()

        for field in (
            self.company_name_input,
            self.department_input,
            self.site_input,
            self.owner_input,
            self.support_email_input,
            self.support_phone_input,
            self.logo_path_input,
        ):
            field.setMinimumHeight(36)

        company_form.addRow("Company Name", self.company_name_input)
        company_form.addRow("Department", self.department_input)
        company_form.addRow("Site", self.site_input)
        company_form.addRow("Owner", self.owner_input)
        company_form.addRow("Support Email", self.support_email_input)
        company_form.addRow("Support Phone", self.support_phone_input)
        company_form.addRow("Logo Path", self.logo_path_input)

        logo_actions = QHBoxLayout()
        logo_actions.addStretch(1)
        self.upload_logo_button = QPushButton("Upload Logo Image")
        self.upload_logo_button.setMinimumHeight(38)
        self.upload_logo_button.clicked.connect(self._upload_logo_image)
        logo_actions.addWidget(self.upload_logo_button)

        thresholds_card = QFrame()
        thresholds_card.setObjectName("Card")
        thresholds_section_label = QLabel("Network Thresholds")
        thresholds_section_label.setStyleSheet("font-size: 11pt; font-weight: 800;")
        thresholds_layout = QFormLayout(thresholds_card)
        thresholds_layout.setHorizontalSpacing(16)
        thresholds_layout.setVerticalSpacing(16)

        self.bandwidth_threshold_input = QLineEdit()
        self.bandwidth_threshold_input.setPlaceholderText("Example: 5")
        self.managed_hosts_limit_input = QLineEdit()
        self.managed_hosts_limit_input.setPlaceholderText("Example: 20")
        self.large_network_threshold_input = QLineEdit()
        self.large_network_threshold_input.setPlaceholderText("Example: 50")

        for field in (
            self.bandwidth_threshold_input,
            self.managed_hosts_limit_input,
            self.large_network_threshold_input,
        ):
            field.setMinimumHeight(36)

        thresholds_layout.addRow("Critical Traffic Threshold (MB/s)", self.bandwidth_threshold_input)
        thresholds_layout.addRow("Managed Host Limit", self.managed_hosts_limit_input)
        thresholds_layout.addRow("Large Network Threshold", self.large_network_threshold_input)

        actions = QHBoxLayout()
        self.settings_status = QLabel("Update the company profile and thresholds, then save your changes.")
        self.settings_status.setStyleSheet("color: #64748b;")
        self.settings_save_button = QPushButton("Save Company Profile")
        self.settings_save_button.setMinimumHeight(38)
        self.settings_save_button.clicked.connect(self._save_settings)
        actions.addWidget(self.settings_status)
        actions.addStretch(1)
        actions.addWidget(self.settings_save_button)

        company_layout.addWidget(company_section_label)
        company_layout.addWidget(company_card)
        company_layout.addLayout(logo_actions)
        company_layout.addWidget(thresholds_section_label)
        company_layout.addWidget(thresholds_card)
        ai_card = QFrame()
        ai_card.setObjectName("Card")
        ai_section_label = QLabel("AI Settings")
        ai_section_label.setStyleSheet("font-size: 11pt; font-weight: 800;")
        ai_layout = QFormLayout(ai_card)
        ai_layout.setHorizontalSpacing(16)
        ai_layout.setVerticalSpacing(14)

        self.ai_api_key_input = QLineEdit()
        self.ai_api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.ai_api_key_input.setPlaceholderText("OpenRouter API key")
        self.ai_api_key_input.setMinimumHeight(36)
        self.ai_model_input = QLineEdit()
        self.ai_model_input.setPlaceholderText("Example: openai/gpt-4o-mini")
        self.ai_model_input.setMinimumHeight(36)
        self.ai_settings_status = QLabel("Store your OpenRouter API key and model here once.")
        self.ai_settings_status.setStyleSheet("color: #64748b;")
        self.ai_settings_save_button = QPushButton("Save AI Settings")
        self.ai_settings_save_button.setMinimumHeight(38)
        self.ai_settings_save_button.clicked.connect(self._save_ai_settings)
        ai_layout.addRow("OpenRouter API Key", self.ai_api_key_input)
        ai_layout.addRow("OpenRouter Model", self.ai_model_input)
        ai_actions = QHBoxLayout()
        ai_actions.addWidget(self.ai_settings_status)
        ai_actions.addStretch(1)
        ai_actions.addWidget(self.ai_settings_save_button)

        company_layout.addWidget(ai_section_label)
        company_layout.addWidget(ai_card)
        company_layout.addLayout(ai_actions)
        company_layout.addLayout(actions)
        company_layout.addStretch(1)

        company_tab = QScrollArea()
        company_tab.setWidgetResizable(True)
        company_tab.setFrameShape(QFrame.Shape.NoFrame)
        company_tab.setWidget(company_content)

        users_content = QWidget()
        users_layout = QVBoxLayout(users_content)
        users_layout.setContentsMargins(14, 14, 14, 14)
        users_layout.setSpacing(16)

        users_filters = QHBoxLayout()
        self.user_search_input = QLineEdit()
        self.user_search_input.setPlaceholderText("Search username or role...")
        self.user_search_input.setMinimumHeight(36)
        self.user_search_input.addAction(
            self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogContentsView),
            QLineEdit.ActionPosition.LeadingPosition,
        )
        self.user_search_input.textChanged.connect(self._refresh_users_table)
        self.user_role_filter = QComboBox()
        self.user_role_filter.addItems(["All Users", "Admin", "Viewer", "Disabled"])
        self.user_role_filter.setMinimumHeight(36)
        self.user_role_filter.currentTextChanged.connect(self._refresh_users_table)
        users_filters.addWidget(self.user_search_input, 1)
        users_filters.addWidget(self.user_role_filter)

        directory_label = QLabel("User Directory")
        directory_label.setStyleSheet("font-weight: 700;")

        self.users_table = QTableWidget(0, 5)
        self.users_table.setHorizontalHeaderLabels(["ID", "Username", "Role", "Active", "Created"])
        self._prepare_table(self.users_table)
        self.users_table.setSortingEnabled(True)

        user_actions_card = QFrame()
        user_actions_card.setObjectName("Card")
        user_actions_layout = QVBoxLayout(user_actions_card)
        user_actions_layout.setSpacing(10)

        add_user_label = QLabel("Create or manage local user accounts.")
        add_user_label.setStyleSheet("color: #64748b;")

        add_user_form = QGridLayout()
        self.new_username_input = QLineEdit()
        self.new_username_input.setPlaceholderText("Username")
        self.new_password_input = QLineEdit()
        self.new_password_input.setPlaceholderText("Password")
        self.new_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_role_combo = QComboBox()
        self.new_role_combo.addItems(["Viewer", "Admin"])

        for field in (self.new_username_input, self.new_password_input, self.new_role_combo):
            field.setMinimumHeight(36)

        create_user_button = QPushButton("Create User")
        create_user_button.clicked.connect(self._create_user)
        self.toggle_user_button = QPushButton("Enable / Disable Selected")
        self.toggle_user_button.clicked.connect(self._toggle_selected_user)

        add_user_form.addWidget(self.new_username_input, 0, 0)
        add_user_form.addWidget(self.new_password_input, 0, 1)
        add_user_form.addWidget(self.new_role_combo, 0, 2)
        add_user_form.addWidget(create_user_button, 0, 3)
        add_user_form.addWidget(self.toggle_user_button, 0, 4)

        self.users_status = QLabel("Manage local accounts from this section.")
        self.users_status.setStyleSheet("color: #64748b;")

        user_actions_layout.addWidget(add_user_label)
        user_actions_layout.addLayout(add_user_form)
        user_actions_layout.addWidget(self.users_status)

        users_layout.addLayout(users_filters)
        users_layout.addWidget(directory_label)
        users_layout.addWidget(self.users_table, 1)
        users_layout.addWidget(user_actions_card)
        users_layout.addStretch(1)

        users_tab = QScrollArea()
        users_tab.setWidgetResizable(True)
        users_tab.setFrameShape(QFrame.Shape.NoFrame)
        users_tab.setWidget(users_content)

        tabs.addTab(company_tab, "Company Settings")
        tabs.addTab(users_tab, "User Management")

        layout.addWidget(intro)
        layout.addWidget(tabs)
        return page

    def _prepare_table(self, table: QTableWidget) -> None:
        table.horizontalHeader().setStretchLastSection(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMouseTracking(True)
        table.setShowGrid(False)
        table.verticalHeader().hide()
        table.verticalHeader().setDefaultSectionSize(38)
        table.setStyleSheet(self._table_style())

    def _table_style(self) -> str:
        if self.current_theme == "dark":
            return (
                "QTableWidget { background: #0f1b2f; color: #e5eefb; border: 1px solid #22324a; "
                "border-radius: 12px; gridline-color: transparent; alternate-background-color: #13253d; "
                "selection-background-color: #153247; selection-color: #ffffff; } "
                "QTableWidget::item { padding: 9px 12px; border-bottom: 1px solid #1d2e47; } "
                "QTableWidget::item:hover { background: #16394b; }"
            )
        return (
            "QTableWidget { background: #ffffff; color: #172033; border: 1px solid #d6e1ee; "
            "border-radius: 12px; gridline-color: transparent; alternate-background-color: #f8fbff; "
            "selection-background-color: #e7f6f4; selection-color: #0f172a; } "
            "QTableWidget::item { padding: 9px 12px; border-bottom: 1px solid #edf2f7; } "
            "QTableWidget::item:hover { background: #f1f8ff; }"
        )

    def _apply_table_styles(self) -> None:
        for table_name in (
            "alerts_table",
            "scan_table",
            "port_table",
            "history_table",
            "events_table",
            "reports_table",
            "users_table",
        ):
            table = getattr(self, table_name, None)
            if table is not None:
                table.setStyleSheet(self._table_style())

    def _button_style(self, role: str) -> str:
        if self.current_theme == "dark":
            styles = {
                "primary": (
                    "background: #0f766e; color: white; border: 1px solid #14b8a6; "
                    "border-radius: 10px; padding: 8px 16px; font-weight: 700;"
                ),
                "secondary": (
                    "background: #132036; color: #dbe7f5; border: 1px solid #2a3f5f; "
                    "border-radius: 10px; padding: 8px 16px; font-weight: 600;"
                ),
                "ghost": (
                    "background: transparent; color: #cbd5e1; border: 1px solid #314962; "
                    "border-radius: 10px; padding: 8px 16px; font-weight: 600;"
                ),
                "quick": (
                    "background: #0f1b2f; color: #dbe7f5; border: 1px solid #29415f; "
                    "border-radius: 12px; padding: 8px 14px; font-weight: 600; text-align: left;"
                ),
            }
        else:
            styles = {
                "primary": (
                    "background: #0f766e; color: white; border: 1px solid #0d9488; "
                    "border-radius: 10px; padding: 8px 16px; font-weight: 700;"
                ),
                "secondary": (
                    "background: #ffffff; color: #243248; border: 1px solid #c7d5e5; "
                    "border-radius: 10px; padding: 8px 16px; font-weight: 600;"
                ),
                "ghost": (
                    "background: transparent; color: #334155; border: 1px solid #d0dbe8; "
                    "border-radius: 10px; padding: 8px 16px; font-weight: 600;"
                ),
                "quick": (
                    "background: #f7fbff; color: #243248; border: 1px solid #d4e1ef; "
                    "border-radius: 12px; padding: 8px 14px; font-weight: 600; text-align: left;"
                ),
            }
        return styles[role]

    def _apply_button_styles(self) -> None:
        for button_name, role in (
            ("theme_button", "secondary"),
            ("scan_button", "primary"),
            ("cancel_scan_button", "secondary"),
            ("export_devices_button", "ghost"),
            ("port_scan_button", "primary"),
            ("cancel_port_scan_button", "secondary"),
            ("export_ports_button", "ghost"),
            ("ai_analyze_button", "primary"),
            ("ai_clear_button", "secondary"),
            ("ai_settings_save_button", "secondary"),
            ("settings_save_button", "primary"),
            ("upload_logo_button", "secondary"),
        ):
            button = getattr(self, button_name, None)
            if button is not None:
                button.setStyleSheet(self._button_style(role))

        for quick_button_name in (
            "ai_top_risks_button",
            "ai_fix_first_button",
            "ai_suspicious_host_button",
            "ai_explain_score_button",
            "ai_close_port_button",
            "ai_block_ip_button",
        ):
            button = getattr(self, quick_button_name, None)
            if button is not None:
                button.setStyleSheet(self._button_style("quick"))

    def _compact_score_label(self, label: str) -> str:
        mapping = {
            "Secure Network": "Secure",
            "Moderately Secure Network": "Monitor",
            "At-Risk Network": "At Risk",
        }
        return mapping.get(label, label)

    def _build_sidebar_items(self) -> None:
        self.sidebar.clear()
        sidebar_entries = [
            ("Dashboard", QStyle.StandardPixmap.SP_DesktopIcon),
            ("Network Scan", QStyle.StandardPixmap.SP_DriveNetIcon),
            ("Port Analysis", QStyle.StandardPixmap.SP_FileDialogDetailedView),
            ("Live Monitoring", QStyle.StandardPixmap.SP_BrowserReload),
            ("Topology", QStyle.StandardPixmap.SP_DirOpenIcon),
            ("History", QStyle.StandardPixmap.SP_FileDialogContentsView),
            ("Event Log", QStyle.StandardPixmap.SP_FileDialogInfoView),
            ("Reports", QStyle.StandardPixmap.SP_FileIcon),
            ("AI Assistant", QStyle.StandardPixmap.SP_MessageBoxInformation),
            ("Settings", QStyle.StandardPixmap.SP_FileDialogListView),
        ]
        for label, icon_name in sidebar_entries:
            item = QListWidgetItem(self.style().standardIcon(icon_name), label)
            self.sidebar.addItem(item)

    def _apply_sidebar_style(self) -> None:
        if self.current_theme == "dark":
            self.sidebar.setStyleSheet(
                """
                QListWidget#Sidebar {
                    background: #0f1b2f;
                    border: 1px solid #22324a;
                    border-radius: 18px;
                    padding: 8px;
                    outline: none;
                }
                QListWidget#Sidebar::item {
                    background: transparent;
                    color: #dbe7f5;
                    border-left: 3px solid transparent;
                    border-radius: 10px;
                    padding: 12px 12px;
                    margin: 3px 0;
                }
                QListWidget#Sidebar::item:selected {
                    background: #153247;
                    color: #ffffff;
                    border-left: 3px solid #2dd4bf;
                    font-weight: 700;
                }
                QListWidget#Sidebar::item:hover {
                    background: #14273f;
                }
                """
            )
            return

        self.sidebar.setStyleSheet(
            """
            QListWidget#Sidebar {
                background: white;
                border: 1px solid #d6e1ee;
                border-radius: 18px;
                padding: 8px;
                outline: none;
            }
            QListWidget#Sidebar::item {
                background: transparent;
                color: #243248;
                border-left: 3px solid transparent;
                border-radius: 10px;
                padding: 12px 12px;
                margin: 3px 0;
            }
            QListWidget#Sidebar::item:selected {
                background: #e7f6f4;
                color: #0f172a;
                border-left: 3px solid #0f766e;
                font-weight: 700;
            }
            QListWidget#Sidebar::item:hover {
                background: #f3f8fd;
            }
            """
        )

    def _change_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        if index == 9:
            self._load_settings_values()

    def _load_initial_state(self) -> None:
        self._load_saved_port_results()
        self.alert_cache = {
            (alert.type_alert, alert.description)
            for alert in self.database.fetch_alerts(limit=500)
        }
        self._load_settings_values()
        self._refresh_scan_table()
        self._refresh_host_selector()
        self._refresh_topology()
        self._refresh_alerts_table()
        self._refresh_history_table()
        self._refresh_events_table()
        self._refresh_reports_table()
        self._recalculate_security()
        self._update_dashboard_cards()

    def _load_settings_values(self) -> None:
        self.security_settings = self.database.fetch_security_settings()
        self.company_name_input.setText(self.database.get_setting("company_name", "NetSecure Enterprise"))
        self.department_input.setText(self.database.get_setting("department", "Security Operations Center"))
        self.site_input.setText(self.database.get_setting("site", "Head Office"))
        self.owner_input.setText(self.database.get_setting("owner", "Infrastructure & Cybersecurity Team"))
        self.support_email_input.setText(self.database.get_setting("support_email", "soc@netsecure-enterprise.local"))
        self.support_phone_input.setText(self.database.get_setting("support_phone", "+212 5 00 00 00 00"))
        self.logo_path_input.setText(self.database.get_setting("logo_path", ""))
        self.bandwidth_threshold_input.setText(
            f"{self.security_settings.bandwidth_alert_threshold_bps / (1024 * 1024):.2f}".rstrip("0").rstrip(".")
        )
        self.managed_hosts_limit_input.setText(str(self.security_settings.managed_hosts_limit))
        self.large_network_threshold_input.setText(str(self.security_settings.large_network_threshold))
        if hasattr(self, "ai_api_key_input"):
            self.ai_api_key_input.setText(self.database.get_setting("openrouter_api_key", ""))
            saved_model = self.database.get_setting("openrouter_model", "openai/gpt-4o-mini")
            self.ai_model_input.setText(saved_model)
            saved_mode = self.database.get_setting("openrouter_mode", "scan-aware")
            mode_index = self.ai_mode_selector.findData(saved_mode)
            self.ai_mode_selector.setCurrentIndex(mode_index if mode_index >= 0 else 1)
            if hasattr(self, "ai_model_hint"):
                self.ai_model_hint.setText(f"Model: {saved_model} | API key is managed in Settings.")
            self._sync_ai_mode_ui()
        self._update_header_branding()
        if hasattr(self, "users_table"):
            self._refresh_users_table()

    def _load_saved_port_results(self) -> None:
        self.port_results_by_ip.clear()
        for row in self.database.fetch_port_scan_summary():
            result = PortScanResult(
                device_ip=row["ip_address"],
                port=int(row["port"]),
                service=row["service"],
                state=row["state"],
                risk_level=row["risk_level"],
                banner=row["banner"],
            )
            self.port_results_by_ip.setdefault(row["ip_address"], []).append(result)

    def _toggle_theme(self, *_args) -> None:
        target_theme = "dark" if self.current_theme == "light" else "light"
        self._apply_theme(target_theme, persist=True)
        self._log_event("Interface", "Info", f"Theme switched to {target_theme} mode.")

    def _apply_theme(self, theme: str, persist: bool = True) -> None:
        self.current_theme = theme
        QApplication.instance().setStyleSheet(DARK_STYLE if theme == "dark" else LIGHT_STYLE)
        self._apply_sidebar_style()
        self._apply_button_styles()
        self._apply_table_styles()
        self.theme_button.setText("Light Mode" if theme == "dark" else "Dark Mode")
        self.header_subtitle.setStyleSheet("color: #9fb2c9;" if theme == "dark" else "color: #60748a;")
        self.header_welcome.setStyleSheet("font-weight: 600; color: #9fb2c9;" if theme == "dark" else "font-weight: 600; color: #60748a;")
        self.chart.set_theme(theme)
        self.topology_widget.set_theme(theme)
        self._apply_ai_page_theme()
        if persist:
            self.database.set_setting("theme", theme)
        self._update_security_panels()
        if hasattr(self, "scan_status_badge"):
            self._set_status_badge(self.scan_status_badge, self.scan_status_badge.text().strip().lower() or "ready")
        if hasattr(self, "port_status_badge"):
            self._set_status_badge(self.port_status_badge, self.port_status_badge.text().strip().lower() or "ready")
        self._refresh_alerts_table()
        self._refresh_port_table(self.host_selector.currentText())
        self._refresh_events_table()
        self._refresh_topology()

    def _launch_network_scan(self, *_args) -> None:
        target = self.target_input.text().strip()
        mode = str(self.network_mode_selector.currentData() or "balanced")
        self.scan_button.setEnabled(False)
        self.cancel_scan_button.setEnabled(True)
        self.scan_progress.show()
        self.scan_progress.setValue(0)
        self.scan_progress_detail.setText("Preparing network scan...")
        self._set_status_badge(self.scan_status_badge, "running")
        self.scan_status.setText(f"Network scan in progress on {target} ({mode})...")
        self._log_event("Network Discovery", "Info", f"Network scan started on {target} in {mode} mode.")
        worker = NetworkScanThread(self.network_scanner, target, mode)
        self._workers.append(worker)
        self.active_network_scan_thread = worker
        worker.progress.connect(self._handle_network_scan_progress)
        worker.result_ready.connect(lambda result, ctx=(target, mode): self._handle_network_scan_result(result, ctx))
        worker.cancelled.connect(lambda result, ctx=(target, mode): self._handle_network_scan_cancelled(result, ctx))
        worker.error.connect(self._handle_worker_error)
        worker.finished.connect(lambda: self._cleanup_worker(worker))
        worker.start()

    def _cancel_network_scan(self, *_args) -> None:
        if self.active_network_scan_thread is None:
            return
        self.active_network_scan_thread.cancel()
        self.cancel_scan_button.setEnabled(False)
        self._set_status_badge(self.scan_status_badge, "cancelled")
        self.scan_progress_detail.setText("Cancelling network scan...")
        self._log_event("Network Discovery", "Info", "Network scan cancellation requested.")

    def _handle_network_scan_progress(self, current: int, total: int, active: int, current_ip: str) -> None:
        if total <= 0:
            return
        percentage = int((current / total) * 100)
        self.scan_progress.setValue(percentage)
        self.scan_progress_detail.setText(
            f"{current}/{total} host(s) tested | {active} active | latest: {current_ip}"
        )

    def _handle_network_scan_result(self, result: list[Device], context: tuple[str, str]) -> None:
        target, mode = context
        self.scan_button.setEnabled(True)
        self.cancel_scan_button.setEnabled(False)
        self.active_network_scan_thread = None
        self.scan_progress.setValue(100)
        known_before = {device.ip_address for device in self.database.fetch_devices()}
        self.devices = result
        self.database.record_devices(result)
        alerts = self.analyzer.generate_alerts(
            result,
            self._all_port_results(),
            known_before,
            self.latest_snapshot,
            self.security_settings,
        )
        self._persist_new_alerts(alerts)
        self._recalculate_security()
        ping_hits = sum(1 for device in result if "Ping" in device.discovery_method)
        arp_hits = sum(1 for device in result if "ARP" in device.discovery_method)
        tcp_hits = sum(1 for device in result if "TCP:" in device.discovery_method)
        summary = (
            f"{len(result)} active host(s) detected | "
            f"ping={ping_hits}, arp={arp_hits}, tcp={tcp_hits}"
        )
        self.database.record_scan_run("Network Scan", target, summary, self.latest_assessment.score)
        self._log_event(
            "Network Discovery",
            "Success",
            f"Scan completed on {target} in {mode} mode with {len(result)} active hosts.",
        )
        self._refresh_scan_table()
        self._refresh_host_selector()
        self._refresh_topology()
        self._refresh_history_table()
        self._set_status_badge(self.scan_status_badge, "completed")
        self.scan_progress_detail.setText("Scan completed.")
        self.scan_status.setText(f"{summary}.")
        self._show_toast("Scan completed successfully", "success")

    def _handle_network_scan_cancelled(self, result: list[Device], context: tuple[str, str]) -> None:
        target, mode = context
        self.scan_button.setEnabled(True)
        self.cancel_scan_button.setEnabled(False)
        self.active_network_scan_thread = None
        self.devices = result
        if result:
            self.database.record_devices(result)
            self._refresh_scan_table()
            self._refresh_host_selector()
            self._refresh_topology()
        self.scan_progress.hide()
        self._set_status_badge(self.scan_status_badge, "cancelled")
        self.scan_progress_detail.setText("Network scan cancelled by the user.")
        self.scan_status.setText(f"Network scan cancelled on {target} ({mode}).")
        self._log_event(
            "Network Discovery",
            "Info",
            f"Network scan cancelled on {target} ({mode}) with {len(result)} partial result(s).",
        )

    def _launch_port_scan(self, *_args) -> None:
        ip_address = self.host_selector.currentText().strip()
        if not ip_address:
            QMessageBox.information(self, "Port Scan", "Start by running a network scan.")
            return
        mode = str(self.port_mode_selector.currentData() or "common")
        custom_ports = self.custom_ports_input.text().strip()
        self.port_scan_button.setEnabled(False)
        self.cancel_port_scan_button.setEnabled(True)
        mode_label = "custom" if custom_ports else mode
        self._set_status_badge(self.port_status_badge, "running")
        self.port_status.setText(f"Port scan in progress on {ip_address} ({mode_label})...")
        self._log_event("Port Scanner", "Info", f"Port scan started on {ip_address} in {mode_label} mode.")
        worker = PortScanThread(self.port_scanner, ip_address, mode, custom_ports)
        self._workers.append(worker)
        self.active_port_scan_thread = worker
        worker.progress.connect(self._handle_port_scan_progress)
        worker.result_ready.connect(lambda result, ctx=(ip_address, mode_label): self._handle_port_scan_result(result, ctx))
        worker.cancelled.connect(lambda result, ctx=(ip_address, mode_label): self._handle_port_scan_cancelled(result, ctx))
        worker.error.connect(self._handle_worker_error)
        worker.finished.connect(lambda: self._cleanup_worker(worker))
        worker.start()

    def _cancel_port_scan(self, *_args) -> None:
        if self.active_port_scan_thread is None:
            return
        self.active_port_scan_thread.cancel()
        self.cancel_port_scan_button.setEnabled(False)
        self._set_status_badge(self.port_status_badge, "cancelled")
        self.port_status.setText("Cancelling port scan...")
        self._log_event("Port Scanner", "Info", "Port scan cancellation requested.")

    def _handle_port_scan_progress(self, current: int, total: int, open_count: int, current_port: int) -> None:
        self.port_status.setText(
            f"Ports tested: {current}/{total} | open: {open_count} | latest port: {current_port}"
        )

    def _handle_port_scan_result(self, result: list[PortScanResult], context: tuple[str, str]) -> None:
        ip_address, mode_label = context
        self.port_scan_button.setEnabled(True)
        self.cancel_port_scan_button.setEnabled(False)
        self.active_port_scan_thread = None
        self.port_results_by_ip[ip_address] = result
        self.database.record_port_scan(ip_address, result)
        self._refine_device_after_port_scan(ip_address, result)
        alerts = self.analyzer.generate_alerts(
            self.devices,
            self._all_port_results(),
            self._known_ips(),
            self.latest_snapshot,
            self.security_settings,
        )
        self._persist_new_alerts(alerts)
        self._recalculate_security()
        summary = f"{len(result)} open port(s) | mode={mode_label}"
        self.database.record_scan_run("Port Scan", ip_address, summary, self.latest_assessment.score)
        self._log_event(
            "Port Scanner",
            "Success",
            f"Port scan completed on {ip_address}: {len(result)} open port(s), mode {mode_label}.",
        )
        self._refresh_port_table(ip_address)
        self._refresh_topology()
        self._refresh_history_table()
        self._set_status_badge(self.port_status_badge, "completed")
        self.port_status.setText(f"{summary} on {ip_address}.")
        risky_ports = sum(1 for item in result if item.risk_level == "Critical")
        if risky_ports:
            self._show_toast(f"{risky_ports} critical port(s) detected on {ip_address}", "critical")
        else:
            self._show_toast("Port scan completed successfully", "success")

    def _handle_port_scan_cancelled(self, result: list[PortScanResult], context: tuple[str, str]) -> None:
        ip_address, mode_label = context
        self.port_scan_button.setEnabled(True)
        self.cancel_port_scan_button.setEnabled(False)
        self.active_port_scan_thread = None
        self.port_results_by_ip[ip_address] = result
        if result:
            self.database.record_port_scan(ip_address, result)
            self._refine_device_after_port_scan(ip_address, result)
            self._refresh_port_table(ip_address)
            self._refresh_topology()
        self._set_status_badge(self.port_status_badge, "cancelled")
        self.port_status.setText(f"Port scan cancelled on {ip_address} ({mode_label}) with {len(result)} result(s).")
        self._log_event(
            "Port Scanner",
            "Info",
            f"Port scan cancelled on {ip_address} ({mode_label}) with {len(result)} partial result(s).",
        )

    def _refine_device_after_port_scan(self, ip_address: str, results: list[PortScanResult]) -> None:
        for index, device in enumerate(self.devices):
            if device.ip_address != ip_address:
                continue
            refined_device = self.network_scanner.refine_device_with_services(device, results)
            self.devices[index] = refined_device
            self.database.record_devices([refined_device])
            break

    def _generate_report(self, *_args) -> None:
        alerts = self.database.fetch_alerts(limit=15)
        pdf_path = self.reporter.generate(
            self.devices,
            self._all_port_results(),
            self.latest_assessment,
            alerts,
            self.database.fetch_company_profile(),
        )
        self.database.record_report(pdf_path.name, self.latest_assessment.score)
        self.database.record_scan_run(
            "Report",
            pdf_path.name,
            f"PDF report generated with score {self.latest_assessment.score}",
            self.latest_assessment.score,
        )
        self._log_event("Reporting", "Success", f"PDF report generated: {pdf_path.name}.")
        self._refresh_reports_table()
        self._refresh_history_table()
        self.report_status.setText(f"Report generated: {pdf_path}")
        QMessageBox.information(self, "Report", f"PDF report generated:\n{Path(pdf_path).resolve()}")

    def _start_worker(self, callback, args: list[object], result_handler, extra_value: object | None = None) -> None:
        worker = WorkerThread(callback, *args)
        self._workers.append(worker)
        if extra_value is None:
            worker.result_ready.connect(result_handler)
        else:
            worker.result_ready.connect(lambda result, ip=extra_value: result_handler(result, ip))
        worker.error.connect(self._handle_worker_error)
        worker.finished.connect(lambda: self._cleanup_worker(worker))
        worker.start()

    def _cleanup_worker(self, worker: WorkerThread) -> None:
        if worker in self._workers:
            self._workers.remove(worker)

    def _handle_worker_error(self, message: str) -> None:
        self.scan_button.setEnabled(True)
        self.cancel_scan_button.setEnabled(False)
        self.port_scan_button.setEnabled(True)
        self.cancel_port_scan_button.setEnabled(False)
        if hasattr(self, "scan_status_badge"):
            self._set_status_badge(self.scan_status_badge, "failed")
        if hasattr(self, "port_status_badge"):
            self._set_status_badge(self.port_status_badge, "failed")
        if hasattr(self, "ai_analyze_button"):
            self.ai_analyze_button.setEnabled(True)
            self.pending_ai_question = ""
        if hasattr(self, "ai_typing_label"):
            self.ai_typing_label.setText("")
        if hasattr(self, "ai_status"):
            self.ai_status.setText("AI analysis failed.")
        self.active_network_scan_thread = None
        self.active_port_scan_thread = None
        self.scan_progress.hide()
        self.scan_progress_detail.setText("Scan interrupted.")
        self.scan_status.setText("Scan failed.")
        self.port_status.setText("Scan failed.")
        self._log_event("System", "Error", f"Operation interrupted: {message}")
        QMessageBox.critical(self, "Operation Interrupted", message)

    def _refresh_scan_table(self, *_args) -> None:
        search = self.device_search_input.text().strip().lower() if hasattr(self, "device_search_input") else ""
        selected_filter = self.device_filter_combo.currentText() if hasattr(self, "device_filter_combo") else "All"

        filtered: list[Device] = []
        for device in self.devices:
            haystack = (
                f"{device.ip_address} {device.mac_address} {device.hostname} "
                f"{device.vendor} {device.discovery_method} {device.device_type} {device.os_guess}"
            ).lower()
            if search and search not in haystack:
                continue
            if selected_filter == "Known" and not device.is_known:
                continue
            if selected_filter == "Unknown" and device.is_known:
                continue
            filtered.append(device)

        self.scan_table.setSortingEnabled(False)
        self.scan_table.setRowCount(len(filtered))
        for row, device in enumerate(filtered):
            values = [
                device.ip_address,
                device.mac_address,
                device.hostname,
                device.device_type,
                device.os_guess,
                device.vendor,
                device.discovery_method,
                device.status,
                "Known" if device.is_known else "Unknown",
            ]
            for column, value in enumerate(values):
                self.scan_table.setItem(row, column, QTableWidgetItem(value))
        self.scan_table.setSortingEnabled(True)

    def _refresh_host_selector(self) -> None:
        current = self.host_selector.currentText()
        self.host_selector.blockSignals(True)
        self.host_selector.clear()
        self.host_selector.addItems([device.ip_address for device in self.devices])
        if current:
            index = self.host_selector.findText(current)
            if index >= 0:
                self.host_selector.setCurrentIndex(index)
        self.host_selector.blockSignals(False)
        if self.host_selector.count() > 0:
            self._refresh_port_table(self.host_selector.currentText() or self.host_selector.itemText(0))
        else:
            self.port_table.setRowCount(0)

    def _refresh_port_table(self, ip_address: str | None) -> None:
        ip_address = (ip_address or "").strip()
        results = self.port_results_by_ip.get(ip_address, [])
        self.port_table.setSortingEnabled(False)
        self.port_table.setRowCount(len(results))
        for row, result in enumerate(results):
            values = [str(result.port), result.service, result.state, result.risk_level, result.banner or "-"]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 3:
                    item.setForeground(QColor(self._risk_color(result.risk_level)))
                self.port_table.setItem(row, column, item)
        self.port_table.setSortingEnabled(True)
        self._refresh_port_details_panel()

    def _refresh_alerts_table(self) -> None:
        alerts = self.database.fetch_alerts(limit=12)
        self.alerts_table.setSortingEnabled(False)
        self.alerts_table.setRowCount(len(alerts))
        for row, alert in enumerate(alerts):
            values = (alert.severity, alert.description, alert.created_at)
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    fill, text = self._severity_badge_colors(alert.severity)
                    item.setText(f" {alert.severity.upper()} ")
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    item.setForeground(QColor(text))
                    item.setBackground(QColor(fill))
                else:
                    item.setBackground(QColor(self._severity_row_background(alert.severity)))
                self.alerts_table.setItem(row, column, item)
        self.alerts_table.setSortingEnabled(True)

    def _refresh_history_table(self, *_args) -> None:
        runs = self.database.fetch_scan_runs(limit=40)
        self.history_table.setSortingEnabled(False)
        self.history_table.setRowCount(len(runs))
        for row, run in enumerate(runs):
            values = [run.scan_type, run.target, run.summary, str(run.score), run.created_at]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 3:
                    item.setForeground(QColor(self._score_color(int(value))))
                self.history_table.setItem(row, column, item)
        self.history_table.setSortingEnabled(True)
        if runs:
            last = runs[0]
            self.last_scan_label.setText(f"Last scan: {last.scan_type} | {last.target} | {last.created_at}")
        else:
            self.last_scan_label.setText("Last scan: no history available yet.")

    def _refresh_events_table(self, *_args) -> None:
        events = self.database.fetch_event_logs(limit=60)
        self.events_table.setSortingEnabled(False)
        self.events_table.setRowCount(len(events))
        for row, event in enumerate(events):
            values = [event.category, event.level, event.message, event.created_at]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 1:
                    item.setForeground(QColor(self._event_level_color(event.level)))
                self.events_table.setItem(row, column, item)
        self.events_table.setSortingEnabled(True)

    def _refresh_users_table(self, *_args) -> None:
        users = self.database.fetch_users()
        search = self.user_search_input.text().strip().lower() if hasattr(self, "user_search_input") else ""
        role_filter = self.user_role_filter.currentText() if hasattr(self, "user_role_filter") else "All Users"

        filtered: list[object] = []
        for user in users:
            username = str(user["username"])
            role = str(user["role"])
            active = str(user["active"])
            haystack = f"{username} {role} {active}".lower()
            if search and search not in haystack:
                continue
            if role_filter == "Admin" and role != "Admin":
                continue
            if role_filter == "Viewer" and role != "Viewer":
                continue
            if role_filter == "Disabled" and active != "No":
                continue
            filtered.append(user)

        self.users_table.setSortingEnabled(False)
        self.users_table.setRowCount(len(filtered))
        for row, user in enumerate(filtered):
            values = [
                str(user["id"]),
                str(user["username"]),
                str(user["role"]),
                str(user["active"]),
                str(user["created_at"]),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 3:
                    item.setForeground(QColor(self._severity_color("Success" if value == "Yes" else "Medium")))
                self.users_table.setItem(row, column, item)
        self.users_table.setSortingEnabled(True)

    def _app_window_title(self) -> str:
        company_name = self.company_profile.get("company_name", "NetSecure Pro").strip() or "NetSecure Pro"
        if company_name.lower() == "netsecure pro":
            return company_name
        return f"{company_name} - NetSecure Pro"

    def _logo_badge_text(self, company_name: str) -> str:
        parts = [part[0] for part in company_name.split() if part]
        if not parts:
            return "NS"
        return "".join(parts[:3]).upper()

    def _build_circular_logo_pixmap(self, logo_path: str, accent_color: str) -> QPixmap | None:
        if not logo_path or not Path(logo_path).exists():
            return None

        source = QPixmap(logo_path)
        if source.isNull():
            return None

        size = self.header_logo.size()
        canvas = QPixmap(size)
        canvas.fill(Qt.GlobalColor.transparent)

        painter = QPainter(canvas)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)

        path = QPainterPath()
        rect = QRectF(canvas.rect().adjusted(3, 3, -3, -3))
        path.addEllipse(rect)
        painter.setClipPath(path)
        scaled = source.scaled(
            rect.toRect().size(),
            Qt.AspectRatioMode.KeepAspectRatioByExpanding,
            Qt.TransformationMode.SmoothTransformation,
        )
        offset_x = int(rect.x() + (rect.width() - scaled.width()) / 2)
        offset_y = int(rect.y() + (rect.height() - scaled.height()) / 2)
        painter.drawPixmap(offset_x, offset_y, scaled)
        painter.setClipping(False)
        painter.setPen(QPen(QColor(accent_color), 3))
        painter.drawEllipse(rect)
        painter.end()
        return canvas

    def _update_header_branding(self) -> None:
        if not hasattr(self, "header_logo"):
            return

        self.company_profile = self.database.fetch_company_profile()
        company_name = self.company_profile.get("company_name", "NetSecure Enterprise")
        department = self.company_profile.get("department", "Security Operations Center")
        site = self.company_profile.get("site", "Head Office")
        primary_color = self.company_profile.get("primary_color", "#0ea5a8")
        accent_color = self.company_profile.get("accent_color", "#54b8ff")
        logo_path = self.company_profile.get("logo_path", "").strip()

        if hasattr(self, "company_name_input"):
            company_name = self.company_name_input.text().strip() or company_name
            department = self.department_input.text().strip() or department
            site = self.site_input.text().strip() or site
            logo_path = self.logo_path_input.text().strip() or logo_path

        self.header_title.setText(company_name or "NetSecure Pro")
        self.header_subtitle.setText(department or site or "Security Operations Center")
        self.header_welcome.setText(f"Welcome back, {self.username.title()}")
        self.setWindowTitle(self._app_window_title())

        circular_logo = self._build_circular_logo_pixmap(logo_path, accent_color)
        if circular_logo is not None:
            self.header_logo.setPixmap(circular_logo)
            self.header_logo.setText("")
            self.header_logo.setStyleSheet("background: transparent;")
            return

        badge_text = self._logo_badge_text(company_name)
        self.header_logo.setPixmap(QPixmap())
        self.header_logo.setText(badge_text)
        self.header_logo.setStyleSheet(
            (
                f"border: 3px solid {accent_color}; border-radius: 30px; "
                f"background: {primary_color}; color: white; font-size: 16pt; font-weight: 800;"
            )
        )

    def _upload_logo_image(self, *_args) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose a logo",
            str(Path.cwd()),
            "Images (*.png *.jpg *.jpeg *.bmp *.svg)",
        )
        if not file_path:
            return
        self.logo_path_input.setText(file_path)
        self._update_header_branding()
        self.settings_status.setText("Logo selected. Remember to save the company profile.")

    def _save_ai_settings(self, *_args) -> None:
        api_key = self.ai_api_key_input.text().strip()
        model = self.ai_model_input.text().strip() or "openai/gpt-4o-mini"
        mode = str(self.ai_mode_selector.currentData() or "scan-aware")
        self.database.set_setting("openrouter_api_key", api_key)
        self.database.set_setting("openrouter_model", model)
        self.database.set_setting("openrouter_mode", mode)
        self.ai_status.setText("AI profile loaded from Settings.")
        if hasattr(self, "ai_settings_status"):
            self.ai_settings_status.setText("AI credentials and model saved successfully.")
        if hasattr(self, "ai_model_hint"):
            self.ai_model_hint.setText(f"Model: {model} | API key is managed in Settings.")
        self._log_event("AI", "Success", f"OpenRouter settings updated for model {model} in {mode} mode.")

    def _apply_ai_page_theme(self) -> None:
        if not hasattr(self, "ai_analyze_button"):
            return

        if self.current_theme == "dark":
            secondary_style = (
                "background: #132036; color: #dbe7f5; border: 1px solid #2a3f5f; "
                "border-radius: 12px; padding: 8px 16px; font-weight: 600;"
            )
            primary_style = (
                "background: #0f766e; color: white; border: 1px solid #0f9488; "
                "border-radius: 12px; padding: 8px 18px; font-weight: 700;"
            )
            quick_style = (
                "background: #0f1b2f; color: #dbe7f5; border: 1px solid #29415f; "
                "border-radius: 12px; padding: 8px 14px; font-weight: 600; text-align: left;"
            )
            output_style = (
                "QTextEdit { background: #0b1526; color: #e5eefb; border: 1px solid #23344c; "
                "border-radius: 18px; padding: 14px; font-family: Segoe UI; font-size: 10pt; }"
            )
            note_color = "color: #9fb2c9;"
        else:
            secondary_style = (
                "background: #ffffff; color: #243248; border: 1px solid #c7d5e5; "
                "border-radius: 12px; padding: 8px 16px; font-weight: 600;"
            )
            primary_style = (
                "background: #0f766e; color: white; border: 1px solid #0d9488; "
                "border-radius: 12px; padding: 8px 18px; font-weight: 700;"
            )
            quick_style = (
                "background: #f7fbff; color: #243248; border: 1px solid #d4e1ef; "
                "border-radius: 12px; padding: 8px 14px; font-weight: 600; text-align: left;"
            )
            output_style = (
                "QTextEdit { background: #fbfdff; color: #172033; border: 1px solid #d7e3f0; "
                "border-radius: 18px; padding: 14px; font-family: Segoe UI; font-size: 10pt; }"
            )
            note_color = "color: #60748a;"

        self.ai_analyze_button.setStyleSheet(primary_style)
        self.ai_clear_button.setStyleSheet(secondary_style)
        self.ai_output.setStyleSheet(output_style)
        self.ai_question_input.setStyleSheet(
            "QTextEdit { border-radius: 14px; padding: 10px 12px; font-size: 10pt; }"
        )

        for quick_button in (
            self.ai_top_risks_button,
            self.ai_fix_first_button,
            self.ai_suspicious_host_button,
            self.ai_explain_score_button,
            self.ai_close_port_button,
            self.ai_block_ip_button,
        ):
            quick_button.setStyleSheet(quick_style)

        for label in (
            self.ai_context_hosts,
            self.ai_context_ports,
            self.ai_context_score,
            self.ai_context_focus,
        ):
            label.setStyleSheet(note_color)
        if hasattr(self, "ai_model_hint"):
            self.ai_model_hint.setStyleSheet(note_color)
        if hasattr(self, "ai_typing_label"):
            self.ai_typing_label.setStyleSheet(note_color + " font-weight: 700;")

    def _set_ai_mode(self, mode: str) -> None:
        index = self.ai_mode_selector.findData(mode)
        if index >= 0:
            self.ai_mode_selector.setCurrentIndex(index)

    def _update_dashboard_insight(self) -> None:
        if not hasattr(self, "dashboard_insight_label"):
            return

        alerts = self.database.fetch_alerts(limit=20)
        critical_count = sum(1 for alert in alerts if alert.severity == "Critical")
        high_count = sum(1 for alert in alerts if alert.severity == "High")
        if critical_count:
            text = f"{critical_count} critical issue(s) detected - immediate action recommended."
            style = (
                "background: #fee2e2; border: 1px solid #fecaca; border-radius: 12px;"
                if self.current_theme == "light"
                else "background: #3b1218; border: 1px solid #7f1d1d; border-radius: 12px;"
            )
        elif high_count:
            text = f"{high_count} high-priority alert(s) need review."
            style = (
                "background: #fff7ed; border: 1px solid #fed7aa; border-radius: 12px;"
                if self.current_theme == "light"
                else "background: #3a2311; border: 1px solid #9a3412; border-radius: 12px;"
            )
        elif self.latest_assessment.score >= 80:
            text = "Network stable - no major threats detected."
            style = (
                "background: #ecfdf5; border: 1px solid #bbf7d0; border-radius: 12px;"
                if self.current_theme == "light"
                else "background: #102b1f; border: 1px solid #166534; border-radius: 12px;"
            )
        else:
            text = "Network activity requires monitoring - review the latest findings and exposed services."
            style = (
                "background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 12px;"
                if self.current_theme == "light"
                else "background: #10223a; border: 1px solid #1d4ed8; border-radius: 12px;"
            )

        self.dashboard_insight_card.setStyleSheet(style)
        self.dashboard_insight_label.setText(text)

    def _severity_badge_colors(self, severity: str) -> tuple[str, str]:
        colors = {
            "Critical": ("#fee2e2" if self.current_theme == "light" else "#7f1d1d", "#991b1b" if self.current_theme == "light" else "#fee2e2"),
            "High": ("#ffedd5" if self.current_theme == "light" else "#7c2d12", "#9a3412" if self.current_theme == "light" else "#ffedd5"),
            "Medium": ("#fef3c7" if self.current_theme == "light" else "#78350f", "#92400e" if self.current_theme == "light" else "#fef3c7"),
            "Low": ("#dcfce7" if self.current_theme == "light" else "#14532d", "#166534" if self.current_theme == "light" else "#dcfce7"),
            "Info": ("#dbeafe" if self.current_theme == "light" else "#1e3a8a", "#1d4ed8" if self.current_theme == "light" else "#dbeafe"),
        }
        return colors.get(severity, ("#e2e8f0", "#334155"))

    def _severity_row_background(self, severity: str) -> str:
        row_colors = {
            "Critical": "#fff5f5" if self.current_theme == "light" else "#1f1115",
            "High": "#fff9f2" if self.current_theme == "light" else "#1f1610",
            "Medium": "#fffdf2" if self.current_theme == "light" else "#211c10",
            "Low": "#f5fff8" if self.current_theme == "light" else "#0f1f16",
            "Info": "#f5fbff" if self.current_theme == "light" else "#0f1825",
        }
        return row_colors.get(severity, "#ffffff" if self.current_theme == "light" else "#0f1b2f")

    def _set_status_badge(self, badge: QLabel, state: str) -> None:
        labels = {
            "idle": "READY",
            "ready": "READY",
            "running": "RUNNING",
            "completed": "COMPLETED",
            "cancelled": "CANCELLED",
            "failed": "FAILED",
        }
        styles = {
            "idle": self._button_style("ghost"),
            "ready": self._button_style("ghost"),
            "running": self._button_style("secondary"),
            "completed": self._button_style("primary"),
            "cancelled": self._button_style("ghost"),
            "failed": (
                "background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; border-radius: 10px; padding: 6px 12px; font-weight: 700;"
                if self.current_theme == "light"
                else "background: #7f1d1d; color: #fee2e2; border: 1px solid #b91c1c; border-radius: 10px; padding: 6px 12px; font-weight: 700;"
            ),
        }
        badge.setText(labels.get(state, state.upper()))
        badge.setStyleSheet(styles.get(state, self._button_style("ghost")))

    def _refresh_port_details_panel(self, *_args) -> None:
        if not hasattr(self, "port_details_label"):
            return

        ip_address, port, service = self._selected_port_context()
        if not port:
            self.port_details_label.setText("Select a port to inspect its service, risk, and banner.")
            return

        row = self.port_table.currentRow()
        risk = self.port_table.item(row, 3).text().strip() if row >= 0 and self.port_table.item(row, 3) else "Unknown"
        banner = self.port_table.item(row, 4).text().strip() if row >= 0 and self.port_table.item(row, 4) else "-"
        purpose, exposure_note = self._port_service_explanation(port, service)
        recommendation = (
            "Close or filter this service immediately."
            if risk in {"Critical", "High"}
            else "Review service exposure and keep only what is necessary."
        )
        self.port_details_label.setText(
            f"IP: {ip_address}\n"
            f"Port: {port}\n"
            f"Service: {service}\n"
            f"Risk: {risk}\n"
            f"Purpose: {purpose}\n"
            f"What it does: {exposure_note}\n"
            f"Banner: {banner}\n"
            f"Recommendation: {recommendation}"
        )

    def _port_service_explanation(self, port: str, service: str) -> tuple[str, str]:
        service_key = (service or "").strip().upper()
        port_text = str(port).strip()

        service_map = {
            "FTP": (
                "Transfers files between systems.",
                "FTP is commonly used for file upload/download, but classic FTP does not encrypt credentials or content.",
            ),
            "SSH": (
                "Provides secure remote administration.",
                "SSH lets administrators log in remotely and execute commands over an encrypted channel.",
            ),
            "TELNET": (
                "Provides remote command-line access.",
                "Telnet allows remote administration but sends traffic in clear text, which makes it unsafe on modern networks.",
            ),
            "SMTP": (
                "Handles outgoing email delivery.",
                "SMTP is used by mail servers and devices to relay or submit email messages.",
            ),
            "DNS": (
                "Resolves domain names to IP addresses.",
                "DNS translates names such as websites or internal hostnames into IP addresses so devices can communicate.",
            ),
            "HTTP": (
                "Serves web content over plain text.",
                "HTTP exposes web pages or APIs, but without TLS it does not protect the exchanged data.",
            ),
            "POP3": (
                "Downloads email from a mail server.",
                "POP3 is an older mail retrieval protocol often used by legacy email clients.",
            ),
            "NETBIOS": (
                "Supports legacy Windows name and file-sharing services.",
                "NetBIOS is often tied to old Windows discovery and sharing features and may expose internal host information.",
            ),
            "IMAP": (
                "Retrieves and manages email on a mail server.",
                "IMAP keeps messages on the server and lets clients synchronize folders and message states.",
            ),
            "HTTPS": (
                "Serves encrypted web content.",
                "HTTPS protects web traffic with TLS and is commonly used for secure dashboards, portals, and APIs.",
            ),
            "SMB": (
                "Shares files, printers, and Windows resources.",
                "SMB is widely used in Windows environments for file sharing and remote administrative access.",
            ),
            "RDP": (
                "Provides remote desktop access.",
                "RDP lets an administrator or user control a Windows system remotely through a graphical session.",
            ),
            "UNKNOWN": (
                "Exposes a reachable network service.",
                "The port is open, but the application could not confidently identify the service running behind it.",
            ),
        }

        if service_key in service_map:
            return service_map[service_key]

        port_map = {
            "21": service_map["FTP"],
            "22": service_map["SSH"],
            "23": service_map["TELNET"],
            "25": service_map["SMTP"],
            "53": service_map["DNS"],
            "80": service_map["HTTP"],
            "110": service_map["POP3"],
            "139": service_map["NETBIOS"],
            "143": service_map["IMAP"],
            "443": service_map["HTTPS"],
            "445": service_map["SMB"],
            "3389": service_map["RDP"],
        }
        if port_text in port_map:
            return port_map[port_text]

        return (
            "Exposes a reachable network service.",
            "This open port means a service is listening on the host and can accept inbound connections.",
        )

    def _show_toast(self, message: str, level: str = "info") -> None:
        if not hasattr(self, "toast_label"):
            return

        styles = {
            "success": (
                "background: #14532d; color: #ecfdf5; border: 1px solid #22c55e; border-radius: 12px; padding: 10px 14px;"
                if self.current_theme == "dark"
                else "background: #ecfdf5; color: #166534; border: 1px solid #86efac; border-radius: 12px; padding: 10px 14px;"
            ),
            "critical": (
                "background: #7f1d1d; color: #fee2e2; border: 1px solid #ef4444; border-radius: 12px; padding: 10px 14px;"
                if self.current_theme == "dark"
                else "background: #fff1f2; color: #991b1b; border: 1px solid #fda4af; border-radius: 12px; padding: 10px 14px;"
            ),
            "info": (
                "background: #10223a; color: #dbeafe; border: 1px solid #2563eb; border-radius: 12px; padding: 10px 14px;"
                if self.current_theme == "dark"
                else "background: #eff6ff; color: #1d4ed8; border: 1px solid #93c5fd; border-radius: 12px; padding: 10px 14px;"
            ),
        }
        self.toast_label.setStyleSheet(styles.get(level, styles["info"]))
        self.toast_label.setText(message)
        self.toast_label.adjustSize()
        self.toast_label.move(self.width() - self.toast_label.width() - 26, 24)
        self.toast_label.show()
        self.toast_label.raise_()
        QTimer.singleShot(3200, self.toast_label.hide)

    def _sync_ai_mode_ui(self, *_args) -> None:
        mode = str(self.ai_mode_selector.currentData() or "scan-aware")
        if mode == "general":
            self.ai_question_input.setPlaceholderText(
                "Ask how to close a port, block an IP, harden a service, or apply defensive network controls..."
            )
            self.ai_output.setPlaceholderText("General cybersecurity answers will appear here.")
            self.ai_mode_badge.setText("GENERAL CHAT")
            self.ai_mode_badge.setStyleSheet(
                "background: rgba(251, 191, 36, 0.16); color: #fef3c7; border: 1px solid rgba(251, 191, 36, 0.35); "
                "border-radius: 16px; padding: 10px 14px; font-weight: 800; letter-spacing: 1px;"
            )
            if not self.ai_chat_history:
                self.ai_status.setText("General Chat is ready for defensive cybersecurity and network administration questions.")
            self._refresh_ai_context_panel()
            return

        self.ai_question_input.setPlaceholderText(
            "Ask for a risk summary, exposed services, suspicious hosts, or remediation advice based on the latest scan..."
        )
        self.ai_output.setPlaceholderText("Scan-aware analysis will appear here.")
        self.ai_mode_badge.setText("SCAN-AWARE")
        self.ai_mode_badge.setStyleSheet(
            "background: rgba(125, 211, 252, 0.16); color: #e0f2fe; border: 1px solid rgba(125, 211, 252, 0.35); "
            "border-radius: 16px; padding: 10px 14px; font-weight: 800; letter-spacing: 1px;"
        )
        if not self.ai_chat_history:
            self.ai_status.setText("Scan-Aware Chat is linked to your current hosts, ports, alerts, and score.")
        self._refresh_ai_context_panel()

    def _clear_ai_chat(self, *_args) -> None:
        self.ai_chat_history.clear()
        self.pending_ai_question = ""
        self.pending_ai_mode = str(self.ai_mode_selector.currentData() or "scan-aware")
        if hasattr(self, "ai_typing_label"):
            self.ai_typing_label.setText("")
        self._render_ai_empty_state()
        self._sync_ai_mode_ui()
        self._log_event("AI", "Info", "AI chat history cleared.")

    def _render_ai_empty_state(self) -> None:
        mode = str(self.ai_mode_selector.currentData() or "scan-aware")
        title = "General Chat" if mode == "general" else "Scan-Aware Chat"
        hint = (
            "Ask a defensive cybersecurity question such as how to close a port, block an IP, or harden a service."
            if mode == "general"
            else "Ask for a risk summary, suspicious hosts, exposed services, or remediation advice from the latest scan."
        )
        html = f"""
        <div style="padding:18px;">
            <div style="font-size:18px; font-weight:700; margin-bottom:8px;">{escape(title)}</div>
            <div style="font-size:13px; color:#6b7280; line-height:1.6;">
                {escape(hint)}
            </div>
        </div>
        """
        self.ai_output.setHtml(html)

    def _render_ai_chat(self) -> None:
        if not self.ai_chat_history:
            self._render_ai_empty_state()
            return

        sections: list[str] = []
        current_mode = ""
        for item in self.ai_chat_history:
            mode = item.get("mode", "")
            role = item.get("role", "")
            content = item.get("content", "").strip()
            timestamp = item.get("timestamp", "")
            if not content:
                continue
            if mode and mode != current_mode:
                current_mode = mode
                label = "General Chat" if mode == "general" else "Scan-Aware Chat"
                sections.append(
                    f"<div style='margin: 8px 0 12px 0; font-size:12px; font-weight:700; color:#0f766e;'>{escape(label)}</div>"
                )
            if role == "user":
                bubble_style = (
                    "background:#e6f7f5; border:1px solid #c7ebe6; color:#172033; "
                    "border-radius:14px; padding:12px 14px; margin:8px 0 8px 56px;"
                )
                title = "You"
            else:
                bubble_style = (
                    "background:#132036; border:1px solid #22324a; color:#f8fbff; "
                    "border-radius:14px; padding:12px 14px; margin:8px 56px 8px 0;"
                )
                if self.current_theme != "dark":
                    bubble_style = (
                        "background:#f8fbff; border:1px solid #d7e3f0; color:#172033; "
                        "border-radius:14px; padding:12px 14px; margin:8px 56px 8px 0;"
                    )
                title = "AI Assistant"

            safe_content = escape(content).replace("\n", "<br>")
            time_html = f"<div style='font-size:11px; color:#94a3b8; margin-top:8px;'>{escape(timestamp)}</div>" if timestamp else ""
            sections.append(
                f"<div style='{bubble_style}'>"
                f"<div style='font-weight:700; margin-bottom:6px;'>{title}</div>"
                f"<div style='line-height:1.65; font-size:13px;'>{safe_content}</div>"
                f"{time_html}"
                f"</div>"
            )

        wrapper = "<div style='padding:10px 6px 18px 6px;'>" + "".join(sections) + "</div>"
        self.ai_output.setHtml(wrapper)

    def _refresh_ai_context_panel(self) -> None:
        if not hasattr(self, "ai_summary_hosts"):
            return

        host_count = len(self.devices)
        port_count = len(self._all_port_results())
        score = self.latest_assessment.score if hasattr(self, "latest_assessment") else 100
        focus_ip = self._selected_ip_for_ai()
        focus_ip = focus_ip or "No active host selected"
        _, port, service = self._selected_port_context()

        self.ai_summary_hosts.setText(
            f"<div style='font-size:11px; color:#cbd5e1;'>HOSTS</div><div style='font-size:22px; font-weight:800; color:white;'>{host_count}</div>"
        )
        self.ai_summary_ports.setText(
            f"<div style='font-size:11px; color:#cbd5e1;'>OPEN PORTS</div><div style='font-size:22px; font-weight:800; color:white;'>{port_count}</div>"
        )
        self.ai_summary_score.setText(
            f"<div style='font-size:11px; color:#cbd5e1;'>SCORE</div><div style='font-size:22px; font-weight:800; color:white;'>{score}</div>"
        )
        self.ai_context_hosts.setText(f"Hosts in memory: {host_count}")
        self.ai_context_ports.setText(f"Open ports in memory: {port_count}")
        self.ai_context_score.setText(
            f"Current security score: {score} / {getattr(self.latest_assessment, 'label', 'Unknown')}"
        )
        if port:
            self.ai_context_focus.setText(f"Current focus: {focus_ip} | selected port {port} ({service})")
        else:
            self.ai_context_focus.setText(f"Current focus: {focus_ip}")

    def _queue_ai_question(self, question: str, mode: str | None = None, auto_run: bool = True) -> None:
        if mode:
            self._set_ai_mode(mode)
        self.ai_question_input.setPlainText(question.strip())
        if auto_run:
            self._launch_ai_analysis()

    def _selected_ip_for_ai(self) -> str:
        row = self.scan_table.currentRow() if hasattr(self, "scan_table") else -1
        if row >= 0:
            item = self.scan_table.item(row, 0)
            if item and item.text().strip():
                return item.text().strip()
        current_host = self.host_selector.currentText().strip() if hasattr(self, "host_selector") else ""
        if current_host:
            return current_host
        return self.devices[0].ip_address if self.devices else ""

    def _selected_port_context(self) -> tuple[str, str, str]:
        ip_address = self._selected_ip_for_ai()
        row = self.port_table.currentRow() if hasattr(self, "port_table") else -1
        if row >= 0:
            port_item = self.port_table.item(row, 0)
            service_item = self.port_table.item(row, 1)
            port = port_item.text().strip() if port_item else ""
            service = service_item.text().strip() if service_item else "Unknown"
            return ip_address, port, service

        results = self.port_results_by_ip.get(ip_address, [])
        if results:
            first = results[0]
            return ip_address, str(first.port), first.service
        return ip_address, "", ""

    def _ask_ai_top_risks(self, *_args) -> None:
        self._queue_ai_question(
            "What are the top risks in this scan? Show the evidence from the current results.",
            "scan-aware",
        )

    def _ask_ai_fix_first(self, *_args) -> None:
        self._queue_ai_question(
            "What should I fix first based on this scan? Give me clear priorities.",
            "scan-aware",
        )

    def _ask_ai_suspicious_host(self, *_args) -> None:
        self._queue_ai_question(
            "Which device looks the most suspicious in this scan and why?",
            "scan-aware",
        )

    def _ask_ai_explain_score(self, *_args) -> None:
        self._queue_ai_question(
            "Explain this security score and what increased or decreased it.",
            "scan-aware",
        )

    def _ask_ai_close_selected_port(self, *_args) -> None:
        ip_address, port, service = self._selected_port_context()
        if port:
            question = (
                f"How can I safely close port {port} ({service}) on {ip_address} using defensive steps? "
                "Provide Windows and Linux guidance if relevant."
            )
            self._queue_ai_question(question, "scan-aware")
            return
        self._queue_ai_question(
            "How can I safely close an open port? Provide defensive steps for Windows and Linux.",
            "general",
        )

    def _ask_ai_block_selected_ip(self, *_args) -> None:
        ip_address = self._selected_ip_for_ai()
        if ip_address:
            self._queue_ai_question(
                f"How can I block IP {ip_address} in a firewall using safe defensive steps? Give practical guidance.",
                "scan-aware",
            )
            return
        self._queue_ai_question(
            "How can I block an IP in a firewall using safe defensive steps? Include Windows and Linux examples.",
            "general",
        )

    def _launch_ai_analysis(self, *_args) -> None:
        api_key = self.ai_api_key_input.text().strip()
        model = self.ai_model_input.text().strip() or "openai/gpt-4o-mini"
        mode = str(self.ai_mode_selector.currentData() or "scan-aware")
        question = self.ai_question_input.toPlainText().strip()
        alerts = self.database.fetch_alerts(limit=20)

        if not api_key:
            QMessageBox.warning(self, "AI Assistant", "Please enter your OpenRouter API key in Settings.")
            return
        if mode == "scan-aware" and not self.devices and not self._all_port_results():
            QMessageBox.warning(self, "AI Assistant", "Run a network scan first so the AI has data to analyze.")
            return

        self.pending_ai_question = question
        self.pending_ai_mode = mode
        self.ai_analyze_button.setEnabled(False)
        self.ai_status.setText("AI analysis in progress...")
        if hasattr(self, "ai_typing_label"):
            self.ai_typing_label.setText("AI is analyzing...")
        if not self.ai_chat_history:
            self.ai_output.setHtml(
                "<div style='padding:18px; color:#64748b; font-weight:700;'>AI is analyzing...</div>"
            )
        self._start_worker(
            self.ai_assistant.analyze_network,
            [
                api_key,
                model,
                mode,
                question,
                self.devices,
                self._all_port_results(),
                self.latest_assessment,
                alerts,
                self.database.fetch_company_profile(),
                list(self.ai_chat_history[-8:]),
            ],
            self._handle_ai_analysis_result,
        )

    def _handle_ai_analysis_result(self, result: str) -> None:
        if self.pending_ai_question:
            self.ai_chat_history.append(
                {
                    "role": "user",
                    "content": self.pending_ai_question,
                    "mode": self.pending_ai_mode,
                    "timestamp": datetime.now().strftime("%H:%M"),
                }
            )
        self.ai_chat_history.append(
            {
                "role": "assistant",
                "content": result,
                "mode": self.pending_ai_mode,
                "timestamp": datetime.now().strftime("%H:%M"),
            }
        )
        self._render_ai_chat()
        self.ai_analyze_button.setEnabled(True)
        self.pending_ai_question = ""
        if hasattr(self, "ai_typing_label"):
            self.ai_typing_label.setText("")
        self.ai_status.setText("AI analysis completed successfully.")
        self._log_event("AI", "Success", "AI network analysis completed.")

    def _create_user(self, *_args) -> None:
        username = self.new_username_input.text().strip()
        password = self.new_password_input.text()
        role = self.new_role_combo.currentText()

        if not username or not password:
            QMessageBox.warning(self, "User Management", "Username and password are required.")
            return

        try:
            self.database.add_user(username, password, role)
        except Exception as exc:
            QMessageBox.warning(self, "User Management", f"Unable to add the user:\n{exc}")
            return

        self.new_username_input.clear()
        self.new_password_input.clear()
        self.new_role_combo.setCurrentIndex(0)
        self.users_status.setText(f"User {username} was added successfully.")
        self._log_event("Users", "Success", f"User created: {username} ({role}).")
        self._refresh_users_table()

    def _toggle_selected_user(self, *_args) -> None:
        row = self.users_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "User Management", "Select a user first.")
            return

        username_item = self.users_table.item(row, 1)
        active_item = self.users_table.item(row, 3)
        if username_item is None or active_item is None:
            return

        username = username_item.text().strip()
        currently_active = active_item.text().strip() == "Yes"

        if username == self.username and currently_active:
            QMessageBox.warning(self, "User Management", "You cannot disable the current active session.")
            return

        self.database.set_user_active(username, not currently_active)
        state_text = "enabled" if not currently_active else "disabled"
        self.users_status.setText(f"Account {username} is now {state_text}.")
        self._log_event("Users", "Info", f"Account state updated for {username}: {state_text}.")
        self._refresh_users_table()

    def _refresh_reports_table(self) -> None:
        reports = self.database.fetch_reports(limit=20)
        self.reports_table.setSortingEnabled(False)
        self.reports_table.setRowCount(len(reports))
        for row, report in enumerate(reports):
            values = [report["report_name"], report["generated_at"], str(report["score"])]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 2:
                    item.setForeground(QColor(self._score_color(int(value))))
                self.reports_table.setItem(row, column, item)
        self.reports_table.setSortingEnabled(True)

    def _refresh_topology(self, *_args) -> None:
        self.topology_widget.set_data(self.devices, self.port_results_by_ip)
        router_count = sum(1 for device in self.devices if device.device_type == "Router")
        mobile_count = sum(1 for device in self.devices if device.device_type == "Mobile")
        server_count = sum(1 for device in self.devices if device.device_type == "Server")
        self.topology_status.setText(
            f"{len(self.devices)} device(s) | routers={router_count}, servers={server_count}, mobiles={mobile_count}"
        )

    def _all_port_results(self) -> list[PortScanResult]:
        results: list[PortScanResult] = []
        for items in self.port_results_by_ip.values():
            results.extend(items)
        return results

    def _known_ips(self) -> set[str]:
        return {device.ip_address for device in self.database.fetch_devices()}

    def _persist_new_alerts(self, alerts: list[Alert]) -> None:
        new_alerts: list[Alert] = []
        log_entries: list[EventLogEntry] = []
        for alert in alerts:
            signature = (alert.type_alert, alert.description)
            if signature not in self.alert_cache:
                self.alert_cache.add(signature)
                new_alerts.append(alert)
                log_entries.append(
                    EventLogEntry(
                        category="Alert",
                        level=alert.severity,
                        message=f"{alert.type_alert}: {alert.description}",
                        created_at=alert.created_at,
                    )
                )
        self.database.add_alerts(new_alerts)
        self.database.add_event_logs(log_entries)
        if new_alerts:
            self._refresh_alerts_table()
            self._refresh_events_table()
            self._update_dashboard_cards()

    def _recalculate_security(self) -> None:
        self.latest_assessment = self.analyzer.assess(
            self.devices,
            self._all_port_results(),
            self.latest_snapshot,
            self.security_settings,
        )
        self._update_security_panels()
        self._update_dashboard_cards()

    def _update_security_panels(self) -> None:
        self.score_progress.setValue(self.latest_assessment.score)
        self.score_label.setText(self.latest_assessment.label)
        self.observations_box.setPlainText("\n".join(f"- {item}" for item in self.latest_assessment.observations))
        self.recommendations_box.setPlainText("\n".join(f"- {item}" for item in self.latest_assessment.recommendations))
        self.score_badge.setText(f"{self._compact_score_label(self.latest_assessment.label)} | {self.latest_assessment.score}")
        self.score_badge.setStyleSheet(self._badge_style(self.latest_assessment.score))
        self._refresh_ai_context_panel()

    def _update_dashboard_cards(self) -> None:
        alerts_count = len(self.database.fetch_alerts(limit=1000))
        bandwidth = self._format_speed(self.latest_snapshot.total_bandwidth_bps if self.latest_snapshot else 0.0)
        self.hosts_card.update_content(str(len(self.devices)), "Detected devices")
        self.ports_card.update_content(str(len(self._all_port_results())), "Open services in memory")
        self.alerts_card.update_content(str(alerts_count), "Alerts requiring review")
        self.bandwidth_card.update_content(bandwidth, "Live total throughput")
        self._update_dashboard_insight()

    def _log_event(self, category: str, level: str, message: str) -> None:
        self.database.add_event_log(category, level, message)
        if hasattr(self, "events_table"):
            self._refresh_events_table()

    def timerEvent(self, event) -> None:  # pragma: no cover
        if event.timerId() != self.monitor_timer:
            return
        interface = self.interface_selector.currentText()
        selected_interface = None if interface == "All interfaces" else interface
        snapshot = self.monitor.sample(selected_interface)
        self.latest_snapshot = snapshot
        self.traffic_history.append(snapshot.total_bandwidth_bps / 1024)
        self.traffic_history = self.traffic_history[-30:]
        self.chart.set_history(self.traffic_history)
        self.upload_label.setText(f"Upload: {self._format_speed(snapshot.upload_bps)}")
        self.download_label.setText(f"Download: {self._format_speed(snapshot.download_bps)}")
        self.packets_label.setText(f"Packets: {snapshot.packets_sent} sent / {snapshot.packets_recv} recv")
        self.bytes_label.setText(
            f"Bytes: {self._format_bytes(snapshot.bytes_sent)} sent / {self._format_bytes(snapshot.bytes_recv)} recv"
        )
        average_kbps = sum(self.traffic_history) / max(len(self.traffic_history), 1)
        self.average_bandwidth_label.setText(f"Average throughput: {average_kbps:.1f} KB/s")
        if snapshot.total_bandwidth_bps > self.security_settings.bandwidth_alert_threshold_bps:
            alerts = self.analyzer.generate_alerts(
                self.devices,
                self._all_port_results(),
                self._known_ips(),
                snapshot,
                self.security_settings,
            )
            self._persist_new_alerts(alerts)
            self.monitor_alert_label.setText("High traffic spike detected")
            self.monitor_alert_label.setStyleSheet("color: #dc2626; font-weight: 700;")
        else:
            self.monitor_alert_label.setText("Traffic status normal.")
            self.monitor_alert_label.setStyleSheet("color: #16a34a; font-weight: 700;")
        self._recalculate_security()

    def resizeEvent(self, event) -> None:  # pragma: no cover
        super().resizeEvent(event)
        if hasattr(self, "toast_label") and self.toast_label.isVisible():
            self.toast_label.move(self.width() - self.toast_label.width() - 26, 24)

    def _save_settings(self, *_args) -> None:
        company_values = {
            "company_name": self.company_name_input.text().strip(),
            "department": self.department_input.text().strip(),
            "site": self.site_input.text().strip(),
            "owner": self.owner_input.text().strip(),
            "support_email": self.support_email_input.text().strip(),
            "support_phone": self.support_phone_input.text().strip(),
            "logo_path": self.logo_path_input.text().strip(),
        }

        required_fields = ["company_name", "department", "site", "owner", "support_email"]
        if any(not company_values[key] for key in required_fields):
            QMessageBox.warning(self, "Settings", "Please fill in the required company fields.")
            return

        try:
            bandwidth_mb = float(self.bandwidth_threshold_input.text().strip())
            managed_hosts = int(self.managed_hosts_limit_input.text().strip())
            large_network = int(self.large_network_threshold_input.text().strip())
        except ValueError:
            QMessageBox.warning(self, "Settings", "Please enter valid numeric values.")
            return

        if bandwidth_mb <= 0 or managed_hosts <= 0 or large_network <= 0:
            QMessageBox.warning(self, "Settings", "Threshold values must be greater than zero.")
            return
        if large_network < managed_hosts:
            QMessageBox.warning(
                self,
                "Settings",
                "The large network threshold must be greater than or equal to the managed host limit.",
            )
            return

        for key, value in company_values.items():
            self.database.set_setting(key, value)
        self.database.set_setting("bandwidth_alert_threshold_bps", str(int(bandwidth_mb * 1024 * 1024)))
        self.database.set_setting("managed_hosts_limit", str(managed_hosts))
        self.database.set_setting("large_network_threshold", str(large_network))
        self._load_settings_values()
        self._update_header_branding()
        self._recalculate_security()
        self.settings_status.setText("Company profile and thresholds saved successfully.")
        self._log_event(
            "Settings",
            "Success",
            (
                f"Company profile updated for {company_values['company_name']} | "
                f"traffic threshold={bandwidth_mb:.2f} MB/s, managed hosts={managed_hosts}, large network={large_network}."
            ),
        )
        QMessageBox.information(self, "Settings", "The company profile and settings have been saved.")

    def _export_devices_csv(self, *_args) -> None:
        path = self.exporter.export_devices(self.devices)
        self.scan_status.setText(f"CSV export generated: {path}")
        self._log_event("Export", "Success", f"Device CSV export generated: {path.name}.")

    def _export_ports_csv(self, *_args) -> None:
        path = self.exporter.export_ports(self._all_port_results())
        self.port_status.setText(f"CSV export generated: {path}")
        self._log_event("Export", "Success", f"Port CSV export generated: {path.name}.")

    def _export_history_csv(self, *_args) -> None:
        path = self.exporter.export_history(self.database.fetch_scan_runs(limit=500))
        self.history_status.setText(f"CSV export generated: {path}")
        self._log_event("Export", "Success", f"History CSV export generated: {path.name}.")

    def _export_events_csv(self, *_args) -> None:
        path = self.exporter.export_events(self.database.fetch_event_logs(limit=500))
        self.journal_status.setText(f"CSV export generated: {path}")
        self._log_event("Export", "Success", f"Event log CSV export generated: {path.name}.")

    def _export_reports_csv(self, *_args) -> None:
        reports = self.database.fetch_reports(limit=500)
        rows = [
            {
                "report_name": report["report_name"],
                "generated_at": report["generated_at"],
                "score": report["score"],
            }
            for report in reports
        ]
        path = self.exporter.export_reports(rows)
        self.report_status.setText(f"CSV export generated: {path}")
        self._log_event("Export", "Success", f"Report CSV export generated: {path.name}.")

    def _severity_color(self, severity: str) -> str:
        palette = {
            "Critical": "#dc2626" if self.current_theme == "light" else "#f87171",
            "High": "#ea580c" if self.current_theme == "light" else "#fb923c",
            "Medium": "#2563eb" if self.current_theme == "light" else "#60a5fa",
            "Low": "#16a34a" if self.current_theme == "light" else "#4ade80",
            "Info": "#0891b2" if self.current_theme == "light" else "#67e8f9",
            "Success": "#16a34a" if self.current_theme == "light" else "#4ade80",
            "Error": "#dc2626" if self.current_theme == "light" else "#f87171",
        }
        return palette.get(severity, "#64748b")

    def _event_level_color(self, level: str) -> str:
        return self._severity_color(level)

    def _risk_color(self, risk_level: str) -> str:
        return self._severity_color(risk_level)

    def _score_color(self, score: int) -> str:
        if score >= 80:
            return "#16a34a" if self.current_theme == "light" else "#4ade80"
        if score >= 50:
            return "#d97706" if self.current_theme == "light" else "#fbbf24"
        return "#dc2626" if self.current_theme == "light" else "#f87171"

    def _badge_style(self, score: int) -> str:
        if score >= 80:
            return (
                "background: #dcfce7; color: #166534; padding: 7px 12px; border-radius: 999px; font-weight: 700;"
                if self.current_theme == "light"
                else "background: #14532d; color: #dcfce7; padding: 7px 12px; border-radius: 999px; font-weight: 700;"
            )
        if score >= 50:
            return (
                "background: #fef3c7; color: #92400e; padding: 7px 12px; border-radius: 999px; font-weight: 700;"
                if self.current_theme == "light"
                else "background: #78350f; color: #fef3c7; padding: 7px 12px; border-radius: 999px; font-weight: 700;"
            )
        return (
            "background: #fee2e2; color: #991b1b; padding: 7px 12px; border-radius: 999px; font-weight: 700;"
            if self.current_theme == "light"
            else "background: #7f1d1d; color: #fee2e2; padding: 7px 12px; border-radius: 999px; font-weight: 700;"
        )

    def _format_speed(self, value: float) -> str:
        if value >= 1024 * 1024:
            return f"{value / (1024 * 1024):.2f} MB/s"
        if value >= 1024:
            return f"{value / 1024:.2f} KB/s"
        return f"{value:.0f} B/s"

    def _format_bytes(self, value: float) -> str:
        units = ["B", "KB", "MB", "GB", "TB"]
        size = float(value)
        for unit in units:
            if size < 1024 or unit == units[-1]:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"


def configure_app_style(app: QApplication) -> None:
    app.setStyleSheet(LIGHT_STYLE)
