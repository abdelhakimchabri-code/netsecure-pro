from __future__ import annotations

import sys

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QCursor
from PyQt6.QtWidgets import QApplication

from .database import DatabaseManager
from .exports import CSVExporter
from .monitor import NetworkMonitor
from .network import NetworkScanner
from .ports import PortScanner
from .reporting import ReportGenerator
from .security import SecurityAnalyzer
from .ui import LoginDialog, MainWindow, configure_app_style


def main() -> int:
    app = QApplication(sys.argv)
    configure_app_style(app)

    database = DatabaseManager()
    login_dialog = LoginDialog(database)
    if login_dialog.exec() != LoginDialog.DialogCode.Accepted:
        return 0

    window = MainWindow(
        username=login_dialog.username,
        database=database,
        network_scanner=NetworkScanner(),
        port_scanner=PortScanner(),
        monitor=NetworkMonitor(),
        analyzer=SecurityAnalyzer(),
        reporter=ReportGenerator(),
        exporter=CSVExporter(),
    )
    screen = app.screenAt(QCursor.pos()) or app.primaryScreen()
    if screen is not None:
        available = screen.availableGeometry()
        safe_width = min(1460, max(1180, available.width() - 80))
        safe_height = min(900, max(760, available.height() - 80))
        window.resize(safe_width, safe_height)
        frame = window.frameGeometry()
        frame.moveCenter(available.center())
        window.move(frame.topLeft())
        window.setWindowState(Qt.WindowState.WindowNoState)
    window.show()
    return app.exec()
