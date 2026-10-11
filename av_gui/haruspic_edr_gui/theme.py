"""Small, deliberately restrained desktop design system."""
from PySide6.QtCore import Qt, QByteArray, QSize
from PySide6.QtGui import QIcon, QPixmap, QPainter, QFont
from PySide6.QtSvg import QSvgRenderer

PATHS = {
    "overview": '<rect x="3" y="3" width="7" height="7" rx="1.4"/><rect x="14" y="3" width="7" height="7" rx="1.4"/><rect x="3" y="14" width="7" height="7" rx="1.4"/><rect x="14" y="14" width="7" height="7" rx="1.4"/>',
    "agents": '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/>',
    "alerts": '<path d="M12 3 2 20h20L12 3zM12 9v5M12 17v.1"/>',
    "events": '<path d="M4 5h16M4 12h10M4 19h16"/><circle cx="19" cy="12" r="1"/>',
    "commands": '<path d="m5 6 6 6-6 6M13 18h6"/>',
    "scan": '<path d="M8 3H3v5M16 3h5v5M3 16v5h5M21 16v5h-5M7 12h10"/>',
    "quarantine": '<rect x="4" y="9" width="16" height="12" rx="2"/><path d="M8 9V6a4 4 0 0 1 8 0v3M12 14v3"/>',
    "updates": '<path d="M20 8a8 8 0 1 0 0 8M20 3v5h-5"/>',
    "policy": '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="10" cy="18" r="2"/>',
    "settings": '<circle cx="12" cy="12" r="4"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2"/>',
    "arrow": '<path d="M5 12h14m-5-5 5 5-5 5"/>',
    "search": '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
    "export": '<path d="M12 3v12m-4-4 4 4 4-4M4 16v5h16v-5"/>',
    "folder": '<path d="M3 6h7l2 3h9v11H3z"/>',
    "shield": '<path d="m12 2 9 4v6c0 5-9 10-9 10S3 17 3 12V6l9-4zM8 12l3 3 5-6"/>',
}


def icon(name, color="#aab9b4", size=20):
    content = PATHS.get(name, PATHS["overview"])
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><g fill="none" stroke="{color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">{content}</g></svg>'
    pm = QPixmap(size * 2, size * 2)
    pm.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pm)
    QSvgRenderer(QByteArray(svg.encode())).render(painter)
    painter.end()
    pm.setDevicePixelRatio(2)
    return QIcon(pm)


def apply(app):
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI" if __import__('os').name == 'nt' else "Inter", 10))
    app.setStyleSheet(STYLE)


STYLE = """
* { font-family: 'Inter', 'Segoe UI', 'Noto Sans', sans-serif; font-size: 13px; color: #233630; }
QMainWindow, QDialog, QWidget#canvas { background: #f5f6f8; }
QLabel { background: transparent; }
QWidget#detailPane { background: #ffffff; }
QLabel#muted { color: #79867f; font-size: 12px; }
QLabel#eyebrow { color: #6c7b75; font-size: 10px; font-weight: 600; letter-spacing: 1.5px; }
QLabel#title { font-size: 27px; font-weight: 600; color: #172d24; }
QLabel#sectionTitle { font-size: 16px; font-weight: 600; }
QLabel#metric { font-size: 34px; font-weight: 500; color: #172d24; }
QLabel#bannerTitle { font-size: 20px; font-weight: 600; color: #183e30; }
QFrame#sidebar { background: #14251f; border: none; }
QLabel#brand { color: #f0f5f2; font-size: 25px; font-weight: 600; letter-spacing: -1px; }
QLabel#sideCaption { color: #7f9b8d; font-size: 10px; letter-spacing: 1.5px; }
QLabel#sideText { color: #a3b9ad; font-size: 11px; }
QLabel#mark { background: #c9e8a1; color: #182d23; font-size: 23px; font-weight: 700; border-radius: 9px; }
QPushButton#nav { text-align: left; padding: 11px 15px; color: #aabbb1; border: 0; background: transparent; border-radius: 7px; font-size: 13px; }
QPushButton#nav:hover { background: #1d3329; color: #f3f6f4; }
QPushButton#nav:checked { background: #2a4336; color: #e6f4db; font-weight: 600; }
QFrame#topbar { background: #ffffff; border-bottom: 1px solid #e3e8e4; }
QFrame#card { background: #ffffff; border: 1px solid #e1e7e2; border-radius: 10px; }
QFrame#banner { background: #eaf1e5; border: 1px solid #dce7d4; border-radius: 10px; }
QFrame#line { background: #e7ebe7; border: 0; max-height: 1px; }
QPushButton { background: #ffffff; border: 1px solid #dbe2dd; border-radius: 6px; padding: 8px 13px; font-weight: 500; }
QPushButton:hover { background: #edf2ec; border-color: #a9bcb0; }
QPushButton:pressed { background: #e0e9df; }
QPushButton:disabled { color: #a6afa9; background: #f1f4f0; border-color: #e4e8e3; }
QPushButton#primary { background: #244e3c; color: #ffffff; border-color: #244e3c; }
QPushButton#primary:hover { background: #32634c; }
QPushButton#primary:disabled { background: #8ea095; color: #edf0ed; border-color: #8ea095; }
QPushButton#danger { color: #a44335; border-color: #e4c8bf; }
QPushButton#subtle { border: 0; background: transparent; color: #567064; }
QLineEdit, QComboBox, QSpinBox { background: white; border: 1px solid #dce3dd; border-radius: 6px; padding: 8px 11px; min-height: 19px; selection-background-color: #d8e9d6; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus { border-color: #7c9a87; }
QLineEdit:disabled { color: #8a968d; background: #f2f4f1; }
QComboBox::drop-down { border: none; width: 23px; }
QComboBox QAbstractItemView { background: white; selection-background-color: #e5efdf; color: #233630; }
QPlainTextEdit { background: #ffffff; border: 1px solid #dce3dd; border-radius: 7px; padding: 12px; font-family: 'Cascadia Code', 'Noto Sans Mono', monospace; font-size: 12px; selection-background-color: #d8e9d6; }
QTableWidget { background: white; border: 0; outline: 0; gridline-color: #f0f2ef; selection-background-color: #edf3e9; selection-color: #1e422f; }
QTableWidget::item { padding: 10px 12px; border-bottom: 1px solid #edf0ec; }
QTableWidget::item:selected { background: #edf3e9; color: #1e422f; }
QHeaderView::section { background: #fafbf9; color: #7b8780; font-size: 11px; font-weight: 500; padding: 11px 12px; border: 0; border-bottom: 1px solid #e7ece6; }
QHeaderView { background: #fafbf9; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: transparent; width: 7px; margin: 0; }
QScrollBar::handle:vertical { background: #cbd5cd; border-radius: 3px; min-height: 35px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { height: 7px; background: transparent; }
QScrollBar::handle:horizontal { background: #cbd5cd; border-radius: 3px; min-width: 30px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QCheckBox { spacing: 10px; padding: 5px 0; }
QCheckBox::indicator { width: 17px; height: 17px; border: 1px solid #b8c7bc; border-radius: 4px; background: white; }
QCheckBox::indicator:checked { background: #497b53; border-color: #497b53; image: none; }
QTabWidget::pane { border: 1px solid #e1e7e2; background: white; border-radius: 7px; }
QTabBar::tab { padding: 10px 18px; color: #708075; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #244e3c; border-bottom-color: #244e3c; }
QToolTip { color: #ffffff; background: #244332; border: 0; padding: 6px; }
QProgressBar { background: #e6ede4; border: none; border-radius: 2px; max-height: 3px; }
QProgressBar::chunk { background: #58886a; }
QSplitter::handle { background: transparent; width: 16px; }
QMenu { background: white; border: 1px solid #dce3dd; padding: 4px; }
QMenu::item { padding: 8px 22px; }
QMenu::item:selected { background: #edf3e9; }
"""
