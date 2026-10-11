from __future__ import annotations
from datetime import datetime, timezone, timedelta
import json
from PySide6.QtCore import Qt, Signal, QRectF, QSize
from PySide6.QtGui import QColor, QPainter, QPen, QFont
from PySide6.QtWidgets import (QWidget, QFrame, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QStyledItemDelegate, QLineEdit, QPlainTextEdit, QTabWidget, QScrollArea, QFormLayout)
from .theme import icon


def label(text="", name="", wrap=False):
    widget = QLabel(str(text))
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setObjectName(name)
    widget.setWordWrap(wrap)
    return widget


def button(text, callback=None, primary=False, symbol=None):
    widget = QPushButton(text)
    if primary:
        widget.setObjectName("primary")
    if symbol:
        widget.setIcon(icon(symbol, "#ffffff" if primary else "#567064"))
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    if callback:
        widget.clicked.connect(callback)
    return widget


def card():
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(22, 20, 22, 20)
    layout.setSpacing(14)
    return frame, layout


def row(*widgets, stretch=False):
    layout = QHBoxLayout()
    layout.setSpacing(10)
    for widget in widgets:
        layout.addWidget(widget)
    if stretch:
        layout.addStretch()
    return layout


def pretty_time(value):
    try:
        date = datetime.fromtimestamp(value, timezone.utc) if isinstance(value, (int, float)) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        return date.astimezone().strftime("%d.%m.%Y  %H:%M")
    except (ValueError, TypeError, OverflowError, OSError):
        return "—"


STATUS = {"online":"На связи", "offline":"Не на связи", "stale":"Давно не на связи", "open":"Открыт", "ack":"В работе", "closed":"Закрыт",
          "critical":"Критический", "high":"Высокий", "medium":"Средний", "low":"Низкий", "info":"Информация",
          "queued":"В очереди", "sent":"Доставлена", "acked":"Выполнена", "failed":"Ошибка"}
PALETTE = {"online":("#e7f1e4", "#397346"), "acked":("#e7f1e4", "#397346"), "closed":("#eef0ed", "#778177"),
           "high":("#f9ede1", "#a46833"), "critical":("#f9e6e3", "#ae554d"), "failed":("#f9e6e3", "#ae554d"),
           "open":("#f9ede1", "#a46833"), "ack":("#e6eef7", "#547593"), "medium":("#f4f0dd", "#96843c")}


class PillDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        raw = index.data(Qt.ItemDataRole.UserRole + 1)
        if not raw:
            return super().paint(painter, option, index)
        painter.save()
        if option.state & __import__('PySide6.QtWidgets', fromlist=['QStyle']).QStyle.StateFlag.State_Selected:
            painter.fillRect(option.rect, QColor("#edf3e9"))
        painter.setPen(QColor("#edf0ec"))
        painter.drawLine(option.rect.bottomLeft(), option.rect.bottomRight())
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        text = STATUS.get(raw, raw)
        bg, fg = PALETTE.get(raw, ("#eef1ed", "#778277"))
        width = min(option.fontMetrics.horizontalAdvance(text) + 22, option.rect.width() - 16)
        rect = QRectF(option.rect.x() + 10, option.rect.center().y() - 12, width, 25)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(bg))
        painter.drawRoundedRect(rect, 5, 5)
        painter.setPen(QColor(fg))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, option.fontMetrics.elidedText(text, Qt.TextElideMode.ElideRight, int(width)-12))
        painter.restore()


class DataTable(QWidget):
    selected = Signal(object)

    def __init__(self, columns, empty="Нет записей", parent=None):
        super().__init__(parent)
        self.columns = columns
        self.records = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.table = QTableWidget(0, len(columns))
        self.table.setHorizontalHeaderLabels([c[0] for c in columns])
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(53)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.table.setItemDelegate(PillDelegate(self.table))
        self.table.horizontalHeader().setMinimumSectionSize(95)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.table.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        for i, col in enumerate(columns):
            self.table.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch if len(col) < 3 else QHeaderView.ResizeMode.Interactive)
            if len(col) >= 3:
                self.table.setColumnWidth(i, col[2])
        self.table.itemSelectionChanged.connect(self._selected)
        layout.addWidget(self.table)
        self.empty = label(empty, "muted", True)
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty.setMinimumHeight(100)
        layout.addWidget(self.empty)
        self.footer = label("", "muted")
        self.footer.setContentsMargins(14, 10, 10, 10)
        layout.addWidget(self.footer)

    def _selected(self):
        self.selected.emit(self.current())

    def current(self):
        if not self.table.selectionModel().hasSelection():
            return None
        item = self.table.item(self.table.currentRow(), 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def set_records(self, records):
        previous = self.current()
        key = (previous or {}).get("id", (previous or {}).get("event_id"))
        self.records = records
        table = self.table
        table.blockSignals(True)
        table.setSortingEnabled(False)
        table.setRowCount(len(records))
        selected_row = -1
        for r, record in enumerate(records):
            for c, column in enumerate(self.columns):
                value = column[1](record)
                item = QTableWidgetItem(STATUS.get(str(value), str(value)) if value is not None else "—")
                item.setToolTip(item.text())
                if c == 0:
                    item.setData(Qt.ItemDataRole.UserRole, record)
                if str(value) in STATUS:
                    item.setData(Qt.ItemDataRole.UserRole + 1, str(value))
                table.setItem(r, c, item)
            if key is not None and record.get("id", record.get("event_id")) == key:
                selected_row = r
        table.setSortingEnabled(True)
        table.blockSignals(False)
        # Sorting may have moved rows. Select by the stable record identity.
        if selected_row >= 0:
            for r in range(table.rowCount()):
                record = table.item(r, 0).data(Qt.ItemDataRole.UserRole)
                if record.get("id", record.get("event_id")) == key:
                    table.selectRow(r)
                    self._selected()
                    break
        else:
            table.clearSelection()
            table.setCurrentCell(-1, -1)
            self.selected.emit(None)
        self.empty.setVisible(not records)
        table.setVisible(bool(records))
        self.footer.setText(f"Записей: {len(records)}")

    def filter(self, value):
        value = value.casefold().strip()
        count = 0
        for r in range(self.table.rowCount()):
            visible = any(value in self.table.item(r, c).text().casefold() for c in range(self.table.columnCount()))
            self.table.setRowHidden(r, not visible)
            count += visible
        if self.table.currentRow() >= 0 and self.table.isRowHidden(self.table.currentRow()):
            self.table.clearSelection()
            self.table.setCurrentCell(-1, -1)
        self.footer.setText(f"Показано {count} из {len(self.records)}")


class Details(QFrame):
    def __init__(self, title="Детали записи"):
        super().__init__()
        self.setObjectName("card")
        self.setMinimumWidth(275)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.addWidget(label(title, "sectionTitle"))
        self.hint = label("Выберите запись в таблице, чтобы увидеть подробности.", "muted", True)
        layout.addWidget(self.hint)
        self.content = QPlainTextEdit()
        self.content.setReadOnly(True)
        self.content.setPlaceholderText("Данные появятся здесь")
        tabs = QTabWidget()
        self.summary = QWidget()
        self.summary.setObjectName("detailPane")
        self.summary_form = QFormLayout(self.summary)
        self.summary_form.setContentsMargins(10,16,10,16)
        self.summary_form.setSpacing(16)
        self.summary_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.summary)
        tabs.addTab(scroll,"Сводка")
        tabs.addTab(self.content,"JSON")
        layout.addWidget(tabs, 1)
        self.actions = QVBoxLayout()
        layout.addLayout(self.actions)

    def show_record(self, record):
        self.hint.setText("Полные данные выбранной записи" if record else "Выберите запись в таблице, чтобы увидеть подробности.")
        self.content.setPlainText(json.dumps(record, ensure_ascii=False, indent=2) if record else "")
        while self.summary_form.rowCount():
            self.summary_form.removeRow(0)
        names = {"hostname":"Устройство", "os_name":"Операционная система", "arch":"Архитектура", "agent_version":"Версия агента",
                 "status":"Статус", "last_seen_at":"Последняя активность", "enrolled_at":"Дата подключения", "title":"Обнаружение",
                 "severity":"Уровень", "event_type":"Тип события", "ts":"Время события", "created_at":"Создано",
                 "command_type":"Команда", "updated_at":"Обновлено", "original_path":"Исходный путь", "malware_name":"Обнаружение",
                 "timestamp":"Дата изоляции", "result":"Результат", "payload":"Данные"}
        for key, title in names.items():
            if not record or key not in record:
                continue
            value = record[key]
            if key in ("last_seen_at","enrolled_at","ts","created_at","updated_at","timestamp"):
                value = pretty_time(value)
            elif isinstance(value,dict):
                value = json.dumps(value,ensure_ascii=False,indent=2)
            elif value is None:
                value = "Ожидается"
            else:
                value = STATUS.get(str(value), str(value))
            field = label(str(value)[:1500],"",True)
            field.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.summary_form.addRow(label(title,"muted"),field)


class ActivityChart(QWidget):
    """Actual loaded alert counts per local day; no fabricated trend percentages."""
    def __init__(self):
        super().__init__()
        self.setMinimumHeight(145)
        self.values = [0] * 7
        self.days = []
        self.set_alerts([])

    def set_alerts(self, alerts):
        today = datetime.now().date()
        days = [today - timedelta(days=i) for i in reversed(range(7))]
        counts = {day:0 for day in days}
        for alert in alerts:
            try:
                dt = datetime.fromisoformat(str(alert["created_at"]).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                day = dt.astimezone().date()
                if day in counts:
                    counts[day] += 1
            except (KeyError, ValueError, TypeError):
                pass
        self.values, self.days = list(counts.values()), days
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        step = w / 7
        ceiling = max(max(self.values), 1)
        p.setPen(QPen(QColor("#e8ede6"), 1))
        for y in (25, (h-30)/2, h-30):
            p.drawLine(0, int(y), w, int(y))
        for i, value in enumerate(self.values):
            height = (h-57)*value/ceiling if value else 2
            rect = QRectF(i*step+step*.23, h-30-height, step*.54, height)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor("#426b4f" if i == 6 else "#bccfad"))
            p.drawRoundedRect(rect, 3, 3)
            p.setPen(QColor("#7a877d"))
            p.drawText(QRectF(i*step, h-21, step, 20), Qt.AlignmentFlag.AlignCenter, self.days[i].strftime("%d.%m"))
            if value:
                p.drawText(QRectF(i*step, h-52-height, step, 20), Qt.AlignmentFlag.AlignCenter, str(value))
        p.end()
