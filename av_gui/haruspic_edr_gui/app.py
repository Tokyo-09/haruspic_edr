from __future__ import annotations
import argparse
from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from PySide6.QtCore import Qt, QObject, Signal, QRunnable, QThreadPool, QTimer, QStandardPaths, QSize
from PySide6.QtGui import QAction, QKeySequence, QFont
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QFrame, QVBoxLayout, QHBoxLayout, QGridLayout,
    QStackedWidget, QScrollArea, QLineEdit, QComboBox, QCheckBox, QSpinBox, QPlainTextEdit,
    QFileDialog, QMessageBox, QSplitter, QFormLayout, QProgressBar, QTabWidget)
from . import __version__
from .backend import ApiClient, BackendError, LocalEngine, Preferences, read_json, validate_url
from .theme import apply, icon
from .widgets import label, button, card, row, pretty_time, DataTable, Details, ActivityChart


class TaskSignals(QObject):
    done = Signal(object, object)


class Task(QRunnable):
    def __init__(self, work):
        super().__init__()
        self.signals = TaskSignals()
        self.work = work

    def run(self):
        try:
            value, error = self.work(), None
        except Exception as exc:
            value, error = None, str(exc) if isinstance(exc, (BackendError, OSError, ValueError)) else f"Ошибка обработки данных: {type(exc).__name__}"
        self.signals.done.emit(value, error)


PAGES = [
    ("overview", "Обзор", "Центр управления", "Состояние инфраструктуры и события, требующие внимания."),
    ("agents", "Устройства", "Устройства", "Подключённые агенты, доступность и удалённые действия."),
    ("alerts", "Инциденты", "Инциденты", "Разберите обнаружение, назначьте статус и изучите исходное событие."),
    ("events", "События", "Журнал событий", "Телеметрия агентов. До 1 000 последних событий в текущей выборке."),
    ("commands", "Команды", "Удалённые команды", "Очередь задач и результаты выполнения на выбранном устройстве."),
    ("scan", "Сканирование", "Локальное сканирование", "Проверка файлов на этом компьютере через установленный движок."),
    ("quarantine", "Карантин", "Локальный карантин", "Изолированные файлы этого компьютера. До 1 000 последних записей."),
    ("updates", "Базы и обновления", "Базы и обновления", "Подписанные базы обнаружения локального агента."),
    ("policy", "Политики", "Политика телеметрии", "Единая серверная политика. Агенты получают изменения при следующем опросе."),
    ("settings", "Настройки", "Настройки консоли", "Подключение к серверу, локальный движок и журнал операций."),
]


class MainWindow(QMainWindow):
    def __init__(self, demo=False, preferences_path=None):
        super().__init__()
        self.setWindowTitle("Haruspic EDR — Desktop console")
        self.setWindowIcon(icon("shield", "#244e3c", 40))
        self.resize(1440, 980)
        self.setMinimumSize(1100, 740)
        self.demo = demo
        self.api = None
        self.generation = 0
        self.jobs = {}
        self.data = {"stats":{}, "agents":[], "alerts":[], "events":[]}
        self.last_sync = None
        self.policy_loaded = False
        self.current_page = "overview"
        self.preferences_path = preferences_path or Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppConfigLocation)) / "preferences.json"
        self.startup_error = None
        try:
            self.prefs = Preferences.load(self.preferences_path)
        except Exception as exc:
            self.prefs = Preferences.defaults()
            self.startup_error = "Не удалось прочитать настройки. Используются значения по умолчанию."
        self.engine = LocalEngine(replace(self.prefs))
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(3)
        self.nav = {}
        self.page_widgets = {}
        self._build()
        self.timer = QTimer(self)
        self.timer.setInterval(30000)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()
        if demo:
            from .demo import snapshot
            self.apply_snapshot(snapshot())
            self.connection.setText("Демо · данные примера")
            self.notice("Демонстрационный режим. Данные вымышлены; операции с сервером и файлами отключены.")
        elif self.startup_error:
            self.notice(self.startup_error, True)
        self.navigate("overview")

    def _build(self):
        container = QWidget()
        self.setCentralWidget(container)
        root = QHBoxLayout(container)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(224)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(16, 26, 16, 20)
        side.setSpacing(5)
        brandrow = QHBoxLayout()
        mark = label("h", "mark")
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark.setFixedSize(35, 37)
        brandrow.addWidget(mark)
        brandrow.addWidget(label("haruspic", "brand"))
        brandrow.addStretch()
        side.addLayout(brandrow)
        caption = label("ENDPOINT SECURITY", "sideCaption")
        caption.setContentsMargins(46, 0, 0, 19)
        side.addWidget(caption)
        for index,(key, name, _, _) in enumerate(PAGES):
            if index in (0,5,8):
                text = {0:"ИНФРАСТРУКТУРА",5:"ЭТОТ КОМПЬЮТЕР",8:"УПРАВЛЕНИЕ"}[index]
                section = label(text, "sideCaption")
                section.setContentsMargins(14, 20 if index else 4, 0, 10)
                side.addWidget(section)
            nav = button("  " + name, lambda checked=False, k=key:self.navigate(k))
            nav.setObjectName("nav")
            nav.setCheckable(True)
            nav.setIcon(icon(key))
            nav.setIconSize(QSize(19, 19))
            self.nav[key] = nav
            side.addWidget(nav)
        side.addStretch()
        side.addWidget(label("HARUSPIC EDR", "sideCaption"))
        side.addWidget(label(f"Desktop console  /  {__version__}", "sideText"))
        root.addWidget(sidebar)
        right = QVBoxLayout()
        right.setContentsMargins(0,0,0,0)
        right.setSpacing(0)
        root.addLayout(right, 1)
        top = QFrame()
        top.setObjectName("topbar")
        top.setFixedHeight(68)
        top_layout = QHBoxLayout(top)
        top_layout.setContentsMargins(32,0,32,0)
        self.breadcrumb = label("Рабочее пространство  /  Обзор", "muted")
        top_layout.addWidget(self.breadcrumb)
        top_layout.addStretch()
        self.connection = label("Сервер не подключён", "muted")
        top_layout.addWidget(self.connection)
        top_layout.addSpacing(14)
        self.connect_shortcut = button("Подключение", lambda:self.navigate("settings"), symbol="settings")
        top_layout.addWidget(self.connect_shortcut)
        right.addWidget(top)
        self.message = label("", "muted", True)
        self.message.setContentsMargins(32,10,32,10)
        self.message.hide()
        right.addWidget(self.message)
        self.progress = QProgressBar()
        self.progress.setRange(0,0)
        self.progress.setTextVisible(False)
        self.progress.hide()
        right.addWidget(self.progress)
        self.stack = QStackedWidget()
        right.addWidget(self.stack, 1)
        for key, _, title, subtitle in PAGES:
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            body = QWidget()
            body.setObjectName("canvas")
            layout = QVBoxLayout(body)
            layout.setContentsMargins(32,28,32,24)
            layout.setSpacing(18)
            heading = QHBoxLayout()
            words = QVBoxLayout()
            words.setSpacing(7)
            words.addWidget(label(title, "title"))
            words.addWidget(label(subtitle, "muted", True))
            heading.addLayout(words, 1)
            refresh = button("Обновить", self.refresh, symbol="updates")
            heading.addWidget(refresh)
            layout.addLayout(heading)
            getattr(self, "build_" + key)(layout)
            scroll.setWidget(body)
            self.page_widgets[key] = scroll
            self.stack.addWidget(scroll)
        self.footer = label("Готово. Подключите сервер или настройте локальный движок.", "muted")
        self.footer.setContentsMargins(32,9,32,9)
        right.addWidget(self.footer)
        action = QAction(self)
        action.setShortcut(QKeySequence("Ctrl+R"))
        action.triggered.connect(self.refresh)
        self.addAction(action)
        action = QAction(self)
        action.setShortcut(QKeySequence("Ctrl+,"))
        action.triggered.connect(lambda:self.navigate("settings"))
        self.addAction(action)

    def build_overview(self, layout):
        frame, banner = card()
        frame.setObjectName("banner")
        banner.setContentsMargins(20,14,20,14)
        banner.setSpacing(8)
        banner.addWidget(label("ОПЕРАТИВНАЯ СВОДКА", "eyebrow"))
        self.summary = label("Подключите инфраструктуру", "bannerTitle")
        self.summary_hint = label("Добавьте сервер, чтобы увидеть устройства, обнаружения и задачи.", "muted", True)
        line = QHBoxLayout()
        words = QVBoxLayout()
        words.addWidget(self.summary)
        words.addWidget(self.summary_hint)
        line.addLayout(words,1)
        line.addWidget(button("К инцидентам", lambda:self.navigate("alerts"), symbol="arrow"))
        banner.addLayout(line)
        layout.addWidget(frame)
        metrics = QHBoxLayout()
        metrics.setSpacing(16)
        self.metrics = {}
        for key, title, hint in [("agents","УСТРОЙСТВА","Зарегистрировано на сервере"),("online","НА СВЯЗИ","Последняя активность агентов"),
                                 ("open_alerts","ОТКРЫТЫЕ ИНЦИДЕНТЫ","Ожидают разбора"),("events","СОБЫТИЯ","Всего сохранено на сервере")]:
            frame, inside = card()
            inside.setContentsMargins(20,14,20,14)
            inside.setSpacing(6)
            inside.addWidget(label(title,"eyebrow"))
            self.metrics[key] = label("—","metric")
            inside.addWidget(self.metrics[key])
            inside.addWidget(label(hint,"muted",True))
            metrics.addWidget(frame,1)
        layout.addLayout(metrics)
        frame, inside = card()
        heading = row(label("Требуют внимания","sectionTitle"))
        heading.addStretch()
        heading.addWidget(button("Все инциденты  →", lambda:self.navigate("alerts")))
        inside.addLayout(heading)
        self.overview_alerts = DataTable(self.alert_columns(), "Открытых инцидентов в загруженной выборке нет. Это не является подтверждением отсутствия угроз.")
        self.overview_alerts.setFixedHeight(227)
        self.overview_alerts.table.verticalHeader().setDefaultSectionSize(43)
        self.overview_alerts.table.doubleClicked.connect(lambda:self.navigate("alerts"))
        inside.addWidget(self.overview_alerts)
        layout.addWidget(frame)
        lower = QHBoxLayout()
        lower.setSpacing(16)
        chartcard, chartlayout = card()
        chartlayout.addLayout(row(label("Обнаружения за 7 дней","sectionTitle"),label("ПО ВЫБОРКЕ","eyebrow")))
        self.chart = ActivityChart()
        chartlayout.addWidget(self.chart)
        chartlayout.addWidget(label("До 500 последних инцидентов; график не заменяет полную статистику.","muted",True))
        lower.addWidget(chartcard, 3)
        healthcard, health = card()
        health.addWidget(label("Состояние подключения","sectionTitle"))
        self.health_text = label("Нет подключения к серверу", "", True)
        health.addWidget(self.health_text)
        self.sync_text = label("Последняя синхронизация: —", "muted", True)
        health.addWidget(self.sync_text)
        health.addWidget(label("Связь с агентом не подтверждает работу сканирования. Проверяйте события agent_status и версию базы на устройстве.","muted",True))
        health.addStretch()
        health.addWidget(button("Проверить локальную базу", lambda:self.navigate("updates"), symbol="shield"))
        lower.addWidget(healthcard, 2)
        layout.addLayout(lower)
        layout.addStretch()

    def hostname(self, record):
        agent_id = record.get("agent_id", "")
        return next((a.get("hostname", a["id"]) for a in self.data["agents"] if a.get("id")==agent_id), agent_id or "—")

    def alert_columns(self):
        return [("Обнаружение",lambda r:r.get("title","—")),("Устройство",self.hostname,170),
                ("Уровень",lambda r:r.get("severity"),145),("Время",lambda r:pretty_time(r.get("created_at")),160)]

    def table_page(self, layout, columns, name, empty, details_title):
        toolbar = QHBoxLayout()
        search = QLineEdit()
        search.setPlaceholderText("Поиск в загруженной выборке…")
        search.setClearButtonEnabled(True)
        search.addAction(icon("search", "#87968b"), QLineEdit.ActionPosition.LeadingPosition)
        toolbar.addWidget(search,1)
        toolbar.addWidget(button("Экспорт JSON", lambda:self.export_records(getattr(self,name).records), symbol="export"))
        layout.addLayout(toolbar)
        splitter = QSplitter()
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(16)
        tablecard, inside = card()
        inside.setContentsMargins(0,0,0,0)
        table = DataTable(columns,empty)
        table.setMinimumHeight(390)
        table.setMinimumWidth(440)
        inside.addWidget(table)
        details = Details(details_title)
        table.selected.connect(details.show_record)
        splitter.addWidget(tablecard)
        splitter.addWidget(details)
        splitter.setSizes([760,315])
        layout.addWidget(splitter,1)
        search.textChanged.connect(table.filter)
        table.search = search
        setattr(self,name,table)
        return details

    def build_agents(self, layout):
        details = self.table_page(layout,[("Устройство",lambda r:r.get("hostname","—")),("ОС",lambda r:r.get("os_name"),110),
            ("Связь",lambda r:r.get("status"),130),("Активность",lambda r:pretty_time(r.get("last_seen_at")),160)],
            "agents_table","Подключите сервер. Зарегистрированные агенты появятся здесь.","Карточка устройства")
        for title,kind in (("Проверить связь","ping"),("Собрать инвентаризацию","collect_inventory"),("Сканировать путь…","scan_path")):
            control = button(title,lambda checked=False,k=kind:self.from_agent(k), primary=kind=="scan_path")
            control.setEnabled(False)
            self.agents_table.selected.connect(lambda record,b=control:b.setEnabled(bool(record) and not self.demo and self.api is not None))
            details.actions.addWidget(control)
        details.actions.addWidget(button("История команд →", self.agent_history))

    def build_alerts(self, layout):
        filterrow = QHBoxLayout()
        self.alert_filter = QComboBox()
        for title,code in [("Все статусы", ""),("Открытые","open"),("В работе","ack"),("Закрытые","closed")]:
            self.alert_filter.addItem(title,code)
        self.alert_filter.currentIndexChanged.connect(self.render_alerts)
        filterrow.addWidget(self.alert_filter)
        filterrow.addWidget(label("До 500 последних инцидентов. Выберите запись для изменения статуса.","muted",True),1)
        layout.addLayout(filterrow)
        details = self.table_page(layout,[("Обнаружение",lambda r:r.get("title","—")),("Уровень",lambda r:r.get("severity"),140),
            ("Статус",lambda r:r.get("status"),125)],"alerts_table","В этой выборке нет инцидентов.","Разбор инцидента")
        for title,status in (("Взять в работу","ack"),("Закрыть инцидент","closed"),("Открыть повторно","open")):
            b = button(title,lambda checked=False,s=status:self.change_alert(s),primary=status=="ack")
            b.setEnabled(False)
            self.alerts_table.selected.connect(lambda record,b=b:b.setEnabled(bool(record) and not self.demo and self.api is not None))
            details.actions.addWidget(b)
        details.actions.addWidget(button("Показать исходное событие",self.show_alert_event))

    def build_events(self, layout):
        self.table_page(layout,[("Тип события",lambda r:r.get("event_type","—")),("Устройство",self.hostname,150),
            ("Уровень",lambda r:r.get("severity"),140),("Время",lambda r:pretty_time(r.get("ts")),155)],
            "events_table","Событий пока нет. Подключите сервер или измените фильтр.","Содержимое события")

    def build_commands(self, layout):
        frame, inside = card()
        self.command_agent = QComboBox()
        self.command_agent.setMinimumWidth(240)
        self.command_agent.currentIndexChanged.connect(self.load_commands)
        self.command_kind = QComboBox()
        for title,code in [("Проверка связи","ping"),("Инвентаризация","collect_inventory"),("Сканирование пути","scan_path")]:
            self.command_kind.addItem(title,code)
        self.command_path = QLineEdit()
        self.command_path.setPlaceholderText("Абсолютный путь на удалённом устройстве")
        self.command_kind.currentIndexChanged.connect(lambda:self.command_path.setEnabled(self.command_kind.currentData()=="scan_path"))
        self.command_path.setEnabled(False)
        inside.addLayout(row(self.command_agent,self.command_kind))
        inside.addLayout(row(self.command_path,button("Отправить команду",self.send_command,True,"arrow")))
        inside.addWidget(label("Команда попадёт в очередь. Результат появится после выполнения агентом; scan_path работает в режиме обнаружения.","muted",True))
        layout.addWidget(frame)
        self.table_page(layout,[("Команда",lambda r:r.get("command_type","—")),("Статус",lambda r:r.get("status"),130),
            ("Создана",lambda r:pretty_time(r.get("created_at")),165)],"commands_table","Выберите устройство. Здесь появятся последние 50 команд.","Результат выполнения")

    def path_control(self, placeholder, mode="file"):
        field = QLineEdit()
        field.setPlaceholderText(placeholder)
        def browse():
            if mode == "directory":
                value = QFileDialog.getExistingDirectory(self,"Выберите каталог")
            else:
                value,_ = QFileDialog.getOpenFileName(self,"Выберите файл")
            if value:
                field.setText(value)
        return field, row(field,button("Обзор…",browse,symbol="folder"))

    def build_scan(self, layout):
        frame, inside = card()
        inside.addWidget(label("Что проверить","sectionTitle"))
        self.scan_path, pathrow = self.path_control("Абсолютный путь к файлу или каталогу")
        pathrow.addWidget(button("Каталог…",lambda:self.choose_scan_directory()))
        inside.addLayout(pathrow)
        self.scan_mode = QComboBox()
        for title,code in [("Сигнатуры · хеши файлов","fast"),("YARA · активная база правил","yara-scan"),("Full · режим YARA движка","full")]:
            self.scan_mode.addItem(title,code)
        self.scan_rules, rulesrow = self.path_control("Свои YARA-правила — необязательно","directory")
        self.scan_rules.setEnabled(False)
        self.scan_mode.currentIndexChanged.connect(lambda:self.scan_rules.setEnabled(self.scan_mode.currentData()!="fast"))
        inside.addLayout(row(label("Режим"),self.scan_mode))
        inside.addLayout(rulesrow)
        self.quarantine_check = QCheckBox("Перемещать обнаруженные файлы в карантин")
        inside.addWidget(self.quarantine_check)
        inside.addWidget(label("По умолчанию файлы остаются на месте. Полное сканирование процессов ещё не реализовано в движке.","muted",True))
        self.scan_start = button("Начать сканирование",self.scan,True,"scan")
        self.scan_stop = button("Остановить",lambda:self.engine.cancel())
        self.scan_stop.setEnabled(False)
        inside.addLayout(row(self.scan_start,self.scan_stop,button("Сохранить результат",self.save_scan_output,symbol="export"),stretch=True))
        layout.addWidget(frame)
        layout.addWidget(label("Результат проверки","sectionTitle"))
        self.scan_output = QPlainTextEdit()
        self.scan_output.setReadOnly(True)
        self.scan_output.setPlaceholderText("Здесь появятся обнаружения, действия и сообщения движка. Сканирование не блокирует интерфейс.")
        self.scan_output.document().setMaximumBlockCount(15000)
        self.scan_output.setMinimumHeight(260)
        layout.addWidget(self.scan_output,1)

    def build_quarantine(self, layout):
        details = self.table_page(layout,[("Исходный путь",lambda r:r.get("original_path","—")),("Обнаружение",lambda r:r.get("malware_name"),190),
            ("Дата",lambda r:pretty_time(r.get("timestamp")),160)],"quarantine_table","Карантин ещё не загружен. Нажмите «Обновить».","Изолированный файл")
        for title,action in (("Восстановить файл…","restore"),("Удалить окончательно…","delete")):
            b = button(title,lambda checked=False,a=action:self.quarantine_action(a))
            b.setObjectName("danger")
            b.setEnabled(False)
            self.quarantine_table.selected.connect(lambda r,b=b:b.setEnabled(bool(r) and not self.demo))
            details.actions.addWidget(b)
        details.actions.addWidget(label("Восстановление возвращает файл в исходное место. Существующий файл не перезаписывается.","muted",True))

    def build_updates(self, layout):
        frame, inside = card()
        inside.addWidget(label("Активная база обнаружения","sectionTitle"))
        self.feed_labels = {}
        form = QFormLayout()
        form.setSpacing(16)
        for key in ("Версия базы","Срок действия","Источник обновлений","Публичный ключ","Каталог данных","Проверка подписи"):
            value = label("—","",True)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.feed_labels[key] = value
            form.addRow(label(key,"muted"),value)
        inside.addLayout(form)
        inside.addLayout(row(button("Проверить подпись",lambda:self.local_job("Проверка базы",lambda:self.engine.run(["check-feed"],timeout=60)),symbol="shield"),
                             button("Загрузить обновление",self.update_feed,True,"updates"),stretch=True))
        inside.addWidget(label("Обновление проверяется доверенным ключом. После смены базы работающий агент пока нужно перезапустить, чтобы он загрузил новую версию.","muted",True))
        layout.addWidget(frame)
        self.update_output = QPlainTextEdit()
        self.update_output.setReadOnly(True)
        self.update_output.setPlaceholderText("Результаты проверки и обновления базы")
        layout.addWidget(self.update_output,1)

    def build_policy(self, layout):
        frame, inside = card()
        inside.addWidget(label("События, отправляемые агентами","sectionTitle"))
        self.policy_fields = {}
        titles = {"send_heartbeat":"Сигналы активности", "send_host_info":"Сведения о компьютере", "send_file_events":"Файловые события",
                  "send_clean_scans":"Результаты без обнаружений", "send_detections":"Обнаружения угроз", "send_command_results":"Результаты команд"}
        for key,title in titles.items():
            check = QCheckBox(title)
            self.policy_fields[key] = check
            inside.addWidget(check)
        layout.addWidget(frame)
        frame, inside = card()
        inside.addWidget(label("Частота и объём","sectionTitle"))
        form = QFormLayout()
        for key,title,low,high,suffix in [("file_event_sample_percent","Выборка файловых событий",0,100," %"),
                ("heartbeat_interval_secs","Интервал активности",5,3600," сек"),("max_batch","Событий в пакете",1,1000,"")]:
            field = QSpinBox()
            field.setRange(low,high)
            field.setSuffix(suffix)
            self.policy_fields[key] = field
            form.addRow(label(title),field)
        inside.addLayout(form)
        inside.addLayout(row(button("Загрузить с сервера",self.load_policy),button("Применить политику",self.save_policy,True),stretch=True))
        self.policy_hint = label("Сначала загрузите действующую политику с сервера.","muted",True)
        inside.addWidget(self.policy_hint)
        layout.addWidget(frame)
        layout.addStretch()

    def build_settings(self, layout):
        tabs = QTabWidget()
        network = QWidget()
        form_layout = QVBoxLayout(network)
        form_layout.setContentsMargins(24,24,24,24)
        form_layout.setSpacing(18)
        form_layout.addWidget(label("Подключение к Haruspic EDR","sectionTitle"))
        form = QFormLayout()
        form.setSpacing(15)
        self.server_url = QLineEdit(self.prefs.server_url)
        self.server_url.setPlaceholderText("https://edr.example.org")
        self.token = QLineEdit()
        self.token.setEchoMode(QLineEdit.EchoMode.Password)
        self.token.setPlaceholderText("Admin token · хранится только до выхода из приложения")
        self.ca_path, ca_row = self.path_control("PEM-файл частного CA — необязательно")
        self.ca_path.setText(self.prefs.ca_file)
        form.addRow(label("Адрес сервера"),self.server_url)
        form.addRow(label("Токен доступа"),self.token)
        form.addRow(label("Доверенный CA"),ca_row)
        form_layout.addLayout(form)
        form_layout.addLayout(row(button("Подключиться",self.connect_server,True),button("Импорт доступа…",self.import_credentials),button("Отключиться",self.disconnect_server),stretch=True))
        form_layout.addWidget(label("Сохранение настроек не сохраняет токен. Импортируйте admin-credentials.json из установки сервера; enrollment.json предназначен для регистрации агентов.","muted",True))
        form_layout.addStretch()
        local = QWidget()
        locallayout = QVBoxLayout(local)
        locallayout.setContentsMargins(24,24,24,24)
        locallayout.setSpacing(18)
        locallayout.addWidget(label("Подключение локального движка","sectionTitle"))
        localform = QFormLayout()
        localform.setSpacing(15)
        self.local_fields = {}
        for key,title in (("cli_path","Исполняемый файл spire"),("core_config","Конфигурация ядра · JSON"),("agent_config","Конфигурация агента · TOML")):
            field, pathrow = self.path_control(title)
            field.setText(getattr(self.prefs,key))
            localform.addRow(label(title),pathrow)
            self.local_fields[key] = field
        locallayout.addLayout(localform)
        locallayout.addWidget(label("GUI использует права текущего пользователя. Защищённые файлы установленного агента могут быть недоступны; приложение не меняет ACL и не запрашивает повышение прав автоматически.","muted",True))
        locallayout.addWidget(button("Сохранить настройки",self.save_preferences,True))
        locallayout.addLayout(row(button("Наблюдение и исключения…",lambda:self.edit_configuration(False)),button("Лимиты сканирования…",lambda:self.edit_configuration(True))))
        locallayout.addStretch()
        logpage = QWidget()
        loglayout = QVBoxLayout(logpage)
        loglayout.setContentsMargins(20,20,20,20)
        loglayout.addWidget(label("Операции текущего сеанса","sectionTitle"))
        self.operation_log = QPlainTextEdit()
        self.operation_log.setReadOnly(True)
        self.operation_log.document().setMaximumBlockCount(500)
        loglayout.addWidget(self.operation_log)
        tabs.addTab(network,"Сервер")
        tabs.addTab(local,"Локальный агент")
        tabs.addTab(logpage,"Диагностика")
        layout.addWidget(tabs,1)

    def navigate(self, key):
        self.current_page = key
        self.stack.setCurrentWidget(self.page_widgets[key])
        for name,b in self.nav.items():
            b.setChecked(name == key)
        title = next(p[1] for p in PAGES if p[0]==key)
        self.breadcrumb.setText("Рабочее пространство  /  " + title)
        if key == "commands":
            self.load_commands()
        elif key == "policy" and not self.policy_loaded and self.api:
            self.load_policy()
        elif key in ("quarantine", "updates") and not self.demo:
            self.refresh()

    def notice(self, text, error=False):
        # All network/engine strings are rendered as plain text, never rich text.
        self.message.setText(str(text)[:700])
        self.message.setStyleSheet("background: #f9eee8; color: #8b4938;" if error else "background: #edf3e8; color: #45654e;")
        self.message.show()
        self.operation_log.appendPlainText(datetime.now().strftime("%H:%M:%S") + "  " + str(text)[:1500])

    def task(self, key, work, success, failure=None, session=False):
        if key in self.jobs:
            return False
        if len(self.jobs) >= 6:
            self.notice("Дождитесь завершения текущих операций.")
            return False
        generation = self.generation
        task = Task(work)
        self.jobs[key] = task
        self.progress.show()
        self.footer.setText("Выполняется: " + key)
        def finished(value, error):
            self.jobs.pop(key,None)
            self.progress.setVisible(bool(self.jobs))
            self.footer.setText("Готово" if not self.jobs else "Выполняется операция…")
            if session and generation != self.generation:
                return
            if error:
                if failure:
                    failure(error)
                else:
                    self.notice(error,True)
            else:
                success(value)
        task.signals.done.connect(finished, Qt.ConnectionType.QueuedConnection)
        self.pool.start(task)
        return True

    def save_preferences(self):
        if "Локальный движок" in self.jobs:
            return self.notice("Дождитесь завершения локальной операции.",True)
        prefs = Preferences(server_url=self.server_url.text().strip(),ca_file=self.ca_path.text().strip(),
                            **{k:w.text().strip() for k,w in self.local_fields.items()})
        try:
            prefs.save(self.preferences_path)
            self.prefs = prefs
            self.engine = LocalEngine(replace(prefs))
            self.notice("Настройки сохранены. Токен доступа остаётся только в памяти.")
        except OSError as exc:
            self.notice(str(exc),True)

    def connect_server(self):
        if self.demo:
            return self.notice("Для реального подключения перезапустите приложение без --demo.")
        try:
            client = ApiClient(self.server_url.text(),self.token.text().strip(),self.ca_path.text().strip())
        except (ValueError, BackendError, OSError) as exc:
            return self.notice(str(exc),True)
        self.generation += 1
        self.api = None
        self.policy_loaded = False
        self.clear_remote()
        self.connection.setText("Подключение…")
        def connected(data):
            self.api = client
            self.prefs.server_url, self.prefs.ca_file = client.base, client.ca_file
            try:
                self.prefs.save(self.preferences_path)
            except OSError:
                self.notice("Подключение установлено, но настройки не удалось сохранить.",True)
            self.token.clear()
            self.apply_snapshot(data)
            self.notice("Подключение установлено. Данные синхронизированы.")
            self.navigate("overview")
        self.task("Подключение " + str(self.generation),client.snapshot,connected,self.remote_error,session=True)

    def import_credentials(self):
        path,_ = QFileDialog.getOpenFileName(self,"Доступ администратора",filter="JSON (*.json)")
        if not path:
            return
        try:
            data = read_json(path,64*1024)
            if not isinstance(data.get("admin_token"),str) or not isinstance(data.get("console_url"),str):
                raise BackendError("Нужен admin-credentials.json, а не профиль регистрации агента.")
            address = data["console_url"].removesuffix("/console")
            validate_url(address)
            self.server_url.setText(address)
            self.token.setText(data["admin_token"])
            self.notice("Доступ импортирован в память. Нажмите «Подключиться».")
        except (BackendError,OSError,ValueError) as exc:
            self.notice(str(exc),True)

    def clear_remote(self):
        self.data = {"stats":{},"agents":[],"alerts":[],"events":[]}
        for table in (self.agents_table,self.alerts_table,self.events_table,self.commands_table,self.overview_alerts):
            table.set_records([])
        self.command_agent.clear()
        for value in self.metrics.values():
            value.setText("—")
        self.summary.setText("Подключите инфраструктуру")
        self.summary_hint.setText("Добавьте сервер, чтобы увидеть устройства, обнаружения и задачи.")
        self.chart.set_alerts([])
        self.health_text.setText("Нет подключения к серверу")
        self.sync_text.setText("Последняя синхронизация: —")
        self.last_sync = None
        self.policy_loaded = False
        for field in self.policy_fields.values():
            if isinstance(field,QCheckBox):
                field.setChecked(False)
            else:
                field.setValue(field.minimum())
        self.policy_hint.setText("Сначала загрузите действующую политику с сервера.")

    def disconnect_server(self):
        self.generation += 1
        self.api = None
        self.token.clear()
        self.clear_remote()
        self.connection.setText("Сервер не подключён")
        self.notice("Сеанс закрыт. Токен удалён из полей приложения; выполняющиеся запросы завершатся без применения результатов.")

    def remote_error(self, error):
        self.connection.setText("Нет связи · данные устарели" if self.last_sync else "Сервер не подключён")
        self.health_text.setText("Нет связи. Последние данные могут быть устаревшими.")
        self.notice(error,True)

    def refresh(self):
        if self.demo:
            return
        if self.current_page=="quarantine":
            engine = self.engine
            self.task("Карантин",engine.quarantine,lambda rows:self.quarantine_table.set_records(rows))
        elif self.current_page=="updates":
            engine = self.engine
            self.task("Сведения о базе",engine.feed_info,self.show_feed)
        elif self.current_page=="commands":
            self.load_commands()
        elif self.api:
            client = self.api
            self.task("Синхронизация",client.snapshot,self.apply_snapshot,self.remote_error,session=True)

    def apply_snapshot(self, data):
        self.data = data
        for key,widget in self.metrics.items():
            widget.setText(str(data["stats"].get(key,"—")))
        opened = data["stats"].get("open_alerts",0)
        self.summary.setText("Есть инциденты, требующие внимания" if opened else "Открытых инцидентов нет")
        self.summary_hint.setText(f"Открыто: {opened}  ·  На связи: {data['stats'].get('online',0)} из {data['stats'].get('agents',0)} устройств")
        self.agents_table.set_records(data["agents"])
        self.agents_table.filter(self.agents_table.search.text())
        self.render_alerts()
        self.events_table.set_records(data["events"])
        self.events_table.filter(self.events_table.search.text())
        self.overview_alerts.set_records([a for a in data["alerts"] if a.get("status")=="open"][:4])
        self.chart.set_alerts(data["alerts"])
        old = self.command_agent.currentData()
        self.command_agent.blockSignals(True)
        self.command_agent.clear()
        self.command_agent.addItem("Выберите устройство…",None)
        for a in data["agents"]:
            self.command_agent.addItem(f"{a.get('hostname','—')} · {a.get('os_name','—')}",a.get("id"))
        index = self.command_agent.findData(old)
        self.command_agent.setCurrentIndex(max(index,0))
        self.command_agent.blockSignals(False)
        self.last_sync = datetime.now()
        self.sync_text.setText("Последняя синхронизация: " + self.last_sync.strftime("%H:%M:%S"))
        self.health_text.setText("Данные примера" if self.demo else "API доступен · синхронизация каждые 30 сек")
        if not self.demo:
            self.connection.setText("●  Сервер подключён")

    def render_alerts(self):
        if not hasattr(self,"alerts_table"):
            return
        status = self.alert_filter.currentData()
        self.alerts_table.set_records([a for a in self.data["alerts"] if not status or a.get("status")==status])
        self.alerts_table.filter(self.alerts_table.search.text())

    def require_remote(self):
        if self.demo:
            self.notice("В демонстрационном режиме изменения отключены.")
            return False
        if not self.api:
            self.notice("Сначала подключите сервер в настройках.",True)
            return False
        return True

    def confirm(self, title, text):
        dialog = QMessageBox(QMessageBox.Icon.Warning,title,text,QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.Cancel,self)
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        dialog.button(QMessageBox.StandardButton.Yes).setText("Подтвердить")
        dialog.button(QMessageBox.StandardButton.Cancel).setText("Отмена")
        return dialog.exec()==QMessageBox.StandardButton.Yes

    def from_agent(self, kind):
        record = self.agents_table.current()
        if record:
            self.command_agent.setCurrentIndex(self.command_agent.findData(record["id"]))
            self.command_kind.setCurrentIndex(self.command_kind.findData(kind))
            self.navigate("commands")
            self.command_path.setFocus()

    def agent_history(self):
        record = self.agents_table.current()
        if record:
            self.command_agent.setCurrentIndex(self.command_agent.findData(record["id"]))
            self.navigate("commands")
        else:
            self.notice("Выберите устройство в таблице.")

    def send_command(self):
        if not self.require_remote():
            return
        agent,kind,path = self.command_agent.currentData(),self.command_kind.currentData(),self.command_path.text().strip()
        if not agent:
            return self.notice("Выберите устройство.",True)
        if kind=="scan_path" and not path:
            return self.notice("Укажите путь на выбранном устройстве.",True)
        if not self.confirm("Отправить команду?",f"Устройство: {self.command_agent.currentText()}\nКоманда: {self.command_kind.currentText()}" + ("\nПуть: " + path if kind=="scan_path" else "")):
            return
        client = self.api
        def done(value):
            self.notice("Команда поставлена в очередь. Идентификатор: " + str(value.get("id","—")))
            self.load_commands()
        self.task("Отправка команды",lambda:client.command(agent,kind,path),done,session=True)

    def load_commands(self):
        if not hasattr(self,"commands_table"):
            return
        agent = self.command_agent.currentData()
        self.commands_table.set_records([])
        if not agent or not self.api or self.demo:
            return
        client = self.api
        self.task("Команды " + str(agent),lambda:client.commands(agent),
                  lambda rows:self.commands_table.set_records(rows) if self.command_agent.currentData()==agent else None,session=True)

    def change_alert(self, status):
        record = self.alerts_table.current()
        if not record or not self.require_remote():
            return
        client = self.api
        def done(value):
            self.notice("Статус инцидента обновлён.")
            self.refresh()
        self.task("Статус инцидента",lambda:client.alert_status(record["id"],status),done,session=True)

    def show_alert_event(self):
        record = self.alerts_table.current()
        if not record:
            return self.notice("Выберите инцидент.")
        event_id = record.get("event_id","")
        matches = [e for e in self.data["events"] if e.get("event_id")==event_id]
        if not matches:
            return self.notice("Исходное событие не входит в последние 1 000 загруженных записей. API пока не поддерживает запрос события по ID.",True)
        self.navigate("events")
        self.events_table.set_records(matches)
        self.events_table.search.clear()
        self.events_table.table.selectRow(0)

    def choose_scan_directory(self):
        path = QFileDialog.getExistingDirectory(self,"Каталог для сканирования")
        if path:
            self.scan_path.setText(path)

    def local_job(self, title, work, scan=False):
        if self.demo:
            return self.notice("Локальные операции отключены в демонстрационном режиме.")
        if "Локальный движок" in self.jobs:
            return self.notice("Дождитесь завершения текущей операции.")
        output = self.scan_output if scan else self.update_output
        output.setPlainText(title + "…")
        self.scan_start.setEnabled(False)
        self.scan_stop.setEnabled(scan)
        def completed(value, error=False):
            self.scan_start.setEnabled(True)
            self.scan_stop.setEnabled(False)
            output.setPlainText(str(value))
            self.notice(title + (": " + str(value) if error else ": завершено."),error)
            if title=="Проверка базы":
                self.feed_labels["Проверка подписи"].setText("Проверка не пройдена" if error else "Проверено движком · " + datetime.now().strftime("%H:%M"))
            if self.current_page=="quarantine" or (title=="Обновление базы" and not error):
                self.refresh()
        self.task("Локальный движок",work,completed,lambda error:completed(error,True))

    def scan(self):
        path,mode = self.scan_path.text().strip(),self.scan_mode.currentData()
        rules = self.scan_rules.text().strip() if mode!="fast" else ""
        quarantine = self.quarantine_check.isChecked()
        if quarantine and not self.confirm("Сканирование с карантином", "Обнаруженные файлы будут перемещены из исходных каталогов. Продолжить?"):
            return
        engine = self.engine
        self.local_job("Сканирование",lambda:engine.scan(path,mode,quarantine,rules),scan=True)

    def quarantine_action(self, action):
        record = self.quarantine_table.current()
        if not record or self.demo:
            return
        title = "Восстановить файл" if action=="restore" else "Удалить файл окончательно"
        if not self.confirm(title, str(record.get("original_path","")) + ("\nФайл снова станет доступен приложениям." if action=="restore" else "\nЭто действие необратимо.")):
            return
        engine = self.engine
        self.local_job(title,lambda:engine.quarantine_action(action,record["id"]))

    def show_feed(self, data):
        for key,widget in self.feed_labels.items():
            widget.setText(str(data.get(key,"—")))
        expires = data.get("expires_at")
        self.feed_labels["Срок действия"].setText(pretty_time(expires) if expires else "—")
        if isinstance(expires,(int,float)) and expires <= datetime.now(timezone.utc).timestamp():
            self.feed_labels["Срок действия"].setText("Просрочена · " + pretty_time(expires))
            self.notice("Активная база просрочена. Требуется новый подписанный выпуск.",True)

    def update_feed(self):
        engine = self.engine
        self.local_job("Обновление базы",lambda:engine.run(["update-db"],timeout=180))

    def load_policy(self):
        if not self.require_remote():
            return
        client = self.api
        def show(data):
            for key,field in self.policy_fields.items():
                if key not in data:
                    return self.notice("Сервер вернул неполную политику.",True)
            for key,field in self.policy_fields.items():
                if isinstance(field,QCheckBox):
                    field.setChecked(bool(data[key]))
                else:
                    field.setValue(int(data[key]))
            self.policy_loaded = True
            self.policy_hint.setText("Политика загружена: " + datetime.now().strftime("%H:%M:%S"))
        self.task("Политика",lambda:client.request("GET","/v1/policy"),show,session=True)

    def save_policy(self):
        if not self.require_remote():
            return
        if not self.policy_loaded:
            return self.notice("Сначала загрузите действующую политику.",True)
        data = {key:field.isChecked() if isinstance(field,QCheckBox) else field.value() for key,field in self.policy_fields.items()}
        if not self.confirm("Применить политику ко всем агентам?","Изменения затронут сбор телеметрии всей подключённой инфраструктуры."):
            return
        client = self.api
        self.task("Сохранение политики",lambda:client.request("PUT","/v1/policy",data),
                  lambda result:self.notice("Политика сохранена на сервере. Агенты применят её при следующем опросе."),session=True)

    def edit_configuration(self, limits):
        if self.demo:
            return self.notice("Редактирование отключено в демонстрационном режиме.")
        if "Локальный движок" in self.jobs:
            return self.notice("Дождитесь завершения локальной операции.")
        from .config_dialog import ConfigurationDialog
        try:
            path = self.prefs.core_config if limits else self.prefs.agent_config
            dialog = ConfigurationDialog(path,limits,self)
            if dialog.exec():
                self.notice("Настройки агента сохранены; предыдущая версия — в .gui-backup. Перезапустите агент, чтобы применить изменения.")
        except Exception as exc:
            self.notice(str(exc),True)

    def export_records(self, records):
        path,_ = QFileDialog.getSaveFileName(self,"Экспорт загруженной выборки","haruspic-export.json","JSON (*.json)")
        if path:
            try:
                Path(path).write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding="utf-8")
                self.notice("Выборка сохранена: " + path)
            except OSError as exc:
                self.notice(str(exc),True)

    def save_scan_output(self):
        path,_ = QFileDialog.getSaveFileName(self,"Сохранить результат","haruspic-scan.txt","Текст (*.txt)")
        if path:
            try:
                Path(path).write_text(self.scan_output.toPlainText(),encoding="utf-8")
                self.notice("Результат сохранён: " + path)
            except OSError as exc:
                self.notice(str(exc),True)

    def closeEvent(self, event):
        if self.jobs:
            self.notice("Дождитесь завершения запросов. Локальное сканирование можно остановить кнопкой «Остановить».")
            event.ignore()
            return
        self.timer.stop()
        self.api = None
        self.token.clear()
        event.accept()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Haruspic EDR desktop console")
    parser.add_argument("--demo",action="store_true",help="read-only preview with clearly labelled synthetic data")
    parser.add_argument("--screenshot",help="save a preview PNG and exit; requires --demo")
    parser.add_argument("--page",choices=[p[0] for p in PAGES],default="overview")
    args = parser.parse_args(argv)
    if args.screenshot and not args.demo:
        parser.error("--screenshot requires --demo")
    app = QApplication.instance() or QApplication([sys.argv[0]])
    app.setApplicationName("haruspic_edr_gui")
    app.setOrganizationName("Haruspic")
    apply(app)
    window = MainWindow(demo=args.demo)
    window.navigate(args.page)
    if args.screenshot:
        window.resize(1440, 1120)
    window.show()
    if args.screenshot:
        def capture():
            if args.page in ("agents", "alerts", "events"):
                getattr(window, args.page + "_table").table.selectRow(0)
                app.processEvents()
            path = Path(args.screenshot).resolve()
            path.parent.mkdir(parents=True,exist_ok=True)
            if not window.grab().save(str(path)):
                app.exit(1)
            else:
                app.quit()
        QTimer.singleShot(500,capture)
    return app.exec()
