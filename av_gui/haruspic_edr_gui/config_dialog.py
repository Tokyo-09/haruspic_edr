from PySide6.QtWidgets import QDialog, QVBoxLayout, QFormLayout, QPlainTextEdit, QComboBox, QSpinBox, QMessageBox
from PySide6.QtCore import Qt
from .widgets import label, button, row
from .configuration import read_agent, edit_agent, edit_limits, LIMITS, AGENT_FIELDS
from .backend import read_json


class ConfigurationDialog(QDialog):
    def __init__(self, path, limits=False, parent=None):
        super().__init__(parent)
        self.path,self.limits = path,limits
        self.original = read_json(path) if limits else read_agent(path)
        self.setWindowTitle("Лимиты сканирования" if limits else "Наблюдение и исключения")
        self.resize(650,650)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26,26,26,26)
        layout.setSpacing(16)
        layout.addWidget(label(self.windowTitle(),"sectionTitle"))
        layout.addWidget(label("Изменения записываются в локальную конфигурацию. Для работающего агента потребуется перезапуск.","muted",True))
        form = QFormLayout()
        form.setSpacing(12)
        self.fields = {}
        if limits:
            names = {"max_file_bytes":"Размер файла, байт", "max_files":"Файлов на сканирование", "max_entries":"Записей при обходе",
                     "max_depth":"Глубина обхода", "timeout_secs":"Время сканирования, сек", "yara_timeout_secs":"Время YARA, сек"}
            for key,(default,low,high) in LIMITS.items():
                field = QSpinBox()
                field.setRange(low,high)
                field.setValue(self.original.get("scan_limits",{}).get(key,default))
                self.fields[key] = field
                form.addRow(label(names[key]),field)
        else:
            names = {"watch_paths":"Наблюдаемые каталоги", "excluded_paths":"Исключённые каталоги", "excluded_extensions":"Исключённые расширения", "excluded_files":"Исключённые имена файлов"}
            for key,title in names.items():
                field = QPlainTextEdit()
                field.setMaximumHeight(85)
                field.setPlaceholderText("Одна запись на строку")
                field.setPlainText("\n".join(self.original.get(key,[])))
                self.fields[key] = field
                form.addRow(label(title),field)
            policy = QComboBox()
            policy.addItem("Только обнаружение","observe")
            policy.addItem("Автоматический карантин","quarantine")
            policy.setCurrentIndex(max(0,policy.findData(self.original.get("response_policy","observe"))))
            self.fields["response_policy"] = policy
            form.addRow(label("Реагирование"),policy)
        layout.addLayout(form)
        self.error = label("","muted",True)
        layout.addWidget(self.error)
        layout.addStretch()
        layout.addLayout(row(button("Отмена",self.reject),button("Сохранить",self.save,True)))

    def save(self):
        try:
            if self.limits:
                edit_limits(self.path,{k:w.value() for k,w in self.fields.items()},self.original)
            else:
                values = {k:[v.strip() for v in w.toPlainText().splitlines() if v.strip()] for k,w in self.fields.items() if k!="response_policy"}
                values["response_policy"] = self.fields["response_policy"].currentData()
                if values["response_policy"]=="quarantine" and self.original.get("response_policy")!="quarantine":
                    dialog = QMessageBox(QMessageBox.Icon.Warning,"Включить карантин?","После перезапуска агент сможет перемещать обнаруженные файлы в карантин.",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.Cancel,self)
                    dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
                    if dialog.exec()!=QMessageBox.StandardButton.Yes:
                        return
                edit_agent(self.path,values,self.original)
            self.accept()
        except Exception as exc:
            self.error.setText(str(exc))
