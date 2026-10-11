"""Validated local configuration edits. Enrollment secrets are never exposed in GUI forms."""
from __future__ import annotations
import json
import os
from pathlib import Path
import stat
import tempfile
import tomllib
from .backend import BackendError, read_json

LIMITS = {"max_file_bytes":(64*1024*1024,1,256*1024*1024), "max_files":(10000,1,100000),
          "max_entries":(50000,1,1000000), "max_depth":(64,1,128), "timeout_secs":(120,1,3600), "yara_timeout_secs":(2,1,30)}
AGENT_FIELDS = ("watch_paths","excluded_paths","excluded_extensions","excluded_files","response_policy")


def toml_dump(data, prefix=()):
    """Serialize the existing config's JSON-compatible TOML types, preserving all fields."""
    lines = []
    if prefix:
        lines.append("[" + ".".join(json.dumps(k) for k in prefix) + "]")
    for key,value in data.items():
        if isinstance(value,dict):
            continue
        if not isinstance(value,(str,int,float,bool,list)) or value is None:
            raise BackendError("Конфигурация содержит неподдерживаемый тип TOML; используйте текстовый редактор.")
        lines.append(json.dumps(key) + " = " + json.dumps(value,ensure_ascii=False,allow_nan=False))
    for key,value in data.items():
        if isinstance(value,dict):
            lines += ["",toml_dump(value,(*prefix,key))]
    return "\n".join(lines) + "\n"


def atomic_write(path, content):
    path = Path(path)
    if path.is_symlink():
        raise BackendError("Запись через символическую ссылку запрещена.")
    mode = stat.S_IMODE(path.stat().st_mode)
    previous = path.read_bytes()
    backup = path.with_name(path.name + ".gui-backup")
    for target,data in ((backup,previous),(path,content.encode())):
        if target.is_symlink():
            raise BackendError("Резервный файл является символической ссылкой.")
        fd,temporary = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd,"wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            os.chmod(temporary,mode)
            os.replace(temporary,target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def read_agent(path):
    raw = Path(path).read_bytes()
    if len(raw)>1024*1024:
        raise BackendError("Конфигурация слишком большая.")
    return tomllib.loads(raw.decode("utf-8"))


def edit_agent(path, values, expected):
    if set(values) != set(AGENT_FIELDS):
        raise BackendError("Недопустимые поля настроек агента.")
    if values["response_policy"] not in ("observe","quarantine"):
        raise BackendError("Некорректный режим реагирования.")
    for key in AGENT_FIELDS[:-1]:
        if not isinstance(values[key],list) or any(not isinstance(v,str) or not v or '\n' in v or '\r' in v for v in values[key]):
            raise BackendError("Поля каталогов и исключений должны содержать списки строк.")
    if not values["watch_paths"] or any(not Path(p).is_absolute() for p in values["watch_paths"]+values["excluded_paths"]):
        raise BackendError("Нужен хотя бы один каталог наблюдения; пути должны быть абсолютными.")
    data = read_agent(path)
    if data != expected:
        raise BackendError("Конфигурация изменилась вне GUI. Откройте её заново.")
    data.update(values)
    output = toml_dump(data)
    if tomllib.loads(output) != data:
        raise BackendError("Не удалось сохранить TOML без потери данных.")
    atomic_write(path,output)


def edit_limits(path, values, expected):
    if set(values)!=set(LIMITS) or any(type(values[k]) is not int or not low<=values[k]<=high for k,(_,low,high) in LIMITS.items()):
        raise BackendError("Лимиты выходят за допустимые пределы движка.")
    data = read_json(path)
    if data != expected:
        raise BackendError("Конфигурация изменилась вне GUI. Откройте её заново.")
    data["scan_limits"] = values
    atomic_write(path,json.dumps(data,ensure_ascii=False,indent=2)+"\n")
