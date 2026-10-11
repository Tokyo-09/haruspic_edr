"""Transport and local engine adapter, independent of Qt.

No shell execution, no background enrollment, no saved admin credentials.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict, field
from contextlib import closing
import json
import os
from pathlib import Path
import shutil
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


class BackendError(Exception):
    pass


def read_json(path, cap=1024 * 1024):
    with Path(path).open("rb") as stream:
        raw = stream.read(cap + 1)
    if len(raw) > cap:
        raise BackendError("JSON-файл превышает допустимый размер.")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise BackendError("Ожидался объект JSON.")
    return value


def validate_url(value):
    value = value.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment or any(ord(c) < 33 for c in value)):
        raise BackendError("Укажите адрес сервера: https://edr.example.org, без пути и параметров.")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise BackendError("Для удалённого сервера требуется HTTPS.")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise BackendError("Некорректный порт сервера.") from exc
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise BackendError("Перенаправление отклонено. Укажите конечный адрес сервера.")


@dataclass(frozen=True)
class ApiClient:
    base: str
    token: str = field(repr=False)
    ca_file: str = ""

    def __post_init__(self):
        object.__setattr__(self, "base", validate_url(self.base))
        if not self.token or not self.token.isascii() or any(c.isspace() for c in self.token):
            raise BackendError("Укажите корректный admin token.")

    def request(self, method, path, body=None, query=None):
        if not path.startswith("/v1/"):
            raise BackendError("Недопустимый API-маршрут.")
        address = self.base + path
        if query:
            address += "?" + urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
        context = ssl.create_default_context(cafile=self.ca_file or None)
        opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))
        req = urllib.request.Request(address, method=method,
            data=None if body is None else json.dumps(body, ensure_ascii=False).encode(),
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with opener.open(req, timeout=12) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
                if len(raw) > 8 * 1024 * 1024:
                    raise BackendError("Ответ сервера слишком большой. Уменьшите выборку.")
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            messages = {401:"Нет доступа. Проверьте admin token.", 403:"Операция запрещена сервером.",
                        404:"Объект не найден на сервере.", 422:"Сервер отклонил параметры запроса.", 429:"Сервер перегружен. Повторите позже."}
            raise BackendError(messages.get(exc.code, f"Сервер вернул HTTP {exc.code}.")) from None
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
            raise BackendError("Сервер недоступен. Проверьте адрес, сеть и доверенный TLS-сертификат.") from None
        except (json.JSONDecodeError, UnicodeError):
            raise BackendError("Сервер вернул некорректный JSON.") from None

    def snapshot(self):
        result = {"stats":self.request("GET", "/v1/stats"), "agents":self.request("GET", "/v1/agents"),
                  "alerts":self.request("GET", "/v1/alerts", query={"limit":500}),
                  "events":self.request("GET", "/v1/events", query={"limit":1000})}
        if not isinstance(result["stats"], dict) or any(not isinstance(result[k], list) or any(not isinstance(r, dict) for r in result[k]) for k in ("agents", "alerts", "events")):
            raise BackendError("Ответ сервера не соответствует схеме консоли.")
        return result

    def command(self, agent_id, kind, path=""):
        if kind not in ("ping", "collect_inventory", "scan_path"):
            raise BackendError("Команда не поддерживается.")
        if kind == "scan_path" and (not path.strip() or len(path) > 4096):
            raise BackendError("Укажите путь на выбранном устройстве.")
        return self.request("POST", f"/v1/agents/{urllib.parse.quote(str(agent_id), safe='')}/commands",
                            {"command_type":kind, "payload":{"path":path} if kind == "scan_path" else {}})

    def commands(self, agent_id):
        return self.request("GET", f"/v1/agents/{urllib.parse.quote(str(agent_id), safe='')}/commands")

    def alert_status(self, alert_id, status):
        if status not in ("open", "ack", "closed"):
            raise BackendError("Недопустимый статус инцидента.")
        return self.request("PATCH", f"/v1/alerts/{int(alert_id)}", {"status":status})


@dataclass
class Preferences:
    server_url: str = "https://"
    ca_file: str = ""
    cli_path: str = ""
    core_config: str = ""
    agent_config: str = ""

    @classmethod
    def defaults(cls):
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Spire/config/agent" if os.name == "nt" else Path("/etc/spire/agent")
        binary = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Spire/bin/spire.exe" if os.name == "nt" else Path("/opt/spire/bin/spire")
        repo = Path(__file__).resolve().parents[2]
        for candidate in (binary, repo / "target/release" / ("spire.exe" if os.name == "nt" else "spire"), repo / "target/debug" / ("spire.exe" if os.name == "nt" else "spire")):
            if candidate.is_file():
                binary = candidate
                break
        return cls(cli_path=str(binary), core_config=str(base / "config.json"), agent_config=str(base / "agent.toml"))

    @classmethod
    def load(cls, path):
        result = cls.defaults()
        if Path(path).exists():
            values = read_json(path)
            for key in asdict(result):
                if isinstance(values.get(key), str):
                    setattr(result, key, values[key])
        return result

    def save(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(asdict(self), stream, ensure_ascii=False, indent=2)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def readonly_db(path):
    # URI quoting also handles spaces, # and Windows drive letters.
    return closing(sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=2))


class LocalEngine:
    def __init__(self, prefs):
        self.prefs = prefs
        self._lock = threading.Lock()
        self._cancel = threading.Event()

    def context(self):
        cfg = read_json(self.prefs.core_config)
        state = Path(cfg.get("spire_dir") or (Path.home() / ".spire")).expanduser()
        if not state.is_absolute():
            raise BackendError("spire_dir в конфигурации должен быть абсолютным.")
        env = {**os.environ, "SPIRE_CONFIG_PATH":str(Path(self.prefs.core_config).resolve()),
               "SPIRE_AGENT_CONFIG":str(Path(self.prefs.agent_config).resolve()), "SPIRE_STATE_DIR":str(state)}
        # Follow the installed agent's private CA; explicit GUI CA can override it.
        runtime = Path(self.prefs.core_config).with_name("runtime-env.json")
        ca = self.prefs.ca_file
        if not ca and runtime.is_file():
            ca = read_json(runtime).get("SPIRE_CA_CERT", "")
        if ca:
            env["SPIRE_CA_CERT"] = ca
        else:
            env.pop("SPIRE_CA_CERT", None)
        return cfg, state, env

    def run(self, args, timeout=600):
        if not self._lock.acquire(blocking=False):
            raise BackendError("Другая операция движка ещё выполняется.")
        try:
            self._cancel.clear()
            _, _, env = self.context()
            binary = Path(self.prefs.cli_path).expanduser()
            if not binary.is_absolute() or not binary.is_file():
                raise BackendError("CLI не найден. Укажите абсолютный путь к spire в настройках.")
            with tempfile.TemporaryFile() as output:
                with subprocess.Popen([str(binary), *args], env=env, cwd=str(Path(self.prefs.core_config).resolve().parent),
                                      stdout=output, stderr=subprocess.STDOUT,
                                      creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0) as process:
                    deadline = time.monotonic() + timeout
                    reason = None
                    while process.poll() is None:
                        if self._cancel.is_set():
                            reason = "Операция отменена. Уже выполненные действия не откатываются."
                        elif time.monotonic() > deadline:
                            reason = "Превышено время выполнения операции."
                        elif os.fstat(output.fileno()).st_size > 4 * 1024 * 1024:
                            reason = "Вывод движка превысил лимит 4 MiB."
                        if reason:
                            process.terminate()
                            try:
                                process.wait(timeout=3)
                            except subprocess.TimeoutExpired:
                                process.kill()
                            break
                        time.sleep(.05)
                    process.wait()
                output.seek(0)
                text = output.read(4 * 1024 * 1024).decode("utf-8", "replace")
                if reason:
                    raise BackendError(reason)
                if process.returncode:
                    raise BackendError(text[-6000:] or f"Движок завершился с кодом {process.returncode}.")
                return text.strip() or "Операция завершена. Движок не сообщил обнаружений; проверьте отчёт и сообщения о неполном сканировании."
        finally:
            self._lock.release()

    def cancel(self):
        self._cancel.set()

    def scan(self, path, mode, quarantine=False, rules="", report=""):
        target = Path(path).expanduser()
        if not target.is_absolute() or not target.exists():
            raise BackendError("Выберите существующий файл или каталог с абсолютным путём.")
        if mode not in ("fast", "full", "yara-scan"):
            raise BackendError("Режим сканирования не поддерживается движком.")
        args = ["scan"] + (["--quarantine"] if quarantine else []) + [mode, "--path", str(target)]
        if rules:
            if mode == "fast" or not Path(rules).is_dir():
                raise BackendError("Пользовательские YARA-правила доступны только в режимах YARA; выберите каталог.")
            args += ["--rules", str(Path(rules).resolve())]
        if report:
            args += ["--report", str(Path(report).resolve())]
        return self.run(args)

    def quarantine(self):
        _, state, _ = self.context()
        path = state / "response.db"
        if not path.exists():
            return []
        with readonly_db(path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute("SELECT id,original_path,malware_name,timestamp FROM quarantine ORDER BY timestamp DESC LIMIT 1000")]

    def quarantine_action(self, action, record_id):
        if action not in ("restore", "delete") or int(record_id) < 1:
            raise BackendError("Недопустимое действие карантина.")
        return self.run(["quarantine", action, "--id", str(int(record_id))], timeout=30)

    def feed_info(self):
        cfg, state, _ = self.context()
        result = {"Каталог данных":str(state), "Источник обновлений":cfg.get("update_url", "Не задан"),
                  "Публичный ключ":cfg.get("update_public_key", "Не задан"), "Версия базы":"Не установлена"}
        if (state / "feed-state.db").exists():
            with readonly_db(state / "feed-state.db") as conn:
                row = conn.execute("SELECT version,directory FROM active_feed WHERE id=1").fetchone()
            if row:
                directory = str(row[1])
                if Path(directory).name != directory or not directory.startswith("signed-") or "\\" in directory:
                    raise BackendError("Некорректный путь активной базы.")
                manifest = read_json(state / "feeds" / directory / "manifest.json")
                result.update({"Версия базы":str(row[0]), "expires_at":manifest.get("expires_at"),
                               "Проверка подписи":"Выполните проверку движком"})
        return result
