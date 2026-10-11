#!/usr/bin/env python3
"""Spire Setup: shared terminal wizard for Linux/systemd and Windows/Task Scheduler.

Only the Python standard library is needed. Windows distributions freeze this
entry point as SpireSetup.exe. --stage and --dry-run never register services.
"""
from __future__ import annotations
import argparse
import ctypes
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import secrets
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

FEED_FILES = ("manifest.json", "manifest.sig", "database.db", "yara.zip")
MARKER_VERSION = 1


class SetupError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise SetupError(message)


def load_json(path, limit=1024 * 1024):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, f"Слишком большой файл: {path}")
    return json.loads(raw)


def url(value):
    require(isinstance(value, str), "Некорректный адрес сервера")
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme in ("http", "https") and parsed.hostname, "Адрес должен начинаться с https://")
    require(not parsed.username and not parsed.password and not parsed.query and not parsed.fragment,
            "Адрес не должен содержать пароль, параметры или fragment")
    require(parsed.path in ("", "/"), "Укажите адрес сервера без дополнительного пути")
    require(parsed.scheme == "https" or parsed.hostname in ("localhost", "127.0.0.1", "::1"),
            "HTTP разрешён только для localhost; для клиентских машин нужен HTTPS")
    require(not any(ord(c) < 33 for c in value), "Адрес содержит пробелы или управляющие символы")
    _ = parsed.port  # validate port range
    return value.rstrip("/")


def public_key(value):
    require(isinstance(value, str), "Некорректный публичный ключ")
    value = value.strip().lower()
    require(len(value) == 64 and all(c in "0123456789abcdef" for c in value), "Публичный ключ должен содержать 64 hex-символа")
    return value


def profile(path):
    data = load_json(path, 128 * 1024)
    require(isinstance(data, dict), "Профиль должен быть объектом JSON")
    require(data.get("schema_version") == 1, "Неподдерживаемая версия профиля подключения")
    data = {k: data[k] for k in ("schema_version", "server_url", "update_url", "update_public_key", "enrollment_token", "ca_pem") if k in data}
    for field in ("server_url", "update_url"):
        data[field] = url(data[field])
    data["update_public_key"] = public_key(data["update_public_key"])
    token = data["enrollment_token"]
    require(isinstance(token, str) and len(token) >= 32 and "\n" not in token and "\r" not in token,
            "Некорректный enrollment token")
    if data.get("ca_pem"):
        ssl.create_default_context(cadata=data["ca_pem"])
    return data


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise SetupError("Сервер перенаправляет запрос; укажите конечный HTTPS-адрес")


def request_json(address, ca_pem=None, body=None, headers=None):
    context = ssl.create_default_context(cadata=ca_pem or None)
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(address, data=None if body is None else json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with opener.open(request, timeout=10) as response:
            raw = response.read(64 * 1024 + 1)
            require(len(raw) <= 64 * 1024, "Ответ сервера слишком большой")
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        raise SetupError(f"Сервер вернул HTTP {exc.code}. Проверьте профиль подключения.") from exc
    except urllib.error.URLError as exc:
        raise SetupError(f"Не удалось подключиться: {exc.reason}. Проверьте адрес, TLS и firewall.") from exc


def server_files(root):
    """Allowlist distribution files so development keys/databases never get copied."""
    root = Path(root)
    for name in ("pyproject.toml", "uv.lock", "README.md"):
        yield root / name
    for path in sorted((root / "src/spire_server").rglob("*")):
        if path.is_file() and not path.is_symlink() and path.suffix in (".py", ".html", ".css", ".js") and "__pycache__" not in path.parts:
            yield path


def ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


class Layout:
    def __init__(self, target, stage=None):
        self.target = target
        self.stage = Path(stage).resolve() if stage else None
        self.pure = PureWindowsPath if target == "windows" else PurePosixPath
        if target == "windows":
            # Predictable machine-wide locations, independent of the elevated user's profile.
            self.app = str(self.pure(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Spire")
            base = self.pure(os.environ.get("ProgramData", r"C:\ProgramData")) / "Spire"
            self.config, self.state = str(base / "config"), str(base / "data")
        else:
            self.app, self.config, self.state = "/opt/spire", "/etc/spire", "/var/lib/spire"

    def join(self, first, *parts):
        return str(self.pure(first).joinpath(*parts))

    def file(self, native):
        if not self.stage:
            return Path(native)
        path = self.pure(native)
        parts = path.parts[1:]
        if self.target == "windows":
            parts = (path.drive.rstrip(":"), *parts)
        result = self.stage.joinpath(*parts)
        require(result.is_relative_to(self.stage), "Некорректный путь staging")
        return result

    def role_config(self, role):
        return self.join(self.config, role)

    def role_state(self, role):
        return self.join(self.state, role)

    def binary(self, name):
        return self.join(self.app, "bin", name + (".exe" if self.target == "windows" else ""))


def task_xml(script, working_directory):
    ns = "http://schemas.microsoft.com/windows/2004/02/mit/task"
    ET.register_namespace("", ns)
    def child(parent, tag, text=None, **attrs):
        node = ET.SubElement(parent, "{" + ns + "}" + tag, attrs)
        node.text = text
        return node
    root = ET.Element("{" + ns + "}Task", version="1.2")
    triggers = child(root, "Triggers")
    boot = child(triggers, "BootTrigger")
    child(boot, "Enabled", "true")
    child(boot, "Delay", "PT30S")
    principals = child(root, "Principals")
    principal = child(principals, "Principal", id="System")
    child(principal, "UserId", "S-1-5-18")
    child(principal, "LogonType", "ServiceAccount")
    child(principal, "RunLevel", "HighestAvailable")
    settings = child(root, "Settings")
    for name, value in (("MultipleInstancesPolicy", "IgnoreNew"), ("DisallowStartIfOnBatteries", "false"),
                        ("StopIfGoingOnBatteries", "false"), ("StartWhenAvailable", "true"),
                        ("AllowStartOnDemand", "true"), ("Enabled", "true"), ("ExecutionTimeLimit", "PT0S")):
        child(settings, name, value)
    restart = child(settings, "RestartOnFailure")
    child(restart, "Interval", "PT1M")
    child(restart, "Count", "999")
    actions = child(root, "Actions", Context="System")
    execute = child(actions, "Exec")
    child(execute, "Command", str(PureWindowsPath(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"))
    child(execute, "Arguments", '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + script + '"')
    child(execute, "WorkingDirectory", working_directory)
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def run_ps_script(executable, arguments, env_file, working, log):
    # A supervisor bounds logs and restarts the child, including after clean exit.
    # Scheduler handles reboot and supervisor failure; no hidden service is installed.
    args = ", ".join(ps_quote(arg) for arg in arguments)
    return f'''$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath {ps_quote(working)}
$settings = Get-Content -Encoding UTF8 -Raw -LiteralPath {ps_quote(env_file)} | ConvertFrom-Json
$settings.PSObject.Properties | ForEach-Object {{ [Environment]::SetEnvironmentVariable($_.Name, [string]$_.Value, 'Process') }}
while ($true) {{
    if ((Test-Path -LiteralPath {ps_quote(log)}) -and (Get-Item -LiteralPath {ps_quote(log)}).Length -gt 10MB) {{
        Move-Item -LiteralPath {ps_quote(log)} -Destination {ps_quote(log + '.previous')} -Force
    }}
    $ErrorActionPreference = 'Continue'
    & {ps_quote(executable)} @({args}) 2>&1 | ForEach-Object {{
        if ((Test-Path -LiteralPath {ps_quote(log)}) -and (Get-Item -LiteralPath {ps_quote(log)}).Length -gt 10MB) {{
            Move-Item -LiteralPath {ps_quote(log)} -Destination {ps_quote(log + '.previous')} -Force
        }}
        $_ | Out-File -LiteralPath {ps_quote(log)} -Append -Encoding utf8
    }}
    $ErrorActionPreference = 'Stop'
    Start-Sleep -Seconds 10
}}
'''


class Installer:
    def __init__(self, args, runner=None):
        self.args = args
        self.layout = Layout(args.platform, args.stage)
        self.source = Path(args.bundle).resolve()
        suffix = ".exe" if args.platform == "windows" else ""
        self.bin = Path(args.bin_dir).resolve() if args.bin_dir else self.source / "bin"
        self.names = {name: self.bin / (name + suffix) for name in ("spire", "spired", "spire-feed", "uv")}
        self.runner = runner or self.run
        self.marker = self.layout.file(self.layout.join(self.layout.role_config(args.role), "installation.json"))
        self.plan_data = {}
        self.previously_managed = self.marker.exists()

    @staticmethod
    def run(command, **kwargs):
        result = subprocess.run(list(map(str, command)), text=True, encoding="utf-8", errors="replace",
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=kwargs.pop("timeout", 600), **kwargs)
        if result.returncode:
            # Commands never include enrollment/admin tokens. Do not dump environment.
            raise SetupError(f"Не удалось выполнить {Path(command[0]).name}: {result.stderr[-2000:]}")
        return result

    def write(self, native, content, mode=0o600):
        path = self.layout.file(native)
        path.parent.mkdir(parents=True, exist_ok=True)
        require(not path.is_symlink(), f"Отказ записи через symlink: {path}")
        data = content.encode("utf-8-sig" if path.suffix == ".ps1" else "utf-8") if isinstance(content, str) else content
        if path.exists() and path.read_bytes() == data:
            os.chmod(path, mode)
            return
        if path.is_file():
            backup = path.with_name(path.name + ".previous")
            require(not backup.is_symlink(), "Symlink вместо резервной копии")
            shutil.copyfile(path, backup)
            os.chmod(backup, mode)
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".spire-")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def json(self, native, data):
        self.write(native, json.dumps(data, ensure_ascii=False, indent=2) + "\n")

    def copy(self, source, native, mode=0o755):
        require(Path(source).is_file(), f"Нет файла дистрибутива: {source}")
        # Binaries can be large. Atomic streamed copy; no whole-binary RAM allocation.
        target = self.layout.file(native)
        target.parent.mkdir(parents=True, exist_ok=True)
        app_root = self.layout.file(self.layout.app)
        if self.layout.target == "linux" and target.is_relative_to(app_root):
            directory = target.parent
            while directory.is_relative_to(app_root):
                require(not directory.is_symlink(), f"Каталог приложения является ссылкой: {directory}")
                os.chmod(directory, 0o755)
                directory = directory.parent
        require(not target.is_symlink(), f"Symlink вместо файла: {target}")
        fd, temporary = tempfile.mkstemp(dir=target.parent, prefix=".spire-")
        try:
            with Path(source).open("rb") as source_file, os.fdopen(fd, "wb") as dest:
                shutil.copyfileobj(source_file, dest, 1024 * 1024)
                dest.flush()
                os.fsync(dest.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def verify_bundle(self):
        manifest = self.source / "bundle.json"
        if not manifest.exists():
            require(self.args.bin_dir, "Нет bundle.json. Используйте готовый дистрибутив или укажите --bin-dir для разработки.")
            return
        data = load_json(manifest)
        require(data["platform"] == self.args.platform, "Дистрибутив предназначен для другой ОС")
        machine = platform.machine().lower().replace("amd64", "x86_64").replace("aarch64", "arm64")
        require(data["arch"] == machine or self.args.stage, "Архитектура дистрибутива не соответствует компьютеру")
        require(isinstance(data.get("files"), dict) and data["files"], "Пустой manifest дистрибутива")
        actual = {p.relative_to(self.source).as_posix() for p in self.source.rglob("*") if p.is_file() and p != manifest}
        require(actual == set(data["files"]), "Состав дистрибутива изменён. Распакуйте его в отдельную пустую папку.")
        require(not self.args.bin_dir, "--bin-dir разрешён только для сборки из исходников")
        for relative, expected in data["files"].items():
            require(not PurePosixPath(relative).is_absolute() and ".." not in PurePosixPath(relative).parts and "\\" not in relative,
                    "Небезопасный путь в manifest дистрибутива")
            file = self.source / relative
            require(file.resolve().is_relative_to(self.source) and file.is_file(), f"Нет файла дистрибутива: {relative}")
            with file.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else self.digest(stream)
            require(digest == expected, f"Файл повреждён: {relative}. Получите дистрибутив заново.")

    @staticmethod
    def digest(stream):
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        return digest.hexdigest()

    def preflight(self):
        self.verify_bundle()
        role, layout = self.args.role, self.layout
        for name in (("spire", "spired") if role == "agent" else ("spire-feed",)):
            require(self.names[name].is_file(), f"Нет {name}. Сначала соберите дистрибутив: python3 installer/package.py")
        cfg_dir = layout.file(layout.role_config(role))
        require(not cfg_dir.exists() or self.marker.exists() or not any(cfg_dir.iterdir()),
                "Обнаружены настройки без метки установщика. Автоматическая перезапись запрещена; сохраните их отдельно.")
        if role == "agent":
            data = profile(self.args.profile)
            watches = self.args.watch or ([r"C:\Users"] if layout.target == "windows" else ["/home"])
            for path in watches:
                require(layout.pure(path).is_absolute(), "Каталоги наблюдения должны иметь абсолютные пути")
                require("\n" not in path and "\r" not in path, "Некорректный путь наблюдения")
                if not self.args.stage:
                    require(Path(path).is_dir(), f"Каталог не существует: {path}")
            data.update(watch_paths=watches, response_policy=self.args.policy)
            if self.marker.exists():
                old = load_json(self.marker)
                require(old.get("server_url") == data["server_url"] and old.get("update_public_key") == data["update_public_key"],
                        "Установленный агент принадлежит другому серверу или ключу. Сначала выполните контролируемую миграцию identity.")
            self.plan_data = data
        else:
            address = url(self.args.public_url)
            key = public_key(Path(self.args.public_key).read_text(encoding="utf-8").strip())
            feed = Path(self.args.feed).resolve()
            require(all((feed / name).is_file() for name in FEED_FILES), "Нужен готовый подписанный feed: manifest.json, manifest.sig, database.db, yara.zip")
            ca = Path(self.args.ca_cert).read_text(encoding="utf-8") if self.args.ca_cert else None
            if ca:
                ssl.create_default_context(cadata=ca)
            tls = address.startswith("https:")
            if tls:
                require(self.args.tls_cert and self.args.tls_key, "Для HTTPS укажите --tls-cert и --tls-key")
                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(self.args.tls_cert, self.args.tls_key)
            self.plan_data = {"server_url": address, "update_url": address, "update_public_key": key, "ca_pem": ca,
                              "port": urllib.parse.urlsplit(address).port or (443 if tls else 80), "tls": tls, "feed": str(feed)}
            if self.marker.exists():
                old = load_json(self.marker)
                require(old.get("server_url") == address and old.get("update_public_key") == key, "Изменение адреса/ключа сервера требует отдельной миграции клиентов")
            self.uv = str(self.names["uv"]) if self.names["uv"].is_file() else shutil.which("uv")
            require(self.uv, "Для установки сервера нужен uv. Он включается в полный дистрибутив; при сборке из исходников установите uv.")
            require((self.source / "server/uv.lock").is_file(), "В дистрибутиве нет серверной части")
        if self.marker.exists():
            require(load_json(self.marker).get("schema_version") == MARKER_VERSION, "Неподдерживаемая версия установленного мастера")
        if not self.args.stage and not self.args.dry_run:
            host = "windows" if os.name == "nt" else "linux"
            require(host == layout.target and (host != "linux" or sys.platform.startswith("linux")), "Эта ОС не поддерживается данным дистрибутивом")
            if host == "windows":
                require(ctypes.windll.shell32.IsUserAnAdmin(), "Запустите установщик от имени администратора")
            else:
                require(os.geteuid() == 0, "Запустите установку через sudo")
                require(Path("/run/systemd/system").is_dir(), "Нужна Linux-система с запущенным systemd")
            self.check_managed_targets()
        return self.plan_data

    def task_name(self):
        return "SpireAgent" if self.args.role == "agent" else "SpireServer"

    def check_managed_targets(self):
        if self.previously_managed:
            return
        if self.layout.target == "linux":
            for base in ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
                require(not Path(base, f"spire-{self.args.role}.service").exists(), "Служба с этим именем уже существует вне установщика")
            if self.args.role == "agent":
                require(not Path("/usr/local/bin/spire").exists(), "Существующий /usr/local/bin/spire не принадлежит установщику")
        else:
            self.runner(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                         "if (Get-ScheduledTask -TaskName " + ps_quote(self.task_name()) + " -ErrorAction SilentlyContinue) { throw 'Task already exists outside Spire Setup' }"])

    @contextmanager
    def install_lock(self):
        # OS locks are released on process exit, so interrupted installs can be retried.
        path = self.layout.file(self.layout.join(self.layout.config, "setup.lock"))
        with path.open("a+b") as lock:
            lock.seek(0)
            lock.write(b"0")
            lock.flush()
            lock.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise SetupError("Другой экземпляр Spire Setup уже выполняется") from exc
            try:
                yield
            finally:
                if os.name == "nt":
                    lock.seek(0)
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)

    def stop_existing(self):
        if self.args.stage or not self.previously_managed:
            return
        if self.layout.target == "windows":
            self.runner(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                         "$ErrorActionPreference='Stop'; $t=Get-ScheduledTask -TaskName " + ps_quote(self.task_name()) +
                         " -ErrorAction SilentlyContinue; if ($t) { $t | Stop-ScheduledTask; Start-Sleep -Seconds 2 }"])
        else:
            unit = f"spire-{self.args.role}.service"
            if Path("/etc/systemd/system", unit).exists():
                self.runner(["systemctl", "stop", unit])

    def show_plan(self):
        data, layout = self.plan_data, self.layout
        print(f"\nSpire Setup — {'агент' if self.args.role == 'agent' else 'сервер'} / {layout.target}")
        print(f"  Адрес:       {data['server_url']}\n  Приложение:  {layout.app}\n  Настройки:   {layout.role_config(self.args.role)}\n  Данные:      {layout.role_state(self.args.role)}")
        if self.args.role == "agent":
            print("  Наблюдение:  " + ", ".join(data["watch_paths"]))
            print("  Действие:    " + ("только обнаружение" if self.args.policy == "observe" else "карантин"))
        else:
            print("  Сервер:      установка Python 3.12 и зависимостей из lock-файла через uv")
        print("  Автозапуск:  " + ("systemd" if layout.target == "linux" else "задача Spire в Планировщике, SYSTEM"))
        print("  Секреты:     сохраняются в закрытых файлах; в журнал не выводятся")
        if self.args.stage:
            print(f"  STAGING:     {self.args.stage}; службы и сеть не используются")

    def private_directory(self, native):
        path = self.layout.file(native)
        require(not path.is_symlink() and not (hasattr(path, "is_junction") and path.is_junction()), f"Каталог является ссылкой: {path}")
        path.mkdir(parents=True, exist_ok=True)
        if self.layout.target == "windows" and not self.args.stage:
            self.runner(["icacls", str(path), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])
        else:
            os.chmod(path, 0o700)

    def install(self):
        self.preflight()
        self.show_plan()
        if self.args.dry_run:
            print("\nПроверка завершена. Изменения не внесены.")
            return
        if not self.args.yes:
            require(input("\nУстановить с этими настройками? [да/нет]: ").strip().lower() in ("да", "yes", "y"), "Установка отменена")
        if not self.args.stage:
            print("[1/5] Проверка подписи и доступности сервера...")
            if self.args.role == "agent":
                result = request_json(self.plan_data["server_url"] + "/health", self.plan_data.get("ca_pem"))
                require(result.get("service") == "spire-edr", "По указанному адресу работает другой сервис")
            else:
                self.runner([self.names["spire-feed"], "verify", "--directory", self.args.feed, "--public-key", self.args.public_key])
        for native in (self.layout.config, self.layout.state):
            self.private_directory(native)
            if self.layout.target == "linux":
                os.chmod(self.layout.file(native), 0o711)
        app_path = self.layout.file(self.layout.app)
        require(not app_path.is_symlink(), "Каталог приложения является ссылкой")
        app_path.mkdir(parents=True, exist_ok=True)
        if self.layout.target == "linux":
            os.chmod(app_path, 0o755)
        if self.layout.target == "windows":
            self.private_directory(self.layout.app)
        with self.install_lock():
            # A second installer may have completed while the first plan was displayed.
            self.previously_managed = self.marker.exists()
            self.preflight()
            self.apply_install()

    def apply_install(self):
        self.stop_existing()
        for native in (self.layout.role_config(self.args.role), self.layout.role_state(self.args.role)):
            self.private_directory(native)
        marker = {"schema_version": MARKER_VERSION, "role": self.args.role, "server_url": self.plan_data["server_url"],
                  "update_public_key": self.plan_data["update_public_key"], "status": "installing"}
        self.json(str(self.layout.pure(self.layout.role_config(self.args.role)) / "installation.json"), marker)
        print("[2/5] Подготовка файлов и настроек...")
        if self.args.role == "agent":
            self.install_agent()
        else:
            self.install_server()
        marker["status"] = "staged" if self.args.stage else "ready"
        self.json(self.layout.join(self.layout.role_config(self.args.role), "installation.json"), marker)
        print("\nГотово." if not self.args.stage else "\nФайлы staging подготовлены. Системные настройки не изменены.")

    def install_agent(self):
        l, data = self.layout, self.plan_data
        cfg, state = l.role_config("agent"), l.role_state("agent")
        for name in ("spire", "spired"):
            self.copy(self.names[name], l.binary(name))
        core = {"spire_dir": state, "update_url": data["update_url"], "update_public_key": data["update_public_key"]}
        self.json(l.join(cfg, "config.json"), core)
        # JSON strings/arrays are valid TOML values; escaping prevents config injection.
        settings = {"watch_paths": data["watch_paths"], "excluded_paths": [state, cfg, l.app],
                    "excluded_extensions": [], "excluded_files": [], "telemetry": True,
                    "telemetry_url": data["server_url"], "enrollment_token": data["enrollment_token"], "response_policy": self.args.policy}
        self.write(l.join(cfg, "agent.toml"), "\n".join(f"{key} = {json.dumps(value, ensure_ascii=False)}" for key, value in settings.items()) + "\n")
        env = {"SPIRE_CONFIG_PATH": l.join(cfg, "config.json"), "SPIRE_AGENT_CONFIG": l.join(cfg, "agent.toml"), "SPIRE_STATE_DIR": state, "SPIRE_READY_FILE": l.join(state, "agent.ready")}
        if data.get("ca_pem"):
            self.write(l.join(cfg, "ca.pem"), data["ca_pem"])
            env["SPIRE_CA_CERT"] = l.join(cfg, "ca.pem")
        self.json(l.join(cfg, "runtime-env.json"), env)
        if not self.args.stage:
            print("[3/5] Установка и проверка подписанной базы...")
            child_env = {**os.environ, **env}
            try:
                self.runner([l.binary("spire"), "check-feed"], env=child_env)
            except SetupError:
                # An interrupted download can leave feed-state.db without an active feed.
                self.runner([l.binary("spire"), "update-db"], env=child_env)
                self.runner([l.binary("spire"), "check-feed"], env=child_env)
            identity = l.file(l.join(state, "agent_identity.json"))
            if not identity.exists():
                response = request_json(data["server_url"] + "/v1/agents/enroll", data.get("ca_pem"),
                    {"hostname": socket.gethostname(), "os_name": l.target, "arch": platform.machine(), "agent_version": "0.2.0"},
                    {"X-Enrollment-Token": data["enrollment_token"]})
                require(all(isinstance(response.get(k), str) and 1 <= len(response[k]) <= 512 for k in ("agent_id", "agent_token")), "Сервер вернул некорректную identity")
                self.json(l.join(state, "agent_identity.json"), {"agent_id": response["agent_id"], "agent_token": response["agent_token"]})
            else:
                identity_data = load_json(identity)
                request_json(data["server_url"] + "/v1/runtime/policy", data.get("ca_pem"), headers={"Authorization": "Bearer " + identity_data["agent_token"]})
        self.register("agent", l.binary("spired"), ["-v"], env, cfg, state)
        if l.target == "windows":
            cli_script = "param([Parameter(ValueFromRemainingArguments=$true)][string[]]$CliArgs)\n"
            cli_script += "$ErrorActionPreference='Stop'\n$settings=Get-Content -Encoding UTF8 -Raw -LiteralPath " + ps_quote(l.join(cfg, "runtime-env.json")) + " | ConvertFrom-Json\n"
            cli_script += "$settings.PSObject.Properties | ForEach-Object { [Environment]::SetEnvironmentVariable($_.Name,[string]$_.Value,'Process') }\n"
            cli_script += "& " + ps_quote(l.binary("spire")) + " @CliArgs\nexit $LASTEXITCODE\n"
            self.write(l.join(cfg, "spire.ps1"), cli_script)
        if l.target == "linux":
            wrapper = "#!/bin/sh\n" + "\n".join(f"export {key}={shlex.quote(value)}" for key, value in env.items())
            self.write("/usr/local/bin/spire", wrapper + "\nexec " + shlex.quote(l.binary("spire")) + ' "$@"\n', 0o755)
        print("[5/5] Агент настроен. Диагностика: setup doctor --role agent")

    def install_server(self):
        l, data = self.layout, self.plan_data
        cfg, state = l.role_config("server"), l.role_state("server")
        source = self.source / "server"
        app = l.join(l.app, "server")
        for item in server_files(source):
            self.copy(item, l.join(app, *item.relative_to(source).parts), 0o644)
        secrets_file = l.file(l.join(cfg, "secrets.json"))
        credentials = load_json(secrets_file) if secrets_file.exists() else {"admin_token": secrets.token_urlsafe(32), "enrollment_token": secrets.token_urlsafe(32)}
        require(credentials["admin_token"] != credentials["enrollment_token"] and all(isinstance(v, str) and len(v) >= 32 and v.isascii() and not any(c.isspace() for c in v) for v in credentials.values()), "Некорректные сохранённые секреты")
        self.json(l.join(cfg, "secrets.json"), credentials)
        self.json(l.join(cfg, "admin-credentials.json"), {"console_url": data["server_url"] + "/console", "admin_token": credentials["admin_token"]})
        connection = {key: data[key] for key in ("server_url", "update_url", "update_public_key", "ca_pem")}
        connection.update(schema_version=1, enrollment_token=credentials["enrollment_token"])
        self.json(l.join(cfg, "enrollment.json"), connection)
        updates = l.join(state, "updates")
        for name in FEED_FILES:
            self.copy(Path(data["feed"]) / name, l.join(updates, name), 0o644)
        if not self.args.stage:
            self.runner([self.names["spire-feed"], "verify", "--directory", updates, "--public-key", self.args.public_key])
        env = {"SPIRE_ADMIN_TOKEN": credentials["admin_token"], "SPIRE_ENROLLMENT_TOKEN": credentials["enrollment_token"],
               "SPIRE_DATABASE_URL": "sqlite:///" + l.join(state, "spire.db").replace("\\", "/"), "SPIRE_UPDATES_DIR": updates}
        self.json(l.join(cfg, "runtime-env.json"), env)
        self.write(l.join(cfg, "server.env"), "\n".join(key + "=" + json.dumps(value) for key, value in env.items()) + "\n")
        arguments = ["-m", "uvicorn", "spire_server.main:app", "--app-dir", l.join(app, "src"), "--host",
                     ("::" if data["tls"] else "::1") if ":" in urllib.parse.urlsplit(data["server_url"]).hostname else ("0.0.0.0" if data["tls"] else "127.0.0.1"), "--port", str(data["port"])]
        if data["tls"]:
            self.copy(self.args.tls_cert, l.join(cfg, "tls-cert.pem"), 0o644)
            self.copy(self.args.tls_key, l.join(cfg, "tls-key.pem"), 0o600)
            arguments += ["--ssl-certfile", l.join(cfg, "tls-cert.pem"), "--ssl-keyfile", l.join(cfg, "tls-key.pem")]
        if not self.args.stage:
            print("[3/5] Установка Python и зависимостей сервера...")
            self.runner([self.uv, "sync", "--locked", "--no-dev", "--no-editable", "--project", app, "--python", "3.12"], timeout=1200,
                        env={**os.environ, "UV_PYTHON_INSTALL_DIR": l.join(l.app, "python"), "UV_CACHE_DIR": l.join(l.app, "uv-cache"), "UV_PYTHON_PREFERENCE": "only-managed"},
                        **({"umask": 0o022} if l.target == "linux" else {}))
        python = l.join(app, ".venv", "Scripts" if l.target == "windows" else "bin", "python.exe" if l.target == "windows" else "python")
        if l.target == "linux" and not self.args.stage:
            self.prepare_server_user(cfg, state)
        self.register("server", python, arguments, env, cfg, state)
        if not self.args.stage:
            print("[5/5] Проверка HTTPS/API...")
            last = None
            for _ in range(15):
                try:
                    response = request_json(data["server_url"] + "/health", data.get("ca_pem"))
                    require(response.get("service") == "spire-edr", "Ответ другого сервиса")
                    last = None
                    break
                except (SetupError, OSError) as error:
                    last = error
                    time.sleep(1)
            if last:
                raise SetupError(f"Служба установлена, но API недоступен: {last}. Исправьте DNS/TLS/firewall и повторите мастер; секреты сохранятся.")
        print(f"Консоль: {data['server_url']}/console\nДанные администратора: {l.join(cfg, 'admin-credentials.json')}\nПрофиль для клиентов: {l.join(cfg, 'enrollment.json')}")

    def prepare_server_user(self, cfg, state):
        import pwd
        try:
            account = pwd.getpwnam("spire-server")
        except KeyError:
            shell = shutil.which("nologin") or "/usr/sbin/nologin"
            self.runner(["useradd", "--system", "--user-group", "--home-dir", state, "--no-create-home", "--shell", shell, "spire-server"])
            account = pwd.getpwnam("spire-server")
        require(account.pw_uid != 0, "spire-server не должен иметь UID 0")
        os.chown(cfg, 0, account.pw_gid)
        os.chmod(cfg, 0o750)
        # Credentials exported for the administrator stay root-only.
        for name in ("tls-key.pem", "tls-cert.pem"):
            path = Path(cfg, name)
            if path.exists():
                os.chown(path, 0, account.pw_gid)
                os.chmod(path, 0o640)
        for path in [Path(state), *Path(state).rglob("*")]:
            require(not path.is_symlink(), f"Недопустимая ссылка в данных сервера: {path}")
            os.chown(path, account.pw_uid, account.pw_gid)

    def register(self, role, executable, arguments, env, cfg, state):
        l = self.layout
        ready = l.file(l.join(state, "agent.ready"))
        if role == "agent" and not self.args.stage:
            ready.unlink(missing_ok=True)
        if l.target == "windows":
            script = l.join(cfg, "run.ps1")
            self.copy(self.source / "installer/windows-job.ps1", l.join(cfg, "windows-job.ps1"), 0o600)
            self.write(script, "$ErrorActionPreference='Stop'\n. " + ps_quote(l.join(cfg, "windows-job.ps1")) + "\n" + run_ps_script(executable, arguments, l.join(cfg, "runtime-env.json"), state, l.join(state, "service.log")))
            xml = l.join(cfg, "task.xml")
            self.write(xml, task_xml(script, state))
            if not self.args.stage:
                print("[4/5] Настройка автозапуска Windows...")
                task = "SpireAgent" if role == "agent" else "SpireServer"
                self.runner(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    "$ErrorActionPreference='Stop'; Register-ScheduledTask -TaskName " + ps_quote(task) + " -Xml ([IO.File]::ReadAllText(" + ps_quote(xml) + ")) -Force | Out-Null; Start-ScheduledTask -TaskName " + ps_quote(task)])
        else:
            lines = ["[Unit]", f"Description=Spire {role}", "After=network-online.target", "Wants=network-online.target", "", "[Service]",
                     "Type=simple", "User=" + ("spire-server" if role == "server" else "root"), f"WorkingDirectory={state}", "UMask=0077", "Restart=always", "RestartSec=10", "MemoryMax=768M", "TasksMax=128", "LimitNOFILE=4096"]
            if role == "server":
                lines += [f"EnvironmentFile={cfg}/server.env", "NoNewPrivileges=true", "PrivateTmp=true",
                          "ProtectSystem=strict", "ProtectHome=true", f"ReadWritePaths={state}",
                          "CapabilityBoundingSet=CAP_NET_BIND_SERVICE", "AmbientCapabilities=CAP_NET_BIND_SERVICE"]
            else:
                lines += ['Environment="' + key + '=' + value + '"' for key, value in env.items()]
                lines += ["CPUQuota=100%"]
            lines += ["ExecStart=" + " ".join('"' + str(arg).replace('"', '\\"') + '"' for arg in [executable, *arguments]), "", "[Install]", "WantedBy=multi-user.target", ""]
            unit = f"spire-{role}.service"
            self.write("/etc/systemd/system/" + unit, "\n".join(lines), 0o644)
            if not self.args.stage:
                print("[4/5] Настройка systemd...")
                self.runner(["systemctl", "daemon-reload"])
                self.runner(["systemctl", "enable", unit])
                self.runner(["systemctl", "restart", unit])
                self.runner(["systemctl", "is-active", "--quiet", unit])

        if role == "agent" and not self.args.stage:
            for _ in range(300):
                if ready.is_file():
                    break
                time.sleep(.1)
            require(ready.is_file(), "Агент не подтвердил запуск наблюдения. Проверьте журнал службы/задачи и каталоги наблюдения.")


def doctor(args):
    l = Layout(args.platform, args.stage)
    cfg = l.role_config(args.role)
    marker = l.file(l.join(cfg, "installation.json"))
    require(marker.exists(), "Установка этой роли не найдена")
    data = load_json(marker)
    print(f"Spire {args.role}: {data['status']}\nАдрес: {data['server_url']}\nДанные: {l.role_state(args.role)}")
    if args.stage:
        return
    if args.platform == "linux":
        Installer.run(["systemctl", "is-active", f"spire-{args.role}.service"])
        print(f"Журнал: journalctl -u spire-{args.role}.service -n 100")
    else:
        task = "SpireAgent" if args.role == "agent" else "SpireServer"
        result = Installer.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", f"(Get-ScheduledTask -TaskName '{task}').State"])
        require(result.stdout.strip() == "Running", "Задача Windows не запущена")
        print("Журнал: " + l.join(l.role_state(args.role), "service.log"))
    if args.role == "agent":
        env = load_json(l.file(l.join(cfg, "runtime-env.json")))
        Installer.run([l.binary("spire"), "check-feed"], env={**os.environ, **env})
        identity = load_json(l.file(l.join(l.role_state("agent"), "agent_identity.json")))
        ca = Path(env["SPIRE_CA_CERT"]).read_text(encoding="utf-8") if env.get("SPIRE_CA_CERT") else None
        request_json(data["server_url"] + "/v1/runtime/policy", ca, headers={"Authorization": "Bearer " + identity["agent_token"]})
    else:
        connection = profile(l.file(l.join(cfg, "enrollment.json")))
        request_json(data["server_url"] + "/health", connection.get("ca_pem"))
    print("Проверки завершены успешно.")


def arguments(argv=None):
    root = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Spire Setup — мастер установки сервера и агента")
    parser.add_argument("action", nargs="?", choices=("agent", "server", "doctor"))
    parser.add_argument("--role", choices=("agent", "server"), default="agent", help="роль для doctor")
    parser.add_argument("--bundle", default=str(root))
    parser.add_argument("--bin-dir", help="каталог бинарников при работе из исходников")
    parser.add_argument("--platform", choices=("linux", "windows"), default="windows" if os.name == "nt" else "linux")
    parser.add_argument("--profile", help="файл подключения, выданный администратором")
    parser.add_argument("--watch", action="append", help="наблюдаемый каталог; можно повторять")
    parser.add_argument("--policy", choices=("observe", "quarantine"), default="observe")
    parser.add_argument("--public-url")
    parser.add_argument("--public-key", help="файл доверенного публичного ключа feed")
    parser.add_argument("--feed", help="готовый подписанный пакет")
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--ca-cert", help="CA для частной PKI; публичный PEM попадёт в профиль подключения")
    parser.add_argument("--yes", action="store_true", help="применить параметры без вопросов")
    parser.add_argument("--dry-run", action="store_true", help="проверить и показать план без изменений")
    parser.add_argument("--stage", help="подготовить файлы образа без запуска команд и сети")
    args = parser.parse_args(argv)
    if not args.action:
        require(not args.yes and sys.stdin.isatty(), "Укажите agent, server или doctor")
        print("Spire Setup\n  1. Установить агент\n  2. Установить сервер\n  3. Проверить установку")
        args.action = {"1":"agent", "2":"server", "3":"doctor"}.get(input("Выберите [1]: ").strip() or "1")
        require(args.action, "Неизвестный пункт")
    if args.action == "doctor":
        if not argv and len(sys.argv) == 1:
            args.role = "server" if input("Проверить сервер? [нет, агент]: ").strip().lower() in ("да", "yes", "y") else "agent"
        return args
    args.role = args.action
    def ask(name, label, default=None):
        if getattr(args, name):
            return
        require(not args.yes and sys.stdin.isatty(), f"Нужен параметр --{name.replace('_','-')}")
        value = input(label + (f" [{default}]" if default else "") + ": ").strip() or default
        require(value, "Значение не задано")
        setattr(args, name, value)
    if args.role == "agent":
        ask("profile", "Путь к файлу подключения enrollment.json")
        if not args.watch and not args.yes and sys.stdin.isatty():
            value = input("Каталог для наблюдения [" + (r"C:\Users" if args.platform=="windows" else "/home") + "]: ").strip()
            if value:
                args.watch = [value]
            if input("Включить автоматический карантин? [нет]: ").strip().lower() in ("да", "yes", "y"):
                args.policy = "quarantine"
    else:
        ask("public_url", "Адрес сервера для клиентов, например https://edr.example.org")
        ask("public_key", "Путь к feed-public.hex")
        ask("feed", "Каталог подписанного пакета")
        if args.public_url.startswith("https:"):
            ask("tls_cert", "TLS-сертификат PEM (с цепочкой)")
            ask("tls_key", "Закрытый TLS-ключ PEM")
            if not args.ca_cert and not args.yes and sys.stdin.isatty():
                args.ca_cert = input("CA частной PKI, если используется (пусто для публичного TLS): ").strip() or None
    return args


def main(argv=None):
    try:
        args = arguments(argv)
        if args.action == "doctor":
            doctor(args)
        else:
            Installer(args).install()
        return 0
    except (SetupError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print(f"\nОшибка: {exc}\nУстраните причину и повторите мастер. Данные и identity сохраняются. После ошибки обновления служба может оставаться остановленной; повторите установку и выполните doctor.", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nУстановка прервана.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    result = main()
    if getattr(sys, "frozen", False) and len(sys.argv) == 1:
        try:
            input("Нажмите Enter, чтобы закрыть мастер...")
        except (EOFError, KeyboardInterrupt):
            pass
    sys.exit(result)
