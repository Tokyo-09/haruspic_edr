"""Real onboarding with signed feed + server + watcher in a temporary directory.

Uses the installer file/enrollment logic, without registering machine services.
Run with server/.venv's Python after cargo build (SPIRE_TEST_BIN_DIR optional).
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import zipfile
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from installer import setup

BIN = Path(os.environ.get("SPIRE_TEST_BIN_DIR", REPO / "target/debug")).resolve()
SUFFIX = ".exe" if os.name == "nt" else ""


class IsolatedLayout(setup.Layout):
    def __init__(self, root):
        super().__init__("windows" if os.name == "nt" else "linux")
        self.root = root
        self.app, self.config, self.state = (str(root / name) for name in ("app", "config", "state"))

    def file(self, native):
        if native == "/usr/local/bin/spire":
            return self.root / "cli-wrapper"
        path = Path(native)
        assert path.is_relative_to(self.root), f"test attempted system write: {path}"
        return path


def main():
    with tempfile.TemporaryDirectory(prefix="spire-onboarding-") as temporary:
        root = Path(temporary)
        feed = root / "feed"
        sample = b"harmless onboarding detection fixture"
        database = root / "input.db"
        with sqlite3.connect(database) as conn:
            conn.execute("CREATE TABLE default_db(md5hash TEXT, sha256hash TEXT, name TEXT)")
            conn.execute("INSERT INTO default_db VALUES(?,?,?)", (
                hashlib.md5(sample).hexdigest(), hashlib.sha256(sample).hexdigest(), "Test.Onboarding"))
        with zipfile.ZipFile(root / "rules.zip", "w") as archive:
            archive.writestr("test.yar", 'rule fixture { strings: $a="harmless onboarding detection fixture" condition: $a }')
        run = setup.Installer.run
        signer = BIN / ("spire-feed" + SUFFIX)
        run([signer, "keygen", "--private-key", root / "private.pk8", "--public-key", root / "public.hex"])
        run([signer, "sign", "--private-key", root / "private.pk8", "--database", database, "--yara", root / "rules.zip",
             "--version", "1", "--expires-at", str(int(time.time()) + 3600), "--out", feed])
        run([signer, "verify", "--directory", feed, "--public-key", root / "public.hex"])
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        address = f"http://127.0.0.1:{port}"
        admin, enrollment = "test-admin-" + "a" * 40, "test-enroll-" + "b" * 40
        env = {**os.environ, "PYTHONPATH": str(REPO / "server/src"), "SPIRE_ADMIN_TOKEN": admin,
               "SPIRE_ENROLLMENT_TOKEN": enrollment, "SPIRE_DATABASE_URL": "sqlite:///" + str(root / "server.db").replace("\\", "/"),
               "SPIRE_UPDATES_DIR": str(feed)}
        with (root / "server.log").open("w") as server_log, (root / "agent.log").open("w") as agent_log:
            server = subprocess.Popen([sys.executable, "-m", "uvicorn", "spire_server.main:app", "--host", "127.0.0.1", "--port", str(port)],
                                      cwd=root, env=env, stdout=server_log, stderr=server_log)
            agent = None
            try:
                for _ in range(100):
                    try:
                        setup.request_json(address + "/health")
                        break
                    except setup.SetupError:
                        assert server.poll() is None, (root / "server.log").read_text()
                        time.sleep(.1)
                else:
                    raise AssertionError("server startup timeout")
                profile_path = root / "enrollment.json"
                profile_path.write_text(json.dumps({"schema_version":1, "server_url":address, "update_url":address,
                    "update_public_key":(root / "public.hex").read_text(), "enrollment_token":enrollment}))
                watch = root / "watch"
                watch.mkdir()
                args = setup.arguments(["agent", "--yes", "--bundle", str(REPO), "--bin-dir", str(BIN),
                    "--profile", str(profile_path), "--watch", str(watch), "--stage", str(root / "stage")])
                installer = setup.Installer(args)
                installer.preflight()
                installer.layout = IsolatedLayout(root / "installation")
                installer.args.stage = None
                l = installer.layout
                cfg, state = l.role_config("agent"), l.role_state("agent")
                Path(cfg).mkdir(parents=True)
                Path(state).mkdir(parents=True)
                # Simulate interruption after creating the state DB but before activation.
                with sqlite3.connect(Path(state) / "feed-state.db"):
                    pass
                with patch.object(installer, "register"):
                    installer.install_agent()
                    identity_path = Path(state) / "agent_identity.json"
                    identity = identity_path.read_bytes()
                    # Copy same binaries/configs again; existing identity and active feed must survive.
                    installer.install_agent()
                    assert identity_path.read_bytes() == identity
                identities = setup.request_json(address + "/v1/agents", headers={"Authorization":"Bearer " + admin})
                assert len(identities) == 1, identities
                runtime = setup.load_json(Path(cfg) / "runtime-env.json")
                agent = subprocess.Popen([l.binary("spired"), "-v"], cwd=state, env={**os.environ, **runtime}, stdout=agent_log, stderr=agent_log)
                for _ in range(200):
                    assert agent.poll() is None, (root / "agent.log").read_text()
                    # Repeat after watcher starts; no exact startup sleep assumptions.
                    (watch / "fixture.bin").write_bytes(sample)
                    events = setup.request_json(address + "/v1/events", headers={"Authorization":"Bearer " + admin})
                    if any(event["event_type"] == "detection" for event in events):
                        break
                    time.sleep(.1)
                else:
                    raise AssertionError("detection telemetry missing: " + (root / "agent.log").read_text())
                assert (Path(state) / "agent.ready").read_text().strip() == str(agent.pid), "watcher readiness missing"
                assert (watch / "fixture.bin").exists(), "observe must preserve file"
                print("Installer E2E passed: interrupted bootstrap recovered, identity preserved, real watcher detection reached server")
            finally:
                for proc in (agent, server):
                    if proc is not None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()


if __name__ == "__main__":
    main()
