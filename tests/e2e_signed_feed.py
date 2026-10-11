"""Run after cargo build: exercise release signing, HTTP updates and CLI scans."""
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import zipfile

REPO = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("SPIRE_TEST_BIN_DIR", REPO / "target/debug")).resolve()
SUFFIX = ".exe" if os.name == "nt" else ""
CLI = BIN / ("spire" + SUFFIX)
SIGNER = BIN / ("spire-feed" + SUFFIX)


def main():
    with tempfile.TemporaryDirectory(prefix="spire-feed-e2e-") as temporary:
        root = Path(temporary)
        def run(binary, *args, success=True):
            result = subprocess.run([str(binary), *map(str, args)], cwd=root,
                                    capture_output=True, text=True, timeout=30)
            assert (result.returncode == 0) == success, result.stdout + result.stderr
            return result.stdout + result.stderr

        sample = root / "sample"
        sample.write_bytes(b"harmless signed feed fixture")
        database = root / "input.db"
        with sqlite3.connect(database) as conn:
            conn.execute("CREATE TABLE default_db(md5hash TEXT, sha256hash TEXT, name TEXT)")
            conn.execute("INSERT INTO default_db VALUES(?,?,?)", (
                hashlib.md5(sample.read_bytes()).hexdigest(),
                hashlib.sha256(sample.read_bytes()).hexdigest(), "Test.Fixture"))
        with zipfile.ZipFile(root / "rules.zip", "w") as archive:
            archive.writestr("test.yar", 'rule fixture { strings: $a="harmless signed feed fixture" condition: $a }')
        run(SIGNER, "keygen", "--private-key", root / "test-private.pk8", "--public-key", root / "test-public.hex")
        served = root / "served"
        served.mkdir()
        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(QuietHandler, directory=str(served)))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = {"spire_dir": str(root / "state"), "update_public_key": (root / "test-public.hex").read_text(),
                      "update_url": f"http://127.0.0.1:{server.server_port}"}
            (root / "config.json").write_text(json.dumps(config))
            def release(version):
                out = root / f"release-{version}"
                run(SIGNER, "sign", "--private-key", root / "test-private.pk8", "--database", database,
                    "--yara", root / "rules.zip", "--version", version,
                    "--expires-at", int(time.time()) + 3600, "--out", out)
                for file in out.iterdir():
                    shutil.copyfile(file, served / file.name)
                return out
            def active_version():
                with sqlite3.connect(root / "state/feed-state.db") as conn:
                    return conn.execute("SELECT version FROM active_feed WHERE id=1").fetchone()[0]
            release(1)
            run(CLI, "update-db")
            assert active_version() == 1
            assert "observe skipped" in run(CLI, "scan", "fast", "--path", sample)
            assert "observe skipped" in run(CLI, "scan", "yara-scan", "--path", sample)
            assert sample.exists()
            assert "rollback/replay" in run(CLI, "update-db", success=False)
            good = release(2)
            (served / "manifest.sig").write_bytes(b"x" * 64)
            assert "signature verification failed" in run(CLI, "update-db", success=False)
            assert active_version() == 1
            shutil.copyfile(good / "manifest.sig", served / "manifest.sig")
            with (served / "database.db").open("r+b") as output:
                output.seek(100)
                output.write(b"modified")
            assert "digest mismatch" in run(CLI, "update-db", success=False)
            assert active_version() == 1
            shutil.copyfile(good / "database.db", served / "database.db")
            run(CLI, "update-db")
            assert active_version() == 2
            assert "observe skipped" in run(CLI, "scan", "fast", "--path", sample)
            print("E2E passed: sign -> HTTP -> verify -> activate -> hash/YARA detection; tamper and replay rejected")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    main()
