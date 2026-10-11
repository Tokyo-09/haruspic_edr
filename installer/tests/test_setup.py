import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from installer import setup

REPO = Path(__file__).resolve().parents[2]


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="spire-setup-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("spire", "spired", "spire-feed", "uv"):
            for suffix in ("", ".exe"):
                (self.bin / (name + suffix)).write_bytes(b"fixture, never executed")
        self.connection = {"schema_version": 1, "server_url": "https://edr.example.org",
                           "update_url": "https://edr.example.org", "update_public_key": "ab" * 32,
                           "enrollment_token": "e" * 43}
        self.profile = self.root / "enrollment.json"
        self.save_profile()
        self.feed = self.root / "feed"
        self.feed.mkdir()
        for name in setup.FEED_FILES:
            (self.feed / name).write_bytes(b"fixture; stage does not verify signatures")
        self.key = self.root / "public.hex"
        self.key.write_text("ab" * 32)

    def save_profile(self):
        self.profile.write_text(json.dumps(self.connection))

    def instance(self, target="linux", role="agent", extra=()):
        args = [role, "--yes", "--bundle", str(REPO), "--bin-dir", str(self.bin), "--platform", target,
                "--stage", str(self.root / (target + "-stage"))]
        args += ["--profile", str(self.profile)] if role == "agent" else [
            "--public-url", "http://127.0.0.1:8080", "--public-key", str(self.key), "--feed", str(self.feed)]
        return setup.Installer(setup.arguments(args + list(extra)))

    def install(self, instance):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.object(instance, "runner", side_effect=AssertionError("stage ran command")), patch.object(setup, "request_json", side_effect=AssertionError("stage used network")):
            instance.install()
        self.assertNotIn(self.connection["enrollment_token"], output.getvalue())
        return output.getvalue()

    def test_both_platforms_produce_parseable_configs_and_preserve_identity(self):
        for target in ("linux", "windows"):
            with self.subTest(target=target):
                instance = self.instance(target)
                self.install(instance)
                l = instance.layout
                cfg = l.role_config("agent")
                settings = tomllib.loads(l.file(l.join(cfg, "agent.toml")).read_text(encoding="utf-8"))
                self.assertEqual(settings["response_policy"], "observe")
                self.assertTrue(l.pure(settings["watch_paths"][0]).is_absolute())
                identity = l.file(l.join(l.role_state("agent"), "agent_identity.json"))
                identity.write_text('{"agent_id":"keep","agent_token":"keep-token"}')
                self.install(self.instance(target))
                self.assertEqual(json.loads(identity.read_text())["agent_id"], "keep")
                if target == "windows":
                    root = ET.fromstring(l.file(l.join(cfg, "task.xml")).read_text())
                    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
                    self.assertEqual(root.find("t:Settings/t:ExecutionTimeLimit", ns).text, "PT0S")
                    self.assertEqual(root.find("t:Principals/t:Principal/t:UserId", ns).text, "S-1-5-18")
                    self.assertTrue(l.file(l.join(cfg, "run.ps1")).read_bytes().startswith(b"\xef\xbb\xbf"))
                else:
                    unit = l.file("/etc/systemd/system/spire-agent.service").read_text()
                    self.assertIn("CPUQuota=100%", unit)
                    self.assertIn("SPIRE_AGENT_CONFIG=", unit)

    def test_server_secrets_are_distinct_preserved_and_not_in_client_profile(self):
        for target in ("linux", "windows"):
            instance = self.instance(target, "server")
            self.install(instance)
            l = instance.layout
            cfg = l.role_config("server")
            secrets_path = l.file(l.join(cfg, "secrets.json"))
            credentials = setup.load_json(secrets_path)
            self.assertNotEqual(credentials["admin_token"], credentials["enrollment_token"])
            connection = setup.profile(l.file(l.join(cfg, "enrollment.json")))
            self.assertNotIn("admin_token", connection)
            self.assertNotIn(credentials["admin_token"], json.dumps(connection))
            db = l.file(l.join(l.role_state("server"), "spire.db"))
            db.write_bytes(b"preserve existing database")
            self.install(self.instance(target, "server"))
            self.assertEqual(setup.load_json(secrets_path), credentials)
            self.assertEqual(db.read_bytes(), b"preserve existing database")
            if os.name != "nt":
                self.assertEqual(secrets_path.stat().st_mode & 0o777, 0o600)

    def test_dry_run_has_no_writes(self):
        instance = self.instance(extra=("--dry-run",))
        self.install(instance)
        self.assertFalse(instance.layout.stage.exists())

    def test_refuses_unmanaged_configuration(self):
        instance = self.instance()
        cfg = instance.layout.file(instance.layout.role_config("agent"))
        cfg.mkdir(parents=True)
        (cfg / "config.json").write_text("{}")
        with self.assertRaises(setup.SetupError):
            instance.preflight()
        self.assertEqual((cfg / "config.json").read_text(), "{}")

    def test_refuses_silent_server_or_signing_key_migration(self):
        self.install(self.instance())
        for field, value in (("server_url", "https://other.example.org"), ("update_public_key", "cd" * 32)):
            previous = self.connection[field]
            self.connection[field] = value
            self.save_profile()
            with self.assertRaises(setup.SetupError):
                self.instance().preflight()
            self.connection[field] = previous
        self.save_profile()

    def test_urls_and_paths_are_validated(self):
        for value in ("http://remote.example", "https://host/?token=x", "https://user:pass@host", "https://host/path", "https://host\n"):
            with self.subTest(value=value), self.assertRaises(setup.SetupError):
                setup.url(value)
        with self.assertRaises(setup.SetupError):
            self.instance(extra=("--watch", "relative")).preflight()
        self.assertEqual(setup.url("http://127.0.0.1:8080/"), "http://127.0.0.1:8080")

    def test_copy_does_not_follow_symlinks(self):
        if os.name == "nt":
            self.skipTest("symlink privilege is not assumed on Windows")
        instance = self.instance()
        victim = self.root / "outside"
        victim.write_text("original")
        target = instance.layout.file(instance.layout.binary("spire"))
        target.parent.mkdir(parents=True)
        target.symlink_to(victim)
        with self.assertRaises(setup.SetupError):
            instance.copy(self.bin / "spire", instance.layout.binary("spire"))
        self.assertEqual(victim.read_text(), "original")

    def test_server_allowlist_excludes_keys_databases_and_cache(self):
        root = self.root / "server"
        (root / "src/spire_server/__pycache__").mkdir(parents=True)
        for relative in ("keys/private.pem", "data/spire.db", ".env", "src/spire_server/__pycache__/x.pyc", "src/spire_server/main.py"):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture")
        files = [p.relative_to(root).as_posix() for p in setup.server_files(root)]
        self.assertEqual(files, ["pyproject.toml", "uv.lock", "README.md", "src/spire_server/main.py"])

    def test_bundle_tampering_is_rejected(self):
        instance = self.instance()
        bundle = self.root / "bundle"
        bundle.mkdir()
        file = bundle / "payload"
        file.write_bytes(b"a")
        import hashlib
        (bundle / "bundle.json").write_text(json.dumps({"platform":"linux", "arch":"x86_64", "files":{"payload":hashlib.sha256(b"a").hexdigest()}}))
        instance.source = bundle
        instance.args.bin_dir = None
        instance.verify_bundle()
        file.write_bytes(b"b")
        with self.assertRaises(setup.SetupError):
            instance.verify_bundle()

    def test_install_lock_prevents_parallel_install(self):
        if os.name == "nt":
            self.skipTest("Windows lock is exercised through OS integration")
        instance = self.instance()
        instance.layout.file(instance.layout.config).mkdir(parents=True)
        with instance.install_lock(), self.assertRaises(setup.SetupError):
            with self.instance().install_lock():
                self.fail("parallel installer acquired lock")


if __name__ == "__main__":
    unittest.main()
