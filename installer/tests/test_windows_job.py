"""Native Windows test: kill the supervisor and ensure its child is also gone."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

from installer.setup import ps_quote


@unittest.skipUnless(os.name == "nt", "native Windows integration")
class WindowsJobTests(unittest.TestCase):
    def test_child_terminates_with_supervisor(self):
        helper = Path(__file__).resolve().parents[1] / "windows-job.ps1"
        with tempfile.TemporaryDirectory(prefix="spire-job-") as temporary:
            root = Path(temporary)
            pid_file = root / "child.txt"
            script = root / "probe.ps1"
            script.write_text("$ErrorActionPreference='Stop'\n. " + ps_quote(helper) + "\n"
                "$p=Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 120' -PassThru\n"
                "$p.Id | Out-File -Encoding ascii -LiteralPath " + ps_quote(pid_file) + "\nStart-Sleep -Seconds 120\n", encoding="utf-8-sig")
            parent = subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                for _ in range(200):
                    if pid_file.exists() and pid_file.read_text().strip():
                        break
                    if parent.poll() is not None:
                        self.fail(str(parent.communicate()))
                    time.sleep(.1)
                self.assertTrue(pid_file.exists(), "job did not start child")
                child = int(pid_file.read_text().strip())
                parent.terminate()
                parent.wait(timeout=10)
                result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    f"Start-Sleep -Seconds 1; if (Get-Process -Id {child} -ErrorAction SilentlyContinue) {{ exit 1 }}"], timeout=10)
                self.assertEqual(result.returncode, 0, "orphan child survived supervisor termination")
            finally:
                if parent.poll() is None:
                    parent.terminate()
                    parent.wait(timeout=10)
                parent.communicate()
