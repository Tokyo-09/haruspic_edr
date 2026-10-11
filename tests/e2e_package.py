"""Exercise the shipped entry point after unpacking, never install host services."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import zipfile

REPO = Path(__file__).resolve().parents[1]


def main():
    suffix = ".zip" if os.name == "nt" else ".tar.gz"
    archives = list((REPO / "dist").glob("spire-setup-*" + suffix))
    assert len(archives) == 1, archives
    archive = archives[0]
    with archive.open("rb") as stream:
        actual_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    assert Path(str(archive) + ".sha256").read_text().split()[0] == actual_hash
    with tempfile.TemporaryDirectory(prefix="spire-package-test-") as temporary:
        root = Path(temporary)
        if os.name == "nt":
            with zipfile.ZipFile(archive) as packed:
                packed.extractall(root)
        else:
            with tarfile.open(archive) as packed:
                packed.extractall(root, filter="data")
        bundle, = [path for path in root.iterdir() if path.is_dir()]
        profile = root / "enrollment.json"
        profile.write_text(json.dumps({"schema_version":1, "server_url":"https://edr.example.org",
            "update_url":"https://edr.example.org", "update_public_key":"ab" * 32, "enrollment_token":"e" * 43}))
        stage = root / "stage"
        command = [str(bundle / ("SpireSetup.exe" if os.name == "nt" else "install.sh")), "agent",
                   "--profile", str(profile), "--stage", str(stage), "--yes"]
        dry = subprocess.run([*command, "--dry-run"], capture_output=True, timeout=120)
        assert dry.returncode == 0, dry.stdout + dry.stderr
        assert not stage.exists(), "dry-run changed filesystem"
        result = subprocess.run(command, capture_output=True, timeout=120)
        assert result.returncode == 0, result.stdout + result.stderr
        markers = list(stage.rglob("installation.json"))
        assert len(markers) == 1 and json.loads(markers[0].read_text())["status"] == "staged"
        print("Distribution E2E passed: archive checksum, native launcher, dry-run and staged install")


if __name__ == "__main__":
    main()
