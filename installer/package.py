#!/usr/bin/env python3
"""Build a secret-free native distribution; never cross-label host binaries."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from installer.setup import server_files


def build(args):
    target = "windows" if os.name == "nt" else "linux"
    if target == "linux" and not sys.platform.startswith("linux"):
        raise ValueError("Build on Linux or Windows")
    arch = platform.machine().lower().replace("amd64", "x86_64").replace("aarch64", "arm64")
    suffix = ".exe" if target == "windows" else ""
    binaries = Path(args.bin_dir).resolve()
    uv = Path(args.uv or shutil.which("uv") or "missing-uv")
    required = [binaries / (name + suffix) for name in ("spire", "spired", "spire-feed")]
    for path in [*required, uv]:
        if not path.is_file():
            raise ValueError(f"Missing native executable: {path}")
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    name = f"spire-setup-{target}-{arch}"
    # Do not recursively package the repository: it can contain keys and test data.
    with tempfile.TemporaryDirectory(prefix="spire-package-", dir=out) as temp:
        root = Path(temp) / name
        (root / "bin").mkdir(parents=True)
        def copy(source, relative):
            dest = root / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, dest)
        for path in required:
            copy(path, "bin/" + path.name)
        copy(uv, "bin/uv" + suffix)
        for relative in ("installer/setup.py", "installer/windows-job.ps1", "docs/installation.md", "docs/signed-updates-and-response.md", "README.md"):
            copy(REPO / relative, relative)
        for source in server_files(REPO / "server"):
            copy(source, "server/" + source.relative_to(REPO / "server").as_posix())
        if target == "windows":
            # PyInstaller must run on the target OS; administrator manifest prompts UAC.
            subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--console", "--uac-admin",
                            "--name", "SpireSetup", "--distpath", str(root), "--workpath", str(Path(temp) / "build"),
                            "--specpath", str(Path(temp) / "spec"), str(REPO / "installer/setup.py")], check=True)
        else:
            copy(REPO / "installer/install.sh", "install.sh")
            (root / "install.sh").chmod(0o755)
        manifest = {"schema_version": 1, "platform": target, "arch": arch, "files": {}}
        for path in sorted(root.rglob("*")):
            if path.is_file():
                with path.open("rb") as stream:
                    digest = hashlib.sha256()
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                manifest["files"][path.relative_to(root).as_posix()] = digest.hexdigest()
        (root / "bundle.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        archive = shutil.make_archive(str(out / name), "zip" if target == "windows" else "gztar", temp, name)
    with open(archive, "rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    Path(archive + ".sha256").write_text(digest + "  " + Path(archive).name + "\n", encoding="ascii")
    print(archive)
    return archive


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", default=os.environ.get("SPIRE_BUILD_BIN_DIR", str(REPO / "target/release")))
    parser.add_argument("--uv", help="native uv executable to include")
    parser.add_argument("--out", default=str(REPO / "dist"))
    try:
        build(parser.parse_args())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
