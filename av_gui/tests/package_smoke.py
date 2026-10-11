"""Unpack and launch the actual native bundle without a display or external services."""
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    suffix = '.zip' if os.name=='nt' else '.tar.gz'
    archive, = list((ROOT/'dist').glob('haruspic_edr_gui-*'+suffix))
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream,'sha256').hexdigest()
    assert Path(str(archive)+'.sha256').read_text().split()[0]==digest
    with tempfile.TemporaryDirectory(prefix='haruspic-gui-smoke-') as temporary:
        root = Path(temporary)
        if os.name=='nt':
            with zipfile.ZipFile(archive) as packed:
                packed.extractall(root)
        else:
            with tarfile.open(archive) as packed:
                packed.extractall(root,filter='data')
        executable = root/'haruspic_edr_gui'/('haruspic_edr_gui.exe' if os.name=='nt' else 'haruspic_edr_gui')
        output = root/'preview.png'
        result = subprocess.run([str(executable),'--demo','--screenshot',str(output)],
            env={**os.environ,'QT_QPA_PLATFORM':'offscreen'},capture_output=True,timeout=60)
        assert result.returncode==0, result.stdout+result.stderr
        assert output.is_file() and output.stat().st_size>10000
        assert list((root/'haruspic_edr_gui/licenses').rglob('*'))
        print('Packaged GUI passed: archive checksum, frozen executable launch, real Qt screenshot')


if __name__=='__main__':
    main()
