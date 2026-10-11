#!/usr/bin/env python3
"""Create a native onedir GUI distribution on its target OS."""
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent


def main():
    destination = ROOT / 'dist'
    destination.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='haruspic-gui-build-') as temporary:
        work = Path(temporary)
        subprocess.run([sys.executable,'-m','PyInstaller','--noconfirm','--clean','--onedir','--windowed',
            '--name','haruspic_edr_gui','--paths',str(ROOT),'--distpath',str(work/'dist'),
            '--workpath',str(work/'work'),'--specpath',str(work),str(ROOT/'main.py')],check=True)
        bundle = work/'dist/haruspic_edr_gui'
        shutil.copy2(ROOT/'README.md',bundle/'README.md')
        shutil.copytree(ROOT/'screenshots',bundle/'screenshots',ignore=shutil.ignore_patterns('ci-*'))
        licenses = bundle/'licenses'
        licenses.mkdir()
        for name in ('PySide6','PySide6_Essentials','PySide6_Addons','shiboken6','pyinstaller'):
            dist = metadata.distribution(name)
            for file in dist.files or []:
                if any(part.lower() in ('licenses','license','copying') or part.lower().startswith(('license.','copying.')) for part in file.parts):
                    source = Path(dist.locate_file(file))
                    if source.is_file():
                        target = licenses/name/Path(*file.parts)
                        target.parent.mkdir(parents=True,exist_ok=True)
                        shutil.copy2(source,target)
        (bundle/'build-info.json').write_text(json.dumps({'app':'haruspic_edr_gui','version':'0.1.0',
            'python':platform.python_version(),'platform':platform.platform(),
            'packages':{n:metadata.version(n) for n in ('PySide6','shiboken6','pyinstaller')}},indent=2)+'\n')
        kind = 'windows' if os.name=='nt' else 'linux'
        arch = platform.machine().lower().replace('amd64','x86_64')
        archive = shutil.make_archive(str(destination/f'haruspic_edr_gui-{kind}-{arch}'), 'zip' if os.name=='nt' else 'gztar',work/'dist','haruspic_edr_gui')
    with open(archive,'rb') as stream:
        digest = hashlib.file_digest(stream,'sha256').hexdigest()
    Path(archive+'.sha256').write_text(digest+'  '+Path(archive).name+'\n')
    print(archive)


if __name__=='__main__':
    main()
