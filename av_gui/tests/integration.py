"""Real Qt actions -> real FastAPI server and Rust CLI, isolated in a temp directory."""
from contextlib import closing
import hashlib
import json
import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from unittest.mock import patch
from PySide6.QtWidgets import QApplication
from haruspic_edr_gui.app import MainWindow
from haruspic_edr_gui.backend import Preferences, LocalEngine
from haruspic_edr_gui.theme import apply

REPO = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get('SPIRE_TEST_BIN_DIR', REPO/'target/release')).resolve()
SUFFIX = '.exe' if os.name=='nt' else ''
APP = QApplication.instance() or QApplication([])
apply(APP)


def wait(window):
    deadline = time.monotonic()+45
    while window.jobs and time.monotonic()<deadline:
        APP.processEvents()
        time.sleep(.01)
    APP.processEvents()
    assert not window.jobs, 'GUI worker did not finish'


def run(*args):
    result = subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=30)
    assert result.returncode==0, result.stdout+result.stderr


def main():
    with tempfile.TemporaryDirectory(prefix='haruspic-gui-integration-') as temporary:
        root = Path(temporary)
        sample = root/'safe fixture.bin'
        sample.write_bytes(b'harmless GUI integration fixture')
        with closing(sqlite3.connect(root/'input.db')) as conn, conn:
            conn.execute('CREATE TABLE default_db(md5hash TEXT,sha256hash TEXT,name TEXT)')
            conn.execute('INSERT INTO default_db VALUES(?,?,?)',(hashlib.md5(sample.read_bytes()).hexdigest(),hashlib.sha256(sample.read_bytes()).hexdigest(),'Test.GUI'))
        with zipfile.ZipFile(root/'rules.zip','w') as archive:
            archive.writestr('test.yar','rule gui_fixture { strings: $a="harmless GUI integration fixture" condition: $a }')
        signer = BIN/('spire-feed'+SUFFIX)
        run(signer,'keygen','--private-key',root/'test.pk8','--public-key',root/'public.hex')
        run(signer,'sign','--private-key',root/'test.pk8','--database',root/'input.db','--yara',root/'rules.zip',
            '--version','1','--expires-at',int(time.time())+3600,'--out',root/'feed')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0))
            port = listener.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        admin, enrollment = 'gui-admin-'+'a'*40, 'gui-enroll-'+'b'*40
        server_python = os.environ.get('SPIRE_SERVER_PYTHON',str(REPO/'server/.venv'/('Scripts/python.exe' if os.name=='nt' else 'bin/python')))
        env = {**os.environ,'PYTHONPATH':str(REPO/'server/src'),'SPIRE_ADMIN_TOKEN':admin,'SPIRE_ENROLLMENT_TOKEN':enrollment,
               'SPIRE_DATABASE_URL':'sqlite:///'+str(root/'server.db').replace('\\','/'),'SPIRE_UPDATES_DIR':str(root/'feed')}
        window = None
        with (root/'server.log').open('w') as log:
            server = subprocess.Popen([server_python,'-m','uvicorn','spire_server.main:app','--host','127.0.0.1','--port',str(port)],cwd=root,env=env,stdout=log,stderr=log)
            def api(path,body=None,token=None,enroll=False):
                headers = {'Content-Type':'application/json'}
                if token:
                    headers['X-Enrollment-Token' if enroll else 'Authorization'] = token if enroll else 'Bearer '+token
                req = urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers=headers)
                with urllib.request.urlopen(req,timeout=3) as response:
                    return json.load(response)
            try:
                for _ in range(100):
                    try:
                        api('/health')
                        break
                    except OSError:
                        assert server.poll() is None,(root/'server.log').read_text()
                        time.sleep(.1)
                identity = api('/v1/agents/enroll',{'hostname':'GUI-TEST','os_name':'linux','arch':'x86_64'},enrollment,True)
                api('/v1/telemetry/ingest',{'events':[{'id':'gui-fixture-event','ts':'2026-10-11T10:00:00Z','type':'detection','severity':'high','data':{'path':'<b>fixture</b>','malware':'Test.GUI'}}]},identity['agent_token'])
                cfg = root/'config.json'
                cfg.write_text(json.dumps({'spire_dir':str(root/'state'),'update_url':base,'update_public_key':(root/'public.hex').read_text()}))
                window = MainWindow(preferences_path=root/'preferences.json')
                window.timer.stop()
                window.show()
                window.prefs = Preferences(server_url=base,cli_path=str(BIN/('spire'+SUFFIX)),core_config=str(cfg),agent_config=str(root/'agent.toml'))
                window.engine = LocalEngine(window.prefs)
                window.server_url.setText(base)
                window.token.setText(admin)
                window.connect_server()
                wait(window)
                assert window.api is not None,window.message.text()
                assert window.metrics['agents'].text()=='1'
                assert window.metrics['open_alerts'].text()=='1'
                assert window.token.text()==''
                assert admin not in (root/'preferences.json').read_text()
                window.navigate('alerts')
                window.alerts_table.table.selectRow(0)
                window.change_alert('ack')
                wait(window)
                assert api('/v1/alerts',token=admin)[0]['status']=='ack'
                window.command_agent.setCurrentIndex(1)
                wait(window)
                with patch.object(window,'confirm',return_value=True):
                    window.send_command()
                wait(window)
                assert api('/v1/agents/'+identity['agent_id']+'/commands',token=admin)[0]['command_type']=='ping'
                window.load_policy()
                wait(window)
                window.policy_fields['send_file_events'].setChecked(True)
                with patch.object(window,'confirm',return_value=True):
                    window.save_policy()
                wait(window)
                assert api('/v1/policy',token=admin)['send_file_events'] is True
                window.navigate('updates')
                window.update_feed()
                wait(window)
                assert 'Activated signed feed' in window.update_output.toPlainText(),window.update_output.toPlainText()
                window.refresh()
                wait(window)
                assert window.feed_labels['Версия базы'].text()=='1'
                window.navigate('scan')
                window.scan_path.setText(str(sample))
                window.scan()
                wait(window)
                assert 'observe skipped' in window.scan_output.toPlainText(),window.scan_output.toPlainText()
                assert sample.exists()
                window.quarantine_check.setChecked(True)
                with patch.object(window,'confirm',return_value=True):
                    window.scan()
                wait(window)
                assert not sample.exists(),window.scan_output.toPlainText()
                window.navigate('quarantine')
                window.refresh()
                wait(window)
                assert len(window.quarantine_table.records)==1
                window.quarantine_table.table.selectRow(0)
                with patch.object(window,'confirm',return_value=True):
                    window.quarantine_action('restore')
                wait(window)
                assert sample.exists(),window.message.text()
                assert window.quarantine_table.records==[]
                window.disconnect_server()
                assert window.api is None and window.events_table.records==[]
                print('GUI integration passed: connect, alerts, commands, policy, signed update, real scan, quarantine and restore, disconnect')
            finally:
                if window:
                    wait(window)
                    window.close()
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__=='__main__':
    main()
