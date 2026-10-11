from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from haruspic_edr_gui.backend import ApiClient, BackendError, Preferences, LocalEngine, NoRedirect, validate_url
from haruspic_edr_gui.configuration import read_agent, edit_agent, edit_limits, LIMITS


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'config.json'
        self.config.write_text(json.dumps({'spire_dir':str(self.root),'update_public_key':'ab'*32}))
        self.prefs = Preferences(core_config=str(self.config),cli_path=str(self.root/'spire'),agent_config=str(self.root/'agent.toml'))
        self.engine = LocalEngine(self.prefs)

    def test_credentials_are_not_saved_or_in_repr(self):
        path = self.root/'preferences.json'
        self.prefs.save(path)
        self.assertNotIn('token',path.read_text())
        client = ApiClient('https://example.org','very-private-token')
        self.assertNotIn('very-private-token',repr(client))
        self.assertEqual(Preferences.load(path),self.prefs)

    def test_transport_rejects_unsafe_addresses_and_redirects(self):
        for value in ('http://example.org','https://a:p@example.org','https://example.org?q=secret','https://example.org/path','file:///tmp/foo'):
            with self.subTest(value=value),self.assertRaises(BackendError):
                validate_url(value)
        self.assertEqual(validate_url('http://127.0.0.1:8000/'),'http://127.0.0.1:8000')
        with self.assertRaises(BackendError):
            ApiClient('https://example.org','abc\r\nHeader:foo')
        with self.assertRaises(BackendError):
            NoRedirect().redirect_request(None)

    def test_command_allowlist_and_url_encoding(self):
        client = ApiClient('https://example.org','token')
        with patch.object(ApiClient,'request',return_value={}) as request:
            client.command('a/b','scan_path','/tmp/a; touch nope')
            args = request.call_args.args
            self.assertEqual(args[1],'/v1/agents/a%2Fb/commands')
            self.assertEqual(args[2]['payload']['path'],'/tmp/a; touch nope')
            with self.assertRaises(BackendError):
                client.command('id','run','whoami')
            self.assertEqual(request.call_count,1)

    def test_scan_arguments_remain_separate(self):
        path = self.root/'file; echo injected'
        path.write_text('safe')
        with patch.object(self.engine,'run',return_value='done') as run:
            self.engine.scan(str(path),'fast',True)
            self.assertEqual(run.call_args.args[0],['scan','--quarantine','fast','--path',str(path)])
            with self.assertRaises(BackendError):
                self.engine.scan(str(path),'process-scan')

    def test_quarantine_read_only_and_safe_actions(self):
        db = self.root/'response.db'
        with closing(sqlite3.connect(db)) as conn, conn:
            conn.execute('CREATE TABLE quarantine(id,original_path,malware_name,timestamp)')
            conn.execute('INSERT INTO quarantine VALUES(1,?,?,100)',('a#file','test'))
        self.assertEqual(self.engine.quarantine()[0]['original_path'],'a#file')
        with patch.object(self.engine,'run') as run:
            self.engine.quarantine_action('restore',1)
            self.assertEqual(run.call_args.args[0],['quarantine','restore','--id','1'])
            with self.assertRaises(BackendError):
                self.engine.quarantine_action('execute',1)

    def test_agent_config_preserves_secret_and_nested_limits(self):
        path = self.root/'agent.toml'
        path.write_text('enrollment_token="hidden-token"\nwatch_paths=[]\nexcluded_paths=[]\nexcluded_extensions=[]\nexcluded_files=[]\nresponse_policy="observe"\n[queue_limits]\nmax_events=100\n')
        original = read_agent(path)
        values = dict(watch_paths=[str(self.root)],excluded_paths=[],excluded_extensions=['tmp'],excluded_files=[],response_policy='observe')
        edit_agent(path,values,original)
        result = read_agent(path)
        self.assertEqual(result['enrollment_token'],'hidden-token')
        self.assertEqual(result['queue_limits'],{'max_events':100})
        self.assertTrue(path.with_name('agent.toml.gui-backup').is_file())
        with self.assertRaises(BackendError):
            edit_agent(path,values,original)

    def test_limits_are_bounded_and_preserve_key(self):
        before = json.loads(self.config.read_text())
        values = {k:v[0] for k,v in LIMITS.items()}
        values['max_depth'] = 1000
        with self.assertRaises(BackendError):
            edit_limits(self.config,values,before)
        self.assertEqual(json.loads(self.config.read_text()),before)
        values['max_depth'] = 32
        edit_limits(self.config,values,before)
        self.assertEqual(json.loads(self.config.read_text())['update_public_key'],'ab'*32)

    def test_feed_directory_cannot_escape_state(self):
        with closing(sqlite3.connect(self.root/'feed-state.db')) as conn, conn:
            conn.execute('CREATE TABLE active_feed(id,version,directory)')
            conn.execute('INSERT INTO active_feed VALUES(1,1,?)',('signed-../../outside',))
        with self.assertRaises(BackendError):
            self.engine.feed_info()


if __name__ == '__main__':
    unittest.main()
