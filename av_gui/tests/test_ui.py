import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from haruspic_edr_gui.app import MainWindow, PAGES
from haruspic_edr_gui.theme import apply
from haruspic_edr_gui.demo import snapshot

APP = QApplication.instance() or QApplication([])
apply(APP)


def wait_jobs(window):
    deadline = time.monotonic()+10
    while window.jobs and time.monotonic()<deadline:
        APP.processEvents()
        time.sleep(.01)
    APP.processEvents()
    assert not window.jobs, 'UI task did not complete'


class UiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.window = MainWindow(preferences_path=Path(self.temp.name)/'prefs.json')
        self.window.timer.stop()
        self.window.show()
        APP.processEvents()

    def tearDown(self):
        wait_jobs(self.window)
        self.window.close()
        self.window.deleteLater()
        APP.processEvents()
        self.temp.cleanup()

    def test_all_pages_and_empty_state(self):
        for key,*_ in PAGES:
            self.window.navigate(key)
            APP.processEvents()
            self.assertIs(self.window.stack.currentWidget(),self.window.page_widgets[key])
        self.assertEqual(self.window.metrics['agents'].text(),'—')
        self.assertEqual(self.window.agents_table.records,[])

    def test_untrusted_strings_are_plain_and_selection_uses_stable_id(self):
        data = snapshot()
        data['agents'][0]['hostname'] = '<img src=x onerror=alert(1)>'
        self.window.apply_snapshot(data)
        table = self.window.agents_table.table
        table.sortItems(0,Qt.SortOrder.DescendingOrder)
        table.selectRow(0)
        selected = self.window.agents_table.current()
        self.window.apply_snapshot(data)
        self.assertEqual(self.window.agents_table.current()['id'],selected['id'])
        self.window.notice('<b>not HTML</b>')
        self.assertEqual(self.window.message.textFormat(),Qt.TextFormat.PlainText)
        self.window.agents_table.filter('nonexistent')
        self.assertIsNone(self.window.agents_table.current())

    def test_disconnect_clears_data_and_token(self):
        self.window.apply_snapshot(snapshot())
        self.window.token.setText('secret')
        self.window.disconnect_server()
        self.assertEqual(self.window.token.text(),'')
        self.assertEqual(self.window.events_table.records,[])
        self.assertEqual(self.window.metrics['online'].text(),'—')

    def test_demo_cannot_run_cli_or_remote_commands(self):
        self.window.demo = True
        with patch.object(self.window.engine,'run') as run:
            self.window.update_feed()
            self.window.send_command()
            self.window.save_policy()
            self.window.edit_configuration(False)
            run.assert_not_called()
        self.assertFalse(self.window.jobs)

    def test_obsolete_session_result_is_ignored(self):
        values = []
        self.window.task('delayed',lambda:(time.sleep(.03),42)[1],values.append,session=True)
        self.window.disconnect_server()
        wait_jobs(self.window)
        self.assertEqual(values,[])

    def test_failed_scan_restores_controls(self):
        self.window.local_job('Сканирование',lambda:(_ for _ in ()).throw(ValueError('fixture error')),scan=True)
        self.assertFalse(self.window.scan_start.isEnabled())
        wait_jobs(self.window)
        self.assertTrue(self.window.scan_start.isEnabled())
        self.assertFalse(self.window.scan_stop.isEnabled())
        self.assertIn('fixture error',self.window.scan_output.toPlainText())


if __name__ == '__main__':
    unittest.main()
