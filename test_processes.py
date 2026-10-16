import os
import sys
import subprocess
import tempfile
import time
from pathlib import Path
import unittest
from unittest.mock import patch
import psutil
from PySide6.QtGui import QIcon
from PySide6.QtTest import QAbstractItemModelTester
from PySide6.QtCore import Qt, QItemSelectionModel
from PySide6.QtWidgets import QApplication, QMessageBox
from processes import ProcessModel, process_groups
from metrics import Monitor, terminate_process
import test_ui
from test_ui import wait
from app import Window


class ProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_ui.UITests.setUpClass()
        cls.app = test_ui.UITests.app

    def test_installed_desktop_icon_resolves_quoted_executable(self):
        paths = QIcon.themeSearchPaths()
        try:
            with tempfile.TemporaryDirectory() as folder:
                image = Path(folder)/'sample.svg'
                image.write_text('<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><rect width="16" height="16" fill="red"/></svg>')
                (Path(folder)/'org.example.Sample.desktop').write_text(f'[Desktop Entry]\nName=Sample App\nIcon={image}\nExec="/opt/Sample App/sample-app" %U\n')
                (Path(folder)/'invalid.desktop').write_text('invalid desktop entry')
                with patch('processes.QStandardPaths.standardLocations',return_value=[folder]):
                    model = ProcessModel(QIcon())
                self.assertEqual(model.desktop_icons['sample-app'],str(image))
                model.rows = [dict(name='sample-app',status='sleeping',cpu=None,memory=0,disk=None,pid=42,user='test')]
                self.assertFalse(model.index(0,0).data(Qt.DecorationRole).isNull())
        finally:
            QIcon.setThemeSearchPaths(paths)

    def test_application_groups_aggregate_and_separate_interpreters(self):
        base = dict(created=1.,status='sleeping',user='test',uid=1000,cpu=1.,memory=1024,disk=10,network=100)
        rows = [dict(base,pid=1,name='codex',exe='/one/codex',ppid=0),
                dict(base,pid=2,name='codex',exe='/two/codex',ppid=0),
                dict(base,pid=3,name='codex-helper',exe='/two/codex-helper',ppid=2),
                dict(base,pid=4,name='python',exe='/usr/bin/python',cmdline=['python','first.py']),
                dict(base,pid=5,name='python',exe='/usr/bin/python',cmdline=['python','second.py'])]
        groups = process_groups(rows)
        self.assertEqual(len(groups),3)
        group = groups[0]
        self.assertEqual(group['name'],'codex')
        self.assertEqual(group['cpu'],3.)
        self.assertEqual(group['memory'],3072)
        self.assertEqual(group['network'],300)
        self.assertEqual([row['pid'] for row in group['children']],[1,2,3])
        self.assertNotIn('_parent',rows[0])

    def test_group_expansion_child_selection_and_pid_filter_survive_refresh(self):
        window = Window()
        window.show()
        try:
            wait(1400)
            window.timer.stop()
            window.sampler.wait()
            self.app.processEvents()
            page = window.process_page
            base = dict(created=1.,status='sleeping',user='test',uid=os.getuid(),cpu=1.,memory=1024,disk=0,network=100,exe='/opt/codex')
            rows = [dict(base,pid=987651,name='codex'),dict(base,pid=987652,name='codex')]
            data = dict(window.snapshot,process_rows=rows)
            tester = QAbstractItemModelTester(page.model,QAbstractItemModelTester.FailureReportingMode.Fatal)
            page.receive(data)
            root = page.proxy.index(0,0)
            self.assertEqual(root.data(),'codex (2)')
            page.table.setExpanded(root,True)
            page.table.selectionModel().select(root,QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
            self.assertFalse(page.end_task.isEnabled())
            child = page.proxy.index(1,0,root)
            page.table.selectionModel().select(child,QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
            self.assertEqual(page.selected()['pid'],987652)
            page.receive(dict(data,process_rows=list(reversed(rows))))
            self.assertEqual(page.selected()['pid'],987652)
            self.assertTrue(page.table.isExpanded(page.proxy.index(0,0)))
            page.search.setText('987652')
            self.assertEqual(page.proxy.rowCount(),1)
            self.assertEqual(page.proxy.rowCount(page.proxy.index(0,0)),1)
            page.search.clear()
            self.app.processEvents()
            window.grab().save('reference/linux-processes-group-fixture.png')
        finally:
            window.close()

    def test_live_rows_and_cpu_warmup(self):
        monitor = Monitor()
        self.addCleanup(monitor.close)
        first = monitor.sample()
        self.assertTrue(first['process_rows'])
        self.assertTrue(all(p['cpu'] is None for p in first['process_rows']))
        second = monitor.sample()
        own = next(p for p in second['process_rows'] if p['pid']==os.getpid())
        self.assertIsNotNone(own['cpu'])
        self.assertGreater(own['memory'],0)
        self.assertEqual(own['created'],psutil.Process().create_time())

    def test_terminate_checks_identity_then_signals_only_child(self):
        child = subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])
        try:
            created = psutil.Process(child.pid).create_time()
            with self.assertRaises(psutil.NoSuchProcess):
                terminate_process(child.pid,created-1)
            self.assertIsNone(child.poll())
            terminate_process(child.pid,created)
            self.assertLess(child.wait(timeout=5),0)
            with self.assertRaises(ValueError):
                terminate_process(os.getpid(),psutil.Process().create_time())
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)

    def test_navigation_filter_sort_selection_pause_and_cancel(self):
        window = Window()
        window.show()
        try:
            deadline = time.monotonic()+10
            while len(window.histories[('cpu','cpu')]) < 3 and time.monotonic() < deadline:
                wait(100)
            self.assertGreaterEqual(len(window.histories[('cpu','cpu')]),3)
            window.navbuttons[0][0].click()
            self.assertEqual(window.pages.currentIndex(),0)
            self.assertTrue(window.navbuttons[0][0].isChecked())
            page = window.process_page
            self.assertEqual(page.table.sizeHintForRow(0),30)
            data = window.snapshot
            self.assertIsNotNone(data)
            rows = [dict(pid=987654+i,created=1.,name=name,status='sleeping',user='test',uid=os.getuid(),cpu=cpu,memory=memory,disk=0.) for i,(name,cpu,memory) in enumerate([('app.test',2.,1024),('Another',12.,2048)])]
            data = dict(data,process_rows=rows)
            page.receive(data)
            page.table.sortByColumn(2,Qt.DescendingOrder)
            self.assertEqual(page.proxy.index(0,0).data(),'Another')
            page.search.setText('APP.TEST')
            self.assertEqual(page.proxy.rowCount(),1)
            page.search.setText('does-not-exist')
            self.assertEqual(page.proxy.rowCount(),0)
            page.search.clear()
            page.table.selectionModel().select(page.proxy.index(0,0),QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
            identity = page.selected()['pid']
            page.receive(dict(data,process_rows=list(reversed(rows))))
            self.assertEqual(page.selected()['pid'],identity)
            with patch('processes.QMessageBox.question',return_value=QMessageBox.No), patch('processes.terminate_process') as terminate:
                page.end_selected()
                terminate.assert_not_called()
            with patch('processes.QMessageBox.question',return_value=QMessageBox.Yes), patch('processes.terminate_process') as terminate:
                page.end_selected()
                terminate.assert_called_once_with(identity,1.)
            page.toggle_pause()
            page.receive(dict(data,process_rows=[]))
            self.assertEqual(page.model.rowCount(),2)
            page.toggle_pause()
            self.assertEqual(page.model.rowCount(),0)
            page.receive(window.snapshot)
            window.grab().save('reference/linux-processes.png')
            matched = next((row['name'] for row in page.model.rows if row['name'].casefold() in page.model.desktop_icons),None)
            if matched:
                page.search.setText(matched)
                self.app.processEvents()
                window.grab().save('reference/linux-processes-icons.png')
                page.search.clear()
            window.resize(900,660)
            self.app.processEvents()
            window.grab().save('reference/linux-processes-compact.png')
            window.navbuttons[1][0].click()
            self.assertEqual(window.pages.currentIndex(),1)
            self.assertTrue(window.navbuttons[1][0].isChecked())
        finally:
            window.close()


if __name__ == '__main__':
    unittest.main()
