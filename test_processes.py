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
from processes import ProcessModel, ProcessAnomaliesDialog, process_groups
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
            self.assertTrue(page.end_task.isEnabled())
            with patch('processes.QMessageBox.question',return_value=QMessageBox.No), patch('processes.terminate_process') as terminate:
                page.end_selected()
                terminate.assert_not_called()
            with patch('processes.QMessageBox.question',return_value=QMessageBox.Yes) as ask, patch('processes.terminate_process',side_effect=[None,psutil.NoSuchProcess(987652)]) as terminate:
                page.end_selected()
                self.assertIn('987651, 987652',ask.call_args.args[2])
                self.assertEqual([c.args for c in terminate.call_args_list],[(987651,1.),(987652,1.)])
                self.assertIn('1 processi, 1 già terminati',page.status.text())
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

    def test_suspicious_processes_are_marked_and_searchable(self):
        window = Window()
        window.show()
        try:
            wait(1400)
            window.timer.stop()
            window.sampler.wait()
            page = window.process_page
            base = dict(created=1.,status='sleeping',user='test',uid=os.getuid(),cpu=1.,memory=1024,disk=0,network=100)
            rows = [dict(base,pid=987661,name='miner',exe='/tmp/miner'),dict(base,pid=987662,name='miner',exe='/tmp/miner'),
                    dict(base,pid=987663,name='quiet',exe='/usr/bin/quiet')]
            threats = dict(processes=[dict(pid=987662,created=1.,severity='alta',reasons=['Parametri tipici di un miner'])],
                           system=[dict(severity='media',reason='Nuova tastiera USB collegata')])
            page.receive(dict(window.snapshot,process_rows=rows,threats=threats))
            self.assertTrue(page.process_anomalies.isEnabled())
            self.assertEqual(page.process_anomalies.text(),'Anomalie dei processi (1)')
            dialog = ProcessAnomaliesDialog(page,page.model)
            item = dialog.tree.topLevelItem(0)
            self.assertEqual([item.text(i) for i in range(4)],['Sospetto','miner','987662','test'])
            self.assertEqual(item.child(0).text(0),'Parametri tipici di un miner')
            dialog.close()
            statuses = {page.proxy.index(i,0).data():page.proxy.index(i,1).data() for i in range(page.proxy.rowCount())}
            self.assertEqual(statuses['miner (2)'],'Sospetto')
            self.assertNotEqual(statuses['quiet'],'Sospetto')
            group = next(i for i in range(page.proxy.rowCount()) if page.proxy.index(i,0).data() == 'miner (2)')
            self.assertIn('miner',page.proxy.index(group,1).data(Qt.ToolTipRole))
            self.assertIn('1 processi da verificare (cerca «sospetto»), 1 avvisi di sistema',page.status.text())
            self.assertIn('tastiera USB',page.status.toolTip())
            page.search.setText('sospetto')
            self.assertEqual(page.proxy.rowCount(),1)
            root = page.proxy.index(0,0)
            children = {page.proxy.index(i,6,root).data():page.proxy.index(i,1,root).data() for i in range(page.proxy.rowCount(root))}
            self.assertEqual(children['987662'],'Sospetto')
            self.assertNotEqual(children['987661'],'Sospetto')
            page.search.clear()
            legacy = dict(window.snapshot,process_rows=rows)
            legacy.pop('threats')
            page.receive(legacy)
            self.assertIn('Controlli di sicurezza non disponibili',page.status.text())
            self.assertFalse(page.process_anomalies.isEnabled())
            page.receive(dict(window.snapshot,process_rows=rows,threats=dict(processes=[],system=[])))
            dialog = ProcessAnomaliesDialog(page,page.model)
            self.assertIn('Nessun processo segnalato',dialog.tree.topLevelItem(0).text(1))
            dialog.close()
        finally:
            window.close()

    def test_tray_announces_new_alerts_once_and_close_hides(self):
        class FakeTray:
            def __init__(self):
                self.messages, self.tooltip = [], ''
            def showMessage(self,title,text,*args):
                self.messages.append((title,text))
            def setIcon(self,icon):
                pass
            def setToolTip(self,text):
                self.tooltip = text
        window = Window()
        window.show()
        try:
            wait(1400)
            window.timer.stop()
            window.sampler.wait()
            window.tray = tray = FakeTray()
            rows = [dict(pid=987671,created=1.,name='dropper',status='sleeping',user='test',uid=os.getuid(),cpu=1.,memory=1,disk=0,network=0)]
            threats = dict(processes=[dict(pid=987671,created=1.,severity='alta',reasons=['Eseguibile in memoria condivisa'])],
                           system=[dict(severity='media',reason='Nuova tastiera USB collegata')],traps=[])
            data = dict(window.snapshot,process_rows=rows,threats=threats)
            window.receive(data)
            self.assertEqual(len(tray.messages),1)
            self.assertEqual(tray.messages[0][0],'Comportamento sospetto')
            self.assertIn('dropper (PID 987671)',tray.messages[0][1])
            self.assertIn('altri 1',tray.messages[0][1])
            self.assertIn('2 avvisi',tray.tooltip)
            window.receive(data)
            self.assertEqual(len(tray.messages),1)  # unchanged findings are not repeated
            window.receive(dict(data,threats=dict(threats,system=[])))
            window.receive(data)
            self.assertEqual(len(tray.messages),2)  # a finding that came back is announced again
            window.timer.start(1000)
            window.close()
            self.assertFalse(window.isVisible())
            self.assertTrue(window.timer.isActive())  # still monitoring in the tray
            self.assertIn('area di notifica',tray.messages[-1][1])
        finally:
            window.quitting = True
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
