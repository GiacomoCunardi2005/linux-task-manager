import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import psutil
import metrics
from metrics import Monitor, root_state
import rootservice

EMPTY = dict(processes=[],system=[],traps=[])


class RootStateTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name)/'state.json'

    def write(self,mode=0o640,**changes):
        data = dict(version=1,time=time.time(),user=os.getuid(),threats=EMPTY,processes={},features={})
        data.update(changes)
        self.path.write_text(json.dumps(data))
        os.chmod(self.path,mode)
        return data

    def read(self):
        return root_state(self.path,owner=os.getuid())  # in tests "root" is the test user

    def test_only_fresh_private_well_formed_state_is_trusted(self):
        self.write()
        self.assertEqual(self.read()['threats'],EMPTY)
        self.assertIsNone(root_state(self.path,owner=0))  # not owned by root
        for mode,changes in [(0o662,{}),(0o640,dict(time=time.time()-60)),(0o640,dict(user=os.getuid()+1)),
                             (0o640,dict(version=2)),(0o640,dict(threats=dict(EMPTY,system=[dict(severity='x',reason='y')]))),
                             (0o640,dict(processes={'1:1.0':dict(exe=5,disk=None)}))]:
            self.write(mode,**changes)
            self.assertIsNone(self.read(),(mode,changes))
        self.path.write_text('{broken')
        self.assertIsNone(self.read())
        link = Path(self.folder.name)/'link.json'
        self.write()
        link.symlink_to(self.path)
        self.assertIsNone(root_state(link,owner=os.getuid()))

    def test_monitor_uses_root_findings_and_fills_other_users_fields(self):
        monitor = Monitor()
        self.addCleanup(monitor.close)
        monitor.sample()
        other = next((p for p in psutil.process_iter(['uids','create_time','exe']) if p.info['uids'] and p.info['uids'].real != os.getuid()
                      and not p.info['exe'] and p.pid != 2 and p.ppid() != 2),None)
        if other is None:
            self.skipTest('nessun processo di un altro utente con eseguibile illeggibile')
        finding = dict(pid=other.pid,created=other.info['create_time'],severity='alta',reasons=['dal servizio root'])
        state = dict(threats=dict(processes=[finding],system=[],traps=['/tmp/x']),
                     processes={f"{other.pid}:{other.info['create_time']!r}":dict(exe='/usr/bin/servizio',disk=123.)})
        with patch('metrics.root_state',return_value=state):
            data = monitor.sample()
        self.assertEqual(data['protection'],'root')
        self.assertEqual(data['threats']['processes'],[finding])
        row = next(r for r in data['process_rows'] if r['pid'] == other.pid)
        self.assertEqual(row['exe'],'/usr/bin/servizio')
        self.assertEqual(row['disk'],123.)
        self.assertEqual(monitor.detector.traps.paths,{})  # local traps are handed over to the service
        with patch('metrics.root_state',return_value=None):
            self.assertEqual(monitor.sample()['protection'],'utente')
        self.assertTrue(monitor.detector.traps.paths)  # and re-armed when the service is gone


class LightSampleTests(unittest.TestCase):
    def test_tray_sample_keeps_security_and_device_counters(self):
        monitor = Monitor()
        self.addCleanup(monitor.close)
        with patch('metrics.root_state',return_value=None):
            full = monitor.sample()
            last = monitor.last_time
            monitor.light = True
            light = monitor.sample()
        self.assertTrue(light['light'])
        self.assertEqual((light['disks'],light['nets'],light['connections']),({},{},[]))
        self.assertEqual(set(light['threats']),{'processes','system','traps'})
        self.assertEqual(light['protection'],'utente')
        self.assertTrue(light['process_rows'])
        self.assertEqual(monitor.last_time,last)  # next full sample averages rates over the hidden period
        self.assertTrue(full['disks'] or full['nets'])

    def test_light_sample_does_not_remove_devices_from_an_open_window(self):
        from PySide6.QtWidgets import QApplication
        import test_ui
        test_ui.UITests.setUpClass()
        from app import Window
        window = Window()
        window.show()
        try:
            test_ui.wait(1400)
            window.timer.stop()
            window.sampler.wait()
            before = set(window.resources)
            window.receive(dict(window.snapshot,light=True,disks={},nets={},gpus={},npus={},connections=[]))
            QApplication.processEvents()
            self.assertEqual(set(window.resources),before)
        finally:
            window.quitting = True
            window.close()


class RootServiceTests(unittest.TestCase):
    def test_sampler_state_and_atomic_private_write(self):
        sampler = rootservice.Sampler()
        sampler.rows()
        time.sleep(.1)
        rows = sampler.rows()
        own = next(r for r in rows if r['pid'] == os.getpid())
        self.assertIsNotNone(own['cpu'])
        data = rootservice.state(rows,EMPTY,os.getuid(),dict(fanotify=False,exec=False))
        self.assertNotIn(f"{own['pid']}:{own['created']!r}",data['processes'])  # the app already reads its own user
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'state.json'
            rootservice.write_state(data,os.getgid(),path)
            self.assertEqual(path.stat().st_mode & 0o777,0o640)
            self.assertIsNotNone(root_state(path,owner=os.getuid()))
            self.assertEqual(sorted(p.name for p in Path(folder).iterdir()),['state.json'])

    def test_raw_proc_sampler_matches_psutil(self):
        busy = subprocess.Popen([sys.executable,'-c','while True: pass'])
        self.addCleanup(busy.wait)
        self.addCleanup(busy.kill)
        sampler = rootservice.Sampler()
        sampler.rows()
        time.sleep(1)
        rows = {r['pid']:r for r in sampler.rows()}
        proc = psutil.Process(busy.pid)
        row = rows[busy.pid]
        self.assertEqual((row['created'],row['exe'],row['ppid'],row['uid'],row['name']),
                         (proc.create_time(),proc.exe(),proc.ppid(),proc.uids().real,proc.name()))
        self.assertGreater(row['cpu'],80/sampler.cores)  # one full core, as a share of the whole machine
        self.assertIsNotNone(rows[os.getpid()]['disk'])
        self.assertIn(busy.pid,{pid for pid,_ in sampler.static})  # described once, then cached
        with patch.object(rootservice.Sampler,'describe',wraps=rootservice.Sampler.describe) as describe:
            sampler.rows()
        self.assertNotIn(busy.pid,[call.args[0] for call in describe.call_args_list])  # known processes are not re-read

    def test_terminate_checks_caller_identity_and_protected_pids(self):
        child = subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        created = psutil.Process(child.pid).create_time()
        with self.assertRaises(PermissionError):
            rootservice.terminate([f'{child.pid}:{created!r}'],caller=os.getuid()+1,allowed=os.getuid())
        results = dict(rootservice.terminate([f'{child.pid}:{created-1!r}',f'1:{psutil.Process(1).create_time()!r}'],os.getuid(),os.getuid()))
        self.assertEqual(results,{child.pid:'già terminato',1:'protetto'})
        self.assertIsNone(child.poll())
        self.assertEqual(rootservice.terminate([f'{child.pid}:{created!r}'],os.getuid(),os.getuid()),[(child.pid,'inviato')])
        self.assertEqual(child.wait(5),-15)

    def test_terminate_entry_point_rejects_missing_pkexec_identity(self):
        with patch.dict(os.environ,{},clear=True), patch('rootservice.load_user',return_value=type('U',(),{'pw_uid':os.getuid()})):
            self.assertEqual(rootservice.main(['terminate','1:1.0']),1)
        self.assertEqual(rootservice.main([]),2)

    def test_terminate_as_root_reports_cancelled_password(self):
        with patch('metrics.subprocess.run',return_value=subprocess.CompletedProcess([],126,'','')):
            with self.assertRaisesRegex(PermissionError,'annullata'):
                metrics.terminate_as_root([(5,1.)])
        with patch('metrics.subprocess.run',return_value=subprocess.CompletedProcess([],0,'5 inviato\n6 già terminato\n','')) as run:
            self.assertEqual(metrics.terminate_as_root([(5,1.),(6,2.5)]),{'5':'inviato','6':'già terminato'})
        self.assertEqual(run.call_args.args[0][2:],['5:1.0','6:2.5'])


if __name__ == '__main__':
    unittest.main()
