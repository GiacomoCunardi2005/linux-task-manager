"""Real TLS/auth integration, bounded snapshots and remote UI source isolation."""
import copy
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from metrics import Monitor
from remote import RemoteMonitor, endpoint, validate_packet, MAX_SNAPSHOT
from server import credentials, Snapshots, SnapshotServer


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.config = Path(cls.temp.name)/'config'
        cls.token, cls.key = credentials(cls.config,initialize=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cls.config/'certificate.pem',cls.config/'private-key.pem')
        cls.snapshots = Snapshots(Monitor())
        cls.server = SnapshotServer(('127.0.0.1',0),cls.token,cls.snapshots,context)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.snapshots.worker.start()
        deadline = time.monotonic()+10
        while cls.snapshots.current() is None and time.monotonic()<deadline:
            time.sleep(.05)
        if cls.snapshots.current() is None:
            cls.tearDownClass()
            raise AssertionError('No server snapshot')

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.snapshots.close()
        cls.temp.cleanup()

    def client(self,key=None):
        return RemoteMonitor('127.0.0.1',self.port,key or self.key)

    def request(self,path,token=None,method='GET'):
        context = ssl._create_unverified_context()
        connection = http.client.HTTPSConnection('127.0.0.1',self.port,context=context,timeout=3)
        try:
            headers = {'Authorization':'Bearer '+token} if token else {}
            connection.request(method,path,headers=headers)
            response = connection.getresponse()
            body = response.read(MAX_SNAPSHOT+1)
            return response.status,body
        finally:
            connection.close()

    def test_real_tls_sample_metadata_and_no_command_arguments(self):
        client = self.client()
        data = client.sample()
        self.assertGreater(data['memory']['total'],0)
        self.assertTrue(client.cpu_name)
        self.assertTrue(client.cpu_details)
        self.assertTrue(data['process_rows'])
        self.assertTrue(all(row['cmdline']==[] for row in data['process_rows']))
        self.assertTrue(all(len(row['command_id'])==64 for row in data['process_rows']))

        packet = json.loads(self.snapshots.current())
        self.assertEqual(validate_packet(packet)['memory']['total'],data['memory']['total'])
        client.close()
        self.assertEqual(client.token,'')

    def test_auth_paths_no_remote_commands_and_stale_snapshot(self):
        self.assertEqual(self.request('/v1/snapshot')[0],401)
        self.assertEqual(self.request('/v1/snapshot','0'*64)[0],401)
        self.assertEqual(self.request('/v1/snapshot?token='+self.token)[0],401)
        self.assertEqual(self.request('/etc/passwd',self.token)[0],404)
        self.assertEqual(self.request('/v1/terminate',self.token,'POST')[0],501)
        with patch.object(self.snapshots,'current',return_value=None):
            self.assertEqual(self.request('/v1/snapshot',self.token)[0],503)
        with self.assertRaisesRegex(ValueError,'rifiutata'):
            self.client(self.key.split('.')[0]+'.'+'0'*64).sample()

    def test_pin_verified_before_sending_access_token(self):
        client = self.client('0'*64+'.'+self.token)
        with patch('remote.http.client.HTTPSConnection.request') as request:
            with self.assertRaisesRegex(ValueError,'Certificato diverso'):
                client.sample()
            request.assert_not_called()

    def test_bad_addresses_keys_and_packets_are_rejected(self):
        for host,port,key in [('https://example.org',8765,self.key),('a/b',8765,self.key),('localhost',0,self.key),('localhost',8765,'bad'),('host\r\nX:yes',8765,self.key)]:
            with self.assertRaises(ValueError):
                endpoint(host,port,key)
        self.assertEqual(endpoint('[::1]',8765,self.key)[0],'::1')
        packet = json.loads(self.snapshots.current())
        for path,value in [(('version',),99),(('data','process_rows'),{}),(('data','cpu','cores'),[float('nan')]),(('memory_hardware','installed'),'32 GB'),(('data','memory','total'),-1),(('data','memory','value'),101),(('data','cpu','value'),10**500),(('data','connections'),[dict(id='cycle',parent='cycle',name='Test',kind='Hub',protocol='USB4',speed=None,details=[])])]:
            invalid = copy.deepcopy(packet)
            parent = invalid
            for field in path[:-1]:
                parent = parent[field]
            parent[path[-1]] = value
            with self.assertRaises(ValueError):
                validate_packet(invalid)
        legacy = copy.deepcopy(packet)
        legacy['data'].pop('connections',None)
        for device in legacy['data']['nets'].values():
            device.pop('hardware',None)
        validate_packet(legacy)
        self.assertLess(self.snapshots.updated,time.monotonic()+1)
        with patch('server.time.monotonic',return_value=self.snapshots.updated+11):
            self.assertIsNone(self.snapshots.current())

    def test_headless_cli_and_credentials_remain_stable_and_private(self):
        token,key = credentials(self.config,initialize=True)
        self.assertEqual(key,self.key)
        self.assertEqual((self.config/'token').stat().st_mode & 0o777,0o600)
        self.assertEqual((self.config/'private-key.pem').stat().st_mode & 0o777,0o600)
        process = subprocess.run([sys.executable,'-c',
            'import sys,server; assert not any(k.startswith("PySide6") for k in sys.modules)'],capture_output=True,text=True,timeout=5)
        self.assertEqual(process.returncode,0,process.stderr)
        (self.config/'token').chmod(0o644)
        try:
            with self.assertRaisesRegex(ValueError,'600'):
                credentials(self.config)
        finally:
            (self.config/'token').chmod(0o600)

    def test_headless_process_stops_cleanly_on_sigterm(self):
        probe = socket.socket()
        probe.bind(('127.0.0.1',0))
        port = probe.getsockname()[1]
        probe.close()
        process = subprocess.Popen([sys.executable,'server.py','--host','127.0.0.1','--port',str(port),'--config',str(self.config)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
            env=dict(os.environ,DISPLAY='',WAYLAND_DISPLAY=''))
        try:
            deadline = time.monotonic()+8
            while time.monotonic()<deadline:
                try:
                    data = RemoteMonitor('127.0.0.1',port,self.key).sample()
                    break
                except (OSError,ValueError):
                    if process.poll() is not None:
                        self.fail('Headless server exited before its first sample')
                    time.sleep(.1)
            else:
                self.fail('Headless server startup timed out')
            self.assertGreater(data['memory']['total'],0)
            process.terminate()
            stdout,stderr = process.communicate(timeout=8)
            self.assertEqual(process.returncode,0,stderr)
            self.assertIn('sola lettura',stdout)
            self.assertNotIn(self.token,stdout+stderr)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()

    @unittest.skipIf(os.geteuid()==0,'The user service installer intentionally rejects root')
    def test_installer_uses_only_server_files_and_is_repeatable(self):
        with tempfile.TemporaryDirectory(prefix='task manager ') as folder:
            root = Path(folder)
            binary = root/'bin'
            binary.mkdir()
            fake = binary/'systemctl'
            fake.write_text('#!/bin/sh\nexit 0\n')
            fake.chmod(0o755)
            env = dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],
                XDG_DATA_HOME=str(root/'data'),XDG_CONFIG_HOME=str(root/'config'))
            for _ in range(2):
                result = subprocess.run(['./install-server.sh'],env=env,capture_output=True,text=True,timeout=45)
                self.assertEqual(result.returncode,0,result.stderr)
            target = root/'data/linux-task-manager-server'
            unit = (root/'config/systemd/user/linux-task-manager-server.service').read_text()
            self.assertIn(f'"{target}/start-server.sh" --config "{root}/config/linux-task-manager-server"',unit)
            self.assertTrue((target/'.venv-server/bin/python').exists())
            self.assertFalse((target/'app.py').exists())
            self.assertNotIn('PySide6',(target/'requirements-server.txt').read_text())
            run = subprocess.run([str(target/'start-server.sh'),'--config',str(root/'config/linux-task-manager-server'),'--show-key'],capture_output=True,text=True,timeout=5)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertRegex(run.stdout,r'[a-f0-9]{64}\.[a-f0-9]{64}')

    def test_slow_tls_client_does_not_block_another_client(self):
        stalled = socket.create_connection(('127.0.0.1',self.port),timeout=3)
        try:
            self.assertGreater(self.client().sample()['memory']['total'],0)
        finally:
            stalled.close()


class RemoteUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_ui import UITests
        UITests.setUpClass()
        cls.app = UITests.app
        ServerTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        ServerTests.tearDownClass()

    def test_connection_button_validates_input_then_connects(self):
        from app import Window
        from test_ui import wait
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication, QDialogButtonBox, QLineEdit, QSpinBox
        window = Window()
        window.show()
        failures = []
        def fill():
            try:
                dialog = QApplication.activeModalWidget()
                buttons = dialog.findChild(QDialogButtonBox)
                buttons.button(QDialogButtonBox.Ok).click()
                self.assertTrue(dialog.isVisible())
                Path('reference').mkdir(exist_ok=True)
                dialog.grab().save('reference/linux-connection.png')
                entries = {edit.accessibleName():edit for edit in dialog.findChildren(QLineEdit)}
                entries['IP o nome del server'].setText('127.0.0.1')
                entries['Chiave di accesso al server'].setText(ServerTests.key)
                dialog.findChild(QSpinBox).setValue(ServerTests.port)
                self.assertEqual(entries['Chiave di accesso al server'].echoMode(),QLineEdit.Password)
                buttons.button(QDialogButtonBox.Ok).click()
            except BaseException as exc:
                failures.append(exc)
                if QApplication.activeModalWidget():
                    QApplication.activeModalWidget().reject()
        try:
            QTimer.singleShot(0,fill)
            window.connect_button.click()
            if failures:
                raise failures[0]
            self.assertIsInstance(window.monitor,RemoteMonitor)
            deadline = time.monotonic()+5
            while window.snapshot is None and time.monotonic()<deadline:
                wait(50)
            self.assertIsNotNone(window.snapshot)
            def disconnect():
                dialog = QApplication.activeModalWidget()
                buttons = dialog.findChild(QDialogButtonBox)
                next(button for button in buttons.buttons() if button.text()=='Torna al PC locale').click()
            QTimer.singleShot(0,disconnect)
            window.connect_button.click()
            self.assertIsInstance(window.monitor,Monitor)
        finally:
            window.close()

    def test_remote_local_switch_resets_history_and_never_signals_local_pid(self):
        from app import Window
        from test_ui import wait
        from PySide6.QtCore import QItemSelectionModel
        window = Window()
        window.show()
        try:
            wait(1200)
            remote = RemoteMonitor('127.0.0.1',ServerTests.port,ServerTests.key)
            window.switch_monitor(remote)
            self.assertIsNone(window.snapshot)
            self.assertFalse(window.histories)
            self.assertTrue(window.process_page.read_only)
            deadline = time.monotonic()+8
            while window.snapshot is None and time.monotonic()<deadline:
                wait(50)
            self.assertIsNotNone(window.snapshot)
            self.assertIn('Remoto',window.source_label.text())
            Path('reference').mkdir(exist_ok=True)
            window.grab().save('reference/linux-remote.png')
            page = window.process_page
            index = page.proxy.index(0,0)
            page.table.selectionModel().select(index,QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
            page.selection_changed()
            self.assertFalse(page.end_task.isEnabled())
            with patch('processes.terminate_process') as terminate:
                page.end_task.setEnabled(True)
                page.end_selected()
                terminate.assert_not_called()
            window.show_page('performance')
            for pair in list(window.resources):
                window.select(*pair)
                self.assertTrue(window.heading.text())
            window.core_action.setChecked(True)
            window.show_error('Server spento')
            self.assertIn('interrotto',window.source_label.text())
            window.switch_monitor(Monitor())
            self.assertFalse(window.process_page.read_only)
            self.assertIsNone(window.snapshot)
            self.assertFalse(window.histories)
            self.assertFalse(window.process_page.end_task.isEnabled())
            self.assertIn('PC locale',window.source_label.text())
            wait(1200)
            self.assertIsNotNone(window.snapshot)
            self.assertEqual(remote.token,'')
        finally:
            window.close()


if __name__ == '__main__':
    unittest.main()
