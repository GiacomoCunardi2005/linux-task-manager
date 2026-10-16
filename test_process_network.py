import os
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from process_network import ProcessNetwork, parse_nethogs_row


class ProcessNetworkTests(unittest.TestCase):
    def test_trace_parser_accepts_spaces_and_scientific_totals(self):
        self.assertEqual(parse_nethogs_row('/opt/my app/codex/123/1000\t1.2e+06\t4000'),(123,1000,1200000,4000))
        for text in ('unknown UDP/0/0\t1\t2','Refreshing:','bad','app/1/1000\tnan\t1','app/1/1000\t-2\t1','app/1/1000\t1e90\t1'):
            self.assertIsNone(parse_nethogs_row(text))

    def test_rate_uses_process_creation_identity_and_counter_reset(self):
        monitor = ProcessNetwork()
        created = [42.]
        process = SimpleNamespace(uids=lambda:SimpleNamespace(real=1000),create_time=lambda:created[0])
        with patch('process_network.psutil.Process',return_value=process):
            monitor._publish([(123,1000,100,200)],10)
            self.assertIsNone(monitor.rates[(123,42.)])
            monitor._publish([(123,1000,300,400)],12)
            self.assertEqual(monitor.rates[(123,42.)],1600)
            created[0] = 43.
            monitor._publish([(123,1000,500,600)],14)
            self.assertIsNone(monitor.rates[(123,43.)])
            monitor._publish([(123,1000,0,0)],16)
            self.assertIsNone(monitor.rates[(123,43.)])

    def test_missing_helper_is_unavailable_instead_of_zero(self):
        monitor = ProcessNetwork()
        rows = [dict(pid=123,created=1.,uid=1000)]
        with patch('process_network.shutil.which',return_value=None):
            message = monitor.sample(rows,[('test','id')])
        self.assertIsNone(rows[0]['network'])
        self.assertIn('non disponibile',message)
        monitor.close()

    def test_close_stops_owned_helper_and_reader(self):
        monitor = ProcessNetwork()
        process = subprocess.Popen([sys.executable,'-u','-c','import time; print("Refreshing:",flush=True); time.sleep(60)'],stdout=subprocess.PIPE,text=True)
        monitor.process = process
        monitor.thread = threading.Thread(target=monitor._read,args=(process,),daemon=True)
        thread = monitor.thread
        thread.start()
        try:
            monitor.close()
            self.assertIsNotNone(process.poll())
            self.assertFalse(thread.is_alive())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
