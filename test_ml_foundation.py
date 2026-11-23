"""Regression tests for coherent observations used by the future automatic ML pipeline."""
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import psutil

from detection import Detector, ProcessScanner
from metrics import Monitor, compatible_finding, root_process_row, valid_network
from netbehavior import NetworkAnalyzer, FLOW_RETENTION
from netwatch import NetWatch, parse_destroy, socket_owner


TUPLE = ('10.0.0.2',50000,'203.0.113.9',443)
KEY = '203.0.113.9:443'
NOW = 1_800_000_000.


class ProcessImageTests(unittest.TestCase):
    def child(self,script):
        child = subprocess.Popen([sys.executable,'-u','-c',script],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        def cleanup():
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
            child.stdin.close()
            child.stdout.close()
        self.addCleanup(cleanup)
        self.ready(child)
        return child

    def ready(self,child):
        self.assertTrue(select.select([child.stdout],[],[],5)[0],'child handshake timed out')
        self.assertEqual(child.stdout.readline().strip(),'ready')

    def sample(self,scanner,pid):
        return next(row for row in scanner.rows() if row['pid'] == pid)

    def test_exec_same_pid_and_executable_refreshes_arguments_and_resets_rates(self):
        new = "import sys; print('ready',flush=True); sys.stdin.readline()"
        child = self.child(f"import os,sys; print('ready',flush=True); sys.stdin.readline(); os.execv(sys.executable,[sys.executable,'-u','-c',{new!r},'new-image'])")
        scanner = ProcessScanner()
        before = self.sample(scanner,child.pid)
        self.assertIsNotNone(self.sample(scanner,child.pid)['cpu'])
        child.stdin.write('\n')
        child.stdin.flush()
        self.ready(child)
        after = self.sample(scanner,child.pid)
        self.assertEqual((before['pid'],before['created'],before['start_ticks']),(after['pid'],after['created'],after['start_ticks']))
        self.assertEqual(after['exe'],before['exe'])
        self.assertIn('new-image',after['cmdline'])
        self.assertNotEqual(after['image_fingerprint'],before['image_fingerprint'])
        self.assertGreater(after['exec_generation'],before['exec_generation'])
        self.assertIsNone(after['cpu'])
        self.assertIsNone(after['disk'])
        self.assertIsNone(after['io_read'])
        self.assertEqual(after['threads'],psutil.Process(child.pid).num_threads())

    def test_exec_to_another_executable_updates_path_and_name(self):
        child = self.child("import os,sys; print('ready',flush=True); sys.stdin.readline(); os.execl('/usr/bin/sleep','sleep','30')")
        scanner = ProcessScanner()
        before = self.sample(scanner,child.pid)
        child.stdin.write('\n')
        child.stdin.flush()
        deadline = time.monotonic()+5
        while time.monotonic() < deadline and os.readlink(f'/proc/{child.pid}/exe') != '/usr/bin/sleep':
            time.sleep(.01)
        after = self.sample(scanner,child.pid)
        self.assertEqual(after['exe'],'/usr/bin/sleep')
        self.assertEqual(after['name'],'sleep')
        self.assertEqual(after['created'],before['created'])
        self.assertGreater(after['exec_generation'],before['exec_generation'])

    def test_event_invalidates_unchanged_image_and_generation_survives_racing_sample(self):
        scanner = ProcessScanner()
        pid = os.getpid()
        before = self.sample(scanner,pid)
        scanner.exec_seen(before)
        refreshed = self.sample(scanner,pid)
        self.assertGreater(refreshed['exec_generation'],before['exec_generation'])
        original, calls = scanner.image, []
        def racing(target):
            image = original(target)
            if target == pid:
                calls.append(target)
                if len(calls) == 2:
                    return (*image[:2],b'changed\0',image[3])
            return image
        with patch.object(scanner,'image',side_effect=racing):
            self.assertNotIn(pid,{r['pid'] for r in scanner.rows()})
        after = self.sample(scanner,pid)
        self.assertEqual(after['exec_generation'],refreshed['exec_generation'])
        self.assertIsNone(after['cpu'])

    def test_detector_refreshes_static_reasons_and_cpu_history_on_exec(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            detector = Detector(home=root,proc=root,usb_root=root,config=root/'ignore',read_crontab=lambda:'',
                                traps=False,agents=False,preload=root/'preload',system_startup=())
            row = dict(pid=5,created=1.,name='tool',exe='/home/u/tool',cmdline=['tool'],cpu=100.,exec_generation=0)
            with patch('detection.psutil.net_connections',return_value=[]), patch.object(detector,'static_reasons',side_effect=lambda r:[('media','old image')] if r['exe'].endswith('tool') else []):
                self.assertEqual(detector.assess([row],1,0)['processes'][0]['reasons'],['old image'])
                detector.assess([row],1,60)
                clean = dict(row,exe='/usr/bin/sleep',cmdline=['sleep','30'],exec_generation=1)
                self.assertEqual(detector.assess([clean],1,120)['processes'],[])
                self.assertEqual(list(detector.cpu[(5,1.)]),[(120,1.)])
                detector.exec_seen(clean)
                detector.assess([clean],1,121)
                self.assertEqual(list(detector.cpu[(5,1.)]),[(121,1.)])

    def test_root_observation_and_findings_cannot_cross_exec_images(self):
        local = self.sample(ProcessScanner(),os.getpid())
        root = dict(local,exe='/root/old-image',image_fingerprint='different',observed_at=NOW)
        self.assertIsNone(root_process_row(local,root))
        root = dict(local,observed_at=NOW,disk=321.)
        self.assertEqual(root_process_row(local,root)['disk'],321.)
        hidden = dict(local,exe=None,image_fingerprint=None)
        self.assertEqual(root_process_row(hidden,root)['observed_at'],NOW)
        self.assertIsNone(root_process_row(hidden,dict(root,name='changed')))
        self.assertIsNone(root_process_row(hidden,dict(root,boot_id='another-boot')))
        self.assertIsNone(root_process_row(hidden,dict(exe='/old/service',disk=12.)))
        self.assertFalse(compatible_finding(local,None))
        self.assertFalse(compatible_finding(local,{}))
        image = {k:local[k] for k in ('boot_id','start_ticks','name','cmdline','image_fingerprint')}
        self.assertTrue(compatible_finding(local,image))
        self.assertFalse(compatible_finding(local,dict(image,image_fingerprint='different')))
        finding = dict(pid=local['pid'],created=local['created'],severity='alta',reasons=['old image'],image=dict(image_fingerprint='different'))
        state = dict(threats=dict(processes=[finding],system=[],traps=[]),processes={})
        monitor = Monitor.__new__(Monitor)
        from unittest.mock import Mock
        monitor.detector = Mock()
        result = {}
        with patch('metrics.root_state',return_value=state):
            monitor.security([local],1,result)
        self.assertEqual(result['threats']['processes'],[])


class SocketAccountingTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = NetworkAnalyzer(now=NOW)

    def snap(self,t,out,inb,cookie=1,tuple4=TUPLE,starts=None):
        self.analyzer.snapshot(NOW+t,[(*tuple4,out,inb,cookie)],starts=starts)

    def close(self,t,out,inb,cookie=1,tuple4=TUPLE,duration=10):
        self.analyzer.close(NOW+t,tuple4[2],tuple4[3],out,inb,duration,tuple4,cookie)

    def test_snapshot_and_final_totals_are_counted_once_and_duplicate_close_ignored(self):
        self.snap(0,0,0)
        self.snap(5,100,50)
        self.close(10,1000,500)
        self.close(11,1000,500)
        self.snap(9,900,400)  # an ss snapshot delivered after the destroy notification
        self.assertEqual(self.analyzer.volumes(KEY,NOW+12),(1000,500))
        self.assertEqual(self.analyzer.bucket[3],1000)
        self.assertEqual(len(self.analyzer.conns),1)

    def test_first_positive_snapshot_counts_only_after_observed_syn(self):
        self.snap(5,80_000_000,1000,starts={TUPLE:NOW})
        self.assertEqual(self.analyzer.volumes(KEY,NOW+5),(80_000_000,1000))
        self.close(10,80_000_000,1000)
        self.assertEqual(self.analyzer.volumes(KEY,NOW+10),(80_000_000,1000))
        self.assertIn('volume',dict(self.analyzer.destination(KEY,NOW+10)[0]))

    def test_preexisting_socket_baselines_each_direction_independently(self):
        self.snap(0,1000,None)
        self.snap(5,1100,500)
        self.assertEqual(self.analyzer.volumes(KEY,NOW+5),(100,None))
        self.snap(10,1200,550)
        self.assertEqual(self.analyzer.transfers[-1][2:],(100,50))
        self.assertEqual(self.analyzer.bucket[3],200)

    def test_tuple_reuse_and_multiple_sockets_do_not_share_counters(self):
        other = (TUPLE[0],50001,*TUPLE[2:])
        self.snap(0,0,0)
        self.snap(1,100,10)
        self.snap(2,0,0,cookie=2)
        self.snap(3,50,5,cookie=2)
        self.snap(4,0,0,cookie=3,tuple4=other)
        self.snap(5,20,2,cookie=3,tuple4=other)
        self.close(6,200,20)  # delayed close for the old socket
        self.close(7,80,8,cookie=2)
        self.close(8,30,3,cookie=3,tuple4=other)
        self.assertEqual(self.analyzer.volumes(KEY,NOW+8),(310,31))

    def test_disappeared_socket_keeps_counters_until_delayed_close(self):
        self.snap(0,0,0)
        self.snap(1,100,10)
        self.analyzer.snapshot(NOW+900,[])
        self.close(901,1000,100,duration=901)
        self.assertEqual(self.analyzer.volumes(KEY,NOW+901),(1000,100))

    def test_evicted_state_never_causes_lifetime_totals_to_be_counted_again(self):
        self.snap(0,0,0)
        self.snap(1,100,10)
        with patch('netbehavior.MAX_FLOWS',1):
            self.snap(2,0,0,cookie=2)
        self.close(3,1000,100,duration=3)
        self.assertEqual(self.analyzer.volumes(KEY,NOW+3),(100,10))
        self.assertEqual(len(self.analyzer.flows),2)
        self.analyzer.prune_flows(NOW+FLOW_RETENTION+100)
        self.assertFalse(self.analyzer.flows)

    def test_resurrected_active_socket_cannot_recount_totals_after_eviction(self):
        starts = {TUPLE:NOW}
        self.snap(1,100,10,starts=starts)
        with patch('netbehavior.MAX_FLOWS',1):
            self.snap(2,0,0,cookie=2)
        self.snap(3,150,15,starts=starts)
        self.assertEqual(self.analyzer.volumes(KEY,NOW+3),(100,10))
        self.snap(4,200,20,starts=starts)
        self.assertEqual(self.analyzer.volumes(KEY,NOW+4),(150,15))

    def test_missing_totals_and_duration_remain_unknown_and_do_not_train(self):
        self.close(10,None,100,duration=None)
        self.assertEqual(self.analyzer.volumes(KEY,NOW+10),(None,100))
        vector = self.analyzer.destination(KEY,NOW+10)[2]
        self.assertIsNone(vector[0])
        self.assertIsNone(vector[2])
        self.assertIsNone(vector[4])
        self.analyzer.analyze(NOW+10)
        self.assertEqual(self.analyzer.base['vectors'],[])
        for invalid in (-1,float('nan'),float('inf'),True,'9',2**64):
            self.assertIsNone(self.analyzer.counter(invalid))

    def test_backward_wall_clock_cannot_create_negative_duration_or_log_age(self):
        self.analyzer.base['dest'][KEY] = [NOW+7200,NOW+7200,1]
        self.close(1,100,10,duration=-7200)
        self.assertIsNone(self.analyzer.conns[-1][4])
        self.assertEqual(self.analyzer.destination(KEY,NOW+1)[2][6],0.)
        self.assertFalse(self.analyzer.analyze(NOW-7200))  # future observations are not current traffic


class SocketCollectionTests(unittest.TestCase):
    def watch(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        watch = NetWatch(Path(folder.name)/'baseline',include_loopback=True)
        self.addCleanup(watch.close)
        return watch

    def test_ss_cookie_and_directional_missing_counter(self):
        watch = self.watch()
        output = '0 0 10.0.0.2:50000 203.0.113.9:443 uid:1000 ino:7 sk:1234abcd cgroup:/\n\t cubic bytes_acked:101\n'
        with patch('netwatch.subprocess.run',return_value=subprocess.CompletedProcess([],0,output)):
            self.assertEqual(watch.flows(),[(*TUPLE,100,None,0x1234abcd)])

    def test_syn_during_ss_query_is_included_in_the_first_observed_totals(self):
        watch = self.watch()
        def flows():
            watch.starts[TUPLE] = NOW+.5
            return [(*TUPLE,100,10,1)]
        watch.times.update(snapshot=NOW-10,idle=NOW,analyze=NOW,save=NOW)
        with patch.object(watch,'flows',side_effect=flows), patch('netwatch.time.monotonic',side_effect=[50.,51.]):
            watch.poll(NOW)
        self.assertEqual(watch.analyzer.volumes(KEY,NOW+1),(100,10))

    def test_destroy_parser_cookie_and_truncated_attributes(self):
        body = bytearray(72)
        body[0] = socket.AF_INET
        struct.pack_into('>HH',body,4,50000,443)
        body[8:12] = socket.inet_pton(socket.AF_INET,TUPLE[0])
        body[24:28] = socket.inet_pton(socket.AF_INET,TUPLE[2])
        struct.pack_into('=II',body,44,0x1234abcd,7)
        info = bytearray(136)
        struct.pack_into('QQ',info,120,101,51)
        payload = bytes(body)+struct.pack('HH',140,2)+info
        data = struct.pack('IHHII',16+len(payload),20,0,0,0)+payload
        self.assertEqual(parse_destroy(data,True)[0],(socket.AF_INET,*TUPLE,101,51,(7<<32)|0x1234abcd))
        self.assertEqual(parse_destroy(data)[0],(socket.AF_INET,*TUPLE,101,51))
        self.assertEqual(parse_destroy(data[:-1],True),[])

    def test_live_owner_and_descriptor_reuse_are_checked(self):
        sock = socket.socket()
        self.addCleanup(sock.close)
        fd = sock.fileno()
        inode = os.fstat(fd).st_ino
        owner = socket_owner(os.getpid(),fd,inode)
        self.assertIsNotNone(owner)
        self.assertEqual(owner['created'],psutil.Process().create_time())
        self.assertEqual(owner['exe'],psutil.Process().exe())
        self.assertIsNone(socket_owner(os.getpid(),fd,inode+1))
        sock.close()
        self.assertIsNone(socket_owner(os.getpid(),fd,inode))

    def test_attribution_clears_stale_names_and_exports_verified_identity(self):
        watch = self.watch()
        sock = socket.socket()
        self.addCleanup(sock.close)
        fd,inode = sock.fileno(),os.fstat(sock.fileno()).st_ino
        line = f'0 0 10.0.0.2:50000 203.0.113.9:443 users:(("wrong-name",pid={os.getpid()},fd={fd})) ino:{inode} sk:1\n'
        item = dict(key=KEY,score=70,process='stale name',kind='destinazione',subject=KEY,evidence=[])
        watch.analyzer.processes[KEY] = 'old cached name'
        with patch('netwatch.subprocess.run',return_value=subprocess.CompletedProcess([],0,line)):
            watch.attribute([item])
        self.assertEqual(item['owners'][0]['created'],psutil.Process().create_time())
        self.assertNotIn('wrong-name',item['process'])
        self.assertTrue(valid_network(dict(anomalies=[item])))
        self.assertFalse(valid_network(dict(anomalies=[dict(item,owners=[dict(item['owners'][0],created=float('nan'))])])))
        with patch('netwatch.subprocess.run',side_effect=subprocess.TimeoutExpired('ss',2)):
            watch.attribute([item])
        self.assertIsNone(item['process'])
        self.assertEqual(item['owners'],[])
        self.assertIsNone(item['process_observed_at'])
        self.assertNotIn(KEY,watch.analyzer.processes)


if __name__ == '__main__':
    unittest.main()
