import ctypes
import errno
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import psutil
from filewatch import FileWatch, MASK, MODIFY, RENAME, DELETE, ONDIR, OVERFLOW, parse_events, process_identity


HANDLE = (b'fsid1234',1,b'parent')


def fid(kind,handle,name=None):
    fsid,handle_type,opaque = handle
    value = fsid+struct.pack('=Ii',len(opaque),handle_type)+opaque
    if name is not None:
        value += os.fsencode(name)+b'\0'
    value += b'\0'*((-len(value)-4) % 4)
    return struct.pack('=BBH',kind,0,len(value)+4)+value


def event(mask,pid=None,target=None,pidfd=-1,parent=HANDLE,name='item',fd=-1):
    info = fid(2,parent,name)
    if target is not None:
        info += fid(1,target)
    info += struct.pack('=BBHi',4,0,8,pidfd)
    return struct.pack('=IBBHQii',24+len(info),3,0,24,mask,fd,os.getpid() if pid is None else pid)+info


class FileWatchTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.watch = FileWatch([self.root])
        self.row = dict(pid=os.getpid(),created=psutil.Process().create_time(),name='test',exe=sys.executable)

    def test_variable_records_and_combined_actions_keep_target_identity(self):
        target = (HANDLE[0],7,b'unique-file')
        raw = event(MODIFY | RENAME | DELETE,target=target)
        result, = parse_events(raw)
        self.assertEqual(result['target'],target)
        self.assertEqual(result['names'],[(HANDLE,'item')])
        self.assertFalse(result['error'])
        broken = bytearray(raw)
        struct.pack_into('=H',broken,26,65535)
        self.assertTrue(next(parse_events(broken))['error'])

    def test_pidfd_proves_active_identity_and_rejects_exited_process(self):
        fd = os.pidfd_open(os.getpid())
        try:
            self.assertEqual(process_identity(os.getpid(),fd),(self.row['pid'],self.row['created']))
            self.assertIsNone(process_identity(os.getpid()+1,fd))
        finally:
            os.close(fd)
        child = subprocess.Popen([sys.executable,'-c','pass'])
        fd = os.pidfd_open(child.pid)
        try:
            child.wait(5)
            self.assertIsNone(process_identity(child.pid,fd))
        finally:
            os.close(fd)

    def test_protected_files_count_once_and_descriptors_are_closed(self):
        class Source:
            def parent(source,handle):
                return self.root if handle == HANDLE else self.root.parent/'outside'
        buffers = []
        descriptors = []
        for index in range(35):
            for action in (MODIFY,RENAME):
                fd = os.pidfd_open(os.getpid())
                descriptors.append(fd)
                buffers.append(event(action,target=(HANDLE[0],1,bytes([index])),pidfd=fd))
        outside = os.pidfd_open(os.getpid())
        descriptors.append(outside)
        buffers.append(event(DELETE,target=(HANDLE[0],1,b'outside'),pidfd=outside,parent=(HANDLE[0],1,b'elsewhere')))
        self.watch.consume(Source(),b''.join(buffers))
        finding, = self.watch.poll([self.row],set())
        self.assertIn('35 file distinti',finding['reasons'][0])
        self.assertIn('35 modificati, 35 rinominati, 0 eliminati',finding['reasons'][0])
        for fd in descriptors:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_unknown_pid_overflow_and_directory_events_do_not_invent_findings(self):
        class Source:
            def parent(source,handle):
                return self.root
        for index in range(40):
            self.watch.consume(Source(),event(MODIFY,target=(HANDLE[0],1,bytes([index]))))
        self.assertEqual(self.watch.poll([self.row],set()),[])
        self.assertEqual(self.watch.status()['unattributed'],40)
        self.watch.rescan = False
        self.watch.consume(Source(),event(ONDIR | RENAME))
        self.assertTrue(self.watch.rescan)
        self.watch.consume(Source(),event(OVERFLOW))
        self.assertEqual(self.watch.status()['lost'],1)

    def test_unavailable_collector_is_reported_without_stopping_other_checks(self):
        with patch('filewatch.FanotifySource',side_effect=OSError(errno.EPERM,'permesso negato')):
            self.watch.scan()
        status = self.watch.status()
        self.assertFalse(status['available'])
        self.assertTrue(any('permesso negato' in reason for reason in status['errors']))

    def test_rescan_at_capacity_keeps_existing_marks_and_reports_new_uncovered_folder(self):
        (self.root/'a').mkdir()
        (self.root/'b').mkdir()
        class Source:
            def __init__(source,path):
                source.marks = {}
                source.fd = -1
            def add(source,path,limit=None):
                if path not in source.marks:
                    if limit is not None and limit <= 0:
                        raise OSError(errno.ENOSPC,'limite cartelle')
                    source.marks[path] = str(path)
            def prune(source,inside,progress=None):
                pass
            def close(source):
                pass
        watch = FileWatch([self.root],max_marks=3)
        with patch('filewatch.FanotifySource',Source),patch.object(watch,'_drain'):
            watch.scan()
            watch.scan()
            self.assertEqual(watch.mark_count,3)
            self.assertEqual(watch.status()['errors'],[])
            (self.root/'c').mkdir()
            watch.scan()
            self.assertEqual(watch.mark_count,3)
            self.assertTrue(watch.status()['errors'])

    def test_real_kernel_events_keep_identity_across_rename(self):
        # Unprivileged fanotify can observe our own PID, but cannot request PIDFDs.
        # Decode real kernel records, then attach a real PIDFD of the known test producer.
        lib = ctypes.CDLL(None,use_errno=True)
        lib.fanotify_mark.argtypes = [ctypes.c_int,ctypes.c_uint,ctypes.c_uint64,ctypes.c_int,ctypes.c_char_p]
        fd = lib.fanotify_init(3 | 0x1e00,os.O_RDONLY | os.O_CLOEXEC)
        if fd < 0:
            self.skipTest(f'fanotify FID non disponibile: errno {ctypes.get_errno()}')
        try:
            if lib.fanotify_mark(fd,1 | 4 | 8,MASK,-100,os.fsencode(self.root)) < 0:
                self.skipTest(f'filesystem senza supporto fanotify FID: errno {ctypes.get_errno()}')
            for index in range(35):
                path = self.root/f'{index}.txt'
                path.write_text('test innocuo\n')
                path.rename(self.root/f'{index}.renamed')
            events = list(parse_events(os.read(fd,65536)))
            relevant = [e for e in events if e['mask'] & (MODIFY | RENAME)]
            self.assertTrue(relevant)
            self.assertEqual(len({e['target'] for e in relevant}),35)
            self.assertTrue(all(e['pid'] == os.getpid() and e['names'] and not e['error'] for e in relevant))
            for item in events:
                item['pidfd'] = os.pidfd_open(os.getpid())
            class Source:
                def parent(source,handle):
                    return self.root
            with patch('filewatch.parse_events',return_value=iter(events)):
                self.watch.consume(Source(),b'')
            finding, = self.watch.poll([self.row],set())
            self.assertIn('35 file distinti',finding['reasons'][0])
        finally:
            os.close(fd)


if __name__ == '__main__':
    unittest.main()
