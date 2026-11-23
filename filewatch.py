"""Read-only fanotify collection for bursts of changes in personal folders.

Directory inode marks work on Btrfs subvolumes. Target FIDs deduplicate files
across renames; PIDFDs prevent attributing a delayed event to a recycled PID.
Counts concern non-directory entries: renamed/deleted symlinks or special files
can be included because their former file type is not recoverable after removal.
No file content is opened or read, and no permission events are requested.
"""
import ctypes
import errno
import os
from pathlib import Path
import select
import struct
import threading
import time

import psutil
from detection import user_dir
from filebehavior import FileBehavior

MODIFY, DELETE, RENAME, ONDIR, OVERFLOW = 0x2, 0x200, 0x10000000, 0x40000000, 0x4000
MASK = MODIFY | DELETE | RENAME | 0x100 | 0x08000000 | ONDIR  # CREATE discovers new directories
INIT = 3 | 0x1e00 | 0x80  # CLOEXEC, NONBLOCK, DFID_NAME_TARGET, PIDFD
AT_EMPTY_PATH = 0x1000
NAME_TYPES = (2,10,12)  # DFID_NAME, OLD_DFID_NAME, NEW_DFID_NAME


def personal_roots(home):
    roots = []
    for key in ('DOCUMENTS','DESKTOP','DOWNLOAD','PICTURES','MUSIC','VIDEOS'):
        path = user_dir(Path(home),key)
        if path and path.is_dir():
            path = path.resolve()
            if path not in roots:
                roots.append(path)
    return roots


def parse_events(data):
    """Decode bounded, variable-length records; callers own event and PID FDs."""
    offset = 0
    while offset+24 <= len(data):
        length,version,_,metadata,mask,fd,pid = struct.unpack_from('=IBBHQii',data,offset)
        event = dict(mask=mask,fd=fd,pid=pid,pidfd=-1,names=[],target=None,error=False)
        if length < 24 or offset+length > len(data):
            event['error'] = True
            yield event
            return
        end = offset+length
        if version != 3 or not 24 <= metadata <= length:
            event['error'] = True
        else:
            pos = offset+metadata
            while pos < end:
                if pos+4 > end:
                    event['error'] = True
                    break
                kind,_,size = struct.unpack_from('=BBH',data,pos)
                if size < 4 or pos+size > end:
                    event['error'] = True
                    break
                if kind == 4 and size >= 8:
                    event['pidfd'] = struct.unpack_from('=i',data,pos+4)[0]
                elif kind == 1 or kind in NAME_TYPES:
                    if size < 20:
                        event['error'] = True
                        break
                    count,handle_type = struct.unpack_from('=Ii',data,pos+12)
                    if count > 128 or 20+count > size:
                        event['error'] = True
                        break
                    handle = (data[pos+4:pos+12],handle_type,data[pos+20:pos+20+count])
                    if kind == 1:
                        event['target'] = handle
                    else:
                        name = data[pos+20+count:pos+size].split(b'\0',1)[0]
                        if name and b'/' not in name and name not in (b'.',b'..'):
                            event['names'].append((handle,os.fsdecode(name)))
                pos += size
        yield event
        offset = end


def process_identity(pid,pidfd):
    """A live pidfd must still name the same process before and after /proc reads."""
    if pid <= 0 or pidfd < 0:
        return None
    def alive():
        try:
            fields = Path(f'/proc/self/fdinfo/{pidfd}').read_text().splitlines()
            return any(line.startswith('Pid:') and int(line.split()[1]) == pid for line in fields)
        except (OSError,ValueError,IndexError):
            return False
    if not alive():
        return None
    try:
        created = psutil.Process(pid).create_time()
    except psutil.Error:
        return None
    return (pid,created) if alive() else None


class FanotifySource:
    def __init__(self,path):
        self.lib = ctypes.CDLL(None,use_errno=True)
        self.lib.fanotify_mark.argtypes = [ctypes.c_int,ctypes.c_uint,ctypes.c_uint64,ctypes.c_int,ctypes.c_char_p]
        self.lib.open_by_handle_at.argtypes = [ctypes.c_int,ctypes.c_void_p,ctypes.c_int]
        self.lib.name_to_handle_at.argtypes = [ctypes.c_int,ctypes.c_char_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_int),ctypes.c_int]
        self.fd = self.lib.fanotify_init(INIT,os.O_RDONLY | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(),'fanotify con identità processo non disponibile')
        self.mount = -1
        self.marks = {}
        try:
            self.mount = os.open(path,os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            self.fsid = struct.pack('=Q',os.statvfs(path).f_fsid & (2**64-1))
            # Verify the privilege required for resolving parent handles before claiming coverage.
            fd = self.open_handle(self.handle(self.mount))
            os.close(fd)
        except BaseException:
            self.close()
            raise

    def handle(self,fd):
        buffer = ctypes.create_string_buffer(136)
        struct.pack_into('=I',buffer,0,128)
        mount_id = ctypes.c_int()
        if self.lib.name_to_handle_at(fd,b'',buffer,ctypes.byref(mount_id),AT_EMPTY_PATH) < 0:
            raise OSError(ctypes.get_errno(),'identità cartella non disponibile')
        size,kind = struct.unpack_from('=Ii',buffer)
        if size > 128:
            raise OSError(errno.EOVERFLOW,'identità cartella troppo lunga')
        return self.fsid,kind,bytes(buffer[8:8+size])

    def open_handle(self,handle):
        fsid,kind,opaque = handle
        if fsid != self.fsid:
            raise OSError(errno.EXDEV,'filesystem differente')
        buffer = ctypes.create_string_buffer(struct.pack('=Ii',len(opaque),kind)+opaque)
        fd = self.lib.open_by_handle_at(self.mount,buffer,os.O_PATH | os.O_CLOEXEC | os.O_DIRECTORY)
        if fd < 0:
            raise OSError(ctypes.get_errno(),'cartella non risolvibile')
        return fd

    def add(self,path,limit=None):
        fd = os.open(path,os.O_PATH | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            handle = self.handle(fd)
            if handle not in self.marks:
                if limit is not None and limit <= 0:
                    raise OSError(errno.ENOSPC,'Limite cartelle raggiunto: copertura parziale')
                if self.lib.fanotify_mark(self.fd,1 | 4 | 8,MASK,fd,None) < 0:
                    raise OSError(ctypes.get_errno(),'sorveglianza cartella non disponibile')
                self.marks[handle] = str(path)
        finally:
            os.close(fd)

    def parent(self,handle):
        fd = self.open_handle(handle)
        try:
            return Path(os.readlink(f'/proc/self/fd/{fd}'))
        finally:
            os.close(fd)

    def prune(self,inside,progress=None):
        last_drain = time.monotonic()
        for index,handle in enumerate(list(self.marks)):
            if progress and (index % 128 == 0 or time.monotonic()-last_drain >= .025):
                progress()
                last_drain = time.monotonic()
            try:
                fd = self.open_handle(handle)
            except OSError as exc:
                if exc.errno == errno.ESTALE:
                    self.marks.pop(handle,None)
                continue
            try:
                path = Path(os.readlink(f'/proc/self/fd/{fd}'))
                current = False
                if inside(path):
                    try:
                        # A mount may have replaced the filesystem at this
                        # pathname while our O_PATH mount descriptor stayed open.
                        current = struct.pack('=Q',os.statvfs(path).f_fsid & (2**64-1)) == self.fsid
                    except OSError:
                        pass
                if not current:
                    if self.lib.fanotify_mark(self.fd,2,MASK,fd,None) == 0:
                        self.marks.pop(handle,None)
            finally:
                os.close(fd)

    def close(self):
        for name in ('fd','mount'):
            fd = getattr(self,name,-1)
            if fd >= 0:
                os.close(fd)
                setattr(self,name,-1)


class FileWatch:
    def __init__(self,roots,max_marks=8192):
        self.roots = tuple(dict.fromkeys(Path(p).resolve() for p in roots))
        self.max_marks = max_marks
        self.behavior = FileBehavior()
        self.sources = {}
        self.errors = set()
        self.lost = 0
        self.unattributed = 0
        self.ready = False
        self.mark_count = 0
        self.stopped = threading.Event()
        self.rescan = True
        self.thread = None
        self.lock = threading.Lock()
        self._drain_cursor = 0
        if not self.roots:
            self.errors.add('Nessuna cartella personale disponibile da sorvegliare')

    def inside(self,path):
        return any(path == root or root in path.parents for root in self.roots)

    def error(self,message):
        with self.lock:
            if len(self.errors) < 16:
                self.errors.add(message)

    def start(self):
        self.thread = threading.Thread(target=self.run,daemon=True)
        self.thread.start()
        return self

    def scan(self):
        self.rescan = False
        for fsid,source in list(self.sources.items()):
            try:
                source.prune(self.inside,self._drain)
            except OSError as exc:
                self.error(f'Aggiornamento cartelle: {exc}')
            if not source.marks:
                source.close()
                del self.sources[fsid]
            self._drain()
        pending_limit = max(1,min(self.max_marks,8192))
        stack = list(self.roots[:pending_limit])
        if len(self.roots) > pending_limit:
            self.error('Limite di cartelle in attesa raggiunto: copertura parziale')
        seen = set()
        count = 0
        mark_count = sum(len(source.marks) for source in self.sources.values())
        last_drain = time.monotonic()
        while stack and not self.stopped.is_set():
            if time.monotonic()-last_drain >= .025:
                self._drain()
                last_drain = time.monotonic()
            path = stack.pop()
            if path in seen:
                continue
            seen.add(path)
            source = None
            try:
                fsid = os.statvfs(path).f_fsid
                source = self.sources.get(fsid)
                if source is None:
                    if len(self.sources) >= 32:
                        self.error('Limite di 32 filesystem raggiunto: copertura parziale')
                        continue
                    source = FanotifySource(path)
                    self.sources[fsid] = source
                before = len(source.marks)
                # Existing marks still need traversal when global capacity is
                # reached; add checks the allowance only for a new handle.
                source.add(path,limit=self.max_marks-mark_count)
                mark_count += len(source.marks)-before
                with os.scandir(path) as entries:
                    for entry in entries:
                        count += 1
                        if count % 256 == 0 or time.monotonic()-last_drain >= .025:
                            self._drain()
                            last_drain = time.monotonic()
                        if self.stopped.is_set():
                            stack.clear()
                            break
                        if count > 200000:
                            self.error('Limite di scansione cartelle raggiunto: copertura parziale')
                            stack.clear()
                            break
                        if entry.is_dir(follow_symlinks=False):
                            if len(stack) < pending_limit:
                                stack.append(Path(entry.path))
                            else:
                                self.error('Limite di cartelle in attesa raggiunto: copertura parziale')
            except OSError as exc:
                self.error(f'{path}: {exc.strerror or str(exc)}')
                if source is not None and not source.marks:
                    source.close()
                    self.sources.pop(fsid,None)
        self._drain()
        with self.lock:
            self.ready = True
            self.mark_count = sum(len(s.marks) for s in self.sources.values())

    def _drain(self,timeout=0,budget=.04):
        """Read queues fairly without letting a busy filesystem stall discovery."""
        sources = {source.fd:source for source in self.sources.values() if source.fd >= 0}
        if not sources or self.stopped.is_set():
            return
        ready,_,_ = select.select(list(sources),[],[],timeout)
        if not ready:
            return
        started = time.monotonic()
        start = self._drain_cursor % len(ready)
        for index in range(len(ready)):
            offset = (start+index) % len(ready)
            fd = ready[offset]
            try:
                self.consume(sources[fd],os.read(fd,65536))
            except BlockingIOError:
                pass
            self._drain_cursor = offset+1
            if time.monotonic()-started >= budget:
                break

    def consume(self,source,data):
        for event in parse_events(data):
            try:
                if event['error'] or event['mask'] & OVERFLOW:
                    with self.lock:
                        self.lost += 1
                    continue
                # Directory notifications trigger discovery, while counters
                # describe non-directory entries (including deleted symlinks).
                if event['mask'] & ONDIR:
                    self.rescan = True
                    continue
                actions = [name for mask,name in ((MODIFY,'modifica'),(RENAME,'rinomina'),(DELETE,'eliminazione')) if event['mask'] & mask]
                if not actions or event['target'] is None:
                    continue
                paths = []
                for parent,name in event['names']:
                    try:
                        path = source.parent(parent)/name
                        if self.inside(path):
                            paths.append(path)
                    except OSError:
                        with self.lock:
                            self.unattributed += 1
                if not paths:
                    continue
                identity = process_identity(event['pid'],event['pidfd'])
                if identity is None:
                    with self.lock:
                        self.unattributed += 1
                    continue
                self.behavior.record(identity,event['target'],actions,str(paths[0]))
            finally:
                for fd in {event['fd'],event['pidfd']}:
                    if fd >= 0:
                        os.close(fd)

    def run(self):
        last_scan = 0
        try:
            while not self.stopped.is_set():
                now = time.monotonic()
                if (self.rescan and now-last_scan >= 1) or now-last_scan >= 60:
                    self.scan()
                    last_scan = time.monotonic()
                if not self.sources:
                    self.stopped.wait(.5)
                    continue
                self._drain(timeout=.25)
        except (OSError,ValueError) as exc:
            self.error(f'Osservatore interrotto: {exc}')
        finally:
            for source in self.sources.values():
                source.close()

    def status(self):
        with self.lock:
            return dict(available=self.ready and self.mark_count > 0 and not self.stopped.is_set() and self.thread is not None and self.thread.is_alive(),
                        roots=[str(p) for p in self.roots],errors=sorted(self.errors),lost=self.lost,
                        unattributed=self.unattributed,limited=bool(self.behavior.overflow))

    def poll(self,rows,ignored):
        return self.behavior.poll(rows,ignored)

    def close(self):
        self.stopped.set()
        if self.thread:
            self.thread.join(2)
