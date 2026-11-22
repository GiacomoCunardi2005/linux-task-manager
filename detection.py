"""Suspicious-activity heuristics on data the monitor already reads. Not an antivirus: no file signatures."""
from collections import deque
import ctypes
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import threading
import time
import psutil
import pwd
import select

SYSTEM_DIRS = ('/usr/','/bin/','/sbin/','/lib','/opt/','/snap/','/app/','/nix/store/','/var/lib/flatpak/')
KERNEL_THREAD = re.compile(r'(kworker|kthreadd|ksoftirqd|kswapd|migration/|rcu_|watchdog|kblockd|irq/|kcompactd|khugepaged)')
COMMANDS = [
    (re.compile(r'/dev/(tcp|udp)/'),'alta','Apre una connessione di rete dalla shell (/dev/tcp): tipico delle shell remote'),
    (re.compile(r'\b(nc|ncat|netcat)\b[^|;]*\s-[a-z]*[ec]\b'),'alta','Netcat che esegue una shell (-e/-c)'),
    (re.compile(r'\b(python[0-9.]*|perl|ruby|php)\s+-[a-z]*[ce]\b.*socket.*(pty|subprocess|exec|spawn|dup2)'),'alta','Script in linea che collega una shell a un socket'),
    (re.compile(r'stratum\+(tcp|ssl|tls)://|--donate-level|\bxmrig\b|\bcpuminer\b|\bminerd\b'),'alta','Parametri tipici di un miner di criptovalute'),
    (re.compile(r'base64\s+(-d|--decode)[^|;]*\|\s*(ba|z|da)?sh\b'),'alta','Decodifica base64 eseguita direttamente da una shell'),
    (re.compile(r'\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b'),'media','Scarica ed esegue uno script senza salvarlo (curl/wget | sh)'),
]
STARTUP_EXEC = re.compile(r'^\s*Exec\w*\s*=\s*\S*(/dev/shm|/run/shm|/tmp|/var/tmp)/',re.M)
PORTS = {3333:'pool di mining',4444:'shell remota o pool di mining',5555:'pool di mining',7777:'pool di mining',
         14433:'pool di mining',14444:'pool di mining',45700:'pool di mining',1337:'backdoor',31337:'backdoor',6667:'IRC usato da botnet'}
STARTUP_FILES = ('.bashrc','.bash_profile','.profile','.zshrc','.zprofile','.xprofile','.config/fish/config.fish')
# System-wide autostart locations, readable by normal users too.
SYSTEM_STARTUP = ('/etc/crontab','/etc/cron.d/*','/etc/rc.local','/etc/profile.d/*.sh','/etc/xdg/autostart/*.desktop',
                  '/etc/systemd/system/*.service','/etc/systemd/system/*.timer')
STARTUP_GLOBS = ('.config/autostart/*.desktop','.config/systemd/user/**/*.service','.config/systemd/user/**/*.timer','.config/environment.d/*.conf')
MINER_SECONDS, MINER_CORES = 120, 1.0
RANK = {'media':1,'alta':2}


def read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return ''


def system_path(path):
    return path.startswith(SYSTEM_DIRS)


TEMP_TRAPS = (('/tmp','.backup-credentials-{}.txt'),('/var/tmp','wallet-{}.dat'),('/dev/shm','.ssh-key-{}.bak'))
# Hidden names: desktop indexers (Tracker, Baloo) skip dot files, ransomware and intruders enumerate them too.
HOME_TRAPS = (('','.password-backup-{}.txt'),('DOCUMENTS','.contratti-riservati-{}.docx'),('DESKTOP','.portafoglio-crypto-{}.txt'),
              ('DOWNLOAD','.fatture-{}.pdf'),('.ssh','.backup-key-{}.old'))
TRAP_HEADER = b'# Gestione attivita Linux: file trappola. Nessun programma legittimo lo apre; ogni accesso viene segnalato.\n'
IN_ACCESS, IN_MODIFY, IN_ATTRIB, IN_OPEN, IN_DELETE_SELF, IN_MOVE_SELF, IN_IGNORED = 0x1, 0x2, 0x4, 0x20, 0x400, 0x800, 0x8000
FAN_ACCESS, FAN_MODIFY, FAN_OPEN, FAN_MARK_ADD = 0x1, 0x2, 0x20, 0x1
TRAP_EVENTS = [(IN_MODIFY,'alta','modificata (possibile ransomware)'),(IN_MOVE_SELF,'alta','rinominata o spostata (possibile ransomware)'),
               (IN_ATTRIB,'alta','permessi o date cambiati'),(IN_OPEN | IN_ACCESS,'media','aperta o letta'),(IN_DELETE_SELF,'media','eliminata')]


def user_dir(home,key):
    """XDG user folder (Documenti, Scrivania…) from user-dirs.dirs; '' is home itself, other names are relative."""
    if key in ('','.ssh'):
        return Path(home)/key
    match = re.search(rf'^XDG_{key}_DIR="([^"]*)"',read(Path(home)/'.config'/'user-dirs.dirs'),re.M)
    if not match:
        return None
    folder = Path(match[1].replace('$HOME',str(home)))
    return None if folder == Path(home) else folder  # unset XDG folders point at home: avoid a second trap there


def default_places(home=None):
    home = Path(home or Path.home())
    places = [(Path(d),name,0o644) for d,name in TEMP_TRAPS]  # temp traps are world-readable: any user or root trips them
    places += [(folder,name,0o600) for key,name in HOME_TRAPS if (folder := user_dir(home,key)) and folder.is_dir()]
    return places


class Traps:
    """Decoy files watched with inotify, plus fanotify when running as root.

    inotify needs no privileges and fires for every user, root included, but never names the process:
    without root the PID is looked up afterwards among open descriptors (only slow readers of our own user).
    fanotify (root only on this kernel: unprivileged listeners receive PID 0) names every opener.
    """
    def __init__(self,places=None,registry=None,proc=Path('/proc'),owner=None):
        self.places = default_places() if places is None else [(Path(d),name,mode) for d,name,mode in places]
        self.proc = Path(proc)
        self.owner = owner or (os.getuid(),os.getgid())
        cache = Path(os.environ.get('XDG_CACHE_HOME',Path.home()/'.cache'))
        # Persistent (not /run) so traps left in /var/tmp or home by a crash are still removed after a reboot.
        self.registry = Path(registry or cache/'linux-task-manager'/'traps')
        self.paths, self.hits, self.fd, self.fan = {}, [], None, None
        self.fan_lock, self.fan_seen, self.fan_thread = threading.Lock(), {}, None
        self.lookup = lambda pid: None  # ExecWatcher.recent_description when available

    def arm(self):
        libc = ctypes.CDLL(None,use_errno=True)
        self.add_watch = libc.inotify_add_watch
        self.fan_mark = libc.fanotify_mark
        self.fan_mark.argtypes = [ctypes.c_int,ctypes.c_uint,ctypes.c_uint64,ctypes.c_int,ctypes.c_char_p]
        self.fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(),'inotify non disponibile')
        fan = libc.fanotify_init(0x1 | 0x2,os.O_RDONLY | os.O_CLOEXEC | getattr(os,'O_LARGEFILE',0))  # FAN_CLOEXEC | FAN_NONBLOCK
        self.fan = fan if fan >= 0 else None
        if self.fan is not None:
            # A reader like `cat` exits within milliseconds: describe it the moment fanotify reports it.
            self.fan_thread = threading.Thread(target=self.fan_loop,args=(self.fan,),daemon=True)
            self.fan_thread.start()
        self.registry.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.remove_stale()
        for place in self.places:
            try:
                self.create(place)
            except OSError:
                continue  # missing or read-only folder: the other traps still work
        self.save()

    def create(self,place):
        folder,name,mode = place
        path = folder/name.format(secrets.token_hex(4))
        # O_EXCL + O_NOFOLLOW: a planted file or symlink with the same name is never followed or reused.
        fd = os.open(path,os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,mode)
        with os.fdopen(fd,'wb') as handle:
            handle.write(TRAP_HEADER+secrets.token_hex(256).encode()+b'\n')
            if self.owner != (os.getuid(),os.getgid()):
                os.fchown(handle.fileno(),*self.owner)  # root helper: owned by the user, so user-level ransomware can modify it
            os.fchmod(handle.fileno(),mode)
        future = time.time()+5*365*86400
        os.utime(path,(future,future),follow_symlinks=False)  # systemd-tmpfiles keeps files with any recent timestamp
        wd = self.add_watch(self.fd,str(path).encode(),IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_OPEN | IN_DELETE_SELF | IN_MOVE_SELF)
        if wd < 0:
            os.unlink(path)
            raise OSError(ctypes.get_errno(),f'impossibile sorvegliare {path}')
        if self.fan is not None:
            self.fan_mark(self.fan,FAN_MARK_ADD,FAN_ACCESS | FAN_MODIFY | FAN_OPEN,-100,str(path).encode())
        self.paths[wd] = (path,place)

    def save(self):
        me = psutil.Process()
        (self.registry/f'{me.pid}.json').write_text(json.dumps(dict(created=me.create_time(),paths=[str(p) for p,_ in self.paths.values()])))

    def remove_stale(self):
        for entry in self.registry.glob('*.json'):
            try:
                data = json.loads(entry.read_text())
                if psutil.pid_exists(int(entry.stem)) and psutil.Process(int(entry.stem)).create_time() == data['created']:
                    continue
                for path in map(Path,data['paths']):
                    self.unlink(path)
                entry.unlink()
            except (OSError,ValueError,KeyError,TypeError,psutil.Error):
                continue

    def unlink(self,path):
        """Delete only our own regular trap file, never something else placed at that path."""
        try:
            fd = os.open(path,os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                ours = stat.S_ISREG(info.st_mode) and info.st_uid == self.owner[0] and os.read(fd,len(TRAP_HEADER)) == TRAP_HEADER
            finally:
                os.close(fd)
            if ours:
                os.unlink(path)
        except OSError:
            pass

    def openers(self,path):
        found = []
        for fd_dir in self.proc.glob('[0-9]*/fd'):
            try:
                if any(os.readlink(fd_dir/fd) == str(path) for fd in os.listdir(fd_dir)) and int(fd_dir.parent.name) != os.getpid():
                    found.append(int(fd_dir.parent.name))
            except (OSError,ValueError):
                continue
        return found

    @staticmethod
    def describe(pid):
        """(process name, readable description) straight from /proc, or None once the process is gone."""
        try:
            with open(f'/proc/{pid}/comm') as handle:
                name = handle.read().strip()
            with open(f'/proc/{pid}/status') as handle:
                uid = int(next(line for line in handle if line.startswith('Uid:')).split()[1])
        except (OSError,StopIteration,ValueError):
            return None
        try:
            user = pwd.getpwuid(uid).pw_name
        except KeyError:
            user = str(uid)
        try:
            exe = os.readlink(f'/proc/{pid}/exe').removesuffix(' (deleted)')
        except OSError:
            exe = ''
        return name,f"{name}, utente {user}"+(f", {exe}" if exe else '')

    def fan_loop(self,fan):
        while self.fan == fan:
            try:
                ready,_,_ = select.select([fan],[],[],0.5)
                data = os.read(fan,65536) if ready else b''
            except BlockingIOError:
                continue
            except (OSError,ValueError):
                return  # descriptor closed by close()
            offset = 0
            while offset+24 <= len(data):
                length,_,_,_,_,event_fd,pid = struct.unpack_from('IBBHQii',data,offset)
                offset += max(length,24)
                if event_fd < 0:
                    continue
                try:
                    path = os.readlink(f'/proc/self/fd/{event_fd}')
                except OSError:
                    continue
                finally:
                    os.close(event_fd)
                if pid > 0 and pid != os.getpid():
                    description = self.describe(pid) or self.lookup(pid)
                    with self.fan_lock:
                        seen = self.fan_seen.setdefault(path,{})
                        seen[pid] = (time.monotonic(),description or (seen.get(pid) or (0,None))[1])

    def take_fan_seen(self):
        now = time.monotonic()
        with self.fan_lock:
            seen, self.fan_seen = self.fan_seen, {}
        # Events older than a few seconds belong to an inotify batch already reported.
        return {path:{pid:desc for pid,(when,desc) in pids.items() if now-when < 5} for path,pids in seen.items()}

    def poll(self):
        fan_seen = self.take_fan_seen()
        masks = {}
        while True:
            try:
                data = os.read(self.fd,65536)
            except BlockingIOError:
                break
            offset = 0
            while offset < len(data):
                wd,mask,_,size = struct.unpack_from('iIII',data,offset)
                offset += 16+size
                masks[wd] = masks.get(wd,0) | mask
        clock = time.strftime('%H:%M:%S')
        for wd,mask in masks.items():
            if wd not in self.paths:
                continue
            path,place = self.paths[wd]
            if mask & IN_DELETE_SELF:
                mask &= ~IN_ATTRIB  # unlink changes the link count, which inotify reports as IN_ATTRIB
            actions = [(level,text) for bit,level,text in TRAP_EVENTS if mask & bit]
            if actions:
                seen = fan_seen.get(str(path),{})
                pids = sorted(set(seen) | set(self.openers(path)))
                described = [seen.get(pid) or self.describe(pid) or self.lookup(pid) or ('già terminato','già terminato') for pid in pids]
                names = [name for name,_ in described]
                who = (' da '+', '.join(f'PID {pid} ({text})' for pid,(_,text) in zip(pids,described)) if pids else
                       ' (processo non identificabile: già chiuso, o senza il servizio root)')
                level = 'alta' if any(a[0] == 'alta' for a in actions) else 'media'
                self.hits.append(dict(severity=level,pids=pids,names=names,reason=f"{clock} trappola {path} "+', '.join(a[1] for a in actions)+who))
            if mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED):
                # Re-arm with a new name: the old path may now belong to someone else.
                self.paths.pop(wd,None)
                try:
                    self.create(place)
                except OSError:
                    pass
                self.save()
        del self.hits[:-50]
        return self.hits

    def close(self):
        fan, self.fan = self.fan, None  # fan_loop stops when self.fan changes
        if self.fan_thread:
            self.fan_thread.join(1)
            self.fan_thread = None
        if fan is not None:
            os.close(fan)
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        for path,_ in self.paths.values():
            self.unlink(path)
        self.paths = {}
        (self.registry/f'{os.getpid()}.json').unlink(missing_ok=True)


PROC_EVENT_EXEC = 0x2


def parse_proc_events(data):
    """(pid, tgid) of every exec event in a netlink proc-connector datagram."""
    events, offset = [], 0
    while offset+16 <= len(data):
        length = struct.unpack_from('I',data,offset)[0]
        if length < 16:
            break
        body = offset+16+20  # nlmsghdr + cn_msg
        if body+24 <= offset+length:
            what = struct.unpack_from('I',data,body)[0]
            if what == PROC_EVENT_EXEC:
                events.append(struct.unpack_from('ii',data,body+16))
        offset += (length+3) & ~3
    return events


class ExecWatcher(threading.Thread):
    """Linux proc connector: notified on every exec(), so processes shorter than the 1 s sample are seen."""
    def __init__(self,detector):
        super().__init__(daemon=True)
        self.detector = detector
        # pid -> (time, (name, description)) of recent execs: a reader that exits before /proc can be read is
        # still named, because exec is reported before the program opens anything.
        self.recent = {}
        self.sock = socket.socket(socket.AF_NETLINK,socket.SOCK_DGRAM,11)  # NETLINK_CONNECTOR
        self.sock.bind((0,1))  # CN_IDX_PROC multicast group
        message = struct.pack('IHHII',16+20+4,3,0,0,0)+struct.pack('IIIIHH',1,1,0,0,4,0)+struct.pack('I',1)  # PROC_CN_MCAST_LISTEN
        self.sock.send(message)

    def run(self):
        while True:
            try:
                data = self.sock.recv(65536)
            except OSError:
                return
            for pid,tgid in parse_proc_events(data):
                if pid == tgid:
                    row = self.snapshot(tgid)
                    if row:
                        self.remember(row)
                        self.detector.exec_seen(row)

    def remember(self,row):
        try:
            user = pwd.getpwuid(row['uid']).pw_name
        except (KeyError,TypeError):
            user = str(row['uid'])
        self.recent[row['pid']] = (time.monotonic(),(row['name'],f"{row['name']}, utente {user}"+(f", {row['exe']}" if row['exe'] else '')))
        while len(self.recent) > 4096:
            self.recent.pop(next(iter(self.recent)))

    def recent_description(self,pid):
        entry = self.recent.get(pid)
        return entry[1] if entry and time.monotonic()-entry[0] < 300 else None

    @staticmethod
    def snapshot(pid):
        """Raw /proc reads, fastest first: the process may exit within milliseconds of exec()."""
        base = f'/proc/{pid}/'
        uid = exe = None
        try:
            uid = os.stat(base).st_uid  # /proc/PID is owned by the process's user
            exe = os.readlink(base+'exe')
        except OSError:
            pass  # gone, or another user's executable without root
        try:
            with open(base+'cmdline','rb') as handle:
                cmdline = [arg.decode(errors='replace') for arg in handle.read().split(b'\0') if arg]
            with open(base+'stat','rb') as handle:
                stat_line = handle.read().decode(errors='replace')
            created = psutil.Process(pid).create_time()
        except (OSError,psutil.Error):
            return None
        name = stat_line[stat_line.find('(')+1:stat_line.rfind(')')]
        ppid = int(stat_line[stat_line.rfind(')')+2:].split()[1])
        return dict(pid=pid,created=created,name=name,exe=exe and exe.removesuffix(' (deleted)'),cmdline=cmdline,ppid=ppid,uid=uid)

    def close(self):
        self.sock.close()


def validate_threats(threats):
    """Shape check for findings read from the root service file."""
    def ok(value,names,check):
        if not isinstance(value,dict) or any(name not in value or not check(value[name]) for name in names.split()):
            raise ValueError('Dati del servizio root non validi.')
    ok(threats,'processes system traps',lambda v:isinstance(v,list) and len(v) <= 4096)
    for finding in threats['processes']:
        ok(finding,'pid',lambda v:type(v) is int and 0 < v < 2**31)
        ok(finding,'created',lambda v:isinstance(v,(int,float)) and not isinstance(v,bool))
        ok(finding,'reasons',lambda v:isinstance(v,list) and 0 < len(v) <= 32 and all(isinstance(s,str) for s in v))
    for finding in threats['processes']+threats['system']:
        ok(finding,'severity',lambda v:v in ('media','alta'))
    for finding in threats['system']:
        ok(finding,'reason',lambda v:isinstance(v,str))
    if not all(isinstance(s,str) for s in threats['traps']):
        raise ValueError('Dati del servizio root non validi.')
    return threats


def crontab(user=None):
    try:
        result = subprocess.run(['crontab','-l']+(['-u',user] if user else []),capture_output=True,text=True,timeout=2)
        return result.stdout if result.returncode == 0 else ''
    except (OSError,subprocess.SubprocessError):
        return ''


class Detector:
    def __init__(self,home=None,proc=Path('/proc'),usb_root=Path('/sys/bus/usb/devices'),config=None,read_crontab=crontab,traps=None,
                 preload=Path('/etc/ld.so.preload'),system_startup=SYSTEM_STARTUP):
        self.home = Path(home or Path.home())
        self.system_startup = system_startup
        self.preload = Path(preload)
        self.exec_lock, self.exec_pending, self.short_lived = threading.Lock(), {}, []
        self.proc, self.usb_root, self.read_crontab = Path(proc), Path(usb_root), read_crontab
        self.config = Path(config or Path(os.environ.get('XDG_CONFIG_HOME',self.home/'.config'))/'linux-task-manager'/'detection-ignore.txt')
        self.traps = Traps() if traps is None else traps
        self.trap_error = None
        self.static, self.cpu = {}, {}
        self.keyboards = None
        self.startup, self.startup_time = [], -1e9
        self.sockets, self.sockets_time = {}, -1e9

    def ignored(self):
        try:
            return {line.strip() for line in self.config.read_text(encoding='utf-8').splitlines() if line.strip() and not line.startswith('#')}
        except OSError:
            return set()

    def static_reasons(self,row):
        """Exe/cmdline/name do not change for one PID + start time, so these checks run once per process."""
        reasons = []
        exe, name, pid = row.get('exe') or '', row['name'], row['pid']
        # Real kernel threads are kthreadd (PID 2) or its children; this works even without access to other users' exe.
        if KERNEL_THREAD.match(name) and pid != 2 and row.get('ppid') != 2:
            reasons.append(('alta','Nome da thread del kernel, ma non è figlio di kthreadd: processo travestito'))
        try:
            if exe and os.readlink(self.proc/str(pid)/'exe').endswith(' (deleted)') and not system_path(exe):
                reasons.append(('alta',f'Eseguibile cancellato dal disco dopo l’avvio ({exe})'))
        except OSError:
            pass
        if exe.startswith(('/dev/shm/','/run/shm/')):
            reasons.append(('alta',f'Eseguibile in memoria condivisa ({exe})'))
        elif exe.startswith(('/tmp/','/var/tmp/')) and not exe.startswith('/tmp/.mount_'):
            reasons.append(('media',f'Eseguibile in una cartella temporanea ({exe})'))
        command = ' '.join(row.get('cmdline') or [])
        reasons += [(level,text) for pattern,level,text in COMMANDS if pattern.search(command)]
        return reasons

    def socket_ports(self,now):
        # shortcut: 5 s cache; psutil gives a PID only for sockets whose owner's fds are readable (own user).
        if now-self.sockets_time >= 5:
            self.sockets_time, self.sockets = now, {}
            try:
                for conn in psutil.net_connections('inet'):
                    port = conn.raddr.port if conn.raddr else conn.laddr.port if conn.status == psutil.CONN_LISTEN and conn.laddr else None
                    if conn.pid and port in PORTS:
                        self.sockets.setdefault(conn.pid,set()).add((port,'verso '+conn.raddr.ip if conn.raddr else 'in ascolto'))
            except (psutil.Error,OSError):
                pass
        return self.sockets

    def startup_findings(self,now,ignored):
        if now-self.startup_time < 60:
            return self.startup
        self.startup_time, found = now, []
        files = [self.home/name for name in STARTUP_FILES]+[path for pattern in STARTUP_GLOBS for path in sorted(self.home.glob(pattern))]
        files += [path for pattern in self.system_startup for path in sorted(Path('/').glob(pattern.lstrip('/')))]
        texts = []
        for path in files:
            try:
                if path.is_file():
                    texts.append((str(path),path.read_text(encoding='utf-8',errors='replace')[:262144]))
            except OSError:
                continue  # e.g. root-only system files when running as a user
        texts.append(('crontab utente',self.read_crontab()))
        preload = read(self.preload)
        if preload and '/etc/ld.so.preload' not in ignored:
            found.append(dict(severity='alta',reason=f'/etc/ld.so.preload carica {preload.split()[0]} in ogni programma: tecnica tipica dei rootkit'))
        for label,text in texts:
            if label in ignored:
                continue
            found += [dict(severity=level,reason=f'{label}: {reason}') for pattern,level,reason in COMMANDS if pattern.search(text)]
            if STARTUP_EXEC.search(text):
                found.append(dict(severity='media',reason=f'{label}: avvio automatico di un programma da una cartella temporanea'))
        self.startup = found
        return found

    def keyboard_findings(self):
        devices = {}
        for interface in self.usb_root.glob('*:*'):
            if read(interface/'bInterfaceClass') == '03' and read(interface/'bInterfaceProtocol') == '01':
                device = self.usb_root/interface.name.split(':')[0]
                classes = {read(i/'bInterfaceClass') for i in self.usb_root.glob(device.name+':*')}
                devices[device.name] = (read(device/'product') or 'Dispositivo senza nome',read(device/'idVendor')+':'+read(device/'idProduct'),'08' in classes)
        if self.keyboards is None:
            self.keyboards = set(devices)  # keyboards present when monitoring starts are the baseline
        self.keyboards &= set(devices)  # a removed and reinserted keyboard is reported again
        return [dict(severity='alta' if storage else 'media',reason=f'Nuova tastiera USB collegata: {product} ({ids}, porta {port})'
                    +(' che è anche una memoria di massa: possibile BadUSB' if storage else ': se non l’hai collegata tu, può digitare comandi'))
                for port,(product,ids,storage) in sorted(devices.items()) if port not in self.keyboards]

    def assess(self,rows,cores,now=None):
        now = time.monotonic() if now is None else now
        ignored = self.ignored()
        sockets = self.socket_ports(now)
        # A trap opener whose name is on the ignore list (e.g. a backup tool) is not reported.
        trap_hits = [h for h in self.trap_findings(ignored) if not h['names'] or not set(h['names']) <= ignored]
        trapped = {}
        for hit in trap_hits:
            for pid in hit['pids']:
                trapped.setdefault(pid,[]).append((hit['severity'],'Ha aperto un file trappola: '+hit['reason']))
        alive, processes = set(), []
        for row in rows:
            identity = (row['pid'],row['created'])
            alive.add(identity)
            if row.get('exe') in ignored or row['name'] in ignored:
                continue
            if identity not in self.static:
                self.static[identity] = self.static_reasons(row)
            reasons = list(self.static[identity])+trapped.get(row['pid'],[])
            reasons += [('media',f'Connessione sulla porta {port} ({PORTS[port]}), {where}') for port,where in sorted(sockets.get(row['pid'],()))]
            exe = row.get('exe') or ''
            if row.get('cpu') is not None:
                history = self.cpu.setdefault(identity,deque())
                history.append((now,row['cpu']*cores/100))
                while now-history[0][0] > MINER_SECONDS:
                    history.popleft()
                if exe and not system_path(exe) and now-history[0][0] >= MINER_SECONDS-5 and sum(v for _,v in history)/len(history) >= MINER_CORES:
                    reasons.append(('media',f'Usa almeno un core intero da {MINER_SECONDS//60} minuti con un eseguibile fuori dalle cartelle di sistema'))
            if reasons:
                processes.append(dict(pid=row['pid'],created=row['created'],severity=max((r[0] for r in reasons),key=RANK.get),reasons=[r[1] for r in reasons]))
        self.collect_short_lived(alive,ignored)
        self.static = {k:v for k,v in self.static.items() if k in alive}
        self.cpu = {k:v for k,v in self.cpu.items() if k in alive}
        system = []
        for part in (lambda: self.startup_findings(now,ignored),self.keyboard_findings):
            try:
                system += part()
            except OSError as exc:
                system.append(dict(severity='media',reason=f'Controllo non completato: {exc}'))
        system += [dict(severity=hit['severity'],reason=hit['reason']) for hit in trap_hits]+list(self.short_lived)
        return dict(processes=processes,system=system,traps=[str(p) for p,_ in self.traps.paths.values()] if self.traps else [])

    def exec_seen(self,row):
        """Called by ExecWatcher right after exec(): judge the process before it can exit."""
        reasons = self.static_reasons(row)
        if reasons and len(self.exec_pending) < 1000:
            with self.exec_lock:
                self.exec_pending[(row['pid'],row['created'])] = (row,reasons,time.strftime('%H:%M:%S'))

    def collect_short_lived(self,alive,ignored):
        # Processes still alive are reported by the normal row checks; the rest ended before the 1 s sample.
        with self.exec_lock:
            pending, self.exec_pending = self.exec_pending, {k:v for k,v in self.exec_pending.items() if k in alive}
        for identity,(row,reasons,clock) in pending.items():
            if identity in alive or row['name'] in ignored or row.get('exe') in ignored:
                continue
            self.short_lived.append(dict(severity=max((r[0] for r in reasons),key=RANK.get),
                reason=f"{clock} processo di breve durata PID {row['pid']} ({row['name']}): "+'; '.join(r[1] for r in reasons)))
        del self.short_lived[:-50]

    def trap_findings(self,ignored):
        if not self.traps or 'trappole' in ignored:
            self.close()
            return []
        try:
            if self.traps.fd is None and self.trap_error is None:
                self.traps.arm()
            return list(self.traps.hits if self.traps.fd is None else self.traps.poll())
        except OSError as exc:
            self.trap_error = exc
            self.traps.close()
            return []

    def close(self):
        if self.traps:
            self.traps.close()
