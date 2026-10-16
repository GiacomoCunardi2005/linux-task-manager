"""Linux counters and identity-checked process termination; no root or shell commands."""
from pathlib import Path
import re
import os
import socket
import time
import psutil


def read(path, default=''):
    try:
        return Path(path).read_text().strip()
    except (OSError, UnicodeError):
        return default


def number(path):
    try:
        return int(read(path))
    except ValueError:
        return None


def rate(current, previous, elapsed):
    return max(0, current - previous) / max(elapsed, .001)


def cpu_usage(current, previous):
    # Linux includes guest time in user/nice already.
    def total(t):
        return sum(t) - getattr(t, "guest", 0) - getattr(t, "guest_nice", 0)
    elapsed = total(current) - total(previous)
    idle = current.idle - previous.idle + getattr(current, "iowait", 0) - getattr(previous, "iowait", 0)
    return max(0, min(100, (elapsed-idle)/elapsed*100)) if elapsed > 0 else 0


def size(value):
    if value is None:
        return 'Non disponibile'
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if abs(value) < 1024 or unit == 'TB':
            return f'{value:.1f} {unit}'
        value /= 1024


def percent(value):
    return 'Non disponibile' if value is None else f'{value:.0f}%'


def uptime(seconds):
    days, rest = divmod(int(seconds), 86400)
    hours, rest = divmod(rest, 3600)
    minutes, seconds = divmod(rest, 60)
    return f'{days}:{hours:02}:{minutes:02}:{seconds:02}'


class Monitor:
    def __init__(self):
        self.cpuinfo = read('/proc/cpuinfo')
        self.cpu_name = next((x.split(':', 1)[1].strip() for x in self.cpuinfo.splitlines() if x.startswith('model name')), 'CPU Linux')
        self.cpu_details = self._cpu_details()
        self.disks = [p.name for p in sorted(Path('/sys/block').glob('*')) if not p.name.startswith(('loop', 'ram', 'zram', 'dm-'))]
        self.nets = [name for name in psutil.net_io_counters(pernic=True) if name != 'lo']
        self.gpus = []
        for card in sorted(Path('/sys/class/drm').glob('card[0-9]*')):
            if not re.fullmatch(r'card\d+', card.name):
                continue
            device = card / 'device'
            vendor = read(device / 'vendor')
            brand = {'0x8086': 'Intel Graphics', '0x1002': 'AMD Radeon', '0x10de': 'NVIDIA'}.get(vendor, 'GPU')
            self.gpus.append({'card': card, 'name': brand, 'pci': device.resolve().name, 'driver': (device / 'driver').resolve().name})
        self.last_time = time.monotonic()
        self.last_disks = psutil.disk_io_counters(perdisk=True)
        self.last_net = psutil.net_io_counters(pernic=True)
        self.last_gpu = {}
        self.last_processes = {}
        self.last_cpu = psutil.cpu_times(percpu=True)

    def _cpu_details(self):
        sockets = set(re.findall(r'^physical id\s*:\s*(.+)$', self.cpuinfo, re.M))
        base = number('/sys/devices/system/cpu/cpu0/cpufreq/base_frequency')
        details = [('Velocità di base:', f'{base/1e6:.2f} GHz' if base else 'Non disponibile'),
                   ('Socket:', str(len(sockets)) if sockets else 'Non disponibile'),
                   ('Core:', str(psutil.cpu_count(logical=False) or 'Non disponibile')),
                   ('Processori logici:', str(psutil.cpu_count() or 'Non disponibile')),
                   ('Virtualizzazione:', 'Supportata' if re.search(r'\b(vmx|svm)\b', self.cpuinfo) else 'Non disponibile')]
        for level in (1, 2, 3):
            entries = {}
            for cache in Path('/sys/devices/system/cpu').glob('cpu[0-9]*/cache/index*'):
                if read(cache / 'level') == str(level):
                    entries[(read(cache / 'shared_cpu_list'), read(cache / 'type'))] = read(cache / 'size')
            total = sum(int(v[:-1]) * (1024 if v.endswith('K') else 1024**2) for v in entries.values() if re.fullmatch(r'\d+[KM]', v))
            details.append((f'Cache L{level}:', size(total) if total else 'Non disponibile'))
        return details

    def _gpu_clients(self):
        clients = {}
        # shortcut: fdinfo covers only accessible clients; use a privileged GPU backend if system-wide Intel accounting is required.
        for proc in Path('/proc').glob('[0-9]*'):
            try:
                files = list((proc / 'fd').iterdir())
            except OSError:
                continue
            for fd in files:
                try:
                    if not os.readlink(fd).startswith('/dev/dri/'):
                        continue
                except OSError:
                    continue
                data = read(proc / 'fdinfo' / fd.name)
                if 'drm-client-id:' not in data:
                    continue
                fields = dict(line.split(':', 1) for line in data.splitlines() if ':' in line)
                pci = fields.get('drm-pdev', '').strip()
                cid = fields['drm-client-id'].strip()
                engines = {}
                for key, value in fields.items():
                    if key.startswith('drm-engine-') and value.strip().endswith(' ns'):
                        engines[key.removeprefix('drm-engine-')] = int(value.split()[0])
                clients[(pci, cid)] = engines
        return clients

    def sample(self):
        now = time.monotonic()
        dt = now - self.last_time
        times = psutil.cpu_times(percpu=True)
        cores = [cpu_usage(cur,prev) for cur,prev in zip(times,self.last_cpu)]
        self.last_cpu = times
        freq = psutil.cpu_freq()
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        processes = threads = 0
        rows, previous = [], {}
        for pid in psutil.pids():
            try:
                proc = psutil.Process(pid)
                info = proc.as_dict(['pid','name','create_time','cpu_times','memory_info',
                                     'status','username','uids','num_threads','io_counters'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            processes += 1
            threads += info['num_threads'] or 0
            identity = (pid,info['create_time'])
            cpu = info['cpu_times']
            cpu_time = cpu.user+cpu.system if cpu else None
            io = info['io_counters']
            io_bytes = io.read_bytes+io.write_bytes if io else None
            old_cpu,old_io = self.last_processes.get(identity,(None,None))
            previous[identity] = (cpu_time,io_bytes)
            rows.append({'pid':pid, 'created':info['create_time'], 'name':info['name'] or str(pid),
                'status':info['status'], 'user':info['username'] or 'Non disponibile',
                'uid':info['uids'].real if info['uids'] else None,
                'cpu': min(100,rate(cpu_time,old_cpu,dt)*100/max(1,len(times))) if cpu_time is not None and old_cpu is not None else None,
                'memory':info['memory_info'].rss if info['memory_info'] else None,
                'disk':rate(io_bytes,old_io,dt) if io_bytes is not None and old_io is not None else None})
        self.last_processes = previous
        result = {'cpu': {'value': sum(cores)/len(cores) if cores else 0, 'cores': cores,
                          'freq': freq.current/1000 if freq else None, 'processes': processes,
                          'threads': threads, 'files': read('/proc/sys/fs/file-nr').split()[0] if read('/proc/sys/fs/file-nr') else 'N/D', 'uptime': time.time()-psutil.boot_time()},
                  'memory': {'value': (mem.total-mem.available)/mem.total*100, 'total': mem.total,
                             'used': mem.total-mem.available, 'available': mem.available,
                             'cached': getattr(mem, 'cached', 0), 'buffers': getattr(mem, 'buffers', 0),
                             'shared': getattr(mem, 'shared', 0), 'swap': swap.used, 'swap_total': swap.total},
                  'disks': {}, 'nets': {}, 'gpus': {}, 'process_rows': rows}
        disks = psutil.disk_io_counters(perdisk=True)
        for name in self.disks:
            cur, prev = disks.get(name), self.last_disks.get(name)
            if not cur or not prev:
                continue
            ios = max(0, cur.read_count+cur.write_count-prev.read_count-prev.write_count)
            result['disks'][name] = {'value': min(100, rate(cur.busy_time, prev.busy_time, dt)/10),
                'read': rate(cur.read_bytes, prev.read_bytes, dt), 'write': rate(cur.write_bytes, prev.write_bytes, dt),
                'latency': max(0, cur.read_time+cur.write_time-prev.read_time-prev.write_time)/ios if ios else 0,
                'capacity': (number(f'/sys/block/{name}/size') or 0)*512,
                'model': read(f'/sys/block/{name}/device/model', name),
                'type': 'HDD' if read(f'/sys/block/{name}/queue/rotational') == '1' else 'SSD'}
        nets = psutil.net_io_counters(pernic=True)
        addresses = psutil.net_if_addrs()
        states = psutil.net_if_stats()
        for name in self.nets:
            cur, prev = nets.get(name), self.last_net.get(name)
            if not cur or not prev:
                continue
            sent = rate(cur.bytes_sent, prev.bytes_sent, dt)*8
            received = rate(cur.bytes_recv, prev.bytes_recv, dt)*8
            result['nets'][name] = {'value': max(sent, received), 'sent': sent, 'received': received,
                'ipv4': next((a.address for a in addresses.get(name, []) if a.family == socket.AF_INET), 'Non disponibile'),
                'ipv6': next((a.address.split('%')[0] for a in addresses.get(name, []) if a.family == socket.AF_INET6), 'Non disponibile'),
                'connected': bool(states.get(name) and states[name].isup),
                'wifi': Path(f'/sys/class/net/{name}/wireless').exists()}
        clients = self._gpu_clients() if self.gpus else {}
        for index, gpu in enumerate(self.gpus):
            device = gpu['card'] / 'device'
            busy = number(device / 'gpu_busy_percent')
            engines = {}
            found = False
            for key, values in clients.items():
                if key[0] != gpu['pci']:
                    continue
                found = True
                for engine, value in values.items():
                    old = self.last_gpu.get(key, {}).get(engine)
                    if old is not None:
                        engines[engine] = engines.get(engine, 0) + rate(value, old, dt)/1e7
            if busy is None and found and engines:
                busy = min(100, max(engines.values()))
            result['gpus'][str(index)] = {'value': busy, 'engines': {k:min(100,v) for k,v in engines.items()},
                'vram': number(device / 'mem_info_vram_used'), 'vram_total': number(device / 'mem_info_vram_total'),
                'freq': number(gpu['card'] / 'gt_cur_freq_mhz'), 'driver': gpu['driver'],
                'pci': gpu['pci'], 'name': gpu['name'], 'partial': not (device / 'gpu_busy_percent').exists()}
        self.last_time, self.last_disks, self.last_net, self.last_gpu = now, disks, nets, clients
        return result


def terminate_process(pid, created):
    """Terminate exactly the selected identity, never a recycled PID or a tree."""
    if pid in (0,1,os.getpid()) or created is None:
        raise ValueError('Questo processo non può essere terminato dall’app.')
    proc = psutil.Process(pid)
    if proc.create_time() != created:
        raise psutil.NoSuchProcess(pid, msg='Il PID appartiene ora a un altro processo.')
    if proc.uids().real != os.getuid():
        raise PermissionError('Puoi terminare soltanto i processi del tuo utente.')
    proc.terminate()
