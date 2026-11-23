"""Linux counters and identity-checked process termination. Root work happens only in the separate rootservice."""
from pathlib import Path
import json
import math
import re
import os
import stat
import socket
import subprocess
from collections import Counter
import time
import psutil
from process_network import ProcessNetwork
from detection import Detector, ExecWatcher, ProcessScanner, validate_threats
from hardware import read, number, disk_devices, gpu_devices, npu_devices, wifi_link, link_details, network_identity, connection_devices, network_hardware


ROOT_STATE = Path('/run/linux-task-manager/state.json')
ROOT_TERMINATE = Path('/opt/linux-task-manager-root/terminate')


def root_state(path=ROOT_STATE, owner=0):
    """Findings of the root service, trusted only from a fresh root-owned file nobody else can write."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as handle:
            info = os.fstat(handle.fileno())
            data = json.loads(handle.read(8*1024*1024))
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            return None
        if data.get('version') != 1 or data.get('user') != os.getuid() or not abs(time.time()-data.get('time',0)) < 5:
            return None
        validate_threats(data['threats'])
        if not valid_network(data.get('network')):
            return None
        extra = data['processes']
        if not isinstance(extra, dict) or not all(valid_process_observation(v) for v in extra.values()):
            return None
        return data
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


def valid_network(network):
    """Shape of the behavioural network ranking published by the root service (absent on older services)."""
    if network is None:
        return True
    if not isinstance(network, dict) or not isinstance(network.get('anomalies'), list) or len(network['anomalies']) > 200:
        return False
    text = lambda v: isinstance(v, str) and len(v) < 2000
    def owners(a):
        records = a.get('owners',[])
        stamp = a.get('process_observed_at')
        return isinstance(records,list) and len(records) <= 32 and (
            stamp is None or type(stamp) in (int,float) and math.isfinite(stamp) and stamp > 0) and all(
            isinstance(o,dict) and type(o.get('pid')) is int and o['pid'] > 0
            and type(o.get('created')) in (int,float) and math.isfinite(o['created']) and o['created'] > 0
            and text(o.get('name')) and (o.get('exe') is None or isinstance(o['exe'],str) and len(o['exe']) <= 4096)
            and type(o.get('socket_inode')) is int and o['socket_inode'] > 0
            and type(o.get('fd')) is int and o['fd'] >= 0 for o in records)
    return all(isinstance(a, dict) and text(a.get('subject')) and text(a.get('kind'))
               and isinstance(a.get('score'), (int, float)) and 0 <= a['score'] <= 100
               and isinstance(a.get('evidence'), list) and len(a['evidence']) <= 30 and all(text(e) for e in a['evidence'])
               and (a.get('process') is None or text(a['process'])) and owners(a) for a in network['anomalies'])


def compatible_image(local,observed):
    """Independent scanners can compare image observations, not their local generation numbers."""
    if not isinstance(observed,dict):
        return False
    for key in ('boot_id','start_ticks','image_fingerprint','name'):
        if local.get(key) is not None and observed.get(key) is not None and local[key] != observed[key]:
            return False
    return not (local.get('cmdline') and observed.get('cmdline') and local['cmdline'] != observed['cmdline'])


def compatible_finding(local,observed):
    if not isinstance(observed,dict) or not all(observed.get(k) is not None for k in ('boot_id','start_ticks','name')):
        return False
    return compatible_image(local,observed)


def valid_process_observation(row):
    if not isinstance(row,dict) or not isinstance(row.get('exe'),(str,type(None))):
        return False
    number = lambda v: type(v) in (int,float) and math.isfinite(v) and v >= 0
    if row.get('disk') is not None and not number(row['disk']):
        return False
    if 'boot_id' not in row:
        return True  # compatible file format; these older extras are not merged
    integers = ('pid','start_ticks','ppid','memory','threads','exec_generation')
    if not all(type(row.get(k)) is int and row[k] >= 0 for k in integers):
        return False
    if not isinstance(row['boot_id'],str) or not row['boot_id'] or len(row['boot_id']) > 128:
        return False
    if not all(number(row.get(k)) for k in ('created','observed_at')):
        return False
    if not all(k in row and (row[k] is None or number(row[k])) for k in
               ('cpu','disk','cpu_cores','io_read','io_write','io_read_bytes','io_write_bytes','uid')):
        return False
    if not all(isinstance(row.get(k),str) for k in ('name','user','status')):
        return False
    if not isinstance(row.get('cmdline'),list) or not all(isinstance(v,str) for v in row['cmdline']):
        return False
    fingerprint = row.get('image_fingerprint')
    return fingerprint is None or isinstance(fingerprint,str) and re.fullmatch('[0-9a-f]{64}',fingerprint) is not None


def root_process_row(local,observed):
    """Use an entire root sample only when its lifetime and observable image still match."""
    if not valid_process_observation(observed) or not observed.get('boot_id') or not observed.get('start_ticks'):
        return None  # an older service cannot identify exec generations safely
    required = ('pid','created','boot_id','start_ticks')
    if any(local.get(k) != observed.get(k) for k in required) or not compatible_image(local,observed):
        return None
    fields = ('name','exe','cmdline','uid','user','ppid','status','memory','threads','cpu','disk',
              'cpu_cores','io_read','io_write','io_read_bytes','io_write_bytes','exec_generation','image_fingerprint','observed_at')
    if not all(k in observed for k in fields):
        return None
    return {k:observed[k] for k in (*required,*fields)}


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


def parse_memory_hardware(properties):
    """Decode systemd's cached SMBIOS properties, never infer missing modules."""
    devices = {}
    slots = None
    for line in properties.splitlines():
        key, separator, value = line.partition('=')
        if not separator:
            continue
        if key == 'MEMORY_ARRAY_NUM_DEVICES' and value.isdecimal():
            slots = int(value) or None
        match = re.fullmatch(r'MEMORY_DEVICE_(\d+)_(SIZE|PRESENT|FORM_FACTOR|TYPE|CONFIGURED_SPEED_MTS|SPEED_MTS)',key)
        if match:
            devices.setdefault(match[1],{})[match[2]] = value.strip()
    def positive(value):
        return int(value) if value and value.isdecimal() and int(value) > 0 else None
    populated = [device for device in devices.values() if positive(device.get('SIZE')) or device.get('PRESENT') == '1']
    complete = bool(devices) and all(positive(d.get('SIZE')) or d.get('PRESENT') == '0' for d in devices.values())
    complete = complete and slots is not None and len(devices) == slots
    def summary(key, numeric=False):
        values = [d.get(key) for d in populated]
        if not complete or not values or any(not v or v in ('Unknown','Other','<OUT OF SPEC>','Not Specified') for v in values):
            return None
        if numeric:
            numbers = [positive(v) for v in values]
            return ' / '.join(str(v) for v in sorted(set(numbers)))+' MT/s' if all(numbers) else None
        return ' / '.join(sorted(set(values))).replace('SODIMM','SO-DIMM')
    capacities = [positive(d.get('SIZE')) for d in populated]
    installed = sum(capacities) if complete and capacities and all(capacities) else None
    modules = ', '.join(f'{count} × {size(capacity)}' for capacity,count in sorted(Counter(capacities).items())) if installed else None
    return {'speed':summary('CONFIGURED_SPEED_MTS',True), 'rated_speed':summary('SPEED_MTS',True),
        'type':summary('TYPE'), 'form_factor':summary('FORM_FACTOR'),
        'slots_used':len(populated) if complete else None, 'slots_total':slots,
        'installed':installed, 'modules':modules}


def memory_hardware():
    try:
        result = subprocess.run(['udevadm','info','--query=property','--path=/sys/devices/virtual/dmi/id'],
            capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=2)
        return parse_memory_hardware(result.stdout if result.returncode == 0 else '')
    except (OSError,subprocess.TimeoutExpired):
        return parse_memory_hardware('')


def memory_counters():
    fields = {}
    for line in read('/proc/meminfo').splitlines():
        key,_,value = line.partition(':')
        parts = value.split()
        if len(parts) == 2 and parts[1] == 'kB' and parts[0].isdecimal():
            fields[key] = int(parts[0])*1024
    return fields


class Monitor:
    def __init__(self):
        self.cpuinfo = read('/proc/cpuinfo')
        self.cpu_name = next((x.split(':', 1)[1].strip() for x in self.cpuinfo.splitlines() if x.startswith('model name')), 'CPU Linux')
        self.cpu_details = self._cpu_details()
        self.memory_hardware = memory_hardware()
        self.last_time = time.monotonic()
        self.last_disks = psutil.disk_io_counters(perdisk=True,nowrap=False)
        self.last_net = psutil.net_io_counters(pernic=True,nowrap=False)
        self.last_net_ids = {name:network_identity(name) for name in self.last_net}
        self.net_hardware = {}
        self.last_gpu = {}
        self.last_disk_ids = {}
        self.last_npu = {}
        self.scanner = ProcessScanner()
        self.light = False  # set while the window is hidden in the tray: skip work only the charts need
        self.last_cpu = psutil.cpu_times(percpu=True)
        self.process_network = ProcessNetwork()
        self.detector = Detector()
        try:
            # The proc connector accepts unprivileged listeners on this kernel; without it, 1 s sampling still applies.
            self.exec_watcher = ExecWatcher(self.detector,on_exec=self.scanner.exec_seen)
            if self.detector.traps:
                self.detector.traps.lookup = self.exec_watcher.recent_description
            self.exec_watcher.start()
        except (OSError,RuntimeError):
            self.exec_watcher = None

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

    def security(self,rows,cores,result):
        state = root_state()
        if state:
            # The root service sees every process and owns the traps while it runs; local traps are removed.
            self.detector.close()
            for row in rows:
                extra = state['processes'].get(f"{row['pid']}:{row['created']!r}")
                observed = root_process_row(row,extra)
                if observed:
                    row.update(observed)
            current = {(r['pid'],r['created']):r for r in rows}
            findings = [f for f in state['threats']['processes'] if (f['pid'],f['created']) in current
                        and compatible_finding(current[(f['pid'],f['created'])],f.get('image'))]
            result['threats'], result['protection'], result['network'] = dict(state['threats'],processes=findings), 'root', state.get('network')
        else:
            result['threats'], result['protection'], result['network'] = self.detector.assess(rows,cores), 'utente', None
        result['root_available'] = ROOT_TERMINATE.exists()

    def sample(self):
        now = time.monotonic()
        dt = now - self.last_time
        times = psutil.cpu_times(percpu=True)
        cores = [cpu_usage(cur,prev) for cur,prev in zip(times,self.last_cpu)]
        self.last_cpu = times
        freq = psutil.cpu_freq()
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        meminfo = memory_counters()
        rows = self.scanner.rows()
        processes, threads = self.scanner.processes, self.scanner.threads
        result = {'cpu': {'value': sum(cores)/len(cores) if cores else 0, 'cores': cores,
                          'freq': freq.current/1000 if freq else None, 'processes': processes,
                          'threads': threads, 'files': read('/proc/sys/fs/file-nr').split()[0] if read('/proc/sys/fs/file-nr') else 'N/D', 'uptime': time.time()-psutil.boot_time()},
                  'memory': {'value': (mem.total-mem.available)/mem.total*100, 'total': mem.total,
                             'used': mem.total-mem.available, 'available': mem.available,
                             'cached': getattr(mem, 'cached', 0), 'buffers': getattr(mem, 'buffers', 0),
                             'shared': getattr(mem, 'shared', 0), 'swap': swap.used, 'swap_total': swap.total,
                             'committed':meminfo.get('Committed_AS'), 'commit_limit':meminfo.get('CommitLimit'),
                             'slab_reclaimable':meminfo.get('SReclaimable'), 'slab_unreclaimable':meminfo.get('SUnreclaim')},
                  'disks': {}, 'nets': {}, 'gpus': {}, 'npus': {}, 'process_rows': rows,
                  'connections':[] if self.light else connection_devices()}
        if self.light:
            # Hidden in the tray only security needs data. Device counters and last_time stay untouched,
            # so the next full sample reports correct average rates over the hidden period.
            self.security(rows,len(times),result)
            result['light'] = True
            return result
        disks = psutil.disk_io_counters(perdisk=True,nowrap=False)
        metadata = disk_devices()
        for name,device in metadata.items():
            cur, prev = disks.get(name), self.last_disks.get(name)
            ready = cur is not None and prev is not None and self.last_disk_ids.get(name) == device['identity']
            ios = max(0,cur.read_count+cur.write_count-prev.read_count-prev.write_count) if ready else 0
            result['disks'][name] = {**device,
                'value':min(100,rate(cur.busy_time,prev.busy_time,dt)/10) if ready else None,
                'read':rate(cur.read_bytes,prev.read_bytes,dt) if ready else None,
                'write':rate(cur.write_bytes,prev.write_bytes,dt) if ready else None,
                'latency':max(0,cur.read_time+cur.write_time-prev.read_time-prev.write_time)/ios if ios else (0 if ready else None)}
        for partition in psutil.disk_partitions():
            if not partition.device.startswith('/dev/'):
                continue
            block = Path('/sys/class/block')/Path(partition.device).name
            parent = block.resolve().parent.name
            name = block.name if block.name in result['disks'] else parent
            if name in result['disks']:
                result['disks'][name].setdefault('mounts',[]).append(f'{partition.mountpoint} ({partition.fstype})')
        self.last_disk_ids = {name:d['identity'] for name,d in metadata.items()}
        nets = psutil.net_io_counters(pernic=True,nowrap=False)
        addresses = psutil.net_if_addrs()
        states = psutil.net_if_stats()
        for name in sorted(nets):
            if name == 'lo':
                continue
            cur, prev = nets.get(name), self.last_net.get(name)
            if not cur:
                continue
            identity = network_identity(name)
            if name not in self.net_hardware or self.last_net_ids.get(name) != identity:
                self.net_hardware[name] = network_hardware(Path('/sys/class/net')/name)
            if self.last_net_ids.get(name) != identity or (prev and (cur.bytes_sent < prev.bytes_sent or cur.bytes_recv < prev.bytes_recv)):
                prev = None
            prev = prev or cur
            sent = rate(cur.bytes_sent, prev.bytes_sent, dt)*8
            received = rate(cur.bytes_recv, prev.bytes_recv, dt)*8
            result['nets'][name] = {'value': max(sent, received), 'sent': sent, 'received': received,
                'ipv4': next((a.address for a in addresses.get(name, []) if a.family == socket.AF_INET), 'Non disponibile'),
                'ipv6': next((a.address.split('%')[0] for a in addresses.get(name, []) if a.family == socket.AF_INET6), 'Non disponibile'),
                'connected': bool(states.get(name) and states[name].isup and read(f'/sys/class/net/{name}/carrier') != '0'),
                'wifi': Path(f'/sys/class/net/{name}/wireless').exists(),
                'identity':identity, 'hardware':self.net_hardware[name],
                'speed':states[name].speed if name in states and states[name].speed > 0 else None,
                'duplex':{psutil.NIC_DUPLEX_FULL:'Full duplex',psutil.NIC_DUPLEX_HALF:'Half duplex'}.get(states[name].duplex) if name in states else None,
                'mtu':states[name].mtu if name in states else None,
                'mac':next((a.address for a in addresses.get(name,[]) if a.family == psutil.AF_LINK),None),
                'driver':(Path(f'/sys/class/net/{name}/device/driver').resolve().name if Path(f'/sys/class/net/{name}/device/driver').exists() else None),
                'link':link_details(Path(f'/sys/class/net/{name}/device'))}
            if result['nets'][name]['wifi']:
                result['nets'][name].update(wifi_link(name))
        result['process_network_status'] = self.process_network.sample(rows,[(name,d['identity']) for name,d in result['nets'].items() if d['connected']])
        self.security(rows,len(times),result)
        self.last_net_ids = {name:d['identity'] for name,d in result['nets'].items()}
        self.net_hardware = {name:self.net_hardware[name] for name in result['nets']}
        gpus = gpu_devices()
        clients = self._gpu_clients() if gpus and not self.light else {}
        for gpu in gpus:
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
            result['gpus'][gpu['card'].name] = {'value': busy, 'engines': {k:min(100,v) for k,v in engines.items()},
                'vram': number(device / 'mem_info_vram_used'), 'vram_total': number(device / 'mem_info_vram_total'),
                'freq': number(gpu['card'] / 'gt_cur_freq_mhz'), 'driver': gpu['driver'],
                'identity':str(device.resolve()),
                'pci': gpu['pci'], 'name': gpu['name'], 'partial': not (device / 'gpu_busy_percent').exists()}
        npus = npu_devices()
        for name,device in npus.items():
            previous = self.last_npu.get(name)
            ready = previous is not None and previous['identity'] == device['identity'] and device['busy'] is not None and previous['busy'] is not None and device['busy'] >= previous['busy']
            result['npus'][name] = {**device,'value':min(100,rate(device['busy'],previous['busy'],dt)/10000) if ready else None}
        self.last_npu = npus
        self.last_time, self.last_disks, self.last_net, self.last_gpu = now, disks, nets, clients
        return result


    def close(self):
        self.process_network.close()
        self.detector.close()  # removes the trap files
        if self.exec_watcher:
            self.exec_watcher.close()


def terminate_as_root(targets):
    """Other users' processes: one pkexec call (admin password) to the root helper, identity-checked there too."""
    # shortcut: blocks the window while the polkit dialog is open; move to QProcess if that becomes a problem.
    result = subprocess.run(['pkexec', str(ROOT_TERMINATE)]+[f"{pid}:{created!r}" for pid, created in targets],
                            capture_output=True, text=True, timeout=300)
    if result.returncode in (126, 127):
        raise PermissionError('Autorizzazione di amministratore negata o annullata.')
    if result.returncode != 0:
        raise PermissionError(result.stderr.strip() or 'Il servizio root ha rifiutato la richiesta.')
    return dict(line.split(' ', 1) for line in result.stdout.splitlines() if ' ' in line)


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
