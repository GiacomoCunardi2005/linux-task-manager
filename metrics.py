"""Linux counters and identity-checked process termination; no root or shell commands."""
from pathlib import Path
import re
import os
import socket
import subprocess
from collections import Counter
import time
import psutil
from process_network import ProcessNetwork
from hardware import read, number, disk_devices, gpu_devices, npu_devices, wifi_link, link_details, network_identity, connection_devices


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
        self.last_gpu = {}
        self.last_disk_ids = {}
        self.last_npu = {}
        self.last_processes = {}
        self.last_cpu = psutil.cpu_times(percpu=True)
        self.process_network = ProcessNetwork()

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
        meminfo = memory_counters()
        processes = threads = 0
        rows, previous = [], {}
        for pid in psutil.pids():
            try:
                proc = psutil.Process(pid)
                info = proc.as_dict(['pid','name','create_time','cpu_times','memory_info',
                                     'status','username','uids','num_threads','io_counters','exe','cmdline','ppid'])
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
                'status':info['status'], 'ppid':info['ppid'], 'exe':info['exe'], 'cmdline':info['cmdline'] or [], 'user':info['username'] or 'Non disponibile',
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
                             'shared': getattr(mem, 'shared', 0), 'swap': swap.used, 'swap_total': swap.total,
                             'committed':meminfo.get('Committed_AS'), 'commit_limit':meminfo.get('CommitLimit'),
                             'slab_reclaimable':meminfo.get('SReclaimable'), 'slab_unreclaimable':meminfo.get('SUnreclaim')},
                  'disks': {}, 'nets': {}, 'gpus': {}, 'npus': {}, 'process_rows': rows, 'connections':connection_devices()}
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
                'identity':identity,
                'speed':states[name].speed if name in states and states[name].speed > 0 else None,
                'duplex':{psutil.NIC_DUPLEX_FULL:'Full duplex',psutil.NIC_DUPLEX_HALF:'Half duplex'}.get(states[name].duplex) if name in states else None,
                'mtu':states[name].mtu if name in states else None,
                'mac':next((a.address for a in addresses.get(name,[]) if a.family == psutil.AF_LINK),None),
                'driver':(Path(f'/sys/class/net/{name}/device/driver').resolve().name if Path(f'/sys/class/net/{name}/device/driver').exists() else None),
                'link':link_details(Path(f'/sys/class/net/{name}/device'))}
            if result['nets'][name]['wifi']:
                result['nets'][name].update(wifi_link(name))
        result['process_network_status'] = self.process_network.sample(rows,[(name,d['identity']) for name,d in result['nets'].items() if d['connected']])
        self.last_net_ids = {name:d['identity'] for name,d in result['nets'].items()}
        gpus = gpu_devices()
        clients = self._gpu_clients() if gpus else {}
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
