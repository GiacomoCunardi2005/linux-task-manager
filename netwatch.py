"""Kernel-side collection for the behavioural network analysis (root service only).

- AF_PACKET with a classic BPF filter: only DNS (UDP 53) and outgoing TCP SYN reach Python, with kernel
  timestamps, so connection start times stay exact even when the interpreter is busy.
- sock_diag destroy multicast: every TCP socket that closes reports its final byte counters, so even a
  200 ms beacon connection has its size.
- `ss -tin` every 5 s: byte counters of long-lived connections, to time heartbeats inside one socket.
No payload beyond DNS headers and names is read; nothing is decrypted.
"""
import ctypes
import ipaddress
import json
import os
import queue
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import threading
import time
import psutil
from netbehavior import NetworkAnalyzer

PACKET_HOST, PACKET_OUTGOING = 0, 4
SO_ATTACH_FILTER, SO_TIMESTAMPNS = 26, 35
LOCAL = ('127.','::1','fe80:','169.254.')
DNS_ASSOCIATION_SECONDS = 300
# Round-robin services (Cloudflare, GitHub, Google) answer each query with a different subset of their pool:
# addresses confirmed for an allowed name are remembered this long, so a long connection is not flagged
# just because the latest answer listed other servers.
ADDRESS_MEMORY = 6*3600


class DNSVerifier:
    """Refresh allowed names off the sampling thread, with bounded concurrency and cache."""
    WORKERS = 4

    def __init__(self):
        self.cache, self.pending = {}, set()
        self.lock = threading.Lock()
        self.closed = False
        # A real queue: checking unnamed destinations against every listed domain used to take all four
        # slots each cycle, so an observed name (e.g. a Discord gateway) never got resolved. Now every
        # requested name waits its turn; fixed workers drain the queue in milliseconds.
        self.queue, self.workers = queue.Queue(), []

    def matches(self,name,ip):
        now = time.monotonic()
        with self.lock:
            if self.closed:
                return False
            stamp,addresses = self.cache.get(name,(float('-inf'),set()))
            age = now-stamp
            if age >= 240 and name not in self.pending:
                self.pending.add(name)
                self.queue.put(name)
                while len(self.workers) < self.WORKERS:
                    worker = threading.Thread(target=self.work,daemon=True)
                    worker.start()
                    self.workers.append(worker)
            return 0 <= age <= DNS_ASSOCIATION_SECONDS and ip in addresses

    def work(self):
        # shortcut: a resolver call that never returns keeps one worker busy; four such hangs would stall checks.
        while (name := self.queue.get()) is not None:
            self.resolve(name)

    def resolve(self,name):
        try:
            answers = socket.getaddrinfo(name+'.',None,socket.AF_UNSPEC,socket.SOCK_STREAM)
            addresses = {str(ipaddress.ip_address(answer[4][0])) for answer in answers}
        except (OSError,ValueError,UnicodeError):
            addresses = set()
        with self.lock:
            self.pending.discard(name)
            if not self.closed:
                now = time.monotonic()
                # A failed lookup forgets everything (stay visible); a successful one adds to recent answers.
                previous = self.cache.pop(name,(0,{}))[1] if addresses else {}
                remembered = {ip:seen for ip,seen in previous.items() if now-seen < ADDRESS_MEMORY}
                remembered.update(dict.fromkeys(addresses,now))
                self.cache[name] = (now,remembered)
                while len(self.cache) > 256:
                    del self.cache[next(iter(self.cache))]

    def state(self,name,ip):
        """Why an allowed name could not confirm this IP, in words shown with the item."""
        with self.lock:
            entry = self.cache.get(name)
        if entry is None or name in self.pending:
            return 'riconferma DNS in corso'
        stamp,addresses = entry
        if not addresses:
            return 'la riconferma DNS è fallita'
        if time.monotonic()-stamp > DNS_ASSOCIATION_SECONDS:
            return 'riconferma DNS scaduta, in rinnovo'
        return f'l’IP non compare tra i {len(addresses)} indirizzi risolti per il nome nelle ultime 6 ore'

    def close(self):
        with self.lock:
            self.closed = True
            self.cache.clear()
            for _ in self.workers:
                self.queue.put(None)


class ReverseDNS:
    """Best-effort PTR names for display only; never used as an allow-list identity."""
    def __init__(self):
        self.cache, self.pending = {}, set()
        self.lock = threading.Lock()
        self.closed = False

    def lookup(self,ip):
        try:
            if not ipaddress.ip_address(ip).is_global:
                return None
        except ValueError:
            return None
        now = time.monotonic()
        with self.lock:
            if self.closed:
                return None
            stamp,name = self.cache.get(ip,(float('-inf'),None))
            age = now-stamp
            if age >= DNS_ASSOCIATION_SECONDS and ip not in self.pending and len(self.pending) < 4:
                self.pending.add(ip)
                threading.Thread(target=self.resolve,args=(ip,),daemon=True).start()
            return name if 0 <= age < DNS_ASSOCIATION_SECONDS else None

    def resolve(self,ip):
        try:
            name = socket.gethostbyaddr(ip)[0].lower().rstrip('.')
            if len(name) > 253 or '.' not in name or not all(
                    re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in name.split('.')):
                name = None
        except (OSError,UnicodeError,ValueError):
            name = None
        with self.lock:
            self.pending.discard(ip)
            if not self.closed:
                self.cache.pop(ip,None)
                self.cache[ip] = (time.monotonic(),name)
                while len(self.cache) > 256:
                    del self.cache[next(iter(self.cache))]

    def close(self):
        with self.lock:
            self.closed = True
            self.cache.clear()


def network_exceptions(path):
    """Read exact IPs and DNS suffixes; invalid lines never suppress findings."""
    try:
        lines = Path(path).read_text(encoding='utf-8').splitlines()
    except (OSError,UnicodeError):
        return set(),set()
    domains, addresses = set(),set()
    for line in lines:
        value = line.split('#',1)[0].strip().lower().rstrip('.')
        if not value:
            continue
        try:
            addresses.add(str(ipaddress.ip_address(value)))
            continue
        except ValueError:
            pass
        if len(value) <= 253 and '.' in value and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in value.split('.')):
            domains.add(value)
    return domains,addresses


def excluded_destination(item,analyzer,exceptions,now,verifier=None):
    if item.get('kind') != 'destinazione' or not item.get('key'):
        return False
    domains,addresses = exceptions
    raw = item['key'].rsplit(':',1)[0].strip('[]')
    try:
        ip = str(ipaddress.ip_address(raw))
    except ValueError:
        return False
    if ip in addresses:
        return True
    name = analyzer.ip_domain.get(ip,'').lower().rstrip('.')
    seen = analyzer.dns_seen_at.get(ip)
    recent = seen is not None and 0 <= now-seen <= DNS_ASSOCIATION_SECONDS

    def allowed_name(value):
        value = value.lower().rstrip('.')
        return any(value == domain or value.endswith('.'+domain) for domain in domains)

    allowed = name and allowed_name(name)
    if recent and not allowed:
        return False  # Do not override a recent, different observed name.
    # Every connection to this destination followed a DNS answer for an allowed name: GitHub, Google and CDNs
    # rotate addresses, so re-resolving later may no longer return this IP, but the contact itself was named.
    record = getattr(analyzer,'contact_names',{}).get(item['key'])
    if record and record['names'] and not record['unbacked'] and all(allowed_name(n) for n in record['names']):
        return True
    if recent:
        return True
    if verifier is None:
        return False
    if allowed and verifier.matches(name,ip):
        return True
    # If no name was observed, resolve only explicitly configured names, not guessed subdomains.
    return any(verifier.matches(domain,ip) for domain in sorted(domains)) if not name else False


def explain_unconfirmed(results,analyzer,exceptions,verifier):
    """An item whose observed name is on the exception list but stayed visible says why."""
    domains = exceptions[0]
    for item in results:
        if item.get('kind') != 'destinazione' or not item.get('key'):
            continue
        ip = item['key'].rsplit(':',1)[0].strip('[]')
        name = analyzer.ip_domain.get(ip,'').lower().rstrip('.')
        if name and any(name == d or name.endswith('.'+d) for d in domains):
            record = getattr(analyzer,'contact_names',{}).get(item['key'])
            why = ('alcune connessioni sono partite senza richiesta DNS' if record and record['unbacked']
                   else verifier.state(name,ip) if verifier else 'nessuna riconferma DNS disponibile')
            item['evidence'] = item.get('evidence',[])+[f'«{name}» è tra le eccezioni ma non è confermato: {why}']


def bpf_program():
    """Accept IPv4/IPv6 UDP port 53 and TCP segments with SYN set and ACK clear (offsets from the IP header)."""
    LDB, LDH, LDXMSH, LDBX, LDHX, AND, JEQ, RET = 0x30, 0x28, 0xb1, 0x50, 0x48, 0x54, 0x15, 0x06
    program = [
        (LDB,'',0),(AND,'',0xf0),(JEQ,('v6',None),0x60),(JEQ,(None,'drop'),0x40),
        (LDB,'',9),(JEQ,('v4udp',None),17),(JEQ,(None,'drop'),6),
        (LDXMSH,'',0),(LDBX,'',13),(AND,'',0x12),(JEQ,('accept','drop'),0x02),
        ('v4udp',),(LDXMSH,'',0),(LDHX,'',0),(JEQ,('accept',None),53),(LDHX,'',2),(JEQ,('accept','drop'),53),
        ('v6',),(LDB,'',6),(JEQ,('v6udp',None),17),(JEQ,(None,'drop'),6),
        (LDB,'',53),(AND,'',0x12),(JEQ,('accept','drop'),0x02),
        ('v6udp',),(LDH,'',40),(JEQ,('accept',None),53),(LDH,'',42),(JEQ,('accept','drop'),53),
        ('accept',),(RET,'',0x40000),('drop',),(RET,'',0)]
    labels, code = {}, []
    for item in program:
        if len(item) == 1:
            labels[item[0]] = len(code)
        else:
            code.append(item)
    out = []
    for index,(op,jumps,k) in enumerate(code):
        jt = jf = 0
        if jumps:
            target_t,target_f = jumps
            jt = labels[target_t]-index-1 if target_t else 0
            jf = labels[target_f]-index-1 if target_f else 0
        out.append(struct.pack('HBBI',op,jt,jf,k))
    return out


def attach_filter(sock):
    instructions = bpf_program()
    buffer = ctypes.create_string_buffer(b''.join(instructions))
    program = struct.pack('HxxxxxxQ',len(instructions),ctypes.addressof(buffer))
    sock.setsockopt(socket.SOL_SOCKET,SO_ATTACH_FILTER,program)
    return buffer  # must outlive the socket's filter setup


def parse_ip(packet):
    """(src, dst, protocol, transport payload) for IPv4/IPv6 packets starting at the IP header."""
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4 and len(packet) >= 20:
        header = (packet[0] & 15)*4
        return socket.inet_ntop(socket.AF_INET,packet[12:16]),socket.inet_ntop(socket.AF_INET,packet[16:20]),packet[9],packet[header:]
    if version == 6 and len(packet) >= 40:
        return socket.inet_ntop(socket.AF_INET6,packet[8:24]),socket.inet_ntop(socket.AF_INET6,packet[24:40]),packet[6],packet[40:]
    return None


def read_name(data,offset):
    labels, jumps, end = [], 0, None
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xc0 == 0xc0:
            if offset+1 >= len(data) or jumps > 20:
                raise ValueError('nome DNS non valido')
            end = end or offset+2
            offset, jumps = ((length & 0x3f) << 8) | data[offset+1], jumps+1
            continue
        labels.append(data[offset+1:offset+1+length].decode('ascii','replace'))
        offset += 1+length
    return '.'.join(labels),(end or offset)


def parse_dns(data):
    """Header, first question and A/AAAA answers of a DNS message."""
    if len(data) < 12:
        raise ValueError('DNS troppo corto')
    _,flags,questions,answers = struct.unpack_from('>HHHH',data)
    if questions < 1:
        raise ValueError('nessuna domanda')
    name,offset = read_name(data,12)
    qtype = struct.unpack_from('>H',data,offset)[0]
    offset += 4
    ips = []
    for _ in range(min(answers,64)):
        _,offset = read_name(data,offset)
        rtype,_,_,length = struct.unpack_from('>HHIH',data,offset)
        offset += 10
        if rtype == 1 and length == 4:
            ips.append(socket.inet_ntop(socket.AF_INET,data[offset:offset+4]))
        elif rtype == 28 and length == 16:
            ips.append(socket.inet_ntop(socket.AF_INET6,data[offset:offset+16]))
        offset += length
    return dict(name=name,qtype=qtype,response=bool(flags & 0x8000),rcode=flags & 15,ips=ips)


def parse_destroy(data,include_cookie=False):
    """(family, src, sport, dst, dport, bytes_acked, bytes_received) from sock_diag destroy messages."""
    events, offset = [], 0
    while offset+16+72 <= len(data):
        length = struct.unpack_from('I',data,offset)[0]
        if length < 16+72 or offset+length > len(data):
            break
        body = offset+16
        family = data[body]
        if family not in (socket.AF_INET,socket.AF_INET6):
            offset += (length+3) & ~3
            continue
        sport,dport = struct.unpack_from('>HH',data,body+4)
        size = 4 if family == socket.AF_INET else 16
        src = socket.inet_ntop(family,data[body+8:body+8+size])
        dst = socket.inet_ntop(family,data[body+24:body+24+size])
        acked = received = None
        attribute = body+72
        while attribute+4 <= offset+length:
            alen,atype = struct.unpack_from('HH',data,attribute)
            if alen < 4 or attribute+alen > offset+length:
                break
            if atype == 2 and alen >= 4+136:  # INET_DIAG_INFO: struct tcp_info
                acked,received = struct.unpack_from('QQ',data,attribute+4+120)
            attribute += (alen+3) & ~3
        record = (family,src,sport,dst,dport,acked,received)
        low,high = struct.unpack_from('=II',data,body+44)
        cookie = (high << 32) | low
        events.append(record+(cookie if cookie != 2**64-1 else None,) if include_cookie else record)
        offset += (length+3) & ~3
    return events


def local(address):
    return address.startswith(LOCAL) or address in ('::','0.0.0.0')


def socket_owner(pid,fd,inode):
    """Validate current ownership, not the process name in an older ss snapshot."""
    pidfd = -1
    try:
        pidfd = os.pidfd_open(pid)
        link = f'/proc/{pid}/fd/{fd}'
        expected = f'socket:[{inode}]'
        if os.readlink(link) != expected:
            return None
        process = psutil.Process(pid)
        created,name = process.create_time(),process.name()
        try:
            exe = process.exe() or None
        except psutil.Error:
            exe = None
        after = psutil.Process(pid)
        if os.readlink(link) != expected or after.create_time() != created or after.name() != name:
            return None
        try:
            if after.exe() != (exe or ''):
                return None
        except psutil.Error:
            if exe is not None:
                return None
        if select.select([pidfd],[],[],0)[0]:
            return None
        name = ''.join(c if c.isprintable() else '?' for c in name)[:256]
        exe = ''.join(c if c.isprintable() else '?' for c in exe)[:4096] if exe else None
        return dict(pid=pid,created=created,name=name,exe=exe,socket_inode=inode,fd=fd)
    except (OSError,psutil.Error,ValueError):
        return None
    finally:
        if pidfd >= 0:
            os.close(pidfd)


class NetWatch:
    def __init__(self,baseline_path,uid=None,include_loopback=False,ignore_path=None):
        self.path, self.uid, self.loopback = Path(baseline_path), uid, include_loopback
        self.ignore_path = ignore_path
        self.dns_verifier = DNSVerifier()
        self.reverse_dns = ReverseDNS()
        try:
            baseline = json.loads(self.path.read_text())
        except (OSError,ValueError):
            baseline = None
        self.analyzer = NetworkAnalyzer(baseline)
        self.lock = threading.Lock()
        self.starts = {}  # (src, sport, dst, dport) -> SYN time, for connection duration
        self.features = dict(capture=False,closes=False,flows=False)
        self.results, self.times = [], dict(snapshot=0.,idle=0.,analyze=0.,save=time.time())
        self.sockets, self.running = [], True

    def start(self):
        for name,opener,loop in (('capture',self.open_capture,self.capture_loop),('closes',self.open_closes,self.closes_loop)):
            try:
                sock = opener()
            except OSError:
                continue
            self.sockets.append(sock)
            self.features[name] = True
            threading.Thread(target=loop,args=(sock,),daemon=True).start()
        return self

    # ---------- packet capture ----------
    def open_capture(self):
        sock = socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x0003))
        self.filter = attach_filter(sock)
        sock.setsockopt(socket.SOL_SOCKET,SO_TIMESTAMPNS,1)
        return sock

    def capture_loop(self,sock):
        while self.running:
            try:
                data,ancillary,_,address = sock.recvmsg(65535,64)
            except OSError:
                return
            stamp = next((struct.unpack('qq',value[:16]) for level,kind,value in ancillary if kind == SO_TIMESTAMPNS),None)
            t = stamp[0]+stamp[1]/1e9 if stamp else time.time()
            try:
                self.packet(t,data,address[0],address[2])
            except (ValueError,struct.error,IndexError):
                continue

    def packet(self,t,data,interface,kind):
        loop = interface == 'lo'
        if loop and kind != PACKET_HOST:
            return  # loopback traffic is seen twice
        parsed = parse_ip(data)
        if not parsed:
            return
        src,dst,protocol,payload = parsed
        sport,dport = struct.unpack_from('>HH',payload)
        if protocol == 17:
            message = parse_dns(payload[8:])
            with self.lock:
                self.analyzer.dns_event(t,message['name'],message['qtype'],message['rcode'],message['response'],message['ips'])
        elif protocol == 6 and (kind == PACKET_OUTGOING or (loop and self.loopback)):
            if local(dst) and not self.loopback:
                return
            with self.lock:
                self.starts[(src,sport,dst,dport)] = t
                self.analyzer.syn(t,dst,dport)

    # ---------- socket destruction ----------
    def open_closes(self):
        sock = socket.socket(socket.AF_NETLINK,socket.SOCK_DGRAM,4)  # NETLINK_SOCK_DIAG
        sock.bind((0,1 | 4))  # SKNLGRP_INET_TCP_DESTROY | SKNLGRP_INET6_TCP_DESTROY
        return sock

    def closes_loop(self,sock):
        while self.running:
            try:
                data = sock.recv(1 << 20)
            except OSError:
                return
            t = time.time()
            for _,src,sport,dst,dport,acked,received,cookie in parse_destroy(data,include_cookie=True):
                with self.lock:
                    tuple4 = (src,sport,dst,dport)
                    tracked = self.analyzer.flows.get((tuple4,cookie))
                    start = tracked.get('started') if tracked is not None else None
                    ambiguous = tracked is None and any(key[0] == tuple4 and key[1] != cookie for key in self.analyzer.flows)
                    if start is None and not ambiguous:
                        start = self.starts.get(tuple4)
                    if start is None and tracked is None and tuple4 not in self.starts:
                        continue
                    if start is not None and self.starts.get(tuple4) == start:
                        self.starts.pop(tuple4,None)
                    self.analyzer.close(t,dst,dport,max(0,acked-1) if acked is not None else None,
                                        max(0,received-1) if received is not None else None,
                                        t-start if start is not None and t >= start else None,tuple4=tuple4,token=cookie)

    # ---------- periodic work, called every second by the service ----------
    def flows(self):
        output = subprocess.run(['ss','-tineH','state','established'],capture_output=True,text=True,timeout=2).stdout
        found, current = [], None
        for line in output.splitlines():
            if not line.startswith((' ','\t')):
                parts = line.split()
                if len(parts) >= 4:
                    local_end,peer = parts[2],parts[3]
                    cookie = re.search(r'\bsk:([0-9a-fA-F]+)',line)
                    current = (*local_end.rsplit(':',1),*peer.rsplit(':',1),int(cookie[1],16) if cookie else None)
                continue
            sent = re.search(r'bytes_acked:(\d+)',line)
            received = re.search(r'bytes_received:(\d+)',line)
            if current and (sent or received):
                src,sport,dst,dport = (current[0].strip('[]'),int(current[1]),current[2].strip('[]'),int(current[3]))
                if self.loopback or not local(dst):
                    found.append((src,sport,dst,dport,max(0,int(sent[1])-1) if sent else None,
                                  int(received[1]) if received else None,current[4]))
            current = None
        return found

    def attribute(self,results):
        """One bounded-time snapshot; only inode- and lifetime-verified live owners."""
        targets = {}
        with self.lock:
            self.analyzer.processes.clear()
        for result in results:
            result['process'],result['owners'],result['process_observed_at'] = None,[],None
            key = result.get('key')
            if not key or result.get('score',0) < 40 or len(targets) >= 10:
                continue
            try:
                address,port = key.rsplit(':',1)
                address,port = str(ipaddress.ip_address(address.strip('[]'))),int(port)
                if 0 < port < 65536:
                    targets[(address,port)] = key
            except ValueError:
                continue
        if not targets:
            return
        filters = []
        for address,port in targets:
            if filters:
                filters.append('or')
            filters.extend(['(','dst',address if ':' not in address else f'[{address}]','and','dport','=',f':{port}',')'])
        try:
            response = subprocess.run(['ss','-tnpeH','state','established',*filters],capture_output=True,text=True,timeout=2)
            if response.returncode:
                return
        except (OSError,subprocess.SubprocessError):
            return
        owners = {key:[] for key in targets.values()}
        for line in response.stdout[:2*1024*1024].splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                address,port = parts[3].rsplit(':',1)
                key = targets.get((str(ipaddress.ip_address(address.strip('[]'))),int(port)))
            except ValueError:
                continue
            inode = re.search(r'\bino:(\d+)',line)
            if key is None or not inode or len(owners[key]) >= 32:
                continue
            for pid,fd in re.findall(r'pid=(\d+),fd=(\d+)',line):
                owner = socket_owner(int(pid),int(fd),int(inode[1]))
                if owner is not None and owner not in owners[key]:
                    owners[key].append(owner)
                    if len(owners[key]) >= 32:
                        break
        stamp = time.time()
        for result in results:
            found = owners.get(result.get('key'),[])
            if found:
                result['owners'],result['process_observed_at'] = found,stamp
                names = sorted({(o['name'],o['pid'],o.get('exe') or 'percorso del file non disponibile') for o in found})
                result['process'] = ', '.join(f'{name} (PID {pid}, {exe})' for name,pid,exe in names[:3])[:1999]

    def user_idle(self):
        if self.uid is None:
            return None
        try:
            value = subprocess.run(['loginctl','show-user',str(self.uid),'-p','IdleHint','--value'],
                                   capture_output=True,text=True,timeout=5).stdout.strip()
        except (OSError,subprocess.SubprocessError):
            return None
        return value == 'yes' if value in ('yes','no') else None

    def poll(self,now=None):
        now = time.time() if now is None else now
        if now-self.times['snapshot'] >= 5:
            self.times['snapshot'] = now
            try:
                query_started = time.monotonic()
                flows = self.flows()
                now += max(0,time.monotonic()-query_started)
                with self.lock:
                    self.analyzer.snapshot(now,flows,starts=self.starts)
                    self.features['flow_accounting_limited'] = self.analyzer.flow_loss_time != float('-inf')
                self.features['flows'] = True
            except (OSError,subprocess.SubprocessError):
                self.features['flows'] = False
        if now-self.times['idle'] >= 60:
            self.times['idle'] = now
            idle = self.user_idle()
            if idle is not None:
                with self.lock:
                    self.analyzer.user_idle(now,idle)
        if now-self.times['analyze'] >= 30:
            self.times['analyze'] = now
            with self.lock:
                self.starts = {k:v for k,v in self.starts.items() if now-v < 6*3600}
                results = self.analyzer.analyze(now)
                if self.ignore_path:
                    exceptions = network_exceptions(self.ignore_path)
                    results = [item for item in results if not excluded_destination(item,self.analyzer,exceptions,now,self.dns_verifier)]
                    explain_unconfirmed(results,self.analyzer,exceptions,self.dns_verifier)
            for item in results[:50]:
                key = item.get('key')
                if item.get('kind') == 'destinazione' and key and item.get('subject') == key:
                    name = self.reverse_dns.lookup(key.rsplit(':',1)[0].strip('[]'))
                    if name:
                        item['reverse_name'] = name
            self.attribute(results)
            self.results = results[:50]
        if now-self.times['save'] >= 300:
            self.save()
        return self.results

    def save(self):
        self.times['save'] = time.time()
        try:
            self.path.parent.mkdir(parents=True,exist_ok=True)
            temporary = self.path.with_suffix('.tmp')
            with self.lock:
                temporary.write_text(json.dumps(self.analyzer.base))
            os.replace(temporary,self.path)
        except OSError:
            pass

    def close(self):
        self.running = False
        self.dns_verifier.close()
        self.reverse_dns.close()
        for sock in self.sockets:
            sock.close()
        self.save()
