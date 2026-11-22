"""Kernel-side collection for the behavioural network analysis (root service only).

- AF_PACKET with a classic BPF filter: only DNS (UDP 53) and outgoing TCP SYN reach Python, with kernel
  timestamps, so connection start times stay exact even when the interpreter is busy.
- sock_diag destroy multicast: every TCP socket that closes reports its final byte counters, so even a
  200 ms beacon connection has its size.
- `ss -tin` every 5 s: byte counters of long-lived connections, to time heartbeats inside one socket.
No payload beyond DNS headers and names is read; nothing is decrypted.
"""
import ctypes
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import threading
import time
from netbehavior import NetworkAnalyzer

PACKET_HOST, PACKET_OUTGOING = 0, 4
SO_ATTACH_FILTER, SO_TIMESTAMPNS = 26, 35
LOCAL = ('127.','::1','fe80:','169.254.')


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


def parse_destroy(data):
    """(family, src, sport, dst, dport, bytes_acked, bytes_received) from sock_diag destroy messages."""
    events, offset = [], 0
    while offset+16+72 <= len(data):
        length = struct.unpack_from('I',data,offset)[0]
        if length < 16:
            break
        body = offset+16
        family = data[body]
        sport,dport = struct.unpack_from('>HH',data,body+4)
        size = 4 if family == socket.AF_INET else 16
        src = socket.inet_ntop(family,data[body+8:body+8+size])
        dst = socket.inet_ntop(family,data[body+24:body+24+size])
        acked = received = None
        attribute = body+72
        while attribute+4 <= offset+length:
            alen,atype = struct.unpack_from('HH',data,attribute)
            if alen < 4:
                break
            if atype == 2 and alen >= 4+136:  # INET_DIAG_INFO: struct tcp_info
                acked,received = struct.unpack_from('QQ',data,attribute+4+120)
            attribute += (alen+3) & ~3
        events.append((family,src,sport,dst,dport,acked,received))
        offset += (length+3) & ~3
    return events


def local(address):
    return address.startswith(LOCAL) or address in ('::','0.0.0.0')


class NetWatch:
    def __init__(self,baseline_path,uid=None,include_loopback=False):
        self.path, self.uid, self.loopback = Path(baseline_path), uid, include_loopback
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
            for _,src,sport,dst,dport,acked,received in parse_destroy(data):
                with self.lock:
                    start = self.starts.pop((src,sport,dst,dport),None)
                    if start is None or acked is None:
                        continue  # not a connection this machine opened while we watched
                    self.analyzer.close(t,dst,dport,max(0,acked-1),max(0,received-1),t-start)  # SYN and FIN count as one byte each

    # ---------- periodic work, called every second by the service ----------
    def flows(self):
        output = subprocess.run(['ss','-tinH','state','established'],capture_output=True,text=True,timeout=5).stdout
        found, current = [], None
        for line in output.splitlines():
            if not line.startswith((' ','\t')):
                parts = line.split()
                if len(parts) >= 4:
                    local_end,peer = parts[-2],parts[-1]
                    current = (*local_end.rsplit(':',1),*peer.rsplit(':',1))
                continue
            sent = re.search(r'bytes_acked:(\d+)',line)
            received = re.search(r'bytes_received:(\d+)',line)
            if current and sent:
                src,sport,dst,dport = (current[0].strip('[]'),int(current[1]),current[2].strip('[]'),int(current[3]))
                if self.loopback or not local(dst):
                    found.append((src,sport,dst,dport,int(sent[1]),int(received[1]) if received else 0))
            current = None
        return found

    def attribute(self,results):
        """Process names only for destinations worth a look: a full socket-to-process scan is costly."""
        for result in results[:10]:
            key = result.get('key')
            if not key or result['score'] < 40:
                continue
            ip,port = key.rsplit(':',1)
            try:
                output = subprocess.run(['ss','-tpH','dst',ip if ':' not in ip else f'[{ip}]','dport','=',f':{port}'],
                                        capture_output=True,text=True,timeout=5).stdout
            except (OSError,subprocess.SubprocessError):
                continue
            names = sorted(set(re.findall(r'\("([^"]+)",pid=(\d+)',output)))
            if names:
                self.analyzer.processes[key] = ', '.join(f'{name} (PID {pid})' for name,pid in names[:3])
                result['process'] = self.analyzer.processes[key]

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
                flows = self.flows()
                with self.lock:
                    self.analyzer.snapshot(now,flows)
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
        for sock in self.sockets:
            sock.close()
        self.save()
