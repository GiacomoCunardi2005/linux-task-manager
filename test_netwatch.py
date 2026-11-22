"""Kernel collection tested for real inside a private network namespace (unshare -rn gives CAP_NET_RAW/ADMIN there)."""
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import unittest
from netwatch import bpf_program, parse_dns

SCENARIO = r'''
import json, random, socket, struct, subprocess, sys, tempfile, threading, time
sys.path.insert(0, sys.argv[1])
from netwatch import NetWatch
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)

def query(name, qid):
    labels = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0'
    return struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0) + labels + struct.pack('>HH', 1, 1)

def dns_server(sock):
    while True:
        data, peer = sock.recvfrom(512)
        end = data.index(b'\0', 12) + 5
        known = b'\x06beacon\x07example\x00' in data
        answer = b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 60, 4) + socket.inet_aton('127.0.0.9') if known else b''
        sock.sendto(data[:2] + struct.pack('>HHHHH', 0x8180 if known else 0x8183, 1, int(known), 0, 0) + data[12:end] + answer, peer)

dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); dns.bind(('127.0.0.53', 53))
threading.Thread(target=dns_server, args=(dns,), daemon=True).start()
server = socket.socket(); server.bind(('127.0.0.9', 8443)); server.listen()
def serve():
    while True:
        conn, _ = server.accept(); conn.recv(4096); conn.sendall(b'k' * 900); conn.close()
threading.Thread(target=serve, daemon=True).start()
holder = socket.socket(); holder.bind(('127.0.0.9', 9443)); holder.listen()
kept = []
threading.Thread(target=lambda: kept.append(holder.accept()[0]), daemon=True).start()  # keep it: dropping it closes

watch = NetWatch(tempfile.mktemp(), include_loopback=True).start()
time.sleep(.2)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); client.settimeout(2)
for i in range(3):
    client.sendto(query('beacon.example', i), ('127.0.0.53', 53)); client.recv(512)
    c = socket.create_connection(('127.0.0.9', 8443)); c.sendall(b'x' * 400); c.recv(4096); c.close()
    time.sleep(.1)
for i in range(5):
    client.sendto(query(''.join(random.choice('qwxzjkv0123') for _ in range(14)) + '.com', 10 + i), ('127.0.0.53', 53)); client.recv(512)
long = socket.create_connection(('127.0.0.9', 9443)); long.sendall(b'y' * 1234); time.sleep(.3)
flows = watch.flows()
a = watch.analyzer
deadline = time.time() + 5
while len(a.conns) < 3 and time.time() < deadline:  # close events can lag under load
    time.sleep(.05)
print(json.dumps(dict(
    features=watch.features,
    syns=len(a.events.get('127.0.0.9:8443', [])),
    closes=[[c[2], c[3], round(c[4], 3)] for c in a.conns],
    nx=sorted({d[1] for d in a.dns if d[4] and d[3] == 3}),
    queries=len([d for d in a.dns if not d[4]]),
    domain=a.ip_domain.get('127.0.0.9'),
    dns_before=a.dns_before.get('127.0.0.9:8443'),
    long_flow=[f[4] for f in flows if f[3] == 9443])))
watch.close()
'''


@unittest.skipUnless(shutil.which('unshare') and shutil.which('ip') and shutil.which('ss'),'unshare, ip o ss mancanti')
class KernelCollectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run = subprocess.run(['unshare','-rn',sys.executable,'-c',SCENARIO,str(Path(__file__).resolve().parent)],
                             capture_output=True,text=True,timeout=60)
        if run.returncode != 0 and 'unshare' in run.stderr and 'Operation not permitted' in run.stderr:
            raise unittest.SkipTest('namespace utente non consentiti su questo sistema')
        if run.returncode != 0:
            raise AssertionError(run.stderr[-2000:])
        cls.result = json.loads(run.stdout.strip().splitlines()[-1])

    def test_both_kernel_sources_open(self):
        self.assertEqual(self.result['features'],dict(capture=True,closes=True,flows=False))

    def test_syn_and_close_with_exact_bytes_and_duration(self):
        self.assertEqual(self.result['syns'],3)
        for sent,received,_ in self.result['closes']:  # the FIN, once acknowledged, also counts as one byte
            self.assertIn(sent,(400,401))
            self.assertEqual(received,900)
        self.assertEqual(len(self.result['closes']),3)
        self.assertTrue(all(0 <= c[2] < 1 for c in self.result['closes']))

    def test_dns_queries_answers_and_nxdomain(self):
        self.assertEqual(self.result['domain'],'beacon.example')
        self.assertEqual(len(self.result['nx']),5)
        self.assertEqual(self.result['queries'],8)
        self.assertEqual(self.result['dns_before'],[3,3])  # each of the three connections followed its DNS answer

    def test_long_lived_flow_counters_from_ss(self):
        self.assertEqual(self.result['long_flow'],[1235])  # bytes_acked includes the SYN; only deltas are used


class ParserTests(unittest.TestCase):
    def test_compressed_answers_and_malformed_input(self):
        message = (struct.pack('>HHHHHH',7,0x8180,1,2,0,0)+b'\x03www\x07example\x03com\x00'+struct.pack('>HH',1,1)
                   +b'\xc0\x0c'+struct.pack('>HHIH',5,1,60,6)+b'\x03cdn\xc0\x10'  # CNAME, pointer inside the name
                   +b'\xc0\x2d'+struct.pack('>HHIH',1,1,60,4)+bytes([192,0,2,1]))
        parsed = parse_dns(message)
        self.assertEqual((parsed['name'],parsed['response'],parsed['rcode'],parsed['ips']),('www.example.com',True,0,['192.0.2.1']))
        for broken in (b'',b'\x00'*11,struct.pack('>HHHHHH',1,0,1,0,0,0)+b'\xc0\x0c'):
            with self.assertRaises((ValueError,struct.error)):
                parse_dns(broken)

    def test_bpf_program_is_well_formed(self):
        program = bpf_program()
        self.assertTrue(all(len(i) == 8 for i in program))
        for index,instruction in enumerate(program):
            op,jt,jf,_ = struct.unpack('HBBI',instruction)
            self.assertLess(index+jt+1,len(program)+1)
            self.assertLess(index+jf+1,len(program)+1)


if __name__ == '__main__':
    unittest.main()
