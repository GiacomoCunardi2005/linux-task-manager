"""Kernel collection tested for real inside a private network namespace (unshare -rn gives CAP_NET_RAW/ADMIN there)."""
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from netwatch import bpf_program, parse_dns, network_exceptions, excluded_destination, NetWatch, DNSVerifier, ReverseDNS
from netbehavior import NetworkAnalyzer


class NetworkExceptionsTests(unittest.TestCase):
    def test_idn_alert_is_not_hidden_by_destination_exceptions(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'ignore.txt'
            path.write_text('spotify.com\n192.0.2.1\n')
            watch = NetWatch(Path(folder)/'baseline.json',ignore_path=path)
            self.addCleanup(watch.close)
            watch.analyzer.dns_event(100,'xn--bcher-kva.spotify.com',1,0,True,['192.0.2.1'])
            watch.analyzer.syn(101,'192.0.2.1',443)
            with patch.object(watch,'flows',return_value=[]), patch.object(watch,'user_idle',return_value=None), \
                 patch.object(watch,'attribute'):
                results = watch.poll(102)
            self.assertEqual([item['kind'] for item in results],['idn'])

    def test_reverse_dns_is_async_display_only_and_expires(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'ignore.txt'
            path.write_text('spotify.com\n')
            watch = NetWatch(Path(folder)/'baseline.json',ignore_path=path)
            self.addCleanup(watch.close)
            item = dict(kind='destinazione',key='8.8.8.8:443',subject='8.8.8.8:443',score=90)
            started,release = threading.Event(),threading.Event()
            def reverse(ip):
                started.set()
                release.wait(3)
                return ('host.spotify.com',[],[ip])
            with patch('netwatch.socket.gethostbyaddr',side_effect=reverse), \
                 patch.object(watch,'flows',return_value=[]), patch.object(watch,'user_idle',return_value=None), \
                 patch.object(watch,'attribute'), patch.object(watch.analyzer,'analyze',side_effect=lambda now:[dict(item)]), \
                 patch('netwatch.socket.getaddrinfo',side_effect=socket.gaierror('no answer')):
                try:
                    self.assertEqual(watch.poll(500),[item])
                    self.assertTrue(started.wait(1))
                finally:
                    release.set()
                # Join the pending worker before checking the next snapshot.
                for _ in range(100):
                    with watch.reverse_dns.lock:
                        pending = bool(watch.reverse_dns.pending)
                    if not pending:
                        break
                    threading.Event().wait(.01)
                result = watch.poll(531)
                self.assertEqual(result[0]['reverse_name'],'host.spotify.com')
                self.assertEqual(watch.analyzer.ip_domain,{})
                stamp = watch.reverse_dns.cache['8.8.8.8'][0]
                with patch('netwatch.time.monotonic',return_value=stamp+301), patch('netwatch.threading.Thread'):
                    self.assertIsNone(watch.reverse_dns.lookup('8.8.8.8'))
                self.assertIsNone(watch.reverse_dns.lookup('127.0.0.1'))

    def test_explicit_domain_resolution_without_observed_dns(self):
        verifier = DNSVerifier()
        self.addCleanup(verifier.close)
        analyzer = NetworkAnalyzer(now=100)
        domain = 'gew4-dealer-ssl.spotify.com'
        exceptions = ({domain},set())
        item = dict(kind='destinazione',key='192.0.2.34:443')
        answer = [(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.34',0))]
        with patch('netwatch.socket.getaddrinfo',return_value=answer):
            verifier.resolve(domain)
        self.assertTrue(excluded_destination(item,analyzer,exceptions,100,verifier))
        self.assertFalse(excluded_destination(item,analyzer,(set(),set()),100,verifier))
        analyzer.dns_event(100,'other.example',1,0,True,['192.0.2.34'])
        self.assertFalse(excluded_destination(item,analyzer,exceptions,101,verifier))
        with patch('netwatch.socket.getaddrinfo',return_value=[]):
            verifier.resolve(domain)
        analyzer.ip_domain.clear()
        analyzer.dns_seen_at.clear()
        self.assertFalse(excluded_destination(item,analyzer,exceptions,102,verifier))

    def test_round_robin_answers_are_remembered_but_failures_forget(self):
        verifier = DNSVerifier()
        self.addCleanup(verifier.close)
        answer = lambda *ips: [(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,0)) for ip in ips]
        with patch('netwatch.socket.getaddrinfo',return_value=answer('140.82.113.26')):
            verifier.resolve('alive.github.com')
        with patch('netwatch.socket.getaddrinfo',return_value=answer('140.82.112.26')):
            verifier.resolve('alive.github.com')  # the pool rotated
        self.assertTrue(verifier.matches('alive.github.com','140.82.113.26'))
        self.assertTrue(verifier.matches('alive.github.com','140.82.112.26'))
        stamp = verifier.cache['alive.github.com'][0]
        with patch('netwatch.time.monotonic',return_value=stamp+6*3600+1), \
             patch('netwatch.socket.getaddrinfo',return_value=answer('140.82.114.26')):
            verifier.resolve('alive.github.com')  # six hours later the old addresses are forgotten
            self.assertFalse(verifier.matches('alive.github.com','140.82.113.26'))
        with patch('netwatch.socket.getaddrinfo',side_effect=OSError):
            verifier.resolve('alive.github.com')
        self.assertFalse(verifier.matches('alive.github.com','140.82.114.26'))

    def test_expired_spotify_dns_is_verified_without_blocking_poll(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'ignore.txt'
            path.write_text('spotify.com\n')
            watch = NetWatch(Path(folder)/'baseline.json',ignore_path=path)
            self.addCleanup(watch.close)
            watch.analyzer.dns_event(100,'api-partner.spotify.com',1,0,True,['192.0.2.1'])
            items = [dict(kind='destinazione',key='192.0.2.1:443',score=90),dict(kind='spike',score=80)]
            release,started = threading.Event(),threading.Event()
            threads = []
            real_thread = threading.Thread
            def thread(*args,**kwargs):
                worker = real_thread(*args,**kwargs)
                threads.append(worker)
                return worker
            def resolve(*args):
                started.set()
                release.wait(3)
                return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.1',0))]
            with patch('netwatch.socket.getaddrinfo',side_effect=resolve) as resolver, \
                 patch('netwatch.threading.Thread',side_effect=thread), \
                 patch.object(watch,'flows',return_value=[]), patch.object(watch,'user_idle',return_value=None), \
                 patch.object(watch,'attribute'), patch.object(watch.analyzer,'analyze',return_value=items):
                try:
                    self.assertEqual(watch.poll(500),items)  # the pending resolver cannot block sampling
                    self.assertTrue(started.wait(1))
                    self.assertFalse(watch.dns_verifier.matches('api-partner.spotify.com','192.0.2.1'))
                finally:
                    release.set()
                    for _ in range(200):  # the queued resolution finishes in a worker
                        if 'api-partner.spotify.com' in watch.dns_verifier.cache:
                            break
                        time.sleep(.01)
                resolver.assert_called_once_with('api-partner.spotify.com.',None,socket.AF_UNSPEC,socket.SOCK_STREAM)
                self.assertEqual(watch.poll(531),[items[1]])
                self.assertEqual(watch.analyzer.dns_seen_at['192.0.2.1'],100)
                path.write_text('')
                self.assertEqual(watch.poll(562),items)  # removing the rule overrides a cached success

    def test_verification_rejects_changed_ip_errors_and_expired_cache(self):
        verifier = DNSVerifier()
        self.addCleanup(verifier.close)
        answer = [(socket.AF_INET6,socket.SOCK_STREAM,6,'',('2001:db8::1',0,0,0))]
        with patch('netwatch.socket.getaddrinfo',return_value=answer):
            verifier.resolve('track.spotify.com')
        self.assertTrue(verifier.matches('track.spotify.com','2001:db8::1'))
        self.assertFalse(verifier.matches('track.spotify.com','192.0.2.1'))
        stamp = verifier.cache['track.spotify.com'][0]
        with patch('netwatch.time.monotonic',return_value=stamp+301), patch('netwatch.threading.Thread'):
            self.assertFalse(verifier.matches('track.spotify.com','2001:db8::1'))
        with patch('netwatch.socket.getaddrinfo',side_effect=socket.gaierror('offline')):
            verifier.resolve('track.spotify.com')
        self.assertFalse(verifier.matches('track.spotify.com','2001:db8::1'))
        verifier.close()
        with patch('netwatch.threading.Thread') as thread:
            self.assertFalse(verifier.matches('track.spotify.com','2001:db8::1'))
            thread.assert_not_called()

    def test_domains_ips_and_recent_dns_are_matched_precisely(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'network-ignore.txt'
            path.write_text('# commento\nSpotify.com\n2001:db8::1\n*.invalid.com\n')
            exceptions = network_exceptions(path)
            self.assertEqual(exceptions,({'spotify.com'},{'2001:db8::1'}))
            analyzer = NetworkAnalyzer(now=100)
            analyzer.dns_event(100,'track.spotify.com',1,0,True,['192.0.2.1'])
            destination = dict(kind='destinazione',key='192.0.2.1:443')
            self.assertTrue(excluded_destination(destination,analyzer,exceptions,101))
            self.assertFalse(excluded_destination(destination,analyzer,exceptions,401))
            analyzer.dns_event(102,'spotify.com.attacker.example',1,0,True,['192.0.2.1'])
            self.assertFalse(excluded_destination(destination,analyzer,exceptions,103))
            analyzer.dns_event(104,'spostify.com',1,0,True,['192.0.2.1'])
            self.assertFalse(excluded_destination(destination,analyzer,exceptions,105))
            self.assertTrue(excluded_destination(dict(kind='destinazione',key='[2001:db8::1]:443'),analyzer,exceptions,105))
            self.assertFalse(excluded_destination(dict(kind='spike',key='[2001:db8::1]:443'),analyzer,exceptions,105))
            path.unlink()
            self.assertEqual(network_exceptions(path),(set(),set()))

    def test_poll_reloads_exceptions_without_hiding_other_results(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'ignore.txt'
            path.write_text('spotify.com\n')
            watch = NetWatch(Path(folder)/'baseline.json',ignore_path=path)
            watch.analyzer.dns_event(100,'a.spotify.com',1,0,True,['192.0.2.1'])
            items = [dict(kind='destinazione',key='192.0.2.1:443',score=90),dict(kind='spike',score=80)]
            with patch.object(watch,'flows',return_value=[]), patch.object(watch,'user_idle',return_value=None), \
                 patch.object(watch,'attribute'), patch.object(watch.analyzer,'analyze',return_value=items):
                self.assertEqual(watch.poll(101),[items[1]])
                path.write_text('')
                self.assertEqual(watch.poll(132),items)

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
        self.assertEqual(self.result['long_flow'],[1234])  # compensate the same SYN byte as the close collector


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


class RotatingDnsExceptionTests(unittest.TestCase):
    """An allowed service whose DNS rotates must stay excluded for connections that were opened by name."""
    class NeverMatches:
        def matches(self,name,ip):
            return False  # the name now resolves to other addresses

    def analyzer(self):
        analyzer = NetworkAnalyzer(dict(started=0.),now=0.)
        analyzer.dns_event(100.,'alive.github.com',1,0,True,['140.82.113.26'])
        analyzer.syn(100.4,'140.82.113.26',443)
        return analyzer

    def excluded(self,analyzer,now=4000.):
        exceptions = (network_exceptions_from(['github.com']),set())
        return excluded_destination(dict(kind='destinazione',key='140.82.113.26:443'),analyzer,exceptions,now,self.NeverMatches())

    def test_connection_named_by_an_allowed_domain_survives_rotation(self):
        self.assertTrue(self.excluded(self.analyzer()))

    def test_connection_answered_from_the_resolver_cache_stays_named(self):
        analyzer = self.analyzer()
        analyzer.syn(3000.,'140.82.113.26',443)  # nss-resolve cache hit: no packet, but the address was answered 48 min ago
        self.assertTrue(self.excluded(analyzer))

    def test_connection_without_dns_keeps_it_visible(self):
        analyzer = self.analyzer()
        analyzer.syn(100.4+2*3600+60,'140.82.113.26',443)  # no answer for this address within the cache horizon
        self.assertFalse(self.excluded(analyzer,now=100.4+2*3600+90))

    def test_connection_named_by_another_domain_keeps_it_visible(self):
        analyzer = self.analyzer()
        analyzer.dns_event(3000.,'evil.example',1,0,True,['140.82.113.26'])
        analyzer.syn(3000.5,'140.82.113.26',443)
        self.assertFalse(self.excluded(analyzer))

    def test_recent_other_name_wins_even_without_a_connection(self):
        analyzer = self.analyzer()
        analyzer.dns_event(3900.,'evil.example',1,0,True,['140.82.113.26'])
        self.assertFalse(self.excluded(analyzer))

    def test_record_is_dropped_with_the_destination(self):
        analyzer = self.analyzer()
        analyzer.prune(100.4+3*3600)
        self.assertNotIn('140.82.113.26:443',analyzer.contact_names)


def network_exceptions_from(domains):
    return set(domains)


class UnconfirmedExplanationTests(unittest.TestCase):
    def test_visible_allowed_name_says_why(self):
        from netwatch import explain_unconfirmed
        analyzer = NetworkAnalyzer(dict(started=0.),now=0.)
        analyzer.dns_event(100.,'discord.gg',1,0,True,['162.159.133.234'])
        verifier = DNSVerifier()
        self.addCleanup(verifier.close)
        item = dict(kind='destinazione',key='162.159.133.234:443',evidence=['periodica'])
        explain_unconfirmed([item],analyzer,({'discord.gg'},set()),verifier)
        self.assertIn('riconferma DNS in corso',item['evidence'][-1])
        answer = [(socket.AF_INET,socket.SOCK_STREAM,6,'',('162.159.130.234',0))]
        with patch('netwatch.socket.getaddrinfo',return_value=answer):
            verifier.resolve('discord.gg')
        item['evidence'] = ['periodica']
        explain_unconfirmed([item],analyzer,({'discord.gg'},set()),verifier)
        self.assertIn('non compare tra i 1 indirizzi',item['evidence'][-1])
        other = dict(kind='destinazione',key='192.0.2.1:443',evidence=[])
        explain_unconfirmed([other],analyzer,({'discord.gg'},set()),verifier)
        self.assertEqual(other['evidence'],[])  # names not on the list get no note


class VerifierQueueTests(unittest.TestCase):
    def test_observed_name_is_not_starved_by_a_sweep_of_listed_domains(self):
        verifier = DNSVerifier()
        self.addCleanup(verifier.close)
        def resolve(name,*args):
            ip = '162.159.133.234' if name.startswith('gateway') else '192.0.2.9'
            return [(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,0))]
        with patch('netwatch.socket.getaddrinfo',side_effect=resolve):
            for i in range(106):  # an unnamed destination checked against every listed domain
                verifier.matches(f'domain{i}.example','198.51.100.1')
            verifier.matches('gateway-us-east1-b.discord.gg','162.159.133.234')
            for _ in range(200):
                if verifier.matches('gateway-us-east1-b.discord.gg','162.159.133.234'):
                    break
                time.sleep(.01)
        self.assertTrue(verifier.matches('gateway-us-east1-b.discord.gg','162.159.133.234'))
        self.assertEqual(len(verifier.workers),DNSVerifier.WORKERS)


class ExecutablePathTests(unittest.TestCase):
    def test_socket_owner_reports_the_executable(self):
        from netwatch import socket_owner
        server = socket.socket(); server.bind(('127.0.0.1',0)); server.listen()
        self.addCleanup(server.close)
        inode = os.fstat(server.fileno()).st_ino
        owner = socket_owner(os.getpid(),server.fileno(),inode)
        self.assertEqual(owner['exe'],os.path.realpath(sys.executable))
