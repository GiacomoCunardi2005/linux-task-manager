import random
import unittest
from netbehavior import (NetworkAnalyzer, IsolationForest, WINDOW, MAX_IDN_CONTACTS,
                         beacon, dga_likeness, noisy_or, registered)

DAY = 86400
NOW = 1_800_000_000.


def learnt():
    """An analyzer whose local baseline is already two days old."""
    return NetworkAnalyzer(dict(started=NOW-2*DAY),now=NOW)


def top(results,kind):
    return max((r for r in results if r['kind'] == kind),key=lambda r: r['score'],default=None)


class BeaconTests(unittest.TestCase):
    def test_jittered_beacon_with_missed_beats_is_regular(self):
        rng = random.Random(1)
        times, t = [], NOW-3600
        for i in range(50):
            t += 60*rng.uniform(.95,1.05)*(2 if i in (10,30) else 1)  # two missed beats
            times.append(t)
        strength,period,cv,beats = beacon(times)
        self.assertGreater(strength,.85)
        self.assertAlmostEqual(period,60,delta=3)
        self.assertLess(cv,.05)

    def test_human_or_random_traffic_is_not_a_beacon(self):
        rng = random.Random(2)
        t, times = NOW-3600, []
        for _ in range(50):
            t += rng.expovariate(1/60)
            times.append(t)
        self.assertLess(beacon(times)[0],.35)
        self.assertEqual(beacon([NOW+i*.5 for i in range(40)])[0],0.)  # streaming: too fast to time

    def test_beacon_to_new_destination_ranks_first_and_habitual_one_decays(self):
        analyzer = learnt()
        rng = random.Random(3)
        t = NOW-3700
        for i in range(60):  # C2-like: every 60 s with 3% jitter per beat, ~400 byte request, a DNS answer just before
            t += 60*rng.uniform(.97,1.03)
            analyzer.dns_event(t-.5,'update-check.example','1',0,True,['203.0.113.9'])
            analyzer.syn(t,'203.0.113.9',443)
            analyzer.close(t+.4,'203.0.113.9',443,400+rng.randint(-10,10),900,.4)
        for i in range(40):  # ordinary browsing
            t = NOW-3600+rng.uniform(0,3600)
            analyzer.syn(t,f'198.51.100.{i}',443)
            analyzer.close(t+5,f'198.51.100.{i}',443,2000,80000,5)
        results = analyzer.analyze(NOW)
        first = results[0]
        self.assertEqual(first['key'],'203.0.113.9:443')
        self.assertIn('update-check.example',first['subject'])
        self.assertGreater(first['score'],85)
        self.assertTrue({'beacon','sizes','new','dnsfirst'} <= set(first['indicators']))
        self.assertLess(max((r['score'] for r in results if r['key'].startswith('198.51.100.')),default=0),40)
        analyzer.base['beacons']['203.0.113.9:443'] = NOW-10*DAY  # seen beaconing for 10 days: a habit, e.g. a mail client
        analyzer.base['dest']['203.0.113.9:443'][0] = NOW-10*DAY
        self.assertLess(analyzer.analyze(NOW)[0]['score'],first['score']-40)

    def test_heartbeat_on_one_long_connection_is_timed(self):
        analyzer = learnt()
        out = 0
        for i in range(30):
            out += 120
            analyzer.snapshot(NOW-1800+i*30,[('10.0.0.2',50000,'203.0.113.7',8443,out,out*2)])
        result = top(analyzer.analyze(NOW),'destinazione')
        self.assertIn('beacon',result['indicators'])


class DnsTests(unittest.TestCase):
    def test_dga_burst_of_random_nxdomains(self):
        analyzer = learnt()
        rng = random.Random(4)
        for i in range(30):
            name = ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(16))+'.com'
            analyzer.dns_event(NOW-600+i*10,name,1,3,True)
            analyzer.dns_event(NOW-600+i*10+.01,name,1,3,True)  # every answer is seen twice: stub and upstream
        result = top(analyzer.analyze(NOW),'dga')
        self.assertGreater(result['score'],60)
        self.assertIn('NXDOMAIN',result['evidence'][0])
        self.assertIn('100% mai visti prima',result['evidence'][1])

    def test_a_few_typos_are_not_dga(self):
        analyzer = learnt()
        for i,name in enumerate(['gogle.com','faceboook.com','wikipeda.org','githb.com','stackoverfow.com']):
            analyzer.dns_event(NOW-300+i,name,1,3,True)
        self.assertIsNone(top(analyzer.analyze(NOW),'dga'))
        self.assertLess(dga_likeness('stackoverflow.com'),.3)
        self.assertGreater(dga_likeness('xj4k2q9vbz7m1wpl.com'),.6)

    def test_dns_tunnel_with_encoded_subdomains(self):
        analyzer = learnt()
        rng = random.Random(5)
        for i in range(120):
            chunk = ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz234567') for _ in range(50))
            analyzer.dns_event(NOW-600+i*5,f'{chunk}.{i}.t.exfil-example.net',16,0,False)
        result = top(analyzer.analyze(NOW),'tunnel')
        self.assertGreater(result['score'],60)
        self.assertEqual(result['subject'],'Dominio exfil-example.net')

    def test_cdn_with_short_varied_hosts_is_not_a_tunnel(self):
        analyzer = learnt()
        for i in range(30):
            analyzer.dns_event(NOW-600+i*10,f'img{i}.static.cdn-example.com',1,0,False)
        self.assertIsNone(top(analyzer.analyze(NOW),'tunnel'))
        self.assertEqual(registered('a.b.example.co.uk'),'example.co.uk')


class InternationalDomainTests(unittest.TestCase):
    def contacted(self,name):
        analyzer = NetworkAnalyzer(now=NOW-10)
        analyzer.dns_event(NOW-2,name,1,0,True,['203.0.113.9'])
        analyzer.syn(NOW-1,'203.0.113.9',443)
        return analyzer

    def test_unicode_and_punycode_in_any_label_including_suffix_alert_on_contact(self):
        for name,visible,codepoint in (
                ('bücher.example','bücher.example','U+00FC'),
                ('xn--bcher-kva.example','bücher.example','U+00FC'),
                ('api.xn--bcher-kva.example','api.bücher.example','U+00FC'),
                ('shop.xn--p1ai','shop.рф','U+0440'),
                ('shop.рф','shop.рф','U+0440')):
            with self.subTest(name=name):
                analyzer = self.contacted(name)
                analyzer.processes['203.0.113.9:443'] = 'browser (PID 42)'
                result = top(analyzer.analyze(NOW),'idn')
                self.assertEqual(result['key'],'203.0.113.9:443')
                self.assertEqual(result['score'],70)
                self.assertEqual(result['indicators'],['idn'])
                self.assertEqual(result['process'],'browser (PID 42)')
                self.assertNotIn('203.0.113.9',result['subject'])
                self.assertTrue(result['subject'].isascii())
                self.assertIn(visible,' '.join(result['evidence']))
                self.assertIn(codepoint,' '.join(result['evidence']))

    def test_ascii_digits_hyphens_and_punycode_text_inside_a_label_do_not_alert(self):
        for name in ('api-2.example.com','mirror01.example.net','prefix-xn--test.example'):
            with self.subTest(name=name):
                self.assertIsNone(top(self.contacted(name).analyze(NOW),'idn'))

    def test_invalid_punycode_still_alerts_and_escapes_bidi_and_controls(self):
        for name in ('xn--.example','shop\u202e\u0001.example',
                     'xn--'+'shop\u202e'.encode('punycode').decode('ascii')+'.example'):
            with self.subTest(name=repr(name)):
                result = top(self.contacted(name).analyze(NOW),'idn')
                self.assertIsNotNone(result)
                rendered = result['subject']+' '.join(result['evidence'])
                self.assertNotIn('\u202e',rendered)
                self.assertNotIn('\u0001',rendered)
                self.assertIn('non decodificabili',rendered)
                if name != 'xn--.example':
                    self.assertIn('U+202E',rendered)
                    self.assertIn('\\u202e',rendered)

    def test_lookup_without_connection_or_dns_seen_after_contact_does_not_alert(self):
        analyzer = NetworkAnalyzer(now=NOW-10)
        analyzer.syn(NOW-5,'203.0.113.9',443)
        analyzer.dns_event(NOW-2,'xn--bcher-kva.example',1,0,True,['203.0.113.9'])
        self.assertIsNone(top(analyzer.analyze(NOW),'idn'))

    def test_stale_failed_query_and_ptr_dns_do_not_name_a_contact(self):
        for age,rcode,response,qtype in ((301,0,True,1),(2,3,True,1),(2,0,False,1),(2,0,True,12)):
            with self.subTest(age=age,rcode=rcode,response=response,qtype=qtype):
                analyzer = NetworkAnalyzer(now=NOW-1000)
                analyzer.dns_event(NOW-age,'xn--bcher-kva.example',qtype,rcode,response,['203.0.113.9'])
                analyzer.syn(NOW,'203.0.113.9',443)
                self.assertIsNone(top(analyzer.analyze(NOW),'idn'))
                if not response or rcode or qtype == 12:
                    self.assertNotIn('203.0.113.9',analyzer.ip_domain)

    def test_recorded_contact_survives_later_dns_mapping_overwrite(self):
        analyzer = self.contacted('xn--bcher-kva.example')
        analyzer.dns_event(NOW,'ordinary.example',1,0,True,['203.0.113.9'])
        result = top(analyzer.analyze(NOW+1),'idn')
        self.assertEqual(result['subject'],'xn--bcher-kva.example')
        self.assertEqual(result['when'],NOW-1)

    def test_active_snapshot_records_contact_without_a_captured_syn(self):
        analyzer = NetworkAnalyzer(now=NOW-10)
        analyzer.dns_event(NOW-2,'xn--bcher-kva.example',1,0,True,['203.0.113.9'])
        flow = [('10.0.0.2',50000,'203.0.113.9',443,0,0)]
        analyzer.snapshot(NOW-1,flow)
        self.assertIsNotNone(top(analyzer.analyze(NOW),'idn'))
        self.assertFalse(analyzer.events)  # no send burst or SYN was needed to establish the contact

    def test_contact_expiry_and_bounded_history(self):
        analyzer = self.contacted('xn--bcher-kva.example')
        self.assertIsNone(top(analyzer.analyze(NOW-1+WINDOW),'idn'))
        self.assertFalse(analyzer.idn_contacts)
        for index in range(MAX_IDN_CONTACTS+2):
            name = f'{index}.xn--bcher-kva.example'
            analyzer.dns_event(NOW,name,1,0,True,['203.0.113.9'])
            analyzer.syn(NOW,'203.0.113.9',443)
        self.assertEqual(len(analyzer.idn_contacts),MAX_IDN_CONTACTS)
        self.assertNotIn(('203.0.113.9:443','0.xn--bcher-kva.example'),analyzer.idn_contacts)

    def test_idn_caution_does_not_change_behavioral_score(self):
        ordinary,international = NetworkAnalyzer(now=NOW-4000),NetworkAnalyzer(now=NOW-4000)
        for analyzer,name in ((ordinary,'ordinary.example'),(international,'xn--bcher-kva.example')):
            for index in range(30):
                stamp = NOW-3000+index*60
                analyzer.dns_event(stamp-1,name,1,0,True,['203.0.113.9'])
                analyzer.syn(stamp,'203.0.113.9',443)
        plain = top(ordinary.analyze(NOW),'destinazione')
        results = international.analyze(NOW)
        self.assertEqual(plain['score'],top(results,'destinazione')['score'])
        self.assertEqual(top(results,'idn')['score'],70)

    def test_unusual_names_cannot_overflow_published_evidence_fields(self):
        name = ''.join(chr(0x400+index) for index in range(100))+'.example'
        result = top(self.contacted(name).analyze(NOW),'idn')
        self.assertLess(len(result['subject']),2000)
        self.assertTrue(all(len(line) < 2000 for line in result['evidence']))
        self.assertLessEqual(len(result['evidence']),30)
        self.assertIn('altri',' '.join(result['evidence']))


class VolumeAndForestTests(unittest.TestCase):
    def test_large_upload_to_new_destination_vs_large_download(self):
        analyzer = learnt()
        analyzer.syn(NOW-200,'192.0.2.50',443)
        analyzer.close(NOW-100,'192.0.2.50',443,80e6,2e5,100)
        analyzer.base['dest'].setdefault('192.0.2.60:443',[NOW-30*DAY,NOW,500])
        analyzer.syn(NOW-200,'192.0.2.60',443)
        analyzer.close(NOW-100,'192.0.2.60',443,1e5,900e6,100)
        results = {r['key']:r for r in analyzer.analyze(NOW) if r.get('key')}
        self.assertIn('esfiltrazione',' '.join(results['192.0.2.50:443']['evidence']))
        self.assertGreater(results['192.0.2.50:443']['score'],70)
        self.assertNotIn('192.0.2.60:443',results)

    def test_isolation_forest_separates_an_outlier(self):
        rng = random.Random(6)
        normal = [[rng.gauss(8,1),rng.gauss(11,1),rng.gauss(0,.3),rng.gauss(2,.5)] for _ in range(400)]
        forest = IsolationForest().fit(normal)
        self.assertLess(forest.score([8,11,0,2]),.5)
        self.assertGreater(forest.score([18,3,6,7]),.65)

    def test_noisy_or_needs_several_indicators(self):
        self.assertLess(noisy_or([('new',1)]),40)
        self.assertLess(noisy_or([('beacon',1)]),76)
        self.assertGreater(noisy_or([('beacon',1),('new',1),('sizes',1)]),85)

    def test_device_spike_against_its_own_history(self):
        analyzer = learnt()
        analyzer.base['device']['dst'] = [5+(i % 4) for i in range(300)]
        for i in range(200):  # fan-out: 200 destinations in 5 minutes, e.g. a scan
            analyzer.syn(NOW-100+i*.4,f'10.9.{i//250}.{i % 250}',22)
        result = top(analyzer.analyze(NOW),'spike')
        self.assertIsNotNone(result)
        self.assertIn('destinazioni diverse',result['subject'])

    def test_late_closes_do_not_split_buckets_and_random_traffic_stays_low(self):
        rng = random.Random(7)
        analyzer = NetworkAnalyzer(dict(started=NOW-3*DAY),now=NOW-7000)
        for i in range(20000):  # random browsing; each close arrives after the next SYN
            d, t = f'198.51.{rng.randint(0,1)}.{rng.randint(0,150)}', NOW-7000+i*.35
            analyzer.syn(t,d,443)
            analyzer.close(t+2,d,443,rng.randint(500,500000),rng.randint(1000,5000000),2)
        self.assertIn(len(analyzer.base['device']['conn']),(22,23,24))  # 7000 s / 300 s (alignment), not hundreds of fragments
        results = analyzer.analyze(NOW)
        self.assertLess(max(r['score'] for r in results),40)
        self.assertFalse(any('beacon' in r.get('indicators',()) or r['kind'] == 'spike' for r in results))

    def test_idle_user_raises_the_score(self):
        busy, idle = learnt(), learnt()
        for analyzer,away in ((busy,False),(idle,True)):
            analyzer.user_idle(NOW-4000,away)
            for i in range(40):
                analyzer.syn(NOW-3000+i*60,'203.0.113.20',8080)
        self.assertGreater(idle.analyze(NOW)[0]['score'],busy.analyze(NOW)[0]['score'])


if __name__ == '__main__':
    unittest.main()
