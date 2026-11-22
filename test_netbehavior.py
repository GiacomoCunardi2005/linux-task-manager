import random
import unittest
from netbehavior import NetworkAnalyzer, IsolationForest, beacon, dga_likeness, noisy_or, registered

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
