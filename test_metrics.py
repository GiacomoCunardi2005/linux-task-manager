import unittest
from collections import namedtuple
from metrics import Monitor, cpu_usage, rate, size, uptime


class MetricsTests(unittest.TestCase):
    def test_cpu_avoids_double_counting_guest_and_counts_iowait_as_idle(self):
        Times = namedtuple('Times','user nice system idle iowait guest guest_nice')
        self.assertAlmostEqual(cpu_usage(Times(40,0,10,40,10,10,0),Times(0,0,0,0,0,0,0)), 50)
        self.assertEqual(cpu_usage(Times(0,0,0,0,0,0,0),Times(0,0,0,0,0,0,0)),0)

    def test_counter_reset_and_units(self):
        self.assertEqual(rate(5,10,1),0)
        self.assertEqual(rate(110,10,2),50)
        self.assertEqual(size(1024**3),'1.0 GB')
        self.assertEqual(size(None),'Non disponibile')
        self.assertEqual(uptime(90061),'1:01:01:01')

    def test_real_linux_sample_has_consistent_memory_and_bounded_counters(self):
        monitor = Monitor()
        first = monitor.sample()
        second = monitor.sample()
        for sample in (first,second):
            self.assertGreater(len(sample['cpu']['cores']),0)
            self.assertTrue(0 <= sample['cpu']['value'] <= 100)
            memory = sample['memory']
            self.assertEqual(memory['used']+memory['available'],memory['total'])
            self.assertTrue(all(0 <= d['value'] <= 100 for d in sample['disks'].values()))
            self.assertTrue(all(d['sent'] >= 0 and d['received'] >= 0 for d in sample['nets'].values()))


if __name__ == '__main__':
    unittest.main()
