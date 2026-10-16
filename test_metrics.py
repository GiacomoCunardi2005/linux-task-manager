import unittest
from collections import namedtuple
from unittest.mock import patch
import subprocess
from metrics import Monitor, cpu_usage, rate, size, uptime, parse_memory_hardware, memory_hardware


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

    def test_ram_configured_speed_empty_slot_and_capacity(self):
        properties = """MEMORY_ARRAY_NUM_DEVICES=2
MEMORY_DEVICE_0_SIZE=17179869184
MEMORY_DEVICE_0_FORM_FACTOR=SODIMM
MEMORY_DEVICE_0_TYPE=DDR5
MEMORY_DEVICE_0_SPEED_MTS=5600
MEMORY_DEVICE_0_CONFIGURED_SPEED_MTS=4800
MEMORY_DEVICE_1_PRESENT=0
"""
        ram = parse_memory_hardware(properties)
        self.assertEqual(ram['speed'],'4800 MT/s')
        self.assertEqual(ram['rated_speed'],'5600 MT/s')
        self.assertEqual((ram['slots_used'],ram['slots_total']),(1,2))
        self.assertEqual(ram['form_factor'],'SO-DIMM')
        self.assertEqual(ram['installed'],16*1024**3)
        self.assertEqual(ram['modules'],'1 × 16.0 GB')

    def test_ram_unknown_and_partial_firmware_are_not_guessed(self):
        properties = 'MEMORY_ARRAY_NUM_DEVICES=2\nMEMORY_DEVICE_0_SIZE=17179869184\nMEMORY_DEVICE_0_CONFIGURED_SPEED_MTS=5600\n'
        ram = parse_memory_hardware(properties)
        self.assertIsNone(ram['installed'])
        self.assertIsNone(ram['speed'])
        self.assertIsNone(ram['slots_used'])
        for header in ('','MEMORY_ARRAY_NUM_DEVICES=invalid\n'):
            partial = parse_memory_hardware(properties.replace('MEMORY_ARRAY_NUM_DEVICES=2\n',header))
            self.assertIsNone(partial['installed'])
            self.assertIsNone(partial['speed'])
        ram = parse_memory_hardware(properties.replace('NUM_DEVICES=2','NUM_DEVICES=1').replace('CONFIGURED_SPEED_MTS=5600','SPEED_MTS=5600'))
        self.assertIsNone(ram['speed'])
        self.assertEqual(ram['rated_speed'],'5600 MT/s')
        self.assertIsNone(parse_memory_hardware('MEMORY_ARRAY_NUM_DEVICES=invalid')['installed'])

    def test_ram_metadata_tool_missing_or_timeout_is_nonfatal(self):
        for error in (FileNotFoundError(),subprocess.TimeoutExpired('udevadm',2)):
            with self.subTest(error=type(error).__name__), patch('metrics.subprocess.run',side_effect=error):
                self.assertIsNone(memory_hardware()['speed'])

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
