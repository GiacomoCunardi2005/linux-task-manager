import copy
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from hardware import disk_devices, npu_devices, parse_wifi_link, wifi_link
from metrics import Monitor
from app import Window
import test_ui


class HardwareTests(unittest.TestCase):
    def test_usb_discovery_reports_negotiated_speed_and_removal(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            usb = root/'usb1'/'1-2'
            target = usb/'host0'/'0:0:0:0'
            target.mkdir(parents=True)
            for name,value in {'idVendor':'abcd','speed':'5000','version':'3.20','product':'Test USB'}.items():
                (usb/name).write_text(value)
            (target/'model').write_text('USB test disk')
            block = root/'block'/'sda'
            (block/'queue').mkdir(parents=True)
            (block/'device').symlink_to(target,target_is_directory=True)
            for name,value in {'dev':'8:0','diskseq':'42','size':'2048','removable':'1','queue/rotational':'0'}.items():
                (block/name).write_text(value)
            devices = disk_devices(root/'block')
            self.assertEqual(devices['sda']['link_speed'],'5 Gbit/s')
            self.assertEqual(devices['sda']['bus'],'USB')
            self.assertEqual(devices['sda']['type'],'Disco USB')
            self.assertEqual(devices['sda']['capacity'],1024**2)
            self.assertEqual(devices['sda']['identity'],'42')
            (block/'dev').unlink()
            self.assertEqual(disk_devices(root/'block'),{})

    def test_disk_replacement_with_same_name_has_no_false_io_spike(self):
        monitor = Monitor()
        self.addCleanup(monitor.close)
        device = dict(identity='1',capacity=1024,model='Test',type='SSD',bus='USB',link_speed='480 Mbit/s',removable=True)
        counters = SimpleNamespace(read_count=10,write_count=5,read_bytes=10000,write_bytes=5000,busy_time=100,read_time=50,write_time=50)
        with patch('metrics.disk_devices',return_value={'testdisk':device}), patch('metrics.psutil.disk_io_counters',return_value={'testdisk':counters}):
            self.assertIsNone(monitor.sample()['disks']['testdisk']['value'])
            self.assertEqual(monitor.sample()['disks']['testdisk']['read'],0)
            device['identity'] = '2'
            self.assertIsNone(monitor.sample()['disks']['testdisk']['read'])
        with patch('metrics.disk_devices',return_value={}):
            self.assertEqual(monitor.sample()['disks'],{})

    def test_replaced_nic_with_same_name_starts_a_fresh_baseline(self):
        monitor = Monitor()
        self.addCleanup(monitor.close)
        identity = ['old-nic']
        counters = SimpleNamespace(bytes_sent=100,bytes_recv=200)
        with patch('metrics.network_identity',side_effect=lambda name: identity[0]), patch('metrics.psutil.net_io_counters',return_value={'testnic':counters}) as mocked:
            self.assertEqual(monitor.sample()['nets']['testnic']['value'],0)
            counters = SimpleNamespace(bytes_sent=100,bytes_recv=300)
            mocked.return_value = {'testnic':counters}
            self.assertGreater(monitor.sample()['nets']['testnic']['received'],0)
            identity[0] = 'new-nic'
            mocked.return_value = {'testnic':SimpleNamespace(bytes_sent=100,bytes_recv=1000000000)}
            self.assertEqual(monitor.sample()['nets']['testnic']['value'],0)

    def test_npu_sysfs_and_counter_units(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root/'0000:00:0b.0'
            (target/'freq').mkdir(parents=True)
            (target/'power').mkdir()
            driver = root/'intel_vpu'
            driver.mkdir()
            (target/'driver').symlink_to(driver,target_is_directory=True)
            for name,value in {'npu_busy_time_us':'500000','npu_memory_utilization':'4096','freq/current_freq':'0','freq/hw_max_freq':'1400','npu_current_frequency_mhz':'700','power/runtime_status':'suspended'}.items():
                (target/name).write_text(value)
            accel = root/'accel'/'accel0'
            accel.mkdir(parents=True)
            (accel/'device').symlink_to(target,target_is_directory=True)
            device = npu_devices(root/'accel')['accel0']
            self.assertEqual(device['name'],'Intel AI Boost')
            self.assertEqual(device['freq'],0)
            self.assertEqual(device['memory'],4096)
            monitor = Monitor()
            self.addCleanup(monitor.close)
            with patch('metrics.npu_devices',side_effect=lambda: {'accel0':dict(device)}):
                self.assertIsNone(monitor.sample()['npus']['accel0']['value'])
                device['busy'] += 500000
                monitor.last_time = time.monotonic()-2
                self.assertAlmostEqual(monitor.sample()['npus']['accel0']['value'],25,delta=.2)
                device['busy'] = 0
                self.assertIsNone(monitor.sample()['npus']['accel0']['value'])

    def test_wifi_standard_band_channel_and_radio_bitrate(self):
        text = 'Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n\tSSID: Test:Network\n\tfreq: 5320.0\n\tsignal: -41 dBm\n\trx bitrate: 1200.9 MBit/s 80MHz HE-MCS 11 HE-NSS 2\n\ttx bitrate: 960.7 MBit/s 80MHz HE-MCS 9\n'
        info = parse_wifi_link(text)
        self.assertEqual(info['ssid'],'Test:Network')
        self.assertEqual(info['standard'],'Wi-Fi 6 (802.11ax)')
        self.assertEqual(info['rx_rate'],'1200.9 MBit/s')
        self.assertEqual((info['band'],info['channel'],info['width']),('5 GHz','64','80 MHz'))
        self.assertIn('Wi-Fi 6E',parse_wifi_link(text.replace('5320.0','5935'))['standard'])
        self.assertEqual(parse_wifi_link(text.replace('5320.0','5935'))['channel'],'2')
        self.assertIn('Wi-Fi 7',parse_wifi_link(text.replace('HE-MCS','EHT-MCS'))['standard'])
        self.assertIn('Wi-Fi 5',parse_wifi_link(text.replace('HE-MCS','VHT-MCS'))['standard'])
        self.assertIsNone(parse_wifi_link('Not connected.')['rx_rate'])
        with patch('hardware.subprocess.run',side_effect=FileNotFoundError()):
            self.assertIsNone(wifi_link('wlan0')['standard'])


class HotplugUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_ui.UITests.setUpClass()
        cls.app = test_ui.UITests.app

    def test_sidebar_add_remove_replace_while_paused(self):
        window = Window()
        window.show_page('performance')
        window.show()
        try:
            deadline = time.monotonic()+10
            while window.snapshot is None and time.monotonic() < deadline:
                test_ui.wait(50)
            self.assertIsNotNone(window.snapshot)
            window.timer.stop()
            window.sampler.wait()
            self.app.processEvents()
            baseline = copy.deepcopy(window.snapshot)
            data = copy.deepcopy(baseline)
            data['disks']['testusb'] = dict(identity='42',capacity=32*1024**3,model='USB test disk',type='Disco USB',bus='USB',link_speed='5 Gbit/s',usb_version='3.20',usb_product='Test USB',removable=True,value=None,read=None,write=None,latency=None)
            data['npus']['testaccel'] = dict(identity='pci-test',name='NPU test',driver='intel_vpu',pci='0000:00:0b.0',value=0,busy=0,memory=4096,freq=0,max_freq=1400,state='suspended')
            window.receive(data)
            self.assertIn(('disks','testusb'),window.resources)
            self.assertIn(('npus','testaccel'),window.resources)
            window.select('disks','testusb')
            self.assertIn('5 Gbit/s',window.info_text)
            self.assertIn('Non disponibile',window.info_text)
            self.app.processEvents()
            window.grab().save('reference/linux-usb-fixture.png')
            window.toggle_pause()
            data['disks']['testusb']['identity'] = '43'
            window.receive(data)
            self.assertEqual(window.selection,('cpu','cpu'))
            self.assertEqual(len(window.histories[('disks','testusb')]),1)
            window.select('npus','testaccel')
            window.receive(baseline)
            self.assertNotIn(('disks','testusb'),window.resources)
            self.assertNotIn(('npus','testaccel'),window.resources)
            self.assertEqual(window.selection,('cpu','cpu'))
            window.toggle_pause()
            for key in baseline['nets']:
                if baseline['nets'][key]['wifi']:
                    window.select('nets',key)
                    self.assertIn('Standard Wi-Fi:',window.info_text)
                    self.app.processEvents()
                    window.grab().save('reference/linux-wifi-details.png')
                    window.resize(900,660)
                    self.app.processEvents()
                    window.grab().save('reference/linux-wifi-compact.png')
                    break
        finally:
            window.close()


if __name__ == '__main__':
    unittest.main()
