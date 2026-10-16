"""Offscreen integration check: real counters and all resource views."""
import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
import time
import unittest
from pathlib import Path
from PySide6.QtWidgets import QApplication, QWidget, QScrollArea
from PySide6.QtTest import QTest
from PySide6.QtCore import Qt, QEventLoop, QTimer
from app import Window, STYLE


def wait(ms):
    loop = QEventLoop()
    QTimer.singleShot(ms,loop.quit)
    loop.exec()


class UITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setStyle('Fusion')
        cls.app.setStyleSheet(STYLE)

    def test_network_details_are_grouped_complete_and_fit_compact_windows(self):
        import copy
        from app import bitrate
        window = Window()
        window.show_page('performance')
        window.show()
        try:
            wait(1200)
            window.timer.stop()
            window.sampler.wait()
            self.app.processEvents()
            data = copy.deepcopy(window.snapshot)
            device = dict(identity='wifi-layout-fixture',wifi=True,connected=True,value=8000000,
                sent=2000000,received=8000000,ipv4='192.0.2.10',
                ipv6='2001:0db8:1234:5678:90ab:cdef:1234:5678',mac='02:00:00:00:00:01',
                driver='driver-di-prova',mtu=1500,speed=1200,duplex='Full duplex',
                link=dict(bus='USB',link_speed='5 Gbit/s'),ssid='Rete di laboratorio piano superiore',
                standard='Wi-Fi 6 (802.11ax)',band='5 GHz',frequency='5320 MHz',channel='64',
                width='80 MHz',signal='-48 dBm',rx_rate='1200.9 Mbit/s',tx_rate='1200.9 Mbit/s',
                bssid='02:00:00:00:00:02',hardware=dict(manufacturer='Produttore di prova',model='Scheda Wi-Fi AX di prova',
                    registered_vendor='Fornitore di prova',vendor_id='1234',device_id='5678',bus='USB',location='2-1.2'))
            data['nets'] = {'wlan-test':device}
            window.receive(data)
            window.select('nets','wlan-test')
            window.histories.clear()
            device.update(value=12500,sent=1000,received=12500)
            window.receive(data)
            self.assertEqual(window.graphs[0].maximum,1_000_000)
            self.assertEqual(window.resources[('nets','wlan-test')].graph.maximum,1_000_000)
            self.assertEqual(window.scale.text(),'1.0 Mbps')
            device.update(value=8000000,sent=2000000,received=8000000)
            window.receive(data)
            self.assertGreater(window.graphs[0].maximum,1_000_000)
            self.assertEqual(window.graphs[0].maximum,window.resources[('nets','wlan-test')].graph.maximum)
            names = ('Rete (SSID):','Standard Wi-Fi:','Banda:','Frequenza:','Canale:',
                'Larghezza canale:','Segnale:','Bitrate RX (radio):','Bitrate TX (radio):',
                'Interfaccia:','Tipo di connessione:','Driver:','MTU:','Collegamento USB:',
                'Indirizzo IPv4:','Indirizzo IPv6:','Indirizzo MAC:','Punto di accesso:',
                'Produttore:','Modello:','ID hardware:','Fornitore ID:','Bus hardware:','Posizione:')
            self.assertEqual(len(window.detail_labels),len(names))
            for name in names:
                self.assertIn(name,window.info_text)
            self.assertEqual({heading.text() for heading in window.stats.findChildren(QWidget,'detail-heading')},
                {'Identità hardware','Collegamento Wi-Fi','Scheda di rete','Indirizzi'})
            self.assertEqual(window.device.text(),device['hardware']['model'])
            self.assertIn('1234:5678',window.info_text)
            self.assertIn('Fornitore di prova',window.info_text)
            Path('reference').mkdir(exist_ok=True)
            window.toggle_pause()
            for width,height,expanded in ((1120,790,True),(900,660,False),(900,660,True)):
                window.resize(width,height)
                self.app.processEvents()
                if (window.navigation.width()>100) != expanded:
                    window.toggle_navigation()
                self.app.processEvents()
                wait(50)
                self.app.processEvents()
                scroll = window.findChild(QScrollArea,'detail-scroll')
                self.assertLessEqual(scroll.widget().width(),scroll.viewport().width())
                self.assertEqual(scroll.horizontalScrollBar().maximum(),0)
                window.grab().save(f'reference/wifi-organized-{width}-{int(expanded)}.png')
                for value in window.detail_labels:
                    self.assertGreater(value.width(),35)
                    if value.text() == device['ipv6']:
                        self.assertGreaterEqual(value.width(),value.fontMetrics().horizontalAdvance(value.text()))
                    self.assertGreaterEqual(value.height(),value.heightForWidth(value.width()),repr((value.text(),value.size(),value.sizeHint(),value.minimumSizeHint(),value.sizePolicy().hasHeightForWidth())))
            window.toggle_pause()
            # Refreshing values preserves the sections and the complete copy output.
            device['sent'] = 4500000
            device['ssid'] = 'Rete di prova aggiornata'
            device['signal'] = None
            window.receive(data)
            self.assertEqual(window.value_labels[0].text(),bitrate(device['sent']))
            self.assertIn(device['ssid'],[item.text() for item in window.detail_labels])
            self.assertIn('Non disponibile',[item.text() for item in window.detail_labels])
            window.copy_info()
            self.assertIn('Punto di accesso:',QApplication.clipboard().text())
            self.assertIn('Collegamento USB:',QApplication.clipboard().text())
            # Ethernet retains negotiated speed, duplex and every interface field.
            device['wifi'] = False
            window.receive(data)
            self.assertEqual(len(window.detail_labels),16)
            for name in ('Velocità collegamento:','Duplex:','Interfaccia:','Driver:','MTU:',
                         'Tipo di connessione:','Indirizzo IPv4:','Indirizzo IPv6:',
                         'Indirizzo MAC:','Collegamento USB:'):
                self.assertIn(name,window.info_text)
        finally:
            window.close()

    def test_resources_pause_cores_and_live_render(self):
        window = Window()
        window.show_page('performance')
        window.show()
        try:
            deadline = time.monotonic()+8
            while window.snapshot is None and time.monotonic()<deadline:
                self.app.processEvents()
                wait(50)
            self.assertIsNotNone(window.snapshot)
            wait(1200)
            self.app.processEvents()
            for pair,button in list(window.resources.items()):
                window.findChild(QScrollArea,'resources').ensureWidgetVisible(button)
                QTest.mouseClick(button,Qt.LeftButton)
                self.app.processEvents()
                self.assertEqual(window.selection,pair)
                self.assertTrue(button.isChecked())
                self.assertTrue(window.heading.text())
                self.assertTrue(window.info_text)
                if pair[0] == 'memory':
                    for field in ('Velocità:', 'Slot utilizzati:', 'Fattore di forma:', 'Slab recuperabile', 'Impegnata / limite'):
                        self.assertIn(field,window.info_text)
                if pair[0] == 'connections':
                    self.assertEqual(window.performance_detail.currentWidget(),window.connection_page)
                    self.assertFalse(window.graphs)
                else:
                    visible = [w for w in window.stats.findChildren(QWidget, options=Qt.FindDirectChildrenOnly) if w.isVisible()]
                    self.assertEqual(len(visible),2)
            window.select('cpu','cpu')
            window.core_action.setChecked(True)
            self.assertEqual(len(window.graphs),len(window.snapshot['cpu']['cores']))
            window.core_action.setChecked(False)
            QTest.mouseClick(window.pause,Qt.LeftButton)
            frozen = list(window.graphs[0].samples)
            wait(1200)
            self.assertEqual(window.graphs[0].samples,frozen)
            QTest.mouseClick(window.pause,Qt.LeftButton)
            self.assertFalse(window.paused)
            window.copy_info()
            self.assertIn('CPU',QApplication.clipboard().text())
            self.assertEqual([text for _,text in window.navbuttons],['Processi','Prestazioni'])
            window.toggle_navigation()
            self.assertEqual(window.navigation.width(),52)
            window.toggle_navigation()
            Path('reference').mkdir(exist_ok=True)
            for kind in ('cpu','memory','disks','nets','gpus','npus'):
                pair = next((p for p in window.resources if p[0]==kind),None)
                if pair:
                    window.select(*pair)
                    self.app.processEvents()
                    self.assertTrue(window.grab().save(f'reference/linux-{kind}.png'))
            window.resize(900,660)
            window.select('memory','memory')
            self.app.processEvents()
            window.grab().save('reference/linux-memory-compact.png')
            self.assertEqual(window.findChild(QScrollArea,'detail-scroll').horizontalScrollBar().maximum(),0)
            window.select('cpu','cpu')
            self.app.processEvents()
            window.grab().save('reference/linux-compact.png')
            self.assertEqual(window.findChild(QScrollArea,'detail-scroll').horizontalScrollBar().maximum(),0)
        finally:
            window.close()


if __name__ == '__main__':
    unittest.main()
