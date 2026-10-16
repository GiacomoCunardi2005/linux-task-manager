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
