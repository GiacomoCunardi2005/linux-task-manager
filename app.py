#!/usr/bin/env python3
"""Windows 11 inspired Processes and Performance views for Linux."""
import argparse
from collections import defaultdict, deque
from pathlib import Path
import sys
import time

from PySide6.QtCore import Qt, QTimer, QThread, Signal, QSize, QRectF, QEvent
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen, QIcon, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (QApplication, QWidget, QHBoxLayout, QVBoxLayout, QLabel,
    QPushButton, QToolButton, QScrollArea, QFrame, QGridLayout, QMenu, QSizeGrip, QProgressBar, QStackedWidget,
    QDialog, QFormLayout, QLineEdit, QSpinBox, QDialogButtonBox, QMessageBox, QSizePolicy, QLayout)
from metrics import Monitor, read, size, percent, uptime
from processes import ProcessPage
from remote import RemoteMonitor, PORT
from connections import ConnectionsPage

COLORS = {'cpu':'#42a7bf', 'memory':'#8b8fd7', 'disks':'#9bc86b', 'nets':'#d48bbb', 'gpus':'#aa92d0', 'npus':'#d4a5db', 'connections':'#7daeb8'}
ICON_PATHS = {
 'menu':'M4 6h16M4 12h16M4 18h16',
 'connections':'M12 21V3 M9 6l3-3 3 3 M12 16l-6-4V8 M12 12l6-4V5 M4 8h4 M16 3h4v3h-4z',
 'performance':'M3 3h18v18H3z M5 13h4l2-6 3 11 2-5h3',
 'processes':'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z',
 'history':'M4 6a9 9 0 1 1-1 9 M3 2v6h6 M12 6v6l4 2',
 'startup':'M4 16a8 8 0 0 1 16 0 M12 15l5-8 M6 17h1 M17 17h1',
 'users':'M9 4a3 3 0 1 1 0 6 3 3 0 0 1 0-6 M16 5a3 3 0 0 1 0 6 M3 20v-4a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v4z M17 13a4 4 0 0 1 4 4v3',
 'details':'M9 5h12M9 12h12M9 19h12 M3 5h1M3 12h1M3 19h1',
 'services':'M9 3h6l1 4 4 1v7l-4 1-1 5H9l-1-5-4-1V8l4-1z M12 9a3 3 0 1 1 0 6 3 3 0 0 1 0-6',
 'settings':'M9 3h6l1 4 4 1v7l-4 1-1 5H9l-1-5-4-1V8l4-1z M12 9a3 3 0 1 1 0 6 3 3 0 0 1 0-6',
 'pause':'M8 5v14M16 5v14', 'play':'M7 4l13 8-13 8z',
 'more':'M4 12h1M11 12h1M18 12h1', 'close':'M6 6l12 12M6 18L18 6',
 'max':'M5 5h14v14H5z', 'min':'M5 12h14', 'copy':'M8 7h12v14H8z M4 17V3h12',
}


def icon(name, color='#eeeeee'):
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path d="{ICON_PATHS[name]}" fill="none" stroke="{color}" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/></svg>'
    pixmap = QPixmap(24,24)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    QSvgRenderer(svg.encode()).render(painter)
    painter.end()
    return QIcon(pixmap)


def label(text='', pixels=12, color='#eeeeee'):
    widget = QLabel(text)
    widget.setTextFormat(Qt.PlainText)
    widget.setStyleSheet(f'color:{color}; font-size:{pixels}px; background:transparent;')
    return widget


class Graph(QWidget):
    def __init__(self, color, mini=False):
        super().__init__()
        self.color, self.mini = QColor(color), mini
        self.samples, self.secondary = [], []
        self.maximum = 100
        self.caption = None
        self.setMinimumSize(60 if mini else 180, 42 if mini else 160)
        self.setAccessibleName('Grafico degli ultimi 60 secondi')

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(.5, .5, self.width()-1, self.height()-1)
        p.fillRect(rect, QColor('#202020' if self.mini else '#191919'))
        p.setPen(QPen(QColor('#303030'), .7))
        columns, rows = (3, 2) if self.mini else (15, 10)
        for x in range(columns+1):
            px = rect.left()+rect.width()*x/columns
            p.drawLine(int(px), 0, int(px), self.height())
        for y in range(rows+1):
            py = rect.top()+rect.height()*y/rows
            p.drawLine(0, int(py), self.width(), int(py))
        if self.caption:
            p.setPen(QColor('#cccccc'))
            p.drawText(7,16,self.caption)
        if not self.samples:
            return
        end = self.samples[-1][0]
        for series, dashed in ((self.samples, False), (self.secondary, True)):
            path = QPainterPath()
            points = [(rect.right()-(end-t)/60*rect.width(), rect.bottom()-max(0,min(v/self.maximum,1))*rect.height()) for t,v in series if v is not None and end-t <= 60]
            if not points:
                continue
            path.moveTo(*points[0])
            for point in points[1:]:
                path.lineTo(*point)
            if not dashed:
                area = QPainterPath(path)
                area.lineTo(points[-1][0], rect.bottom())
                area.lineTo(points[0][0], rect.bottom())
                area.closeSubpath()
                fill = QColor(self.color)
                fill.setAlpha(175 if not self.mini else 120)
                p.fillPath(area, fill)
            pen = QPen(self.color, 1.3)
            if dashed:
                pen.setStyle(Qt.DashLine)
            p.setPen(pen)
            p.drawPath(path)
        p.setPen(QPen(self.color if self.mini else QColor('#393939'), .7))
        p.drawRect(rect)


class Resource(QPushButton):
    def __init__(self, title, color, chart=True):
        super().__init__()
        self.setCheckable(True)
        self.setFixedHeight(70)
        self.setObjectName('resource')
        row = QHBoxLayout(self)
        row.setContentsMargins(10,6,8,6)
        row.setSpacing(10)
        self.graph = Graph(color, True) if chart else None
        marker = self.graph or label()
        if not chart:
            marker.setPixmap(icon('connections',color).pixmap(30,30))
            marker.setAlignment(Qt.AlignCenter)
        marker.setFixedSize(60,42)
        row.addWidget(marker)
        column = QVBoxLayout()
        column.setSpacing(1)
        self.full_title = title
        self.title = label(title,15)
        self.subtitle = label('',11)
        self.subtitle.setWordWrap(False)
        column.addWidget(self.title)
        column.addWidget(self.subtitle)
        row.addLayout(column,1)
        # Child labels must not swallow the button's pointer events.
        for child in (marker, self.title, self.subtitle):
            child.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAccessibleName(title)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.title.setText(self.title.fontMetrics().elidedText(self.full_title, Qt.ElideRight, max(40,self.width()-88)))


class Sampler(QThread):
    ready = Signal(object)
    failed = Signal(str)

    def __init__(self, monitor):
        super().__init__()
        self.monitor = monitor

    def run(self):
        try:
            self.ready.emit(self.monitor.sample())
        except Exception as exc:
            self.failed.emit(f'Impossibile leggere i contatori: {exc}')


class TitleBar(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window
        self.setFixedHeight(42)
        self.setObjectName('titlebar')
        row = QHBoxLayout(self)
        row.setContentsMargins(14,0,0,0)
        menu = QToolButton()
        menu.setIcon(icon('menu'))
        menu.setToolTip('Espandi o riduci navigazione')
        menu.clicked.connect(window.toggle_navigation)
        row.addWidget(menu)
        appicon = label()
        appicon.setPixmap(icon('performance',COLORS['cpu']).pixmap(18,18))
        row.addWidget(appicon)
        window.source_label = label('Gestione attività · PC locale',12)
        row.addWidget(window.source_label)
        row.addStretch()
        window.connect_button = QPushButton('Connetti a un server')
        window.connect_button.setAccessibleName('Connetti a un server remoto tramite IP')
        window.connect_button.clicked.connect(window.connection_dialog)
        row.addWidget(window.connect_button)
        for name, title, action in [('min','Riduci a icona',window.showMinimized), ('max','Ingrandisci / ripristina',self.maximize), ('close','Chiudi',window.close)]:
            button = QToolButton()
            button.setIcon(icon(name))
            button.setFixedSize(46,40)
            button.setToolTip(title)
            button.setAccessibleName(title)
            button.clicked.connect(action)
            if name == 'close':
                button.setObjectName('close')
            row.addWidget(button)
        row.setSpacing(8)

    def maximize(self):
        self.window.showNormal() if self.window.isMaximized() else self.window.showMaximized()

    def mousePressEvent(self,event):
        if event.button() == Qt.LeftButton:
            self.window.windowHandle().startSystemMove()

    def mouseDoubleClickEvent(self,event):
        if event.button() == Qt.LeftButton:
            self.maximize()


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.monitor = Monitor()
        self.histories = defaultdict(lambda: deque(maxlen=65))
        self.snapshot = None
        self.selection = ('cpu','cpu')
        self.paused = False
        self.logical = False
        self.setWindowTitle('Gestione attività — Processi Linux')
        self.setWindowIcon(icon('performance',COLORS['cpu']))
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
        self.resize(1120,790)
        self.setMinimumSize(900,660)
        self.setObjectName('window')
        root = QVBoxLayout(self)
        root.setContentsMargins(1,1,1,1)
        root.setSpacing(0)
        root.addWidget(TitleBar(self))
        body = QHBoxLayout()
        body.setSpacing(0)
        root.addLayout(body,1)
        self.navigation = QWidget()
        self.navigation.setFixedWidth(240)
        self.navigation.setObjectName('navigation')
        nav = QVBoxLayout(self.navigation)
        nav.setContentsMargins(4,4,6,10)
        nav.setSpacing(4)
        self.navbuttons = []
        for key, text in [('processes','Processi'),('performance','Prestazioni')]:
            button = QPushButton(text)
            button.setIcon(icon(key))
            button.setIconSize(QSize(20,20))
            button.setFixedHeight(38)
            button.setObjectName('nav')
            button.setCheckable(True)
            button.setChecked(key == 'processes')
            button.clicked.connect(lambda checked=False,k=key: self.show_page(k))
            nav.addWidget(button)
            self.navbuttons.append((button,text))
        nav.addStretch()
        body.addWidget(self.navigation)
        surface = QWidget()
        surface.setObjectName('surface')
        area = QVBoxLayout(surface)
        area.setContentsMargins(0,0,0,0)
        area.setSpacing(0)
        toolbar = QWidget()
        toolbar.setObjectName('toolbar')
        toolbar.setFixedHeight(50)
        tools = QHBoxLayout(toolbar)
        tools.setContentsMargins(16,0,12,0)
        title = label('Prestazioni',14)
        title.setStyleSheet('font-weight:600; font-size:14px; background:transparent;')
        tools.addWidget(title)
        tools.addStretch()
        self.pause = QPushButton('Sospendi')
        self.pause.setIcon(icon('pause'))
        self.pause.clicked.connect(self.toggle_pause)
        tools.addWidget(self.pause)
        more = QToolButton()
        more.setIcon(icon('more'))
        more.setToolTip('Opzioni di visualizzazione')
        more.setAccessibleName('Opzioni di visualizzazione')
        menu = QMenu(more)
        self.core_action = menu.addAction('Mostra processori logici')
        self.core_action.setCheckable(True)
        self.core_action.toggled.connect(self.toggle_cores)
        menu.addAction('Copia informazioni',self.copy_info)
        menu.addAction('Informazioni',self.about)
        more.setMenu(menu)
        more.setPopupMode(QToolButton.InstantPopup)
        tools.addWidget(more)
        area.addWidget(toolbar)
        content = QHBoxLayout()
        content.setSpacing(0)
        area.addLayout(content,1)
        resource_scroll = QScrollArea()
        resource_scroll.setWidgetResizable(True)
        resource_scroll.setFixedWidth(210)
        resource_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        resource_scroll.setObjectName('resources')
        resources = QWidget()
        resource_layout = QVBoxLayout(resources)
        self.resource_layout = resource_layout
        resource_layout.setContentsMargins(4,6,4,6)
        resource_layout.setSpacing(0)
        self.resources = {}
        entries = [('cpu','cpu','CPU'),('memory','memory','Memoria')]
        for kind,key,title in entries:
            resource = Resource(title,COLORS[kind])
            resource.clicked.connect(lambda checked=False,k=kind,n=key: self.select(k,n))
            resource_layout.addWidget(resource)
            self.resources[(kind,key)] = resource
        resource_layout.addStretch()
        resource_scroll.setWidget(resources)
        content.addWidget(resource_scroll)
        detail_scroll = QScrollArea()
        detail_scroll.setWidgetResizable(True)
        detail_scroll.setObjectName('detail-scroll')
        detail_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        detail_scroll.setFrameShape(QFrame.NoFrame)
        detail = QWidget()
        self.detail_layout = QVBoxLayout(detail)
        self.detail_layout.setContentsMargins(28,18,26,12)
        self.detail_layout.setSpacing(5)
        heading = QHBoxLayout()
        self.heading = label('CPU',28)
        self.device = label(self.monitor.cpu_name,14)
        self.device.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.device.setWordWrap(True)
        heading.addWidget(self.heading)
        heading.addWidget(self.device,1)
        self.detail_layout.addLayout(heading)
        chart_labels = QHBoxLayout()
        self.chart_label = label('% di utilizzo',11,'#cccccc')
        self.scale = label('100%',11,'#cccccc')
        chart_labels.addWidget(self.chart_label)
        chart_labels.addStretch()
        chart_labels.addWidget(self.scale)
        self.detail_layout.addLayout(chart_labels)
        self.chartbox = QWidget()
        self.charts = QGridLayout(self.chartbox)
        self.charts.setContentsMargins(0,0,0,0)
        self.charts.setSpacing(5)
        self.graphs = [Graph(COLORS['cpu'])]
        self.charts.addWidget(self.graphs[0],0,0)
        self.detail_layout.addWidget(self.chartbox,1)
        axis = QHBoxLayout()
        axis.addWidget(label('60 secondi',10,'#cccccc'))
        axis.addStretch()
        axis.addWidget(label('0',10,'#cccccc'))
        self.detail_layout.addLayout(axis)
        self.composition_label = label('Composizione memoria',11,'#cccccc')
        self.detail_layout.addWidget(self.composition_label)
        self.composition = QProgressBar()
        self.composition.setRange(0,1000)
        self.composition.setTextVisible(False)
        self.composition.setFixedHeight(35)
        self.composition.setStyleSheet('QProgressBar {border:1px solid #8b8fd7; background:#191919; border-radius:0;} QProgressBar::chunk {background:#5e6196;}')
        self.detail_layout.addWidget(self.composition)
        self.composition.hide()
        self.composition_label.hide()
        self.stats = QWidget()
        self.stats_reflow = QTimer(self)
        self.stats_reflow.setSingleShot(True)
        self.stats_reflow.timeout.connect(self.reflow_stats)
        self.stats.installEventFilter(self)
        self.stats_layout = QGridLayout(self.stats)
        self.stats_layout.setSizeConstraint(QLayout.SetMinimumSize)
        self.stats_layout.setContentsMargins(0,8,0,0)
        self.stats_layout.setHorizontalSpacing(26)
        self.stats_layout.setVerticalSpacing(20)
        self.detail_layout.addWidget(self.stats)
        self.notice = label('',10,'#bdbdbd')
        self.notice.setWordWrap(True)
        self.detail_layout.addWidget(self.notice)
        detail_scroll.setWidget(detail)
        self.performance_detail = QStackedWidget()
        self.performance_detail.addWidget(detail_scroll)
        self.connection_page = ConnectionsPage()
        self.performance_detail.addWidget(self.connection_page)
        content.addWidget(self.performance_detail,1)
        self.pages = QStackedWidget()
        self.process_page = ProcessPage(icon('processes'))
        self.pages.addWidget(self.process_page)
        self.pages.addWidget(surface)
        self.pages.setCurrentIndex(0)
        body.addWidget(self.pages,1)
        grip = QSizeGrip(self)
        grip.setFixedSize(14,14)
        root.addWidget(grip,0,Qt.AlignRight)
        self.make_sampler()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll)
        self.timer.start(1000)
        self.select('cpu','cpu')
        self.poll()

    def make_sampler(self):
        monitor = self.monitor
        self.sampler = Sampler(monitor)
        # Queued signals from the previous source must never populate a new host.
        self.sampler.ready.connect(lambda data: self.receive(data) if self.monitor is monitor else None)
        self.sampler.failed.connect(lambda error: self.show_error(error) if self.monitor is monitor else None)

    def connection_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle('Collegamento a un server')
        dialog.setStyleSheet('QDialog { background:#202020; }')
        dialog.setMinimumWidth(470)
        layout = QVBoxLayout(dialog)
        description = label('Installa la versione server sul PC da monitorare. Inserisci il suo IP e la chiave mostrata sul server. Collegamento cifrato, in sola lettura.',12)
        description.setWordWrap(True)
        layout.addWidget(description)
        form = QFormLayout()
        host = QLineEdit()
        host.setPlaceholderText('192.168.1.50 oppure nome host')
        host.setAccessibleName('IP o nome del server')
        port = QSpinBox()
        port.setRange(1,65535)
        port.setValue(PORT)
        key = QLineEdit()
        key.setEchoMode(QLineEdit.Password)
        key.setPlaceholderText('Copia la chiave completa dal server')
        key.setAccessibleName('Chiave di accesso al server')
        if isinstance(self.monitor,RemoteMonitor):
            host.setText(self.monitor.host)
            port.setValue(self.monitor.port)
        form.addRow('IP / host',host)
        form.addRow('Porta',port)
        form.addRow('Chiave di accesso',key)
        layout.addLayout(form)
        error = label('',11,'#ffb4ab')
        error.setWordWrap(True)
        layout.addWidget(error)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText('Connetti')
        buttons.button(QDialogButtonBox.Cancel).setText('Annulla')
        buttons.rejected.connect(dialog.reject)
        def connect():
            try:
                monitor = RemoteMonitor(host.text(),port.value(),key.text())
            except ValueError as exc:
                error.setText(str(exc))
                return
            dialog.accept()
            self.switch_monitor(monitor)
        buttons.accepted.connect(connect)
        layout.addWidget(buttons)
        if isinstance(self.monitor,RemoteMonitor):
            local = buttons.addButton('Torna al PC locale',QDialogButtonBox.ResetRole)
            local.clicked.connect(lambda: (dialog.accept(),self.switch_monitor(Monitor())))
        dialog.exec()
        key.clear()

    def switch_monitor(self,monitor):
        self.timer.stop()
        self.sampler.wait()
        old = self.monitor
        self.monitor = monitor
        self.sampler.deleteLater()
        old.close()
        self.snapshot = None
        self.histories.clear()
        self.device_ids = {}
        self.paused = False
        self.pause.setText('Sospendi')
        self.pause.setIcon(icon('pause'))
        self.core_action.setChecked(False)
        self.process_page.reset(isinstance(monitor,RemoteMonitor))
        self.sync_resources({'disks':{},'nets':{},'gpus':{},'npus':{}})
        for resource in self.resources.values():
            if resource.graph:
                resource.graph.samples, resource.graph.secondary = [],[]
                resource.graph.update()
            resource.subtitle.setText('In attesa')
        self.connection_page.receive([])
        self.select('cpu','cpu')
        self.device.setText(monitor.cpu_name)
        self.set_stats([],[])
        self.composition.hide()
        self.composition_label.hide()
        self.info_text = 'In attesa dei contatori'
        self.notice.setText('Collegamento al server…' if isinstance(monitor,RemoteMonitor) else 'Lettura dei contatori locali…')
        self.source_label.setText(self.source_text())
        self.connect_button.setText('Connessione / PC locale' if isinstance(monitor,RemoteMonitor) else 'Connetti a un server')
        self.make_sampler()
        self.timer.start(1000)
        self.poll()

    def source_text(self):
        return 'Remoto · '+self.monitor.host+' · sola lettura' if isinstance(self.monitor,RemoteMonitor) else 'Gestione attività · PC locale'

    def show_page(self,key):
        self.pages.setCurrentIndex(0 if key == 'processes' else 1)
        for button,text in self.navbuttons:
            button.setChecked((text == 'Processi') == (key == 'processes'))
        self.setWindowTitle('Gestione attività — '+('Processi' if key == 'processes' else 'Prestazioni')+' Linux')

    def toggle_navigation(self):
        collapsed = self.navigation.width() > 100
        self.navigation.setFixedWidth(52 if collapsed else 240)
        for button,text in self.navbuttons:
            button.setText('' if collapsed else text)
            button.setToolTip(text if collapsed else ('Questa versione comprende la scheda Prestazioni' if not button.isEnabled() else text))

    def sync_resources(self,data):
        entries = [('cpu','cpu','CPU'),('memory','memory','Memoria')]
        entries += [('disks',name,f'Disco {i} ({name})') for i,name in enumerate(data['disks'])]
        entries += [('nets',name,'Wi-Fi' if device['wifi'] else 'Ethernet') for name,device in data['nets'].items()]
        entries += [('gpus',name,f'GPU {i}') for i,name in enumerate(data['gpus'])]
        entries += [('npus',name,f'NPU {i}') for i,name in enumerate(data['npus'])]
        entries += [('connections','connections','Collegamenti')]
        wanted = {(kind,key) for kind,key,_ in entries}
        reset = set(self.resources)-wanted
        for kind,key,_ in entries:
            if kind in ('disks','nets','gpus','npus'):
                old = getattr(self,'device_ids',{}).get((kind,key))
                identity = data[kind][key]['identity']
                if old is not None and old != identity:
                    reset.add((kind,key))
        for kind,key in reset:
            button = self.resources.pop((kind,key))
            self.resource_layout.removeWidget(button)
            button.hide()
            button.deleteLater()
            fields = (kind,'disk-read','disk-write') if kind == 'disks' else (kind,'sent','received') if kind == 'nets' else (kind,f'gpu-{key}')
            for history_key in list(self.histories):
                if history_key[0] in fields and (history_key[1] == key or history_key[0] == f'gpu-{key}'):
                    self.histories.pop(history_key)
        for index,(kind,key,title) in enumerate(entries):
            if (kind,key) not in self.resources:
                button = Resource(title,COLORS[kind],chart=kind != 'connections')
                button.clicked.connect(lambda checked=False,k=kind,n=key: self.select(k,n))
                self.resources[(kind,key)] = button
            button = self.resources[(kind,key)]
            if button.full_title != title:
                button.full_title = title
                button.setAccessibleName(title)
                button.title.setText(button.title.fontMetrics().elidedText(title,Qt.ElideRight,max(40,button.width()-88)))
            if self.resource_layout.indexOf(button) != index:
                self.resource_layout.insertWidget(index,button)
            button.setChecked((kind,key) == self.selection)
        self.device_ids = {(kind,key):d['identity'] for kind in ('disks','nets','gpus','npus') for key,d in data[kind].items()}
        if self.selection not in wanted or self.selection in reset:
            self.select('cpu','cpu')

    def poll(self):
        if not self.sampler.isRunning():
            self.sampler.start()

    def receive(self,data):
        self.source_label.setText(self.source_text())
        self.snapshot = data
        self.sync_resources(data)
        self.process_page.receive(data)
        now = time.monotonic()
        for kind in ('cpu','memory'):
            self.histories[(kind,kind)].append((now,data[kind]['value']))
        for i,v in enumerate(data['cpu']['cores']):
            self.histories[('core',str(i))].append((now,v))
        for kind in ('disks','nets','gpus','npus'):
            for key,values in data[kind].items():
                self.histories[(kind,key)].append((now,values['value']))
                if kind == 'gpus':
                    for engine,value in values['engines'].items():
                        self.histories[(f'gpu-{key}',engine)].append((now,value))
                if kind == 'disks':
                    for field in ('read','write'):
                        self.histories[(f'disk-{field}',key)].append((now,values[field]))
                if kind == 'nets':
                    for field in ('sent','received'):
                        self.histories[(field,key)].append((now,values[field]))
        if not self.paused:
            self.render()

    def show_error(self,error):
        if isinstance(self.monitor,RemoteMonitor):
            self.source_label.setText('Remoto · '+self.monitor.host+' · collegamento interrotto')
        self.notice.setText(error+' — nuovo tentativo tra un secondo.')
        self.process_page.status.setText(error+' — nuovo tentativo tra un secondo.')

    def select(self,kind,key):
        self.selection = (kind,key)
        for pair,button in self.resources.items():
            button.setChecked(pair == self.selection)
        self.core_action.setEnabled(kind == 'cpu')
        self.performance_detail.setCurrentIndex(1 if kind == 'connections' else 0)
        self.rebuild_graphs()
        if self.snapshot:
            self.render()

    def toggle_cores(self,enabled):
        self.logical = enabled
        self.rebuild_graphs()
        if self.snapshot:
            self.render()

    def rebuild_graphs(self):
        for graph in self.graphs:
            self.charts.removeWidget(graph)
            graph.hide()
            graph.deleteLater()
        for row in range(self.charts.rowCount()):
            self.charts.setRowStretch(row,0)
        self.graphs = []
        kind,_ = self.selection
        if kind == 'connections':
            return
        count = (len(self.snapshot['cpu']['cores']) if self.snapshot else (self.monitor.cpu_details[3][1] if len(self.monitor.cpu_details)>3 else 1)) if kind == 'cpu' and self.logical else 1
        count = int(count) if str(count).isdigit() else 1
        if kind == 'gpus':
            count = 4
        elif kind == 'disks':
            count = 2
        cols = 1 if kind == 'disks' else (4 if count > 8 else (2 if count > 1 else 1))
        for i in range(count):
            graph = Graph(COLORS[kind])
            graph.setMinimumSize(50,160 if count == 1 else 45)
            graph.setToolTip(f'Processore logico {i}' if count > 1 else 'Ultimi 60 secondi')
            self.charts.addWidget(graph,i//cols,i%cols)
            self.graphs.append(graph)
            if kind == 'disks':
                self.charts.setRowStretch(i,3 if i == 0 else 1)

    def toggle_pause(self):
        self.paused = not self.paused
        self.pause.setText('Riprendi' if self.paused else 'Sospendi')
        self.pause.setIcon(icon('play' if self.paused else 'pause'))
        if not self.paused and self.snapshot:
            self.render()

    def render(self):
        data = self.snapshot
        for (kind,key),button in self.resources.items():
            if kind == 'connections':
                nodes = data.get('connections')
                button.subtitle.setText('USB / Thunderbolt\n'+(f'{len(nodes)} elementi' if nodes is not None else 'Aggiorna il server'))
                continue
            d = data[kind] if kind in ('cpu','memory') else data[kind].get(key)
            if d is None:
                button.subtitle.setText('Dispositivo non disponibile')
                continue
            if kind == 'cpu':
                sub = f"{percent(d['value'])}  {d['freq']:.2f} GHz" if d['freq'] is not None else percent(d['value'])
            elif kind == 'memory':
                sub = f"{d['used']/1024**3:.1f}/{d['total']/1024**3:.1f} GB ({d['value']:.0f}%)"
            elif kind == 'disks':
                sub = f"{d['type']}\n{percent(d['value'])}"
            elif kind == 'nets':
                sub = f"{key}\n{network_summary(d['sent'],d['received'])}" if d['connected'] else f'{key}\nDisconnesso'
            else:
                sub = f"{d['name']}\n{percent(d['value'])}"
            button.subtitle.setText(sub)
            tooltip = f'{button.title.text()}\n{sub}'
            if kind == 'nets':
                hardware = d.get('hardware',{})
                tooltip += '\n'+' · '.join(v for v in (hardware.get('manufacturer'),hardware.get('model')) if v)
            button.setToolTip(tooltip)
            history = list(self.histories[(kind,key)])
            button.graph.samples = [(history[-1][0]-60,d['value']), history[-1]] if kind == 'memory' and history else history
            button.graph.maximum = max(1_000_000,max((v for _,v in history if v is not None),default=0)*1.1) if kind == 'nets' else 100
            button.graph.update()
        kind,key = self.selection
        if kind == 'connections':
            self.connection_page.receive(data.get('connections'))
            self.info_text = 'USB e Thunderbolt\n'+self.connection_page.copy_text
            return
        d = data[kind] if kind in ('cpu','memory') else data[kind].get(key)
        if d is None:
            self.notice.setText('Dispositivo non disponibile. In attesa del rilevamento automatico.')
            return
        self.notice.setText('')
        self.device.setToolTip('')
        self.composition.setVisible(kind == 'memory')
        self.composition_label.setVisible(kind == 'memory')
        values, details = [], []
        detail_columns = None
        self.scale.setText('100%')
        if kind == 'cpu':
            self.heading.setText('CPU')
            self.device.setText(self.monitor.cpu_name)
            self.chart_label.setText('% di utilizzo')
            values = [('Utilizzo',percent(d['value'])),('Velocità',f"{d['freq']:.2f} GHz" if d['freq'] is not None else 'N/D'),('Processi',str(d['processes'])),('Thread',str(d['threads'])),('File allocati',str(d['files'])),('Tempo di attività',uptime(d['uptime']))]
            details = self.monitor.cpu_details
        elif kind == 'memory':
            self.heading.setText('Memoria')
            hardware = self.monitor.memory_hardware
            self.device.setText(size(hardware['installed'] or d['total']))
            self.chart_label.setText('Utilizzo memoria')
            self.scale.setText(size(d['total']))
            self.composition.setValue(round(d['value']*10))
            self.composition.setToolTip(f"In uso: {size(d['used'])} · disponibile: {size(d['available'])}")
            committed = size(d['committed'])+' / '+size(d['commit_limit']) if d['committed'] is not None and d['commit_limit'] is not None else 'Non disponibile'
            values = [('In uso',size(d['used'])),('Disponibile',size(d['available'])),
                ('Impegnata / limite',committed),('Cache',size(d['cached'])),
                ('Slab recuperabile',size(d['slab_reclaimable'])),('Slab non recuperabile',size(d['slab_unreclaimable']))]
            slots = f"{hardware['slots_used']} di {hardware['slots_total']}" if hardware['slots_used'] is not None and hardware['slots_total'] is not None else 'Non disponibile'
            reserved = hardware['installed']-d['total'] if hardware['installed'] is not None and hardware['installed'] >= d['total'] else None
            details = [('Velocità:',hardware['speed'] or 'Non disponibile'),
                ('Slot utilizzati:',slots),('Fattore di forma:',hardware['form_factor'] or 'Non disponibile'),
                ('Tipo:',hardware['type'] or 'Non disponibile'),('Moduli:',hardware['modules'] or 'Non disponibile'),
                ('Riservata al sistema:',size(reserved)),('Utilizzabile da Linux:',size(d['total'])),
                ('Swap in uso / totale:',size(d['swap'])+' / '+size(d['swap_total'])),
                ('Buffer:',size(d['buffers'])),('Memoria condivisa:',size(d['shared']))]
            self.notice.setText('Velocità configurata dal firmware, in MT/s. Riservata al sistema: RAM installata meno memoria utilizzabile da Linux. Impegno e limite seguono la politica di overcommit Linux.')
        elif kind == 'disks':
            self.heading.setText(self.resources[(kind,key)].full_title.split(' (')[0])
            self.device.setText(d['model'])
            self.chart_label.setText('Tempo di attività')
            values = [('Tempo di attività',percent(d['value'])),('Risposta media',f"{d['latency']:.1f} ms" if d['latency'] is not None else 'Non disponibile'),('Velocità lettura',size(d['read'])+'/s' if d['read'] is not None else 'Non disponibile'),('Velocità scrittura',size(d['write'])+'/s' if d['write'] is not None else 'Non disponibile')]
            details = [('Capacità:',size(d['capacity'])),('Tipo:',d['type']),('Dispositivo:',f'/dev/{key}'),('Collegamento:',d['bus'] or 'Non disponibile'),
                ('Velocità negoziata:',d['link_speed'] or 'Non disponibile'),('Rimovibile:', 'Sì' if d['removable'] else 'No'),
                ('Montaggi:',', '.join(d.get('mounts',[])) or 'Non montato')]
            if d['bus'] == 'USB':
                details += [('Versione USB dichiarata:',d.get('usb_version') or 'Non disponibile'),('Prodotto USB:',d.get('usb_product') or 'Non disponibile')]
                if d.get('usb_route'):
                    details += [('Percorso USB:',d['usb_route']),('Controller USB:',d['usb_controller'])]
            self.notice.setText('La velocità negoziata è quella del collegamento, distinta dal trasferimento effettivo. Primo campione: in attesa dei contatori.' if d['value'] is None else 'La velocità negoziata del collegamento è distinta dalla velocità effettiva di lettura e scrittura.')
        elif kind == 'nets':
            self.heading.setText('Wi-Fi' if d['wifi'] else 'Ethernet')
            hardware = d.get('hardware',{})
            self.device.setText(hardware.get('model') or key)
            self.device.setToolTip(self.device.text())
            self.chart_label.setText('Velocità effettiva')
            values = [('Invio',bitrate(d['sent'])),('Ricezione',bitrate(d['received']))]
            hardware_id = ':'.join([hardware['vendor_id'],hardware['device_id']]) if hardware.get('vendor_id') and hardware.get('device_id') else 'Non disponibile'
            identity = [('Produttore:',hardware.get('manufacturer') or 'Non disponibile'),
                ('Modello:',hardware.get('model') or 'Non disponibile'),('ID hardware:',hardware_id)]
            if hardware.get('registered_vendor') and hardware['registered_vendor'] != hardware.get('manufacturer'):
                identity += [('Fornitore ID:',hardware['registered_vendor'])]
            adapter = [('Interfaccia:',key),('Tipo di connessione:','Wi-Fi' if d['wifi'] else 'Ethernet / virtuale'),
                ('Driver:',d['driver'] or 'Non disponibile'),('MTU:',str(d['mtu']) if d['mtu'] else 'Non disponibile'),
                ('Bus hardware:',hardware.get('bus') or d['link']['bus'] or 'Non disponibile'),
                ('Posizione:',hardware.get('location') or 'Non disponibile')]
            addresses = [('Indirizzo IPv4:',d['ipv4']),('Indirizzo IPv6:',d['ipv6']),
                ('Indirizzo MAC:',d['mac'] or 'Non disponibile')]
            if d['wifi']:
                connection = [(name,d.get(field) or 'Non disponibile') for name,field in (
                    ('Rete (SSID):','ssid'),('Standard Wi-Fi:','standard'),('Banda:','band'),('Frequenza:','frequency'),
                    ('Canale:','channel'),('Larghezza canale:','width'),('Segnale:','signal'),
                    ('Bitrate RX (radio):','rx_rate'),('Bitrate TX (radio):','tx_rate'))]
                addresses += [('Punto di accesso:',d.get('bssid') or 'Non disponibile')]
            else:
                connection = [('Velocità collegamento:',bitrate(d['speed']*1e6) if d['speed'] else 'Non disponibile'),
                    ('Duplex:',d['duplex'] or 'Non disponibile')]
            if d['link']['bus'] == 'USB':
                adapter += [('Collegamento USB:',d['link']['link_speed'] or 'Non disponibile')]
            elif d['link']['link_speed']:
                adapter += [('Velocità bus:',d['link']['link_speed'])]
            detail_columns = [[('Identità hardware',identity),('Collegamento Wi-Fi' if d['wifi'] else 'Collegamento Ethernet',connection)],
                [('Scheda di rete',adapter),('Indirizzi',addresses)]]
            if d['link'].get('usb_route'):
                detail_columns[0].append(('Percorso USB',[('Collegamento:',d['link']['usb_route']),('Controller:',d['link']['usb_controller'])]))
            details = [item for column in detail_columns for _,items in column for item in items]
            self.notice.setText('Traffico effettivo: linea continua RX, tratteggiata TX. I bitrate radio e la velocità del collegamento non sono la velocità Internet.' if d['connected'] else 'Disconnesso')
        elif kind == 'npus':
            self.heading.setText(self.resources[(kind,key)].full_title)
            self.device.setText(d['name'])
            self.chart_label.setText('% di utilizzo NPU')
            values = [('Utilizzo',percent(d['value'])),('Memoria NPU',size(d['memory'])),
                ('Frequenza',f"{d['freq']} MHz" if d['freq'] is not None else 'Non disponibile')]
            details = [('Driver:',d['driver']),('Bus PCI:',d['pci']),
                ('Frequenza massima:',f"{d['max_freq']} MHz" if d['max_freq'] is not None else 'Non disponibile'),
                ('Stato:',{'active':'Attiva','suspended':'Sospesa'}.get(d['state'],d['state'] or 'Non disponibile'))]
            self.notice.setText('Utilizzo reale dal tempo di esecuzione dei job del driver; memoria dei buffer residenti della NPU.' if d['value'] is not None else 'Il driver non espone un contatore di utilizzo NPU accessibile.' if d['busy'] is None else 'In attesa di due campioni del contatore NPU.')
        else:
            self.heading.setText(self.resources[(kind,key)].full_title)
            self.device.setText(d['name'])
            self.chart_label.setText('Utilizzo GPU')
            values = [('Utilizzo',percent(d['value'])),('Memoria dedicata',size(d['vram'])),('Frequenza',f"{d['freq']} MHz" if d['freq'] is not None else 'N/D')]
            details = [('Driver:',d['driver']),('Bus PCI:',d['pci']),('Memoria dedicata totale:',size(d['vram_total']))]
            if d['partial']:
                self.notice.setText('Utilizzo calcolato dai client GPU accessibili al tuo utente (fdinfo). I contatori non esposti dal driver sono indicati come non disponibili.')
            if d['value'] is None:
                self.notice.setText('Il driver non espone un contatore di utilizzo accessibile. Nessun valore simulato.')
        history = list(self.histories[(kind,key)])
        maximum = max(1_000_000,max((v for _,v in history if v is not None),default=0)*1.1) if kind == 'nets' else 100
        if kind == 'nets':
            self.scale.setText(bitrate(maximum))
        for i,graph in enumerate(self.graphs):
            graph.samples = list(self.histories[('core',str(i))]) if kind == 'cpu' and self.logical else history
            graph.maximum = maximum
            if kind == 'nets':
                graph.samples = list(self.histories[('received',key)])
                graph.secondary = list(self.histories[('sent',key)])
            else:
                graph.secondary = []
            if kind == 'disks' and i == 1:
                graph.samples = list(self.histories[('disk-read',key)])
                graph.secondary = list(self.histories[('disk-write',key)])
                graph.maximum = max(1024, max((v for _,v in graph.samples+graph.secondary if v is not None),default=0)*1.1)
                graph.caption = 'Lettura / scrittura · '+size(graph.maximum)+'/s'
            elif kind == 'gpus':
                engines = list(d['engines'])
                names = engines + [n for n in ('render','copy','video','compute') if n not in engines]
                name = names[i]
                graph.samples = list(self.histories[(f'gpu-{key}',name)])
                graph.caption = name+' · '+percent(d['engines'].get(name))
            graph.update()
        self.set_stats(values,details,detail_columns)
        self.info_text = self.heading.text()+' — '+self.device.text()+'\n'+'\n'.join(f'{k}: {v}' for k,v in values)+'\n'+'\n'.join(f'{k} {v}' for k,v in details)

    def eventFilter(self,watched,event):
        if watched is getattr(self,'stats',None) and event.type() == QEvent.Resize and event.size().width() != event.oldSize().width():
            self.stats_reflow.start(0)
        return super().eventFilter(watched,event)

    def reflow_stats(self):
        if hasattr(self,'stats_content'):
            self.set_stats(*self.stats_content)

    def set_stats(self,values,details,detail_columns=None):
        self.stats_content = values,details,detail_columns
        wide = self.stats.width() >= 560
        signature = (tuple(k for k,_ in values), tuple(k for k,_ in details),
            tuple(tuple(title for title,_ in column) for column in detail_columns) if detail_columns else None,wide)
        if getattr(self,'stats_signature',None) == signature:
            for widget,(_,value) in zip(self.value_labels,values):
                small = len(value) >= 17 or value == 'Non disponibile'
                was_small = len(widget.text()) >= 17 or widget.text() == 'Non disponibile'
                if small != was_small:
                    widget.setStyleSheet(f'color:#eeeeee; font-size:{14 if small else 20}px; background:transparent;')
                widget.setText(value)
            for widget,(_,value) in zip(self.detail_labels,details):
                widget.setText(value)
                widget.setToolTip(value)
            return
        self.stats_signature = signature
        self.value_labels, self.detail_labels = [], []
        while self.stats_layout.count():
            item = self.stats_layout.takeAt(0)
            if item.widget():
                item.widget().hide()
                item.widget().deleteLater()
        left = QWidget()
        grid = QGridLayout(left)
        grid.setContentsMargins(0,0,0,0)
        grid.setSpacing(12)
        for i,(name,value) in enumerate(values):
            cell = QWidget()
            column = QVBoxLayout(cell)
            column.setContentsMargins(0,0,0,0)
            column.setSpacing(3)
            column.addWidget(label(name,11,'#cccccc'))
            value_label = label(value,20 if len(value)<17 and value != 'Non disponibile' else 14)
            self.value_labels.append(value_label)
            column.addWidget(value_label)
            if detail_columns:
                cell.setMinimumWidth(140)
                grid.addWidget(cell,0,i)
            elif self.selection[0] == 'cpu':
                row, col, span = (0,i*3,3) if i < 2 else ((1,(i-2)*2,2) if i < 5 else (2,0,6))
                grid.addWidget(cell,row,col,1,span)
            else:
                grid.addWidget(cell,i//2,i%2)
        grid.setRowStretch((len(values)+1)//2,1)
        if detail_columns:
            grid.setColumnStretch(len(values),1)
        self.stats_layout.addWidget(left,0,0,1,2 if detail_columns else 1)
        right = QWidget()
        columns = QGridLayout(right)
        columns.setContentsMargins(0,0,0,0)
        columns.setHorizontalSpacing(24)
        columns.setVerticalSpacing(20)
        layouts = detail_columns or [[('',details)]]
        for column_index,sections in enumerate(layouts):
            container = QWidget()
            groups = QVBoxLayout(container)
            groups.setContentsMargins(0,0,0,0)
            groups.setSpacing(20)
            for title,items in sections:
                section = QWidget()
                section.setObjectName('detail-section')
                group = QVBoxLayout(section)
                group.setContentsMargins(0,0,0,0)
                group.setSpacing(8)
                if title:
                    heading = label(title,12)
                    heading.setObjectName('detail-heading')
                    heading.setStyleSheet('font-size:12px; font-weight:600; color:#eeeeee;')
                    group.addWidget(heading)
                rows = QGridLayout()
                rows.setContentsMargins(0,0,0,0)
                rows.setHorizontalSpacing(12)
                rows.setVerticalSpacing(4)
                rows.setColumnStretch(1,1)
                row = 0
                for name,value in items:
                    full_width = (title == 'Indirizzi' and name == 'Indirizzo IPv6:') or (title == 'Identità hardware' and name == 'Modello:')
                    name_label = label(name,11,'#cccccc')
                    name_label.setWordWrap(True)
                    rows.addWidget(name_label,row,0,1,2 if full_width else 1,Qt.AlignTop)
                    val = label(value,11)
                    val.setWordWrap(True)
                    policy = val.sizePolicy()
                    policy.setHorizontalPolicy(QSizePolicy.Ignored)
                    val.setSizePolicy(policy)
                    val.setMinimumWidth(0)
                    val.setTextInteractionFlags(Qt.TextSelectableByMouse)
                    val.setToolTip(value)
                    self.detail_labels.append(val)
                    if full_width:
                        rows.addWidget(val,row+1,0,1,2,Qt.AlignTop)
                    else:
                        rows.addWidget(val,row,1,Qt.AlignTop)
                    row += 2 if full_width else 1
                group.addLayout(rows)
                groups.addWidget(section)
            groups.addStretch()
            columns.addWidget(container,0 if wide or not detail_columns else column_index,
                column_index if wide or not detail_columns else 0)
            columns.setColumnStretch(column_index if wide else 0,1)
        self.stats_layout.addWidget(right,1 if detail_columns else 0,0 if detail_columns else 1,1,2 if detail_columns else 1)
        self.stats_layout.setColumnStretch(0,1)
        self.stats_layout.setColumnStretch(1,0 if detail_columns else 1)

    def copy_info(self):
        QApplication.clipboard().setText(getattr(self,'info_text','In attesa dei contatori'))

    def about(self):
        from PySide6.QtWidgets import QMessageBox
        QMessageBox.information(self,'Gestione attività per Linux','Prestazioni Linux\nPython + Qt · dati reali da psutil, /proc e /sys.\n\nProcessi e Prestazioni nello stile di Windows 11.\nTerminazione dei processi del proprio utente con conferma.\n\nCampionamento: 1 secondo · cronologia: 60 secondi.\nNon richiede privilegi amministrativi.')

    def resizeEvent(self,event):
        super().resizeEvent(event)
        if hasattr(self,'navigation') and self.width() < 1000 and self.navigation.width() > 100:
            self.toggle_navigation()

    def closeEvent(self,event):
        self.timer.stop()
        self.stats_reflow.stop()
        self.sampler.wait()
        self.monitor.close()
        event.accept()


def network_summary(sent,received):
    divisor,unit = (1e6,'Mbps') if max(sent,received) >= 1e6 else (1e3,'Kbps')
    return f'I:{sent/divisor:.1f} R:{received/divisor:.1f} {unit}'


def bitrate(value):
    for unit in ('bps','Kbps','Mbps','Gbps'):
        if value < 1000 or unit == 'Gbps':
            return f'{value:.1f} {unit}'
        value /= 1000


STYLE = '''
QWidget { color:#eeeeee; background:transparent; font-family:"Segoe UI","Noto Sans"; font-size:12px; }
#window, #navigation, #titlebar { background:#202020; }
#window { border:1px solid #3d3d3d; border-radius:8px; }
#surface, #resources, QScrollArea, QScrollArea > QWidget > QWidget { background:#191919; }
#toolbar { background:#272727; border-top-left-radius:8px; border-bottom:1px solid #303030; }
QScrollArea { border:none; }
QPushButton, QToolButton { border:none; border-radius:4px; padding:7px; background:transparent; }
QPushButton:hover, QToolButton:hover { background:#333333; }
QPushButton:focus-visible, QToolButton:focus-visible { border:1px solid #eeeeee; }
QPushButton:disabled { color:#858585; }
#close:hover { background:#c42b1c; }
#nav { text-align:left; padding-left:12px; }
#nav:checked { background:#303030; border-left:3px solid #d48bbb; }
#resource { background:#191919; border-radius:0; text-align:left; padding:0; }
#resource:hover { background:#252525; }
#resource:checked { background:#2c2c2c; }
QScrollBar:vertical { background:#202020; width:8px; }
QScrollBar::handle:vertical { background:#555555; border-radius:3px; min-height:24px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
#process-page { background:#191919; }
QLineEdit { background:#292929; border:1px solid #444444; border-bottom:1px solid #aaaaaa; border-radius:4px; padding:8px; }
QLineEdit:focus { border-bottom:2px solid #d48bbb; }
QTreeView { background:#191919; border:none; selection-background-color:#414141; selection-color:#ffffff; }
QTreeView::item { padding:0 8px; border:none; height:30px; }
QTreeView::item:selected { background:#414141; color:white; }
QHeaderView::section { background:#202020; color:#eeeeee; border:none; border-right:1px solid #353535; border-bottom:1px solid #353535; padding:6px 8px; }
QMenu { background:#2b2b2b; border:1px solid #444444; padding:4px; }
QMenu::item { padding:8px 24px; }
QMenu::item:selected { background:#404040; }
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--screenshot',type=Path,help='Save an actual live render after 4 samples and exit')
    args = parser.parse_args()
    app = QApplication(sys.argv[:1])
    app.setApplicationName('linux-task-manager')
    app.setApplicationDisplayName('Gestione attività Linux')
    app.setDesktopFileName('linux-task-manager')
    app.setStyle('Fusion')
    app.setStyleSheet(STYLE)
    window = Window()
    window.show()
    if args.screenshot:
        def capture():
            window.grab().save(str(args.screenshot))
            window.close()
        QTimer.singleShot(4200,capture)
    return app.exec()


if __name__ == '__main__':
    sys.exit(main())
