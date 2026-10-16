"""Live Windows-style process table; Linux counters, no fabricated network usage."""
import os
import configparser
import math
from pathlib import Path
import shlex
import psutil
from PySide6.QtCore import Qt, QAbstractItemModel, QSortFilterProxyModel, QModelIndex, QStandardPaths, QItemSelectionModel
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTreeView, QHeaderView, QAbstractItemView, QMessageBox, QStyledItemDelegate, QStyle)
from metrics import size, terminate_process

HEADERS = ['Nome','Stato','CPU','Memoria','Disco','Rete','PID']
STATES = {'running':'In esecuzione','sleeping':'In attesa','disk-sleep':'Attesa disco',
          'stopped':'Sospeso','tracing-stop':'In debug','zombie':'Zombie','idle':'Inattivo','dead':'Terminato'}
SORT_ROLE = Qt.UserRole + 1


def process_groups(rows):
    groups = {}
    by_pid = {row['pid']:row for row in rows}
    for raw in rows:
        row = dict(raw)
        row['_identity'] = ('pid',row['pid'],row['created'])
        program = Path(row.get('exe') or row['name']).name
        parent = by_pid.get(row.get('ppid'))
        if parent and parent.get('uid') == row.get('uid'):
            parent_program = Path(parent.get('exe') or parent['name']).name
            if program.startswith(parent_program+'-'):
                program = parent_program
        args = row.get('cmdline',[])
        script = tuple(args[1:]) if Path(program).name.startswith(('python','pypy')) or Path(program).name in ('node','nodejs','java','bash','sh') else ()
        key = (row.get('uid',row['user']),program,script)
        groups.setdefault(key,[]).append(row)
    result = []
    for key,children in groups.items():
        if len(children) == 1:
            result.append(children[0])
            continue
        group = dict(children[0],name=key[1],pid=None,created=None,children=children,_identity=('app',key))
        for metric in ('cpu','memory','disk','network'):
            values = [row.get(metric) for row in children if row.get(metric) is not None]
            group[metric] = sum(values) if values else None
        group['status'] = f'{len(children)} processi'
        for child in children:
            child['_parent'] = group
        result.append(group)
    for index,row in enumerate(result):
        row['_row'] = index
    return result


class ProcessModel(QAbstractItemModel):
    def __init__(self, fallback_icon):
        super().__init__()
        self.rows = []
        self.totals = {}
        self.fallback_icon = fallback_icon
        self.icons = {}
        icon_paths = [str(Path(path)/'icons') for path in QStandardPaths.standardLocations(QStandardPaths.GenericDataLocation)]
        QIcon.setThemeSearchPaths([str(Path.home()/'.icons')]+icon_paths+QIcon.themeSearchPaths())
        QIcon.setFallbackThemeName('hicolor')
        if not QIcon.themeName():
            QIcon.setThemeName('Adwaita' if 'GNOME' in os.environ.get('XDG_CURRENT_DESKTOP','') else 'breeze')
        self.desktop_icons = {}
        for directory in reversed(QStandardPaths.standardLocations(QStandardPaths.ApplicationsLocation)):
            for desktop in Path(directory).rglob('*.desktop'):
                config = configparser.ConfigParser(interpolation=None,strict=False)
                try:
                    config.read(desktop,encoding='utf-8')
                    entry = config['Desktop Entry']
                    image = entry.get('Icon','')
                    if not image:
                        continue
                    keys = [desktop.stem,desktop.stem.split('.')[-1],entry.get('Name','')]
                    command = shlex.split(entry.get('Exec',''))
                    if command and Path(command[0]).name not in ('env','flatpak','sh','bash','python','python3'):
                        keys.append(Path(command[0]).name)
                    for key in keys:
                        if key:
                            self.desktop_icons[key.casefold()] = image
                except (OSError,UnicodeError,configparser.Error,KeyError,ValueError):
                    continue

    def rowCount(self,parent=QModelIndex()):
        if not parent.isValid():
            return len(self.rows)
        return len(parent.internalPointer().get('children',[])) if parent.column() == 0 else 0

    def index(self,row,column,parent=QModelIndex()):
        if parent.isValid() and parent.column() != 0:
            return QModelIndex()
        nodes = parent.internalPointer().get('children',[]) if parent.isValid() else self.rows
        if not 0 <= row < len(nodes) or not 0 <= column < len(HEADERS):
            return QModelIndex()
        return self.createIndex(row,column,nodes[row])

    def parent(self,index):
        if not index.isValid():
            return QModelIndex()
        parent = index.internalPointer().get('_parent')
        return self.createIndex(parent['_row'],0,parent) if parent else QModelIndex()

    def record(self,index):
        return index.internalPointer() if index.isValid() else None

    def columnCount(self,parent=QModelIndex()):
        return len(HEADERS)

    def data(self,index,role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row, column = self.record(index), index.column()
        name = row['name']+(f" ({len(row['children'])})" if 'children' in row else '')
        values = [name,STATES.get(row['status'],row['status'] or 'N/D'),row['cpu'],row['memory'],row['disk'],row.get('network'),row['pid']]
        value = values[column]
        if role == SORT_ROLE:
            return (-1 if value is None else value) if column >= 2 else str(value).casefold()
        if role == Qt.DisplayRole:
            if value is None:
                return '—' if column == 6 and 'children' in row else 'N/D'
            if column == 2:
                return f'{value:.1f}%'
            if column == 3:
                return f'{value/1024**2:,.1f} MB'
            if column == 4:
                return f'{value/1024**2:.1f} MB/s'
            if column == 5:
                return f'{value/1e6:.2f} Mbps'
            return str(value)
        if role == Qt.TextAlignmentRole:
            return int(Qt.AlignVCenter | (Qt.AlignRight if column >= 2 else Qt.AlignLeft))
        if role == Qt.DecorationRole and column == 0:
            name = row['name']
            if name not in self.icons:
                image = self.desktop_icons.get(name.casefold(),name.lower())
                resolved = QIcon(image) if Path(image).is_absolute() else QIcon.fromTheme(image,self.fallback_icon)
                self.icons[name] = self.fallback_icon if resolved.isNull() else resolved
            return self.icons[name]
        if role == Qt.ToolTipRole:
            if column == 5:
                return 'Traffico TCP + UDP attribuito da NetHogs. Alcuni pacchetti o connessioni non attribuibili possono mancare. N/D: campione iniziale o cattura non disponibile.'
            if 'children' in row:
                return row['name']+' · PID: '+', '.join(str(child['pid']) for child in row['children'])+'\nConsumi aggregati disponibili; la somma RSS può contare pagine condivise. Espandi per selezionare un processo.'
            return f"{row['name']} · PID {row['pid']}\nUtente: {row['user']}\nMemoria: RSS residente; CPU: percentuale dell’intero sistema."
        if role == Qt.BackgroundRole and column in (2,3,4,5):
            strength = 0
            if column == 2:
                strength = (row['cpu'] or 0)/100
            elif column == 3:
                strength = (row['memory'] or 0)/max(1,self.totals.get('memory_total',1))
            elif column == 4:
                strength = min(1,(row['disk'] or 0)/(20*1024**2))
            elif column == 5:
                strength = min(1,(row.get('network') or 0)/1e8)
            strength = math.sqrt(max(0,min(1,strength)))
            return QColor(51+int(strength*80),34+int(strength*32),39+int(strength*35))
        return None

    def headerData(self,section,orientation,role=Qt.DisplayRole):
        if orientation != Qt.Horizontal:
            return None
        if role == Qt.DisplayRole:
            return (self.totals.get(section,'')+'\n'+HEADERS[section]) if section in (2,3,4,5) else HEADERS[section]
        if role == Qt.TextAlignmentRole:
            return int(Qt.AlignVCenter | (Qt.AlignRight if section >= 2 else Qt.AlignLeft))
        if role == Qt.ToolTipRole and section == 4:
            return 'Totale: tempo di attività del disco più impegnato. Righe: letture + scritture per processo.'
        return None

    def update(self,data):
        self.beginResetModel()
        self.process_count = len(data['process_rows'])
        self.rows = process_groups(data['process_rows'])
        disk_loads = [d['value'] for d in data['disks'].values() if d['value'] is not None]
        self.totals = {2:f"{data['cpu']['value']:.0f}%",3:f"{data['memory']['value']:.0f}%",
            4:f"{max(disk_loads):.0f}%" if disk_loads else 'N/D',
            5:f"{sum(d['sent']+d['received'] for d in data['nets'].values())/1e6:.1f} Mbps",
            'memory_total':data['memory']['total']}
        self.endResetModel()
        self.headerDataChanged.emit(Qt.Horizontal,0,6)


class ProcessFilter(QSortFilterProxyModel):
    def filterAcceptsRow(self,row,parent):
        query = getattr(self,'query','')
        item = self.sourceModel().record(self.sourceModel().index(row,0,parent))
        return query in f"{item['name']} {item['pid']} {item['user']}".casefold()


class HeatDelegate(QStyledItemDelegate):
    def paint(self,painter,option,index):
        painter.save()
        selected = bool(option.state & QStyle.State_Selected)
        painter.fillRect(option.rect,QColor('#414141') if selected else index.data(Qt.BackgroundRole))
        painter.setPen(QColor('#3b2c30'))
        painter.drawLine(option.rect.topLeft(),option.rect.bottomLeft())
        painter.setPen(QColor('#eeeeee'))
        painter.drawText(option.rect.adjusted(8,0,-8,0),Qt.AlignRight | Qt.AlignVCenter,index.data())
        painter.restore()


class ProcessPage(QWidget):
    def __init__(self,icon):
        super().__init__()
        self.setObjectName('process-page')
        self.paused = False
        self.latest = None
        root = QVBoxLayout(self)
        root.setContentsMargins(0,0,0,0)
        root.setSpacing(0)
        searchbar = QWidget()
        searchrow = QHBoxLayout(searchbar)
        searchrow.setContentsMargins(16,8,16,8)
        self.search = QLineEdit()
        self.search.setPlaceholderText('Cerca per nome, PID o utente')
        self.search.setClearButtonEnabled(True)
        self.search.setAccessibleName('Cerca processi')
        searchrow.addWidget(self.search)
        root.addWidget(searchbar)
        toolbar = QWidget()
        toolbar.setObjectName('toolbar')
        toolbar.setFixedHeight(50)
        actions = QHBoxLayout(toolbar)
        actions.setContentsMargins(16,0,12,0)
        title = QLabel('Processi')
        title.setStyleSheet('font-size:14px; font-weight:600;')
        actions.addWidget(title)
        actions.addStretch()
        self.pause = QPushButton('Sospendi')
        self.pause.clicked.connect(self.toggle_pause)
        actions.addWidget(self.pause)
        self.end_task = QPushButton('Termina attività')
        self.end_task.setEnabled(False)
        self.end_task.clicked.connect(self.end_selected)
        actions.addWidget(self.end_task)
        root.addWidget(toolbar)
        self.model = ProcessModel(icon)
        self.proxy = ProcessFilter(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setRecursiveFilteringEnabled(True)
        self.proxy.setAutoAcceptChildRows(True)
        self.proxy.setSortRole(SORT_ROLE)
        self.table = QTreeView()
        self.table.setUniformRowHeights(True)
        self.table.setIndentation(18)
        self.table.setRootIsDecorated(True)
        self.table.setModel(self.proxy)
        self.table.setAccessibleName('Processi in esecuzione')
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.header().setFixedHeight(50)
        self.table.header().setStretchLastSection(False)
        for col,width in enumerate((240,112,78,100,96,88,66)):
            self.table.setColumnWidth(col,width)
        self.table.header().setSectionResizeMode(0,QHeaderView.Stretch)
        self.heat_delegate = HeatDelegate(self.table)
        for col in (2,3,4,5):
            self.table.setItemDelegateForColumn(col,self.heat_delegate)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(2,Qt.DescendingOrder)
        self.table.selectionModel().selectionChanged.connect(self.selection_changed)
        self.search.textChanged.connect(self.filter_changed)
        root.addWidget(self.table,1)
        self.status = QLabel('Lettura dei processi…')
        self.status.setWordWrap(True)
        self.status.setStyleSheet('color:#bdbdbd; padding:8px 16px; font-size:11px;')
        root.addWidget(self.status)

    def selected(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        return self.model.record(self.proxy.mapToSource(rows[0]))

    def selection_changed(self,*args):
        row = self.selected()
        self.end_task.setToolTip('Espandi il gruppo e seleziona il singolo PID da terminare' if row and 'children' in row else 'Termina il processo selezionato')
        self.end_task.setEnabled(bool(row and row['uid'] == os.getuid() and row['created'] is not None and row['pid'] is not None and row['pid'] not in (0,1,os.getpid())))

    def filter_changed(self,text):
        self.proxy.query = text.casefold()
        self.proxy.invalidate()
        if text:
            self.table.expandAll()
        self.selection_changed()
        self.update_status()

    def receive(self,data):
        self.latest = data
        if self.paused:
            return
        old = self.selected()
        identity = old['_identity'] if old else None
        expanded = {self.model.record(self.proxy.mapToSource(self.proxy.index(i,0)))['_identity']
            for i in range(self.proxy.rowCount()) if self.table.isExpanded(self.proxy.index(i,0))}
        position = self.table.verticalScrollBar().value()
        self.model.update(data)
        for i,row in enumerate(self.model.rows):
            index = self.proxy.mapFromSource(self.model.index(i,0))
            if index.isValid() and (row['_identity'] in expanded or self.search.text()):
                self.table.setExpanded(index,True)
            for child_index,node in [(None,row)]+list(enumerate(row.get('children',[]))):
                if node['_identity'] != identity:
                    continue
                source = self.model.index(i,0) if child_index is None else self.model.index(child_index,0,self.model.index(i,0))
                target = self.proxy.mapFromSource(source)
                if target.isValid():
                    self.table.selectionModel().select(target,QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
        self.table.verticalScrollBar().setValue(position)
        self.selection_changed()
        self.update_status()

    def update_status(self):
        self.status.setText(f"{getattr(self.model,'process_count',0)} processi · {self.proxy.rowCount()} applicazioni/voci · "+(self.latest.get('process_network_status','Rete in attesa') if self.latest else 'Rete in attesa')+(' · Aggiornamento sospeso' if self.paused else ''))

    def toggle_pause(self):
        self.paused = not self.paused
        self.pause.setText('Riprendi' if self.paused else 'Sospendi')
        if not self.paused and self.latest:
            self.receive(self.latest)
        self.update_status()

    def end_selected(self):
        row = self.selected()
        if not row or not self.end_task.isEnabled():
            return
        answer = QMessageBox.question(self,'Termina attività',
            f"Terminare {row['name']} (PID {row['pid']})?\nI dati non salvati potrebbero andare persi.",
            QMessageBox.Yes | QMessageBox.No,QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        try:
            terminate_process(row['pid'],row['created'])
            self.status.setText(f"Richiesta di terminazione inviata a {row['name']} (PID {row['pid']}).")
        except psutil.NoSuchProcess:
            self.status.setText('Il processo è già terminato o il PID è cambiato.')
        except (psutil.AccessDenied,PermissionError,ValueError) as exc:
            QMessageBox.warning(self,'Impossibile terminare',str(exc))
