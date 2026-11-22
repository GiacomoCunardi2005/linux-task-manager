"""Live read-only USB / USB4 / Thunderbolt hierarchy."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTreeWidget,
    QTreeWidgetItem, QHeaderView, QPushButton, QApplication, QScrollArea, QGridLayout)


def text_label(text,pixels=12):
    label = QLabel(text)
    label.setTextFormat(Qt.PlainText)
    label.setWordWrap(True)
    label.setStyleSheet(f'font-size:{pixels}px;')
    label.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return label


def connection_summary(nodes):
    ports = [n for n in nodes if n['kind']=='Porta esterna']
    if not ports:
        return 'Conteggio prese non disponibile'
    uncertain = any(dict(n['details']).get('Identificazione')=='Canale non abbinato: conteggio fisico non verificabile' for n in ports)
    return f'{len(ports)} canali esterni (da abbinare)' if uncertain else f'{len(ports)} '+('porta esterna' if len(ports)==1 else 'porte esterne')+' (firmware)'


class ConnectionsPage(QWidget):
    def __init__(self):
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(24,20,24,16)
        root.setSpacing(12)
        heading = QHBoxLayout()
        self.heading = text_label('USB e Thunderbolt',26)
        heading.addWidget(self.heading,1)
        copy = QPushButton('Copia collegamenti')
        copy.clicked.connect(lambda:QApplication.clipboard().setText(self.copy_text))
        heading.addWidget(copy)
        root.addLayout(heading)
        self.intro = text_label('Controller, hub e dispositivi collegati. Le velocità sono quelle dei collegamenti, non il traffico effettivo.')
        root.addWidget(self.intro)
        self.body = QGridLayout()
        self.body.setContentsMargins(0,0,0,0)
        self.body.setSpacing(24)
        root.addLayout(self.body,1)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(['Dispositivo / hub','Standard','Collegamento'])
        self.tree.headerItem().setToolTip(1,'USB: versione dichiarata dal dispositivo. USB4/Thunderbolt: generazione rilevata dal kernel.')
        self.tree.setAccessibleName('Gerarchia USB, USB4 e Thunderbolt')
        self.tree.setUniformRowHeights(True)
        self.tree.setIndentation(16)
        self.tree.header().setSectionResizeMode(0,QHeaderView.Stretch)
        self.tree.setColumnWidth(1,100)
        self.tree.setColumnWidth(2,115)
        self.tree.setMinimumHeight(190)
        self.body.addWidget(self.tree,0,0)
        scroll = QScrollArea()
        self.detail_scroll = scroll
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setMinimumHeight(130)
        self.detail = text_label('Seleziona un dispositivo per vedere porte, velocità e controller.')
        self.detail.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        scroll.setWidget(self.detail)
        self.body.addWidget(scroll,1,0)
        self.notice = text_label('USB-C indica il connettore: non dimostra l’uso di Thunderbolt. I controller host sono distinti dai collegamenti esterni attivi.',11)
        self.notice.setStyleSheet('color:#bdbdbd; font-size:11px;')
        root.addWidget(self.notice)
        self.tree.currentItemChanged.connect(self.select)
        self.nodes, self.items, self.groups, self.copy_text = {},{},{},''

    def resizeEvent(self,event):
        super().resizeEvent(event)
        density = 2 if self.width() >= 1700 else 1 if self.width() >= 1050 or (self.height()>=900 and self.width()>=500) else 0
        side_by_side = self.width()>=1050
        if getattr(self,'layout_profile',None) == (density,side_by_side):
            return
        self.layout_profile = density,side_by_side
        self.density = density
        pixels = (12,14,16)[density]
        self.tree.setStyleSheet(f'QTreeWidget {{font-size:{pixels}px;}} QTreeView::item {{height:{30+5*density}px;}} QHeaderView::section {{font-size:{pixels}px;}}')
        self.tree.setColumnWidth(1,100+20*density)
        self.tree.setColumnWidth(2,115+25*density)
        self.detail.setStyleSheet(f'font-size:{pixels}px;')
        self.intro.setStyleSheet(f'font-size:{pixels}px;')
        self.heading.setStyleSheet(f'font-size:{26+4*density}px;')
        self.notice.setStyleSheet(f'color:#bdbdbd; font-size:{11+density}px;')
        self.body.removeWidget(self.detail_scroll)
        self.body.addWidget(self.detail_scroll,0 if side_by_side else 1,1 if side_by_side else 0)
        self.body.setColumnStretch(0,3 if side_by_side else 1)
        self.body.setColumnStretch(1,2 if side_by_side else 0)
        self.detail_scroll.setMinimumHeight(300 if density and not side_by_side else 130)
        self.body.setRowStretch(0,1)

    def receive(self,nodes):
        if nodes is None:
            nodes = []
            self.notice.setText('Collegamenti non disponibili.')
        else:
            self.notice.setText('USB-C indica il connettore. USB4 / Thunderbolt viene associato a una presa solo quando il kernel espone il collegamento. I controller non sono prese fisiche.')
            if any(n['kind']=='Controller host' for n in nodes) and not any(dict(n['details']).get('Associazione USB4 / Thunderbolt')=='Confermata dal kernel' for n in nodes):
                self.notice.setText('Controller USB4 / Thunderbolt rilevato. Il firmware non indica a quale presa USB-C corrisponde: associazione non disponibile. I controller non sono prese fisiche.')
            physical = next((dict(n['details']).get('Posizione fisica Thunderbolt 4') for n in nodes if dict(n['details']).get('Posizione fisica Thunderbolt 4')),None)
            if physical:
                self.notice.setText('Schema Lenovo di questo modello — Thunderbolt 4: '+physical+'. Altra USB-C: vicina alla cerniera. L’abbinamento alle righe port0 / port1 del kernel non è verificato; un dock USB non prova un link Thunderbolt attivo.')
            if any(dict(n['details']).get('Identificazione fisica')=='Verifica incrociata locale con Nikon e hub USB' for n in nodes):
                self.notice.setText('Prese identificate tramite prova incrociata locale con Nikon e hub e schema Lenovo. Thunderbolt 4 indica il supporto della presa; un dock USB non prova un link Thunderbolt attivo. Le altre posizioni fisiche restano da verificare.')
        self.intro.setText(connection_summary(nodes)+'. Controller e collegamenti interni sono raccolti nelle sezioni richiudibili. Le velocità indicano il link, non il traffico.')
        if nodes == list(self.nodes.values()):
            return
        previous = self.tree.currentItem()
        selected = previous.data(0,Qt.UserRole) if previous else None
        expanded = {key for key,item in self.items.items() if item.isExpanded()}
        group_expanded = {key:item.isExpanded() for key,item in self.groups.items()} if nodes else {}
        position = self.tree.verticalScrollBar().value()
        old_ids = set(self.items)
        self.tree.blockSignals(True)
        self.tree.clear()
        self.nodes, self.items, self.groups = {},{},{}
        lines = [self.intro.text(),self.notice.text(),'']
        for key,title in [('external','Porte e collegamenti esterni'),('internal','Collegamenti interni'),('controllers','Controller e root hub (non sono prese)'),('unknown','Dispositivi · posizione non disponibile')]:
            group = QTreeWidgetItem([title])
            self.groups[key] = group
            self.tree.addTopLevelItem(group)
        for node in nodes:
            name = node['name']
            if node['kind'] == 'Root hub / controller':
                name = node['id'].rsplit('/',1)[-1]+' · '+name
            link = node['speed'] or '—'
            if node['kind']=='Porta esterna':
                link = 'USB collegato' if dict(node['details']).get('Stato USB')=='Dispositivo collegato' else 'Nessun USB'
            item = QTreeWidgetItem([name,node['protocol'],link])
            item.setData(0,Qt.UserRole,node['id'])
            for column in range(3):
                item.setToolTip(column,node['name']+'\n'+node['protocol']+' · '+(node['speed'] or 'N/D')+'\n'+'\n'.join(f'{name}: {value}' for name,value in node['details']))
            scope = node.get('group','controllers' if node['kind'] in ('Root hub / controller','Controller host') else 'unknown')
            parent = self.items.get(node['parent'])
            parent_scope = self.nodes.get(node['parent'],{}).get('group',scope)
            if parent and (parent_scope == scope or 'group' not in node):
                parent.addChild(item)
            else:
                self.groups[scope].addChild(item)
            self.nodes[node['id']], self.items[node['id']] = dict(node,details=list(node['details'])),item
            lines.append(node['name']+' · '+node['protocol']+' · '+(node['speed'] or 'N/D'))
            lines.extend('  '+name+': '+value for name,value in node['details'])
        self.copy_text = '\n'.join(lines)
        self.tree.setCurrentItem(self.items.get(selected))
        # Selecting a hidden child can expand its ancestors; restore user state last.
        for key,item in self.items.items():
            item.setExpanded(key in expanded or key not in old_ids and self.nodes[key]['kind']!='Porta esterna')
        for key,group in self.groups.items():
            group.setHidden(group.childCount()==0)
            group.setText(0,group.text(0)+f' · {group.childCount()}')
            group.setExpanded(group_expanded.get(key,key in ('external','unknown')))
        self.tree.blockSignals(False)
        self.tree.verticalScrollBar().setValue(position)
        self.select(self.tree.currentItem())

    def select(self,item,*_):
        if item is None:
            self.detail.setText('Seleziona un dispositivo per vedere porte, velocità e controller.' if self.nodes else 'Nessun collegamento USB / Thunderbolt disponibile.')
            return
        if item.data(0,Qt.UserRole) not in self.nodes:
            self.detail.setText(item.text(0)+'\n\nApri la sezione e seleziona una riga per vedere i dettagli.')
            return
        node = self.nodes[item.data(0,Qt.UserRole)]
        chain = [node['name']]
        parent = node['parent']
        while parent in self.nodes:
            chain.append(self.nodes[parent]['name'])
            parent = self.nodes[parent]['parent']
        self.detail.setText(' → '.join(reversed(chain))+'\n\n'+'\n'.join(f'{key}: {value}' for key,value in node['details']))
