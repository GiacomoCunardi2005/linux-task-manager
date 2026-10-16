"""Live read-only USB / USB4 / Thunderbolt hierarchy."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTreeWidget,
    QTreeWidgetItem, QHeaderView, QPushButton, QApplication, QScrollArea)


def text_label(text,pixels=12):
    label = QLabel(text)
    label.setTextFormat(Qt.PlainText)
    label.setWordWrap(True)
    label.setStyleSheet(f'font-size:{pixels}px;')
    label.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return label


class ConnectionsPage(QWidget):
    def __init__(self):
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(24,20,24,16)
        root.setSpacing(12)
        heading = QHBoxLayout()
        heading.addWidget(text_label('USB e Thunderbolt',26),1)
        copy = QPushButton('Copia collegamenti')
        copy.clicked.connect(lambda:QApplication.clipboard().setText(self.copy_text))
        heading.addWidget(copy)
        root.addLayout(heading)
        root.addWidget(text_label('Controller, hub e dispositivi collegati. Le velocità sono quelle dei collegamenti, non il traffico effettivo.'))
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
        root.addWidget(self.tree,1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setMinimumHeight(130)
        self.detail = text_label('Seleziona un dispositivo per vedere porte, velocità e controller.')
        self.detail.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        scroll.setWidget(self.detail)
        root.addWidget(scroll)
        self.notice = text_label('USB-C indica il connettore: non dimostra l’uso di Thunderbolt. I controller host sono distinti dai collegamenti esterni attivi.',11)
        self.notice.setStyleSheet('color:#bdbdbd; font-size:11px;')
        root.addWidget(self.notice)
        self.tree.currentItemChanged.connect(self.select)
        self.nodes, self.items, self.copy_text = {},{},''

    def receive(self,nodes):
        if nodes is None:
            nodes = []
            self.notice.setText('Questo server non espone i collegamenti: aggiorna la versione server.')
        else:
            self.notice.setText('USB-C indica il connettore: non dimostra l’uso di Thunderbolt. I controller host sono distinti dai collegamenti esterni attivi.')
        if nodes == list(self.nodes.values()):
            return
        previous = self.tree.currentItem()
        selected = previous.data(0,Qt.UserRole) if previous else None
        expanded = {key for key,item in self.items.items() if item.isExpanded()}
        position = self.tree.verticalScrollBar().value()
        old_ids = set(self.items)
        self.tree.blockSignals(True)
        self.tree.clear()
        self.nodes, self.items = {},{}
        lines = []
        for node in nodes:
            name = node['name']
            if node['kind'] == 'Root hub / controller':
                name = node['id'].rsplit('/',1)[-1]+' · '+name
            item = QTreeWidgetItem([name,node['protocol'],node['speed'] or '—'])
            item.setData(0,Qt.UserRole,node['id'])
            for column in range(3):
                item.setToolTip(column,node['name']+'\n'+node['protocol']+' · '+(node['speed'] or 'N/D')+'\n'+'\n'.join(f'{name}: {value}' for name,value in node['details']))
            parent = self.items.get(node['parent'])
            if parent:
                parent.addChild(item)
            else:
                self.tree.addTopLevelItem(item)
            self.nodes[node['id']], self.items[node['id']] = dict(node,details=list(node['details'])),item
            lines.append(node['name']+' · '+node['protocol']+' · '+(node['speed'] or 'N/D'))
            lines.extend('  '+name+': '+value for name,value in node['details'])
        self.copy_text = '\n'.join(lines)
        self.tree.setCurrentItem(self.items.get(selected))
        # Selecting a hidden child can expand its ancestors; restore user state last.
        for key,item in self.items.items():
            item.setExpanded(key in expanded or key not in old_ids)
        self.tree.blockSignals(False)
        self.tree.verticalScrollBar().setValue(position)
        self.select(self.tree.currentItem())

    def select(self,item,*_):
        if item is None:
            self.detail.setText('Seleziona un dispositivo per vedere porte, velocità e controller.' if self.nodes else 'Nessun collegamento USB / Thunderbolt disponibile.')
            return
        node = self.nodes[item.data(0,Qt.UserRole)]
        chain = [node['name']]
        parent = node['parent']
        while parent in self.nodes:
            chain.append(self.nodes[parent]['name'])
            parent = self.nodes[parent]['parent']
        self.detail.setText(' → '.join(reversed(chain))+'\n\n'+'\n'.join(f'{key}: {value}' for key,value in node['details']))
