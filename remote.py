"""Read-only HTTPS transport shared by the desktop and headless server."""
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import ssl

PORT = 8765
MAX_SNAPSHOT = 32 * 1024 * 1024


def fingerprint(certificate):
    return hashlib.sha256(certificate).hexdigest()


def endpoint(host, port, key):
    host = host.strip()
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?', host):
            raise ValueError('Inserisci soltanto un IP o nome host, senza https:// o percorsi.') from None
    if not 1 <= int(port) <= 65535:
        raise ValueError('Porta non valida.')
    if not re.fullmatch(r'[a-f0-9]{64}\.[a-f0-9]{64}', key.strip()):
        raise ValueError('Chiave non valida: copia la chiave completa mostrata sul server.')
    pin, token = key.strip().split('.')
    return host, int(port), pin, token


def validate_packet(packet):
    """Validate the versioned wire shape before Qt consumes a remote sample."""
    number = lambda value: value is None or type(value) in (int, float) and 0 <= value <= 2**64
    percentage = lambda value: value is None or number(value) and value <= 100
    text = lambda value: value is None or isinstance(value, str)
    def fields(value, names, check):
        if not isinstance(value, dict) or any(name not in value or not check(value[name]) for name in names.split()):
            raise ValueError('Dati del server incompleti o non validi.')
    fields(packet, 'host cpu_name', lambda v: isinstance(v,str))
    if packet.get('version') != 1:
        raise ValueError('Versione server incompatibile: aggiorna app e server.')
    details = packet.get('cpu_details')
    if not isinstance(details,list) or any(not isinstance(pair,list) or len(pair)!=2 or any(not isinstance(v,str) for v in pair) for pair in details):
        raise ValueError('Dettagli CPU non validi.')
    fields(packet.get('memory_hardware'), 'speed rated_speed type form_factor modules', text)
    fields(packet['memory_hardware'], 'slots_used slots_total installed', number)
    data = packet.get('data')
    fields(data, 'cpu memory disks nets gpus npus', lambda v:isinstance(v,dict))
    fields(data['cpu'], 'processes threads uptime', lambda v:number(v) and v is not None)
    fields(data['cpu'], 'value', lambda v:percentage(v) and v is not None)
    fields(data['cpu'], 'freq', number)
    fields(data['cpu'], 'files', lambda v:isinstance(v,(str,int)))
    fields(data['cpu'], 'cores', lambda v:isinstance(v,list) and len(v)<=4096 and all(percentage(n) and n is not None for n in v))
    fields(data['memory'], 'total used available cached buffers shared swap swap_total', lambda v:number(v) and v is not None)
    fields(data['memory'], 'value', lambda v:percentage(v) and v is not None)
    fields(data['memory'], 'committed commit_limit slab_reclaimable slab_unreclaimable', number)
    if not isinstance(data.get('process_rows'),list):
        raise ValueError('Elenco processi non valido.')
    for row in data['process_rows']:
        fields(row, 'pid', lambda v:type(v) is int and 0 < v < 2**31)
        fields(row, 'created cpu memory disk network uid ppid', number)
        fields(row, 'name status user', lambda v:isinstance(v,str))
        fields(row, 'exe', text)
        fields(row, 'command_id', lambda v:isinstance(v,str) and re.fullmatch(r'[a-f0-9]{64}',v) is not None)
        fields(row, 'cmdline', lambda v:isinstance(v,list) and all(isinstance(arg,str) for arg in v))
    for kind in ('disks','nets','gpus','npus'):
        for key, device in data[kind].items():
            if not isinstance(key,str):
                raise ValueError('Identificatore dispositivo non valido.')
            fields(device, 'identity', lambda v:isinstance(v,str))
            fields(device, 'value', number if kind == 'nets' else percentage)
            if kind == 'disks':
                fields(device, 'capacity read write latency', number)
                fields(device, 'model type', lambda v:isinstance(v,str))
                fields(device, 'bus link_speed usb_version usb_product', text)
                fields(device, 'removable', lambda v:type(v) is bool)
                if 'usb_route' in device:
                    fields(device,'usb_route usb_controller',lambda v:isinstance(v,str))
                fields(device, 'mounts', lambda v:isinstance(v,list) and all(isinstance(s,str) for s in v))
            elif kind == 'nets':
                fields(device, 'sent received', lambda v:number(v) and v is not None)
                fields(device, 'speed mtu', number)
                fields(device, 'ipv4 ipv6', lambda v:isinstance(v,str))
                fields(device, 'duplex mac driver ssid standard band frequency channel width signal rx_rate tx_rate bssid', text)
                fields(device, 'connected wifi', lambda v:type(v) is bool)
                fields(device.get('link'), 'bus link_speed', text)
                if 'usb_route' in device['link']:
                    fields(device['link'],'usb_route usb_controller',lambda v:isinstance(v,str))
            else:
                fields(device, 'name driver pci', lambda v:isinstance(v,str))
                fields(device, 'freq', number)
                if kind == 'npus':
                    fields(device, 'memory max_freq busy', number)
                    fields(device, 'state', text)
                else:
                    fields(device, 'vram vram_total', number)
                    fields(device, 'partial', lambda v:type(v) is bool)
                    fields(device, 'engines', lambda v:isinstance(v,dict) and all(isinstance(k,str) and percentage(n) for k,n in v.items()))
    if 'connections' in data:
        if not isinstance(data['connections'],list) or len(data['connections'])>4096:
            raise ValueError('Elenco collegamenti non valido.')
        seen = set()
        for node in data['connections']:
            fields(node,'id name kind protocol',lambda v:isinstance(v,str))
            fields(node,'parent speed',text)
            fields(node,'details',lambda v:isinstance(v,list) and all(isinstance(pair,list) and len(pair)==2 and all(isinstance(s,str) for s in pair) for pair in v))
            if node['id'] in seen or node['parent'] is not None and node['parent'] not in seen:
                raise ValueError('Gerarchia dei collegamenti non valida.')
            seen.add(node['id'])
    fields(data, 'process_network_status', lambda v:isinstance(v,str))
    return data


class RemoteMonitor:
    def __init__(self, host, port, key):
        self.host, self.port, self.pin, self.token = endpoint(host,port,key)
        self.cpu_name = 'In attesa del server'
        self.cpu_details = []
        self.memory_hardware = {}

    def sample(self):
        # The out-of-band key pins the certificate before any credential is sent.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = http.client.HTTPSConnection(self.host,self.port,context=context,timeout=3)
        try:
            connection.connect()
            actual = fingerprint(connection.sock.getpeercert(binary_form=True))
            if not hmac.compare_digest(actual,self.pin):
                raise ValueError('Certificato diverso dalla chiave: verifica la chiave sul server.')
            connection.request('GET','/v1/snapshot',headers={'Authorization':'Bearer '+self.token})
            response = connection.getresponse()
            if response.status == 401:
                raise ValueError('Chiave di accesso rifiutata dal server.')
            if response.status == 503:
                raise ValueError('Il server non dispone di un campione recente.')
            if response.status != 200:
                raise ValueError(f'Risposta server inattesa ({response.status}).')
            raw = response.read(MAX_SNAPSHOT+1)
            if len(raw) > MAX_SNAPSHOT:
                raise ValueError('Risposta server troppo grande.')
            packet = json.loads(raw)
            data = validate_packet(packet)
            self.cpu_name, self.cpu_details = packet['cpu_name'], packet['cpu_details']
            self.memory_hardware = packet['memory_hardware']
            return data
        finally:
            connection.close()

    def close(self):
        self.token = ''
