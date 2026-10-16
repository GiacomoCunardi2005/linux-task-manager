"""Read-only Linux device discovery and negotiated link metadata."""
from pathlib import Path
import re
import subprocess


def read(path, default=''):
    try:
        return Path(path).read_text().strip()
    except (OSError, UnicodeError):
        return default


def number(path):
    try:
        return int(read(path))
    except ValueError:
        return None


def usb_speed(node):
    try:
        rate = float(read(Path(node)/'speed'))
        if 0 < rate < 1000000:
            return f'{rate/1000:g} Gbit/s' if rate >= 1000 else f'{rate:g} Mbit/s'
    except ValueError:
        pass
    return None


def link_details(path):
    device = Path(path).resolve()
    parents = (device,*device.parents)
    usb = [node for node in parents if (node/'idVendor').exists()]
    if usb:
        node, root = usb[0],usb[-1]
        route = []
        for ancestor in reversed(usb):
            name = read(ancestor/'product') or ancestor.name
            speed = usb_speed(ancestor) if not re.fullmatch(r'usb\d+',ancestor.name) else None
            route.append(name+(f' ({speed})' if speed else ''))
        return {'bus':'USB','link_speed':usb_speed(node),
            'usb_version':read(node/'version') or None,'usb_product':read(node/'product') or None,
            'usb_route':' → '.join(route), 'usb_controller':root.parent.name}
    for node in parents:
        if re.fullmatch(r'ata\d+',node.name):
            speed = next((read(p) for p in node.glob('link*/sata_spd') if read(p)),None)
            return {'bus':'SATA','link_speed':speed}
    for node in parents:
        if (node/'current_link_speed').exists():
            speed, width = read(node/'current_link_speed'),number(node/'current_link_width')
            speed = speed if re.match(r'[0-9]+(?:\.[0-9]+)? GT/s',speed) else None
            return {'bus':'PCIe','link_speed':speed+(f' ×{width}' if width and width > 0 else '') if speed else None}
    return {'bus':None,'link_speed':None}


def disk_devices(root=Path('/sys/block')):
    devices = {}
    for path in sorted(root.glob('*')):
        if path.name.startswith(('loop','ram','zram','dm-')) or not (path/'dev').exists():
            continue
        link = link_details(path/'device')
        sequence = read(path/'diskseq')
        devices[path.name] = {**link,'identity':sequence or str(path.resolve()),
            'capacity':(number(path/'size') or 0)*512,
            'model':read(path/'device/model',path.name),
            'removable':read(path/'removable') == '1',
            'type':'Disco USB' if link['bus'] == 'USB' else 'SD / eMMC' if path.name.startswith('mmcblk') else 'Unità ottica' if path.name.startswith('sr') else 'HDD' if read(path/'queue/rotational') == '1' else 'SSD'}
    return devices


def gpu_devices(root=Path('/sys/class/drm')):
    devices = []
    for card in sorted(root.glob('card[0-9]*')):
        if not re.fullmatch(r'card\d+',card.name):
            continue
        device = card/'device'
        brand = {'0x8086':'Intel Graphics','0x1002':'AMD Radeon','0x10de':'NVIDIA'}.get(read(device/'vendor'),'GPU')
        devices.append({'card':card,'name':brand,'pci':device.resolve().name,
                        'driver':(device/'driver').resolve().name})
    return devices


def npu_devices(root=Path('/sys/class/accel')):
    devices = {}
    for accel in sorted(root.glob('accel[0-9]*')):
        if not re.fullmatch(r'accel\d+',accel.name):
            continue
        device = accel/'device'
        driver = (device/'driver').resolve().name if (device/'driver').exists() else 'Non disponibile'
        brand = {'intel_vpu':'Intel AI Boost','amdxdna':'AMD Ryzen AI'}.get(driver,'Acceleratore AI')
        frequency = number(device/'freq/current_freq')
        maximum = number(device/'freq/hw_max_freq')
        devices[accel.name] = {'name':brand,'driver':driver,'pci':device.resolve().name,
            'identity':str(device.resolve()), 'busy':number(device/'npu_busy_time_us'),
            'memory':number(device/'npu_memory_utilization'),
            'freq':frequency if frequency is not None else number(device/'npu_current_frequency_mhz'),
            'max_freq':maximum if maximum is not None else number(device/'npu_max_frequency_mhz'),
            'state':read(device/'power/runtime_status') or None}
    return devices


def network_identity(name):
    return str(Path(f'/sys/class/net/{name}').resolve())+'|'+read(f'/sys/class/net/{name}/address')


def network_hardware(net):
    net = Path(net)
    device = (net/'device').resolve()
    empty = dict(manufacturer=None,model=None,registered_vendor=None,vendor_id=None,device_id=None,bus='Virtuale',location=None)
    if not (net/'device').exists():
        return empty
    try:
        result = subprocess.run(['udevadm','info','--query=property','--path='+str(net)],
            capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=2)
        properties = dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line) if result.returncode == 0 else {}
    except (OSError,subprocess.TimeoutExpired):
        properties = {}
    usb = next((p for p in (device,*device.parents) if (p/'idVendor').exists()),None)
    pci = next((p for p in (device,*device.parents) if re.fullmatch(r'[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]',p.name)),None)
    descriptor = usb if usb else pci if pci else device
    def identity(value):
        value = value.removeprefix('0x').lower()
        return value if re.fullmatch(r'[0-9a-f]{4}',value) else None
    return dict(manufacturer=read(descriptor/'manufacturer') or properties.get('ID_VENDOR_FROM_DATABASE') or properties.get('ID_VENDOR','').replace('_',' ') or None,
        model=read(descriptor/'product') or properties.get('ID_MODEL_FROM_DATABASE') or properties.get('ID_MODEL','').replace('_',' ') or None,
        registered_vendor=properties.get('ID_VENDOR_FROM_DATABASE') or None,
        vendor_id=identity(read(descriptor/('idVendor' if usb else 'vendor')) or properties.get('ID_VENDOR_ID','')),
        device_id=identity(read(descriptor/('idProduct' if usb else 'device')) or properties.get('ID_MODEL_ID','')),
        bus='USB' if usb else 'PCI' if pci else properties.get('ID_BUS') or None,
        location=usb.name if usb else pci.name if pci else device.name)


def parse_wifi_link(output):
    details = {}
    for line in output.splitlines():
        key,separator,value = line.strip().partition(':')
        if separator and key in ('SSID','freq','signal','rx bitrate','tx bitrate'):
            details[key] = value.strip()
        match = re.match(r'Connected to ([0-9a-f:]+)',line.strip(),re.I)
        if match:
            details['bssid'] = match[1]
    try:
        frequency = float(details.get('freq',''))
    except ValueError:
        frequency = None
    rates = ' '.join(details.get(k,'') for k in ('rx bitrate','tx bitrate'))
    standard = None
    if 'EHT-MCS' in rates:
        standard = 'Wi-Fi 7 (802.11be)'
    elif 'HE-MCS' in rates:
        standard = 'Wi-Fi 6E (802.11ax)' if frequency and frequency >= 5925 else 'Wi-Fi 6 (802.11ax)'
    elif 'VHT-MCS' in rates:
        standard = 'Wi-Fi 5 (802.11ac)'
    elif re.search(r'(?:^|\s)MCS\s+\d',rates):
        standard = 'Wi-Fi 4 (802.11n)'
    width = re.search(r'(\d+)\s*MHz',rates)
    channel = None
    if frequency:
        if frequency == 2484:
            channel = 14
        elif 2412 <= frequency <= 2472:
            channel = int((frequency-2407)/5)
        elif 5000 <= frequency < 5925:
            channel = int((frequency-5000)/5)
        elif frequency == 5935:
            channel = 2
        elif 5955 <= frequency <= 7115:
            channel = int((frequency-5950)/5)
    def bitrate(key):
        match = re.match(r'([\d.]+)\s+([A-Za-z]+/s)',details.get(key,''))
        return ' '.join(match.groups()) if match else None
    return {'ssid':details.get('SSID'), 'bssid':details.get('bssid'), 'standard':standard,
        'frequency':f'{frequency:g} MHz' if frequency else None,
        'band':('2,4 GHz' if 2400 <= frequency <= 2500 else '5 GHz' if 4900 <= frequency < 5925 else '6 GHz' if 5925 <= frequency <= 7125 else '60 GHz' if 57000 <= frequency <= 71000 else None) if frequency else None,
        'channel':str(channel) if channel is not None else None,
        'width':width[1]+' MHz' if width else None, 'signal':details.get('signal'),
        'rx_rate':bitrate('rx bitrate'),'tx_rate':bitrate('tx bitrate')}


def wifi_link(interface):
    try:
        result = subprocess.run(['iw','dev',interface,'link'],capture_output=True,text=True,
            encoding='utf-8',errors='replace',timeout=1,env=None)
        return parse_wifi_link(result.stdout if result.returncode == 0 else '')
    except (OSError,subprocess.TimeoutExpired):
        return parse_wifi_link('')


def connection_devices(usb_root=Path('/sys/bus/usb/devices'),tb_root=Path('/sys/bus/thunderbolt/devices')):
    """Keep USB and Thunderbolt trees separate unless sysfs proves a relationship."""
    result = []
    usb = {p.resolve():p for p in usb_root.glob('*') if re.fullmatch(r'[0-9a-fA-F]{4}',read(p/'idVendor'))}
    for path,p in sorted(usb.items(),key=lambda item:(len(item[0].parts),str(item[0]))):
        root = re.fullmatch(r'usb\d+',p.name) is not None
        parent = next((str(a) for a in path.parents if a in usb),None)
        version = read(p/'version')
        speed = usb_speed(p)
        vendor,product = read(p/'idVendor'),read(p/'idProduct')
        kind = 'Root hub / controller' if root else 'Hub USB' if read(p/'bDeviceClass').lower() == '09' else 'Dispositivo USB'
        details = [('Tipo',kind),('Produttore',read(p/'manufacturer') or 'Non disponibile'),
            ('ID USB',vendor+':'+product),('Porta / bus',p.name),('Versione USB dichiarata',version or 'Non disponibile'),
            ('Velocità negoziata',speed if not root and speed else 'Non disponibile' if not root else 'Non applicabile al root hub'),
            ('Controller',next((a.parent.name for a in (path,*path.parents) if re.fullmatch(r'usb\d+',a.name)), 'Non disponibile'))]
        result.append(dict(id=str(path),parent=parent,name=read(p/'product') or p.name,kind=kind,
            protocol='USB '+version if version else 'USB',speed=None if root else speed,details=details))
    routers = {p.resolve():p for p in tb_root.glob('*') if re.fullmatch(r'\d+-[0-9a-fA-F]+',p.name) and (p/'generation').exists()}
    for path,p in sorted(routers.items(),key=lambda item:(len(item[0].parts),str(item[0]))):
        generation = read(p/'generation')
        protocol = 'USB4' if generation == '4' else 'Thunderbolt '+generation if generation in ('1','2','3') else 'USB4 / Thunderbolt'
        parent = next((str(a) for a in path.parents if a in routers),None)
        host = p.name.endswith('-0')
        totals = {}
        details = [('Tipo','Controller host' if host else 'Router / dock'),('Protocollo rilevato',protocol),
            ('Produttore',read(p/'vendor_name') or 'Non disponibile'),('Porta / dominio',p.name),
            ('Autorizzazione',{'0':'Da autorizzare','1':'Autorizzato'}.get(read(p/'authorized'),'Non disponibile'))]
        for direction in ('rx','tx'):
            speed,lanes = read(p/(direction+'_speed')),number(p/(direction+'_lanes'))
            match = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)\s+Gb/s',speed)
            total = float(match[1])*lanes if match and lanes and 0 < lanes <= 4 else None
            totals[direction] = f'{total:g} Gbit/s' if total and total < 1000000 else None
            details.extend([(direction.upper()+' per corsia',speed or 'Non disponibile'),
                ('Corsie '+direction.upper(),str(lanes) if lanes else 'Non disponibile'),
                ('Totale '+direction.upper(),totals[direction] or 'Non disponibile')])
        speed = totals['rx'] if totals['rx'] == totals['tx'] else 'RX '+(totals['rx'] or 'N/D')+' / TX '+(totals['tx'] or 'N/D')
        result.append(dict(id=str(path),parent=parent,name=read(p/'device_name') or p.name,
            kind='Controller host' if host else 'Router / dock',protocol=protocol,speed=speed,details=details))
    result.sort(key=lambda node:not node['protocol'].startswith(('USB4','Thunderbolt')))
    return result
