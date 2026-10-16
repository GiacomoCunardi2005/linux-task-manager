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


def link_details(path):
    device = Path(path).resolve()
    parents = (device,*device.parents)
    for node in parents:
        if (node/'idVendor').exists():
            try:
                rate = float(read(node/'speed'))
                speed = f'{rate/1000:g} Gbit/s' if rate >= 1000 else f'{rate:g} Mbit/s' if rate > 0 else None
            except ValueError:
                speed = None
            return {'bus':'USB','link_speed':speed,
                    'usb_version':read(node/'version') or None,
                    'usb_product':read(node/'product') or None}
    for node in parents:
        if re.fullmatch(r'ata\d+',node.name):
            speed = next((read(p) for p in node.glob('link*/sata_spd') if read(p)),None)
            return {'bus':'SATA','link_speed':speed}
    for node in parents:
        if (node/'current_link_speed').exists():
            width = read(node/'current_link_width')
            return {'bus':'PCIe','link_speed':read(node/'current_link_speed')+(f' ×{width}' if width else '')}
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
