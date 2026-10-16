#!/usr/bin/env python3
"""Headless, authenticated TLS snapshots. No Qt and no remote commands."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import subprocess
import threading
import time
from metrics import Monitor
from remote import PORT, MAX_SNAPSHOT, fingerprint

DEFAULT_CONFIG = Path(os.environ.get('XDG_CONFIG_HOME',Path.home()/'.config'))/'linux-task-manager-server'


def credentials(directory, initialize=False):
    directory = Path(directory)
    if initialize:
        directory.mkdir(mode=0o700,parents=True,exist_ok=True)
        directory.chmod(0o700)
        if not (directory/'token').exists():
            with (directory/'token').open('x') as stream:
                os.chmod(stream.name,0o600)
                stream.write(secrets.token_hex(32)+'\n')
        cert, key = directory/'certificate.pem', directory/'private-key.pem'
        if not cert.exists() and not key.exists():
            previous = os.umask(0o077)
            try:
                subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-sha256','-nodes',
                    '-days','3650','-subj','/CN=Linux Task Manager','-keyout',str(key),'-out',str(cert)],
                    check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            finally:
                os.umask(previous)
    token = (directory/'token').read_text().strip()
    if not re.fullmatch(r'[a-f0-9]{64}',token):
        raise ValueError('File token non valido.')
    if any((directory/name).stat().st_mode & 0o077 for name in ('token','private-key.pem')):
        raise ValueError('Token e chiave privata devono avere permessi 600.')
    certificate = ssl.PEM_cert_to_DER_cert((directory/'certificate.pem').read_text())
    return token, fingerprint(certificate)+'.'+token


class Snapshots:
    def __init__(self,monitor):
        self.monitor = monitor
        self.command_key = secrets.token_bytes(32)
        self.body = None
        self.updated = 0
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self.run,daemon=True)

    def run(self):
        while not self.stop.is_set():
            start = time.monotonic()
            try:
                data = self.monitor.sample()
                # Never transmit command arguments: they can contain credentials.
                data['process_rows'] = [dict(row,cmdline=[],command_id=hmac.new(self.command_key,json.dumps(row['cmdline'][1:]).encode(),hashlib.sha256).hexdigest()) for row in data['process_rows']]
                # Optional fields use a stable wire shape even on non-Wi-Fi NICs.
                for device in data['disks'].values():
                    device.setdefault('mounts',[])
                    for field in ('usb_version','usb_product'):
                        device.setdefault(field,None)
                for device in data['nets'].values():
                    for field in ('ssid','standard','band','frequency','channel','width','signal','rx_rate','tx_rate','bssid'):
                        device.setdefault(field,None)
                packet = dict(version=1,host=socket.gethostname(),data=data,cpu_name=self.monitor.cpu_name,
                    cpu_details=self.monitor.cpu_details,memory_hardware=self.monitor.memory_hardware)
                body = json.dumps(packet,allow_nan=False,separators=(',',':')).encode()
                if len(body)>MAX_SNAPSHOT:
                    raise ValueError('Snapshot troppo grande')
                with self.lock:
                    self.body, self.updated = body,time.monotonic()
            except Exception:
                print('Campionamento non riuscito; nuovo tentativo tra un secondo.',flush=True)
            self.stop.wait(max(0,1-(time.monotonic()-start)))

    def current(self):
        with self.lock:
            return self.body if self.updated and time.monotonic()-self.updated < 10 else None

    def close(self):
        self.stop.set()
        self.worker.join()
        self.monitor.close()


class SnapshotHandler(BaseHTTPRequestHandler):
    server_version = 'TaskManager'
    sys_version = ''

    def setup(self):
        self.request.settimeout(3)
        super().setup()

    def log_message(self,*args):
        pass

    def do_GET(self):
        supplied = self.headers.get('Authorization','').encode('utf-8')
        expected = ('Bearer '+self.server.token).encode('ascii')
        if not hmac.compare_digest(supplied,expected):
            self.send_error(401,'Unauthorized')
            return
        if self.path != '/v1/snapshot':
            self.send_error(404,'Not found')
            return
        body = self.server.snapshots.current()
        if body is None:
            self.send_error(503,'No recent sample')
            return
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.end_headers()
        self.wfile.write(body)


class SnapshotServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self,address,token,snapshots,context):
        self.token, self.snapshots = token,snapshots
        self.slots = threading.BoundedSemaphore(8)
        if ':' in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address,SnapshotHandler)
        self.socket = context.wrap_socket(self.socket,server_side=True,do_handshake_on_connect=False)

    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request,address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self,request,address):
        try:
            super().process_request_thread(request,address)
        finally:
            self.slots.release()

    def handle_error(self,request,address):
        pass


def main():
    parser = argparse.ArgumentParser(description='Gestione attività Linux — server senza interfaccia grafica')
    parser.add_argument('--host',default='0.0.0.0',help='Indirizzo su cui ascoltare (predefinito: tutte le IPv4)')
    parser.add_argument('--port',type=int,default=PORT)
    parser.add_argument('--config',type=Path,default=DEFAULT_CONFIG)
    parser.add_argument('--init',action='store_true',help='Crea certificato e chiave di accesso, poi esci')
    parser.add_argument('--show-key',action='store_true',help='Mostra la chiave da copiare nell’app, poi esci')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('Porta non valida')
    try:
        token, key = credentials(args.config,args.init)
        if args.init or args.show_key:
            print('Chiave di accesso (conservala privata):\n'+key)
            return 0
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.config/'certificate.pem',args.config/'private-key.pem')
        snapshots = Snapshots(Monitor())
        try:
            server = SnapshotServer((args.host,args.port),token,snapshots,context)
        except Exception:
            snapshots.monitor.close()
            raise
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        parser.exit(1,f'Avvio non riuscito: {exc}\nEsegui prima --init (richiede openssl).\n')
    def stop(*_):
        threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,stop)
    signal.signal(signal.SIGINT,stop)
    snapshots.worker.start()
    print(f'Server HTTPS in ascolto su {args.host}:{args.port} · sola lettura',flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        snapshots.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
