"""Read per-process TCP/UDP byte counters from the installed NetHogs helper."""
from decimal import Decimal, InvalidOperation
import shutil
import subprocess
import threading
import time
import psutil


def parse_nethogs_row(line):
    fields = line.strip().rsplit('\t',2)
    if len(fields) != 3:
        return None
    identity = fields[0].rsplit('/',2)
    if len(identity) != 3 or not all(value.isdecimal() for value in identity[1:]):
        return None
    try:
        totals = [Decimal(value) for value in fields[1:]]
        if any(not value.is_finite() or value < 0 or value > 2**64 for value in totals):
            return None
        sent,received = map(int,totals)
    except (InvalidOperation,ValueError,OverflowError):
        return None
    pid,uid = map(int,identity[1:])
    return (pid,uid,sent,received) if 0 < pid < 2**31 and uid < 2**32 else None


class ProcessNetwork:
    def __init__(self):
        self.process = None
        self.thread = None
        self.lock = threading.Lock()
        self.signature = None
        self.rates = {}
        self.previous = {}
        self.updated = 0
        self.message = 'In attesa di NetHogs'

    def _publish(self,frame,stamp):
        rates, previous = {}, {}
        for pid,uid,sent,received in frame:
            try:
                proc = psutil.Process(pid)
                if proc.uids().real != uid:
                    continue
                key = (pid,proc.create_time())
            except (psutil.NoSuchProcess,psutil.AccessDenied):
                continue
            previous[key] = (stamp,sent,received)
            old = self.previous.get(key)
            if old and stamp > old[0] and sent >= old[1] and received >= old[2]:
                rates[key] = ((sent-old[1])+(received-old[2]))*8/(stamp-old[0])
            else:
                rates[key] = None
        with self.lock:
            self.rates, self.previous, self.updated = rates, previous, stamp

    def _read(self,process):
        frame,started = [],False
        for line in process.stdout:
            if line.strip() == 'Refreshing:':
                if started:
                    self._publish(frame,time.monotonic())
                frame,started = [],True
            elif started:
                row = parse_nethogs_row(line)
                if row:
                    frame.append(row)
        if started:
            self._publish(frame,time.monotonic())

    def sample(self,rows,interfaces):
        signature = tuple(sorted(interfaces))
        if signature != self.signature:
            self.close()
            self.signature = signature
            self.rates, self.previous, self.updated = {},{},0
            executable = shutil.which('nethogs')
            if executable and signature:
                try:
                    self.process = subprocess.Popen([executable,'-t','-d','1','-v','2','-C','-b',*[name for name,_ in signature]],
                        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,encoding='utf-8',errors='replace',bufsize=1)
                    self.thread = threading.Thread(target=self._read,args=(self.process,),daemon=True)
                    self.thread.start()
                except OSError:
                    self.process = None
            self.message = 'NetHogs non installato o nessuna interfaccia attiva'
        alive = self.process is not None and self.process.poll() is None
        with self.lock:
            ready = alive and self.updated > 0 and time.monotonic()-self.updated < 4
            rates = dict(self.rates)
        self.message = 'TCP + UDP attribuiti da NetHogs' if ready else 'In attesa dei contatori NetHogs' if alive else 'Rete per processo non disponibile: controllare NetHogs e i permessi di cattura'
        for row in rows:
            row['network'] = rates.get((row['pid'],row['created']),0) if ready and row['created'] is not None and row.get('uid') is not None else None
        return self.message

    def close(self):
        process = self.process
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            if self.thread is not None:
                self.thread.join(timeout=2)
            process.stdout.close()
        self.process, self.thread = None,None
