#!/usr/bin/env python3
"""Root service for Gestione attività Linux: full-visibility detection and trap attribution.

`run`: systemd system service, no GUI. Every second it judges all processes (including other users' and
root's), attributes trap access with fanotify, sees short-lived processes through the proc connector and
writes /run/linux-task-manager/state.json, readable only by root and the configured user's group.
`terminate PID:CREATED…`: entry point for pkexec, so stopping another user's process asks for the admin password.
"""
import json
import os
import pwd
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))  # python -I does not add the script folder
import psutil
from detection import Detector, Traps, ExecWatcher, ProcessScanner, crontab, default_places
from netwatch import NetWatch

CONFIG = Path('/etc/linux-task-manager/service.json')
# Root-owned ignore list: a user-writable one would let user-level malware switch the checks off.
IGNORE = Path('/etc/linux-task-manager/ignore.txt')
STATE = Path('/run/linux-task-manager/state.json')
TRAP_REGISTRY = Path('/var/lib/linux-task-manager/traps')


def load_user(config=CONFIG):
    return pwd.getpwnam(json.loads(config.read_text())['user'])


Sampler = ProcessScanner  # shared with the app


def network_findings(anomalies):
    """Only the top of the ranking becomes an alert; the reason stays stable so a notification is not repeated."""
    found = []
    for item in anomalies:
        if item['score'] >= 70:
            names = ', '.join(INDICATORS.get(i,i) for i in item.get('indicators',[])) or item['kind']
            found.append(dict(severity='alta' if item['score'] >= 90 else 'media',
                reason=f"Rete: comportamento anomalo — {item['subject']} ({names})"+(f", processo {item['process']}" if item.get('process') else '')))
    return found


INDICATORS = dict(beacon='periodico',sizes='dimensioni costanti',persist='persistente',new='destinazione nuova',volume='molti dati inviati',
                  short='connessioni brevissime',iforest='profilo insolito',dnsfirst='DNS prima di ogni connessione')


def state(rows,threats,uid,features,network=None):
    # Only fields the unprivileged app cannot read itself for other users' processes.
    extra = {f"{r['pid']}:{r['created']!r}":dict(exe=r['exe'],disk=r['disk']) for r in rows if r['uid'] != uid}
    return dict(version=1,time=time.time(),user=uid,threats=threats,processes=extra,features=features,network=network)


def write_state(data,gid,path=None):
    path = path or STATE
    temporary = path.with_name('.state.tmp')
    fd = os.open(temporary,os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,0o640)
    with os.fdopen(fd,'w') as handle:
        if os.getuid() == 0:
            os.fchown(handle.fileno(),0,gid)
        os.fchmod(handle.fileno(),0o640)
        json.dump(data,handle,allow_nan=False,separators=(',',':'))
    os.replace(temporary,path)


def run():
    user = load_user()
    stop = []
    signal.signal(signal.SIGTERM,lambda *_: stop.append(1))
    signal.signal(signal.SIGINT,lambda *_: stop.append(1))
    traps = Traps(places=default_places(user.pw_dir),registry=TRAP_REGISTRY,owner=(user.pw_uid,user.pw_gid))
    detector = Detector(home=user.pw_dir,config=IGNORE,traps=traps,read_crontab=lambda: crontab(user.pw_name)+crontab('root'),
                        agent_baseline=Path('/var/lib/linux-task-manager/agents.json'))
    features = dict(fanotify=False,exec=False)
    try:
        watcher = ExecWatcher(detector)
        traps.lookup = watcher.recent_description
        watcher.start()
        features['exec'] = True
    except (OSError,RuntimeError) as exc:
        watcher = None
        print(f'Processi brevi non osservabili: {exc}',file=sys.stderr)
    sampler = Sampler()
    watch = NetWatch(Path('/var/lib/linux-task-manager/network.json'),uid=user.pw_uid).start()
    try:
        while not stop:
            started = time.monotonic()
            rows = sampler.rows()
            threats = detector.assess(rows,sampler.cores)
            features['fanotify'] = traps.fan is not None
            anomalies = watch.poll()
            threats['system'] += network_findings(anomalies)
            network = dict(anomalies=anomalies,features=watch.features,
                           learning=time.time()-watch.analyzer.base['started'] < 24*3600)
            write_state(state(rows,threats,user.pw_uid,features,network),user.pw_gid)
            time.sleep(max(0,1-(time.monotonic()-started)))
    finally:
        watch.close()
        detector.close()
        if watcher:
            watcher.close()
        STATE.unlink(missing_ok=True)


def terminate(pairs,caller,allowed):
    """SIGTERM each PID only if it still has the start time the user saw; never PID 1, kernel threads or this service."""
    if caller != allowed:
        raise PermissionError('Solo l’utente configurato può usare questo comando.')
    results = []
    for pair in pairs:
        pid,created = pair.split(':',1)
        pid,created = int(pid),float(created)
        try:
            proc = psutil.Process(pid)
            if proc.create_time() != created:
                results.append((pid,'già terminato'))
                continue
            if pid in (1,2,os.getpid()) or proc.ppid() == 2 or 'rootservice.py' in ' '.join(proc.cmdline()):
                results.append((pid,'protetto'))
                continue
            proc.terminate()
            results.append((pid,'inviato'))
        except psutil.NoSuchProcess:
            results.append((pid,'già terminato'))
    return results


def main(argv):
    if argv[:1] == ['run']:
        run()
        return 0
    if argv[:1] == ['terminate'] and len(argv) > 1:
        try:
            results = terminate(argv[1:],int(os.environ.get('PKEXEC_UID','-1')),load_user().pw_uid)
        except (PermissionError,ValueError,OSError,KeyError) as exc:
            print(exc,file=sys.stderr)
            return 1
        for pid,outcome in results:
            print(f'{pid} {outcome}')
        return 0
    print('Uso: rootservice.py run | terminate PID:AVVIO…',file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
