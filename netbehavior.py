"""Network anomaly scoring: local behaviour plus a separate international-domain caution.

Behaviour indicators use what this machine was observed doing, against a baseline learnt locally.
Independent behaviour indicators are combined with a noisy-OR into a 0-100 score; contacted IDN names
produce a separate fixed caution. The result is a ranked list of what deserves a look, not a verdict.
"""
from collections import Counter, OrderedDict, deque
import math
import statistics
import time
import unicodedata
import numpy as np

WINDOW = 2*3600            # behaviour window for destinations
DNS_WINDOW = 15*60          # DGA / tunnelling window
BUCKET = 300                # device-level metric bucket (5 min)
HISTORY_BUCKETS = 7*24*12   # one week of buckets
LEARNING = 24*3600          # before this, "new destination" means little
CONTACT_DNS_HORIZON = 2*3600  # systemd-resolved can serve an answer from its cache this long after the packet
IDN_DNS_MAX_AGE = 300       # only a recent observed answer can name a contacted destination
MAX_IDN_CONTACTS = 10000    # bounded contact history, independent of the DNS display cache
MAX_FLOWS = 20000           # socket counters and recent close tombstones
FLOW_GRACE = WINDOW+10*60   # keep closed identities through the feature window
FLOW_RETENTION = 6*3600     # match the collector's retention of captured SYNs
WEIGHTS = dict(beacon=.75,sizes=.3,persist=.2,new=.35,volume=.7,short=.35,iforest=.45,dga=.8,tunnel=.8,spike=.5,dnsfirst=.15)
TWO_LEVEL = {'co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au','co.jp','ne.jp','or.jp','com.br','com.cn','net.cn',
             'co.nz','co.za','co.in','com.mx','com.tr','co.kr','com.ar','gov.it'}
VOWELS = set('aeiouy')


def safe_domain_text(value):
    """Keep visible Unicode, but make invisible/control and bidi-format characters explicit."""
    display = ''.join(f'\\u{ord(char):04x}' if unicodedata.category(char).startswith('C')
                      or unicodedata.category(char) in ('Zl','Zp') else char for char in value)
    return display if len(display) <= 1800 else display[:1800]+'…'


def international_domain(name):
    """IDN evidence for any label, including the suffix. IDN is a caution, not a malware verdict."""
    labels = name.rstrip('.').lower().split('.')
    if not any(ord(char) > 127 for char in name) and not any(label.startswith('xn--') for label in labels):
        return None
    decoded, wire, invalid = [], [], []
    for label in labels:
        if label.startswith('xn--'):
            wire.append(safe_domain_text(label))
            try:
                decoded.append(label.encode('ascii').decode('idna'))
            except UnicodeError:
                try:
                    decoded.append(label[4:].encode('ascii').decode('punycode') or label)
                except UnicodeError:
                    decoded.append(label)
                invalid.append(safe_domain_text(label))
        else:
            decoded.append(label)
            try:
                wire.append(label.encode('idna').decode('ascii'))
            except UnicodeError:
                # Malformed labels still deserve attention. This is an escaped representation,
                # rather than a claim that the text is a valid DNS wire name.
                wire.append(''.join(char if 32 <= ord(char) < 127 else f'\\u{ord(char):04x}' for char in label))
                invalid.append(safe_domain_text(label))
    display, ascii_name = safe_domain_text('.'.join(decoded)), safe_domain_text('.'.join(wire))
    points = dict.fromkeys(char for char in ''.join(decoded)+name if ord(char) > 127)
    evidence = [f'Nome internazionale contattato: {display}', f'Forma DNS ASCII/Punycode: {ascii_name}']
    if points:
        evidence.append('Caratteri non ASCII: '+', '.join(
            f'U+{ord(char):04X} {unicodedata.name(char,"SENZA NOME")}' for char in list(points)[:16])
            +(f'; altri {len(points)-16} caratteri distinti' if len(points) > 16 else ''))
    if invalid:
        evidence.append('Etichette non decodificabili come IDNA: '+', '.join(invalid))
    evidence.append('I domini internazionali possono essere legittimi; verificare il nome per possibili caratteri somiglianti.')
    return dict(subject=ascii_name,evidence=[line if len(line) < 1900 else line[:1899]+'…' for line in evidence])


def noisy_or(parts):
    """parts: (indicator, strength 0..1). Several independent indicators reinforce each other."""
    survive = 1.0
    for name,strength in parts:
        survive *= 1-WEIGHTS[name]*max(0.,min(1.,strength))
    return 100*(1-survive)


def entropy(text):
    if not text:
        return 0.
    counts = Counter(text)
    return -sum(n/len(text)*math.log2(n/len(text)) for n in counts.values())


def registered(name):
    """example.co.uk / example.com: the part a domain owner registers (no public suffix database)."""
    labels = name.rstrip('.').lower().split('.')
    take = 3 if len(labels) >= 3 and '.'.join(labels[-2:]) in TWO_LEVEL else 2
    return '.'.join(labels[-take:])


def dga_likeness(name):
    """0..1 randomness of the registrable label: entropy, digits, missing vowels, consonant runs."""
    label = registered(name).split('.')[0]
    if len(label) < 6:
        return 0.
    letters = [c for c in label if c.isalpha()]
    digits = sum(c.isdigit() for c in label)/len(label)
    vowels = sum(c in VOWELS for c in letters)/max(1,len(letters))
    run = longest = 0
    for c in label:
        run = run+1 if c.isalpha() and c not in VOWELS else 0
        longest = max(longest,run)
    score = (min(1,max(0,(entropy(label)-2.8)/1.2))*.4 + min(1,digits*3)*.2 + min(1,max(0,(.32-vowels)/.2))*.2
             + min(1,max(0,(longest-3)/3))*.1 + min(1,max(0,(len(label)-11)/9))*.1)
    return min(1.,score)


def beacon(times):
    """(regularity 0..1, period s, cv, beats) of event times; tolerates jitter and missed beats."""
    times = sorted(times)
    intervals = [b-a for a,b in zip(times,times[1:]) if b-a >= 1]
    if len(intervals) < 7:
        return 0.,None,None,len(intervals)
    period = statistics.median(intervals)
    if period < 5:  # sampling cannot resolve faster rhythms; streaming looks like this too
        return 0.,period,None,len(intervals)
    ratios = [i/period for i in intervals]
    regular = [r for r in ratios if 1 <= round(r) <= 3 and abs(r-round(r)) < .15]  # missed beats are multiples
    core = [i for i in intervals if abs(i/period-1) < .5]
    cv = statistics.pstdev(core)/statistics.mean(core) if len(core) > 2 else 1.
    # Random (Poisson) arrivals also land near multiples of the median ~35% of the time and keep a core CV
    # around .27; real beacons, even with 10-20% jitter, stay well below .2. Both conditions must hold.
    tightness = min(1,max(0,(.22-cv)/.12))
    strength = len(regular)/len(intervals)*tightness*min(1,(len(intervals)-6)/14)
    return strength,period,cv,len(intervals)


class IsolationForest:
    """Liu, Ting & Zhou (2008): anomalies are isolated by fewer random splits. Fitted on local history only."""
    def __init__(self,trees=64,sample=128,seed=7):
        self.trees, self.sample, self.random, self.forest = trees, sample, np.random.default_rng(seed), []

    @staticmethod
    def c(n):
        return 2*(math.log(n-1)+.5772156649)-2*(n-1)/n if n > 2 else (1. if n == 2 else 0.)

    def grow(self,data,depth,limit):
        if depth >= limit or len(data) <= 1:
            return ('leaf',len(data))
        spread = data.max(axis=0)-data.min(axis=0)
        columns = np.flatnonzero(spread > 0)
        if not len(columns):
            return ('leaf',len(data))
        column = self.random.choice(columns)
        split = self.random.uniform(data[:,column].min(),data[:,column].max())
        left = data[:,column] < split
        return ('node',column,split,self.grow(data[left],depth+1,limit),self.grow(data[~left],depth+1,limit))

    def fit(self,vectors):
        data = np.asarray(vectors,dtype=float)
        size = min(self.sample,len(data))
        limit = math.ceil(math.log2(max(2,size)))
        self.size = size
        self.forest = [self.grow(data[self.random.choice(len(data),size,replace=False)],0,limit) for _ in range(self.trees)]
        return self

    def path(self,tree,point,depth=0):
        if tree[0] == 'leaf':
            return depth+self.c(tree[1])
        _,column,split,left,right = tree
        return self.path(left if point[column] < split else right,point,depth+1)

    def score(self,point):
        """0..1; around .5 is ordinary, close to 1 is isolated."""
        mean = sum(self.path(tree,point) for tree in self.forest)/len(self.forest)
        return 2**(-mean/self.c(self.size))


def robust_z(value,history):
    if len(history) < 24:
        return 0.
    median = statistics.median(history)
    # Very steady histories have a MAD near zero: a 10%-of-median floor keeps ordinary wobble from looking extreme.
    mad = max(statistics.median(abs(h-median) for h in history),.1*median,1.)
    return (value-median)/(1.4826*mad)


class NetworkAnalyzer:
    def __init__(self,baseline=None,now=None):
        now = time.time() if now is None else now
        self.base = baseline or {}
        self.base.setdefault('started',now)
        for key in ('dest','domains','beacons'):
            self.base.setdefault(key,{})
        self.base.setdefault('device',{'conn':[],'dst':[],'out':[]})
        self.base.setdefault('vectors',[])
        self.events = {}             # destination key -> deque of connection/burst times
        self.conns = deque(maxlen=20000)   # final connection sizes and known durations
        self.transfers = deque(maxlen=20000)  # (time, destination, uncounted TX, uncounted RX)
        self.dns = deque(maxlen=20000)
        self.ip_domain, self.dns_seen_at = {}, {}  # resolved IP -> name / time of the answer
        self.idn_contacts = OrderedDict()  # (destination key, wire domain) -> (last contact, evidence)
        self.dns_before = {}         # destination key -> [connections preceded by a DNS answer, total]
        # destination key -> names answered by DNS just before each connection, and connections opened without one.
        # Kept while the destination is active, so rotating DNS later cannot erase what was actually contacted.
        self.contact_names = {}
        self.flows = OrderedDict()   # (4-tuple, socket cookie) -> cumulative counters / lifecycle
        self.flow_loss_time = float('-inf')  # totals older than an evicted state cannot safely be recounted
        self.idle = []               # (time, user idle?)
        self.bucket = (int(now//BUCKET),0,set(),0)
        self.forest, self.forest_time = None, 0.
        self.processes = {}          # destination key -> process description (filled by the collector)

    # ---------- ingestion ----------
    def key(self,dst,dport):
        return f'{dst}:{dport}'

    def label(self,key):
        ip = key.rsplit(':',1)[0]
        domain = self.ip_domain.get(ip.strip('[]'))
        return f'{domain} ({key})' if domain else key

    def tick(self,t,dst=None,out=0):
        index,conns,dsts,sent = self.bucket
        now_index = int(t//BUCKET)
        if now_index > index:  # late events (a close after the next connection's SYN) stay in the current bucket
            device = self.base['device']
            quiet = min(now_index-index-1,HISTORY_BUCKETS)  # genuinely empty buckets in between
            for name,value in (('conn',conns),('dst',len(dsts)),('out',sent)):
                device[name] = (device[name]+[value]+[0]*quiet)[-HISTORY_BUCKETS:]
            index,conns,dsts,sent = now_index,0,set(),0
        if dst:
            conns += 1
            dsts.add(dst)
        self.bucket = (index,conns,dsts,sent+out)

    def dns_event(self,t,qname,qtype,rcode,response,ips=()):
        qname = qname.rstrip('.').lower()
        if not qname or qname.endswith(('.local','.arpa','.lan','.home','.station','.internal')) or '.' not in qname:
            return
        self.dns.append((t,qname,qtype,rcode,response))
        if response and rcode == 0 and str(qtype) != '12':  # queries, failures and PTR are not forward identities
            for ip in ips:
                self.ip_domain[ip] = qname
                self.dns_seen_at[ip] = t
        if response and rcode == 0:  # only names that exist become "known"; a failed lookup must stay unseen
            entry = self.base['domains'].setdefault(registered(qname),[t,t,0])
            entry[1], entry[2] = t, entry[2]+1

    def syn(self,t,dst,dport):
        key = self.key(dst,dport)
        self.contacted_name(t,dst,key)
        self.events.setdefault(key,deque(maxlen=300)).append(t)
        entry = self.base['dest'].setdefault(key,[t,t,0])
        entry[1], entry[2] = t, entry[2]+1
        seen = self.dns_seen_at.get(dst)
        backed = bool(seen and 0 <= t-seen < 3)
        counts = self.dns_before.setdefault(key,[0,0])
        counts[0] += backed
        counts[1] += 1
        record = self.contact_names.setdefault(key,dict(names=set(),unbacked=0))
        # With nss-resolve, programs ask systemd-resolved over its own socket and cached answers send no packet:
        # only the upstream query on a cache miss is visible. An address answered within the cache horizon names
        # the connection; one never seen in DNS (or seen too long ago) does not.
        cached = bool(seen is not None and 0 <= t-seen <= CONTACT_DNS_HORIZON)
        name = self.ip_domain.get(dst) if cached else None
        if name and len(record['names']) < 20:
            record['names'].add(name)
        elif not name:
            record['unbacked'] += 1
        self.tick(t,dst)

    def contacted_name(self,t,dst,key):
        """Record at contact time, so a later DNS-cache overwrite cannot erase the evidence."""
        seen = self.dns_seen_at.get(dst)
        if seen is None or not 0 <= t-seen <= IDN_DNS_MAX_AGE:
            return
        detail = international_domain(self.ip_domain.get(dst,''))
        if detail is None:
            return
        identity = (key,detail['subject'])
        self.idn_contacts.pop(identity,None)
        self.idn_contacts[identity] = (t,detail)
        while len(self.idn_contacts) > MAX_IDN_CONTACTS:
            self.idn_contacts.popitem(last=False)

    @staticmethod
    def counter(value):
        """A missing kernel counter is unknown, never an observed zero."""
        return value if type(value) in (int,float) and math.isfinite(value) and 0 <= value < 2**64 else None

    def account(self,t,key,out,inb,state=None,baseline=False):
        """Ingest cumulative socket counters once, independently for each direction."""
        out,inb = self.counter(out),self.counter(inb)
        deltas = []
        for name,value in (('out',out),('in',inb)):
            previous = state.get(name) if state is not None else None
            unknown_start = baseline or (state is not None and state.get('sampled') and previous is None)
            if unknown_start:
                delta = 0 if value == 0 else None
            elif value is None or (previous is not None and value < previous):
                delta = None
            else:
                delta = value if previous is None else value-previous
            deltas.append(delta)
            if state is not None and value is not None:
                state[name] = value
        if state is not None:
            state['sampled'] = True
        if (not baseline and any(value is None or value > 0 for value in deltas)) or (baseline and deltas == [0,0]):
            self.transfers.append((t,key,*deltas))
        if deltas[0] is not None:
            self.tick(t,out=deltas[0])
        return deltas

    def flow(self,t,tuple4,token):
        identity = (tuple(tuple4),token)
        state = self.flows.get(identity)
        if state is None:
            state = dict(out=None,**{'in':None},seen=t,closed=False)
            self.flows[identity] = state
        state['seen'] = max(t,state['seen'])
        self.flows.move_to_end(identity)
        while len(self.flows) > MAX_FLOWS:
            _,lost = self.flows.popitem(last=False)
            self.flow_loss_time = max(self.flow_loss_time,lost['seen'])
        return state

    def close(self,t,dst,dport,out,inb,duration=None,tuple4=None,token=None):
        """Final totals; optional socket identity prevents recounting preceding snapshots.

        Legacy callers without a tuple are standalone connections. Collector callers provide
        a kernel cookie as well, so a delayed close cannot consume a reused tuple's counters.
        """
        key = self.key(dst,dport)
        existing = tuple4 is not None and (tuple(tuple4),token) in self.flows
        state = self.flow(t,tuple4,token) if tuple4 is not None else None
        if state is not None and state['closed']:
            return  # duplicate destroy event, or an older ss result delivered after destruction
        out,inb = self.counter(out),self.counter(inb)
        duration = duration if type(duration) in (int,float) and math.isfinite(duration) and duration >= 0 else None
        uncertain = state is not None and not existing and self.flow_loss_time != float('-inf') and (
            duration is None or t-duration <= self.flow_loss_time)
        self.account(t,key,out,inb,state,baseline=uncertain)
        self.conns.append((t,key,out,inb,duration))
        if state is not None:
            state['closed'] = True

    def snapshot(self,t,flows,starts=None):
        """Long-lived connections: a send burst counts as an event, so heartbeats on one socket are timed too."""
        for item in flows:
            src,sport,dst,dport,out,inb = item[:6]
            out,inb = self.counter(out),self.counter(inb)
            token = item[6] if len(item) > 6 else None
            self.contacted_name(t,dst,self.key(dst,dport))
            tuple4 = (src,sport,dst,dport)
            identity = (tuple4,token)
            old = self.flows.get(identity)
            # With no cookie, a lower counter is the only available sign of tuple reuse.
            if old and old['closed'] and token is None:
                if any(value is not None and old[name] is not None and value < old[name]
                       for name,value in (('out',out),('in',inb))):
                    del self.flows[identity]
                    old = None
            state = self.flow(t,tuple4,token)
            if state['closed']:
                continue
            if old is None and starts is not None:
                start = starts.get(tuple4)
                state['started'] = start if start is not None and 0 <= t-start < FLOW_RETENTION else None
            had_out = old is not None and old['out'] is not None
            previous = old['out'] if had_out else None
            key = self.key(dst,dport)
            start = state.get('started')
            reliable_start = start is not None and start > self.flow_loss_time
            delta,_ = self.account(t,key,out,inb,state,baseline=old is None and not reliable_start)
            if had_out and out is not None and out >= previous and delta is not None and delta > 0:
                self.events.setdefault(key,deque(maxlen=300)).append(t)
        self.prune_flows(t)

    def prune_flows(self,now):
        for identity,state in list(self.flows.items()):
            if now-state['seen'] >= (FLOW_GRACE if state['closed'] else FLOW_RETENTION):
                self.flow_loss_time = max(self.flow_loss_time,state['seen'])
                del self.flows[identity]

    def volumes(self,key,now):
        """Known deltas in the observation window; any missing direction stays unavailable."""
        transfers = [item for item in self.transfers if item[1] == key and 0 <= now-item[0] < WINDOW]
        return tuple(sum(item[column] for item in transfers) if transfers and all(
            item[column] is not None for item in transfers) else None for column in (2,3))

    def user_idle(self,t,idle):
        self.idle = [(s,i) for s,i in self.idle if t-s < WINDOW]+[(t,idle)]

    def was_idle(self,t):
        before = [i for s,i in self.idle if s <= t]
        return bool(before and before[-1])

    # ---------- analysis ----------
    def international_contacts(self,now):
        return [dict(subject=detail['subject'],key=key,kind='idn',score=70,indicators=['idn'],
                     evidence=list(detail['evidence']),process=self.processes.get(key),when=stamp)
                for (key,_),(stamp,detail) in self.idn_contacts.items() if 0 <= now-stamp < WINDOW]

    def destination(self,key,now):
        parts, evidence = [], []
        times = [t for t in self.events.get(key,()) if 0 <= now-t < WINDOW]
        conns = [c for c in self.conns if c[1] == key and 0 <= now-c[0] < WINDOW]
        strength,period,cv,beats = beacon(times)
        first = self.base['dest'].get(key,[now])[0]
        days = 0
        if strength > .3:
            days = (now-self.base['beacons'].setdefault(key,now))/86400
            parts.append(('beacon',strength))
            evidence.append(f'comunicazione periodica ogni {period:.0f} s (CV {cv:.2f}, {beats} intervalli, regolarità {strength*100:.0f}%)'
                            +(f', abituale da {days:.0f} giorni' if days > 3 else ''))
            span = (max(times)-min(times))/3600
            if span > 1:
                parts.append(('persist',min(1,span/6)))
                evidence.append(f'persistente da {span:.1f} ore')
            sizes = [c[2] for c in conns if c[2] is not None]
            if len(sizes) >= 5 and statistics.mean(sizes) > 0:
                size_cv = statistics.pstdev(sizes)/statistics.mean(sizes)
                if size_cv < .25:
                    parts.append(('sizes',1-size_cv*4))
                    evidence.append(f'messaggi di dimensione quasi costante (~{statistics.mean(sizes):.0f} byte, CV {size_cv:.2f})')
            before,total = self.dns_before.get(key,[0,0])
            if total >= 5 and before/total > .7:
                parts.append(('dnsfirst',before/total))
                evidence.append(f'{before/total*100:.0f}% delle connessioni precedute da una richiesta DNS')
        learnt = now-self.base['started'] > LEARNING
        if now-first < 24*3600 and learnt:
            parts.append(('new',1.))
            evidence.append('destinazione mai vista prima di oggi')
        out,inb = self.volumes(key,now)
        if out is not None and inb is not None and out > 5e6 and out/(inb+1) > 3:
            parts.append(('volume',min(1,math.log10(out/5e6)+.5)))
            evidence.append(f'{out/1e6:.1f} MB inviati e {inb/1e6:.1f} MB ricevuti (rapporto {out/(inb+1):.0f}:1): possibile esfiltrazione')
        durations = [c[4] for c in conns if c[4] is not None]
        if len(durations) >= 10 and statistics.median(durations) < 2:
            parts.append(('short',min(1,len(durations)/30)))
            evidence.append(f'{len(durations)} connessioni brevissime (mediana {statistics.median(durations):.1f} s)')
        if days > 3:
            # A rhythm kept for days (mail, sync, chat heartbeats) is a habit: every facet of it is damped together.
            parts = [(name,s*.3 if name in ('beacon','sizes','persist','dnsfirst','short') else s) for name,s in parts]
        vector = self.vector(key,times,conns,strength,now)
        if self.forest and all(value is not None for value in vector):
            isolation = self.forest.score(vector)
            if isolation > .6:
                parts.append(('iforest',(isolation-.6)/.25))
                evidence.append(f'profilo insolito rispetto al traffico abituale (isolamento {isolation:.2f})')
        return parts,evidence,vector,times

    def vector(self,key,times,conns,regularity,now):
        out,inb = self.volumes(key,now)
        durations = [c[4] for c in conns if c[4] is not None]
        first = self.base['dest'].get(key,[now])[0]
        return [math.log1p(out) if out is not None else None,math.log1p(inb) if inb is not None else None,
                math.log1p(out/(inb+1)) if out is not None and inb is not None else None,math.log1p(len(times)),
                math.log1p(statistics.median(durations)) if durations else None,regularity,
                math.log1p(max(0,now-first)/3600),0. if key.endswith((':443',':80')) else 1.]

    def domains(self,now):
        found = []
        recent = [d for d in self.dns if 0 <= now-d[0] < DNS_WINDOW]
        failing = {name for t,name,qtype,rcode,response in recent if response and rcode == 3}
        if len(failing) >= 8:
            likeness = statistics.mean(dga_likeness(n) for n in failing)
            lengths = Counter(len(registered(n).split('.')[0]) for n in failing)
            similar = lengths.most_common(1)[0][1]/len(failing)
            unseen = sum(1 for n in failing if registered(n) not in self.base['domains'])/len(failing)
            strength = min(1,(len(failing)-5)/20)*(.4+.6*likeness)*(.6+.4*unseen)
            if similar > .6:
                strength = min(1,strength*1.2)
            examples = ', '.join(sorted(failing)[:3])
            found.append(dict(subject='Dispositivo: risoluzioni DNS fallite',kind='dga',score=noisy_or([('dga',strength)]),indicators=['dga'],
                evidence=[f'{len(failing)} domini diversi inesistenti (NXDOMAIN) in 15 minuti, es. {examples}',
                          f'casualità media dei nomi {likeness*100:.0f}%, {similar*100:.0f}% con la stessa lunghezza, {unseen*100:.0f}% mai visti prima'],
                when=max(t for t,*_ in recent)))
        by_domain = {}
        for t,name,qtype,rcode,response in recent:
            if response:
                continue
            base = registered(name)
            sub = name[:-len(base)].rstrip('.')
            if sub:
                by_domain.setdefault(base,[]).append((t,sub,qtype))
        for base,queries in by_domain.items():
            subs = {s for _,s,_ in queries}
            if len(subs) < 20:
                continue
            mean_len = statistics.mean(len(s) for s in subs)
            chars = ''.join(subs).replace('.','')
            text = sum(q in (16,10) for _,_,q in queries)/len(queries)  # TXT / NULL
            encoded = sum(1 for s in subs if len(max(s.split('.'),key=len)) >= 24)/len(subs)
            strength = min(1,(len(subs)-15)/60)*min(1,max(0,(mean_len-12)/25))*min(1,max(0,(entropy(chars)-3)/1.2))
            strength = min(1,strength+.3*text+.2*encoded) if strength else 0
            if strength > .05:
                found.append(dict(subject=f'Dominio {base}',kind='tunnel',score=noisy_or([('tunnel',strength)]),indicators=['tunnel'],
                    evidence=[f'{len(subs)} sottodomini diversi in 15 minuti, lunghezza media {mean_len:.0f} caratteri, entropia {entropy(chars):.1f} bit',
                              f'{encoded*100:.0f}% con etichette lunghe da dati codificati, {text*100:.0f}% richieste TXT/NULL: possibile tunnel DNS'],
                    when=max(t for t,_,_ in queries)))
        return found

    def device(self,now):
        found = []
        index,conns,dsts,sent = self.bucket
        history = self.base['device']
        for name,value,text in (('conn',conns,'connessioni avviate'),('dst',len(dsts),'destinazioni diverse'),('out',sent,'byte inviati')):
            z = robust_z(value,history[name])
            if z > 6 and value > 2*statistics.median(history[name]) and value > (20 if name != 'out' else 20e6):
                found.append(dict(subject=f'Dispositivo: picco di {text}',kind='spike',score=noisy_or([('spike',min(1,(z-6)/10+.5))]),indicators=['spike'],
                    evidence=[f'{value:.0f} {text} negli ultimi 5 minuti contro una mediana abituale di {statistics.median(history[name]):.0f} (z robusto {z:.0f})'],when=now))
        return found

    def analyze(self,now=None):
        now = time.time() if now is None else now
        keys = ({k for k,v in self.events.items() if v and 0 <= now-v[-1] < WINDOW}
                | {c[1] for c in self.conns if 0 <= now-c[0] < WINDOW}
                | {c[1] for c in self.transfers if 0 <= now-c[0] < WINDOW})
        results, vectors = [], []
        for key in keys:
            parts,evidence,vector,times = self.destination(key,now)
            if all(value is not None for value in vector):
                vectors.append(vector)
            if not parts:
                continue
            score = noisy_or(parts)
            when = max(times) if times else now
            idle_share = sum(self.was_idle(t) for t in times)/len(times) if times else 0
            if idle_share > .7 and score > 20:
                score = min(100,score*1.15)
                evidence.append(f'{idle_share*100:.0f}% dell’attività mentre l’utente era inattivo')
            results.append(dict(subject=self.label(key),key=key,kind='destinazione',score=round(score,1),evidence=evidence,
                                indicators=[p for p,_ in parts],process=self.processes.get(key),when=when))
        results += self.domains(now)+self.device(now)+self.international_contacts(now)
        for result in results:
            result['score'] = round(result['score'],1)
        # Retrain the forest on this machine's own history; today's vectors join it for tomorrow.
        if now-self.forest_time > 600:
            self.forest_time = now
            self.base['vectors'] = (self.base['vectors']+vectors)[-3000:]
            if len(self.base['vectors']) >= 200:
                self.forest = IsolationForest().fit(self.base['vectors'])
        self.prune(now)
        return sorted(results,key=lambda r: -r['score'])

    def prune(self,now):
        self.prune_flows(now)
        self.transfers = deque((item for item in self.transfers if now-item[0] < WINDOW),maxlen=20000)
        for identity in [identity for identity,(stamp,_) in self.idn_contacts.items() if now-stamp >= WINDOW]:
            del self.idn_contacts[identity]
        for key in [k for k,v in self.events.items() if not v or now-v[-1] > WINDOW]:
            del self.events[key]
            self.contact_names.pop(key,None)
        if len(self.ip_domain) > 50000:
            self.ip_domain = dict(list(self.ip_domain.items())[-25000:])
        for name in ('dest','domains'):
            table = self.base[name]
            if len(table) > 20000:
                for key in sorted(table,key=lambda k: table[k][1])[:len(table)-15000]:
                    del table[key]
        self.base['beacons'] = {k:v for k,v in self.base['beacons'].items() if k in self.base['dest']}
