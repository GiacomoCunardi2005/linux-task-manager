"""Behavioural network anomaly scoring: no blacklists, signatures or models trained on malware.

Every indicator is computed from what this machine was observed doing, against a baseline learnt locally.
Independent indicators are combined with a noisy-OR into a 0-100 score, so one weak indicator stays low and
several independent ones rise together. The result is a ranked list of what deserves a look, not a verdict.
"""
from collections import Counter, deque
import math
import statistics
import time
import numpy as np

WINDOW = 2*3600            # behaviour window for destinations
DNS_WINDOW = 15*60          # DGA / tunnelling window
BUCKET = 300                # device-level metric bucket (5 min)
HISTORY_BUCKETS = 7*24*12   # one week of buckets
LEARNING = 24*3600          # before this, "new destination" means little
WEIGHTS = dict(beacon=.75,sizes=.3,persist=.2,new=.35,volume=.7,short=.35,iforest=.45,dga=.8,tunnel=.8,spike=.5,dnsfirst=.15)
TWO_LEVEL = {'co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au','co.jp','ne.jp','or.jp','com.br','com.cn','net.cn',
             'co.nz','co.za','co.in','com.mx','com.tr','co.kr','com.ar','gov.it'}
VOWELS = set('aeiouy')


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
        self.conns = deque(maxlen=20000)   # closed connections
        self.dns = deque(maxlen=20000)
        self.ip_domain, self.dns_seen_at = {}, {}  # resolved IP -> name / time of the answer
        self.dns_before = {}         # destination key -> [connections preceded by a DNS answer, total]
        self.flows = {}              # long-lived 4-tuple -> (out, in)
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
        for ip in ips:
            self.ip_domain[ip] = qname
            self.dns_seen_at[ip] = t
        if response and rcode == 0:  # only names that exist become "known"; a failed lookup must stay unseen
            entry = self.base['domains'].setdefault(registered(qname),[t,t,0])
            entry[1], entry[2] = t, entry[2]+1

    def syn(self,t,dst,dport):
        key = self.key(dst,dport)
        self.events.setdefault(key,deque(maxlen=300)).append(t)
        entry = self.base['dest'].setdefault(key,[t,t,0])
        entry[1], entry[2] = t, entry[2]+1
        seen = self.dns_seen_at.get(dst)
        counts = self.dns_before.setdefault(key,[0,0])
        counts[0] += bool(seen and 0 <= t-seen < 3)
        counts[1] += 1
        self.tick(t,dst)

    def close(self,t,dst,dport,out,inb,duration=None):
        self.conns.append((t,self.key(dst,dport),out,inb,duration))
        self.tick(t,out=out)

    def snapshot(self,t,flows):
        """Long-lived connections: a send burst counts as an event, so heartbeats on one socket are timed too."""
        current = {}
        for src,sport,dst,dport,out,inb in flows:
            tuple4 = (src,sport,dst,dport)
            current[tuple4] = (out,inb)
            old = self.flows.get(tuple4)
            if old and out > old[0]:
                key = self.key(dst,dport)
                self.events.setdefault(key,deque(maxlen=300)).append(t)
                self.tick(t,out=out-old[0])
        self.flows = current

    def user_idle(self,t,idle):
        self.idle = [(s,i) for s,i in self.idle if t-s < WINDOW]+[(t,idle)]

    def was_idle(self,t):
        before = [i for s,i in self.idle if s <= t]
        return bool(before and before[-1])

    # ---------- analysis ----------
    def destination(self,key,now):
        parts, evidence = [], []
        times = [t for t in self.events.get(key,()) if now-t < WINDOW]
        conns = [c for c in self.conns if c[1] == key and now-c[0] < WINDOW]
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
            sizes = [c[2] for c in conns]
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
        out = sum(c[2] for c in conns)
        inb = sum(c[3] for c in conns)
        if out > 5e6 and out/(inb+1) > 3:
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
        if self.forest:
            isolation = self.forest.score(vector)
            if isolation > .6:
                parts.append(('iforest',(isolation-.6)/.25))
                evidence.append(f'profilo insolito rispetto al traffico abituale (isolamento {isolation:.2f})')
        return parts,evidence,vector,times

    def vector(self,key,times,conns,regularity,now):
        out = sum(c[2] for c in conns)
        inb = sum(c[3] for c in conns)
        durations = [c[4] for c in conns if c[4] is not None]
        first = self.base['dest'].get(key,[now])[0]
        return [math.log1p(out),math.log1p(inb),math.log1p(out/(inb+1)),math.log1p(len(times)),
                math.log1p(statistics.median(durations)) if durations else 0.,regularity,
                math.log1p((now-first)/3600),0. if key.endswith((':443',':80')) else 1.]

    def domains(self,now):
        found = []
        recent = [d for d in self.dns if now-d[0] < DNS_WINDOW]
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
        keys = {k for k,v in self.events.items() if v and now-v[-1] < WINDOW} | {c[1] for c in self.conns if now-c[0] < WINDOW}
        results, vectors = [], []
        for key in keys:
            parts,evidence,vector,times = self.destination(key,now)
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
        results += self.domains(now)+self.device(now)
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
        for key in [k for k,v in self.events.items() if not v or now-v[-1] > WINDOW]:
            del self.events[key]
        if len(self.ip_domain) > 50000:
            self.ip_domain = dict(list(self.ip_domain.items())[-25000:])
        for name in ('dest','domains'):
            table = self.base[name]
            if len(table) > 20000:
                for key in sorted(table,key=lambda k: table[k][1])[:len(table)-15000]:
                    del table[key]
        self.base['beacons'] = {k:v for k,v in self.base['beacons'].items() if k in self.base['dest']}
