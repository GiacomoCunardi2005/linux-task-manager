"""Windows programs under Wine/Proton are a malware vector, not a trusted category.

Wine is no sandbox: a Windows program runs as the user and reaches the whole filesystem through Z:.
wineboot starts the programs listed in the Run/RunOnce keys and in the Startup folders of a prefix without
asking, exactly like Windows logon. These checks flag Windows executables started from temporary or download
folders, living-off-the-land tools used the way malware uses them, and autostart entries in Wine prefixes.
"""
import os
from pathlib import Path
import re
import subprocess
import threading

WINE_LOADER = re.compile(r'^wine(64)?(-preloader)?$')
WINDOWS_PATH = re.compile(r'^[A-Za-z]:\\')
RISKY_FOLDER = re.compile(r'(?i)\\(temp|tmp)\\|\\appdata\\local\\temp\\|\\(downloads|scaricati)\\|^z:\\(tmp|var\\tmp|dev\\shm)\\')
# (program, pattern on the whole command line, severity, reason). Sources: LOLBAS project, MITRE ATT&CK T1218.
LOLBINS = [
    ('powershell|pwsh',r'\s-(e|ec|enc|encodedcommand)\s+[a-z0-9+/=]{16,}','alta','PowerShell con comando codificato in base64'),
    ('powershell|pwsh',r'(iex|invoke-expression).*(downloadstring|invoke-webrequest|iwr|net\.webclient)|(downloadstring|invoke-webrequest|iwr|net\.webclient).*(iex|invoke-expression)','alta','PowerShell scarica ed esegue codice'),
    ('powershell|pwsh',r'\s-(w|windowstyle)\s+h(idden)?\b','media','PowerShell in finestra nascosta'),
    ('mshta',r'(https?:|javascript:|vbscript:)','alta','mshta esegue codice remoto o in linea'),
    ('mshta',r'.','media','mshta esegue un’applicazione HTML'),
    ('rundll32',r'(javascript:|https?:|\\\\\\\\|url\.dll|shell32\.dll,\s*shellexec_rundll)','alta','rundll32 usato per eseguire codice remoto o script'),
    ('regsvr32',r'(/i:|-i:)\s*(https?:|\\\\\\\\)|scrobj','alta','regsvr32 carica uno scriptlet remoto (tecnica Squiblydoo)'),
    ('certutil',r'-(urlcache|decode|decodehex)\b','alta','certutil usato per scaricare o decodificare file'),
    ('bitsadmin',r'/(transfer|addfile|setnotifycmdline)\b','alta','bitsadmin usato per scaricare file o avviare comandi'),
    ('wscript|cscript',r'\.(js|jse|vbs|vbe|wsf)\b','media','script Windows eseguito con Windows Script Host'),
    ('schtasks',r'/create\b','alta','crea un’attività pianificata (avvio automatico)'),
    ('reg',r'\badd\b.*\\currentversion\\run','alta','aggiunge un avvio automatico nel registro'),
]
RUN_SECTION = re.compile(r'^\[Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\'
                         r'(Run|RunOnce|RunServices|RunServicesOnce|Policies\\\\Explorer\\\\Run)\]',re.I)
WINE_DEFAULTS = re.compile(r'(?i)^c:\\\\windows\\\\system32\\\\winemenubuilder\.exe\b')  # created by every new prefix
PREFIX_GLOBS = ('.wine','.local/share/wineprefixes/*','.local/share/Steam/steamapps/compatdata/*/pfx','.steam/steam/steamapps/compatdata/*/pfx',
                'Games/*','Games/Heroic/Prefixes/*/*','.local/share/bottles/bottles/*','.var/app/com.usebottles.bottles/data/bottles/bottles/*')
STARTUP = ('drive_c/users/*/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/*',
           'drive_c/users/*/Start Menu/Programs/Startup/*','drive_c/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/*')


def is_wine(exe,cmdline):
    return bool(cmdline) and WINDOWS_PATH.match(cmdline[0] or '') is not None and (
        not exe or WINE_LOADER.match(os.path.basename(exe)) is not None or '/wine' in exe or 'proton' in exe.lower())


def windows_reasons(command):
    """Reasons for one Windows command line (a running process or an autostart value)."""
    reasons = []
    lowered = command.lower()
    words = lowered.split()
    first = lowered.split('"')[1] if lowered.startswith('"') else (words[0] if words else '')
    program = re.split(r'[\\/]',first)[-1].removesuffix('.exe')
    for names,pattern,level,text in LOLBINS:
        if re.fullmatch(names,program) and re.search(pattern,lowered):
            reasons.append((level,text))
            if names == 'mshta':
                break  # the generic mshta rule only applies when the specific one did not
    if RISKY_FOLDER.search(command):
        reasons.append(('media','programma Windows in una cartella temporanea o dei download'))
    return reasons


def process_reasons(row):
    """Static reasons for a process running under Wine/Proton."""
    cmdline = row.get('cmdline') or []
    if not is_wine(row.get('exe'),cmdline):
        return []
    return [(level,f'Wine/Proton: {text}') for level,text in windows_reasons(' '.join(cmdline))]


def wine_prefix(pid,proc=Path('/proc')):
    """WINEPREFIX of a running Wine process (own user, or any with root)."""
    try:
        environ = (Path(proc)/str(pid)/'environ').read_bytes().split(b'\0')
    except OSError:
        return None
    values = dict(item.split(b'=',1) for item in environ if b'=' in item)
    prefix = values.get(b'WINEPREFIX')
    if not prefix and values.get(b'STEAM_COMPAT_DATA_PATH'):
        prefix = values[b'STEAM_COMPAT_DATA_PATH']+b'/pfx'
    return Path(os.fsdecode(prefix)).resolve() if prefix else None


def run_entries(path):
    """(section, name, value) for every autostart value in a Wine registry file."""
    entries, section = [], None
    with open(path,encoding='utf-8',errors='replace') as handle:
        for line in handle:
            if line.startswith('['):
                match = RUN_SECTION.match(line)
                section = match[0].strip('[]') if match else None
            elif section and line.startswith('"') and '=' in line:
                name,_,value = line.strip().partition('=')
                entries.append((section,name.strip('"'),value.strip('"')))
    return entries


class WinePrefixScanner:
    def __init__(self,home,interval=300,discovery=3600):
        self.home, self.interval, self.discovery = Path(home), interval, discovery
        self.prefixes, self.cache, self.findings, self.time = set(), {}, [], -1e9
        self.discovered, self.discovering = -1e9, False
        self.lock = threading.Lock()

    def add(self,prefix):
        if prefix and (Path(prefix)/'system.reg').exists():
            with self.lock:
                self.prefixes.add(Path(prefix).resolve())  # ~/.steam/steam is a link to ~/.local/share/Steam

    def known(self):
        for pattern in PREFIX_GLOBS:
            for path in self.home.glob(pattern):
                self.add(path)

    def discover(self):
        """Prefixes anywhere in the home (e.g. sandboxes under ~/.cache): a bounded `find`, off the sampling thread."""
        try:
            output = subprocess.run(['find',str(self.home),'-maxdepth','7','-name','system.reg','-not','-path','*/drive_c/*'],
                                    capture_output=True,text=True,timeout=120).stdout
            for line in output.splitlines():
                self.add(Path(line).parent)
        except (OSError,subprocess.SubprocessError):
            pass
        finally:
            self.discovering = False

    def entries(self,path):
        try:
            stamp = os.stat(path).st_mtime_ns
        except OSError:
            return []
        if self.cache.get(path,(None,))[0] != stamp:
            try:
                self.cache[path] = (stamp,run_entries(path))
            except OSError:
                return []
        return self.cache[path][1]

    def scan(self,now,ignored):
        if 'wine' in ignored:
            return []
        if now-self.discovered >= self.discovery and not self.discovering:
            self.discovered, self.discovering = now, True
            threading.Thread(target=self.discover,daemon=True).start()
        if now-self.time < self.interval:
            return self.findings
        self.time = now
        self.known()
        found = []
        with self.lock:
            prefixes = sorted(self.prefixes)
        for prefix in prefixes:
            label = str(prefix).replace(str(self.home),'~',1)
            if label in ignored or str(prefix) in ignored:
                continue
            for name in ('user.reg','system.reg'):
                for section,key,value in self.entries(prefix/name):
                    windows = value.replace('\\\\','\\')
                    if WINE_DEFAULTS.match(value) or key in ignored:
                        continue
                    reasons = windows_reasons(windows)
                    level = 'alta' if any(r[0] == 'alta' for r in reasons) or RISKY_FOLDER.search(windows) else 'media'
                    found.append(dict(severity=level,reason=f'Wine: avvio automatico nel prefisso {label} ({section.rsplit(chr(92),1)[-1]}): '
                        f'«{key}» = {windows[:300]}'+(' — '+'; '.join(r[1] for r in reasons) if reasons else '')))
            for pattern in STARTUP:
                for item in prefix.glob(pattern):
                    if item.name.lower() != 'desktop.ini' and item.name not in ignored:
                        found.append(dict(severity='media',reason=f'Wine: programma nella cartella Esecuzione automatica del prefisso {label}: {item}'))
        self.findings = found
        return found
