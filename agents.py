"""Checks on AI coding agent extensions (Claude Code, Codex): hooks, skills, MCP servers and risky settings.

Hooks, skill `!`command`` preprocessing and MCP server commands are code that runs with the user's
permissions, sometimes before the model or the user sees anything. These checks flag dangerous content,
unpinned MCP packages and risky agent settings, and remember fingerprints so that a hook or MCP server that
appears or changes after approval (a "rug pull") is reported.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import time
try:
    import tomllib
except ImportError:  # Python 3.10: Codex settings (TOML) are skipped, the Claude checks still run
    tomllib = None

NETWORK = re.compile(r'\b(curl|wget|nc|ncat|netcat|socat|telnet|Invoke-WebRequest)\b|/dev/(tcp|udp)/')
SECRET = re.compile(r'gh\s+auth\s+token|\.ssh/|\bid_(rsa|ed25519|ecdsa)\b|\.aws/|\.netrc|\.git-credentials|\bprintenv\b|/etc/shadow|'
                    r'secret-tool|\.codex/auth\.json|\.claude/\.credentials|(OPENAI|ANTHROPIC|GITHUB|AWS_SECRET)_[A-Z_]*(KEY|TOKEN)')
TEMP_EXEC = re.compile(r'(^|[\s"\'=;|&(])(/dev/shm|/run/shm|/tmp|/var/tmp)/(?!\.mount_)')
DYNAMIC = re.compile(r'(?:^|[\s(>\-*])!`([^`\n]+)`',re.M)
INSTRUCTIONS = ('AGENTS.md','CLAUDE.md','GEMINI.md','.cursorrules')
RUNNERS = {'npx','bunx','uvx','pipx'}
INTERVAL = 300
CHANGE_DAYS = 1


def short(path):
    return str(path).replace(str(Path.home()),'~',1)


class AgentScanner:
    def __init__(self,home,baseline,downloads=None,commands=(),interval=INTERVAL):
        self.home, self.baseline, self.downloads = Path(home), Path(baseline), downloads and Path(downloads)
        self.commands, self.interval = commands, interval  # detection.COMMANDS, passed in to avoid a circular import
        self.cache, self.findings, self.time = {}, [], -1e9
        self.md_cache = {}  # path -> (mtime/size, commands, Bash(*)): keeping ~4000 skill texts would cost ~30 MB

    # --- reading, with an mtime cache: thousands of plugin files, few of which change ---
    def text(self,path):
        try:
            info = os.stat(path)
            key = (info.st_mtime_ns,info.st_size)
            if self.cache.get(path,(None,))[0] != key:
                with open(path,encoding='utf-8',errors='replace') as handle:
                    self.cache[path] = (key,handle.read(1_000_000))
            return self.cache[path][1]
        except OSError:
            return None

    def json(self,path):
        text = self.text(path)
        try:
            return json.loads(text) if text else None
        except ValueError:
            return None

    def toml(self,path):
        text = self.text(path)
        try:
            return tomllib.loads(text) if text and tomllib else None
        except (tomllib.TOMLDecodeError if tomllib else ValueError):
            return None

    # --- judging ---
    def judge(self,command,what):
        """Findings for one piece of code that an agent runs automatically."""
        found = [(level,f'{what}: {reason}') for pattern,level,reason in self.commands if pattern.search(command)]
        if TEMP_EXEC.search(command):
            found.append(('alta',f'{what}: esegue un programma da una cartella temporanea'))
        if SECRET.search(command) and NETWORK.search(command):
            found.append(('alta',f'{what}: legge credenziali e usa la rete (possibile furto di token o chiavi)'))
        elif SECRET.search(command):
            found.append(('media',f'{what}: legge credenziali o chiavi'))
        return found

    @staticmethod
    def unpinned(command,args):
        """Package fetched and run fresh at every start: a compromised release runs immediately."""
        runner = Path(command or '').name
        args = list(args or [])
        if runner == 'pnpm' and args[:1] == ['dlx']:
            runner, args = 'pnpm dlx', args[1:]
        elif runner not in RUNNERS:
            return None
        package = next((a for a in args if not a.startswith('-')),None)
        if not package:
            return None
        bare = package[1:] if package.startswith('@') else package  # npm scope @org/name
        if package.endswith('@latest') or ('@' not in bare and '==' not in bare):
            return package
        return None

    # --- collecting what agents execute ---
    def hook_commands(self,data):
        """(event, command) from Claude/Cursor-style hooks.json or settings.json."""
        hooks = data.get('hooks',data) if isinstance(data,dict) else {}
        for event,entries in (hooks.items() if isinstance(hooks,dict) else []):
            for entry in entries if isinstance(entries,list) else []:
                if not isinstance(entry,dict):
                    continue
                inner = entry.get('hooks') if isinstance(entry.get('hooks'),list) else [entry]
                for hook in inner:
                    if isinstance(hook,dict) and isinstance(hook.get('command'),str):
                        yield event,hook['command']

    def mcp_servers(self,data):
        servers = data.get('mcpServers',data) if isinstance(data,dict) else {}
        return {n:s for n,s in servers.items() if isinstance(s,dict)} if isinstance(servers,dict) else {}

    def plugin_dirs(self):
        installed = self.json(self.home/'.claude'/'plugins'/'installed_plugins.json') or {}
        for entries in (installed.get('plugins') or {}).values():
            for entry in entries if isinstance(entries,list) else [entries]:
                if isinstance(entry,dict) and entry.get('installPath'):
                    yield 'Plugin Claude '+Path(entry['installPath']).parent.name,Path(entry['installPath'])
        codex = self.toml(self.home/'.codex'/'config.toml') or {}
        for name,settings in (codex.get('plugins') or {}).items():
            if not (isinstance(settings,dict) and settings.get('enabled')) or '@' not in name:
                continue
            plugin,market = name.split('@',1)
            versions = sorted((self.home/'.codex'/'plugins'/'cache'/market/plugin).glob('*'),key=lambda p: p.stat().st_mtime)
            if versions:
                yield 'Plugin Codex '+plugin,versions[-1]

    def project_dirs(self):
        claude = self.json(self.home/'.claude.json') or {}
        codex = self.toml(self.home/'.codex'/'config.toml') or {}
        seen = []
        for path in list((claude.get('projects') or {}))+list((codex.get('projects') or {})):
            folder = Path(path)
            if folder not in seen and folder != self.home and folder.is_dir():
                seen.append(folder)
        return seen[:300]

    def surfaces(self):
        """(fingerprint key, label, code) for everything that runs automatically, plus static findings."""
        items, found = [], []
        claude = self.json(self.home/'.claude.json') or {}
        codex = self.toml(self.home/'.codex'/'config.toml') or {}
        # Settings that remove the agent's own safety net.
        if codex.get('sandbox_mode') == 'danger-full-access' or codex.get('approval_policy') == 'never':
            found.append(('media','Codex (~/.codex/config.toml): '+' e '.join(
                text for key,value,text in (('sandbox_mode','danger-full-access','sandbox disattivata'),('approval_policy','never','nessuna richiesta di approvazione'))
                if codex.get(key) == value)+': un’istruzione ostile in un repository o in una pagina web può eseguire comandi senza limiti'))
        settings = [(self.home/'.claude'/name) for name in ('settings.json','settings.local.json')]
        for folder in self.project_dirs():
            settings += [folder/'.claude'/'settings.json',folder/'.claude'/'settings.local.json']
            env = self.text(folder/'.env') or ''
            if re.search(r'^\s*(export\s+)?CODEX_HOME\s*=',env,re.M):
                found.append(('alta',f'{short(folder/".env")} imposta CODEX_HOME: tecnica per far caricare a Codex una configurazione del repository (CVE-2025-61260)'))
            for name,server in self.mcp_servers(self.json(folder/'.mcp.json') or {}).items():
                items.append((f'mcp|{folder}/.mcp.json|{name}',f'Server MCP «{name}» del progetto {short(folder)}',server))
            for name,server in ((self.toml(folder/'.codex'/'config.toml') or {}).get('mcp_servers') or {}).items():
                items.append((f'mcp|{folder}/.codex|{name}',f'Server MCP Codex «{name}» del progetto {short(folder)}',server))
            for skill in sorted((folder/'.claude').glob('skills/**/SKILL.md'))+sorted((folder/'.claude').glob('commands/*.md')):
                items += self.markdown(skill,f'Skill del progetto {short(folder)}',found)
        for path in settings:
            data = self.json(path) or {}
            for index,(event,command) in enumerate(self.hook_commands(data)):
                items.append((f'hook|{path}|{event}|{index}',f'Hook {event} in {short(path)}',command))
            if (data.get('permissions') or {}).get('defaultMode') == 'bypassPermissions':
                found.append(('media',f'{short(path)}: Claude Code senza richieste di permesso (bypassPermissions)'))
        for name,server in self.mcp_servers(claude).items():
            items.append((f'mcp|claude|{name}',f'Server MCP «{name}» (~/.claude.json)',server))
        for project,data in (claude.get('projects') or {}).items():
            for name,server in self.mcp_servers(data if isinstance(data,dict) else {}).items():
                items.append((f'mcp|claude|{project}|{name}',f'Server MCP «{name}» del progetto {short(project)}',server))
        for name,server in (codex.get('mcp_servers') or {}).items():
            items.append((f'mcp|codex|{name}',f'Server MCP Codex «{name}»',server))
        for label,folder in self.plugin_dirs():
            for path in folder.rglob('*'):
                if 'node_modules' in path.parts:
                    continue
                if path.name == 'hooks.json':
                    for index,(event,command) in enumerate(self.hook_commands(self.json(path) or {})):
                        items.append((f'hook|{path.relative_to(folder)}|{label}|{event}|{index}',f'{label}: hook {event}',command))
                elif path.name == '.mcp.json':
                    for name,server in self.mcp_servers(self.json(path) or {}).items():
                        items.append((f'mcp|{label}|{name}',f'{label}: server MCP «{name}»',server))
                elif path.name == 'SKILL.md' or (path.suffix == '.md' and path.parent.name in ('commands','agents')):
                    items += self.markdown(path,label,found)
        for root in (self.home/'.claude'/'skills',self.home/'.codex'/'skills',self.home/'.claude'/'commands'):
            for path in sorted(root.rglob('*.md')):
                items += self.markdown(path,'Skill utente',found)
        if self.downloads:
            for name in INSTRUCTIONS:
                if (self.downloads/name).is_file():
                    found.append(('media',f'{short(self.downloads/name)}: istruzioni per agenti nella cartella dei download; un agente avviato lì le seguirebbe'))
        return items,found

    def markdown(self,path,label,found):
        try:
            info = os.stat(path)
        except OSError:
            return []
        key = (info.st_mtime_ns,info.st_size)
        if self.md_cache.get(path,(None,))[0] != key:
            try:
                with open(path,encoding='utf-8',errors='replace') as handle:
                    text = handle.read(1_000_000)
            except OSError:
                return []
            commands = []
            for index,match in enumerate(DYNAMIC.finditer(text)):
                command = match[1].strip()
                first = command.split()[0] if command.split() else ''
                # Documentation often talks about the `!` syntax in prose; only an executable or a path is a command.
                if first.startswith(('/','./','~/','$')) or shutil.which(first):
                    commands.append((index,command))
            frontmatter = text.split('\n---',1)[0] if text.startswith('---') else ''
            self.md_cache[path] = (key,commands,path.name == 'SKILL.md' and bool(re.search(r'allowed-tools:.*Bash\(\*\)',frontmatter)))
        _,commands,bash_all = self.md_cache[path]
        if bash_all:
            found.append(('media',f'{label}: {short(path)} si concede qualsiasi comando shell senza conferma (Bash(*))'))
        return [(f'dyn|{path}|{index}',f'{label}: comando eseguito prima del modello in {short(path)}',command) for index,command in commands]

    # --- scan with fingerprints ---
    def load(self):
        try:
            data = json.loads(self.baseline.read_text())
            return data.get('fingerprints'),data.get('changes',[])
        except (OSError,ValueError,AttributeError):
            return None,[]

    def scan(self,now,ignored):
        if 'agenti' in ignored:
            return []
        if now-self.time >= self.interval:
            self.time = now
            items,found = self.surfaces()
            current, groups = {}, {}
            for key,label,code in items:
                if any(part in ignored for part in (label,key.split('|')[1])):
                    continue
                if isinstance(code,dict):  # MCP server definition
                    command = ' '.join([str(code.get('command') or '')]+[str(a) for a in code.get('args') or []]+[str(code.get('url') or '')])
                    found += self.judge(command,label)
                    package = self.unpinned(code.get('command'),code.get('args'))
                    if package:
                        found.append(('media',f'{label}: avvia {package} senza versione fissata, quindi esegue l’ultima pubblicata a ogni avvio'))
                    if re.match(r'http://(?!localhost|127\.|\[::1\])',str(code.get('url') or '')):
                        found.append(('media',f'{label}: collegamento non cifrato (http)'))
                    code = json.dumps({k:code.get(k) for k in ('command','args','url','env','headers')},sort_keys=True,default=str)
                else:
                    found += self.judge(code,label)
                current[key] = hashlib.sha256(code.encode()).hexdigest()
                groups.setdefault(key,label)
            previous,changes = self.load()
            if previous is not None:
                changed = {}
                for key,digest in current.items():
                    if previous.get(key) != digest:
                        what = 'nuovo' if key not in previous else 'modificato'
                        changed.setdefault(groups[key].split(':')[0],[]).append(what)
                for label,whats in changed.items():
                    changes.append(dict(time=time.time(),reason=f'{label}: {len(whats)} tra hook, server MCP o comandi automatici '
                        +('nuovi' if set(whats) == {'nuovo'} else 'nuovi o modificati')+' dall’ultimo controllo. Se non li hai installati o aggiornati tu, verificali.'))
            changes = [c for c in changes if time.time()-c['time'] < CHANGE_DAYS*86400][-50:]
            try:
                self.baseline.parent.mkdir(parents=True,exist_ok=True)
                temporary = self.baseline.with_suffix('.tmp')
                temporary.write_text(json.dumps(dict(fingerprints=current,changes=changes)))
                os.replace(temporary,self.baseline)
            except OSError:
                pass
            self.findings = [dict(severity=level,reason=reason) for level,reason in dict.fromkeys(found)
                             if not any(word in reason for word in ignored)]
            self.findings += [dict(severity='media',reason=time.strftime('%d/%m %H:%M ',time.localtime(c['time']))+c['reason']) for c in changes]
        return self.findings
