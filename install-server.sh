#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$(readlink -f -- "$0")")"
if [[ "$EUID" -eq 0 ]]; then
    echo 'Esegui come utente normale, senza sudo.' >&2
    exit 1
fi
command -v openssl >/dev/null || { echo 'Installa openssl prima di continuare.' >&2; exit 1; }
command -v systemctl >/dev/null || { echo 'Senza systemd: usa ./start-server.sh --init e poi ./start-server.sh.' >&2; exit 1; }
export TASK_MANAGER_SERVER_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/linux-task-manager-server"
mkdir -p -- "$TASK_MANAGER_SERVER_DIR"
for file in server.py remote.py metrics.py hardware.py process_network.py requirements-server.txt start-server.sh; do
    if [[ ! "$file" -ef "$TASK_MANAGER_SERVER_DIR/$file" ]]; then
        cp -- "$file" "$TASK_MANAGER_SERVER_DIR/$file"
    fi
done
chmod +x -- "$TASK_MANAGER_SERVER_DIR/start-server.sh"
"$TASK_MANAGER_SERVER_DIR/start-server.sh" --init
python3 - <<'PY'
import os
from pathlib import Path
folder=Path(os.environ.get('XDG_CONFIG_HOME',Path.home()/'.config'))/'systemd/user'
folder.mkdir(parents=True,exist_ok=True)
def quote(value):
    return '"'+str(value).replace('\\','\\\\').replace('"','\\"').replace('%','%%').replace('$','$$')+'"'
launcher=quote((Path(os.environ['TASK_MANAGER_SERVER_DIR'])/'start-server.sh').resolve())
config=quote((Path(os.environ.get('XDG_CONFIG_HOME',Path.home()/'.config'))/'linux-task-manager-server').resolve())
(folder/'linux-task-manager-server.service').write_text(f'''[Unit]
Description=Gestione attività Linux — server HTTPS
After=network.target

[Service]
ExecStart={launcher} --config {config}
Restart=on-failure
RestartSec=3
UMask=0077

[Install]
WantedBy=default.target
''')
PY
systemctl --user daemon-reload
systemctl --user enable linux-task-manager-server.service
systemctl --user restart linux-task-manager-server.service
echo 'Server installato. Porta TCP: 8765. Stato: systemctl --user status linux-task-manager-server'
echo 'Per avviarlo anche senza login e dopo un riavvio, esegui una volta:'
printf 'sudo loginctl enable-linger %q\n' "$USER"
