#!/usr/bin/env bash
# Menu entry plus login autostart in the notification area. --no-autostart removes the autostart entry.
set -euo pipefail
project_dir="$(dirname -- "$(readlink -f -- "$0")")"
applications_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
autostart_dir="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"
mkdir -p -- "$applications_dir" "$autostart_dir"
python3 - "$project_dir" "$applications_dir" "$autostart_dir" "${1:-}" <<'PY'
from pathlib import Path
import sys
project, applications, autostart = map(Path, sys.argv[1:4])
def quote(value):
    return '"' + str(value).replace('\\','\\\\').replace('"','\\"').replace('`','\\`').replace('$','\\$').replace('%','%%') + '"'
def entry(extra='', args=''):
    return ('[Desktop Entry]\nType=Application\nName=Gestione attività Linux\n'
        'Comment=Processi, prestazioni e protezione nello stile di Windows 11\n'
        f'Exec={quote(project / "start.sh")}{args}\nIcon={project / "icon.svg"}\n'
        'Terminal=false\nCategories=System;Monitor;\nStartupNotify=false\nStartupWMClass=linux-task-manager\n'+extra)
(applications / 'linux-task-manager.desktop').write_text(entry())
print(applications / 'linux-task-manager.desktop')
target = autostart / 'linux-task-manager.desktop'
if sys.argv[4] == '--no-autostart':
    target.unlink(missing_ok=True)
    print('Avvio automatico rimosso')
else:
    target.write_text(entry('X-GNOME-Autostart-enabled=true\nX-GNOME-Autostart-Delay=3\n',' --tray'))
    print(target, '(avvio al login nell’area di notifica)')
PY
