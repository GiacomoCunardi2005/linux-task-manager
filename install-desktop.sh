#!/usr/bin/env bash
set -euo pipefail
project_dir="$(dirname -- "$(readlink -f -- "$0")")"
applications_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p -- "$applications_dir"
python3 - "$project_dir" "$applications_dir" <<'PY'
from pathlib import Path
import sys
project, applications = map(Path, sys.argv[1:])
def quote(value):
    return '"' + str(value).replace('\\','\\\\').replace('"','\\"').replace('`','\\`').replace('$','\\$').replace('%','%%') + '"'
(applications / 'linux-task-manager.desktop').write_text(
    '[Desktop Entry]\nType=Application\nName=Gestione attività Linux\n'
    'Comment=Processi e prestazioni nello stile di Windows 11\n'
    f'Exec={quote(project / "start.sh")}\nIcon={project / "icon.svg"}\n'
    'Terminal=false\nCategories=System;Monitor;\nStartupNotify=true\nStartupWMClass=linux-task-manager\n')
print(applications / 'linux-task-manager.desktop')
PY
