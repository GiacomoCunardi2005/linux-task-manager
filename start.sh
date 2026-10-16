#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$(readlink -f -- "$0")")"
if [[ ! -x .venv/bin/python ]]; then
    python3 -m venv --system-site-packages .venv
fi
if ! .venv/bin/python -c 'import PySide6.QtSvg, psutil' >/dev/null 2>&1; then
    .venv/bin/python -m pip install -r requirements.txt
fi
exec .venv/bin/python app.py "$@"
