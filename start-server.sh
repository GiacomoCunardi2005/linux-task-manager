#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$(readlink -f -- "$0")")"
if [[ ! -x .venv-server/bin/python ]]; then
    python3 -m venv --system-site-packages .venv-server
fi
if ! .venv-server/bin/python -c 'import psutil' >/dev/null 2>&1; then
    .venv-server/bin/python -m pip install -r requirements-server.txt
fi
exec .venv-server/bin/python server.py "$@"
