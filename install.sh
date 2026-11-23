#!/usr/bin/env bash
# Gestione attività Linux — installer for any Linux distribution.
#
#   ./install.sh                  install for the current user (menu entry + start at login in the tray)
#   ./install.sh --root-service   also install the optional root service (asks for the admin password)
#   ./install.sh --no-autostart   do not start at login
#   ./install.sh --no-deps        do not install system packages (you provide them)
#   ./install.sh --uninstall      remove the app (and the root service, if installed)
#   ./install.sh --yes            do not ask before installing system packages
set -euo pipefail

src="$(dirname -- "$(readlink -f -- "$0")")"
app_dir="${XDG_DATA_HOME:-$HOME/.local/share}/linux-task-manager"
root_service=0 autostart=1 deps=1 uninstall=0 assume_yes=0
for arg in "$@"; do
    case "$arg" in
        --root-service) root_service=1 ;;
        --no-autostart) autostart=0 ;;
        --no-deps) deps=0 ;;
        --uninstall) uninstall=1 ;;
        --yes|-y) assume_yes=1 ;;
        -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Opzione sconosciuta: $arg (usa --help)" >&2; exit 2 ;;
    esac
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'Errore: %s\n' "$*" >&2; exit 1; }
[[ $EUID -ne 0 ]] || die "esegui l'installatore come utente normale, non con sudo: chiederà la password solo quando serve."
as_root() { if [[ $EUID -eq 0 ]]; then "$@"; else sudo "$@"; fi; }

if [[ $uninstall -eq 1 ]]; then
    if [[ -e /etc/systemd/system/linux-task-manager-root.service ]]; then
        say "Rimuovo il servizio root"
        as_root "$app_dir/install-root-service.sh" --uninstall || as_root "$src/install-root-service.sh" --uninstall
    fi
    say "Rimuovo l'app e le voci del menu"
    rm -f -- "${XDG_DATA_HOME:-$HOME/.local/share}/applications/linux-task-manager.desktop" \
             "${XDG_CONFIG_HOME:-$HOME/.config}/autostart/linux-task-manager.desktop"
    rm -rf -- "$app_dir"
    echo "Fatto. Le impostazioni in ~/.config/linux-task-manager sono state lasciate."
    exit 0
fi

# ---------- system packages: Python 3, venv/pip, libraries the Qt wheels need, ss, polkit ----------
install_packages() {
    local manager="" install="" packages=()
    if command -v pacman >/dev/null; then
        manager=pacman install="pacman -S --needed"
        packages=(python python-pip python-psutil python-numpy iproute2 procps-ng polkit libxkbcommon libxkbcommon-x11 fontconfig libglvnd xcb-util-cursor dbus glib2 krb5)
    elif command -v apt-get >/dev/null; then
        manager=apt install="apt-get install"
        packages=(python3 python3-venv python3-pip python3-psutil python3-numpy iproute2 procps pkexec libxkbcommon0 libxkbcommon-x11-0 libfontconfig1 libegl1 libgl1 libxcb-cursor0 libdbus-1-3 libglib2.0-0 libgssapi-krb5-2)
    elif command -v dnf >/dev/null; then
        manager=dnf install="dnf install"
        packages=(python3 python3-pip python3-psutil python3-numpy iproute procps-ng polkit libxkbcommon libxkbcommon-x11 fontconfig mesa-libEGL mesa-libGL xcb-util-cursor dbus-libs glib2 krb5-libs)
    elif command -v zypper >/dev/null; then
        manager=zypper install="zypper install"
        packages=(python3 python3-pip python3-psutil python3-numpy iproute2 procps polkit libxkbcommon0 libxkbcommon-x11-0 fontconfig Mesa-libEGL1 Mesa-libGL1 libxcb-cursor0 libdbus-1-3 glib2-tools krb5)
    elif command -v xbps-install >/dev/null; then
        manager=xbps install="xbps-install"
        packages=(python3 python3-pip python3-psutil python3-numpy iproute2 procps-ng polkit libxkbcommon fontconfig libglvnd xcb-util-cursor dbus-libs glib mit-krb5-libs)
    elif command -v apk >/dev/null; then
        die "Alpine usa musl: le librerie Qt (PySide6) non sono disponibili per musl. Usa una distribuzione con glibc."
    else
        echo "Gestore di pacchetti non riconosciuto: installa a mano Python ≥ 3.10 con venv e pip, poi rilancia con --no-deps." >&2
        return
    fi
    say "Pacchetti di sistema ($manager): ${packages[*]}"
    if [[ $assume_yes -eq 0 ]]; then
        read -r -p "Installarli ora con sudo? [S/n] " answer
        [[ -z "$answer" || "$answer" =~ ^[SsYy] ]] || { echo "Salto: rilancia con --no-deps se li installi tu."; return; }
    fi
    local yes=""
    case "$manager" in pacman) yes="--noconfirm" ;; apt|dnf|xbps) yes="-y" ;; zypper) yes="--non-interactive" ;; esac
    [[ "$manager" == apt ]] && as_root apt-get update
    # Package names drift between releases: try all at once, then one by one so one missing name does not stop the rest.
    if ! as_root $install $yes "${packages[@]}"; then
        for package in "${packages[@]}"; do as_root $install $yes "$package" || echo "  (non disponibile: $package)"; done
    fi
}
[[ $deps -eq 1 ]] && install_packages

python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null \
    || die "serve Python ≥ 3.10 (trovato: $(python3 --version 2>&1 || echo nessuno))."

# ---------- app files ----------
say "Copio l'app in $app_dir"
mkdir -p -- "$app_dir"
find "$app_dir" -maxdepth 1 -type f \( -name '*.py' -o -name '*.sh' \) -delete  # old code; keep .venv and settings
for file in "$src"/*.py "$src"/*.sh "$src"/icon.svg "$src"/requirements.txt "$src"/network-ignore.txt "$src"/README.md "$src"/VERSION; do
    [[ -e "$file" ]] && cp -- "$file" "$app_dir/"
done
rm -f -- "$app_dir"/test_*.py
chmod +x -- "$app_dir"/*.sh

say "Preparo l'ambiente Python (Qt e psutil da pip, la prima volta può richiedere qualche minuto)"
[[ -x "$app_dir/.venv/bin/python" ]] || python3 -m venv --system-site-packages "$app_dir/.venv" \
    || die "impossibile creare l'ambiente Python: installa il pacchetto venv di Python (per esempio python3-venv)."
"$app_dir/.venv/bin/python" -m pip install --quiet --upgrade pip
"$app_dir/.venv/bin/python" -m pip install --quiet -r "$app_dir/requirements.txt"
QT_QPA_PLATFORM=offscreen "$app_dir/.venv/bin/python" -c 'import sys; sys.path.insert(0, sys.argv[1]); import app' "$app_dir" \
    || die "l'app non si avvia: controlla i messaggi qui sopra."

say "Voce nel menu$([[ $autostart -eq 1 ]] && echo ' e avvio al login nell’area di notifica')"
if [[ $autostart -eq 1 ]]; then "$app_dir/install-desktop.sh"; else "$app_dir/install-desktop.sh" --no-autostart; fi

if [[ $root_service -eq 1 ]]; then
    say "Servizio root (rilevamento completo, trappole, analisi di rete)"
    as_root "$app_dir/install-root-service.sh"
fi

echo
say "Installata la versione $(cat "$app_dir/VERSION" 2>/dev/null || echo '?'). Avviala dal menu: «Gestione attività Linux»."
[[ $root_service -eq 1 ]] || echo "    Per la protezione completa: $src/install.sh --root-service"
