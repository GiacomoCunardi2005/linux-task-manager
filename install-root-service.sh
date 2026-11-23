#!/usr/bin/env bash
# Root service for Gestione attività Linux.
#   install:    sudo ./install-root-service.sh
#   uninstall:  sudo ./install-root-service.sh --uninstall
# The code run as root is copied to /opt and owned by root: root never executes files your user can edit.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Esegui con sudo: sudo $0" >&2; exit 1; }
user="${SUDO_USER:-}"
[[ -n "$user" && "$user" != root ]] || { echo "Avvia con sudo dal tuo utente normale (SUDO_USER mancante)." >&2; exit 1; }
src="$(dirname -- "$(readlink -f -- "$0")")"
dest=/opt/linux-task-manager-root
unit=/etc/systemd/system/linux-task-manager-root.service
policy=/usr/share/polkit-1/actions/org.linuxtaskmanager.terminate.policy

if [[ "${1:-}" == --uninstall ]]; then
    systemctl disable --now linux-task-manager-root.service 2>/dev/null || true
    rm -f -- "$unit" "$policy"
    rm -rf -- "$dest"
    systemctl daemon-reload
    echo "Servizio root rimosso. Configurazione lasciata in /etc/linux-task-manager (eliminabile a mano)."
    exit 0
fi

/usr/bin/python3 -c 'import psutil, numpy' 2>/dev/null || {
    echo "Mancano psutil o numpy per il Python di sistema. Installa: sudo pacman -S python-psutil python-numpy (Arch/CachyOS) oppure sudo apt install python3-psutil python3-numpy" >&2
    exit 1
}
command -v pkexec >/dev/null || echo "Avviso: pkexec non trovato, non potrai chiudere processi di root dall'app." >&2
home="$(getent passwd "$user" | cut -d: -f6)"
[[ -d "$home" ]] || { echo "Cartella home di $user non trovata." >&2; exit 1; }

install -d -m 0755 -o root -g root "$dest" /etc/linux-task-manager
install -m 0644 -o root -g root "$src/rootservice.py" "$src/detection.py" "$src/agents.py" "$src/wine.py" "$src/netbehavior.py" "$src/netwatch.py" "$src/filewatch.py" "$src/filebehavior.py" "$dest/"
cat > "$dest/terminate" <<'SH'
#!/bin/sh
exec /usr/bin/python3 -I -B /opt/linux-task-manager-root/rootservice.py terminate "$@"
SH
chown root:root "$dest/terminate"
chmod 0755 "$dest/terminate"
/usr/bin/python3 -c 'import json,sys; print(json.dumps({"user": sys.argv[1]}))' "$user" > /etc/linux-task-manager/service.json
chmod 0644 /etc/linux-task-manager/service.json
[[ -e /etc/linux-task-manager/ignore.txt ]] || printf '%s\n' \
    '# Eccezioni del servizio root, una per riga: percorso eseguibile, nome processo,' \
    '# file di avvio (percorso completo), "crontab utente" o "trappole". Modificabile solo da root.' \
    > /etc/linux-task-manager/ignore.txt
[[ -e /etc/linux-task-manager/network-ignore.txt ]] || install -m 0644 -o root -g root "$src/network-ignore.txt" /etc/linux-task-manager/network-ignore.txt

cat > "$unit" <<EOF
[Unit]
Description=Gestione attività Linux - servizio root (rilevamento e trappole)
After=local-fs.target

[Service]
ExecStart=/usr/bin/python3 -I -B $dest/rootservice.py run
Restart=on-failure
RestartSec=5
RuntimeDirectory=linux-task-manager
RuntimeDirectoryMode=0755
StateDirectory=linux-task-manager
StateDirectoryMode=0700
# Read-only system except where traps and state live.
ProtectSystem=strict
ReadWritePaths=/tmp /var/tmp /dev/shm "$home"
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER

[Install]
WantedBy=multi-user.target
EOF

cat > "$policy" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="org.linuxtaskmanager.terminate">
    <description>Terminare un processo di un altro utente o di root</description>
    <message>Gestione attività vuole terminare un processo che non è tuo</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">$dest/terminate</annotate>
  </action>
</policyconfig>
EOF
chmod 0644 "$unit" "$policy"

systemctl daemon-reload
systemctl enable linux-task-manager-root.service
# restart, not just --now: an already running service would keep executing the old code
systemctl restart linux-task-manager-root.service
sleep 2
systemctl --no-pager --lines=5 status linux-task-manager-root.service || true
echo "Servizio root attivo per l'utente $user. Dopo ogni aggiornamento del progetto rilancia: sudo $0"
