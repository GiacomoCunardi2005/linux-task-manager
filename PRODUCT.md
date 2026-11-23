# Product
<!-- impeccable:product-schema 1 -->

## Platform
Linux desktop, initially CachyOS, verified on GNOME/Wayland.

## Stack
Python + Qt, confirmed by the user. psutil for Linux counters.

## Product Purpose
Recreate Windows 11 Task Manager's Performance view as faithfully as possible, with actual Linux performance data.

## Capabilities and Constraints
CPU, memory, physical block devices, network interfaces, detected DRM GPUs and Linux NPU accelerators. Device insertion/removal is detected during sampling; link metadata includes negotiated USB/PCIe speed and Wi-Fi radio standard/rates. Performance counters are read-only; process termination needs confirmation and PID identity validation; other users' processes additionally need the root service and an admin password. The GUI itself never runs with administrative permissions. Unavailable hardware metrics must be identified honestly. The collapsible navigation must contain only Processi and Prestazioni (explicit user correction). Processi now includes live per-process CPU, RSS, disk I/O, status, PID, user search, numeric sorting and termination. Per-process TCP/UDP traffic uses the existing optional NetHogs helper, without elevating the GUI or changing system capabilities. Process rows group same-user executable names, with actual PIDs expandable. Heuristic suspicious-behaviour checks (detection.py) run on the monitored machine on already collected data plus startup files, own-user sockets and USB keyboards; they are labelled as non-antivirus signals. Decoy trap files in /tmp, /var/tmp and /dev/shm are watched with unprivileged inotify (access by any user triggers; PID only when an own-user process still holds the file), re-armed after deletion and removed on exit or after a crash. Termination targets a single process or, for a group, each of its PIDs after one confirmation.

## Brand Commitments
User explicitly requires the original positions, information hierarchy, graphs and colors. Authority: reference/windows11-performance.jpg, downloaded from TechRadar's Windows 11 Task Manager guide. Italian UI, inferred from the conversation.

## Root service and autostart

The root service also observes bursts of changes in existing XDG personal folders using fanotify directory marks and PIDFD attribution. Distinct files are counted across renames for currently active PID/start-time identities. Initial thresholds are 30 files/15 seconds for medium risk, and 100 files including 20 renames/deletions for high risk. Observation only; no automatic process action. Coverage and limits are shown in process anomalies and the footer tooltip.

The GUI never runs as root (user decision delegated to the developer: safer and Wayland-compatible). An optional systemd system service (rootservice.py, installed root-owned in /opt by install-root-service.sh) gives full visibility: all processes' executables, disk I/O and sockets, fanotify attribution of trap access, root crontab. It writes a root-owned 0640 state file the app trusts only when fresh. Its ignore list lives in /etc so user-level malware cannot silence it. Stopping other users' processes uses pkexec with an identity-checked helper; there is no standing command channel. The headless remote server was removed at the user's request. The app autostarts at login in the tray and quits cleanly on SIGTERM so traps are removed.

Connection topology includes USB root hubs, intermediate hubs and peripherals even without storage/network interfaces, plus actual USB4/Thunderbolt routers exposed by the kernel. It is read-only, includes negotiated link speeds, and separates host capabilities/declared USB versions from actual external links. Parent relationships are taken from sysfs, never inferred from connector shapes, bus numbers or marketing names.

Behavioural network anomaly detection (netbehavior.py, netwatch.py, root service): no blacklists, signatures or malware-trained models. BPF-filtered DNS and SYN capture, sock_diag close events and ss counters feed beaconing, DGA, DNS tunnelling, volume, destination novelty, temporal correlation and an Isolation Forest fitted on the local baseline; independent indicators combine into a 0-100 ranking shown in the Anomalie di rete dialog. Only scores of 70+ become alerts.
