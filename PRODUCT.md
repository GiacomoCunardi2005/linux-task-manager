# Product
<!-- impeccable:product-schema 1 -->

## Platform
Linux desktop, initially CachyOS, verified on GNOME/Wayland.

## Stack
Python + Qt, confirmed by the user. psutil for Linux counters.

## Product Purpose
Recreate Windows 11 Task Manager's Performance view as faithfully as possible, with actual Linux performance data.

## Capabilities and Constraints
CPU, memory, physical block devices, network interfaces, detected DRM GPUs and Linux NPU accelerators. Device insertion/removal is detected during sampling; link metadata includes negotiated USB/PCIe speed and Wi-Fi radio standard/rates. Performance counters are read-only; process termination is limited to the current user, with confirmation and PID identity validation. No administrative permissions. Unavailable hardware metrics must be identified honestly. The collapsible navigation must contain only Processi and Prestazioni (explicit user correction). Processi now includes live per-process CPU, RSS, disk I/O, status, PID, user search, numeric sorting and termination. Per-process TCP/UDP traffic uses the existing optional NetHogs helper, without elevating the GUI or changing system capabilities. Process rows group same-user executable names, with actual PIDs expandable and termination limited to single processes.

## Brand Commitments
User explicitly requires the original positions, information hierarchy, graphs and colors. Authority: reference/windows11-performance.jpg, downloaded from TechRadar's Windows 11 Task Manager guide. Italian UI, inferred from the conversation.

## Headless remote monitoring

Optional Python/psutil-only server, installed as a non-root systemd user service or run in foreground. The desktop connects by IP/host, port and an access key containing a pinned TLS certificate fingerprint and random token. A bounded HTTPS endpoint serves one cached snapshot per second; no remote commands exist. The client reuses Processi and Prestazioni, clears histories/selection on host changes, and permanently disables task termination for remote data. Full process arguments are omitted, retaining only session-keyed grouping identifiers. Intended for private LAN/VPN access; boot without login uses explicit user-configured systemd linger.
