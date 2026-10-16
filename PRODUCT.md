# Product
<!-- impeccable:product-schema 1 -->

## Platform
Linux desktop, initially CachyOS, verified on GNOME/Wayland.

## Stack
Python + Qt, confirmed by the user. psutil for Linux counters.

## Product Purpose
Recreate Windows 11 Task Manager's Performance view as faithfully as possible, with actual Linux performance data.

## Capabilities and Constraints
CPU, memory, physical block devices, network interfaces and detected DRM GPUs. Performance counters are read-only; process termination is limited to the current user, with confirmation and PID identity validation. No administrative permissions. Unavailable hardware metrics must be identified honestly. The collapsible navigation must contain only Processi and Prestazioni (explicit user correction). Processi now includes live per-process CPU, RSS, disk I/O, status, PID, user search, numeric sorting and termination. Network usage per process is unavailable through the chosen Linux backend.

## Brand Commitments
User explicitly requires the original positions, information hierarchy, graphs and colors. Authority: reference/windows11-performance.jpg, downloaded from TechRadar's Windows 11 Task Manager guide. Italian UI, inferred from the conversation.
