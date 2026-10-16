# Performance view

Mode: Operate. Code-first reconstruction from the user-selected screenshot; no new visual direction.

Match the dark Windows 11 22H2 reference: 42px titlebar, 50px toolbar, 240px navigation, 208px device list, main chart with 60 seconds right-aligned, 100% at top right, statistics beneath. Dark surfaces #202020 / #191919 / #272727. CPU cyan, memory lavender, disk green, network pink, GPU purple. Thin square chart grid, translucent area fill, small sparklines, understated typography. Use Segoe UI when installed, otherwise Noto Sans.

The main heading, device name, chart, and two-column statistics retain reference positions. Linux names replace Windows-specific concepts; fd allocation replaces Windows handles. Do not fabricate hardware or counters. GPU engine accounting may cover only accessible processes, and must say so.

User correction: keep only Processi and Prestazioni in the collapsible navigation. Preserve the Performance page.

## Processes view

Extend the same Windows 11 dark world. Reference: reference/windows11-processes.jpg. Main pane uses search, 50px action toolbar, 50px two-line resource headers with live totals, 30px rows, flat dark background, burgundy heat cells for CPU/memory/disk/network. Name and status left; metrics right; Linux PID appended. Theme icons resolved through installed desktop files and XDG icon directories. Expandable same-user executable groups aggregate available usage, retain individual PID children, and do not support batch termination. Interpreter arguments distinguish unrelated scripts. Search and stable identity selection persist through live updates; stopping a task always names its identity and asks about unsaved data.

Memory statistics include configured RAM speed, used slots, form factor, type and module capacities from cached udev SMBIOS data. Installed capacity is distinguished from Linux usable memory; commitment and slab use their actual Linux meanings. Missing firmware data stays unavailable, never inferred from the CPU or RAM model.

Device resources synchronize from each completed sample. Removed/replaced devices discard their own histories and selection safely returns to CPU. NPU uses the same 60-second percentage graph with a warm accent. Network and disk details distinguish observed traffic from negotiated bus/radio rates; additional metadata stays under the graph and the detail pane scrolls vertically at compact heights.

Process network cells show Mbps from NetHogs cumulative TCP/UDP byte deltas. No privileged GUI, automatic privilege changes, or zero values substituted for a failed capture backend. Expanded groups and the selected process identity survive refresh.

## Remote source

A title-bar connection button opens a compact IP/host, port and access-key form. The source label remains visible on both pages, names the remote host and marks read-only mode or connection failure. The connection form offers a return to the local PC. Source changes clear selected PID, all charts and old resource labels; late signals from an earlier sampler are ignored. Existing graph/page layouts remain shared by local and remote monitoring.

## Network Performance details

Preserve every network metric. Keep the chart first, then a compact full-width row of live send/receive values. Under that row, separate connection/radio details, adapter details and addresses with short headings and 20px group gaps, without cards or collapsed disclosures. At 560px available detail width, show connection on the left and adapter/addresses on the right; below that, stack the groups with vertical scrolling. Give IPv6 its own full-width value row so complete addresses remain readable. All values remain in Copy information, and metadata values can be selected or inspected via tooltip. The shared statistics layout must respect content minimum heights rather than squeeze rows; CPU/RAM retain their existing paired-statistics layout.

## Physical connections

Add Collegamenti inside the existing Performance resource list, with a USB symbol instead of an invented sparkline. Its plain tree reads host/root hub → intermediate hub → peripheral; a separate USB4/Thunderbolt router tree avoids guessed cross-bus associations. Keep standard and negotiated link rate in separate columns, complete names/details in selection and tooltips, and a copy action. No utilization graph exists because no comparable real counter is exposed. Preserve expansion/selection during hotplug updates; reset when changing monitored computer.

Network charts and sidebar sparklines have a minimum upper scale of 1 Mbit/s (1,000,000 bit/s); autoscaling above that threshold still follows the 60-second history.

Network identity shows the hardware model at the chart heading and groups manufacturer, model and IDs in Identità hardware. Scheda di rete explicitly calls the Linux name Interfaccia, then shows driver, bus, location and MTU. Keep radio settings and addresses separate; USB route remains its own group. Descriptor manufacturer and registered ID vendor are distinct when they disagree. Model names and IPv6 values receive full-row space when needed. Existing one/two-column reflow and complete Copy information remain shared by local and remote sources.
