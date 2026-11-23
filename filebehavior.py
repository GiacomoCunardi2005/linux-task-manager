"""Bounded, passive aggregation of file activity attributed to live processes.

The collector supplies confirmed process identities and stable file identifiers.
This module never opens a file or acts on a process.  Times are monotonic seconds.
"""

from collections import OrderedDict
from dataclasses import dataclass, field
import math
import os
import threading
import time


ACTIONS = frozenset(('modifica', 'rinomina', 'eliminazione'))


@dataclass(slots=True)
class _Activity:
    last: float
    directory: str
    actions: dict = field(default_factory=dict)


class FileBehavior:
    def __init__(self, window=15, medium=30, high=100, max_files=20000, max_processes=1024):
        if not math.isfinite(window) or window <= 0:
            raise ValueError('window must be positive and finite')
        if not isinstance(medium, int) or medium < 1 or not isinstance(high, int) or high < medium:
            raise ValueError('thresholds must be positive integers with high >= medium')
        if not isinstance(max_files, int) or max_files < 1 or not isinstance(max_processes, int) or max_processes < 1:
            raise ValueError('capacity limits must be positive integers')
        self.window = float(window)
        self.medium = medium
        self.high = high
        self.max_files = max_files
        self.max_processes = max_processes
        self._files = OrderedDict()
        self._processes = OrderedDict()
        self._lock = threading.Lock()
        self._overflow = False
        self._dropped = 0

    @property
    def overflow(self):
        """True once a capacity limit has caused an observation to be lost."""
        with self._lock:
            return self._overflow

    @property
    def dropped(self):
        """Number of distinct file records evicted because of capacity limits."""
        with self._lock:
            return self._dropped

    def _remove_file(self, key, capacity=False):
        self._files.pop(key)
        identity, file_id = key
        files = self._processes[identity]
        files.remove(file_id)
        if not files:
            del self._processes[identity]
        if capacity:
            self._overflow = True
            self._dropped += 1

    def _remove_process(self, identity, capacity=False):
        for file_id in tuple(self._processes[identity]):
            self._remove_file((identity, file_id), capacity=capacity)

    def _prune(self, now):
        # Record order follows the collector's monotonic clock.  Repeated writes
        # only move an existing record: there is no unbounded per-event queue.
        cutoff = now - self.window
        while self._files:
            key, activity = next(iter(self._files.items()))
            if activity.last > cutoff:
                break
            self._remove_file(key)

    def record(self, identity, file_id, action, path, now=None):
        """Record actions on one protected non-directory entry with a confirmed PID.

        ``file_id`` must identify the same object across renames.  Repeated
        actions update three timestamps at most, rather than retaining events.
        The optional ``now`` clock is also used by deterministic tests.
        """
        if isinstance(action, str):
            action = (action,)
        actions = ACTIONS.intersection(action)
        if not actions:
            return
        identity = tuple(identity)
        if len(identity) != 2 or identity[0] <= 0 or not math.isfinite(identity[1]):
            return
        hash(file_id)
        # Keep directory context only, never a file's contents or a growing list
        # of filenames.  Escape control characters in the user-visible reason.
        directory = os.path.dirname(os.fsdecode(path)) or '.'
        directory = ''.join(ch if ch.isprintable() else '?' for ch in directory)
        directory = directory[:512]
        with self._lock:
            when = time.monotonic() if now is None else float(now)
            if not math.isfinite(when):
                return
            self._prune(when)
            key = (identity, file_id)
            activity = self._files.get(key)
            if activity is None:
                if identity not in self._processes and len(self._processes) >= self.max_processes:
                    self._remove_process(next(iter(self._processes)), capacity=True)
                if len(self._files) >= self.max_files:
                    self._remove_file(next(iter(self._files)), capacity=True)
                self._processes.setdefault(identity, set()).add(file_id)
                activity = _Activity(when, directory)
                self._files[key] = activity
            else:
                activity.last = max(activity.last, when)
                activity.directory = directory
                self._files.move_to_end(key)
            for name in actions:
                activity.actions[name] = max(activity.actions.get(name, when), when)
            self._processes.move_to_end(identity)

    def poll(self, rows, ignored=(), now=None):
        """Return explained findings only for the process identities in rows."""
        ignored = set(ignored)
        active = {
            (row['pid'], row['created'])
            for row in rows
            if row.get('name') not in ignored and row.get('exe') not in ignored
        }
        with self._lock:
            when = time.monotonic() if now is None else float(now)
            if not math.isfinite(when):
                return []
            self._prune(when)
            for identity in tuple(self._processes):
                if identity not in active:
                    self._remove_process(identity)
            findings = []
            cutoff = when - self.window
            for identity, files in self._processes.items():
                counts = dict.fromkeys(ACTIONS, 0)
                distinct = destructive = 0
                directories = set()
                for file_id in files:
                    activity = self._files[(identity, file_id)]
                    current = {name for name, timestamp in activity.actions.items() if timestamp > cutoff}
                    if not current:
                        continue
                    distinct += 1
                    destructive += bool(current.intersection(('rinomina', 'eliminazione')))
                    for name in current:
                        counts[name] += 1
                    # Sorting only a bounded selection prevents directory
                    # summaries from growing with the number of affected files.
                    if len(directories) < 3:
                        directories.add(activity.directory)
                if distinct < self.medium:
                    continue
                severity = 'alta' if distinct >= self.high and destructive >= 20 else 'media'
                reason = (
                    f"Attività intensa sui file: {distinct} file distinti in {self.window:g} s "
                    f"({counts['modifica']} modificati, {counts['rinomina']} rinominati, "
                    f"{counts['eliminazione']} eliminati); cartelle: "
                    + ', '.join(sorted(directories))
                )
                findings.append(dict(pid=identity[0], created=identity[1], severity=severity, reasons=[reason]))
            return findings
