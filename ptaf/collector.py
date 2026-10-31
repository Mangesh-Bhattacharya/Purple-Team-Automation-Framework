"""Cross-platform process-creation collector (psutil polling).

This is the zero-privilege baseline collector: it works unmodified on Windows,
macOS, Linux and inside VMs/containers, with no kernel driver or admin rights.
Trade-off: polling can miss processes that live shorter than ``interval``.
Native collectors (Sysmon, auditd, Endpoint Security) should implement the same
``Collector`` interface and emit the same event dicts.

Events use Sigma/Sysmon field names (``Image``, ``CommandLine``, ``ParentImage``,
``User``) so rules written for real telemetry evaluate unchanged.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

import psutil

Event = dict[str, Any]


def _event_from_process(proc: psutil.Process) -> Event | None:
    try:
        with proc.oneshot():
            cmdline = proc.cmdline()
            try:
                image = proc.exe() or (cmdline[0] if cmdline else proc.name())
            except (psutil.AccessDenied, OSError):
                image = cmdline[0] if cmdline else proc.name()
            parent = proc.parent()
            try:
                parent_image = parent.exe() if parent else ""
            except (psutil.AccessDenied, OSError):
                parent_image = parent.name() if parent else ""
            try:
                user = proc.username()
            except (psutil.AccessDenied, KeyError, OSError):
                user = ""
            return {
                "EventType": "process_creation",
                "UtcTime": datetime.now(timezone.utc).isoformat(),
                "ProcessId": proc.pid,
                "ParentProcessId": proc.ppid(),
                "Image": image,
                "CommandLine": " ".join(cmdline),
                "ParentImage": parent_image,
                "User": user,
            }
    except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
        return None


class ProcessCollector:
    """Polls the process table and invokes ``callback`` once per new process."""

    def __init__(self, callback: Callable[[Event], None], interval: float = 0.05) -> None:
        self._callback = callback
        self._interval = interval
        self._seen: set[tuple[int, float]] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _scan(self, emit: bool) -> None:
        for proc in psutil.process_iter():
            try:
                key = (proc.pid, proc.create_time())
            except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
                continue
            if key in self._seen:
                continue
            self._seen.add(key)
            if not emit:
                continue
            event = _event_from_process(proc)
            if event is not None:
                self._callback(event)

    def start(self) -> None:
        self._scan(emit=False)  # baseline: ignore processes that already exist
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="ptaf-collector", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._scan(emit=True)
            time.sleep(self._interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
