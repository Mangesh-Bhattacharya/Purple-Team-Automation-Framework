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

# Seconds during which a new process is re-inspected for an exec() that changed its identity.
RECHECK_WINDOW = 3.0


def _signature(event: "Event | None") -> tuple[str, str] | None:
    return (event["Image"], event["CommandLine"]) if event else None


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
            try:
                parent_cmd = " ".join(parent.cmdline()) if parent else ""
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                parent_cmd = ""
            try:
                cwd = proc.cwd()
            except (psutil.AccessDenied, OSError):
                cwd = ""
            return {
                "EventType": "process_creation",
                "UtcTime": datetime.now(timezone.utc).isoformat(),
                "ProcessId": proc.pid,
                "ParentProcessId": proc.ppid(),
                "Image": image,
                "CommandLine": " ".join(cmdline),
                "ParentImage": parent_image,
                "ParentCommandLine": parent_cmd,
                "CurrentDirectory": cwd,
                "User": user,
            }
    except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
        return None


class ProcessCollector:
    """Polls the process table and invokes ``callback`` once per new process."""

    def __init__(self, callback: Callable[[Event], None], interval: float = 0.05) -> None:
        self._callback = callback
        self._interval = interval
        # key -> (first_seen_monotonic, (Image, CommandLine)); see RECHECK_WINDOW
        self._seen: dict[tuple[int, float], tuple[float, tuple[str, str] | None]] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.errors = 0  # exceptions survived (callback or scan); non-zero deserves attention
        self.last_error: str | None = None
        self.scans = 0

    def _scan(self, emit: bool) -> None:
        now = time.monotonic()
        live: set[tuple[int, float]] = set()
        for proc in psutil.process_iter():
            try:
                key = (proc.pid, proc.create_time())
            except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
                continue
            live.add(key)
            known = self._seen.get(key)
            if known is None:
                event = _event_from_process(proc) if emit else None
                # Baseline processes get an ancient first-seen so they are never re-checked.
                self._seen[key] = (now if emit else -1e9, _signature(event))
                if event is not None:
                    self._emit(event)
                continue
            first_seen, signature = known
            if now - first_seen > RECHECK_WINDOW:
                continue
            # A young process may have been snapshotted between fork() and exec(), when its
            # command line is still the parent's. Re-check and report if it changed.
            event = _event_from_process(proc)
            if event is not None and _signature(event) != signature:
                self._seen[key] = (first_seen, _signature(event))
                self._emit(event)
        # Forget exited processes. Without this the table grows by one entry per process
        # forever, an unbounded leak in a long-running agent.
        for stale in [k for k in self._seen if k not in live]:
            del self._seen[stale]
        self.scans += 1

    def _emit(self, event: Event) -> None:
        try:
            self._callback(event)
        except Exception as exc:  # noqa: BLE001 - one bad event must never kill the sensor
            self._record_error(exc)

    def _record_error(self, exc: Exception) -> None:
        self.errors += 1
        self.last_error = f"{type(exc).__name__}: {exc}"

    def start(self) -> None:
        self._scan(emit=False)  # baseline: ignore processes that already exist
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="ptaf-collector", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._scan(emit=True)
            except Exception as exc:  # noqa: BLE001 - keep the sensor alive across odd OS states
                self._record_error(exc)
            time.sleep(self._interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
