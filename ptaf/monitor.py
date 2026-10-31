"""Long-running monitor: live rule evaluation + scheduled detection self-tests.

One collector feeds a shared buffer. Every event is evaluated live against all
applicable rules (alerts -> ``alerts.jsonl``). On a schedule, canaries run
through the same pipeline and the result is compared with the previous run to
raise ``detection_drift`` alerts. Events produced by canaries are written with
``"synthetic": true`` so they never pollute real alert counts.
"""

from __future__ import annotations

import json
import os
import signal
import threading
from datetime import datetime, timezone
from typing import Any

from . import state
from .collector import Event
from . import status
from . import __version__
from .exports import badge, navigator_layer
from .platform_info import HostInfo
from .sigma_lite import Rule, UnsupportedRule
from .sensor import make_collector
from .validation import EventBuffer, run_selftest


class Monitor:
    def __init__(
        self,
        rules: list[Rule],
        rule_errors: list[str],
        host: HostInfo,
        interval_s: float = 3600.0,
        emit_stdout: bool = True,
        only: tuple[str, ...] = (),
        skip: tuple[str, ...] = (),
        collector_mode: str = "auto",
    ) -> None:
        self.rules = [r for r in rules if r.applies_to(host.os)]
        self.all_rules = rules
        self.rule_errors = rule_errors
        self.host = host
        self.interval_s = interval_s
        self.emit_stdout = emit_stdout
        self.only = only
        self.skip = skip
        self.started = datetime.now(timezone.utc).isoformat()
        self.state_name = "starting"
        self.last_selftest: str | None = None
        self.next_selftest: str | None = None
        self.events_seen = 0
        self.alerts_real = 0
        self.alerts_synthetic = 0
        self.canaries_enabled: int | None = None
        self.buffer = EventBuffer()
        self._pending: list[tuple[Event, list[Rule]]] = []
        self._holding = False
        self._lock = threading.Lock()
        self._stop = threading.Event()
        # May raise SensorUnavailable if a specific collector was demanded but cannot run.
        self._collector, name, note = make_collector(self._on_event, collector_mode)
        self.sensor = {
            "name": name, "note": note, "kind": "event" if name == "procconn" else "poll",
        }  # fmt: skip

    # -- live path ---------------------------------------------------------
    def _on_event(self, event: Event) -> None:
        self.events_seen += 1
        self.buffer.add(event)
        hits = []
        for rule in self.rules:
            try:
                if rule.matches(event):
                    hits.append(rule)
            except UnsupportedRule:
                continue
        if not hits:
            return
        with self._lock:
            if self._holding:
                self._pending.append((event, hits))
                return
        self._write_alerts(event, hits, synthetic=False)

    def _write_alerts(self, event: Event, hits: list[Rule], synthetic: bool) -> None:
        for rule in hits:
            if synthetic:
                self.alerts_synthetic += 1
            else:
                self.alerts_real += 1
            self._emit(
                {
                    "type": "detection",
                    "synthetic": synthetic,
                    "rule": rule.title,
                    "level": rule.level,
                    "techniques": rule.technique_ids,
                    "host": self.host.hostname,
                    "image": event["Image"],
                    "command_line": event["CommandLine"],
                    "time": event["UtcTime"],
                }
            )

    def _emit(self, record: dict[str, Any]) -> None:
        state.append_jsonl("alerts.jsonl", record)
        if self.emit_stdout:
            print(json.dumps(record), flush=True)

    # -- scheduled path ----------------------------------------------------
    def run_selftest_now(self) -> None:
        self.state_name = "testing"
        self._write_status()
        with self._lock:
            self._holding = True
        try:
            previous = state.load_previous()
            synthetic: set[int] = set()
            report = run_selftest(
                self.all_rules,
                self.rule_errors,
                self.host,
                self.buffer,
                synthetic_pids=synthetic,
                only=self.only,
                skip=self.skip,
                sensor_info=self.sensor,
            )
        finally:
            with self._lock:
                self._holding = False
                pending, self._pending = self._pending, []
        for event, hits in pending:
            self._write_alerts(event, hits, synthetic=event["ProcessId"] in synthetic)
        for item in state.compute_drift(previous, report):
            item.update(host=self.host.hostname, time=datetime.now(timezone.utc).isoformat())
            self._emit(item)
        state.save(report)
        (state.state_dir() / "badge.json").write_text(
            json.dumps(badge(report), indent=2), encoding="utf-8"
        )
        (state.state_dir() / "navigator_layer.json").write_text(
            json.dumps(navigator_layer(report, self.all_rules), indent=2), encoding="utf-8"
        )
        self._emit(
            {
                "type": "selftest",
                "coverage_percent": report.coverage,
                "host": self.host.hostname,
                "time": report.started,
            }
        )
        self.canaries_enabled = len(report.results)
        self.last_selftest = report.started
        self.next_selftest = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() + self.interval_s, timezone.utc
        ).isoformat()
        self.state_name = "idle"
        self._write_status()

    # -- heartbeat ---------------------------------------------------------
    def _write_status(self) -> None:
        """Publish a heartbeat so a dashboard can tell whether the agent is really running."""
        c = self._collector
        try:
            status.write_status(
                {
                    "pid": os.getpid(),
                    "version": __version__,
                    "state": self.state_name,
                    "started": self.started,
                    "heartbeat": datetime.now(timezone.utc).isoformat(),
                    "interval_s": self.interval_s,
                    "last_selftest": self.last_selftest,
                    "next_selftest": self.next_selftest,
                    "canaries_enabled": self.canaries_enabled,
                    "alerts": {"real": self.alerts_real, "synthetic": self.alerts_synthetic},
                    "collector": {
                        **self.sensor,
                        "events_seen": self.events_seen,
                        "scans": getattr(c, "scans", 0),
                        "errors": getattr(c, "errors", 0),
                        "last_error": getattr(c, "last_error", None),
                        "exec_events": getattr(c, "exec_events", None),
                        "missed": getattr(c, "missed", None),
                        "dropped": getattr(c, "dropped", None),
                    },
                }
            )
        except OSError:
            pass  # a full or read-only disk must never take the sensor down

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(status.HEARTBEAT_S):
            self._write_status()

    # -- lifecycle ---------------------------------------------------------
    def stop(self, *_: Any) -> None:
        self._stop.set()

    def run(self, run_once: bool = False) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self.stop)
            except ValueError:  # not in main thread
                pass
        lock = state.acquire_lock()
        self._collector.start()
        self._emit(
            {
                "type": "agent_start",
                "version": __version__,
                "host": self.host.hostname,
                "sensor": self.sensor,
                "time": self.started,
            }
        )
        beat = threading.Thread(target=self._heartbeat_loop, name="ptaf-heartbeat", daemon=True)
        beat.start()
        try:
            self.run_selftest_now()
            while not run_once and not self._stop.wait(self.interval_s):
                self.run_selftest_now()
        finally:
            self._stop.set()
            self._collector.stop()
            self.state_name = "stopped"
            self._write_status()
            state.release_lock(lock)
