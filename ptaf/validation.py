"""Closed-loop detection validation.

For each applicable canary: run it, collect the host's own process telemetry,
attribute the resulting events to the canary (by process ancestry), evaluate
every applicable rule against them, and report whether a rule covering the
canary's ATT&CK technique actually fired.

Statuses
--------
detected       a rule mapped to the technique fired on the canary's telemetry
missed         telemetry was seen but no mapped rule fired  -> a real detection gap
no_telemetry   the collector saw nothing; this is a sensor problem, not a rule gap
error          the canary could not be launched
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 - canary argv comes only from canaries.py
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canaries import Canary, canaries_for, new_marker, skipped_for_sensor
from .collector import Event
from .sensor import make_collector
from .platform_info import HostInfo
from .sigma_lite import Rule, UnsupportedRule

# The rules ship INSIDE the package, so every install method (pip, the Kali installer, the
# frozen executable, a source checkout) finds them. A packaging bug here once shipped agents
# with zero rules; tests/test_packaging.py now guards it.
DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "rules"


def load_rules(rules_dir: Path | None = None) -> tuple[list[Rule], list[str]]:
    """Load every ``*.yml``/``*.yaml`` rule; return (rules, error messages)."""
    root = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
    rules: list[Rule] = []
    errors: list[str] = []
    for path in sorted([*root.rglob("*.yml"), *root.rglob("*.yaml")]):
        try:
            rules.append(Rule.from_yaml(path.read_text(encoding="utf-8"), str(path)))
        except Exception as exc:  # noqa: BLE001 - one bad rule file must never stop the agent
            errors.append(f"{path.name}: {type(exc).__name__}: {str(exc).splitlines()[0][:160]}")
    return rules, errors


class EventBuffer:
    """Thread-safe append-only event list shared by collector and validator."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[Event] = []

    def add(self, event: Event) -> None:
        with self._lock:
            self._events.append(event)

    def mark(self) -> int:
        with self._lock:
            return len(self._events)

    def since(self, mark: int) -> list[Event]:
        with self._lock:
            return list(self._events[mark:])


def descendants(events: list[Event], root_pid: int) -> list[Event]:
    """Events for ``root_pid`` and every process descended from it."""
    family = {root_pid}
    changed = True
    while changed:
        changed = False
        for ev in events:
            if ev["ProcessId"] in family:
                continue
            # AncestorPids (event-driven sensor) bridges fork-only intermediates, such as a
            # shell subshell, that never exec()d and so never produced an event of their own.
            if ev["ParentProcessId"] in family or any(
                a in family for a in ev.get("AncestorPids", ())
            ):
                family.add(ev["ProcessId"])
                changed = True
    return [ev for ev in events if ev["ProcessId"] in family]


def _base_technique(technique_id: str) -> str:
    return technique_id.split(".")[0]


def rule_covers(rule: Rule, technique_id: str) -> bool:
    wanted = technique_id.upper()
    return any(
        t == wanted or (_base_technique(t) == wanted) or (_base_technique(wanted) == t)
        for t in rule.technique_ids
    )


@dataclass
class CanaryResult:
    canary_id: str
    technique_id: str
    name: str
    status: str
    rules_fired: list[str] = field(default_factory=list)
    events_observed: int = 0
    detail: str = ""
    duration_s: float = 0.0


@dataclass
class SelfTestReport:
    host: dict[str, Any]
    started: str
    results: list[CanaryResult]
    rules_loaded: int
    rule_errors: list[str]
    sensor: dict[str, Any] | None = None  # which collector produced the telemetry, and why
    skipped: list[dict[str, str]] = field(default_factory=list)  # canaries held back, with reason

    @property
    def coverage(self) -> float | None:
        """Share of *testable* canaries that were detected; None if none ran."""
        testable = [r for r in self.results if r.status in {"detected", "missed"}]
        if not testable:
            return None
        return round(100 * sum(r.status == "detected" for r in testable) / len(testable), 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "started": self.started,
            "coverage_percent": self.coverage,
            "rules_loaded": self.rules_loaded,
            "rule_errors": self.rule_errors,
            "sensor": self.sensor,
            "skipped": self.skipped,
            "results": [asdict(r) for r in self.results],
        }


def _run_canary_once(
    canary: Canary,
    rules: list[Rule],
    host: HostInfo,
    buffer: EventBuffer,
    settle: float = 0.4,
    timeout: float = 30.0,
    synthetic_pids: set[int] | None = None,
) -> CanaryResult:
    marker = new_marker()
    argv = canary.build_argv(marker)
    base = CanaryResult(canary.id, canary.technique_id, canary.name, "error")
    start = time.monotonic()
    mark = buffer.mark()
    try:
        proc = subprocess.Popen(  # nosec B603 - fixed benign argv, no shell=True
            argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
            env=child_env(),
        )  # fmt: skip
    except OSError as exc:
        base.detail = f"could not launch canary: {exc}"
        return base
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        base.detail = f"canary exceeded {timeout}s and was killed"
        return base
    time.sleep(settle)  # let the collector catch up

    events = descendants(buffer.since(mark), proc.pid)
    if synthetic_pids is not None:
        synthetic_pids.update(ev["ProcessId"] for ev in events)
    base.duration_s = round(time.monotonic() - start, 2)
    base.events_observed = len(events)
    if not events:
        base.status = "no_telemetry"
        # Say whether the tool even ran: a tool that failed to start (exit 126/127, a library error)
        # looks identical to a blind sensor unless the exit code is reported.
        base.detail = (
            "collector observed no events for the canary (sensor gap); "
            f"the process exited with code {proc.returncode} after {base.duration_s}s"
        )
        return base

    fired: list[str] = []
    for rule in rules:
        if not rule.applies_to(host.os):
            continue
        try:
            if any(rule.matches(ev) for ev in events):
                fired.append(rule.title)
                if rule_covers(rule, canary.technique_id):
                    base.status = "detected"
        except UnsupportedRule as exc:
            base.detail += f"[{rule.title}: {exc}] "
    base.rules_fired = fired
    if base.status != "detected":
        base.status = "missed"
        seen = "; ".join(
            f"{Path(ev['Image'] or '?').name}: {ev['CommandLine'][:70]}" for ev in events[:8]
        )
        base.detail += (
            "no rule mapped to this technique fired on the canary's telemetry. "
            f"Observed {len(events)} process(es): {seen}"
        )
    return base


def child_env() -> dict[str, str]:
    """Environment for programs PTAF launches (canaries, probes).

    A PyInstaller app points ``LD_LIBRARY_PATH`` at its own bundled libraries, and every child process
    inherits it. System tools such as tcpdump or nmap then load incompatible libraries and die at start
    with exit status 127 (found by the release dry run: the packaged Linux app silently failed every
    external-tool canary). Give children the library path the app was started with.
    """
    env = dict(os.environ)
    if getattr(sys, "frozen", False):
        for var in ("LD_LIBRARY_PATH", "LIBPATH", "DYLD_LIBRARY_PATH"):
            original = env.get(var + "_ORIG")
            if original is not None:
                env[var] = original
            else:
                env.pop(var, None)  # it was set by the bundle, not by the user
    return env


RACE_RETRIES = 3  # extra attempts for a lost read-after-event race (see run_canary)


def run_canary(
    canary: Canary,
    rules: list[Rule],
    host: HostInfo,
    buffer: EventBuffer,
    retries: int = 1,
    **kwargs: Any,
) -> CanaryResult:
    """Run a canary, re-running results that can be a fluke before believing them.

    * ``missed``: a genuine detection gap is deterministic and misses every time; a sensor race does
      not. One retry; a retry-only success is reported as ``detected`` with that stated in ``detail``.
    * ``no_telemetry`` for a canary that needs the event-driven sensor: those tools live only a few
      milliseconds, and the sensor reads the command line AFTER the kernel announces the exec, so it
      sometimes loses the race to a process that has already exited (measured: fine for ~30 ms
      processes, hopeless for ~1 ms ones). The loss is random, so up to ``RACE_RETRIES`` more attempts
      are made. A sensor that is genuinely blind still ends as ``no_telemetry``: the retries never
      turn a real gap into a pass, they only stop a coin-flip from raising a false alarm.
    """
    result = _run_canary_once(canary, rules, host, buffer, **kwargs)
    missed_left = retries
    race_left = RACE_RETRIES if canary.min_sensor == "event" else 0
    first_note = ""
    while result.status != "detected":
        if result.status == "missed" and missed_left > 0:
            missed_left -= 1
        elif result.status == "no_telemetry" and race_left > 0:
            race_left -= 1
        else:
            break
        first_note = first_note or result.detail
        result = _run_canary_once(canary, rules, host, buffer, **kwargs)
        if result.status == "detected":
            result.detail = (
                "detected only on retry; an earlier attempt "
                + (
                    "lost the race to a very short-lived process"
                    if "sensor gap" in first_note
                    else "missed"
                )
                + f". First attempt: {first_note}"
            )
    return result


def run_selftest(
    rules: list[Rule],
    rule_errors: list[str],
    host: HostInfo,
    buffer: EventBuffer | None = None,
    canaries: list[Canary] | None = None,
    synthetic_pids: set[int] | None = None,
    only: tuple[str, ...] = (),
    skip: tuple[str, ...] = (),
    collector_mode: str = "auto",
    sensor_info: dict[str, Any] | None = None,
) -> SelfTestReport:
    """Run the canaries for this OS.

    With no ``buffer`` it starts its own sensor (chosen by ``collector_mode``) and records which
    one in the report. Canaries that need the event-driven sensor are skipped, with a stated
    reason, when only the polling sensor is available: a gap is never blamed on the rules for
    what is really a sensor limitation.
    """
    own_collector: Any = None
    if buffer is None:
        buffer = EventBuffer()
        own_collector, name, note = make_collector(buffer.add, collector_mode)
        sensor_info = {
            "name": name,
            "note": note,
            "kind": "event" if name == "procconn" else "poll",
        }
        own_collector.start()
    kind = (sensor_info or {}).get("kind")
    skipped: list[dict[str, str]] = []
    if canaries is None:
        canaries = canaries_for(host.os, only=only, skip=skip, sensor=kind)
        if kind:
            skipped = [
                {"id": c.id, "reason": "needs the event-driven sensor (run as root on Linux)"}
                for c in skipped_for_sensor(host.os, kind)
                if (not only or c.id in only) and c.id not in skip
            ]
    try:
        results = [
            run_canary(c, rules, host, buffer, synthetic_pids=synthetic_pids) for c in canaries
        ]
    finally:
        if own_collector:
            own_collector.stop()
    return SelfTestReport(
        host=host.to_dict(),
        started=datetime.now(timezone.utc).isoformat(),
        results=results,
        rules_loaded=len(rules),
        rule_errors=rule_errors,
        sensor=sensor_info,
        skipped=skipped,
    )
