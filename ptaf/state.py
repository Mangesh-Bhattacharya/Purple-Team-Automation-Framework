"""Persistent state and detection-drift computation.

Drift = a canary that was ``detected`` on the previous run and is now not.
That is the signal that a rule was edited, a log pipeline broke, a sensor was
disabled or an EDR update changed behaviour -- the failure mode normal
alerting can never show you, because a broken detection is silent.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .validation import SelfTestReport

MAX_LOG_BYTES = 10 * 1024 * 1024  # rotate a JSONL log once it passes this size
KEEP_ROTATED = 3  # alerts.jsonl.1 .. .3 are kept; older ones are deleted


def state_dir() -> Path:
    """State lives in ~/.ptaf (or $PTAF_HOME). Alerts contain command lines, which can hold
    secrets, so on POSIX the directory is private to the owning user (0700)."""
    base = Path(os.environ.get("PTAF_HOME") or Path.home() / ".ptaf")
    base.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            base.chmod(0o700)
        except OSError:
            pass  # e.g. a directory we do not own; doctor reports it
    return base


def _rotate(path: Path) -> None:
    """Cap disk use of an append-only log: path -> path.1 -> .2 -> .3, oldest dropped."""
    try:
        if path.stat().st_size < MAX_LOG_BYTES:
            return
    except OSError:
        return
    for i in range(KEEP_ROTATED, 0, -1):
        older = path.with_name(f"{path.name}.{i}")
        newer = path if i == 1 else path.with_name(f"{path.name}.{i - 1}")
        try:
            if newer.exists():
                if older.exists():
                    older.unlink()
                newer.replace(older)
        except OSError:
            return


def _state_file() -> Path:
    return state_dir() / "state.json"


def load_previous() -> dict[str, str]:
    try:
        data = json.loads(_state_file().read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in data.get("statuses", {}).items()}
    except (OSError, ValueError):
        return {}


def compute_drift(previous: dict[str, str], report: SelfTestReport) -> list[dict[str, Any]]:
    drift = []
    for result in report.results:
        before = previous.get(result.canary_id)
        if before == "detected" and result.status != "detected":
            drift.append(
                {
                    "type": "detection_drift",
                    "canary_id": result.canary_id,
                    "technique_id": result.technique_id,
                    "from": before,
                    "to": result.status,
                    "severity": "high" if result.status == "missed" else "medium",
                    "detail": result.detail,
                }
            )
    return drift


def save(report: SelfTestReport) -> None:
    payload = {
        "updated": report.started,
        "statuses": {r.canary_id: r.status for r in report.results},
    }
    _state_file().write_text(json.dumps(payload, indent=2), encoding="utf-8")
    history = state_dir() / "history.jsonl"
    _rotate(history)
    with history.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(report.to_dict()) + "\n")


def append_jsonl(name: str, record: dict[str, Any]) -> None:
    path = state_dir() / name
    _rotate(path)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


class AlreadyRunning(RuntimeError):
    """Another monitor already holds the lock for this state directory."""


def acquire_lock(name: str = "monitor.lock") -> Path:
    """Single-instance guard so two agents cannot double-alert or corrupt state.

    A stale lock (its process is gone) is taken over; a live one raises AlreadyRunning.
    """
    import psutil

    lock = state_dir() / name
    try:
        holder = int(lock.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        holder = None
    if holder and holder != os.getpid() and psutil.pid_exists(holder):
        raise AlreadyRunning(f"another PTAF monitor is running (pid {holder})")
    lock.write_text(str(os.getpid()), encoding="utf-8")
    return lock


def release_lock(lock: Path) -> None:
    try:
        if lock.read_text(encoding="utf-8").strip() == str(os.getpid()):
            lock.unlink()
    except OSError:
        pass
