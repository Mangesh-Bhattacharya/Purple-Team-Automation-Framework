"""Agent heartbeat: lets a dashboard answer "is the tool actually running?".

The monitor rewrites ``status.json`` every few seconds. A reader never trusts the file blindly:
health is derived from heartbeat age AND whether the recorded process still exists, so a crashed
agent shows as offline even if its last heartbeat was recent.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from . import state

HEARTBEAT_S = 5.0
ONLINE_WITHIN_S = 3 * HEARTBEAT_S  # a couple of missed beats is still "online"
STALE_WITHIN_S = 60.0  # beyond this the agent is considered offline


def status_path() -> Path:
    return state.state_dir() / "status.json"


def write_status(data: dict[str, Any]) -> None:
    """Atomic write so a reader never sees a half-written file."""
    path = status_path()
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, path)


def read_status() -> dict[str, Any] | None:
    try:
        data = json.loads(status_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _parse(ts: Any) -> float | None:
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def health_from_age(age_s: float | None) -> str:
    if age_s is None:
        return "never"
    if age_s <= ONLINE_WITHIN_S:
        return "online"
    if age_s <= STALE_WITHIN_S:
        return "stale"
    return "offline"


def agent_summary(status: dict[str, Any] | None, now: float | None = None) -> dict[str, Any]:
    """Dashboard-ready view of the agent. ``health``: online | stale | offline | never."""
    now = now if now is not None else datetime.now(timezone.utc).timestamp()
    if not status:
        return {"health": "never", "state": "not started", "heartbeat": None, "age_s": None}
    beat = _parse(status.get("heartbeat"))
    age = None if beat is None else max(0.0, now - beat)
    health = health_from_age(age)
    pid = status.get("pid")
    if status.get("state") == "stopped":
        health = "offline"  # clean shutdown
    elif isinstance(pid, int) and health != "never" and not psutil.pid_exists(pid):
        health = "offline"  # process is gone: crashed or killed
    started = _parse(status.get("started"))
    return {
        "health": health,
        "state": str(status.get("state", "unknown")),
        "pid": pid if isinstance(pid, int) else None,
        "version": str(status.get("version", "")),
        "heartbeat": status.get("heartbeat"),
        "age_s": None if age is None else round(age, 1),
        "started": status.get("started"),
        "uptime_s": None if started is None or health == "offline" else round(now - started),
        "interval_s": status.get("interval_s"),
        "last_selftest": status.get("last_selftest"),
        "next_selftest": status.get("next_selftest"),
        "collector": status.get("collector") or {},
        "alerts": status.get("alerts") or {},
        "canaries_enabled": status.get("canaries_enabled"),
    }
