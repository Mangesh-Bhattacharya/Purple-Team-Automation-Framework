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


def state_dir() -> Path:
    base = Path(os.environ.get("PTAF_HOME") or Path.home() / ".ptaf")
    base.mkdir(parents=True, exist_ok=True)
    return base


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
    with (state_dir() / "history.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(report.to_dict()) + "\n")


def append_jsonl(name: str, record: dict[str, Any]) -> None:
    with (state_dir() / name).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
