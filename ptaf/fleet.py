"""Organization-wide view: merge exported host summaries into one fleet picture.

There is deliberately no central server and no inbound network listener on endpoints. Each agent
exports a summary (``ptaf export summary > <host>.json``); you gather them in a folder by
whatever mechanism you already trust (file share, config management, object storage) and point
the dashboard at it with ``--fleet DIR``.

Those files are UNTRUSTED input. Only whitelisted fields are read, sizes and counts are capped,
and every value is coerced and truncated, so a hostile or corrupt file can skip itself but cannot
inject markup, exhaust memory or crash the dashboard.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .status import health_from_age

MAX_FILE_BYTES = 5_000_000
MAX_HOSTS = 2000
MAX_RESULTS_PER_HOST = 60
ALLOWED_STATUS = {"detected", "missed", "no_telemetry", "error"}
KNOWN_OS = {"windows", "linux", "macos"}
_TECH = re.compile(r"^T\d{4}(\.\d{3})?$")
#: Higher = worse. A technique is shown as the worst status seen on any host.
_SEVERITY = {"detected": 0, "error": 1, "no_telemetry": 1, "missed": 2}


def _text(value: Any, limit: int) -> str:
    return "" if value is None else str(value)[:limit]


def _ts(value: Any) -> float | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _read_host(path: Path, now: float) -> dict[str, Any]:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("file too large")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("host"), dict):
        raise ValueError("not a PTAF summary")
    host = data["host"]
    latest = data.get("latest") if isinstance(data.get("latest"), dict) else {}
    results: dict[str, str] = {}
    names: dict[str, str] = {}
    for r in (latest.get("results") or [])[:MAX_RESULTS_PER_HOST]:
        if not isinstance(r, dict):
            continue
        tid, status = _text(r.get("technique_id"), 12), _text(r.get("status"), 20)
        if _TECH.match(tid) and status in ALLOWED_STATUS:
            if _SEVERITY[status] >= _SEVERITY.get(results.get(tid, "detected"), 0):
                results[tid] = status
            names.setdefault(tid, _text(r.get("name"), 80))
    cov = latest.get("coverage_percent")
    coverage = float(cov) if isinstance(cov, (int, float)) and 0 <= cov <= 100 else None
    generated = _ts(data.get("generated")) or path.stat().st_mtime
    age = max(0.0, now - generated)
    agent = data.get("agent") if isinstance(data.get("agent"), dict) else {}
    # A snapshot nobody refreshed is itself a finding: the host stopped reporting.
    health = health_from_age(age) if agent.get("health") in ("online", "stale") else "offline"
    if agent.get("health") in ("online", "stale"):
        health = "online" if age <= 15 * 60 else "stale" if age <= 6 * 3600 else "offline"
    elif agent.get("health") == "never":
        health = "never"
    os_name = _text(host.get("os"), 10).lower()
    return {
        "name": _text(host.get("hostname"), 80) or path.stem[:80],
        "os": os_name if os_name in KNOWN_OS else "unknown",
        "virtualization": _text(host.get("virtualization"), 40) or "unknown",
        "container": _text(host.get("container"), 20) or None,
        "coverage": coverage,
        "health": health,
        "age_s": round(age),
        "last_check": _text(latest.get("started"), 40) or None,
        "detected": sum(v == "detected" for v in results.values()),
        "gaps": sum(v == "missed" for v in results.values()),
        "blind": sum(v in {"no_telemetry", "error"} for v in results.values()),
        "techniques": results,
        "_names": names,
    }


def load_fleet(directory: Path, now: float | None = None) -> dict[str, Any]:
    now = now if now is not None else datetime.now(timezone.utc).timestamp()
    hosts: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    files = sorted(Path(directory).glob("*.json"))
    for path in files[:MAX_HOSTS]:
        try:
            hosts.append(_read_host(path, now))
        except (OSError, ValueError, TypeError, KeyError) as exc:
            skipped.append({"file": path.name[:80], "reason": _text(exc, 120)})
    if len(files) > MAX_HOSTS:
        skipped.append({"file": "*", "reason": f"only the first {MAX_HOSTS} files were read"})

    matrix: dict[str, dict[str, Any]] = {}
    for h in hosts:
        for tid, status in h["techniques"].items():
            cell = matrix.setdefault(
                tid,
                {"technique_id": tid, "name": h["_names"].get(tid, ""), "hosts": 0,
                 "detected": 0, "missed": 0, "blind": 0, "status": "detected"},
            )  # fmt: skip
            cell["hosts"] += 1
            key = (
                "detected" if status == "detected" else "missed" if status == "missed" else "blind"
            )
            cell[key] += 1
            if _SEVERITY[status] > _SEVERITY[cell["status"]]:
                cell["status"] = status
    for h in hosts:
        h.pop("_names", None)

    covs = [h["coverage"] for h in hosts if h["coverage"] is not None]
    by = lambda key: {  # noqa: E731 - tiny local helper
        v: sum(1 for h in hosts if h[key] == v) for v in sorted({h[key] for h in hosts})
    }
    return {
        "hosts": hosts,
        "matrix": sorted(matrix.values(), key=lambda c: c["technique_id"]),
        "rollup": {
            "hosts": len(hosts),
            "online": sum(h["health"] == "online" for h in hosts),
            "stale": sum(h["health"] == "stale" for h in hosts),
            "offline": sum(h["health"] in ("offline", "never") for h in hosts),
            "with_gaps": sum(h["gaps"] > 0 for h in hosts),
            "avg_coverage": round(sum(covs) / len(covs), 1) if covs else None,
            "by_os": by("os"),
            "by_virtualization": by("virtualization"),
        },
        "skipped": skipped,
    }
