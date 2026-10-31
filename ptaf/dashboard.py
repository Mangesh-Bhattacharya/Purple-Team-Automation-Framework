# flake8: noqa: E501  (the demo-data tables below are deliberately one record per line)
"""Client/organization dashboard: live local server, token-protected LAN server, or a snapshot.

What it answers, in plain language: Is the tool running? Is it protecting us? What changed?
What do I need to do? Plus, for organizations, the same across many machines (--fleet).

Security posture
----------------
* Binds to 127.0.0.1 by default. Beyond loopback a token is REQUIRED (the CLI enforces it); the
  token travels in a header and is read from the URL *fragment*, which browsers never send to
  servers or put in access logs.
* Read-only: GET/HEAD only, fixed routes, URL paths never map to files.
* Alert fields (command lines, image paths) and fleet files come from outside the dashboard and
  are treated as attacker-controlled: the page renders them with ``textContent`` only, and a strict
  CSP forbids external network access.
"""

from __future__ import annotations

import hmac
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import __version__, state, status
from .agents import run_agents
from .doctor import run_checks
from .fleet import load_fleet
from .platform_info import collect_host_info
from .validation import load_rules

TEMPLATE = Path(__file__).with_name("dashboard.html")
LAB_JS = Path(__file__).with_name("lab.js")

EXPLAIN = {
    "detected": {
        "label": "Protected",
        "meaning": "We safely imitated this attacker behavior and your detection caught it.",
        "action": "No action needed. This is re-checked automatically.",
    },
    "missed": {
        "label": "Gap",
        "meaning": "We imitated this behavior and nothing alerted. An attacker could go unseen.",
        "action": "Add or fix a detection rule for this technique, then re-run the self-test.",
    },
    "no_telemetry": {
        "label": "Blind spot",
        "meaning": "The sensor did not record the test at all, so we cannot say you are covered.",
        "action": "Check that logging or the sensor is running on this machine.",
    },
    "error": {
        "label": "Could not test",
        "meaning": "The safe test could not be launched on this machine.",
        "action": "Check permissions or security tooling that may be blocking the test.",
    },
}

LEVEL_ORDER = {"critical": 0, "warning": 1, "info": 2, "ok": 3}


def _read_jsonl(name: str, limit: int) -> list[dict[str, Any]]:
    path = state.state_dir() / name
    rows: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue  # tolerate a truncated final line
                if isinstance(row, dict):
                    rows.append(row)
    except OSError:
        return []
    return rows[-limit:]


def _ts(value: Any) -> float | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


# --- coverage matrix ------------------------------------------------------------------------
def build_matrix(latest: dict[str, Any] | None, rules: list[Any]) -> list[dict[str, Any]]:
    """One cell per technique: verified / gap / blind / unverified (a rule exists, untested)."""
    cells: dict[str, dict[str, Any]] = {}
    for rule in rules:
        for tid in rule.technique_ids:
            cells.setdefault(
                tid,
                {"technique_id": tid, "state": "unverified", "name": rule.title,
                 "detail": "A rule maps here but no canary has tested it on this machine."},
            )  # fmt: skip
    for r in (latest or {}).get("results", []):
        tid = r.get("technique_id")
        if not tid:
            continue
        status_ = r.get("status")
        new = {
            "detected": (
                "verified",
                "A canary ran and a rule fired: " + ", ".join(r.get("rules_fired") or []),
            ),
            "missed": ("gap", "A canary ran and no rule fired. This is a real detection gap."),
            "no_telemetry": ("blind", "The sensor saw nothing for this test, so it is unverified."),
            "error": ("blind", "This test could not run on this machine."),
        }.get(status_)
        if new:
            cells[tid] = {"technique_id": tid, "state": new[0], "name": r.get("name", tid),
                          "detail": new[1]}  # fmt: skip
    return sorted(cells.values(), key=lambda c: c["technique_id"])


def build_history_strips(history: list[dict[str, Any]], limit: int = 30) -> list[dict[str, Any]]:
    """Per-check timeline: one row per canary, one cell per past self-test run."""
    runs = history[-limit:]
    rows: dict[str, dict[str, Any]] = {}
    for i, run in enumerate(runs):
        for r in run.get("results", []):
            cid = str(r.get("canary_id", ""))[:60]
            row = rows.setdefault(
                cid, {"id": cid, "name": r.get("name", cid), "technique_id": r.get("technique_id"),
                      "cells": [None] * len(runs)},
            )  # fmt: skip
            row["cells"][i] = {"t": run.get("started"), "s": r.get("status")}
    return list(rows.values())


# --- "what needs my attention" --------------------------------------------------------------
_KIND_RULES = (
    ("used to be detected", "drift"),
    ("went undetected", "gap"),
    ("could not be verified", "blind"),
    ("overdue", "overdue"),
    ("agent is not running", "agent"),
    ("no agent has reported", "agent"),
    ("heartbeat", "agent"),
    ("rule files failed", "rules"),
    ("health check", "health"),
    ("sensor has been hitting", "sensor"),
    ("kernel dropped", "sensor"),
    ("polling sensor", "info"),
    ("check skipped", "info"),
    ("nothing needs", "ok"),
)


def item_kind(title: str) -> str:
    """What sort of finding this is, so the Triage agent can explain its ranking."""
    low = title.lower()
    return next((kind for needle, kind in _KIND_RULES if needle in low), "info")


def attention_items(s: dict[str, Any]) -> list[dict[str, str]]:
    """Plain-language, prioritised actions. Pure, so snapshots and tests get the same answer."""
    items: list[dict[str, str]] = []

    def add(level: str, title: str, detail: str, action: str = "") -> None:
        items.append(
            {"level": level, "title": title, "detail": detail, "action": action,
             "kind": item_kind(title)}
        )  # fmt: skip

    agent = s.get("agent") or {}
    health = agent.get("health", "never")
    if health in ("offline", "never"):
        add("critical" if health == "offline" else "warning",
            "The Sentinel agent is not running" if health == "offline" else "No agent has reported yet",
            "Detections are not being checked continuously, so a silent failure would go unnoticed."
            if health == "offline" else "Only one-off self-tests have been run on this machine.",
            "Start it with `ptaf monitor` (or install the service: `ptaf service`).")  # fmt: skip
    elif health == "stale":
        add("warning", "The agent's heartbeat is late",
            f"Last heartbeat {agent.get('age_s')} s ago; it may be stuck or overloaded.",
            "Check the machine and the agent's log output.")  # fmt: skip

    for d in (s.get("drift") or [])[-3:][::-1]:
        add("critical", f"{d.get('technique_id')} used to be detected and no longer is",
            f"It changed from {d.get('from')} to {d.get('to')}. A rule, log pipeline or sensor changed.",
            "Compare recent rule edits and sensor/agent updates, then re-run the self-test.")  # fmt: skip

    results = (s.get("latest") or {}).get("results", [])
    gaps = [r for r in results if r.get("status") == "missed"]
    if gaps:
        add("critical", f"{len(gaps)} attacker behavior(s) went undetected",
            "; ".join(f"{r['name']} ({r['technique_id']})" for r in gaps[:4]),
            "Add or fix the matching detection rule, then re-run the self-test.")  # fmt: skip
    blind = [r for r in results if r.get("status") in ("no_telemetry", "error")]
    if blind:
        add("warning", f"{len(blind)} check(s) could not be verified",
            "; ".join(r["name"] for r in blind[:4]),
            "This is a sensor problem, not a rule gap. Run `ptaf doctor` on the machine.")  # fmt: skip

    interval = agent.get("interval_s")
    last = _ts(agent.get("last_selftest") or (s.get("latest") or {}).get("started"))
    if interval and last and health in ("online", "stale"):
        late = _ts(s.get("generated")) - last if _ts(s.get("generated")) else 0
        if late > 2.5 * float(interval):
            add("warning", "Self-tests are overdue",
                f"The last check was {int(late // 60)} minutes ago; one is expected every "
                f"{int(float(interval) // 60)} minutes.", "Check that the agent is not stuck.")  # fmt: skip

    col = agent.get("collector") or {}
    if col.get("errors"):
        add("warning", "The sensor has been hitting errors",
            f"{col['errors']} error(s); last: {col.get('last_error')}",
            "Run `ptaf doctor`; the sensor keeps running but may be missing events.")  # fmt: skip
    if col.get("dropped"):
        add("warning", "The kernel dropped events under load",
            f"{col['dropped']} overflow(s) reported by the event-driven sensor.",
            "Reduce load on the machine or run fewer concurrent workloads.")  # fmt: skip
    if col.get("kind") == "poll" and (s.get("host") or {}).get("os") == "linux":
        add("info", "Using the polling sensor, which can miss very short-lived commands",
            col.get("note", ""), 'Run as root for the event-driven sensor: sudo "$(command -v ptaf)" monitor')  # fmt: skip

    for k in (s.get("latest") or {}).get("skipped", [])[:3]:
        add("info", f"Check skipped: {k.get('id')}", k.get("reason", ""))
    if (s.get("latest") or {}).get("rule_errors"):
        add("warning", "Some rule files failed to load",
            "; ".join(s["latest"]["rule_errors"][:3]), "Fix them with `ptaf rules check`.")  # fmt: skip

    for c in (s.get("health_checks") or {}).get("checks") or []:
        if c.get("status") == "fail":
            add(
                "critical",
                f"Health check failed: {c.get('name')}",
                c.get("detail", ""),
                c.get("fix", ""),
            )
        elif c.get("status") == "warn":
            add(
                "warning",
                f"Health check warning: {c.get('name')}",
                c.get("detail", ""),
                c.get("fix", ""),
            )

    if not items:
        if results:
            add(
                "ok", "Nothing needs your attention", "The agent is running and every check passed."
            )
        else:  # never claim success before a single check has run
            add(
                "info",
                "The first safe tests have not finished yet",
                "Results appear in roughly 10-20 seconds; this page updates by itself.",
            )
    items.sort(key=lambda i: LEVEL_ORDER[i["level"]])
    return items


# --- summaries ----------------------------------------------------------------------------------
def _alert_counts(alerts: list[dict[str, Any]], now: float) -> dict[str, int]:
    real = synth = 0
    for a in alerts:
        if a.get("type") != "detection":
            continue
        t = _ts(a.get("time"))
        if t is not None and now - t > 86400:
            continue
        if a.get("synthetic"):
            synth += 1
        else:
            real += 1
    return {"real_24h": real, "synthetic_24h": synth}


def _health_checks() -> dict[str, Any] | None:
    try:
        data = json.loads((state.state_dir() / "doctor.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and isinstance(data.get("checks"), list) else None


def build_summary(now: float | None = None) -> dict[str, Any]:
    now = now if now is not None else datetime.now(timezone.utc).timestamp()
    history = _read_jsonl("history.jsonl", 200)
    alerts = _read_jsonl("alerts.jsonl", 1000)
    latest = history[-1] if history else None
    rules, _errors = load_rules()
    summary: dict[str, Any] = {
        "generated": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "demo": False,
        "version": __version__,
        "host": latest["host"] if latest else collect_host_info().to_dict(),
        "agent": status.agent_summary(status.read_status(), now),
        "latest": latest,
        "trend": [{"time": h["started"], "coverage": h["coverage_percent"]} for h in history],
        "matrix": build_matrix(latest, rules),
        "history": build_history_strips(history),
        "alerts": [a for a in alerts if a.get("type") == "detection"][-200:],
        "alert_counts": _alert_counts(alerts, now),
        "drift": [a for a in alerts if a.get("type") == "detection_drift"][-20:],
        "health_checks": _health_checks(),
        "explain": EXPLAIN,
    }
    summary["attention"] = attention_items(summary)
    summary["agents"] = run_agents(summary, _rule_titles(rules))
    return summary


def _rule_titles(rules: list[Any]) -> dict[str, list[str]]:
    """technique id -> titles of the rules that claim to cover it."""
    out: dict[str, list[str]] = {}
    for rule in rules:
        for tid in rule.technique_ids:
            out.setdefault(tid, []).append(rule.title)
    return out


def demo_summary() -> dict[str, Any]:
    """Clearly-labelled sample data for screenshots, demos and README GIFs."""
    now = datetime.now(timezone.utc)
    iso = lambda dt: dt.isoformat()  # noqa: E731
    results = [
        ("win-encoded-powershell", "T1059.001", "Encoded PowerShell command line", "detected", ["Suspicious Encoded PowerShell"]),
        ("win-powershell-bypass-hidden", "T1059.001", "PowerShell with Bypass and hidden window", "detected", ["PowerShell With Bypass Policy and Hidden Window"]),
        ("win-system-discovery", "T1082", "System information discovery", "detected", ["System Information Discovery via systeminfo"]),
        ("demo-lsass", "T1003.001", "LSASS memory access attempt", "missed", []),
        ("demo-runkey", "T1547.001", "Registry run-key persistence", "no_telemetry", []),
    ]  # fmt: skip
    host = {"os": "windows", "os_version": "Windows 11 Pro", "arch": "AMD64",
            "hostname": "DEMO-WORKSTATION-07", "virtualization": "VMware", "container": None,
            "distro": None, "kali": False}  # fmt: skip
    coverage = [60.0, 60.0, 75.0, 75.0, 75.0, 100.0, 100.0, 75.0]
    runs = len(coverage)
    trend = [
        {"time": iso(now - timedelta(hours=runs - i)), "coverage": c}
        for i, c in enumerate(coverage)
    ]
    history = []
    for i in range(runs):
        history.append({"started": iso(now - timedelta(hours=runs - i)),
                        "statuses": {r[0]: ("detected" if (r[0] != "demo-lsass" or i < runs - 1) and r[3] != "no_telemetry" else r[3] if r[3] == "no_telemetry" else "missed") for r in results}})  # fmt: skip
    strips = [
        {"id": cid, "name": name, "technique_id": tid,
         "cells": [{"t": h["started"], "s": h["statuses"][cid]} for h in history]}
        for cid, tid, name, _s, _r in results
    ]  # fmt: skip
    latest = {
        "host": host, "started": iso(now - timedelta(minutes=14)), "coverage_percent": 75.0,
        "rules_loaded": 21, "rule_errors": [], "skipped": [],
        "sensor": {"name": "poll", "kind": "poll", "note": "portable polling (50 ms)"},
        "results": [{"canary_id": c, "technique_id": t, "name": n, "status": s, "rules_fired": r,
                     "events_observed": 4, "detail": "", "duration_s": 1.4} for c, t, n, s, r in results],
    }  # fmt: skip
    summary: dict[str, Any] = {
        "generated": iso(now),
        "demo": True,
        "version": __version__,
        "host": host,
        "agent": {
            "health": "online",
            "state": "idle",
            "pid": 4182,
            "version": __version__,
            "heartbeat": iso(now - timedelta(seconds=3)),
            "age_s": 3.0,
            "started": iso(now - timedelta(hours=6, minutes=12)),
            "uptime_s": 22320,
            "interval_s": 3600,
            "last_selftest": latest["started"],
            "next_selftest": iso(now + timedelta(minutes=46)),
            "collector": {
                "name": "poll",
                "kind": "poll",
                "note": "portable polling (50 ms)",
                "events_seen": 18342,
                "errors": 0,
                "scans": 428113,
            },
            "alerts": {"real": 2, "synthetic": 14},
            "canaries_enabled": 5,
        },
        "latest": latest,
        "trend": trend,
        "matrix": build_matrix(latest, [])
        + [
            {
                "technique_id": "T1140",
                "state": "unverified",
                "name": "Base64 Decode Utility Executed",
                "detail": "A rule maps here but no canary has tested it on this machine.",
            },
            {
                "technique_id": "T1574.006",
                "state": "unverified",
                "name": "Dynamic Linker Preload",
                "detail": "A rule maps here but no canary has tested it on this machine.",
            },
        ],
        "history": strips,
        "alerts": [
            {"type": "detection", "synthetic": False, "rule": "Suspicious Encoded PowerShell", "level": "medium",
             "techniques": ["T1059.001"], "host": host["hostname"], "time": iso(now - timedelta(minutes=37)),
             "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
             "command_line": "powershell.exe -enc SQBFAFgA..."},
            {"type": "detection", "synthetic": True, "rule": "Suspicious Encoded PowerShell", "level": "medium",
             "techniques": ["T1059.001"], "host": host["hostname"], "time": iso(now - timedelta(minutes=14)),
             "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
             "command_line": "powershell.exe -NoProfile -NonInteractive -EncodedCommand UwB0AGEAcgB0AC0A..."},
        ],  # fmt: skip
        "alert_counts": {"real_24h": 2, "synthetic_24h": 14},
        "drift": [{"type": "detection_drift", "technique_id": "T1003.001", "from": "detected",
                   "to": "missed", "severity": "high", "host": host["hostname"],
                   "time": iso(now - timedelta(hours=1))}],  # fmt: skip
        "health_checks": {"time": iso(now - timedelta(minutes=20)), "checks": [
            {"name": "process visibility", "status": "ok", "detail": "99.1% of 412 processes readable", "fix": ""},
            {"name": "sensor smoke test", "status": "ok", "detail": "the 'poll' sensor observed a process it started", "fix": ""},
            {"name": "rules", "status": "ok", "detail": "21 of 21 rules runnable", "fix": ""},
        ]},  # fmt: skip
        "explain": EXPLAIN,
    }
    summary["attention"] = attention_items(summary)
    summary["agents"] = run_agents(
        summary,
        {"T1059.001": ["Suspicious Encoded PowerShell"], "T1082": ["System Information Discovery"]},
    )
    return summary


def demo_fleet() -> dict[str, Any]:
    """Fictional fleet in the exact shape load_fleet() returns. Clearly labelled DEMO in the UI."""
    spec = [
        ("DEMO-WORKSTATION-07", "windows", "VMware", 75.0, "online", {"T1059.001": "detected", "T1082": "detected", "T1003.001": "missed", "T1547.001": "no_telemetry"}),
        ("DEMO-WORKSTATION-11", "windows", "none", 100.0, "online", {"T1059.001": "detected", "T1082": "detected", "T1003.001": "detected", "T1547.001": "detected"}),
        ("DEMO-SRV-DC01", "windows", "Hyper-V", 100.0, "online", {"T1059.001": "detected", "T1082": "detected", "T1003.001": "detected"}),
        ("DEMO-SRV-WEB02", "linux", "KVM/QEMU", 83.3, "online", {"T1140": "detected", "T1070.003": "missed", "T1059.006": "detected"}),
        ("DEMO-SRV-DB01", "linux", "AWS EC2", 100.0, "stale", {"T1140": "detected", "T1070.003": "detected", "T1059.006": "detected"}),
        ("DEMO-KALI-01", "linux", "VirtualBox", 100.0, "online", {"T1046": "detected", "T1110.001": "detected", "T1040": "detected", "T1190": "detected"}),
        ("DEMO-KALI-ARM", "linux", "Apple Virtualization", 66.7, "online", {"T1046": "detected", "T1110.001": "missed", "T1040": "detected"}),
        ("DEMO-MAC-DEV04", "macos", "none", 100.0, "online", {"T1140": "detected", "T1059.002": "detected", "T1574.006": "detected"}),
        ("DEMO-LAPTOP-23", "windows", "none", None, "offline", {}),
    ]  # fmt: skip
    hosts, matrix = [], {}
    for name, os_, vm, cov, health, techs in spec:
        hosts.append({"name": name, "os": os_, "virtualization": vm, "container": None, "coverage": cov,
                      "health": health, "age_s": {"online": 40, "stale": 5400, "offline": 172800}[health],
                      "last_check": None, "detected": sum(v == "detected" for v in techs.values()),
                      "gaps": sum(v == "missed" for v in techs.values()),
                      "blind": sum(v == "no_telemetry" for v in techs.values()), "techniques": techs})  # fmt: skip
        for tid, st in techs.items():
            c = matrix.setdefault(tid, {"technique_id": tid, "name": "", "hosts": 0, "detected": 0, "missed": 0, "blind": 0, "status": "detected"})  # fmt: skip
            c["hosts"] += 1
            c["detected" if st == "detected" else "missed" if st == "missed" else "blind"] += 1
            if st == "missed" or (st == "no_telemetry" and c["status"] == "detected"):
                c["status"] = st
    covs = [h["coverage"] for h in hosts if h["coverage"] is not None]

    def by(k: str) -> dict[str, int]:
        return {v: sum(1 for h in hosts if h[k] == v) for v in sorted({h[k] for h in hosts})}

    return {"demo": True, "hosts": hosts, "matrix": sorted(matrix.values(), key=lambda c: c["technique_id"]),
            "rollup": {"hosts": len(hosts), "online": sum(h["health"] == "online" for h in hosts),
                       "stale": sum(h["health"] == "stale" for h in hosts),
                       "offline": sum(h["health"] == "offline" for h in hosts),
                       "with_gaps": sum(h["gaps"] > 0 for h in hosts),
                       "avg_coverage": round(sum(covs) / len(covs), 1), "by_os": by("os"),
                       "by_virtualization": by("virtualization")}, "skipped": []}  # fmt: skip


def render_html(
    summary: dict[str, Any] | None,
    fleet: dict[str, Any] | None = None,
    auth: bool = False,
    static: bool = False,
) -> str:
    """Embed data in the template. ``<`` is escaped so data cannot close the script tag.

    With ``auth`` the page ships with NO data; it fetches it using the access token.
    With ``static`` (exported snapshots) the page never polls a server, wherever it is hosted.
    """
    payload: dict[str, Any] = {"auth": True} if auth else {"summary": summary, "fleet": fleet}
    if static and not auth:
        payload["static"] = True
    blob = json.dumps(payload).replace("<", "\\u003c")
    page = TEMPLATE.read_text(encoding="utf-8")
    lab = LAB_JS.read_text(encoding="utf-8").replace("</script", "<\\/script")
    return page.replace("__PTAF_DATA__", blob).replace("/*__PTAF_LAB__*/", lab)


CSP = (
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
    "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

# --- live updates (server-sent events) -----------------------------------------------------------
STREAM_POLL_S = 0.5  # how often the stream checks for new data
STREAM_KEEPALIVE_S = 15.0
MAX_STREAMS = 16  # cap concurrent live connections so they cannot exhaust the server
_stream_slots = threading.BoundedSemaphore(MAX_STREAMS)
_WATCHED = ("status.json", "alerts.jsonl", "history.jsonl", "doctor.json")


def _fingerprint() -> tuple:
    """Changes whenever the agent writes anything the dashboard shows."""
    out = []
    base = state.state_dir()
    for name in _WATCHED:
        try:
            st = (base / name).stat()
            out.append((st.st_mtime_ns, st.st_size))
        except OSError:
            out.append(None)
    return tuple(out)


_doctor_lock = threading.Lock()
_doctor_cache: dict[str, Any] = {"at": 0.0, "data": None}
DOCTOR_TTL_S = 60


def run_health_check() -> dict[str, Any]:
    """Run the doctor on demand, cached for a minute so the endpoint cannot be used to burn CPU."""
    with _doctor_lock:
        if time.monotonic() - _doctor_cache["at"] > DOCTOR_TTL_S or _doctor_cache["data"] is None:
            checks = [c.to_dict() for c in run_checks()]
            data = {"time": datetime.now(timezone.utc).isoformat(), "checks": checks}
            try:
                (state.state_dir() / "doctor.json").write_text(json.dumps(data), encoding="utf-8")
            except OSError:
                pass
            _doctor_cache.update(at=time.monotonic(), data=data)
        return _doctor_cache["data"]


def make_handler(demo: bool = False, fleet_dir: Path | None = None, token: str | None = None):
    def authorised(headers) -> bool:
        if not token:
            return True
        supplied = headers.get("X-PTAF-Token") or ""
        auth = headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            supplied = auth[7:]
        return hmac.compare_digest(supplied.encode(), token.encode())

    def fleet_data() -> dict[str, Any] | None:
        if demo:
            return demo_fleet()
        return load_fleet(fleet_dir) if fleet_dir else None

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _stream(self) -> None:
            """Push a tiny 'update' event whenever agent state changes; the page then re-fetches.

            Uses fetch streaming on the client (not EventSource) so the access token can travel in a
            header. Keepalives hold the connection open; a dead client is noticed on the next write.
            """
            if not _stream_slots.acquire(blocking=False):
                return self._json(503, {"error": "too many live connections"})
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Accel-Buffering", "no")
                self.send_header("Content-Security-Policy", CSP)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(b"retry: 3000\nevent: hello\ndata: {}\n\n")
                self.wfile.flush()
                last, idle = _fingerprint(), 0.0
                while True:
                    time.sleep(STREAM_POLL_S)
                    now = _fingerprint()
                    if now != last:
                        last, idle, msg = now, 0.0, b"event: update\ndata: {}\n\n"
                    else:
                        idle += STREAM_POLL_S
                        if idle < STREAM_KEEPALIVE_S:
                            continue
                        idle, msg = 0.0, b": keepalive\n\n"
                    self.wfile.write(msg)
                    self.wfile.flush()
            except OSError:
                pass  # client went away
            finally:
                _stream_slots.release()

        def _json(self, code: int, obj: Any) -> None:
            self._send(code, json.dumps(obj).encode(), "application/json")

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            route = self.path.split("?", 1)[0]
            if route == "/healthz":  # liveness for load balancers; reveals nothing
                return self._send(200, b"ok", "text/plain")
            if route in ("/", "/index.html"):
                if token:  # shell only: the data is fetched with the token
                    return self._send(
                        200, render_html(None, auth=True).encode(), "text/html; charset=utf-8"
                    )
                summary = demo_summary() if demo else build_summary()
                return self._send(
                    200, render_html(summary, fleet_data()).encode(), "text/html; charset=utf-8"
                )
            if not route.startswith("/api/"):
                return self._send(404, b"not found", "text/plain")
            if not authorised(self.headers):
                return self._json(401, {"error": "access token required"})
            if route == "/api/stream":
                return self._stream()
            if route == "/api/summary":
                return self._json(200, demo_summary() if demo else build_summary())
            if route == "/api/fleet":
                data = fleet_data()
                return self._json(200 if data else 404, data or {"error": "no fleet configured"})
            if route == "/api/doctor":
                return self._json(200, run_health_check())
            return self._json(404, {"error": "not found"})

        do_HEAD = do_GET  # noqa: N815

        def _method_not_allowed(self) -> None:
            self.send_response(405)
            self.send_header("Allow", "GET, HEAD")
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_POST = do_PUT = do_DELETE = do_PATCH = _method_not_allowed  # noqa: N815

        def log_message(self, *_: Any) -> None:  # keep the terminal quiet
            return

    return Handler


def stop_on_signals() -> None:
    """Turn SIGTERM (systemd, Docker, kill) and SIGINT into a normal clean shutdown.

    A background job started by a non-interactive shell inherits SIGINT as IGNORED, and SIGTERM
    would otherwise kill the process outright, skipping cleanup (lock, final status). Both are
    routed to KeyboardInterrupt so the usual ``finally`` blocks run. Main thread only.
    """
    import signal

    def _raise(*_: Any) -> None:
        raise KeyboardInterrupt

    for name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, _raise)
            except (ValueError, OSError):
                pass  # not the main thread, or not permitted here


def make_server(
    host: str = "127.0.0.1",
    port: int = 8787,
    demo: bool = False,
    fleet_dir: Path | None = None,
    token: str | None = None,
) -> ThreadingHTTPServer:
    """Bind the dashboard server (raises OSError if the port is taken)."""
    return ThreadingHTTPServer((host, port), make_handler(demo, fleet_dir, token))


def serve(
    host: str = "127.0.0.1",
    port: int = 8787,
    demo: bool = False,
    fleet_dir: Path | None = None,
    token: str | None = None,
) -> None:
    server = make_server(host, port, demo, fleet_dir, token)
    stop_on_signals()
    print(
        f"PTAF dashboard on http://{host}:{port}"
        + ("/#token=<your token>" if token else "")
        + "  (Ctrl-C to stop)"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
