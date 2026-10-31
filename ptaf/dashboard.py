"""Client-facing dashboard: live local server or a self-contained HTML snapshot.

Security posture
----------------
* The live server binds to 127.0.0.1 by default and only answers GET for two
  fixed routes; it never maps URL paths to files.
* Alert fields (command lines, image paths) come from processes on the host and
  must be treated as attacker-controlled. The page renders them with
  ``textContent`` only, and a strict CSP forbids inline event handlers and any
  external network access.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import state
from .platform_info import collect_host_info

TEMPLATE = Path(__file__).with_name("dashboard.html")

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


def _read_jsonl(name: str, limit: int) -> list[dict[str, Any]]:
    path = state.state_dir() / name
    rows: list[dict[str, Any]] = []
    try:
        with path.open() as fh:
            for line in fh:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue  # tolerate a truncated final line
    except OSError:
        return []
    return rows[-limit:]


def build_summary() -> dict[str, Any]:
    history = _read_jsonl("history.jsonl", 200)
    alerts = _read_jsonl("alerts.jsonl", 500)
    latest = history[-1] if history else None
    return {
        "generated": datetime.now(timezone.utc).isoformat(),
        "demo": False,
        "host": latest["host"] if latest else collect_host_info().to_dict(),
        "latest": latest,
        "trend": [{"time": h["started"], "coverage": h["coverage_percent"]} for h in history],
        "alerts": [a for a in alerts if a.get("type") == "detection"][-100:],
        "drift": [a for a in alerts if a.get("type") == "detection_drift"][-20:],
        "explain": EXPLAIN,
    }


def demo_summary() -> dict[str, Any]:
    """Clearly-labelled sample data for screenshots, demos and README GIFs."""
    now = datetime.now(timezone.utc)
    results = [
        (
            "T1059.001",
            "Encoded PowerShell command line",
            "detected",
            ["Suspicious Encoded PowerShell"],
        ),
        ("T1140", "Base64 decode", "detected", ["Base64 Decode Utility Executed"]),
        ("T1003.001", "LSASS memory access attempt", "missed", []),
        ("T1053.005", "Scheduled task creation", "detected", ["Scheduled Task Created"]),
        ("T1547.001", "Registry run-key persistence", "no_telemetry", []),
    ]
    coverage = [60.0, 60.0, 75.0, 75.0, 75.0, 100.0, 100.0, 75.0]
    trend = [
        {"time": (now - timedelta(hours=len(coverage) - i)).isoformat(), "coverage": c}
        for i, c in enumerate(coverage)
    ]
    host = {
        "os": "windows",
        "os_version": "Windows 11 Pro",
        "arch": "AMD64",
        "hostname": "DEMO-WORKSTATION-07",
        "virtualization": "VMware",
        "container": None,
    }
    return {
        "generated": now.isoformat(),
        "demo": True,
        "host": host,
        "latest": {
            "host": host,
            "started": now.isoformat(),
            "coverage_percent": 75.0,
            "rules_loaded": 14,
            "rule_errors": [],
            "results": [
                {
                    "canary_id": f"demo-{i}",
                    "technique_id": t,
                    "name": n,
                    "status": s,
                    "rules_fired": r,
                    "events_observed": 4,
                    "detail": "",
                    "duration_s": 1.4,
                }
                for i, (t, n, s, r) in enumerate(results)
            ],
        },
        "trend": trend,
        "alerts": [
            {
                "type": "detection",
                "synthetic": False,
                "rule": "Suspicious Encoded PowerShell",
                "level": "medium",
                "techniques": ["T1059.001"],
                "host": host["hostname"],
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -enc SQBFAFgA...",
                "time": now.isoformat(),
            },
        ],
        "drift": [
            {
                "type": "detection_drift",
                "technique_id": "T1003.001",
                "from": "detected",
                "to": "missed",
                "severity": "high",
                "host": host["hostname"],
                "time": (now - timedelta(hours=1)).isoformat(),
            },
        ],
        "explain": EXPLAIN,
    }


def render_html(summary: dict[str, Any]) -> str:
    """Embed the summary in the template. ``<`` is escaped so data can't close the tag."""
    payload = json.dumps(summary).replace("<", "\\u003c")
    return TEMPLATE.read_text(encoding="utf-8").replace("__PTAF_DATA__", payload)


CSP = (
    "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; "
    "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'"
)


def make_handler(demo: bool):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            route = self.path.split("?", 1)[0]
            summary = demo_summary() if demo else build_summary()
            if route == "/api/summary":
                self._send(200, json.dumps(summary).encode(), "application/json")
            elif route in ("/", "/index.html"):
                self._send(200, render_html(summary).encode(), "text/html; charset=utf-8")
            else:
                self._send(404, b"not found", "text/plain")

        def log_message(self, *_: Any) -> None:  # keep the terminal quiet
            return

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8787, demo: bool = False) -> None:
    server = ThreadingHTTPServer((host, port), make_handler(demo))
    print(f"PTAF dashboard on http://{host}:{port}  (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
