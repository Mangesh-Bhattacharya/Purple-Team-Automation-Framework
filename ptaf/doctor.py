"""``ptaf doctor``: preflight diagnostics an operator can run before trusting the agent.

The most important question for a detection-assurance tool is not "did a rule fire" but
"can this sensor actually see what it needs to?". A process collector that is denied access
to other users' command lines will report green while blind. Doctor measures that.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404 - fixed benign argv only
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import psutil

from . import state
from .canaries import CANARIES, canaries_for
from .platform_info import collect_host_info
from .sensor import SensorUnavailable, make_collector
from .sigma_lite import check_rule
from .validation import EventBuffer, child_env, load_rules

OK, WARN, FAIL = "ok", "warn", "fail"


@dataclass
class Check:
    name: str
    status: str
    detail: str
    fix: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _visibility() -> Check:
    """Share of processes whose command line this user can read."""
    total = denied = 0
    for proc in psutil.process_iter():
        total += 1
        try:
            proc.cmdline()
        except psutil.AccessDenied:
            denied += 1
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            total -= 1
    if total == 0:
        return Check("process visibility", FAIL, "no processes could be enumerated")
    pct = round(100 * denied / total, 1)
    admin = "Administrator" if os.name == "nt" else "root"
    fix = f"Run the agent as {admin} (or grant it process-inspection rights) for full visibility."
    if pct > 30:
        return Check(
            "process visibility",
            WARN,
            f"{pct}% of processes are unreadable "
            f"({denied}/{total}); the sensor is largely blind to other users",
            fix,
        )
    if pct > 5:
        return Check(
            "process visibility",
            WARN,
            f"{pct}% of processes are unreadable " f"({denied}/{total})",
            fix,
        )
    return Check("process visibility", OK, f"{100 - pct}% of {total} processes readable")


def _sensor_smoke(mode: str) -> Check:
    """Start a harmless process and confirm the chosen sensor sees it. Catches a blind sensor."""
    argv = ["ping", "-n", "2", "127.0.0.1"] if os.name == "nt" else ["sleep", "2"]
    buf = EventBuffer()
    try:
        col, name, _note = make_collector(buf.add, mode)
    except SensorUnavailable as exc:
        return Check("sensor smoke test", FAIL, str(exc))
    col.start()
    try:
        proc = subprocess.Popen(  # nosec B603 - constant argv
            argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
            env=child_env(),
        )  # fmt: skip
        deadline = time.monotonic() + 3
        seen = False
        while time.monotonic() < deadline and not seen:
            seen = any(e["ProcessId"] == proc.pid for e in buf.since(0))
            time.sleep(0.05)
        proc.kill()
        proc.wait()
    except OSError as exc:
        return Check("sensor smoke test", WARN, f"could not start the probe process: {exc}")
    finally:
        col.stop()
    if seen:
        return Check("sensor smoke test", OK, f"the '{name}' sensor observed a process it started")
    return Check(
        "sensor smoke test",
        FAIL,
        f"the '{name}' sensor could not observe a process it just started: it is blind",
        "Check that an EDR or OS policy is not blocking process enumeration.",
    )


#: Offensive tools a Kali purple-team exercise cares about (binary names).
KALI_TOOLS = ("nmap", "masscan", "hydra", "john", "hashcat", "sqlmap", "nikto", "gobuster",
              "tcpdump", "msfconsole", "responder", "netexec", "impacket-secretsdump")  # fmt: skip


def _kali_checks(host, sensor_kind: str | None) -> list[Check]:
    if not host.kali:
        return []
    checks = [Check("kali linux", OK, f"Kali {host.distro_version or ''} on {host.arch}".strip())]
    found = [t for t in KALI_TOOLS if shutil.which(t)]
    missing_core = [t for t in ("nmap", "hydra", "sqlmap", "tcpdump") if t not in found]
    checks.append(
        Check(
            "offensive tooling",
            OK if not missing_core else WARN,
            f"{len(found)} of {len(KALI_TOOLS)} known tools installed: "
            f"{', '.join(found) or 'none'}",
            "Install more with e.g. `sudo apt install kali-tools-top10`." if missing_core else "",
        )
    )
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        checks.append(
            Check(
                "kali privileges",
                WARN,
                "running as a normal user (Kali's default); the sensor cannot see other users' "
                "processes and the event-driven sensor is unavailable",
                'Run with: sudo "$(command -v ptaf)" doctor',
            )
        )
    return checks


def _sensor_check(mode: str) -> tuple[Check, str | None]:
    try:
        col, name, note = make_collector(lambda e: None, mode)
    except SensorUnavailable as exc:
        return Check("sensor", FAIL, str(exc)), None
    del col
    if name == "procconn":
        return Check("sensor", OK, f"event-driven (kernel proc connector): {note}"), "event"
    on_linux = sys.platform.startswith("linux")
    fix = "On Linux/Kali, run as root for the event-driven sensor." if on_linux else ""
    return Check("sensor", WARN if on_linux else OK, f"polling: {note}", fix), "poll"


def run_checks(rules_dir: Path | None = None, collector_mode: str = "auto") -> list[Check]:
    host = collect_host_info()
    checks: list[Check] = []

    ok_py = sys.version_info >= (3, 10)
    checks.append(
        Check(
            "python",
            OK if ok_py else FAIL,
            sys.version.split()[0] + ("" if ok_py else " (3.10+ required)"),
        )
    )
    vm = host.virtualization if host.virtualization != "none" else "bare metal"
    checks.append(Check("platform", OK, f"{host.os} {host.arch}, {vm}"))
    if host.container:
        checks.append(
            Check(
                "container",
                WARN,
                f"running in {host.container}: visibility is limited to this container's processes",
                "Run the agent on the host, or share the host PID namespace (e.g. --pid=host).",
            )
        )

    checks.append(_visibility())
    sensor_check, sensor_kind = _sensor_check(collector_mode)
    checks.append(sensor_check)
    checks.extend(_kali_checks(host, sensor_kind))

    try:
        d = state.state_dir()
        probe = d / ".doctor"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        free_mb = shutil.disk_usage(d).free // (1024 * 1024)
        if free_mb < 100:
            checks.append(
                Check(
                    "state directory",
                    WARN,
                    f"{d} has only {free_mb} MB free",
                    "Free disk space; logs rotate but still need room.",
                )
            )
        else:
            checks.append(Check("state directory", OK, f"{d} writable, {free_mb} MB free"))
    except OSError as exc:
        checks.append(
            Check(
                "state directory",
                FAIL,
                f"cannot write state: {exc}",
                "Set PTAF_HOME to a writable directory.",
            )
        )

    rules, errors = load_rules(rules_dir)
    verdicts = [check_rule(r) for r in rules]
    runnable = sum(v.verdict == "runnable" for v in verdicts)
    if not rules:
        checks.append(Check("rules", FAIL, "no Sigma rules found", "Point --rules at a directory."))
    elif runnable == 0:
        checks.append(Check("rules", FAIL, f"0 of {len(rules)} rules can run on this agent"))
    else:
        status = WARN if errors or runnable < len(rules) else OK
        checks.append(
            Check(
                "rules",
                status,
                f"{runnable} of {len(rules)} rules runnable"
                + (f", {len(errors)} failed to load" if errors else ""),
                "Run `ptaf rules check` for per-rule reasons." if status == WARN else "",
            )
        )

    available = canaries_for(host.os, sensor=sensor_kind)
    on_os = [c for c in CANARIES if host.os in c.platforms]
    installable = [c for c in on_os if c.precondition()]
    not_installed = [c.id for c in on_os if c not in installable]
    needs_sensor = [c.id for c in installable if c not in available]
    if not available:
        checks.append(Check("canaries", FAIL, f"no canaries can run on {host.os}"))
    elif not_installed or needs_sensor:
        why = []
        if needs_sensor:
            why.append(
                f"{len(needs_sensor)} need the event-driven sensor ({', '.join(needs_sensor)})"
            )
        if not_installed:
            why.append(f"{len(not_installed)} need tools that are not installed")
        checks.append(
            Check(
                "canaries",
                WARN if needs_sensor else OK,
                f"{len(available)} runnable; skipped: " + "; ".join(why),
                "Run as root on Linux for the event-driven sensor." if needs_sensor else "",
            )
        )
    else:
        checks.append(Check("canaries", OK, f"{len(available)} canaries available on {host.os}"))

    checks.append(_sensor_smoke(collector_mode))
    checks.append(Check("network", OK, "PTAF makes no network connections (canaries are local)"))
    return checks


def exit_code(checks: list[Check]) -> int:
    return 1 if any(c.status == FAIL for c in checks) else 0
