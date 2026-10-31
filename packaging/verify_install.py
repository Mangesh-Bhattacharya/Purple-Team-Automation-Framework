"""Verify a PTAF install on THIS machine: repeated rounds plus an optional soak test.

    python packaging/verify_install.py --rounds 4
    python packaging/verify_install.py --rounds 3 --soak 90
    python packaging/verify_install.py --binary dist/ptaf --rounds 3

Each round uses a fresh state directory and runs every command, validating exit codes and
output. Within a round `selftest` runs twice so the baseline/drift path is exercised too.
--soak starts the real `monitor` agent, drives process churn at it, samples its memory, then
stops it gracefully and checks it exited cleanly with valid logs and a released lock.

Exit status is 0 only if every check in every round passed. Intended for operators and
enterprise change-approval; it makes no network connections.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess  # nosec B404 - fixed argv built from this script's own arguments
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from xml.etree import ElementTree as ET  # nosec B405 - parsing our own tool's output

ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str], env: dict, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603 - constant argv
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
        encoding="utf-8",
        errors="replace",
    )


class Results:
    def __init__(self) -> None:
        self.rows: list[tuple[int, str, bool, str]] = []

    def add(self, rnd: int, name: str, ok: bool, detail: str = "") -> None:
        self.rows.append((rnd, name, ok, detail))
        print(
            f"  [{'PASS' if ok else 'FAIL'}] {name}"
            + (f"  ({detail})" if detail and not ok else "")
        )

    @property
    def failures(self) -> list[tuple[int, str, bool, str]]:
        return [r for r in self.rows if not r[2]]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def one_round(rnd: int, base: list[str], res: Results) -> None:
    home = tempfile.mkdtemp(prefix="ptaf-verify-")
    env = {**os.environ, "PTAF_HOME": home}
    print(f"\n=== round {rnd} (state: {home})")
    if rnd == 1 and len(base) == 1:  # a built app: its very first launch can take ~14 s on macOS
        print("  (warming up the application: the OS scans a new unsigned build on first launch)")
        try:
            run(base + ["--version"], env, timeout=180)
        except subprocess.TimeoutExpired:
            pass

    def check(name: str, args: list[str], ok_codes=(0,), json_out=False, validator=None):
        started = time.monotonic()
        try:
            p = run(base + args, env)
        except subprocess.TimeoutExpired:
            return res.add(rnd, name, False, "timed out")
        good = p.returncode in ok_codes
        detail = f"exit {p.returncode}: {(p.stderr or p.stdout)[-200:].strip()}"
        if good and (json_out or validator):
            try:
                data = json.loads(p.stdout) if json_out else p.stdout
                if validator and not validator(data):
                    good, detail = False, "output failed validation"
            except ValueError as exc:
                good, detail = False, f"invalid output: {exc}"
        res.add(rnd, f"{name} [{time.monotonic() - started:.1f}s]", good, detail)
        return p

    check("info", ["info"], json_out=True, validator=lambda d: "os" in d)
    check(
        "doctor",
        ["doctor", "--json-out"],
        json_out=True,
        validator=lambda d: not any(c["status"] == "fail" for c in d),
    )
    check(
        "canaries list",
        ["canaries", "--json-out"],
        json_out=True,
        validator=lambda d: len(d["canaries"]) > 0,
    )
    check("rules check --strict", ["rules", "check", "--strict"])
    check(
        "selftest (first run)",
        ["selftest", "--format", "json"],
        json_out=True,
        validator=lambda d: d["coverage_percent"] == 100.0 and not d["drift"],
    )
    check(
        "selftest (second run, baseline exists, no drift)",
        ["selftest", "--format", "json"],
        json_out=True,
        validator=lambda d: not d["drift"],
    )
    check(
        "selftest junit",
        ["selftest", "--format", "junit"],
        validator=lambda x: ET.fromstring(x).get("failures") == "0",  # nosec B314 - own output
    )
    check("monitor --once", ["monitor", "--once", "--quiet"])
    out = Path(home) / "report.html"
    check("dashboard --export", ["dashboard", "--export", str(out)])
    res.add(
        rnd,
        "exported dashboard is a real page",
        out.exists() and "PTAF Sentinel" in out.read_text(encoding="utf-8"),
    )
    check("export badge", ["export", "badge"], json_out=True, validator=lambda d: "message" in d)
    check(
        "export navigator",
        ["export", "navigator"],
        json_out=True,
        validator=lambda d: d["domain"] == "enterprise-attack",
    )

    port = free_port()
    srv = subprocess.Popen(  # nosec B603 - constant argv
        base + ["dashboard", "--demo", "--port", str(port)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        body = b""
        for _ in range(240 if len(base) == 1 else 40):  # a built app starts more slowly
            try:
                body = urllib.request.urlopen(  # nosec B310 - loopback only
                    f"http://127.0.0.1:{port}/api/summary", timeout=2
                ).read()
                break
            except OSError:
                time.sleep(0.25)
        res.add(rnd, "dashboard server answers /api/summary", b'"demo": true' in body)
    finally:
        srv.terminate()
        srv.wait(timeout=10)

    alerts = Path(home) / "alerts.jsonl"
    bad = 0
    if alerts.exists():
        for line in alerts.read_text(encoding="utf-8").splitlines():
            try:
                json.loads(line)
            except ValueError:
                bad += 1
    res.add(rnd, "alerts.jsonl is valid JSON lines", bad == 0, f"{bad} bad lines")
    res.add(rnd, "no stale monitor lock left behind", not (Path(home) / "monitor.lock").exists())
    shutil.rmtree(home, ignore_errors=True)


def soak(base: list[str], seconds: int, res: Results) -> None:
    import psutil

    home = tempfile.mkdtemp(prefix="ptaf-soak-")
    env = {**os.environ, "PTAF_HOME": home}
    print(f"\n=== soak {seconds}s (real monitor under process churn)")
    agent = subprocess.Popen(  # nosec B603 - constant argv
        base + ["monitor", "--interval", "30", "--quiet"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    proc = psutil.Process(agent.pid)
    samples: list[float] = []
    spawned = 0
    t0 = time.monotonic()
    try:
        while time.monotonic() - t0 < seconds:
            for _ in range(10):  # churn: short-lived processes the collector must keep up with
                subprocess.Popen(
                    [sys.executable, "-c", "pass"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )  # nosec B603
                spawned += 1
            try:
                samples.append(proc.memory_info().rss / 1e6)
            except psutil.NoSuchProcess:
                break
            time.sleep(1.0)
        alive = agent.poll() is None
        res.add(0, f"agent stayed alive for {seconds}s while {spawned} processes churned", alive)
    finally:
        if agent.poll() is None:
            agent.terminate()
        try:
            code = agent.wait(timeout=60)
        except subprocess.TimeoutExpired:
            agent.kill()
            code = -9
    res.add(
        0,
        "agent shut down gracefully on SIGTERM/terminate",
        code in (0, -15, 1 if os.name == "nt" else 0),
        f"exit {code}",
    )
    if len(samples) >= 10:
        warm = samples[len(samples) // 4]  # after startup/first self-test
        growth = samples[-1] - warm
        res.add(
            0,
            f"memory stable (warm {warm:.0f} MB -> end {samples[-1]:.0f} MB, +{growth:.1f} MB)",
            growth < 25,
            "possible leak",
        )
    res.add(
        0,
        "state intact after soak (history.jsonl present)",
        (Path(home) / "history.jsonl").exists(),
    )
    res.add(0, "lock released after soak", not (Path(home) / "monitor.lock").exists())
    shutil.rmtree(home, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--soak", type=int, default=0, help="seconds of soak test (0 = skip)")
    ap.add_argument("--binary", help="verify a built executable instead of `python -m ptaf`")
    a = ap.parse_args()
    base = [a.binary] if a.binary else [sys.executable, "-m", "ptaf"]
    if not a.binary:
        os.chdir(ROOT)
    res = Results()
    for rnd in range(1, a.rounds + 1):
        one_round(rnd, base, res)
    if a.soak:
        soak(base, a.soak, res)
    total, bad = len(res.rows), res.failures
    print(
        f"\n{total - len(bad)}/{total} checks passed across {a.rounds} round(s)"
        + (f" + {a.soak}s soak" if a.soak else "")
    )
    for rnd, name, _, detail in bad:
        print(f"  FAILED (round {rnd}): {name}: {detail}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
