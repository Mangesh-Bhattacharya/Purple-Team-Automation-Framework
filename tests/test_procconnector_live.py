"""Live proc-connector tests. Skipped unless on Linux as root with a working connector.

CI runs these on a real Ubuntu kernel with sudo (containers cannot use the connector):
    sudo env "PATH=$PATH" python -m pytest tests/test_procconnector_live.py -v
"""

import os
import shutil
import subprocess
import sys
import time

import pytest

from ptaf import procconnector as pc
from ptaf.validation import EventBuffer, descendants

_ok, _reason = pc.available()
pytestmark = pytest.mark.skipif(not _ok, reason=f"proc connector unavailable: {_reason}")


def _collect(seconds: float):
    buf = EventBuffer()
    col = pc.ProcConnectorCollector(buf.add)
    col.start()
    return buf, col


def test_every_short_lived_process_is_seen_where_polling_would_miss_them():
    true_bin = shutil.which("true") or "/bin/true"
    buf, col = _collect(2)
    try:
        pids = []
        for _ in range(60):
            p = subprocess.Popen([true_bin], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pids.append(p.pid)
            p.wait()
        time.sleep(0.8)
        seen = {e["ProcessId"] for e in buf.since(0)}
    finally:
        col.stop()
    caught = sum(pid in seen for pid in pids)
    # ~1 ms processes: a 50 ms poller would catch almost none. Allow some slack for /proc races.
    assert caught >= 0.8 * len(pids), f"only {caught}/{len(pids)} short-lived processes seen"


def test_command_line_is_read_at_exec_time_not_the_parents():
    buf, col = _collect(2)
    try:
        p = subprocess.Popen(["sleep", "0.6"])
        time.sleep(0.4)
        ev = [e for e in buf.since(0) if e["ProcessId"] == p.pid]
        p.wait()
    finally:
        col.stop()
    assert ev and ev[-1]["CommandLine"].startswith("sleep 0.6"), ev


def test_fork_only_subshell_does_not_break_attribution():
    """( sleep ) forks a subshell that never exec()s; its child must still be attributed."""
    buf, col = _collect(2)
    try:
        root = subprocess.Popen(["/bin/sh", "-c", "( sleep 0.6 ); true"])
        time.sleep(0.4)
        events = buf.since(0)
        root.wait()
    finally:
        col.stop()
    family = descendants(events, root.pid)
    assert any(e["CommandLine"].startswith("sleep") for e in family), [
        (e["ProcessId"], e["ParentProcessId"], e["CommandLine"]) for e in events
    ]


def test_collector_counts_but_does_not_crash_on_processes_that_vanish():
    buf, col = _collect(2)
    try:
        for _ in range(30):
            subprocess.run([sys.executable, "-c", "pass"], check=False)
        time.sleep(0.5)
        alive = col._thread.is_alive()
    finally:
        col.stop()
    assert alive and col.exec_events >= 30 and col.errors == 0


def test_running_as_root_is_what_makes_this_work():
    assert os.geteuid() == 0
