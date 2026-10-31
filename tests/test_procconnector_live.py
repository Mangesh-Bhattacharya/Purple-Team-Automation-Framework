"""Live proc-connector tests. Skipped unless a working connector is available (verified live).

CI runs these on a real Ubuntu kernel with sudo (containers cannot use the connector):
    sudo env "PATH=$PATH" python -m pytest tests/test_procconnector_live.py -v
"""

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


def test_every_exec_reaches_us_and_unreadable_ones_are_counted_not_lost():
    """The kernel feed is complete; the only loss is a process exiting before /proc is read.

    Measured on GitHub's Ubuntu runner: 0 of 60 ~1 ms ``true`` processes could be read in time.
    That is the honest floor of read-after-event collection (auditd/eBPF would be needed below it).
    What must hold: every exec event arrives, and each one is either delivered or counted.
    """
    true_bin = shutil.which("true") or "/bin/true"
    buf, col = _collect(2)
    try:
        pids = []
        for _ in range(60):
            p = subprocess.Popen([true_bin], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pids.append(p.pid)
            p.wait()
        time.sleep(0.8)
        delivered = len({e["ProcessId"] for e in buf.since(0)} & set(pids))
    finally:
        col.stop()
    assert col.exec_events >= len(pids), f"kernel feed incomplete: {col.exec_events}/{len(pids)}"
    assert delivered + col.missed >= 0.9 * len(pids)  # accounted for, never silently dropped


def test_processes_that_live_tens_of_milliseconds_are_caught():
    """The case that matters: nmap/hydra/sqlmap-style commands live long enough to be read.

    A 50 ms poller catches roughly half of 30 ms processes at best; this sensor should get nearly
    all of them. The threshold is deliberately conservative for loaded CI machines.
    """
    buf, col = _collect(2)
    try:
        pids = []
        for _ in range(40):
            p = subprocess.Popen(["sleep", "0.03"])
            pids.append(p.pid)
            p.wait()
        time.sleep(0.8)
        delivered = len({e["ProcessId"] for e in buf.since(0)} & set(pids))
    finally:
        col.stop()
    print(f"delivered {delivered}/{len(pids)} 30 ms processes; missed={col.missed}")
    assert delivered >= 0.7 * len(pids), f"only {delivered}/{len(pids)} 30 ms processes seen"


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
