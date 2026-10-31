"""`ptaf up` start and stop on real Windows (runs only on a Windows machine, i.e. CI's windows-latest).

POSIX signals do not exist on Windows. Ctrl+C reaches a console program as SIGINT and Ctrl+Break as
SIGBREAK; a service manager that calls TerminateProcess cannot be handled by any program. This test
sends CTRL_BREAK_EVENT to a new process group, which is how a supervising process asks a console
program to stop, and checks the shutdown is clean.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

from ptaf.canaries import canaries_for
from ptaf.platform_info import collect_host_info

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")


def test_up_serves_a_live_dashboard_and_stops_cleanly_on_ctrl_break(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    one = canaries_for(collect_host_info().os, sensor="poll")[0].id
    proc = subprocess.Popen(
        [sys.executable, "-m", "ptaf", "up", "--no-browser", "--port", str(port), "--only", one],
        env={**os.environ, "PTAF_HOME": str(tmp_path)},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )  # fmt: skip
    try:
        summary = None
        for _ in range(120):  # up to ~60 s for the first real result
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/summary", timeout=2) as r:
                    summary = json.load(r)
                if summary.get("latest"):
                    break
            except OSError:
                pass
            time.sleep(0.5)
        assert summary and summary["latest"], "no results within 60 s"
        assert summary["agent"]["health"] == "online"
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            assert b"PtafLab" in r.read()  # the full page, with the Lab engine inlined

        proc.send_signal(signal.CTRL_BREAK_EVENT)
        code = proc.wait(timeout=60)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert code == 0, f"exit code {code}"
    assert not (tmp_path / "monitor.lock").exists()
    assert json.loads((tmp_path / "status.json").read_text())["state"] == "stopped"
