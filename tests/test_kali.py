"""Kali Linux support: proc-connector wire format, sensor selection, Kali detection, canaries."""

import shutil
import struct
import subprocess
import sys

import pytest

from ptaf import procconnector as pc
from ptaf import sensor
from ptaf.canaries import CANARIES, canaries_for, skipped_for_sensor
from ptaf.platform_info import is_kali, parse_os_release
from ptaf.validation import descendants


# --- wire format: pure, so verified on every OS -------------------------------------
def _msg(what: int, payload: bytes, idx=pc.CN_IDX_PROC, val=pc.CN_VAL_PROC) -> bytes:
    event = struct.pack("=IIQ", what, 0, 123456789) + payload
    cn = struct.pack("=IIIIHH", idx, val, 0, 0, len(event), 0) + event
    return struct.pack("=IHHII", 16 + len(cn), pc.NLMSG_DONE, 0, 0, 0) + cn


def test_exec_event_is_decoded():
    buf = _msg(pc.PROC_EVENT_EXEC, struct.pack("=ii", 4242, 4242))
    assert pc.parse_proc_events(buf) == [{"what": "exec", "pid": 4242}]


def test_fork_and_exit_events_are_decoded():
    fork = _msg(pc.PROC_EVENT_FORK, struct.pack("=iiii", 10, 10, 11, 11))
    exit_ = _msg(pc.PROC_EVENT_EXIT, struct.pack("=iiII", 11, 11, 0, 17))
    assert pc.parse_proc_events(fork) == [{"what": "fork", "parent_pid": 10, "child_pid": 11}]
    assert pc.parse_proc_events(exit_) == [{"what": "exit", "pid": 11}]


def test_two_messages_in_one_datagram_are_both_read():
    a = _msg(pc.PROC_EVENT_EXEC, struct.pack("=ii", 1, 1))
    b = _msg(pc.PROC_EVENT_EXEC, struct.pack("=ii", 2, 2))
    pad = lambda x: x + b"\x00" * ((-len(x)) % 4)  # noqa: E731 - NLMSG_ALIGN
    assert [e["pid"] for e in pc.parse_proc_events(pad(a) + b)] == [1, 2]


@pytest.mark.parametrize(
    "garbage",
    [
        b"",
        b"\x00" * 7,
        b"\xff" * 200,
        _msg(pc.PROC_EVENT_EXEC, struct.pack("=ii", 1, 1))[:-3],  # truncated mid-event
        _msg(pc.PROC_EVENT_EXEC, struct.pack("=ii", 1, 1), idx=99),  # not the proc connector
        _msg(0x40000000, b"\x00" * 8),  # an event kind we ignore
    ],
)
def test_malformed_or_foreign_datagrams_never_raise_and_yield_no_events(garbage):
    assert pc.parse_proc_events(garbage) == []


def test_subscribe_message_has_the_layout_the_kernel_expects():
    msg = pc.build_subscribe_message(77)
    length, mtype, _flags, _seq, pid = struct.unpack_from("=IHHII", msg)
    assert length == len(msg) == 16 + 20 + 4 and mtype == pc.NLMSG_DONE and pid == 77
    idx, val, _s, _a, plen, _f = struct.unpack_from("=IIIIHH", msg, 16)
    assert (idx, val, plen) == (pc.CN_IDX_PROC, pc.CN_VAL_PROC, 4)
    assert struct.unpack_from("=I", msg, 36)[0] == pc.PROC_CN_MCAST_LISTEN
    stop = pc.build_subscribe_message(77, listen=False)
    assert struct.unpack_from("=I", stop, 36)[0] == pc.PROC_CN_MCAST_IGNORE


# --- lineage: fork-only intermediates must not break attribution --------------------
def test_ancestor_chain_follows_fork_lineage_and_stops_at_unknown_pids():
    col = pc.ProcConnectorCollector(lambda e: None)
    col._parents.update({900005: 900004, 900004: 900003})
    assert col._ancestors(900005) == [900005, 900004, 900003]  # 900003 unknown -> stop
    assert col._ancestors(0) == []


def test_ancestor_chain_cannot_loop_forever():
    col = pc.ProcConnectorCollector(lambda e: None)
    col._parents.update({900001: 900002, 900002: 900001})
    assert len(col._ancestors(900001)) <= 2


def test_attribution_bridges_a_fork_only_subshell_via_ancestor_pids():
    ev = lambda pid, ppid, anc=(): {  # noqa: E731
        "ProcessId": pid, "ParentProcessId": ppid, "AncestorPids": list(anc)
    }  # fmt: skip
    root = ev(100, 1)
    # pid 102 ("sleep") was forked by subshell 101, which never exec'd and has no event.
    sleeper = ev(102, 101, anc=[101, 100])
    stranger = ev(200, 1, anc=[1])
    got = descendants([root, sleeper, stranger], 100)
    assert [e["ProcessId"] for e in got] == [100, 102]


def test_exec_handling_counts_a_process_that_vanished_instead_of_dropping_it(monkeypatch):
    import psutil

    col = pc.ProcConnectorCollector(lambda e: None)

    def gone(_proc):
        raise psutil.NoSuchProcess(1)

    monkeypatch.setattr(pc.psutil, "Process", gone)
    col._handle_exec(123456)
    assert col.exec_events == 1 and col.missed == 1  # visible, never silent


def test_exec_handling_attaches_ancestors_and_survives_a_crashing_callback(monkeypatch):
    got = []
    col = pc.ProcConnectorCollector(lambda e: (got.append(e), 1 / 0))
    col._parents[900010] = 900009
    monkeypatch.setattr(
        pc, "_event_from_process", lambda _p: {"ProcessId": 5, "ParentProcessId": 900010}
    )

    class _Proc:  # pid 5 is the exec'd process; past 900009 the fork map is incomplete,
        def __init__(self, pid):  # so the psutil fallback is consulted and finds nothing
            if pid != 5:
                raise pc.psutil.NoSuchProcess(pid)

    monkeypatch.setattr(pc.psutil, "Process", _Proc)
    col._handle_exec(5)
    assert got and got[0]["AncestorPids"][:2] == [900010, 900009]
    assert col.errors == 1 and "ZeroDivisionError" in col.last_error


# --- availability / selector ----------------------------------------------------------
@pytest.mark.skipif(sys.platform.startswith("linux"), reason="non-Linux behaviour")
def test_proc_connector_reports_unavailable_off_linux():
    ok, reason = pc.available()
    assert not ok and "Linux" in reason


def test_auto_falls_back_to_polling_and_says_why(monkeypatch):
    monkeypatch.setattr(pc, "available", lambda: (False, "needs root or CAP_NET_ADMIN to x"))
    col, name, note = sensor.make_collector(lambda e: None, "auto")
    assert name == "poll" and "root" in note


def test_forcing_an_unavailable_sensor_is_an_error_not_a_silent_downgrade(monkeypatch):
    monkeypatch.setattr(pc, "available", lambda: (False, "no"))
    with pytest.raises(sensor.SensorUnavailable):
        sensor.make_collector(lambda e: None, "procconn")


def test_auto_prefers_the_event_driven_sensor_when_it_works(monkeypatch):
    monkeypatch.setattr(pc, "available", lambda: (True, "ok"))
    _col, name, _note = sensor.make_collector(lambda e: None, "auto")
    assert name == "procconn"


def test_env_var_selects_collector_and_junk_is_ignored(monkeypatch):
    monkeypatch.setenv("PTAF_COLLECTOR", "poll")
    assert sensor.default_mode() == "poll"
    monkeypatch.setenv("PTAF_COLLECTOR", "bogus")
    assert sensor.default_mode() == "auto"


# --- Kali detection ---------------------------------------------------------------------
KALI_OS_RELEASE = """PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
VERSION_ID="2025.4"
VERSION="2025.4"
ID=kali
ID_LIKE=debian
HOME_URL="https://www.kali.org/"
"""


def test_kali_is_recognised_from_os_release():
    rel = parse_os_release(KALI_OS_RELEASE)
    assert rel["ID"] == "kali" and rel["VERSION_ID"] == "2025.4" and is_kali(rel)


@pytest.mark.parametrize(
    "text,expected",
    [("ID=ubuntu\nID_LIKE=debian\n", False), ("ID=debian\n", False), ("", False),
     ("ID=parrot\nID_LIKE=kali debian\n", True), ("# comment\nbroken line\nID='kali'\n", True)],
)  # fmt: skip
def test_is_kali_handles_other_distros_derivatives_and_junk(text, expected):
    assert is_kali(parse_os_release(text)) is expected


# --- Kali canaries ---------------------------------------------------------------------
def test_kali_canaries_exist_for_the_core_offensive_tools():
    ids = {c.id for c in CANARIES}
    assert {"kali-nmap", "kali-hydra", "kali-sqlmap", "kali-hashcat", "kali-tcpdump"} <= ids


def test_kali_canaries_need_the_tool_and_the_event_sensor(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/" + b if b == "nmap" else None)
    ids = [c.id for c in canaries_for("linux", sensor="event")]
    assert "kali-nmap" in ids and "kali-hydra" not in ids  # only installed tools
    assert "kali-nmap" not in [c.id for c in canaries_for("linux", sensor="poll")]
    assert [c.id for c in skipped_for_sensor("linux", "poll")] == ["kali-nmap"]
    assert skipped_for_sensor("linux", "event") == []


def test_kali_canaries_only_print_version_or_usage_and_touch_no_network():
    for c in CANARIES:
        if not c.id.startswith("kali-"):
            continue
        args = c.build_argv("m")[1:]
        assert all(a.startswith("-") or a in {"version"} for a in args), (c.id, args)
        assert len(args) == 1


# --- installer script ----------------------------------------------------------------------
INSTALLER = "packaging/install-kali.sh"


def _installer_text():
    import pathlib

    return (pathlib.Path(__file__).resolve().parents[1] / INSTALLER).read_text(encoding="utf-8")


def test_installer_never_touches_system_python_or_forces_pip():
    text = _installer_text()
    for bad in ("--break-system-packages", "sudo pip", "pip install --user", "apt install -y"):
        assert bad not in text
    assert "venv" in text and "set -euo pipefail" in text


@pytest.mark.skipif(shutil.which("bash") is None or sys.platform == "win32", reason="needs bash")
def test_installer_is_syntactically_valid_bash():
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[1] / INSTALLER
    assert subprocess.run(["bash", "-n", str(path)], check=False).returncode == 0


def test_a_surprise_error_while_dispatching_is_recorded_and_collection_continues(monkeypatch):
    col = pc.ProcConnectorCollector(lambda e: None)
    monkeypatch.setattr(col, "_handle_exec", lambda pid: 1 / 0)
    # replicate one iteration of the receive loop's guarded dispatch
    buf = _msg(pc.PROC_EVENT_EXEC, struct.pack("=ii", 7, 7))
    try:
        col._dispatch(buf)
    except Exception as exc:  # noqa: BLE001
        col._record(exc)
    assert col.errors == 1 and "ZeroDivisionError" in col.last_error
