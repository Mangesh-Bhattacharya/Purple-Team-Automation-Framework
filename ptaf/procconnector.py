"""Event-driven exec collector for Linux (and therefore Kali) using the kernel proc connector.

Why: the portable collector polls the process table every 50 ms, so it can miss commands that
live for less time than that, which describes most offensive tooling (``nmap --version``,
``id``, ``whoami``). The kernel proc connector pushes an event at the moment of every
``exec()``, so even a process that lives for a few milliseconds is seen and its command line is
read immediately.

Requirements: Linux, and root or CAP_NET_ADMIN (the kernel requires it to subscribe). No extra
packages. In a container the events are scoped to the container's PID namespace.

Honest limits: it still reads ``/proc/<pid>/cmdline`` after the event arrives, so a process that
exits within microseconds can be gone before it is read (that event is counted in ``missed``,
never silently dropped). The kernel can also drop events under extreme load (``ENOBUFS``,
counted in ``dropped``). It improves on polling by orders of magnitude; it is not auditd.

The wire-format parser is pure so it is unit-tested on every OS; only the socket needs Linux.
"""

from __future__ import annotations

import errno
import os
from collections import OrderedDict
import socket
import struct
import subprocess  # nosec B404 - fixed benign probe only
import sys
import threading
import time
from typing import Any, Callable

import psutil

from .collector import Event, _event_from_process

NETLINK_CONNECTOR = 11
CN_IDX_PROC = 0x1
CN_VAL_PROC = 0x1
NLMSG_DONE = 0x3
PROC_CN_MCAST_LISTEN = 1
PROC_CN_MCAST_IGNORE = 2

PROC_EVENT_FORK = 0x00000001
PROC_EVENT_EXEC = 0x00000002
PROC_EVENT_EXIT = 0x80000000
MAX_TRACKED = 50_000  # cap on the fork lineage map
MAX_DEPTH = 16  # ancestor chain length attached to each event

_NLHDR = struct.Struct("=IHHII")  # len, type, flags, seq, pid
_CNMSG = struct.Struct("=IIIIHH")  # idx, val, seq, ack, len, flags
_PEHDR = struct.Struct("=IIQ")  # what, cpu, timestamp_ns
_EXEC = struct.Struct("=ii")  # process_pid, process_tgid
_FORK = struct.Struct("=iiii")  # parent_pid, parent_tgid, child_pid, child_tgid
_EXIT = struct.Struct("=iiII")  # process_pid, process_tgid, exit_code, exit_signal


def build_subscribe_message(pid: int, listen: bool = True) -> bytes:
    """The datagram that asks the kernel to start (or stop) sending proc events to us."""
    op = struct.pack("=I", PROC_CN_MCAST_LISTEN if listen else PROC_CN_MCAST_IGNORE)
    cn = _CNMSG.pack(CN_IDX_PROC, CN_VAL_PROC, 0, 0, len(op), 0) + op
    return _NLHDR.pack(_NLHDR.size + len(cn), NLMSG_DONE, 0, 0, pid) + cn


def parse_proc_events(buf: bytes) -> list[dict[str, Any]]:
    """Decode one netlink datagram into events. Malformed input yields [] , never an exception.

    Returns dicts like ``{"what": "exec", "pid": 1234}`` or
    ``{"what": "fork", "parent_pid": 1, "child_pid": 2}``; other event kinds are ignored.
    """
    events: list[dict[str, Any]] = []
    offset = 0
    while offset + _NLHDR.size <= len(buf):
        msg_len, msg_type, *_ = _NLHDR.unpack_from(buf, offset)
        if msg_len < _NLHDR.size or offset + msg_len > len(buf):
            break  # truncated or corrupt: stop rather than guess
        body = offset + _NLHDR.size
        if msg_type == NLMSG_DONE and body + _CNMSG.size + _PEHDR.size <= offset + msg_len:
            idx, val, *_ = _CNMSG.unpack_from(buf, body)
            if idx == CN_IDX_PROC and val == CN_VAL_PROC:
                ev = body + _CNMSG.size
                what, _cpu, _ts = _PEHDR.unpack_from(buf, ev)
                data = ev + _PEHDR.size
                end = offset + msg_len
                if what == PROC_EVENT_EXEC and data + _EXEC.size <= end:
                    _pid, tgid = _EXEC.unpack_from(buf, data)
                    events.append({"what": "exec", "pid": tgid})
                elif what == PROC_EVENT_EXIT and data + _EXIT.size <= end:
                    _pid, tgid, *_ = _EXIT.unpack_from(buf, data)
                    events.append({"what": "exit", "pid": tgid})
                elif what == PROC_EVENT_FORK and data + _FORK.size <= end:
                    pp, _ptg, cp, ctg = _FORK.unpack_from(buf, data)
                    events.append({"what": "fork", "parent_pid": pp, "child_pid": ctg})
        offset += (msg_len + 3) & ~3  # NLMSG_ALIGN
    return events


def available() -> tuple[bool, str]:
    """Can the proc connector be used right now? ``(ok, reason)``; never raises.

    Subscribing can *succeed* and still deliver nothing (the kernel silently ignores listeners
    outside the initial PID/user namespace, i.e. inside most containers). So this proves it live:
    it starts a harmless process and requires that process's exec event to actually arrive.
    """
    if not sys.platform.startswith("linux"):
        return False, "proc connector is Linux-only"
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
    except (OSError, AttributeError) as exc:
        return False, f"netlink connector unavailable: {exc}"
    try:
        sock.bind((os.getpid(), CN_IDX_PROC))
        sock.settimeout(0.2)
        sock.send(build_subscribe_message(os.getpid()))
        probe = subprocess.Popen(  # nosec B603 B607 - fixed benign probe, no shell
            [sys.executable, "-c", "pass"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )  # fmt: skip
        deadline = time.monotonic() + 2.0
        try:
            while time.monotonic() < deadline:
                try:
                    buf = sock.recv(65536)
                except socket.timeout:
                    continue
                if any(
                    e["what"] == "exec" and e["pid"] == probe.pid for e in parse_proc_events(buf)
                ):
                    return True, "kernel proc connector available (verified with a live probe)"
        finally:
            probe.wait()
            try:
                sock.send(build_subscribe_message(os.getpid(), listen=False))
            except OSError:
                pass
        return False, (
            "subscribed but received no events (likely a container or non-initial PID namespace)"
        )
    except PermissionError:
        return False, "needs root or CAP_NET_ADMIN to subscribe to exec events"
    except OSError as exc:
        return False, f"cannot subscribe: {exc}"
    finally:
        sock.close()


class ProcConnectorCollector:
    """Drop-in replacement for ``ProcessCollector``: same start/stop/callback contract."""

    name = "procconn"

    def __init__(self, callback: Callable[[Event], None]) -> None:
        self._callback = callback
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None
        self.errors = 0
        self.last_error: str | None = None
        self.scans = 0  # kept for interface parity with the polling collector
        self.exec_events = 0
        self.missed = 0  # exec seen but the process was gone before /proc could be read
        self.dropped = 0  # kernel reported buffer overflow (ENOBUFS)
        # child -> parent from fork events. A fork-only process (e.g. a shell subshell) never
        # exec()s, so without this map the chain between a canary and its descendants has gaps.
        self._parents: "OrderedDict[int, int]" = OrderedDict()

    def start(self) -> None:
        ok, reason = available()
        if not ok:
            raise OSError(reason)
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
        sock.bind((os.getpid(), CN_IDX_PROC))
        sock.settimeout(0.5)
        sock.send(build_subscribe_message(os.getpid()))
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="ptaf-procconn", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                buf = self._sock.recv(65536)
            except socket.timeout:
                continue
            except OSError as exc:
                if exc.errno == errno.ENOBUFS:
                    self.dropped += 1
                    continue
                if self._stop.is_set():
                    return
                self._record(exc)
                return
            try:
                self._dispatch(buf)
            except Exception as exc:  # noqa: BLE001 - one odd event must never end collection
                self._record(exc)

    def _dispatch(self, buf: bytes) -> None:
        for ev in parse_proc_events(buf):
            if ev["what"] == "fork":
                self._parents[ev["child_pid"]] = ev["parent_pid"]
                while len(self._parents) > MAX_TRACKED:
                    self._parents.popitem(last=False)  # bounded: oldest entries go first
            elif ev["what"] == "exit":
                self._parents.pop(ev["pid"], None)
            elif ev["what"] == "exec":
                self._handle_exec(ev["pid"])

    def _handle_exec(self, pid: int) -> None:
        self.exec_events += 1
        if pid == os.getpid():
            return
        try:
            event = _event_from_process(psutil.Process(pid))
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            event = None
        if event is None:
            self.missed += 1
            return
        event["AncestorPids"] = self._ancestors(event["ParentProcessId"])
        try:
            self._callback(event)
        except Exception as exc:  # noqa: BLE001 - one bad event must never kill the sensor
            self._record(exc)

    def _ancestors(self, parent: int) -> list[int]:
        chain: list[int] = []
        cur = parent
        for _ in range(MAX_DEPTH):
            if not cur or cur in chain:
                break
            chain.append(cur)
            nxt = self._parents.get(cur)
            if nxt is None:
                try:
                    nxt = psutil.Process(cur).ppid()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
            cur = nxt
        return chain

    def _record(self, exc: Exception) -> None:
        self.errors += 1
        self.last_error = f"{type(exc).__name__}: {exc}"

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.send(build_subscribe_message(os.getpid(), listen=False))
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2)
        if self._sock is not None:
            self._sock.close()
            self._sock = None
