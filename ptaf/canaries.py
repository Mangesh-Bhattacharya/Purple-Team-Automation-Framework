"""Benign, local-only "canary" behaviours used to test detections end to end.

SAFETY MODEL (enforced by design and by tests/test_sentinel.py)
---------------------------------------------------------------
* Each canary launches a harmless local process whose *shape* (image name,
  command-line flags) matches what a real detection rule looks for.
* The payload is always a no-op: sleeping, decoding a short random string and
  discarding it, or a read-only system query. No network, no file writes, no
  credential access, no persistence, no privilege use, nothing off this host.
* argv is built as a list and run without a shell from this process; the only
  shell is ``sh -c`` over a fixed, quoted script on Unix.

Each canary also carries ``modeled_events``: the process events the OS is
expected to report. Tests use them to prove every rule fires for its canary on
every OS *without needing that OS*; the live self-test then checks reality.

Contributors adding canaries must keep to the same bar (see CONTRIBUTING.md).
"""

from __future__ import annotations

import base64
import shutil
import sys
import uuid
from dataclasses import dataclass
from typing import Any, Callable

Event = dict[str, Any]

_PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_SYS32 = "C:\\Windows\\System32\\"


def _ev(image: str, argv: list[str]) -> Event:
    return {
        "EventType": "process_creation",
        "ProcessId": 1,
        "ParentProcessId": 0,
        "Image": image,
        "CommandLine": " ".join(argv),
        "ParentImage": "",
        "User": "tester",
    }


@dataclass(frozen=True)
class Canary:
    id: str
    technique_id: str
    name: str
    tactic: str
    platforms: tuple[str, ...]  # subset of windows / linux / macos
    description: str
    build_argv: Callable[[str], list[str]]  # marker -> argv
    modeled_events: Callable[[str, list[str]], list[Event]]  # (os, argv) -> events

    def available_on(self, os_name: str) -> bool:
        return os_name in self.platforms


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _sh(script: str) -> list[str]:
    return ["/bin/sh", "-c", script]


# --- Windows ---------------------------------------------------------------
def _win_encoded_ps(_m: str) -> list[str]:
    # Decodes to: Start-Sleep -Milliseconds 1200  (a pure no-op)
    encoded = base64.b64encode("Start-Sleep -Milliseconds 1200".encode("utf-16-le")).decode()
    exe = shutil.which("powershell.exe") or "powershell.exe"
    return [exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]


def _win_ps_bypass_hidden(_m: str) -> list[str]:
    exe = shutil.which("powershell.exe") or "powershell.exe"
    return [
        exe,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-Command",
        "Start-Sleep -Milliseconds 1200",
    ]


def _win_systeminfo(_m: str) -> list[str]:
    return ["systeminfo.exe"]  # read-only local query; takes seconds


def _win_tasklist(_m: str) -> list[str]:
    return ["tasklist.exe", "/v"]  # read-only local query


# --- Unix ------------------------------------------------------------------
def _unix_base64_decode(marker: str) -> list[str]:
    payload = _b64(f"ptaf-canary-{marker}")
    return _sh(f"(sleep 1; printf %s '{payload}') | base64 -d >/dev/null 2>&1")


def _unix_openssl_decode(marker: str) -> list[str]:
    payload = _b64(f"ptaf-canary-{marker}")
    return _sh(f"(sleep 1; printf %s '{payload}') | openssl enc -d -base64 >/dev/null 2>&1")


def _unix_history_evasion(_m: str) -> list[str]:
    return _sh("HISTFILE=/dev/null; sleep 1")


def _unix_python_inline_b64(_m: str) -> list[str]:
    code = "import base64,time; base64.b64decode('cHRhZg=='); time.sleep(1)"
    return [sys.executable or shutil.which("python3") or "python3", "-c", code]


def _preload_argv(var: str) -> list[str]:
    # The trailing ':' stops the shell exec-ing sleep directly (which would hide this cmdline).
    return _sh(f"{var}=/nonexistent/ptaf-canary.so sleep 1; :")


def _unix_preload_env(_m: str) -> list[str]:
    return _preload_argv("DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD")


def _m_preload(os_name: str, _argv: list[str]) -> list[Event]:
    argv = _preload_argv("DYLD_INSERT_LIBRARIES" if os_name == "macos" else "LD_PRELOAD")
    return [_ev("/bin/sh", argv)]


def _mac_osascript(_m: str) -> list[str]:
    return ["/usr/bin/osascript", "-e", "delay 1"]


# --- modeled events (what the OS should report) -------------------------------
def _m_single(win_image: str | None = None, unix_image: str | None = None):
    def build(os_name: str, argv: list[str]) -> list[Event]:
        image = win_image if os_name == "windows" else (unix_image or argv[0])
        return [_ev(image or argv[0], argv)]

    return build


def _m_pipeline(child_image: str, child_cmd: str):
    def build(os_name: str, argv: list[str]) -> list[Event]:
        return [_ev(argv[0], argv), _ev(child_image, child_cmd.split())]

    return build


CANARIES: tuple[Canary, ...] = (
    Canary(
        "win-encoded-powershell",
        "T1059.001",
        "Encoded PowerShell command line",
        "Execution",
        ("windows",),
        "powershell.exe -EncodedCommand with a sleep-only payload.",
        _win_encoded_ps,
        _m_single(win_image=_PS),
    ),
    Canary(
        "win-powershell-bypass-hidden",
        "T1059.001",
        "PowerShell with ExecutionPolicy Bypass and a hidden window",
        "Defense Evasion",
        ("windows",),
        "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden, sleep only.",
        _win_ps_bypass_hidden,
        _m_single(win_image=_PS),
    ),
    Canary(
        "win-system-discovery",
        "T1082",
        "System information discovery",
        "Discovery",
        ("windows",),
        "Runs systeminfo.exe, a read-only local query.",
        _win_systeminfo,
        _m_single(win_image=_SYS32 + "systeminfo.exe"),
    ),
    Canary(
        "win-process-discovery",
        "T1057",
        "Verbose process listing",
        "Discovery",
        ("windows",),
        "Runs tasklist.exe /v, a read-only local query.",
        _win_tasklist,
        _m_single(win_image=_SYS32 + "tasklist.exe"),
    ),
    Canary(
        "unix-base64-decode",
        "T1140",
        "Base64 decode of piped data",
        "Defense Evasion",
        ("linux", "macos"),
        "Pipes a random marker through `base64 -d`, discards output.",
        _unix_base64_decode,
        _m_pipeline("/usr/bin/base64", "base64 -d"),
    ),
    Canary(
        "unix-openssl-decode",
        "T1140",
        "OpenSSL base64 decode of piped data",
        "Defense Evasion",
        ("linux", "macos"),
        "Pipes a random marker through `openssl enc -d -base64`, discards output.",
        _unix_openssl_decode,
        _m_pipeline("/usr/bin/openssl", "openssl enc -d -base64"),
    ),
    Canary(
        "unix-history-evasion",
        "T1070.003",
        "Shell history disabled via HISTFILE",
        "Defense Evasion",
        ("linux", "macos"),
        "sh -c 'HISTFILE=/dev/null; sleep 1' (variable assignment only).",
        _unix_history_evasion,
        _m_single(unix_image="/bin/sh"),
    ),
    Canary(
        "unix-python-inline-base64",
        "T1059.006",
        "Python one-liner decoding base64",
        "Execution",
        ("linux", "macos"),
        "python -c that decodes a constant string and sleeps.",
        _unix_python_inline_b64,
        _m_single(unix_image="/usr/bin/python3"),
    ),
    Canary(
        "unix-preload-env",
        "T1574.006",
        "Dynamic-linker preload variable on a command",
        "Persistence",
        ("linux", "macos"),
        "Sets LD_PRELOAD / DYLD_INSERT_LIBRARIES to a nonexistent path; loader ignores it.",
        _unix_preload_env,
        _m_preload,
    ),
    Canary(
        "macos-osascript",
        "T1059.002",
        "AppleScript executed from the command line",
        "Execution",
        ("macos",),
        "osascript -e 'delay 1' (no UI, no effect).",
        _mac_osascript,
        _m_single(unix_image="/usr/bin/osascript"),
    ),
)


def new_marker() -> str:
    return uuid.uuid4().hex[:12]


def canaries_for(os_name: str) -> list[Canary]:
    return [c for c in CANARIES if c.available_on(os_name)]
