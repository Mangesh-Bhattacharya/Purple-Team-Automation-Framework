"""Pick the best available collector for this machine and say which one was chosen.

``auto`` prefers the event-driven Linux proc connector (root on Linux/Kali) and falls back to the
portable polling collector, always reporting why, so an operator is never silently on the weaker
sensor without knowing.
"""

from __future__ import annotations

import os
from typing import Any, Callable

from . import procconnector
from .collector import Event, ProcessCollector

MODES = ("auto", "poll", "procconn")


class SensorUnavailable(RuntimeError):
    """A specific collector was demanded but cannot run here."""


def default_mode() -> str:
    mode = os.environ.get("PTAF_COLLECTOR", "auto").lower()
    return mode if mode in MODES else "auto"


def make_collector(callback: Callable[[Event], None], mode: str = "auto") -> tuple[Any, str, str]:
    """Return ``(collector, name, note)``. Raises SensorUnavailable only if the mode is forced."""
    if mode not in MODES:
        raise ValueError(f"unknown collector mode {mode!r}")
    note = "portable polling (50 ms); can miss processes shorter than that"
    if mode in ("auto", "procconn"):
        ok, reason = procconnector.available()
        if ok:
            return (
                procconnector.ProcConnectorCollector(callback),
                "procconn",
                "event-driven exec events from the kernel proc connector",
            )
        if mode == "procconn":
            raise SensorUnavailable(reason)
        if reason.startswith("needs root"):
            note += f"; for event-driven collection: {reason}"
    return ProcessCollector(callback), "poll", note
