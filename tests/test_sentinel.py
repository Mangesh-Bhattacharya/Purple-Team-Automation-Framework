"""Tests for PTAF Sentinel: rule engine, attribution, drift, exports, safety."""

import json
import sys

import pytest

from ptaf import state
from ptaf.canaries import CANARIES, canaries_for
from ptaf.collector import ProcessCollector
from ptaf.exports import badge, navigator_layer
from ptaf.platform_info import collect_host_info
from ptaf.service import render
from ptaf.sigma_lite import Rule, UnsupportedRule
from ptaf.validation import (
    CanaryResult,
    EventBuffer,
    SelfTestReport,
    descendants,
    load_rules,
    rule_covers,
    run_selftest,
)

RULE = """
title: t
id: x
logsource: {category: process_creation, product: linux}
detection:
  sel:
    Image|endswith: '/curl'
    CommandLine|contains|all: ['-o', 'http']
  filt:
    User: root
  condition: sel and not filt
tags: [attack.execution, attack.t1059.004, attack.t1105]
level: low
"""


def ev(**kw):
    base = {"ProcessId": 1, "ParentProcessId": 0, "Image": "", "CommandLine": "", "User": "bob"}
    return {**base, **kw}


# --- rule engine ---------------------------------------------------------
def test_rule_matches_case_insensitively_and_respects_not():
    rule = Rule.from_yaml(RULE)
    hit = ev(Image="/usr/bin/CURL", CommandLine="curl -o x HTTP://a")
    assert rule.matches(hit)
    assert not rule.matches({**hit, "User": "root"})
    assert not rule.matches({**hit, "CommandLine": "curl -o x"})  # 'all' needs both


def test_technique_ids_keep_subtechnique_and_skip_tactic_tags():
    assert Rule.from_yaml(RULE).technique_ids == ["T1059.004", "T1105"]


def test_unknown_selection_and_modifier_fail_loudly():
    bad_cond = RULE.replace("sel and not filt", "sel and nope")
    with pytest.raises(UnsupportedRule):
        Rule.from_yaml(bad_cond).matches(ev())
    bad_mod = RULE.replace("endswith", "base64")
    with pytest.raises(UnsupportedRule):
        Rule.from_yaml(bad_mod).matches(ev())


def test_quantified_conditions_and_parentheses():
    text = RULE.replace("sel and not filt", "(1 of s*) and not filt").replace("sel:", "s1:")
    rule = Rule.from_yaml(text)
    assert rule.matches(ev(Image="/bin/curl", CommandLine="-o http"))


def test_windows_backslash_rule_actually_matches_windows_path():
    """Regression: the shipped rule used a doubled backslash and never matched."""
    rules, errors = load_rules()
    assert not errors
    ps = next(r for r in rules if r.product == "windows")
    event = ev(
        Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        CommandLine="powershell.exe -NoProfile -EncodedCommand AAAA",
    )
    assert ps.matches(event)


def test_rule_covers_matches_base_and_sub_techniques():
    rule = Rule.from_yaml(RULE)
    assert rule_covers(rule, "T1059.004") and rule_covers(rule, "T1059")
    assert not rule_covers(rule, "T1140")


# --- attribution ---------------------------------------------------------
def test_descendants_follows_process_ancestry():
    events = [
        ev(ProcessId=10, ParentProcessId=1),
        ev(ProcessId=11, ParentProcessId=10),
        ev(ProcessId=12, ParentProcessId=11),
        ev(ProcessId=99, ParentProcessId=1),
    ]
    assert [e["ProcessId"] for e in descendants(events, 10)] == [10, 11, 12]


# --- drift / exports -----------------------------------------------------
def _report(status):
    res = CanaryResult("c1", "T1140", "n", status, ["rule A"] if status == "detected" else [])
    return SelfTestReport({"hostname": "h"}, "now", [res], 1, [])


def test_drift_only_when_previously_detected_now_not(tmp_path, monkeypatch):
    monkeypatch.setenv("PTAF_HOME", str(tmp_path))
    state.save(_report("detected"))
    prev = state.load_previous()
    assert state.compute_drift(prev, _report("detected")) == []
    drift = state.compute_drift(prev, _report("missed"))
    assert drift[0]["severity"] == "high" and drift[0]["to"] == "missed"
    assert state.compute_drift({}, _report("missed")) == []  # first run: no baseline


def test_badge_and_navigator_are_three_state():
    rules = [Rule.from_yaml(RULE)]
    assert badge(_report("detected"))["message"] == "100%"
    assert badge(_report("missed"))["color"] == "red"
    layer = navigator_layer(_report("missed"), rules)
    colors = {t["techniqueID"]: t["color"] for t in layer["techniques"]}
    assert colors["T1140"] == "#c53030"  # proven gap
    assert colors["T1105"] == "#d4a017"  # rule exists, untested


def test_coverage_is_none_when_nothing_testable():
    assert _report("no_telemetry").coverage is None


# --- safety contract -----------------------------------------------------
FORBIDDEN = [
    r"https?:",
    r"\bcurl\b",
    r"\bwget\b",
    r"\bnc\b",
    r"\bncat\b",
    r"/dev/tcp",
    r"/etc/(passwd|shadow)",
    r"\bsudo\b",
    r"\brm\b",
    r">>",
    r"mimikatz",
    r"\bchmod\b",
    r"\bcrontab\b",
    r"schtasks",
    r"\breg\b",
]


@pytest.mark.parametrize("canary", CANARIES, ids=lambda c: c.id)
def test_canary_argv_is_local_and_benign(canary):
    import re

    argv = canary.build_argv("abc123")
    assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
    flat = " ".join(argv)
    for bad in FORBIDDEN:
        assert not re.search(bad, flat, re.I), f"{canary.id} matches forbidden pattern {bad!r}"


_ALL_RULES, _ = load_rules()


@pytest.mark.parametrize(
    "canary,os_name",
    [(c, o) for c in CANARIES for o in c.platforms],
    ids=lambda v: v.id if hasattr(v, "id") else v,
)
def test_every_canary_fires_its_rule_on_every_supported_os(canary, os_name):
    """Deterministic cross-OS check: modelled telemetry must trip a rule for the technique."""
    events = canary.modeled_events(os_name, canary.build_argv("m"))
    rules = [r for r in _ALL_RULES if r.applies_to(os_name) and rule_covers(r, canary.technique_id)]
    assert rules, f"no {os_name} rule maps to {canary.technique_id}"
    assert any(r.matches(e) for r in rules for e in events), f"{canary.id} not caught on {os_name}"


BENIGN = [
    ("/bin/ls", "ls -la /tmp"),
    ("/usr/bin/base64", "base64 notes.txt"),
    ("/bin/sh", "sh -c echo hello"),
    ("/usr/bin/python3", "python3 manage.py runserver"),
    ("/usr/bin/openssl", "openssl x509 -in cert.pem -noout"),
    ("/usr/bin/osascript", "osascript script.scpt"),
    ("C:\\Windows\\System32\\notepad.exe", "notepad.exe notes.txt"),
    (
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -NoProfile -File build.ps1",
    ),
    ("C:\\Windows\\System32\\tasklist.exe", "tasklist.exe"),
]


@pytest.mark.parametrize("image,cmd", BENIGN)
def test_ordinary_activity_does_not_trip_any_rule(image, cmd):
    event = ev(Image=image, CommandLine=cmd)
    for os_name in ("windows", "linux", "macos"):
        for rule in _ALL_RULES:
            if rule.applies_to(os_name):
                assert not rule.matches(event), f"false positive: {rule.title} on {cmd!r}"


def test_every_platform_has_a_canary_and_every_canary_maps_to_attack():
    for os_name in ("windows", "linux", "macos"):
        assert canaries_for(os_name)
    assert all(c.technique_id.startswith("T") for c in CANARIES)


def test_service_templates_render_for_all_platforms():
    assert "ExecStart=" in render("linux")
    assert "launchctl" in render("macos")
    assert "schtasks" in render("windows")
    with pytest.raises(ValueError):
        render("plan9")


# --- live integration (runs on every OS in CI) ---------------------------
def test_collector_sees_a_new_process():
    import subprocess
    import sys
    import time

    buf = EventBuffer()
    col = ProcessCollector(buf.add, interval=0.02)
    col.start()
    try:
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1)"])
        time.sleep(0.6)
        seen = [e for e in buf.since(0) if e["ProcessId"] == p.pid]
        p.wait()
    finally:
        col.stop()
    assert seen and "time.sleep" in seen[0]["CommandLine"]


def test_live_selftest_detects_canaries_on_this_host(tmp_path, monkeypatch):
    monkeypatch.setenv("PTAF_HOME", str(tmp_path))
    host = collect_host_info()
    rules, errors = load_rules()
    report = run_selftest(rules, errors, host)
    assert not errors and report.results
    statuses = {r.canary_id: r.status for r in report.results}
    # A sensor gap on an exotic CI runner is tolerated; a rule gap is not.
    assert "missed" not in statuses.values(), json.dumps(report.to_dict(), indent=1)


def test_canary_with_missing_prerequisite_is_skipped_not_reported_as_a_gap(monkeypatch):
    from ptaf import canaries

    assert any(c.id == "unix-python-inline-base64" for c in canaries.canaries_for("linux"))
    monkeypatch.setattr(canaries, "_python_exe", lambda: None)
    assert not any(c.id == "unix-python-inline-base64" for c in canaries.canaries_for("linux"))
    assert canaries.canaries_for("linux")  # the rest still run


@pytest.mark.skipif(sys.platform == "win32", reason="os.execv semantics differ on Windows")
def test_collector_reports_a_process_whose_identity_changes_after_exec():
    import subprocess
    import time

    code = "import os,time; time.sleep(0.5); os.execv('/bin/sleep', ['sleep', '2'])"
    buf = EventBuffer()
    col = ProcessCollector(buf.add, interval=0.02)
    col.start()
    try:
        p = subprocess.Popen([sys.executable, "-c", code])
        time.sleep(1.5)
        cmds = [e["CommandLine"] for e in buf.since(0) if e["ProcessId"] == p.pid]
        p.wait()
    finally:
        col.stop()
    assert any("os.execv" in c for c in cmds), cmds  # pre-exec identity
    assert any(c.startswith("sleep 2") for c in cmds), cmds  # post-exec identity


def test_missed_canary_is_retried_and_flakiness_is_reported(monkeypatch):
    from ptaf import validation

    calls = []

    def fake_once(canary, rules, host, buffer, **kw):
        calls.append(1)
        status = "missed" if len(calls) == 1 else "detected"
        return CanaryResult(canary.id, canary.technique_id, canary.name, status, detail="first")

    monkeypatch.setattr(validation, "_run_canary_once", fake_once)
    res = validation.run_canary(CANARIES[0], [], collect_host_info(), EventBuffer())
    assert len(calls) == 2 and res.status == "detected"
    assert "retry" in res.detail  # flakiness stays visible


def test_a_real_gap_stays_missed_after_retry(monkeypatch):
    from ptaf import validation

    monkeypatch.setattr(
        validation,
        "_run_canary_once",
        lambda c, r, h, b, **kw: CanaryResult(c.id, c.technique_id, c.name, "missed"),
    )
    res = validation.run_canary(CANARIES[0], [], collect_host_info(), EventBuffer())
    assert res.status == "missed"


# --- extended Sigma coverage + compatibility report ----------------------------
def _r(detection_yaml, product="linux", category="process_creation"):
    return Rule.from_yaml(
        f"title: t\nid: x\nlogsource: {{category: {category}, product: {product}}}\n"
        f"detection:\n{detection_yaml}\nlevel: low\ntags: [attack.t1059]\n"
    )


def test_wildcards_regex_windash_cidr_exists_null_and_them():
    wild = _r(r"  s:\n    Image: '*\powershell.exe'\n  condition: s".replace("\\n", "\n"))
    assert wild.matches(ev(Image="C:\\Windows\\powershell.exe"))
    assert not wild.matches(ev(Image="C:\\Windows\\powershell.exe.bak"))
    rx = _r("  s:\n    CommandLine|re: 'sc\\s+(create|config)'\n  condition: s")
    assert rx.matches(ev(CommandLine="SC  CREATE svc")) and not rx.matches(ev(CommandLine="scx"))
    wd = _r("  s:\n    CommandLine|windash|contains: ' -enc'\n  condition: s")
    assert wd.matches(ev(CommandLine="powershell /enc AAA")) and wd.matches(
        ev(CommandLine="x -enc")
    )
    ip = _r("  s:\n    DestinationIp|cidr: '10.0.0.0/8'\n  condition: s")
    assert ip.matches(ev(DestinationIp="10.2.3.4")) and not ip.matches(ev(DestinationIp="8.8.8.8"))
    ex = _r("  s:\n    ParentImage|exists: false\n  condition: s")
    assert ex.matches(ev(ParentImage="")) and not ex.matches(ev(ParentImage="/bin/sh"))
    nl = _r("  s:\n    User: null\n  condition: s")
    assert nl.matches(ev(User="")) and not nl.matches(ev(User="bob"))
    them = _r("  a:\n    Image|endswith: '/x'\n  b:\n    User: bob\n  condition: all of them")
    assert them.matches(ev(Image="/bin/x", User="bob")) and not them.matches(
        ev(Image="/bin/x", User="alice")
    )
    kw = _r("  keywords:\n    - 'mimikatz'\n  condition: keywords")
    assert kw.matches(ev(CommandLine="run MIMIKATZ now")) and not kw.matches(ev(CommandLine="ls"))


def test_regex_guards_reject_oversized_or_invalid_patterns():
    big = _r("  s:\n    CommandLine|re: '" + "a" * 1200 + "'\n  condition: s")
    assert "regex longer" in big.unsupported_reason()
    bad = _r("  s:\n    CommandLine|re: '(unclosed'\n  condition: s")
    assert "invalid regex" in bad.unsupported_reason()


def test_compat_report_is_three_state_and_names_the_reason():
    from ptaf.sigma_lite import check_rule

    ok = check_rule(_r("  s:\n    Image|endswith: '/x'\n  condition: s"))
    assert ok.verdict == "runnable"
    part = check_rule(_r("  s:\n    OriginalFileName: 'x.exe'\n  condition: s"))
    assert part.verdict == "partial" and "OriginalFileName" in part.reasons[0]
    net = check_rule(
        _r("  s:\n    Image|endswith: '/x'\n  condition: s", category="network_connection")
    )
    assert net.verdict == "unsupported" and "network_connection" in net.reasons[0]
    bad = check_rule(_r("  s:\n    Image|base64: 'x'\n  condition: s"))
    assert bad.verdict == "unsupported"


# --- collector robustness (enterprise long-running behaviour) -------------------
def test_collector_forgets_exited_processes_so_memory_stays_bounded():
    import subprocess
    import time

    col = ProcessCollector(lambda e: None, interval=0.02)
    col.start()
    try:
        base = len(col._seen)
        for _ in range(40):
            subprocess.run([sys.executable, "-c", "pass"], check=False)
        time.sleep(0.6)
        grown = len(col._seen) - base
    finally:
        col.stop()
    assert grown < 30, f"seen-table grew by {grown} after 40 short-lived processes (leak)"


def test_collector_survives_a_crashing_callback_and_keeps_collecting():
    import subprocess
    import time

    seen = []

    def flaky(event):
        seen.append(event)
        raise RuntimeError("boom")

    col = ProcessCollector(flaky, interval=0.02)
    col.start()
    try:
        subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.6)"]).wait()
        time.sleep(0.3)
        alive = col._thread.is_alive()
    finally:
        col.stop()
    assert alive and seen and col.errors >= 1 and "RuntimeError" in (col.last_error or "")


def test_events_carry_the_extra_fields_real_sigma_rules_use():
    import psutil

    from ptaf.collector import _event_from_process

    event = _event_from_process(psutil.Process())
    assert {"ParentCommandLine", "CurrentDirectory", "Image", "CommandLine"} <= set(event)


# --- state hardening -------------------------------------------------------------
def test_state_dir_is_private_on_posix(tmp_path, monkeypatch):
    import os
    import stat

    monkeypatch.setenv("PTAF_HOME", str(tmp_path / "s"))
    d = state.state_dir()
    if os.name == "posix":
        assert stat.S_IMODE(d.stat().st_mode) == 0o700


def test_logs_rotate_and_old_ones_are_dropped(tmp_path, monkeypatch):
    monkeypatch.setenv("PTAF_HOME", str(tmp_path))
    monkeypatch.setattr(state, "MAX_LOG_BYTES", 200)
    for i in range(120):
        state.append_jsonl("alerts.jsonl", {"i": i, "pad": "x" * 40})
    names = sorted(p.name for p in tmp_path.iterdir() if p.name.startswith("alerts"))
    assert names == ["alerts.jsonl", "alerts.jsonl.1", "alerts.jsonl.2", "alerts.jsonl.3"]
    total = sum(p.stat().st_size for p in tmp_path.iterdir())
    assert total < 6 * 200 + 400  # bounded, not growing with record count


def test_second_monitor_is_refused_and_stale_lock_is_taken_over(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.setenv("PTAF_HOME", str(tmp_path))
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        (tmp_path / "monitor.lock").write_text(str(holder.pid), encoding="utf-8")
        with pytest.raises(state.AlreadyRunning):
            state.acquire_lock()
    finally:
        holder.kill()
        holder.wait()
    lock = state.acquire_lock()  # holder is dead -> stale lock is taken over
    assert lock.read_text(encoding="utf-8").strip().isdigit()
    state.release_lock(lock)
    assert not lock.exists()


def _scripted(monkeypatch, statuses):
    from ptaf import validation

    calls = []

    def fake(canary, rules, host, buffer, **kw):
        calls.append(1)
        st = statuses[min(len(calls) - 1, len(statuses) - 1)]
        return CanaryResult(canary.id, canary.technique_id, canary.name, st, detail="sensor gap")

    monkeypatch.setattr(validation, "_run_canary_once", fake)
    return validation, calls


def _event_canary():
    from ptaf.canaries import CANARIES

    return next(c for c in CANARIES if c.min_sensor == "event")


def test_a_lost_race_on_a_millisecond_lived_tool_is_retried_and_reported_honestly(monkeypatch):
    validation, calls = _scripted(monkeypatch, ["no_telemetry", "no_telemetry", "detected"])
    res = validation.run_canary(_event_canary(), [], collect_host_info(), EventBuffer())
    assert res.status == "detected" and len(calls) == 3
    assert "lost the race" in res.detail  # the flakiness stays visible


def test_a_genuinely_blind_sensor_still_reports_blind_after_the_retries(monkeypatch):
    validation, calls = _scripted(monkeypatch, ["no_telemetry"])
    res = validation.run_canary(_event_canary(), [], collect_host_info(), EventBuffer())
    assert res.status == "no_telemetry" and len(calls) == 1 + validation.RACE_RETRIES


def test_other_canaries_are_not_retried_on_no_telemetry(monkeypatch):
    from ptaf.canaries import CANARIES

    validation, calls = _scripted(monkeypatch, ["no_telemetry"])
    core = next(c for c in CANARIES if c.min_sensor == "any")
    assert (
        validation.run_canary(core, [], collect_host_info(), EventBuffer()).status == "no_telemetry"
    )
    assert len(calls) == 1  # a sensor that sees nothing for a long-lived canary is a real problem


def test_a_no_telemetry_result_says_whether_the_tool_ran_and_how_it_exited(monkeypatch):
    """A tool that failed to start must be distinguishable from a blind sensor."""
    import sys

    from ptaf import canaries, validation
    from ptaf.canaries import Canary

    c = canaries.CANARIES[0]
    quick = Canary(
        id="q", technique_id="T1", name="q", tactic="x", platforms=(), description="",
        build_argv=lambda m: [sys.executable, "-c", "import sys; sys.exit(7)"],
        modeled_events=c.modeled_events,
    )  # fmt: skip
    # an empty buffer that never receives events: the sensor "sees nothing"
    res = validation._run_canary_once(quick, [], collect_host_info(), EventBuffer(), settle=0.05)
    assert res.status == "no_telemetry" and "exited with code 7" in res.detail
