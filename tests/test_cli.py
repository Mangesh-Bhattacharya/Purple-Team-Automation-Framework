"""CLI contract tests: exit codes, formats, doctor, rule checks, canary listing."""

import json
from xml.etree import ElementTree as ET

import pytest
from click.testing import CliRunner

from ptaf import cli, reports, state
from ptaf.canaries import CANARY_TAG, canaries_for
from ptaf.platform_info import collect_host_info
from ptaf.validation import CanaryResult, SelfTestReport

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PTAF_HOME", str(tmp_path))


def _report(*statuses):
    results = [
        CanaryResult(f"c{i}", "T1140", f"n{i}", s, ["r"] if s == "detected" else [], detail="d")
        for i, s in enumerate(statuses)
    ]
    return SelfTestReport({"hostname": "h", "os": "linux"}, "t", results, 1, [])


@pytest.mark.parametrize(
    "statuses,drift,code",
    [
        (["detected", "detected"], [], reports.EXIT_OK),
        (["detected", "missed"], [], reports.EXIT_GAP),
        (["detected"], [{"x": 1}], reports.EXIT_GAP),
        (["detected", "no_telemetry"], [], reports.EXIT_SENSOR),
        (["error"], [], reports.EXIT_SENSOR),
        (["missed", "no_telemetry"], [], reports.EXIT_GAP),  # a real gap outranks a sensor issue
    ],
)
def test_exit_code_contract(statuses, drift, code):
    assert reports.exit_code_for(_report(*statuses), drift) == code


def test_blind_sensor_cannot_pass_a_ci_gate(monkeypatch):
    monkeypatch.setattr(cli, "run_selftest", lambda *a, **k: _report("no_telemetry"))
    result = runner.invoke(cli.main, ["selftest"])
    assert result.exit_code == reports.EXIT_SENSOR


def test_junit_is_well_formed_and_maps_statuses():
    root = ET.fromstring(reports.to_junit(_report("detected", "missed", "no_telemetry")))
    assert root.get("tests") == "3" and root.get("failures") == "1" and root.get("errors") == "1"
    assert root.find("testcase/failure").get("type") == "DetectionGap"
    assert root.find("testcase/error").get("type") == "SensorProblem"


def test_junit_escapes_hostile_text():
    rep = _report("missed")
    rep.results[0].detail = '<script>alert("x")</script> & "q"'
    ET.fromstring(reports.to_junit(rep))  # raises if the XML is broken


def test_unknown_canary_id_is_a_usage_error():
    for cmd in (["selftest", "--only", "nope"], ["selftest", "--skip", "nope"]):
        result = runner.invoke(cli.main, cmd)
        assert result.exit_code == reports.EXIT_USAGE and "unknown canary" in result.output


def test_filtered_run_does_not_overwrite_the_full_baseline(monkeypatch):
    monkeypatch.setattr(cli, "run_selftest", lambda *a, **k: _report("detected"))
    runner.invoke(cli.main, ["selftest"])
    baseline = state.load_previous()
    monkeypatch.setattr(cli, "run_selftest", lambda *a, **k: _report("missed"))
    only = canaries_for(collect_host_info().os)[0].id
    runner.invoke(cli.main, ["selftest", "--only", only])
    assert state.load_previous() == baseline


def test_monitor_rejects_a_dangerously_short_interval():
    result = runner.invoke(cli.main, ["monitor", "--interval", "1", "--once"])
    assert result.exit_code == reports.EXIT_USAGE


def test_monitor_exits_4_when_another_instance_holds_the_lock(tmp_path):
    import subprocess
    import sys

    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        (tmp_path / "monitor.lock").write_text(str(holder.pid), encoding="utf-8")
        result = runner.invoke(cli.main, ["monitor", "--once"])
    finally:
        holder.kill()
        holder.wait()
    assert result.exit_code == reports.EXIT_LOCKED and "another PTAF monitor" in result.output


def test_canaries_command_lists_commands_without_running_them():
    result = runner.invoke(cli.main, ["canaries", "--json-out", "--all-platforms"])
    data = json.loads(result.output)
    assert data["tag"] == CANARY_TAG and len(data["canaries"]) >= 10
    assert all(c["command"] and c["description"] for c in data["canaries"])
    assert any(c["tagged"] for c in data["canaries"])  # shell/python canaries carry the tag


def test_doctor_runs_and_reports_machine_readable_checks():
    result = runner.invoke(cli.main, ["doctor", "--json-out"])
    checks = json.loads(result.output)
    names = {c["name"] for c in checks}
    assert {
        "python",
        "process visibility",
        "state directory",
        "rules",
        "sensor smoke test",
    } <= names
    assert all(c["status"] in {"ok", "warn", "fail"} for c in checks)
    assert result.exit_code == (1 if any(c["status"] == "fail" for c in checks) else 0)


def test_rules_check_reports_each_verdict_and_strict_fails(tmp_path):
    good = "title: g\nid: 1\nlogsource: {category: process_creation, product: linux}\n"
    (tmp_path / "good.yml").write_text(
        good + "detection:\n  s: {Image|endswith: /x}\n  condition: s\nlevel: low\n"
        "tags: [attack.t1059]\n",
        encoding="utf-8",
    )
    (tmp_path / "net.yml").write_text(
        good.replace("process_creation", "network_connection")
        + "detection:\n  s: {Image|endswith: /x}\n  condition: s\n"
        + "level: low\ntags: [attack.t1059]\n",
        encoding="utf-8",
    )
    (tmp_path / "broken.yml").write_text("title: [unclosed", encoding="utf-8")
    out = runner.invoke(cli.main, ["rules", "check", str(tmp_path), "--json-out"])
    data = json.loads(out.output)
    assert data["counts"]["runnable"] == 1 and data["counts"]["unsupported"] == 1
    assert len(data["load_errors"]) == 1
    assert runner.invoke(cli.main, ["rules", "check", str(tmp_path)]).exit_code == 0
    assert runner.invoke(cli.main, ["rules", "check", str(tmp_path), "--strict"]).exit_code == 1


def test_bundled_rules_are_all_runnable():
    out = runner.invoke(cli.main, ["rules", "check", "--json-out"])
    data = json.loads(out.output)
    assert data["counts"]["partial"] == 0 and data["counts"]["unsupported"] == 0


def test_a_malformed_rule_file_is_reported_not_fatal(tmp_path):
    from ptaf.validation import load_rules

    (tmp_path / "bad.yml").write_text("title: [unclosed", encoding="utf-8")
    (tmp_path / "bin.yml").write_bytes(b"\xff\xfe\x00garbage")
    (tmp_path / "list.yml").write_text("- just\n- a list\n", encoding="utf-8")
    rules_, errors = load_rules(tmp_path)  # must not raise
    assert rules_ == [] and len(errors) == 3


def test_build_script_can_make_a_folder_build_and_defaults_to_one_file():
    """macOS needs --onedir (a one-file app re-unpacks and is re-scanned on every launch: ~14 s)."""
    import importlib.util
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[1] / "packaging" / "build.py"
    spec = importlib.util.spec_from_file_location("ptaf_build", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert "--onefile" in mod.build_command() and "--onedir" not in mod.build_command()
    assert "--onedir" in mod.build_command(onedir=True) and "--onefile" not in mod.build_command(
        True
    )
    cmd = " ".join(mod.build_command(True))
    assert "ptaf/rules" in cmd and "dashboard.html" in cmd  # the rules still ship in the app
