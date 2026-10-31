"""Agent heartbeat, fleet aggregation (untrusted input), attention list, dashboard server auth."""

import json
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer

import pytest
from click.testing import CliRunner

from ptaf import cli, state, status
from ptaf import dashboard as dash
from ptaf.fleet import MAX_FILE_BYTES, load_fleet


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PTAF_HOME", str(tmp_path / "state"))


NOW = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc).timestamp()


def iso(offset_s: float) -> str:
    return datetime.fromtimestamp(NOW + offset_s, timezone.utc).isoformat()


# --- heartbeat ------------------------------------------------------------------------------
def test_no_status_means_never_started():
    assert status.agent_summary(None, NOW)["health"] == "never"


@pytest.mark.parametrize(
    "age,expected", [(2, "online"), (14, "online"), (30, "stale"), (59, "stale"), (120, "offline")]
)
def test_health_follows_heartbeat_age(age, expected):
    st = {"pid": os.getpid(), "state": "idle", "heartbeat": iso(-age), "started": iso(-3600)}
    assert status.agent_summary(st, NOW)["health"] == expected


def test_a_crashed_agent_is_offline_even_with_a_fresh_heartbeat():
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    st = {"pid": dead.pid, "state": "idle", "heartbeat": iso(-1), "started": iso(-60)}
    assert status.agent_summary(st, NOW)["health"] == "offline"


def test_a_cleanly_stopped_agent_is_offline():
    st = {"pid": os.getpid(), "state": "stopped", "heartbeat": iso(-1), "started": iso(-60)}
    assert status.agent_summary(st, NOW)["health"] == "offline"


def test_garbage_status_never_crashes_the_reader():
    state.state_dir()
    status.status_path().write_text("{not json", encoding="utf-8")
    assert status.read_status() is None
    status.status_path().write_text("[1,2]", encoding="utf-8")
    assert status.read_status() is None
    assert (
        status.agent_summary({"heartbeat": "yesterday-ish", "pid": "x"}, NOW)["health"] == "never"
    )


def test_status_write_is_atomic_and_roundtrips():
    status.write_status({"pid": 1, "state": "idle"})
    assert status.read_status() == {"pid": 1, "state": "idle"}
    assert not list(state.state_dir().glob("*.tmp"))


def test_monitor_publishes_a_heartbeat_and_stops_cleanly():
    """End to end on this OS with one real canary."""
    from ptaf.canaries import canaries_for
    from ptaf.monitor import Monitor
    from ptaf.platform_info import collect_host_info
    from ptaf.validation import load_rules

    host = collect_host_info()
    one = canaries_for(host.os, sensor="poll")[0].id
    rules, errors = load_rules()
    mon = Monitor(rules, errors, host, interval_s=3600, emit_stdout=False, only=(one,))
    mon.run(run_once=True)
    st = status.read_status()
    assert st["state"] == "stopped" and st["pid"] == os.getpid()
    assert st["collector"]["name"] in {"poll", "procconn"} and st["last_selftest"]
    assert status.agent_summary(st)["health"] == "offline"  # stopped
    records = [json.loads(x) for x in (state.state_dir() / "alerts.jsonl").read_text().splitlines()]
    assert any(r["type"] == "agent_start" for r in records)
    assert not (state.state_dir() / "monitor.lock").exists()


# --- fleet: files are UNTRUSTED ---------------------------------------------------------------
def _host_file(d, name, **over):
    doc = {
        "generated": iso(-30),
        "agent": {"health": "online"},
        "host": {"hostname": name, "os": "linux", "virtualization": "KVM/QEMU"},
        "latest": {
            "started": iso(-30),
            "coverage_percent": 75.0,
            "results": [
                {"technique_id": "T1140", "name": "Base64", "status": "detected"},
                {"technique_id": "T1070.003", "name": "History", "status": "missed"},
            ],
        },
    }
    doc.update(over)
    (d / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")


def test_fleet_rolls_up_hosts_and_shows_the_worst_result_per_technique(tmp_path):
    _host_file(tmp_path, "a")
    _host_file(
        tmp_path, "b", latest={"coverage_percent": 100, "results": [
            {"technique_id": "T1070.003", "name": "History", "status": "detected"}]},
    )  # fmt: skip
    fleet = load_fleet(tmp_path, now=NOW)
    assert fleet["rollup"]["hosts"] == 2 and fleet["rollup"]["with_gaps"] == 1
    assert fleet["rollup"]["avg_coverage"] == 87.5
    cell = next(c for c in fleet["matrix"] if c["technique_id"] == "T1070.003")
    assert cell["status"] == "missed" and cell["hosts"] == 2 and cell["missed"] == 1


def test_hostile_and_corrupt_fleet_files_are_skipped_or_neutralised(tmp_path):
    (tmp_path / "junk.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "list.json").write_text("[1,2,3]", encoding="utf-8")
    (tmp_path / "nohost.json").write_text('{"latest": {}}', encoding="utf-8")
    (tmp_path / "huge.json").write_text(" " * (MAX_FILE_BYTES + 10), encoding="utf-8")
    _host_file(
        tmp_path,
        "evil",
        host={"hostname": "<script>alert(1)</script>" + "A" * 500, "os": "TempleOS", "virtualization": {"x": 1}},
        latest={"coverage_percent": 9999, "results": [
            {"technique_id": "T1140; DROP TABLE", "status": "detected"},
            {"technique_id": "T1059", "status": "pwned"},
            {"technique_id": "T1059.001", "name": "<img onerror=x>", "status": "detected"},
        ] + [{"technique_id": "T1000", "status": "detected"}] * 500},
    )  # fmt: skip
    fleet = load_fleet(tmp_path, now=NOW)  # must not raise
    assert len(fleet["skipped"]) == 4
    (host,) = fleet["hosts"]
    assert len(host["name"]) <= 80 and host["os"] == "unknown"
    assert host["coverage"] is None  # out-of-range value rejected
    assert list(host["techniques"]) == ["T1059.001", "T1000"]  # bad ids / statuses dropped


def test_a_snapshot_nobody_refreshed_is_reported_as_silent(tmp_path):
    _host_file(tmp_path, "old", generated=iso(-3 * 86400))
    (host,) = load_fleet(tmp_path, now=NOW)["hosts"]
    assert host["health"] == "offline" and host["age_s"] >= 3 * 86400


# --- attention list ---------------------------------------------------------------------------
def _summary(**over):
    base = {
        "generated": iso(0), "host": {"os": "windows"},
        "agent": {"health": "online", "interval_s": 3600, "collector": {}},
        "latest": {"started": iso(-60), "results": [], "skipped": [], "rule_errors": []},
        "drift": [], "health_checks": None,
    }  # fmt: skip
    base.update(over)
    return base


def test_a_healthy_machine_says_so_plainly():
    items = dash.attention_items(_summary())
    assert [i["level"] for i in items] == ["ok"]


def test_problems_are_prioritised_and_say_what_to_do():
    s = _summary(
        agent={"health": "offline", "collector": {"errors": 3, "last_error": "boom"}},
        latest={"started": iso(-60), "rule_errors": ["x.yml: bad"], "skipped": [], "results": [
            {"name": "A", "technique_id": "T1", "status": "missed"},
            {"name": "B", "technique_id": "T2", "status": "no_telemetry"}]},
        drift=[{"technique_id": "T1003", "from": "detected", "to": "missed"}],
    )  # fmt: skip
    items = dash.attention_items(s)
    levels = [i["level"] for i in items]
    assert levels == sorted(levels, key=dash.LEVEL_ORDER.get)  # most urgent first
    assert levels[0] == "critical" and "not running" in items[0]["title"]
    text = " ".join(i["title"] + i["detail"] for i in items)
    assert "T1003" in text and "undetected" in text and "could not be verified" in text
    assert all(i["action"] for i in items if i["level"] == "critical")


def test_overdue_checks_are_flagged():
    s = _summary(agent={"health": "online", "interval_s": 600, "collector": {}},
                 latest={"started": iso(-7200), "results": []})  # fmt: skip
    assert any("overdue" in i["title"] for i in dash.attention_items(s))


def test_failed_health_checks_surface_with_their_fix():
    s = _summary(health_checks={"checks": [{"name": "sensor smoke test", "status": "fail",
                                            "detail": "blind", "fix": "check EDR"}]})  # fmt: skip
    item = next(i for i in dash.attention_items(s) if "sensor smoke test" in i["title"])
    assert item["level"] == "critical" and item["action"] == "check EDR"


# --- server: token auth, methods, fleet ------------------------------------------------------------
TOKEN = "correct-horse-battery"


@pytest.fixture
def server():
    made = []

    def start(**kw):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), dash.make_handler(**kw))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        made.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    yield start
    for srv in made:
        srv.shutdown()
        srv.server_close()


def _get(url, headers=None, method="GET"):
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req) as r:  # nosec B310 - loopback test server
            return r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers


def test_protected_server_ships_no_data_without_the_token(server):
    base = server(demo=True, token=TOKEN)
    code, body, _ = _get(base + "/")
    assert code == 200 and b'"auth": true' in body
    assert b"DEMO-WORKSTATION" not in body  # the page shell carries no data at all
    assert _get(base + "/api/summary")[0] == 401
    assert _get(base + "/api/summary", {"Authorization": "Bearer nope-nope-nope"})[0] == 401
    assert _get(base + "/api/summary", {"Authorization": "Bearer " + TOKEN[:-1]})[0] == 401
    assert _get(base + "/api/fleet")[0] == 401 and _get(base + "/api/doctor")[0] == 401


def test_protected_server_serves_data_with_the_token(server):
    base = server(demo=True, token=TOKEN)
    code, body, hdrs = _get(base + "/api/summary", {"Authorization": "Bearer " + TOKEN})
    assert code == 200 and json.loads(body)["demo"] is True
    assert "no-store" in hdrs["Cache-Control"] and hdrs["Referrer-Policy"] == "no-referrer"
    assert _get(base + "/api/summary", {"X-PTAF-Token": TOKEN})[0] == 200
    code, body, _ = _get(base + "/api/fleet", {"Authorization": "Bearer " + TOKEN})
    assert code == 200 and json.loads(body)["rollup"]["hosts"] >= 5


def test_healthz_is_open_but_reveals_nothing(server):
    base = server(demo=True, token=TOKEN)
    assert _get(base + "/healthz")[:2] == (200, b"ok")


def test_only_get_and_head_are_allowed(server):
    base = server(demo=True)
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        req = urllib.request.Request(base + "/api/summary", data=b"x", method=method)
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req)  # nosec B310
        assert exc.value.code == 405
    assert _get(base + "/", method="HEAD")[0] == 200


def test_fleet_endpoint_reads_a_directory_and_404s_without_one(server, tmp_path):
    fleet_dir = tmp_path / "fleet"
    fleet_dir.mkdir()
    _host_file(fleet_dir, "web01")
    base = server(fleet_dir=fleet_dir)
    code, body, _ = _get(base + "/api/fleet")
    assert code == 200 and json.loads(body)["hosts"][0]["name"] == "web01"
    assert _get(server() + "/api/fleet")[0] == 404


def test_render_with_auth_embeds_no_summary():
    html = dash.render_html(dash.demo_summary(), dash.demo_fleet(), auth=True)
    assert '"auth": true' in html and "DEMO-" not in html


def test_health_check_endpoint_is_cached_and_saved_for_the_page(server):
    base = server(demo=True)
    code, body, _ = _get(base + "/api/doctor")
    assert code == 200 and {c["name"] for c in json.loads(body)["checks"]} >= {"python", "rules"}
    assert (state.state_dir() / "doctor.json").exists()
    assert dash.build_summary()["health_checks"]["checks"]  # the page can show it later


# --- CLI ------------------------------------------------------------------------------------------------
def test_dashboard_refuses_a_network_bind_without_a_token_and_rejects_weak_tokens():
    r = CliRunner()
    out = r.invoke(cli.main, ["dashboard", "--host", "0.0.0.0"])
    assert out.exit_code == 2 and "without an access token" in out.output
    out = r.invoke(cli.main, ["dashboard", "--host", "0.0.0.0", "--token", "short"])
    assert out.exit_code == 2 and "at least 12" in out.output


def test_export_includes_the_fleet_and_summary_is_valid_json(tmp_path):
    r = CliRunner()
    page = tmp_path / "r.html"
    assert r.invoke(cli.main, ["dashboard", "--demo", "--export", str(page)]).exit_code == 0
    html = page.read_text(encoding="utf-8")
    assert "DEMO-KALI-01" in html and "DEMO DATA" in html
    out = r.invoke(cli.main, ["export", "summary"])
    assert out.exit_code == 0 and "attention" in json.loads(out.output)


def test_the_rules_ship_inside_the_package():
    """Guards the packaging bug that once shipped agents with zero rules."""
    import pathlib

    import ptaf
    from ptaf.validation import DEFAULT_RULES_DIR

    assert DEFAULT_RULES_DIR.parent == pathlib.Path(ptaf.__file__).resolve().parent
    assert len(list(DEFAULT_RULES_DIR.glob("*.yml"))) >= 21
    pyproject = (pathlib.Path(ptaf.__file__).resolve().parents[1] / "pyproject.toml").read_text()
    assert "rules/*.yml" in pyproject and "dashboard.html" in pyproject
