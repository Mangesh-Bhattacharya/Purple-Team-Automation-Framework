"""Dashboard tests: summary shape, injection-safe embedding, HTTP routes."""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from ptaf import dashboard as dash
from ptaf import state


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("PTAF_HOME", str(tmp_path))


def test_demo_summary_is_labelled_and_has_every_status():
    d = dash.demo_summary()
    assert d["demo"] is True
    statuses = {r["status"] for r in d["latest"]["results"]}
    assert {"detected", "missed", "no_telemetry"} <= statuses
    assert set(d["explain"]) >= statuses


def test_empty_state_builds_without_results():
    d = dash.build_summary()
    assert d["latest"] is None and d["trend"] == [] and d["alerts"] == []


def test_corrupt_jsonl_lines_are_skipped():
    (state.state_dir() / "alerts.jsonl").write_text(
        '{"type": "detection", "rule": "r"}\n{truncated\n'
    )
    assert len(dash.build_summary()["alerts"]) == 1


def test_embedded_data_cannot_break_out_of_script_tag():
    evil = dash.demo_summary()
    evil["alerts"][0]["command_line"] = "</script><script>alert(1)</script>"
    html = dash.render_html(evil)
    assert "</script><script>alert(1)" not in html
    assert html.count("</script>") == html.count("<script")  # only our own tags


def test_template_never_uses_innerhtml_for_data():
    assert "innerHTML" not in dash.TEMPLATE.read_text()


def test_template_makes_no_external_requests():
    text = dash.TEMPLATE.read_text()
    assert "http://" not in text.replace("http://www.w3.org/2000/svg", "")
    assert "https://" not in text


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), dash.make_handler(demo=True))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_routes_headers_and_404(server):
    with urllib.request.urlopen(server + "/api/summary") as r:
        assert json.load(r)["demo"] is True
        assert "default-src 'none'" in r.headers["Content-Security-Policy"]
        assert r.headers["X-Content-Type-Options"] == "nosniff"
    with urllib.request.urlopen(server + "/") as r:
        assert b"PTAF Sentinel" in r.read()
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(server + "/etc/passwd")
    assert exc.value.code == 404
