"""Drive the dashboard like a user in real headless Chrome and check what happens.

A harness script is appended to a static export. It clicks tabs and techniques, ticks a checklist,
plays the attack story, flips the motion switch and feeds hostile input to the Detection Lab, then
writes what it observed into the page. Skipped when Chrome is not installed.
"""

import json
import os
import pathlib
import re
import shutil
import subprocess

import pytest

from ptaf import dashboard as dash


def find_chrome():
    for cand in (
        os.environ.get("PTAF_CHROME"),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        shutil.which("google-chrome"),
        shutil.which("google-chrome-stable"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ):
        if cand and pathlib.Path(cand).exists():
            return cand
    return None


CHROME = find_chrome()
pytestmark = pytest.mark.skipif(CHROME is None, reason="Chrome not installed")

HARNESS = r"""
(function () {
  const out = {}, $ = (id) => document.getElementById(id), q = (s) => Array.from(document.querySelectorAll(s));
  const step = (ms, fn) => new Promise((r) => setTimeout(() => { try { fn(); } catch (e) { out["error_" + Math.random()] = String(e); } r(); }, ms));
  (async function () {
    await step(300, () => { out.tabs = q("#agent-tabs .tab").map((t) => t.textContent); });
    for (const name of ["Triage", "Explain", "Fix", "Planner", "Readiness"]) {
      await step(120, () => { const b = q("#agent-tabs .tab").find((t) => t.textContent.indexOf(name) === 0); b.click(); });
      await step(120, () => { out["tab_" + name] = $("agent-body").innerText.slice(0, 400); });
    }
    await step(100, () => { q("#agent-tabs .tab").find((t) => t.textContent.indexOf("Fix") === 0).click(); });
    await step(100, () => { const cb = q("#agent-body input[type=checkbox]")[0]; out.fix_before = $("agent-body").innerText.match(/\d of \d done/)[0]; cb.click(); });
    await step(100, () => { out.fix_after = $("agent-body").innerText.match(/\d of \d done/)[0]; out.fix_commands = q("#agent-body .cmd code").map((c) => c.textContent); });
    await step(100, () => { q("#kc .tech")[0].click(); });
    await step(100, () => { out.kc_detail = $("kc-detail").innerText.slice(0, 500); out.kc_pressed = q("#kc .tech[aria-pressed=true]").length; });
    await step(100, () => { $("kc-play").click(); });
    await step(3500, () => { out.story_playing = $("kc-story").innerText.slice(0, 200); out.story_spot = q("#kc .col.spot").length; });
    await step(100, () => { $("kc-play").click(); });
    await step(100, () => { out.story_stopped = $("kc-play").textContent; out.story_spot_after = q("#kc .col.spot").length; });
    // Detection Lab: normal use, unsupported modifier, bad JSON, hostile content
    await step(100, () => { out.lab_default = $("lab-result").innerText.split("\n")[0]; $("lab-preset").value = "3"; $("lab-preset").dispatchEvent(new Event("change")); });
    await step(100, () => { out.lab_nomatch = $("lab-result").innerText.split("\n")[0]; });
    await step(100, () => { $("lab-rule").value = "title: t\ndetection:\n  s:\n    Ip|cidr: '10.0.0.0/8'\n  condition: s\n"; $("lab-rule").dispatchEvent(new Event("input")); });
    await step(400, () => { out.lab_unsupported = $("lab-result").innerText.slice(0, 160); $("lab-event").value = "{not json"; $("lab-event").dispatchEvent(new Event("input")); });
    await step(400, () => { out.lab_badjson = $("lab-result").innerText.split("\n")[0];
      $("lab-event").value = JSON.stringify({ Image: "<img src=x onerror=\"document.title='PWNED'\">", CommandLine: "<script>document.title='PWNED2'<\/script>" });
      $("lab-rule").value = "title: x\ndetection:\n  s:\n    CommandLine|contains: 'script'\n  condition: s\n"; $("lab-rule").dispatchEvent(new Event("input")); });
    await step(500, () => { out.lab_hostile_verdict = $("lab-result").innerText.split("\n")[0]; out.title_after_hostile = document.title; out.injected_img = q("#lab-result img, #agent-body img, #kc img").length; });
    // Motion switch
    await step(100, () => { out.motion_before = document.documentElement.classList.contains("motion"); $("btn-motion").click(); });
    await step(100, () => { out.motion_after = document.documentElement.classList.contains("motion"); out.motion_label = $("btn-motion").textContent;
      out.reveal_visible = q(".reveal").every((e) => e.classList.contains("in")); });
    await step(50, () => { document.body.setAttribute("data-done", "1"); const pre = document.createElement("pre"); pre.id = "selftest"; pre.textContent = JSON.stringify(out); document.body.appendChild(pre); });
  })();
})();
"""


@pytest.fixture(scope="module")
def observed(tmp_path_factory):
    html = dash.render_html(dash.demo_summary(), dash.demo_fleet(), static=True)
    html = html.replace("</body>", f"<script>{HARNESS}</script></body>")
    page = tmp_path_factory.mktemp("ui") / "ui.html"
    page.write_text(html, encoding="utf-8")
    p = subprocess.run(
        [CHROME, "--headless=new", "--disable-gpu", "--no-sandbox", "--virtual-time-budget=20000",
         "--dump-dom", page.as_uri()],
        capture_output=True, text=True, timeout=120, check=False, encoding="utf-8",
    )  # fmt: skip
    m = re.search(r'<pre id="selftest">(.*?)</pre>', p.stdout, re.S)
    assert m, "the harness never finished:\n" + p.stdout[-600:]
    import html as h

    return json.loads(h.unescape(m.group(1)))


def test_no_script_errors_in_the_harness(observed):
    assert not [k for k in observed if k.startswith("error_")], observed


def test_all_five_agents_are_present_and_each_says_something_useful(observed):
    assert [t.split(" (")[0] for t in observed["tabs"]] == [
        "Triage",
        "Explain",
        "Fix",
        "Planner",
        "Readiness",
    ]
    assert "Why it ranks here" in observed["tab_Triage"]
    assert "Why attackers use it" in observed["tab_Explain"]
    assert "ptaf selftest" in observed["tab_Fix"] or "starter" in observed["tab_Fix"].lower()
    assert "Next step" in observed["tab_Planner"]
    assert "/ 100" in observed["tab_Readiness"] and "Capped at 79" in observed["tab_Readiness"]


def test_fix_checklist_progress_updates_when_a_step_is_ticked(observed):
    assert observed["fix_before"] != observed["fix_after"]
    assert observed["fix_after"].startswith("1 of")
    assert (
        any(c.startswith("ptaf ") for c in observed["fix_commands"])
        or observed["fix_commands"] == []
    )


def test_selecting_a_technique_explains_it_and_marks_it_pressed(observed):
    assert "Why attackers use it" in observed["kc_detail"] and observed["kc_pressed"] == 1


def test_the_attack_story_plays_highlights_a_stage_and_stops_cleanly(observed):
    assert re.match(r"Stage \d of \d", observed["story_playing"]) and observed["story_spot"] == 1
    assert observed["story_stopped"].startswith("▶") and observed["story_spot_after"] == 0


def test_the_lab_matches_misses_and_explains_errors_honestly(observed):
    assert observed["lab_default"].startswith("✓ MATCH")
    assert observed["lab_nomatch"].startswith("✕ NO MATCH")
    assert "not available in the browser Lab" in observed["lab_unsupported"]
    assert "not valid JSON" in observed["lab_badjson"]


def test_hostile_text_in_the_lab_is_inert(observed):
    assert observed["lab_hostile_verdict"].startswith("✓ MATCH")
    assert observed["title_after_hostile"] == "PTAF Sentinel — Detection Assurance"  # not PWNED
    assert observed["injected_img"] == 0


def test_the_motion_switch_turns_animation_off_and_never_hides_content(observed):
    assert observed["motion_before"] is True and observed["motion_after"] is False
    assert observed["motion_label"] == "Motion: off" and observed["reveal_visible"] is True
