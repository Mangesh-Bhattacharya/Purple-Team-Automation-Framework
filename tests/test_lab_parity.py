"""The browser Detection Lab must agree with the Python engine the agent really runs.

Both engines get the same vectors: every shipped rule file is parsed by PyYAML and by the Lab's
YAML-subset parser, and a broad set of rule/event pairs is evaluated by sigma_lite and by lab.js.
Any disagreement is a bug in the Lab. Runs on Node (same V8 engine as Chrome); skipped if absent.
"""

import json
import pathlib
import shutil
import subprocess

import pytest
import yaml

from ptaf.sigma_lite import Rule, UnsupportedRule

ROOT = pathlib.Path(__file__).resolve().parents[1]
LAB = ROOT / "ptaf" / "lab.js"
RULES = sorted((ROOT / "ptaf" / "rules").glob("*.yml"))
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node not installed")

RUNNER = """
const lab = require(process.argv[1]).PtafLab;
const v = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = {yaml: v.yaml.map(t => { try { return {ok: true, value: lab.parseYaml(t)}; } catch (e) { return {ok: false, error: e.message}; } }),
             eval: v.eval.map(([r, ev]) => lab.evaluate(r, ev))};
process.stdout.write(JSON.stringify(out));
"""


def run_node(yaml_texts, evals):
    p = subprocess.run(
        [NODE, "-e", RUNNER, str(LAB)],
        input=json.dumps({"yaml": yaml_texts, "eval": evals}),
        capture_output=True, text=True, timeout=60, check=False, encoding="utf-8",
    )  # fmt: skip
    assert p.returncode == 0, p.stderr[-800:]
    return json.loads(p.stdout)


def rule_text(detection: str, product="linux") -> str:
    return (
        f"title: t\nid: x\nlogsource: {{category: process_creation, product: {product}}}\n"
        f"detection:\n{detection}\nlevel: low\ntags: [attack.t1059, attack.t1140]\n"
    )


EVENTS = [
    {"Image": "/usr/bin/base64", "CommandLine": "base64 -d", "User": "bob"},
    {"Image": "/usr/bin/base64", "CommandLine": "base64 notes.txt", "User": "root"},
    {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile -EncodedCommand AAAA",
        "User": "SYSTEM",
    },
    {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell /enc AAAA -ExecutionPolicy Bypass -WindowStyle Hidden",
    },
    {
        "Image": "/bin/sh",
        "CommandLine": "sh -c HISTFILE=/dev/null; sleep 1 # ptaf-canary",
        "ParentImage": "",
    },
    {"Image": "/usr/bin/python3", "CommandLine": "python3 /usr/bin/sqlmap --version"},
    {"Image": "/usr/bin/nmap", "CommandLine": "nmap -sS 10.0.0.0/24"},
    {"Image": "/usr/bin/ls", "CommandLine": "ls -la"},
    {"Image": "", "CommandLine": ""},
    {"CommandLine": "DYLD_INSERT_LIBRARIES=/x run"},
]

HAND_RULES = [
    "  s:\n    Image|endswith: '/base64'\n    CommandLine|contains: [' -d', '--decode']\n  condition: s",
    "  s:\n    Image: '*\\powershell.exe'\n  condition: s",
    "  s:\n    CommandLine|re: 'sc\\s+(create|config)|base64\\s+-d'\n  condition: s",
    "  s:\n    CommandLine|windash|contains: ' -enc'\n  condition: s",
    "  s:\n    ParentImage|exists: false\n  condition: s",
    "  s:\n    User: null\n  condition: s",
    "  a:\n    Image|endswith: '/x'\n  b:\n    User: bob\n  condition: all of them",
    "  a:\n    Image|endswith: '/nmap'\n  b:\n    CommandLine|contains: '-sS'\n  condition: 1 of them",
    "  kw:\n    - 'sqlmap'\n    - 'HISTFILE'\n  condition: kw",
    "  s1:\n    Image|endswith: '/base64'\n  s2:\n    CommandLine|contains: '-d'\n  f:\n    User: root\n  condition: (s1 and s2) and not f",
    "  sel_a:\n    Image|endswith: '/nmap'\n  sel_b:\n    Image|endswith: '/ls'\n  condition: 1 of sel_*",
    "  s:\n    CommandLine|contains|all: ['python3', 'sqlmap']\n  condition: s",
    "  s:\n    - Image|endswith: '/ls'\n    - CommandLine|contains: 'nmap'\n  condition: s",
    "  s:\n    Image|startswith: 'C:\\Windows'\n    CommandLine|contains: 'Bypass'\n  condition: s",
    "  s:\n    Image|endswith: '/ls'\n  condition: s or missing_selection",  # unknown selection
    "  s:\n    Image|base64: 'x'\n  condition: s",  # unsupported modifier
    "  s:\n    Image|endswith: '/ls'\n  condition: s and (",  # broken condition
]


def python_eval(text, event):
    try:
        rule = Rule.from_yaml(text)
        return {"ok": True, "matched": rule.matches(event)}
    except (UnsupportedRule, ValueError, yaml.YAMLError) as exc:
        return {"ok": False, "error": str(exc)}


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.name)
def test_lab_yaml_parser_agrees_with_pyyaml_on_every_shipped_rule(path):
    text = path.read_text(encoding="utf-8")
    (res,) = run_node([text], [])["yaml"]
    assert res["ok"], res
    want = yaml.safe_load(text)
    for key in ("title", "id", "logsource", "detection", "tags", "level"):
        assert res["value"].get(key) == want.get(key), (key, res["value"].get(key), want.get(key))


def test_lab_evaluation_agrees_with_the_python_engine_on_every_rule_and_event():
    texts = [p.read_text(encoding="utf-8") for p in RULES] + [rule_text(r) for r in HAND_RULES]
    pairs = [(t, e) for t in texts for e in EVENTS]
    got = run_node([], pairs)["eval"]
    mismatches = []
    for (text, event), lab in zip(pairs, got):
        want = python_eval(text, event)
        if want["ok"] != lab["ok"] or (want["ok"] and want["matched"] != lab["matched"]):
            mismatches.append(
                (text.split("detection:")[1][:90].replace("\n", "|"), event, want, lab)
            )
    assert not mismatches, f"{len(mismatches)} disagreement(s); first: {mismatches[0]}"
    assert len(pairs) > 400  # a real sweep, not a token check


def test_lab_reports_which_selection_decided_the_match():
    rule = rule_text(
        "  a:\n    Image|endswith: '/nmap'\n  b:\n    User: root\n  condition: a and not b"
    )
    (res,) = run_node([], [(rule, {"Image": "/usr/bin/nmap", "User": "bob"})])["eval"]
    assert res["ok"] and res["matched"] and res["selections"] == {"a": True, "b": False}
    assert res["techniques"] == ["T1059", "T1140"] and res["condition"] == "a and not b"


def test_lab_says_so_for_modifiers_it_cannot_do_instead_of_guessing():
    rule = rule_text("  s:\n    DestinationIp|cidr: '10.0.0.0/8'\n  condition: s")
    (res,) = run_node([], [(rule, {"DestinationIp": "10.1.1.1"})])["eval"]
    assert not res["ok"] and "not available in the browser Lab" in res["error"]


def test_lab_never_throws_on_garbage_input():
    garbage = [
        "",
        "just text",
        "- a\n- b",
        "title: [unclosed",
        "detection:\n  s: {a: }\n",
        "x: 'unterminated",
    ]
    got = run_node([], [(g, {"a": 1}) for g in garbage])["eval"]
    assert all(r["ok"] is False and r["error"] for r in got)
