"""The legal and policy documents exist, say the important things, and are reachable."""

import pathlib

from click.testing import CliRunner

from ptaf import cli, legal

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = [
    "TERMS.md",
    "PRIVACY.md",
    "COPYRIGHT.md",
    "TRADEMARK.md",
    "THIRD_PARTY_NOTICES.md",
    "SECURITY.md",
]


def text(name):
    return (ROOT / name).read_text(encoding="utf-8")


def test_every_policy_document_exists_and_the_readme_links_to_it():
    readme = text("README.md")
    for name in DOCS:
        assert len(text(name)) > 500, name
        assert f"]({name})" in readme, f"README does not link {name}"


def test_the_terms_demand_authorized_use_and_disclaim_guarantees():
    t = text("TERMS.md").lower()
    for phrase in (
        "authorized use only",
        "as is",
        "can and will",
        "not a guarantee",
        "mit license",
    ):
        assert phrase in t, phrase


def test_the_terms_do_not_narrow_the_mit_license():
    assert "nothing on this page narrows it" in text("TERMS.md")


def test_the_privacy_policy_matches_what_the_software_really_does():
    p = text("PRIVACY.md")
    assert "no telemetry" in p.lower() and "0700" in p and "outbound" in p
    for name in ("history.jsonl", "alerts.jsonl", "status.json"):  # the files it says it writes
        assert name in p


def test_third_party_notices_cover_every_runtime_dependency_and_attack():
    t = text("THIRD_PARTY_NOTICES.md")
    for dep in ("psutil", "Click", "PyYAML"):
        assert dep in t
    assert "MITRE" in t and "registered trademark" in t


def test_ptaf_legal_prints_the_notice_and_the_banner_line_is_short():
    out = CliRunner().invoke(cli.main, ["legal"])
    assert out.exit_code == 0
    for word in ("AUTHORIZED", "ALERTS", "NO GUARANTEE", "PRIVACY", "MIT"):
        assert word in out.output
    assert len(legal.ACCEPTABLE_USE) < 200 and "authorized" in legal.ACCEPTABLE_USE


def test_the_acceptable_use_line_is_shown_where_people_start_the_tool():
    out = CliRunner().invoke(cli.main, ["canaries"])
    assert legal.ACCEPTABLE_USE in out.output
