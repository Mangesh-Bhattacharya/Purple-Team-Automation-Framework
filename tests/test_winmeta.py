"""Windows version-resource fields: OriginalFileName etc.

Cross-platform tests run everywhere; the Windows ones run only on a Windows machine (CI's
windows-latest) because that is the only place the real API can be exercised.
"""

import os
import shutil
import subprocess
import sys
import time

import pytest

from ptaf import winmeta
from ptaf.collector import ProcessCollector
from ptaf.sigma_lite import Rule, check_rule
from ptaf.validation import EventBuffer

WIN = sys.platform == "win32"


def _rule(product: str, field: str = "OriginalFileName") -> Rule:
    return Rule.from_yaml(
        f"title: t\nid: x\nlogsource: {{category: process_creation, product: {product}}}\n"
        f"detection:\n  s:\n    {field}: cmd.exe\n  condition: s\nlevel: low\ntags: [attack.t1059]\n"
    )


def test_the_compat_check_knows_windows_agents_supply_the_version_fields():
    for field in ("OriginalFileName", "Description", "Product", "Company", "FileVersion"):
        assert check_rule(_rule("windows", field)).verdict == "runnable", field
        assert check_rule(_rule("linux", field)).verdict == "partial", field  # not collected there
    assert check_rule(_rule("windows", "IntegrityLevel")).verdict == "partial"  # still unsupported


@pytest.mark.skipif(WIN, reason="non-Windows behaviour")
def test_off_windows_everything_is_empty_and_never_raises():
    assert winmeta.version_info("/bin/ls") == {} and winmeta.version_info("") == {}


def test_missing_and_non_executable_files_give_empty_results(tmp_path):
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    assert winmeta.version_info(str(tmp_path / "nope.exe")) == {}
    assert winmeta.version_info(str(tmp_path / "notes.txt")) == {}


@pytest.mark.skipif(not WIN, reason="needs the Windows version API")
def test_windows_reads_original_file_name_description_and_company():
    cmd = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
    info = winmeta.version_info(cmd)
    assert info["OriginalFileName"].lower() == "cmd.exe", info
    assert info.get("Description") and info.get("Company"), info


@pytest.mark.skipif(not WIN, reason="needs the Windows version API")
def test_a_renamed_binary_still_reports_its_original_name(tmp_path):
    """The reason this field matters: rename cmd.exe and the real name is still in the metadata."""
    src = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
    renamed = tmp_path / "quarterly-report.exe"
    shutil.copy(src, renamed)
    assert winmeta.version_info(str(renamed))["OriginalFileName"].lower() == "cmd.exe"


@pytest.mark.skipif(not WIN, reason="needs the Windows version API")
def test_the_collector_attaches_the_fields_to_live_process_events():
    buf = EventBuffer()
    col = ProcessCollector(buf.add, interval=0.02)
    col.start()
    try:
        p = subprocess.Popen(
            ["cmd.exe", "/c", "ping -n 3 127.0.0.1 >nul"], stdout=subprocess.DEVNULL
        )
        deadline = time.time() + 6
        ev = []
        while time.time() < deadline and not ev:
            ev = [e for e in buf.since(0) if e["ProcessId"] == p.pid and e.get("OriginalFileName")]
            time.sleep(0.1)
        p.wait()
    finally:
        col.stop()
    assert ev and ev[0]["OriginalFileName"].lower() == "cmd.exe", ev


@pytest.mark.skipif(not WIN, reason="needs the Windows version API")
def test_a_rule_on_original_file_name_fires_on_a_renamed_binary(tmp_path):
    src = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
    renamed = tmp_path / "update.exe"
    shutil.copy(src, renamed)
    event = {"Image": str(renamed), **winmeta.version_info(str(renamed))}
    assert _rule("windows").matches(event)  # matched by what it IS, not what it is called


@pytest.mark.parametrize(
    "raw,want",
    [("Cmd.Exe.MUI", "Cmd.Exe"), ("PowerShell.EXE.mui", "PowerShell.EXE"), ("Cmd.Exe", "Cmd.Exe"),
     ("notepad.exe", "notepad.exe"), ("", ""), ("mui", "mui")],
)  # fmt: skip
def test_the_mui_suffix_windows_adds_is_stripped_so_names_match_sysmon_and_sigma(raw, want):
    assert winmeta.clean_original_file_name(raw) == want
