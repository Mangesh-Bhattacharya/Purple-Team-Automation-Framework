"""Sanity tests for defensive-module scaffolding: log parsing and the
Sigma-style rule validation harness.
"""

from modules.defensive.log_parser import (
    NormalizedEvent,
    correlate_by_host,
    parse_json_lines,
    to_epoch_seconds,
)
from modules.defensive.validate_detections import RULES_DIR, check_rule


def test_parse_json_lines_skips_invalid_lines():
    lines = [
        '{"event_type": "network_connection", "timestamp": "2026-01-01T00:00:00Z", "host": "h1"}',
        "not json",
        "",
    ]
    events = list(parse_json_lines(lines, source="suricata"))
    assert len(events) == 1
    assert isinstance(events[0], NormalizedEvent)
    assert events[0].event_type == "network_connection"


def test_correlate_by_host_groups_events():
    events = [
        NormalizedEvent(source="s", event_type="a", timestamp=None, host="h1"),
        NormalizedEvent(source="s", event_type="b", timestamp=None, host="h1"),
        NormalizedEvent(source="s", event_type="c", timestamp=None, host="h2"),
    ]
    grouped = correlate_by_host(events)
    assert len(grouped["h1"]) == 2
    assert len(grouped["h2"]) == 1


def test_to_epoch_seconds_handles_bad_input():
    assert to_epoch_seconds(None) is None
    assert to_epoch_seconds("not-a-timestamp") is None
    assert to_epoch_seconds("2026-01-01T00:00:00Z") is not None


def test_example_detection_rule_is_valid():
    rule_files = sorted(RULES_DIR.rglob("*.yml")) if RULES_DIR.exists() else []
    assert rule_files, "expected at least one example Sigma rule under detection_rules/"
    for rule_path in rule_files:
        result = check_rule(rule_path)
        assert result.ok, f"{rule_path}: {result.errors}"
        assert result.technique_ids, f"{rule_path} is not mapped to any ATT&CK technique"
