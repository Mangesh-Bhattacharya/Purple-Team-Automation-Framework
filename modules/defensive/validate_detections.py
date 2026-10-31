"""Automated test harness for detection coverage.

Loads every Sigma-style rule under modules/defensive/detection_rules/,
checks it is well-formed, and reports which MITRE ATT&CK technique IDs
(from the rule's "tags") have at least one detection rule -- cross-checked
against the offensive module's attack_techniques.yaml so it's easy to see
detection coverage gaps.

This does not execute against a real SIEM. It is a static coverage check,
meant to run in CI (see .github/workflows/ci.yml) and locally.
"""

from __future__ import annotations

import pathlib
import sys
from dataclasses import dataclass, field

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "modules" / "defensive" / "detection_rules"
ATTACK_TECHNIQUES_FILE = REPO_ROOT / "modules" / "offensive" / "attack_techniques.yaml"

REQUIRED_FIELDS = ["title", "id", "logsource", "detection", "level"]


@dataclass
class RuleCheckResult:
    path: pathlib.Path
    ok: bool
    errors: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)


def _extract_technique_ids(tags: list[str]) -> list[str]:
    """Pull attack.tNNNN(.NNN) style tags out and normalize to T-IDs."""
    ids = []
    for tag in tags or []:
        if tag.startswith("attack.t"):
            raw = tag.split("attack.")[1]
            ids.append(raw.upper().split(".")[0])
    return sorted(set(ids))


def check_rule(path: pathlib.Path) -> RuleCheckResult:
    errors: list[str] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return RuleCheckResult(path=path, ok=False, errors=[f"YAML parse error: {exc}"])

    if not isinstance(data, dict):
        return RuleCheckResult(
            path=path, ok=False, errors=["Rule root is not a mapping."]
        )

    for required in REQUIRED_FIELDS:
        if required not in data:
            errors.append(f"Missing required field: {required}")

    technique_ids = _extract_technique_ids(data.get("tags", []))
    if not technique_ids:
        errors.append("No attack.tXXXX tag found -- rule isn't mapped to ATT&CK.")

    return RuleCheckResult(
        path=path, ok=not errors, errors=errors, technique_ids=technique_ids
    )


def load_known_technique_ids() -> set[str]:
    if not ATTACK_TECHNIQUES_FILE.exists():
        return set()
    data = yaml.safe_load(ATTACK_TECHNIQUES_FILE.read_text(encoding="utf-8")) or {}
    return {entry["id"] for entry in data.get("techniques", []) if "id" in entry}


def main() -> int:
    if not RULES_DIR.exists():
        print(f"No detection_rules directory at {RULES_DIR}")
        return 1

    rule_files = sorted(RULES_DIR.rglob("*.yml")) + sorted(RULES_DIR.rglob("*.yaml"))
    if not rule_files:
        print("No detection rules found -- nothing to validate.")
        return 0

    known_techniques = load_known_technique_ids()
    covered: set[str] = set()
    had_error = False

    for rule_path in rule_files:
        result = check_rule(rule_path)
        status = "OK" if result.ok else "FAILED"
        print(f"[{status}] {rule_path.relative_to(REPO_ROOT)}")
        for error in result.errors:
            print(f"    - {error}")
            had_error = True
        covered.update(result.technique_ids)

    if known_techniques:
        gaps = sorted(known_techniques - covered)
        print()
        print(f"Techniques with a detection rule: {sorted(covered)}")
        print(f"Techniques with NO detection rule yet: {gaps}")

    return 1 if had_error else 0


if __name__ == "__main__":
    sys.exit(main())
