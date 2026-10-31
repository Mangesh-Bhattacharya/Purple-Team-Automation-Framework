"""Dependency-light Sigma rule evaluator for process-creation telemetry.

Supported
---------
* selections: ``field|modifier: value-or-list`` maps, lists of maps (OR), keyword lists
* modifiers: ``contains startswith endswith all re windash cidr exists lt lte gt gte``
* wildcards ``*`` and ``?`` in plain/contains/startswith/endswith values
* ``null`` values, ``condition`` with and/or/not/parentheses, ``1 of x*``, ``all of x*``,
  ``1 of them``, ``all of them``

Matching is case-insensitive, like Sigma. Anything unsupported raises ``UnsupportedRule``
instead of silently never matching, so a rule that cannot run is reported, not counted as
"no detection". ``check_rule`` gives that report without needing any event.

Known limits (documented, not hidden): no ``base64``/``base64offset`` modifiers, no
``timeframe``/aggregation conditions, no correlation rules, and backslash-escaping of literal
wildcards is not interpreted. Regexes come from rule files: treat untrusted rule sources
like untrusted code. Patterns are length-capped and fed truncated input to bound cost.
"""

from __future__ import annotations

import functools
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Mapping

import yaml


class UnsupportedRule(ValueError):
    """Raised when a rule uses Sigma features this evaluator does not implement."""


_SUPPORTED_MODIFIERS = {
    "contains", "startswith", "endswith", "all", "re", "windash", "cidr",
    "exists", "lt", "lte", "gt", "gte",
}  # fmt: skip
MAX_PATTERN_LEN = 1000
MAX_INPUT_LEN = 8192

#: Event fields PTAF's collectors populate. Rules using others cannot match (reported).
COLLECTED_FIELDS = {
    "Image", "CommandLine", "ParentImage", "ParentCommandLine", "User", "ProcessId",
    "ParentProcessId", "CurrentDirectory", "EventType", "UtcTime",
}  # fmt: skip


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


@functools.lru_cache(maxsize=2048)
def _compile(pattern: str) -> "re.Pattern[str]":
    if len(pattern) > MAX_PATTERN_LEN:
        raise UnsupportedRule(f"regex longer than {MAX_PATTERN_LEN} characters")
    try:
        return re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error as exc:
        raise UnsupportedRule(f"invalid regex: {exc}") from exc


def _glob_to_regex(glob: str) -> str:
    return "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in glob)


def _windash_variants(value: str) -> list[str]:
    swapped = re.sub(r"(^|\s)-", r"\1/", value)
    return [value] if swapped == value else [value, swapped]


def _match_value(actual: Any, kind: str, expected: Any) -> bool:
    if expected is None:
        return actual is None or actual == ""
    if actual is None:
        return False
    if kind in {"lt", "lte", "gt", "gte"}:
        try:
            a, e = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {"lt": a < e, "lte": a <= e, "gt": a > e, "gte": a >= e}[kind]
    if kind == "cidr":
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(
                str(expected), strict=False
            )
        except ValueError:
            return False
    a = str(actual)[:MAX_INPUT_LEN]
    if kind == "re":
        return _compile(str(expected)).search(a) is not None
    e = str(expected)
    if "*" in e or "?" in e:
        body = _glob_to_regex(e)
        pattern = {
            "contains": body,
            "startswith": "^" + body,
            "endswith": body + "$",
        }.get(kind, "^" + body + "$")
        return _compile(pattern).search(a) is not None
    a, e = a.lower(), e.lower()
    if kind == "contains":
        return e in a
    if kind == "startswith":
        return a.startswith(e)
    if kind == "endswith":
        return a.endswith(e)
    return a == e


def _eval_selection(selection: Any, event: Mapping[str, Any]) -> bool:
    if isinstance(selection, list):  # list of maps and/or keywords -> OR
        return any(_eval_selection(s, event) for s in selection)
    if isinstance(selection, (str, int, float)) and not isinstance(selection, bool):
        needle = str(selection).replace("*", "").lower()  # keyword: appears in any text field
        return any(needle in str(v).lower() for v in event.values() if isinstance(v, str))
    if not isinstance(selection, dict):
        raise UnsupportedRule("unsupported selection shape")
    for key, expected in selection.items():
        field, *mods = key.split("|")
        unknown = set(mods) - _SUPPORTED_MODIFIERS
        if unknown:
            raise UnsupportedRule(f"unsupported modifier(s): {sorted(unknown)}")
        if "exists" in mods:
            present = event.get(field) not in (None, "")
            if present != bool(expected):
                return False
            continue
        require_all = "all" in mods
        kind = next((m for m in mods if m not in {"all", "windash"}), "equals")
        values = _as_list(expected)
        if "windash" in mods:
            values = [v2 for v in values for v2 in _windash_variants(str(v))]
        results = [_match_value(event.get(field), kind, v) for v in values]
        if not (all(results) if require_all else any(results)):
            return False
    return True


def _validate_patterns(selection: Any) -> None:
    """Compile every ``|re`` pattern up front so a bad one is reported, not silently skipped."""
    if isinstance(selection, list):
        for item in selection:
            _validate_patterns(item)
    elif isinstance(selection, dict):
        for key, expected in selection.items():
            if "re" in key.split("|")[1:]:
                for value in _as_list(expected):
                    _compile(str(value))


def _selection_fields(selection: Any) -> set[str]:
    if isinstance(selection, list):
        return set().union(*[_selection_fields(s) for s in selection]) if selection else set()
    if isinstance(selection, dict):
        return {k.split("|")[0] for k in selection}
    return set()


_TOKEN = re.compile(r"\(|\)|[^\s()]+")


def _eval_condition(condition: str, selections: dict[str, bool]) -> bool:
    tokens = _TOKEN.findall(condition)
    pos = 0

    def peek() -> str | None:
        return tokens[pos].lower() if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def quantified(kind: str) -> bool:
        take()  # 'of'
        pattern = take()
        if pattern.lower() == "them":
            hits = list(selections.values())
        else:
            regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
            hits = [v for k, v in selections.items() if regex.match(k)]
        if not hits:
            raise UnsupportedRule(f"'{kind} of {pattern}' matches no selection")
        return all(hits) if kind == "all" else any(hits)

    def atom() -> bool:
        tok = peek()
        if tok is None:
            raise UnsupportedRule("unexpected end of condition")
        if tok == "not":
            take()
            return not atom()
        if tok == "(":
            take()
            value = disjunction()
            if peek() != ")":
                raise UnsupportedRule("unbalanced parentheses")
            take()
            return value
        word = take()
        if word.lower() in {"1", "all"} and peek() == "of":
            return quantified("all" if word.lower() == "all" else "1")
        if word not in selections:
            raise UnsupportedRule(f"condition references unknown selection '{word}'")
        return selections[word]

    def conjunction() -> bool:
        value = atom()
        while peek() == "and":
            take()
            value = atom() and value
        return value

    def disjunction() -> bool:
        value = conjunction()
        while peek() == "or":
            take()
            value = conjunction() or value
        return value

    result = disjunction()
    if pos != len(tokens):
        raise UnsupportedRule(f"unexpected token '{tokens[pos]}' in condition")
    return result


@dataclass
class Rule:
    """A parsed Sigma rule ready to be evaluated against flat event dicts."""

    id: str
    title: str
    level: str
    product: str | None
    category: str | None
    technique_ids: list[str]
    detection: dict[str, Any]
    path: str = ""

    @classmethod
    def from_yaml(cls, text: str, path: str = "") -> "Rule":
        data = yaml.safe_load(text)
        if not isinstance(data, dict) or "detection" not in data:
            raise UnsupportedRule("not a Sigma rule mapping")
        logsource = data.get("logsource") or {}
        tags = [str(t) for t in data.get("tags") or []]
        techniques = sorted(
            {
                t.split("attack.", 1)[1].upper()
                for t in tags
                if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t.lower())
            }
        )
        return cls(
            id=str(data.get("id", "")),
            title=str(data.get("title", "untitled")),
            level=str(data.get("level", "medium")),
            product=logsource.get("product"),
            category=logsource.get("category"),
            technique_ids=techniques,
            detection=data["detection"],
            path=path,
        )

    def applies_to(self, os_name: str) -> bool:
        """``os_name`` is one of windows / linux / macos."""
        return self.product is None or self.product.lower() == os_name

    def matches(self, event: Mapping[str, Any]) -> bool:
        detection = dict(self.detection)
        condition = detection.pop("condition", None)
        if not isinstance(condition, str):
            raise UnsupportedRule("only single-string conditions are supported")
        results = {name: _eval_selection(sel, event) for name, sel in detection.items()}
        return _eval_condition(condition, results)

    def fields_used(self) -> set[str]:
        return set().union(
            *[_selection_fields(sel) for k, sel in self.detection.items() if k != "condition"]
        )

    def unsupported_reason(self) -> str | None:
        """None if this evaluator can run the rule; otherwise why not. Needs no event."""
        try:
            for name, selection in self.detection.items():
                if name != "condition":
                    _validate_patterns(selection)
            self.matches({})
        except UnsupportedRule as exc:
            return str(exc)
        return None


@dataclass
class RuleCompat:
    """Static compatibility verdict for one rule file."""

    path: str
    title: str
    verdict: str  # runnable | partial | unsupported
    reasons: list[str]
    product: str | None
    category: str | None
    techniques: list[str]


def check_rule(rule: Rule) -> RuleCompat:
    """Can PTAF run this rule against the telemetry it collects? Honest, three-state."""
    reasons: list[str] = []
    problem = rule.unsupported_reason()
    if problem:
        return RuleCompat(rule.path, rule.title, "unsupported", [problem], rule.product,
                          rule.category, rule.technique_ids)  # fmt: skip
    verdict = "runnable"
    if rule.category not in (None, "process_creation"):
        verdict = "unsupported"
        reasons.append(f"needs '{rule.category}' telemetry; PTAF collects process_creation only")
    missing = sorted(rule.fields_used() - COLLECTED_FIELDS)
    if missing and verdict == "runnable":
        verdict = "partial"
        reasons.append(f"uses fields PTAF does not collect (will not match): {missing}")
    return RuleCompat(rule.path, rule.title, verdict, reasons, rule.product, rule.category,
                      rule.technique_ids)  # fmt: skip
