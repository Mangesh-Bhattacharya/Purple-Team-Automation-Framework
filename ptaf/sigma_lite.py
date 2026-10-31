"""Minimal, dependency-light Sigma rule evaluator.

Supports the subset of Sigma that process-creation rules need:

* selections made of ``field|modifier: value-or-list`` maps
* modifiers: ``contains``, ``startswith``, ``endswith``, ``all`` (and plain equality)
* a list of values is OR'd (or AND'd with the ``all`` modifier)
* ``condition`` with ``and`` / ``or`` / ``not`` / parentheses / ``1 of x*`` / ``all of x*``

Matching is case-insensitive, like Sigma. Anything unsupported raises
``UnsupportedRule`` instead of silently never matching, so a broken rule is
reported loudly rather than counted as "no detection".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

import yaml


class UnsupportedRule(ValueError):
    """Raised when a rule uses Sigma features this evaluator does not implement."""


_SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all"}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _match_value(actual: Any, modifier: str, expected: Any) -> bool:
    if actual is None:
        return expected is None
    a, e = str(actual).lower(), str(expected).lower()
    if modifier == "contains":
        return e in a
    if modifier == "startswith":
        return a.startswith(e)
    if modifier == "endswith":
        return a.endswith(e)
    return a == e


def _eval_selection(selection: Any, event: Mapping[str, Any]) -> bool:
    if isinstance(selection, list):  # list of maps -> OR
        return any(_eval_selection(s, event) for s in selection)
    if not isinstance(selection, dict):
        raise UnsupportedRule("keyword/string selections are not supported")
    for key, expected in selection.items():
        field, *mods = key.split("|")
        unknown = set(mods) - _SUPPORTED_MODIFIERS
        if unknown:
            raise UnsupportedRule(f"unsupported modifier(s): {sorted(unknown)}")
        require_all = "all" in mods
        kind = next((m for m in mods if m != "all"), "equals")
        results = [_match_value(event.get(field), kind, v) for v in _as_list(expected)]
        if not (all(results) if require_all else any(results)):
            return False
    return True


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
