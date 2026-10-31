"""Windows defaults to cp1252; every text file read/write must name its encoding."""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATTERN = re.compile(r"\.(read_text|write_text)\(|\.open\(")


def _calls(path: pathlib.Path):
    text = path.read_text(encoding="utf-8")
    for match in PATTERN.finditer(text):
        # take the call up to its matching close paren
        depth, i = 0, match.end() - 1
        while i < len(text):
            depth += text[i] == "("
            depth -= text[i] == ")"
            if depth == 0:
                break
            i += 1
        yield text.count("\n", 0, match.start()) + 1, text[max(0, match.start() - 12) : i + 1]


def test_every_text_io_call_declares_an_encoding():
    offenders = []
    for path in sorted((ROOT / "ptaf").glob("*.py")):
        for line, call in _calls(path):
            if "encoding=" not in call and "Popen" not in call and "webbrowser" not in call:
                offenders.append(f"{path.name}:{line}: {call[:60]}")
    assert not offenders, "missing encoding=: " + "; ".join(offenders)
