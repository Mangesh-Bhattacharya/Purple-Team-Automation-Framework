"""Install PTAF into a throwaway virtualenv and prove the INSTALLED package works.

Running tests from a source checkout hides packaging bugs: this once shipped an agent with zero
Sigma rules because they lived outside the package. This script builds a clean venv, installs the
project the way a user would (non-editable), changes to an unrelated directory, and checks that the
rules, dashboard page and CLI all work.

    python packaging/check_wheel.py
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - fixed argv built from this script's own paths
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIN_RULES = 21


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603 - constant argv, no shell
        cmd,
        capture_output=True,
        text=True,
        cwd=cwd,
        check=False,
        encoding="utf-8",
        errors="replace",
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ptaf-wheel-") as tmp:
        env_dir, away = Path(tmp) / "venv", Path(tmp) / "elsewhere"
        away.mkdir()
        venv.create(env_dir, with_pip=True)
        bindir = env_dir / ("Scripts" if sys.platform == "win32" else "bin")
        py = bindir / ("python.exe" if sys.platform == "win32" else "python")
        ptaf = bindir / ("ptaf.exe" if sys.platform == "win32" else "ptaf")

        install = run([str(py), "-m", "pip", "install", "--quiet", str(ROOT)])
        if install.returncode:
            print("pip install failed:\n" + install.stderr[-800:])
            return 1

        problems: list[str] = []
        check = run([str(ptaf), "rules", "check", "--json-out"], cwd=away)
        try:
            counts = json.loads(check.stdout)["counts"]
            if counts["runnable"] < MIN_RULES:
                problems.append(
                    f"only {counts['runnable']} rules shipped in the install (want {MIN_RULES}+)"
                )
        except (ValueError, KeyError):
            problems.append(
                f"`ptaf rules check` produced no usable output: {check.stdout[-200:]}{check.stderr[-200:]}"
            )
        if run([str(ptaf), "--version"], cwd=away).returncode:
            problems.append("`ptaf --version` failed")
        out = away / "report.html"
        dash = run([str(ptaf), "dashboard", "--demo", "--export", str(out)], cwd=away)
        if dash.returncode or "PTAF Sentinel" not in (
            out.read_text(encoding="utf-8") if out.exists() else ""
        ):
            problems.append("the dashboard page was not shipped in the install")
        canaries = run([str(ptaf), "canaries", "--json-out"], cwd=away)
        if canaries.returncode:
            problems.append("`ptaf canaries` failed")

        for p in problems:
            print("FAIL:", p)
        if not problems:
            print(
                f"installed package OK: {counts['runnable']} rules, dashboard and CLI work from an unrelated directory"
            )
        return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
