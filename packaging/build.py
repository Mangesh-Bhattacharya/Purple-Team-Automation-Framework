"""Build a single-file ptaf executable for the current OS.

    python packaging/build.py        ->  dist/ptaf  (dist/ptaf.exe on Windows)

Requires: pip install pyinstaller. Bundles the Sigma rules and dashboard page.
"""

from __future__ import annotations

import os
import pathlib
import subprocess  # nosec B404 - fixed argv
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SEP = os.pathsep  # PyInstaller's --add-data separator is ';' on Windows, ':' elsewhere


def main() -> int:
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--clean",
        "--noconfirm",
        "--name",
        "ptaf",
        "--add-data",
        f"{ROOT / 'modules' / 'defensive' / 'detection_rules'}{SEP}"
        "modules/defensive/detection_rules",
        "--add-data",
        f"{ROOT / 'ptaf' / 'dashboard.html'}{SEP}ptaf",
        "--paths",
        str(ROOT),
        "--distpath",
        str(ROOT / "dist"),
        "--workpath",
        str(ROOT / "build"),
        "--specpath",
        str(ROOT / "build"),
        str(ROOT / "packaging" / "ptaf_entry.py"),
    ]
    return subprocess.call(cmd)  # nosec B603 - constant argv, no shell


if __name__ == "__main__":
    raise SystemExit(main())
