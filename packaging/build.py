"""Build a self-contained ptaf application for the current OS.

    python packaging/build.py            ->  dist/ptaf        one file (dist/ptaf.exe on Windows)
    python packaging/build.py --onedir   ->  dist/ptaf/ptaf   a folder (ship it zipped)

Which to use: ``--onefile`` unpacks ~10 MB into a fresh temp folder on EVERY launch. On macOS that
made every command take ~14 s (measured, even ``--version``) because the OS re-scans the newly
written, unsigned libraries each time. ``--onedir`` pays that cost once, on the first launch, then
runs in ~0.3 s. Use ``--onedir`` for macOS; ``--onefile`` is fine on Linux.

Requires: pip install pyinstaller. Bundles the Sigma rules and the dashboard page.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess  # nosec B404 - fixed argv
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SEP = os.pathsep  # PyInstaller's --add-data separator is ';' on Windows, ':' elsewhere


def build_command(onedir: bool = False) -> list[str]:
    return [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onedir" if onedir else "--onefile",
        "--clean",
        "--noconfirm",
        "--name",
        "ptaf",
        "--add-data",
        f"{ROOT / 'ptaf' / 'rules'}{SEP}ptaf/rules",
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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--onedir", action="store_true", help="build a folder (fast launches on macOS)")
    args = ap.parse_args(argv)
    return subprocess.call(build_command(args.onedir))  # nosec B603 - constant argv, no shell


if __name__ == "__main__":
    raise SystemExit(main())
