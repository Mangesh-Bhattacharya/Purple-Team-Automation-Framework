#!/usr/bin/env bash
#
# PTAF Sentinel installer for Kali Linux (also fine on Debian/Ubuntu and other Linux).
#
# Why a script: current Kali (like Debian 12+) enforces PEP 668, so `pip install` into the
# system Python is refused ("externally-managed-environment"). This installs into a private
# virtualenv and puts a `ptaf` launcher in ~/.local/bin. It never modifies system Python.
#
#   ./packaging/install-kali.sh              # install for the current user
#   ./packaging/install-kali.sh --uninstall  # remove everything it created
#
# It does not start any service and makes no network connection except fetching Python
# packages from PyPI during install (use --offline with a pre-populated wheel dir, see below).
#
set -euo pipefail

PREFIX="${PTAF_PREFIX:-$HOME/.local/share/ptaf}"
BIN_DIR="${PTAF_BIN_DIR:-$HOME/.local/bin}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WHEELS=""

say() { printf '==> %s\n' "$*"; }
die() { printf 'ptaf-install: %s\n' "$*" >&2; exit 1; }

case "${1:-}" in
  --uninstall)
    rm -rf "$PREFIX" "$BIN_DIR/ptaf"
    say "Removed $PREFIX and $BIN_DIR/ptaf (state in ~/.ptaf is kept; delete it yourself if wanted)"
    exit 0 ;;
  --offline)
    WHEELS="${2:?--offline needs a directory of wheels}"
    [ -d "$WHEELS" ] || die "wheel directory not found: $WHEELS" ;;
  "" ) ;;
  *) die "unknown option: $1" ;;
esac

# --- environment checks -----------------------------------------------------
if [ -r /etc/os-release ]; then . /etc/os-release; fi
say "Detected: ${PRETTY_NAME:-unknown Linux} ($(uname -m))"
[ "$(uname -s)" = "Linux" ] || die "this installer is for Linux; see README for macOS/Windows"

command -v python3 >/dev/null || die "python3 not found. On Kali: sudo apt install python3"
python3 - <<'PY' || die "Python 3.10+ is required"
import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)
PY

# venv needs the python3-venv package on Debian-family systems (Kali included).
if ! python3 -c "import venv, ensurepip" 2>/dev/null; then
  die "python3-venv is missing. Run:  sudo apt install python3-venv   then re-run this script"
fi

# --- install ----------------------------------------------------------------
say "Creating virtualenv in $PREFIX"
python3 -m venv "$PREFIX/venv"
PIP="$PREFIX/venv/bin/pip"
"$PIP" install --quiet --upgrade pip || true   # an old pip is not fatal offline

say "Installing PTAF Sentinel"
if [ -n "$WHEELS" ]; then
  "$PIP" install --quiet --no-index --find-links "$WHEELS" "$SRC"
else
  "$PIP" install --quiet "$SRC"
fi

mkdir -p "$BIN_DIR"
ln -sf "$PREFIX/venv/bin/ptaf" "$BIN_DIR/ptaf"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) say "NOTE: $BIN_DIR is not on your PATH. Add:  export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

say "Installed. Verifying with the built-in preflight:"
"$BIN_DIR/ptaf" doctor || true

cat <<'EOF'

Next steps
  ptaf canaries                 list exactly what a self-test will execute
  ptaf selftest                 run the benign canaries once
  sudo "$(command -v ptaf)" selftest
                                as root: event-driven sensor + full process visibility
                                (root keeps its own state in /root/.ptaf, separate from yours)
  ptaf dashboard                plain-English dashboard on http://127.0.0.1:8787
  ptaf service --os linux       print a systemd unit to review (nothing is installed for you)

Tip (Kali): as the default non-root user the agent cannot read other users' command lines.
`ptaf doctor` shows how much it is missing; run it with sudo for production-grade visibility.
EOF
