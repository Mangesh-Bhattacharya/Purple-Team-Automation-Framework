#!/usr/bin/env bash
# Runs INSIDE the official kalilinux/kali-rolling image (see .github/workflows/ci.yml).
# Exercises the real Kali user journey, including the failure paths a new user will hit.
set -euo pipefail
cp -r /src /work && cd /work

echo "== 1. Kali identifies itself and PTAF recognises it"
grep -q '^ID=kali' /etc/os-release

apt-get update -qq

if ! command -v python3 >/dev/null; then
  echo "== 2. bare image has no python: the installer must say so clearly"
  if ./packaging/install-kali.sh 2>/tmp/e1; then echo "installer should have failed"; exit 1; fi
  grep -q "python3 not found" /tmp/e1
  apt-get install -y -qq python3 >/dev/null
fi

if ! python3 -c "import ensurepip, venv" 2>/dev/null; then
  echo "== 3. python without venv: the installer must tell the user the apt command"
  if ./packaging/install-kali.sh 2>/tmp/e2; then echo "installer should have failed"; exit 1; fi
  grep -q "python3-venv" /tmp/e2
  apt-get install -y -qq python3-venv >/dev/null
fi

echo "== 4. the PEP 668 trap (informational): why the installer uses a venv"
if python3 -m pip --version >/dev/null 2>&1; then
  if python3 -m pip install --dry-run pyyaml >/tmp/pep668 2>&1; then
    echo "pip into system python was allowed on this image"
  elif grep -qi "externally-managed" /tmp/pep668; then
    echo "confirmed: PEP 668 refuses plain pip install here"
  else
    echo "pip failed for another reason:"; tail -3 /tmp/pep668
  fi
fi

echo "== 5. install the offensive tools a Kali purple-team box has, then PTAF"
apt-get install -y -qq openssl nmap hydra sqlmap tcpdump >/dev/null
./packaging/install-kali.sh
export PATH="$HOME/.local/bin:$PATH"

echo "== 6. doctor, canaries, rules"
ptaf doctor || true
ptaf doctor --json-out | python3 -c "import json,sys; d={c['name']:c for c in json.load(sys.stdin)}; assert 'kali linux' in d, 'Kali not detected'; print('kali detected:', d['kali linux']['detail'])"
ptaf rules check --strict
ptaf canaries | head -20

echo "== 7. real self-test (container: polling sensor, so Kali tool canaries are skipped by design)"
ptaf selftest | tee /tmp/selftest.txt
grep -q "SKIPPED" /tmp/selftest.txt && echo "tool canaries correctly skipped under polling"
if grep -q "MISSED" /tmp/selftest.txt; then echo "a detection gap was reported on Kali"; exit 1; fi

echo "== 8. uninstall leaves no launcher behind"
./packaging/install-kali.sh --uninstall
test ! -e "$HOME/.local/bin/ptaf"
echo "KALI CONTAINER CHECKS PASSED"
