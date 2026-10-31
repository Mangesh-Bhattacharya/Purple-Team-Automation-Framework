# PTAF Sentinel on Kali Linux

Kali is a first-class target: bare metal, VM (VMware, VirtualBox, Hyper-V, QEMU/KVM, UTM),
ARM (Raspberry Pi, Apple Silicon VMs), cloud images, WSL and containers. PTAF detects Kali from
`/etc/os-release` and adapts.

## Install (the PEP 668 way)

Current Kali refuses `pip install` into the system Python ("externally-managed-environment").
Do **not** use `--break-system-packages`. Use the installer, which makes a private virtualenv:

```bash
sudo apt install python3 python3-venv     # if missing; the installer tells you
git clone https://github.com/Mangesh-Bhattacharya/Purple-Team-Automation-Framework.git
cd Purple-Team-Automation-Framework
./packaging/install-kali.sh               # installs to ~/.local/share/ptaf, launcher in ~/.local/bin
./packaging/install-kali.sh --uninstall   # removes it again
```

It never touches system Python, starts no service, and runs `ptaf doctor` at the end.

## Run it as root for the best results

Kali's default user is not root, and that matters:

| | normal user | `sudo` |
|---|---|---|
| Sees other users' processes | no (largely blind: see `ptaf doctor`) | yes |
| Sensor | polling every 50 ms (misses short commands) | **event-driven kernel proc connector** |
| Offensive-tool canaries (`nmap`, `hydra`, ...) | skipped, with the reason shown | run |

```bash
sudo "$(command -v ptaf)" doctor
sudo "$(command -v ptaf)" selftest
sudo "$(command -v ptaf)" monitor --interval 3600
```

(`sudo` has its own PATH, hence `"$(command -v ptaf)"`. Root keeps its own state in `/root/.ptaf`.)

### Why the event-driven sensor

Offensive tools are often short-lived (`nmap --version`, `id`, `whoami`). A polling sensor misses
anything that lives less than its interval. The Linux **proc connector** is a kernel netlink
feed that reports every `exec()` the moment it happens, with no extra packages and no kernel
module. PTAF reads the command line immediately and tracks fork lineage so a canary's
descendants stay attributable even through shell subshells.

* `ptaf doctor` proves it works with a live probe (a subscribe call can succeed and still
  deliver nothing inside a container, so it is not taken on trust).
* `--collector auto|poll|procconn` (or `PTAF_COLLECTOR`). `auto` uses the event-driven sensor when
  it is genuinely available and **says why** when it falls back. Forcing `procconn` where it cannot
  work exits with code 3, never a silent downgrade.
* Containers and other non-initial PID namespaces cannot use it; PTAF reports that and polls.

## What it tests on Kali

Besides the portable canaries, each offensive tool you have installed gets a harmless canary that
runs the **real binary with a flag that only prints version or usage**: no scanning, no network,
no files. Each is paired with a Sigma rule you can adapt for production hosts.

| Tool | Technique | Rule |
|---|---|---|
| nmap, masscan | T1046 | network scanner executed |
| hydra | T1110.001 | online password guessing |
| john, hashcat | T1110.002 | offline password cracking |
| sqlmap, nikto | T1190 | web exploitation tool |
| gobuster | T1595.003 | content brute-forcing |
| tcpdump | T1040 | packet capture |

Canaries for tools that are not installed are skipped, never reported as gaps. Run
`ptaf canaries` to see the exact commands before anything runs.

**Why this is useful:** the rules are meant to be deployed on *production* hosts, where these
tools should never run. Kali is where you generate the activity; `ptaf selftest` on a target
host proves the rule fires there. On Kali itself the rules are intentionally noisy.

## Kali-specific checks in `ptaf doctor`

Kali version and architecture, which offensive tools are installed, whether you are on the
default non-root user (with the exact `sudo` command to fix it), the active sensor, and a live
smoke test of that sensor.

## Verification status (be skeptical, check CI)

* The proc-connector **wire-format parser**, lineage tracking, sensor selection, Kali detection
  and installer syntax are unit-tested on every OS.
* CI runs the real installer inside the official `kalilinux/kali-rolling` image (including its
  failure paths: no Python, no venv) and runs the live proc-connector tests plus the tool
  canaries as root on a real Ubuntu kernel. See the `kali` and `linux-root-sensor` jobs.
* **Not yet verified:** a physical Kali machine, ARM Kali, NetHunter, hardened/EDR-protected
  Kali, or Kali ISO live boot. The tool-canary Image names for script-based tools (sqlmap, nikto
  appear as `python3`/`perl` running the script) follow Kali's packaging and are modelled; the
  CI job exercises sqlmap for real.

## Limits

* Process-creation telemetry only. No network capture, no auditd/eBPF yet.
* Proc connector needs root and the initial PID namespace.
* `msfconsole`, `responder`, `impacket-*` and `netexec` are inventoried by `doctor` but have no
  canary yet (they are heavy or interactive to run harmlessly).
* Unsigned binaries; English only.
