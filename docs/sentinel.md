# PTAF Sentinel: continuous detection assurance

Most detection engineering fails silently: a rule is edited, a log pipeline
breaks, an EDR update changes behavior, and nobody finds out until an incident.
Sentinel runs on the endpoint, fires **benign canary behaviors**, watches the
host's own telemetry, and checks that the Sigma rules you ship actually fire.

```bash
pip install -e .
ptaf info                 # OS / arch / VM / container fingerprint
ptaf selftest             # run canaries once; exit 1 on a gap or drift (CI-friendly)
ptaf monitor --interval 3600   # agent: live rule matching + hourly self-test + drift alerts
ptaf export navigator > layer.json   # open at mitre-attack.github.io/attack-navigator
ptaf export badge > badge.json       # shields.io endpoint badge
ptaf dashboard            # plain-English dashboard on http://127.0.0.1:8787 (add --demo for sample data)
ptaf dashboard --export report.html   # one self-contained file to send to a client
ptaf service --os linux   # print a systemd unit / launchd plist / schtasks command to review
```

## Run it as an application (no Python needed)

`python packaging/build.py` builds a single self-contained `dist/ptaf` for the OS you run it on
(`dist/ptaf.exe` on Windows). Tagging a release (`v*`) builds Linux, macOS and Windows binaries
in CI, smoke-tests each with real canaries, and attaches them with SHA-256 checksums.
Binaries are **not code-signed yet**: macOS Gatekeeper and Windows SmartScreen will warn, so
verify the checksum, or build from source. Canaries that need an interpreter (the Python one)
are skipped, never counted as gaps, when none is installed.

State and alerts live in `~/.ptaf` (override with `PTAF_HOME`): `alerts.jsonl`,
`history.jsonl`, `state.json`, `badge.json`, `navigator_layer.json`.

## What a result means

| Status | Meaning |
|---|---|
| `detected` | A rule mapped to the technique fired on the canary's telemetry |
| `missed` | Telemetry was seen, no mapped rule fired: a **real gap** |
| `no_telemetry` | The collector saw nothing: a **sensor** problem, not a rule gap |
| drift | Was `detected` last run, is not now: something regressed |

The Navigator layer is three-state so it cannot overstate coverage: green =
verified by a canary, yellow = a rule exists but nothing has tested it, red =
proven gap.

## Platforms and VMs

One Python codebase; CI runs the real canaries on Ubuntu, Windows and macOS.
Host fingerprinting recognises VMware, VirtualBox, KVM/QEMU, Hyper-V, Parallels,
Xen, AWS EC2, GCE, and Docker/Podman/Kubernetes/WSL containers. The collector
needs no admin rights or kernel driver.

## Safety model

Canaries only launch no-op local processes shaped like the real thing (sleep,
or decode a random string to nowhere). No network, no file writes, no
credentials, no persistence. `tests/test_sentinel.py` enforces this with a
forbidden-token check on every canary's argv. Service files are printed for
review, never installed automatically.

## Known limits (read before relying on it)

* The default collector **polls** the process table (50 ms), so it cannot see
  processes shorter than that. Canaries are built to live ~1 s. Sysmon / auditd /
  Endpoint Security collectors should implement the same event shape.
* Only process-creation rules are evaluated so far. Sigma support is a subset
  (`contains/startswith/endswith/all`, `and/or/not`, `1 of x*`); unsupported
  rules raise loudly instead of silently never matching.
* 10 canaries and 15 rules ship today (Windows 4, Linux/macOS 5 shared + 1 macOS-only).
  Coverage % is only over techniques that have a canary.
* Verification status, stated plainly: CI runs the real canaries on GitHub-hosted Ubuntu,
  Windows and macOS runners (Python 3.10 and 3.12) and all pass. That is hosted VMs, not a
  fleet: results on hardened or EDR-protected endpoints may differ, which is the point of
  running it there. A missed canary is retried once; a retry-only success is flagged.
