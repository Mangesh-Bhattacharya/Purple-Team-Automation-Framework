# PTAF Sentinel for organizations

This page maps the problems practitioners and security teams report to what PTAF does about
them, how to deploy and approve it, and, just as important, what it does **not** do yet.

## The problems, and what we built

Research (vendor and practitioner write-ups; these are indicative, not authoritative, and the
figures vendors quote were not independently verified) points to the same recurring pain
points. Each row says what PTAF does and where it is honest about a gap.

| Problem teams report | What PTAF does | Status |
|---|---|---|
| **Detections silently stop working** (rule edits, log pipeline or parser changes, EDR updates) while the dashboard stays quiet | Runs harmless canaries, runs your Sigma rules against the host's real telemetry, raises `detection_drift` when something that used to fire stops | Shipped |
| **Cannot tell a rule gap from a sensor/collection problem** (log collection issues are widely cited as a leading cause of detection failure) | Separate statuses: `missed` (rule gap) vs `no_telemetry`/`error` (sensor problem) with different exit codes; `ptaf doctor` measures how much the sensor can actually see | Shipped |
| **A green dashboard hides a blind sensor** | `doctor` reports the share of processes the agent cannot read and runs a live smoke test of its own collector | Shipped |
| **Alert fatigue; SOC resents unlabelled test traffic** | `ptaf canaries` lists every command before it runs; shell/Python/PowerShell canaries carry the tag `ptaf-canary` so a SOC can filter or label them; the monitor marks canary-caused alerts `synthetic: true` | Shipped; see limits |
| **Existing tools are heavy**: Atomic Red Team is PowerShell-centric and harder on Linux/macOS; Caldera has heavy setup and dependency problems | One Python codebase, no kernel driver, no admin rights required, optional single-file executables | Shipped (unsigned) |
| **Sigma support differs between tools** (unsupported modifiers, missing field mappings) | `ptaf rules check <dir>` says which of *your* rules are runnable, partial (use fields PTAF does not collect) or unsupported, and why | Shipped |
| **Detection-as-code needs CI integration** | Stable exit codes, `--format junit`, `--only/--skip`, JSON everywhere | Shipped |
| **Operational safety**: agents that leak memory, fill disks, crash on one bad file, or double-run | Bounded memory, rotated logs, private state dir, single-instance lock, a bad rule file is reported not fatal, collector survives callback errors | Shipped (found and fixed by running it; see below) |

## Exit codes (stable)

`ptaf selftest`:

| Code | Meaning |
|---|---|
| 0 | every runnable canary detected, no drift |
| 1 | a detection **gap** or drift was found |
| 2 | usage error (bad option, unknown canary id, interval under 30 s) |
| 3 | **sensor problem**: a canary produced no telemetry or could not run (this is not a rule gap) |
| 4 | another monitor already holds the state-directory lock (`monitor` only) |

A real gap (1) outranks a sensor problem (3) when both occur.

## Before you deploy

1. `ptaf doctor`: preflight. **Read the process-visibility line.** Run as a normal user, an
   agent cannot read other users' command lines, so it is partly blind to system activity.
   On the machine this guide was developed on, 40% of processes were unreadable as a normal
   user. For production coverage run the agent as root/Administrator (or with the platform's
   process-inspection rights), then re-run `doctor`.
2. `ptaf canaries`: print exactly what will execute. Attach this to your change request.
3. `ptaf rules check <your-rules-dir> --strict`: know which rules will actually run.
4. `python packaging/verify_install.py --rounds 3 --soak 90`: repeated end-to-end rounds plus a
   soak of the live agent under process churn, on the target machine. Exit 0 only if everything
   passed. Makes no network connections.

## Getting your SOC to accept the test traffic

Test activity that looks like an attack will alert unless it is labelled. PTAF cannot decide your
SIEM policy, but it gives you the handles:

* The tag `ptaf-canary` appears in the command line of the shell, Python and PowerShell
  canaries. Filter or label on `CommandLine contains "ptaf-canary"`. Children spawned by those
  shells (e.g. `base64 -d`) do not carry the tag; correlate by parent.
* Not every canary can carry a tag (the encoded-PowerShell, `systeminfo`, `tasklist` and
  `osascript` canaries run real binaries whose command line we do not control). Allowlist by
  parent process / host / time window as your policy prefers.
* Be careful: broad allowlists for test traffic are themselves a risk. Prefer narrow, time-boxed
  rules scoped to the hosts that run the agent.
* `--skip <id>` removes any canary your policy does not accept.

## Operating notes

* State: `~/.ptaf` or `$PTAF_HOME`, private (0700) on POSIX. Alerts include command lines,
  which can contain secrets; treat the directory as sensitive.
* Logs rotate at 10 MB and keep 3 generations (`alerts.jsonl`, `history.jsonl`).
* One monitor per state directory; a second exits with code 4.
* Run a filtered selftest (`--only/--skip`) any time: it does not overwrite the baseline, so it
  cannot hide drift.
* PTAF makes **no network connections**.

## What it does not do yet (read this)

* **Verified on GitHub-hosted runners and one developer Mac, not on hardened, EDR-protected or
  domain-joined fleets.** Behaviour there may differ, which is the reason to run it there.
* The collector **polls** (50 ms) so it can miss processes shorter than that. Native Sysmon,
  auditd and macOS Endpoint Security collectors are not built yet.
* Only **process-creation** telemetry. Network, file, registry, authentication and cloud rules
  are reported as unsupported by `rules check`, not silently ignored.
* Sigma subset: no `base64`/`base64offset`, no aggregation/`timeframe`, no correlation rules.
  Rules referencing fields PTAF does not collect (e.g. `OriginalFileName`) are `partial`.
* Coverage % counts only techniques that have a canary (10 today).
* No central console: each host reports locally. Fleet aggregation is the next major piece.
* Release executables are **unsigned** (Gatekeeper / SmartScreen will warn).
* English only.
* Not a replacement for a full adversary-emulation platform: canaries imitate the *shape* of
  behaviour with harmless commands, not real attack chains.

## Problems found by running it, not by reading it

Being straight about what verification caught is part of the product's credibility:

* The shipped PowerShell rule had a doubled backslash and could never match a Windows path.
* Windows' default text encoding broke file reads.
* A fork-vs-exec race hid a process's real command line from the collector.
* The collector's seen-process table grew without bound in a long-running agent (memory leak).
* A single malformed rule file crashed the whole agent at startup.
* A blind sensor exited 0, so it could have passed a CI gate.
* A frozen executable ran a canary under the wrong process name and falsely reported a gap.
