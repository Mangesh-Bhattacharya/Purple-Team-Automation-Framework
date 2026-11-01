# The bug that would have made every cmd.exe rule silently useless

*PTAF Sentinel v0.2.0 (beta). Process-creation telemetry only. Synthetic voice used in the companion video.*

Detection rules fail quietly. A rule is edited, a log pipeline breaks, an EDR update changes what it reports, and nothing errors. The dashboard just stays quiet, and quiet looks like safe.

I built PTAF Sentinel to make that failure loud. It runs harmless imitations of attacker behavior on a machine, runs your Sigma rules against that machine's own process telemetry, and tells you which behaviors were caught, missed, or newly stopped being caught. It is open source (MIT) and it makes no outbound network connections.

## The bug

On Windows, the API reported the original name of `cmd.exe` as `Cmd.Exe.MUI`. Sigma rules, and Sysmon, expect `Cmd.Exe`. A rule keyed on the original file name of `cmd.exe` would have silently missed it. Nothing would have errored.

We found it because CI runs the real canaries on real Windows, macOS and Linux runners, not because anyone read the code. The fix strips the `.MUI` suffix. The same field is also the one that defeats the classic "rename the binary" trick: `cmd.exe` copied to `notes.txt.exe` still reports `Cmd.Exe`.

That one field was the only blocker for 527 of the 1,383 SigmaHQ process-creation rules. With it, 1,304 of those 1,383 (94%) are now runnable by PTAF. "Runnable" means PTAF can evaluate the rule. It does not mean the rule is good, and I have not cross-checked the 94% against pySigma.

## What you can run today

```
pip install .
ptaf up
```

That starts the agent and a live dashboard. In one measured run on macOS the server was up in about 1.9 seconds and the first real results arrived in about 10.8 seconds. `ptaf selftest` exits 0 when everything is caught, 1 for a gap or drift, and 3 when the sensor itself is blind, so a blind sensor can no longer pass a CI gate.

## What it is not

- It tests process creation only.
- Windows and macOS sensors poll every 50 ms and can miss very short-lived processes.
- It has been tested on CI runners and one developer Mac, not on hardened or EDR-protected fleets, physical machines, ARM or NetHunter Kali.
- Release apps are unsigned, so your OS will warn you.
- The five analysis agents on the dashboard are rule-based, not an AI model.
- A pass means one harmless test was caught by one rule on that machine at that time. It is not a security guarantee.

Use it only on systems you own or are authorized to test. Its tests can trigger security alerts.

## Get it

- Code and v0.2.0 prerelease: https://github.com/Mangesh-Bhattacharya/Purple-Team-Automation-Framework
- The software is free. If you want help, optional paid services start at USD 149: see [docs/PRICING.md](../PRICING.md).

Feedback and bug reports are welcome as GitHub issues.
