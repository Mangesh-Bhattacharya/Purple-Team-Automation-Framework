# Verified facts ledger (the ONLY source marketing may draw claims from)

Every claim below was verified in this repository's CI or by a measured run. IDs let reviewers check copy
line by line. If it is not here, it cannot be claimed. Last updated 2026-10-31.

## What it is
- F1  PTAF Sentinel runs harmless imitations of attacker behavior on a machine, runs Sigma rules against that
      machine's own process telemetry, and reports which behaviors were caught, missed, or newly stopped being caught.
- F2  MIT-licensed, open source, Python. No telemetry; the agent makes no outbound network connections.
- F3  Status: v0.2.0, **beta**. Tagged v0.2.0 and published as a GitHub prerelease (Linux x86_64, macOS arm64, Windows x86_64 binaries + SHA256 checksums); not on PyPI; release apps are unsigned.

## Verified results
- F10 CI runs the real canaries on Windows, macOS and Linux, Python 3.10 and 3.12.
- F11 Works on a real Kali Linux image (kali-rolling container, installer included).
- F12 On a real Linux kernel with the event-driven sensor, 9 of 9 canaries were detected, including real nmap, hydra, sqlmap, tcpdump.
- F13 Fresh install to live dashboard: server up in ~1.9 s, first real results in ~10.8 s (measured once, macOS).
- F14 Live updates: 10 of 10 pushed updates arrived within 0.15 s, median 0.08 s (measured locally).
- F15 Memory stayed flat: +1.3 MB across 800 short-lived processes in a 90 s soak (measured locally).
- F16 `ptaf up` starts and cleanly stops on a real Windows runner (CI test).
- F17 Rule checker over all 3,161 public SigmaHQ rules (commit 05d1031): 0 load errors, 10.5 s.
- F18 Of 1,383 SigmaHQ process-creation rules, 1,304 (94%) are "runnable" by PTAF (was 697 / 50% before it learned
      Windows version-resource fields). "Runnable" = PTAF can evaluate the rule; NOT that the rule is good.
- F19 One field (OriginalFileName) was the only blocker for 527 of those rules; it defeats rename-the-binary evasion.
- F20 The in-browser Detection Lab agrees with the Python engine on 494 rule/event pairs and all shipped rules.
- F21 235 automated tests; lint and security scan clean.

## Real bugs found by actually running it (honest stories)
- S1  The example PowerShell rule had a doubled backslash and could never match a real Windows path; it passed
      syntax checks for weeks. Found the first time the rules were actually executed.
- S2  A normal `pip install` shipped the agent with zero rules (they lived outside the package).
- S3  A blind sensor exited 0 and could have passed a CI gate; now it exits 3.
- S4  The packaged Linux app silently failed every external-tool canary: PyInstaller's library path made tools exit 127.
- S5  On Windows the API reported cmd.exe's original name as "Cmd.Exe.MUI", so rules for cmd.exe would have silently missed.
- S6  A one-file macOS app took ~14 s to start on every command (re-scanned each launch); the folder build starts in ~0.3 s.

## Features that exist today
`ptaf up` (agent + live dashboard, one command) · `selftest` (exit 0 ok / 1 gap or drift / 3 sensor problem, JUnit) ·
`doctor` · `canaries` (lists exactly what runs) · `rules check` · kill-chain explorer with a playable story ·
five rule-based local analysis agents (NOT an AI model) · browser Detection Lab · fleet view from exported
summaries · token-protected dashboard · Kali installer and Kali-tool canaries · 19 canaries, 21 rules.

- F22 Shipped features are exactly the list above; verified in code: `CANARIES` has 19 entries and `ptaf/rules/` has 21 rule files; `ptaf canaries` lists what runs.
- F23 README legal notice: "Use PTAF only on systems you own or are authorized to test. Its tests can trigger security alerts."
- F25 Services are priced in USD in docs/PRICING.md ($149 / $790 / $49-149 per month / $390); the software stays free (MIT). Prices are untested starting points.
- F24 README premise: detection rules fail silently; a quiet dashboard proves nothing. This is the project's stated premise, NOT a measured statistic about breaches.

## Limits that must be said (never omit when making broad claims)
- L1 Process-creation telemetry only. L2 Windows/macOS sensor polls every 50 ms and can miss very short-lived processes.
- L3 Tested on CI runners and one developer Mac; NOT on hardened/EDR-protected fleets, physical machines, ARM or NetHunter Kali.
- L4 Unsigned release apps (OS warnings). L5 English only; no central console yet.
- L6 A passing result means one harmless test was caught by one rule on that machine at that time; it is not a security guarantee.
- L7 The 94% figure was not cross-checked against pySigma.

## NOT true (do not claim, ever)
Customers, users, stars, downloads, testimonials, awards, partnerships, "AI-powered", "enterprise-ready", "zero false
positives", "complete coverage", "replaces your SIEM/EDR", "certified", "SOC 2", any pricing already in effect.
