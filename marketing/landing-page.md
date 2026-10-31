# Landing page copy: PTAF Sentinel

*Beta software (v0.2.0), process-creation telemetry only [F3, L1]. Claim IDs are from `marketing/FACTS.md`; strip the bracketed IDs before publishing, but keep the sentences they support.*

---

## Hero

# Unit tests for your detection rules.

PTAF Sentinel runs harmless imitations of attacker behavior on a machine, runs your Sigma rules against that machine's own process telemetry, and tells you which behaviors were caught, which were missed, and which stopped being caught [F1].

**[View on GitHub]** &nbsp; Open source, MIT-licensed, no telemetry [F2]. Beta: v0.2.0, not yet released or on PyPI [F3].

---

## Three value blocks

### 1. Find silent failures
A rule that exists is not a rule that fires. Our own example PowerShell rule had a doubled backslash and could never match a real Windows path, and it passed syntax checks for weeks [S1]. PTAF reports caught, missed, and newly stopped being caught [F1].

### 2. Tell a rule gap from a blind sensor
"Missed" and "no telemetry" are different statuses with different exit codes. A blind sensor now exits 3 instead of 0, so it cannot pass a CI gate [S3]. `ptaf selftest` exits 0 (ok), 1 (gap or drift) or 3 (sensor problem), with JUnit output.

### 3. Bring your own Sigma rules
`ptaf rules check <dir>` says which of your rules PTAF can run, and why not for the rest. Across the 3,161 public SigmaHQ rules it loaded with 0 load errors [F17]; 1,304 of 1,383 process-creation rules (94%) are runnable [F18]. "Runnable" means PTAF can evaluate the rule, not that the rule is good [F18, L7].

---

## How it works

1. **Install and start.** Clone the repo, `pip install .`, run `ptaf up`. It starts the agent and a live dashboard [F22]. In one measured run on macOS the server was up in about 1.9 s and first real results arrived in about 10.8 s [F13].
2. **Safe tests run.** `ptaf canaries` lists exactly what will run. There are 19 canaries and 21 rules today. Run it only on systems you own or are authorized to test; its tests can trigger security alerts.
3. **Read the report.** Plain-English results of caught, missed, and drifted, updating live: 10 of 10 pushed updates arrived within 0.15 s in a local measurement [F14].

---

## Proof (what has actually been verified)

| Claim | Evidence |
|---|---|
| Runs the real canaries on Windows, macOS, Linux; Python 3.10 and 3.12 | CI [F10] |
| Works on real Kali Linux | kali-rolling container with installer [F11] |
| Event-driven sensor on a real Linux kernel | 9 of 9 canaries detected, including nmap, hydra, sqlmap, tcpdump [F12] |
| Memory stays flat | +1.3 MB over 800 short-lived processes, 90 s soak, measured locally [F15] |
| `ptaf up` starts and stops cleanly on Windows | CI test on a real Windows runner [F16] |
| In-browser Detection Lab matches the Python engine | 494 rule/event pairs plus all shipped rules [F20] |
| Test suite | 235 automated tests; lint and security scan clean [F21] |

A removed blocker: one field (OriginalFileName) was the only obstacle for 527 rules; supporting it takes runnable rules from 697 (50%) to 1,304 (94%) and defeats rename-the-binary evasion [F18, F19].

We found real bugs by running it, and say so: a normal `pip install` once shipped the agent with zero rules [S2]; the packaged Linux app silently failed every external-tool canary [S4]; Windows reported cmd.exe as "Cmd.Exe.MUI", which would have silently missed cmd.exe rules [S5].

We do not list customers, users, stars, downloads or testimonials, because we have none to claim.

---

## Honest limits

- Process-creation telemetry only; no network, file, registry or authentication rules yet [L1].
- On Windows and macOS the sensor polls every 50 ms and can miss very short-lived processes [L2].
- Tested on CI runners and one developer Mac, not on hardened or EDR-protected fleets, physical machines, ARM or NetHunter Kali [L3].
- Release apps are unsigned, so expect OS warnings [L4].
- English only; no central console yet [L5].
- A pass means one harmless test was caught by one rule on that machine at that time. It is not a security guarantee [L6].
- The 94% figure was not cross-checked against pySigma [L7].

PTAF Sentinel does not replace your SIEM or EDR.

---

## FAQ

**Is it AI?** No. The five analysis agents (Triage, Explain, Fix, Planner, Readiness) are rule-based and run locally.

**Does anything leave my machine?** No telemetry, and the agent makes no outbound network connections [F2].

**Will it set off my alerts?** It can. Use it only on systems you own or are authorized to test. `ptaf canaries` shows what runs without executing it.

**Is it production or enterprise-ready?** No. It is a beta [F3] with unsigned apps and no central console [L4, L5].

**What does a green result mean?** One harmless test was caught by one rule on that machine at that time [L6].

**Which platforms?** CI covers Windows, macOS and Linux [F10]; Kali is supported through an installer [F11]. See limits above [L3].

**Can I use my own rules?** Yes, Sigma rules, for process-creation behavior [F17, L1].

**What does it cost?** It is MIT-licensed open source [F2].

**Can I contribute or report bugs?** Yes, via the GitHub repository.

---

## Call to action

**[Try PTAF Sentinel on GitHub]** (https://github.com/Mangesh-Bhattacharya/Purple-Team-Automation-Framework)

```
git clone https://github.com/Mangesh-Bhattacharya/Purple-Team-Automation-Framework.git
cd Purple-Team-Automation-Framework
python3 -m venv .venv && . .venv/bin/activate
pip install .
ptaf up
```

Beta software. Use only on systems you own or are authorized to test.
