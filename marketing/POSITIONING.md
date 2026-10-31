# PTAF Sentinel: Positioning

Every claim carries a ledger ID from `marketing/FACTS.md`. Status: v0.2.0 **beta** [F3]. Broad claims carry limits [L1-L7].

## One-line pitch (13 words)

Unit tests for your detection rules: find out which ones actually fire. [F1]

## Description (2 sentences)

PTAF Sentinel runs harmless imitations of attacker behavior on a machine, runs Sigma rules against that machine's own process telemetry, and reports which behaviors were caught, missed, or newly stopped being caught [F1]. It is MIT-licensed, open source, makes no outbound network connections from the agent, and is currently a beta (v0.2.0) limited to process-creation telemetry [F2, F3, L1].

## Audience personas

### 1. Detection engineer
- **Pain:** Rules can pass syntax checks and still never match. Our own example PowerShell rule had a doubled backslash and could never match a real Windows path; it passed syntax checks for weeks [S1].
- **What we show them:** `ptaf rules check <dir>` reports which of their Sigma rules PTAF can run; on the public SigmaHQ set, 1,304 of 1,383 process-creation rules (94%) are runnable and the checker loaded all 3,161 public rules with 0 load errors [F17, F18, L7]. `ptaf selftest` exits 0 / 1 / 3 (ok / gap or drift / blind sensor) with JUnit output, so it can gate CI [S3, F22]. The browser Detection Lab matches the Python engine on 494 rule/event pairs [F20].
- **Honest limit that matters:** "Runnable" means PTAF can evaluate the rule, not that the rule is good [F18]. Process-creation only: no network, file, registry or authentication rules [L1]. The 94% was not cross-checked against pySigma [L7].

### 2. SOC lead / CISO
- **Pain:** Quiet dashboards look like safety; a broken pipeline or changed EDR report produces no error [F24; F1].
- **What we show them:** A plain-English list of what was caught, missed, and what stopped being caught [F1]. "Missed" (rule wrong) and "no telemetry" (sensor blind) are separate statuses; a blind sensor now exits 3 so it cannot pass a gate [S3]. Memory stayed flat (+1.3 MB over 800 short-lived processes, 90 s soak, measured locally) [F15].
- **Honest limit that matters:** A pass means one harmless test was caught by one rule on that machine at that time; it is not a security guarantee [L6]. Not tested on hardened or EDR-protected fleets, physical machines, ARM or NetHunter Kali [L3]. No central console yet; English only [L5].

### 3. Consultant / MSSP
- **Pain:** Needing repeatable, explainable evidence for a client that a specific detection fired.
- **What we show them:** Open-source, MIT-licensed [F2]; 19 canaries and 21 rules, and `ptaf canaries` lists exactly what will run before anything executes [F22]. Fleet view merges exported summaries [F22]. Works on real Kali (installer included) [F11].
- **Honest limit that matters:** Release apps are unsigned and trigger OS warnings [L4]. No central console [L5]. Tests can trigger alerts in the client's SOC, so written authorization is needed [F23].

## Message pillars

1. **Verify, do not assume.** Each result is a specific harmless test caught (or not) by a specific rule on this machine [F1, L6].
2. **Rule gap versus blind sensor.** Different statuses and exit codes; a blind sensor exits 3, not 0 [S3, F22].
3. **Tested by actually running it.** CI runs the real canaries on Windows, macOS, Linux, Python 3.10 and 3.12 [F10]; on a real Linux kernel with the event-driven sensor, 9 of 9 canaries were detected including real nmap, hydra, sqlmap, tcpdump [F12, L3].
4. **Honest about its own bugs.** We publish what running it exposed: [S1] through [S6], e.g. a pip install that shipped zero rules [S2] and a Windows name quirk that would have silently missed cmd.exe rules [S5].
5. **Local, open, quick to try.** MIT, no telemetry, no outbound connections from the agent [F2]; server up in ~1.9 s and first real results in ~10.8 s, measured once on macOS [F13]; live updates within 0.15 s for 10 of 10 pushes [F14].

Every pillar is subject to: beta [F3], process-creation only [L1], limited test environments [L3].

## Objections and honest answers

| Objection | Honest answer |
|---|---|
| "Is it just Atomic Red Team?" | We make no comparison claims about other tools; the ledger holds no facts about them. What PTAF does: runs harmless imitations, evaluates Sigma rules on local process telemetry, and reports caught / missed / newly stopped [F1], and separates rule gaps from a blind sensor [S3]. Process-creation only [L1]. |
| "Will it trigger my SOC?" | It can. Its tests can trigger security alerts, so run it only on systems you own or are authorized to test [F23]. `ptaf canaries` lists exactly what runs without executing anything [F22]. |
| "Is it AI?" | No. The five analysis agents (Triage, Explain, Fix, Planner, Readiness) are rule-based and local, not an AI model [F22]. |
| "Is it enterprise-ready?" | No. It is a v0.2.0 beta, not yet released or on PyPI, with unsigned apps and no central console [F3, L4, L5]. It has not been tested on hardened or EDR-protected fleets [L3]. |
| "Does a pass mean I am protected?" | No [L6]. |
| "Does it see network or registry activity?" | Not yet; process-creation only, and unsupported rule types are reported rather than ignored [L1]. |
| "Can it miss fast processes?" | Yes. Windows/macOS polling is every 50 ms and can miss very short-lived processes [L2]. |
| "Who uses it?" | We do not claim users or customers. The ledger records none. |
| "Does data leave my machine?" | No telemetry; the agent makes no outbound network connections [F2]. |

## Comparison paragraph

PTAF Sentinel is a verification tool for Sigma rules: it checks, on one machine, whether harmless imitations of attacker behavior are caught by the rules you give it, using that machine's own process telemetry [F1, L1]. It does not replace a SIEM, an EDR, a pen test, or a full threat-emulation program, and it offers no guarantee of coverage [L6, "NOT true" list]. We do not compare it feature-by-feature with named alternatives because we hold no verified facts about them. Within its scope its distinct points are the caught / missed / newly-stopped report [F1], the separation of rule gaps from blind sensors [S3], and local operation with no telemetry [F2]. It is beta [F3] and has not been tested on hardened or EDR-protected fleets [L3].

## Do-not-say list

Customers, users, stars, downloads, testimonials, awards, partnerships, "AI-powered", "enterprise-ready", "zero false positives", "complete coverage", "replaces your SIEM/EDR", "certified", "SOC 2", any pricing in effect.
