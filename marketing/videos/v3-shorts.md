# V3: Three vertical shorts (9:16, 30 s each)

All three: "BETA v0.2.0" tag in the corner [F3]; synthetic-voice disclosure in the description; captions burned in at 56 px+.
Visuals: plain animated text plus real terminal/browser capture. No invented output.

## Short (a): S1, the rule that could never match
Working title: A Rule That Passed For Weeks And Never Matched
Hook (0-2 s): on-screen "It passed for weeks. It could never match." + VO line 1.

| Time | Voiceover line |
|---|---|
| 0:00-0:02 | Our example rule passed syntax checks for weeks, and could never match. [S1] |
| 0:02-0:10 | It had a doubled backslash, so it could never match a real Windows path. [S1] |
| 0:10-0:18 | We only found out the first time the rules were actually executed. [S1] |
| 0:18-0:25 | PTAF Sentinel runs harmless imitations of attacker behavior and checks if your rules catch them. [F1] |
| 0:25-0:30 | Open source, MIT, beta. Process creation only. [F2, F3, L1] |

Shots: 0-10 plain text path with doubled backslash (label ILLUSTRATIVE, or real diff); 10-18 terminal `ptaf selftest` run; 18-25 dashboard; 25-30 end card `ptaf up` + repo.
Captions: "Passed syntax checks. Never matched." / "Found by running it" / "BETA".
CTA: "Run `ptaf up`."
Title (<=70): The Rule That Passed For Weeks and Never Matched (49)
Description: Beta (v0.2.0) open-source (MIT) tool; process-creation telemetry only; a pass is not a security guarantee; verified on CI runners and one developer Mac. Narration is a synthetic (AI-generated) voice. Repo: <link>
Tags (9): detection engineering, sigma rules, detection testing, purple team, blue team, open source security, powershell, cybersecurity, shorts
Hashtags: #DetectionEngineering #Sigma #Shorts
Thumbnail text: NEVER MATCHED
First comment: "Beta, process-creation only. The full story is in the 90 s video. Repo: <link>"

## Short (b): S5, Cmd.Exe.MUI
Working title: Why cmd.exe Rules Would Silently Miss
Hook (0-2 s): on-screen "cmd.exe" crossed to "Cmd.Exe.MUI".

| Time | Voiceover line |
|---|---|
| 0:00-0:02 | On Windows, cmd.exe reported its own name wrong. [S5] |
| 0:02-0:12 | The API gave cmd.exe's original name as "Cmd.Exe.MUI", so rules for cmd.exe would have silently missed. [S5] |
| 0:12-0:20 | Silent is the problem: nothing errors, the dashboard just stays quiet. [S5, F1] |
| 0:20-0:26 | PTAF Sentinel runs the rules against real telemetry to catch exactly this kind of gap. [F1] |
| 0:26-0:30 | Open source, beta, process creation only. [F2, F3, L1] |

Shots: 0-12 plain text card "cmd.exe -> Cmd.Exe.MUI" (animated text); 12-26 terminal `ptaf rules check <dir>` real run; 26-30 end card.
Captions: "Cmd.Exe.MUI" / "Rules would silently miss" / "BETA".
CTA: "Check your rules: `ptaf rules check <dir>`."
Title: cmd.exe Was Reported as "Cmd.Exe.MUI" (Silent Misses) (51)
Description: as short (a), plus: this bug was found and fixed during development of v0.2.0 beta. Synthetic voice disclosed.
Tags (9): windows security, sigma rules, detection engineering, cmd.exe, detection testing, blue team, open source security, cybersecurity, shorts
Hashtags: #WindowsSecurity #DetectionEngineering #Shorts
Thumbnail text: CMD.EXE.MUI
First comment: "Beta, process-creation only; tested on CI runners and one developer Mac. Repo: <link>"

## Short (c): S4, exit 127
Working title: The App That Failed Every Tool Check
Hook (0-2 s): on-screen "exit 127" large.

| Time | Voiceover line |
|---|---|
| 0:00-0:02 | Exit code 127, on every external tool check. [S4] |
| 0:02-0:12 | The packaged Linux app silently failed every external-tool canary: PyInstaller's library path made the tools exit 127. [S4] |
| 0:12-0:20 | We found it by running the packaged app, not by reading code. [S4] |
| 0:20-0:26 | A real Kali image and real nmap, hydra, sqlmap and tcpdump canaries now check out: 9 of 9 detected on a real Linux kernel. [F11, F12] |
| 0:26-0:30 | Beta v0.2.0. Not tested on physical or ARM Kali. [F3, L3] |


Shots: 0-12 big text "exit 127" then plain text card (real CHANGELOG entry if present); 12-26 terminal `ptaf canaries` (list) and, on Linux with sudo, `ptaf selftest`; 26-30 end card.
Captions: "exit 127" / "9 of 9 on a real Linux kernel" / "BETA, not tested on physical or ARM Kali".
CTA: "Kali? See docs/kali.md."
Title: The Packaged App That Silently Failed (Exit 127) (46)
Description: as short (a); Linux sensor result measured on a real Linux kernel; not tested on physical machines, ARM or NetHunter Kali. Synthetic voice disclosed.
Tags (9): kali linux, pyinstaller, nmap, detection engineering, purple team, blue team, open source security, cybersecurity, shorts
Hashtags: #KaliLinux #PurpleTeam #Shorts
Thumbnail text: EXIT CODE 127
First comment: "Beta v0.2.0. Details and limits in docs/kali.md. Repo: <link>"
