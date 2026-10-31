# V2: "We ran the rules. Here is what broke." (90 s, detection engineers, 16:9)

Working title: Our Example Rule Could Never Match. Here Is How We Found Out.
Show "BETA v0.2.0" lower-third throughout. [F3]

## Voiceover

| Time | Voiceover line |
|---|---|
| 0:00-0:07 | Our example PowerShell rule had a doubled backslash. It could never match a real Windows path, and it passed syntax checks for weeks. [S1] |
| 0:07-0:15 | We only found out the first time the rules were actually executed. That is the gap PTAF Sentinel is built for. [S1, F1] |
| 0:15-0:27 | It runs harmless imitations of attacker behavior, runs Sigma rules against the machine's own process telemetry, and reports caught, missed, or newly stopped being caught. [F1] |
| 0:27-0:40 | Running it found more. A normal pip install shipped the agent with zero rules, because they lived outside the package. [S2] |
| 0:40-0:48 | On Windows, the API reported cmd.exe's original name as "Cmd.Exe.MUI", so rules for cmd.exe would have silently missed. [S5] |
| 0:48-0:56 | A blind sensor used to exit 0 and could pass a CI gate. Now it exits 3. [S3] |
| 0:56-1:10 | Then the rules question. We ran the rule checker over all 3,161 public SigmaHQ rules: zero load errors, 10.5 seconds. [F17] |
| 1:10-1:22 | Of 1,383 process-creation rules, 1,304, 94 percent, are runnable by PTAF. It was 50 percent before it learned Windows version-resource fields. [F18] |
| 1:22-1:30 | Caveat: runnable means PTAF can evaluate the rule, not that the rule is good. We have not cross-checked the 94 percent against pySigma. Process creation only. Beta, v0.2.0. [F18, L7, L1, F3] |

## Shot list

| Time | On screen |
|---|---|
| 0:00-0:15 | Plain animated text of a Windows path with a doubled backslash, labelled "ILLUSTRATIVE". Better: record the real fixing diff from the repo history (`git log -p` on the example rule; the reviewer must confirm the rule text matches S1). |
| 0:15-0:27 | Terminal: `ptaf canaries` (lists what runs, executes nothing), then `ptaf selftest` and the dashboard flipping |
| 0:27-0:40 | Plain text card: "pip install -> 0 rules shipped" [S2]. Optionally the real CHANGELOG.md entry on screen |
| 0:40-0:48 | Plain text card: "Cmd.Exe.MUI" beside "cmd.exe". Real CHANGELOG/commit if present |
| 0:48-0:56 | Terminal: `ptaf selftest; echo $?` on a machine/condition where the sensor is blind (only if you can reproduce for real; otherwise show the docs table of exit codes) |
| 0:56-1:10 | Terminal: `ptaf rules check <path-to-SigmaHQ-rules>` with the real run and its real output/timing (re-run; do not reuse a stale number on screen unless it matches F17) |
| 1:10-1:30 | Browser: docs/sigmahq-coverage.md rendered on GitHub, scroll to the method and caveats. Plain text card: "94% runnable (1,304 / 1,383) / was 50% (697) / not cross-checked vs pySigma" |

## On-screen captions
"Passed syntax checks for weeks" / "Found by actually running it" / "0 rules shipped" / "Cmd.Exe.MUI" / "Blind sensor now exits 3" / "3,161 SigmaHQ rules: 0 load errors" / "94% runnable, not 94% good" / "Not cross-checked against pySigma" / "BETA v0.2.0"

## CTA
"Run `ptaf rules check` on your own rules directory. Beta; process-creation rules only."

## Publishing block
- Title (<=70): The Detection Rule That Could Never Match (and 94% of SigmaHQ)  (65 chars)
- Description:
  Honest bug stories from building PTAF Sentinel, an open-source (MIT) tool that checks whether detection rules actually fire on a machine, plus how many public SigmaHQ rules it can run.
  Numbers: rule checker over 3,161 public SigmaHQ rules (commit 05d1031): 0 load errors. Of 1,383 process-creation rules, 1,304 (94%) are runnable. "Runnable" means PTAF can evaluate the rule, not that the rule is good. The 94% was not cross-checked against pySigma.
  BETA (v0.2.0, not yet released, unsigned apps). Limits: process-creation telemetry only; tested on CI runners and one developer Mac, not hardened or EDR-protected fleets; a pass is not a security guarantee.
  Repo: <link>.
  Voice disclosure: narration is a synthetic (AI-generated) voice, not a real person.
- Tags (11): sigma rules, sigmahq, detection engineering, detection as code, detection testing, purple team, blue team, open source security, windows security, threat detection, cybersecurity
- Hashtags: #DetectionEngineering #Sigma #BlueTeam
- Thumbnail text (<=5 words): THIS RULE NEVER MATCHED
- First comment: "Caveats up front: beta v0.2.0, process-creation only, and the 94% has not been cross-checked against pySigma. If you spot a flaw in the method, say so: docs/sigmahq-coverage.md. Repo: <link>"
