# V1: "Quiet isn't safe" (60 s explainer, security leads, 16:9)

Working title: Quiet Isn't Safe: Unit Tests for Your Detection Rules
Status line to show in every video: "PTAF Sentinel v0.2.0 is a BETA." [F3]
Ledger IDs in brackets are for review only. Strip before publishing.

## Voiceover

| Time | Voiceover line |
|---|---|
| 0:00-0:04 | Detection rules fail silently, and quiet looks like safe. [F1] |
| 0:04-0:12 | A rule gets edited, a pipeline breaks, and nothing errors: the dashboard just stays quiet. [F1] |
| 0:12-0:22 | PTAF Sentinel runs harmless imitations of attacker behavior on a machine, then runs your Sigma rules against that machine's own process telemetry. [F1] |
| 0:22-0:32 | It tells you which behaviors were caught, which were missed, and which used to be caught and stopped. [F1] |
| 0:32-0:40 | It also separates a wrong rule from a blind sensor. They get different statuses and different exit codes, so a blind sensor cannot pass a CI gate. [S3] |
| 0:40-0:48 | It is open source, MIT licensed, and sends no telemetry. [F2] |
| 0:48-0:56 | It is a beta, v0.2.0. It checks process creation only, and a pass means one harmless test was caught by one rule on that machine at that time. It is not a guarantee. [F3, L1, L6] |
| 0:56-1:00 | Try it on a machine you own: `ptaf up`. Link below. [F1] |


## Shot list (real footage only)

| Time | On screen |
|---|---|
| 0:00-0:04 | Plain animated text on warm-dark background: "Quiet" -> "Quiet is not the same as safe." |
| 0:04-0:12 | Plain animated text: edit a rule / pipeline breaks / nothing errors (three words, no UI) |
| 0:12-0:22 | Screen recording: terminal, run `ptaf up`, banner, browser opens to the real dashboard, first-run screen, ring fills (per docs/launch/demo-script.md 0-8 s). Do not speed up beyond 2x. |
| 0:22-0:32 | Screen recording: real dashboard with real results from your machine; hover over a caught, a missed and a drift item |
| 0:32-0:40 | Terminal: run `ptaf selftest; echo $?` and show the exit code. Plain text card after: "0 ok / 1 gap or drift / 3 sensor problem" |
| 0:40-0:48 | Browser: the footer line "no data leaves this machine" held large enough to read. Then GitHub repo page with MIT licence visible |
| 0:48-0:56 | Plain text card: "BETA v0.2.0 / Process-creation only / A pass is not a guarantee" |
| 0:56-1:00 | End card: repo URL, `ptaf up` in mono |

If the dashboard shows demo data, burn in "DEMO DATA" (the README screenshot is demo data). Prefer a live run.

## On-screen captions
"Quiet is not the same as safe." / "Caught. Missed. Stopped working." / "Wrong rule vs blind sensor" / "Open source, MIT, no telemetry" / "BETA v0.2.0, process-creation only" / "A pass is not a guarantee"

## CTA
"Run `ptaf up` on a machine you own. Use it only on systems you are authorized to test." [F23]

## Publishing block
- Title (<=70): Quiet Isn't Safe: Verify Your Detection Rules (Beta)  (51 chars)
- Description:
  PTAF Sentinel runs harmless imitations of attacker behavior on a machine and checks whether your Sigma rules catch them. Open source (MIT), no telemetry.
  BETA (v0.2.0, not yet released, release apps unsigned). Limits: process-creation telemetry only; verified on CI runners and one developer Mac, not on hardened or EDR-protected fleets; a pass is not a security guarantee.
  Repo: <link>. Use only on systems you own or are authorized to test.
  Voice disclosure: the narration in this video is a synthetic (AI-generated) voice, not a real person.
- Tags (10): detection engineering, sigma rules, detection as code, purple team, blue team, security validation, open source security, SOC, cybersecurity, detection testing
- Hashtags: #DetectionEngineering #SigmaRules #PurpleTeam
- Thumbnail text (<=5 words): QUIET IS NOT SAFE
- First comment: "Beta, v0.2.0. Process-creation telemetry only; a pass is not a guarantee. Tell me which limits matter most to you and I will prioritize them. Repo: <link>"
