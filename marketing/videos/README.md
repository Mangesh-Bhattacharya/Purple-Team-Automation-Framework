# Video production notes

Every spoken or captioned claim must carry a ledger ID in the script (from marketing/FACTS.md). IDs are stripped before publishing. If a claim has no ID, it does not ship.

## Hard rules
1. Beta stated in every video (on-screen tag plus voiceover or caption). [F3]
2. Never call the five analysis agents AI; they are rule-based and local.
3. No invented users, stars, downloads, testimonials, awards, benchmarks. No "hack", "unhackable", "guaranteed".
4. Visuals are real: screen recordings, real terminal output, or plain animated text. Dashboard README image is demo data: label "DEMO DATA" or record a live run instead.
5. Synthetic voice disclosed in every description, and say it again in the first comment if the platform asks.
6. Include the limits line (process-creation only; CI runners plus one developer Mac; a pass is not a guarantee).
7. Re-record after any UI change; do not reuse stale numbers (F13-F15 are single local measurements).

## Style guide
- Look: warm-dark. Background oklch(16.47% .0203 57.05) (about #1c1612 area), cards oklch(22.84% .0251 63.32), text oklch(95.07% .0155 67.64), amber accent oklch(78% .16 65), success oklch(69.9% .14 150.04), destructive oklch(69.8% .1698 35.2). Source: ptaf/dashboard.html. Convert to sRGB in the editor.
- Fonts: IBM Plex Sans (text), IBM Plex Mono (commands, rule text, exit codes), as used in the dashboard.
- Captions: IBM Plex Sans semibold, 44 px at 1080p landscape, 56-64 px on 1080x1920 shorts, max two lines, keep inside the safe area (bottom 20 percent clear on shorts), foreground colour on a 70 percent dark pill. Key word in amber.
- Terminal: font size 18+, dark theme, 1280x800 window, `ptaf up` banner visible.
- Beta tag: amber pill "BETA v0.2.0" top-left, always visible.
- Motion: simple fades and typewriter text; no stock footage, no fake hacker visuals.
- Audio: low-volume ambient bed optional; narration at -16 LUFS.

## Record by hand
- `ptaf up` startup, first-run screen, ring filling, live updates (real run, max 2x speed-up).
- `ptaf selftest; echo $?`, `ptaf canaries`, `ptaf rules check <SigmaHQ path>` (re-run, show real output).
- Rule edit causing a drift/regression and the fix (docs/launch/demo-script.md).
- Browser: GitHub repo, docs/sigmahq-coverage.md, docs/kali.md.
- Linux root run for the event-driven sensor, if you show 9 of 9 (F12).
- Anything showing bug-story evidence: real diff or CHANGELOG lines.

## Generate
- Narration (synthetic voice; disclose).
- Plain animated text cards and end cards, captions, thumbnails (text only plus a real screenshot).
- Do NOT generate: dashboard imagery, terminal output, people, logos of other companies.

## Checklist
- [ ] Script lines all have ledger IDs; reviewer pass done
- [ ] Beta tag and limits line on screen
- [ ] Synthetic-voice disclosure in description and first comment
- [ ] No demo data unlabelled; no stale numbers
- [ ] Captions burned in and readable muted
- [ ] Title <=70, 8-12 tags, 3 hashtags, thumbnail <=5 words
- [ ] IDs stripped from published text
- [ ] Legal note ("only on systems you own or are authorized to test") in description
