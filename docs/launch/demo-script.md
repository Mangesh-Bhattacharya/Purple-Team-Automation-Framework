# 20-second demo recording: shot list

Goal: a viewer understands the product with the sound off. Record the real thing, not a mock-up.
Window ~1280x800, dark theme, terminal font size 18+. Tools: any screen recorder; export a GIF/MP4.

| t | Screen | Caption (burn in) |
|---|---|---|
| 0-3 s | Terminal: `ptaf up` and the banner | "One command." |
| 3-8 s | Browser opens: "Running the first safe tests..." spinner, then the ring fills to 100% | "Safe tests run on this machine." |
| 8-13 s | Edit a rule (add a typo to one path in `ptaf/rules/...yml`), wait for the next check (use `ptaf selftest`), page flips: red "regression" item appears | "A rule silently breaks..." |
| 13-17 s | Click the kill-chain technique, then "Open the fix checklist" | "...and you see exactly what and why." |
| 17-20 s | Fix the typo, tile turns green | "Unit tests for your detections." |

Notes
- Show the footer line "no data leaves this machine" once, large enough to read.
- Do not speed up the first-results wait beyond 2x; honesty about the ~10 s is part of the pitch.
- Voice is optional. If used, label it as AI-generated where the platform asks and do not imitate a real person.
- Re-record after any UI change; a stale recording is worse than none.
