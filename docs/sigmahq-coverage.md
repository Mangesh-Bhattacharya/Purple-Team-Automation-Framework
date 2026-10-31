# How much of the public Sigma rule set can PTAF run?

PTAF's rule checker was run over the public [SigmaHQ](https://github.com/SigmaHQ/sigma) rule set to
answer a practical question: *if I bring my own rules, how many will actually be evaluated?*

## Result

| | Before | After |
|---|---|---|
| Rule files read | 3,161 | 3,161 |
| Files that failed to load | 0 | 0 |
| Process-creation rules | 1,383 | 1,383 |
| **Runnable** process-creation rules | 697 (50%) | **1,304 (94%)** |
| Of which Windows rules (1,193) | 510 (43%) | 1,117 (94%) |

Read in 10.5 seconds. "After" adds the Windows version-resource fields described below.

## What changed the number

The rule checker also reports *why* a rule cannot run. For 680 of the process-creation rules the reason
was the same: they match on fields PTAF did not collect. One field dominated:

| Field | Rules blocked | Rules blocked **only** by this field |
|---|---|---|
| `OriginalFileName` | 587 | 527 |
| `Description` | 70 | 19 |
| `Product` | 47 | 7 |
| `Hashes` | 40 | 24 |
| `IntegrityLevel` | 26 | 21 |

`OriginalFileName` is the name stored inside a Windows executable's version resource, so it still reads
`Cmd.Exe` when the file has been renamed to `quarterly-report.exe`. That is why so many rules use it. PTAF
now reads it (and `Description`, `Product`, `Company`, `FileVersion`) on Windows with no extra
dependencies (`ptaf/winmeta.py`). The test suite checks this on a real Windows machine in CI, including
the rename case.

## What this number does NOT mean

- **"Runnable" is not "correct".** It means PTAF can evaluate the rule on the telemetry it collects. It
  says nothing about whether the rule is accurate or free of false positives.
- **It was not cross-checked against pySigma** on these rules. PTAF's engine is tested against itself and
  against its own YAML parser; semantic differences from other Sigma tools on rarely used features are
  possible.
- **Windows figures assume a Windows agent.** Linux and macOS agents do not supply those fields.
- **Still not runnable:** rules for other telemetry (registry, network, file, image-load, PowerShell
  script blocks, cloud, identity), rules using `Hashes`, `IntegrityLevel` or `LogonId`, and a few using
  `base64offset`, `fieldref` or regex flags.
- The 1,383 count covers rules whose log source is `process_creation`. Other categories are not counted
  as runnable.

## Reproduce it

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git
git -C sigma sparse-checkout set rules
ptaf rules check sigma/rules --json-out > coverage.json
```

Measured against SigmaHQ commit `05d1031` (2026-10-21). The SigmaHQ rules are published under their own
[Detection Rule License](https://github.com/SigmaHQ/Detection-Rule-License); PTAF read them from a local
copy for measurement and does not redistribute them.
