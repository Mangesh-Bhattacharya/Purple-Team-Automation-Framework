# Changelog

All notable changes. Dates are ISO. This project is pre-1.0: interfaces may change.

## [Unreleased]

### Added
- Windows version-resource fields (`OriginalFileName`, `Description`, `Product`, `Company`,
  `FileVersion`) on Windows process events. On the public SigmaHQ set this raises runnable
  process-creation rules from 50% to 94% and defeats rename-the-binary evasion.
- `ptaf legal`, the acceptable-use notice at start-up, and TERMS, PRIVACY, COPYRIGHT, TRADEMARK and
  THIRD_PARTY_NOTICES documents.
- `docs/sigmahq-coverage.md`: how the SigmaHQ coverage number was measured, with caveats.

### Changed
- README rewritten to lead with what is verified; unbuilt ideas moved to a labelled roadmap.

## [0.2.0] - in progress (not yet tagged)

### Added
- **PTAF Sentinel**: a cross-platform agent that runs harmless canaries, runs Sigma rules against the
  host's own process telemetry and alerts on detection drift.
- `ptaf up` (agent + live dashboard), live push updates, first-run state, clean shutdown on SIGTERM.
- Analysis agents (Triage, Explain, Fix, Planner, Readiness), kill-chain explorer, browser Detection Lab,
  change-aware motion system.
- Kali Linux support: PEP 668-safe installer, Kali detection, offensive-tool canaries and rules,
  event-driven Linux proc-connector sensor.
- `ptaf doctor`, `ptaf canaries`, `ptaf rules check`, JUnit output, stable exit codes.
- Fleet (organization) view merging exported host summaries; token-protected dashboard.
- Single-file and folder application builds.

### Fixed
- The shipped PowerShell rule could never match a Windows path (doubled backslash).
- A normal `pip install` shipped the agent with zero rules.
- Collector memory leak; one malformed rule file crashed the agent; a blind sensor exited 0.
- Exported snapshots showed a false "cannot reach server" banner; macOS one-file app took ~14 s per launch.
