# Contributing to PTAF

Thanks for your interest in the Purple Team Automation Framework. PTAF is
early-stage scaffolding (see the main README's Status notes) -- there is
real room to shape the architecture, not just add small fixes.

## Ground rules

1. **Safety first.** Offensive modules must stay non-destructive and
   non-malicious: no real credential exfiltration, no contact with systems
   outside an explicit, user-provided scope, no functional exploit or
   malware code. If a contribution can't be described safely in a PR, it
   won't be merged.
2. **Everything maps to a source of truth.** Offensive techniques should
   reference a MITRE ATT&CK technique ID. Detection logic should reference
   the finding/technique it is meant to catch.
3. **Explainable over clever.** AI/ML components should surface which
   features or events drove a finding, not just a bare score.

## Getting started

```bash
git clone https://github.com/Mangesh-Bhattacharya/Purple-Team-Automation-Framework.git
cd Purple-Team-Automation-Framework
python3 -m venv .venv
source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -r requirements.txt
pip install -r requirements-dev.txt  # if present: test/lint tooling
```

Run tests before opening a PR:

```bash
pytest
```

## How to contribute

- **Bug reports / feature requests:** open an issue using the provided
  templates.
- **New offensive module:** add it under `modules/offensive/`, document the
  ATT&CK technique(s) it maps to, and keep it safe-by-default (see above).
- **New defensive module / detection rule:** add it under
  `modules/defensive/`. Sigma rules go in
  `modules/defensive/detection_rules/`.
- **AI/analysis plugin:** add it under `modules/ai_analysis/`, and document
  what input it expects and what it outputs.
- **Docs:** improvements to `docs/` and module READMEs are always welcome,
  even without code changes.

## Pull request process

1. Fork the repo and create a branch from `main`.
2. Keep PRs focused -- one module or fix per PR where possible.
3. Update or add tests under `tests/` for any behavior change.
4. Update the relevant README/docs in the same PR.
5. Fill out the PR template; link the issue it resolves, if any.
6. A maintainer will review; CI (lint + basic security scan) must pass.

## Code style

- Python: `black` formatting, `flake8` clean.
- Prefer small, well-documented functions with type hints over large
  do-everything scripts.

## Reporting security issues

Do not open a public issue for a security vulnerability -- see
[SECURITY.md](SECURITY.md) instead.
