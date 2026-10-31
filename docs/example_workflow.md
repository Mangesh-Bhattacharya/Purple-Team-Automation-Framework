# Example Purple Team Workflow

This walks through how the pieces currently in the repo fit together end
to end. Every step below is runnable today against the scaffolding code --
nothing here requires a real target environment.

## 1. Run the offensive simulation

```bash
python -m modules.offensive.emulation
```

This runs every registered technique in `modules/offensive/emulation.py`
and prints one JSON `Finding` per technique, e.g.:

```json
{
  "technique_id": "T1110",
  "technique_name": "Brute Force (simulated)",
  "tactic": "Credential Access",
  "status": "simulated",
  "summary": "No real credential access attempted. ...",
  "details": {"scope": "local-only", "accounts_checked": 0},
  "timestamp": "2026-07-07T00:00:00+00:00",
  "run_id": "..."
}
```

## 2. Check detection coverage for those techniques

```bash
python -m modules.defensive.validate_detections
```

This loads every rule under `ptaf/rules/`,
validates it's well-formed and ATT&CK-tagged, and prints which technique
IDs (from `modules/offensive/attack_techniques.yaml`) have **no**
matching detection rule yet -- i.e. the gap a real red/purple team
exercise is meant to surface.

Example output:

```
[OK] ptaf/rules/suspicious_encoded_powershell.yml

Techniques with a detection rule: ['T1027', 'T1059.001']
Techniques with NO detection rule yet: ['T1021', 'T1078', 'T1087', 'T1110', 'T1526', 'T1583']
```

That gap list is the actionable output of a purple team pass: it tells you
exactly which simulated techniques would currently slip past detection.

## 3. Parse and cluster example log data

```python
from modules.defensive.log_parser import parse_json_lines
from modules.ai_analysis.clustering import cluster_events_naive

lines = [
    '{"event_type": "process_creation", "host": "ws-01", "timestamp": "2026-07-07T00:00:00Z"}',
    '{"event_type": "process_creation", "host": "ws-02", "timestamp": "2026-07-07T00:01:00Z"}',
    '{"event_type": "network_connection", "host": "ws-01", "timestamp": "2026-07-07T00:02:00Z"}',
]
events = [e.raw for e in parse_json_lines(lines, source="example")]
clusters = cluster_events_naive(events, feature_names=["event_type"])
for c in clusters:
    print(c.cluster_id, c.size, c.top_features)
```

`cluster_events_naive` requires no ML dependencies; swap in
`cluster_events` (KMeans, via scikit-learn) once `requirements-dev.txt`'s
optional `scikit-learn` dependency is installed.

## 4. Run the test suite

```bash
pytest
```

Confirms the safety contract (offensive stubs never raise, always return a
well-formed Finding) and that the example Sigma rule parses and maps to a
real ATT&CK ID.

## 5. Where a real report would plug in

Steps 1-3's JSON output is the intended input to a report generator that
produces the PDF/Markdown Purple Team report described in the top-level
README. That generator isn't implemented yet -- it's a good first PR (see
[CONTRIBUTING.md](../CONTRIBUTING.md)).
