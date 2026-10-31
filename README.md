# Purple Team Automation Framework (PTAF)

[![CI](https://github.com/Mangesh-Bhattacharya/Purple-Team-Automation-Framework/actions/workflows/ci.yml/badge.svg)](https://github.com/Mangesh-Bhattacharya/Purple-Team-Automation-Framework/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**AI-Driven Offensive + Defensive Security Automation for Mid-Level Practitioners**

Author: [Mangesh Bhattacharya](https://github.com/Mangesh-Bhattacharya) — Cybersecurity Practitioner | MITS-AI Graduate (Ontario Tech University) | Threat Intelligence & Automation

---

## Project Vision

PTAF is a free, open-source Purple Team automation framework built to help mid-level cybersecurity practitioners simulate real-world adversarial behavior, strengthen defensive controls, and accelerate security engineering workflows.

It is designed to run on Kali Linux, Ubuntu, and cloud shells, enabling practitioners to:

- Execute safe, controlled offensive simulations
- Automatically map defensive gaps
- Generate remediation guidance
- Produce Purple Team reports
- Collaborate with contributors from across the security community

The long-term goal is to make PTAF a practical, well-documented Purple Team automation toolkit for defenders, SOC analysts, threat hunters, and aspiring security engineers.

## New: PTAF Sentinel (v0.2): your detections, continuously verified

PTAF now ships an endpoint agent for **Windows, macOS, Linux and any VM**. It
fires harmless canary behaviors, watches the host's own telemetry, and proves
your Sigma rules still fire. If a rule silently stops working, it raises a
`detection_drift` alert. Results export as an ATT&CK Navigator layer
(green = verified, yellow = untested, red = gap) and a coverage badge.

```bash
pip install -e . && ptaf selftest
```

Details, limits and safety model: [docs/sentinel.md](docs/sentinel.md). For organizations: [docs/enterprise.md](docs/enterprise.md). **Kali Linux:** [docs/kali.md](docs/kali.md).

![Dashboard: agent health, what needs attention, coverage, history, alerts, sensor health, fleet (demo data)](docs/assets/dashboard-demo-v2.jpg)

## Core Capabilities

### 1. Offensive Simulation Modules (Safe & Controlled)

- Credential harvesting simulation (non-malicious)
- Phishing emulation
- Web application misconfiguration checks
- Cloud IAM misconfiguration detection
- Lateral movement path mapping
- Attack path visualization

### 2. Defensive Automation Modules

- Log correlation (SIEM-agnostic)
- MITRE ATT&CK mapping
- Alert quality scoring
- Detection gap identification
- Automated defensive recommendations
- Purple Team report generation (PDF/Markdown)

### 3. AI-Driven Analysis

- Threat pattern clustering
- Behavioral anomaly detection
- Automated defensive tuning suggestions
- Attack replay analysis

### 4. Collaboration Features

- Modular plugin system
- Clear contribution guidelines
- Issue templates for new modules
- Community roadmap
- Periodic "Purple Team Challenges" for contributors

## Technical Requirements

- **Language:** Python
- **OS:** Kali Linux, Ubuntu, Windows Subsystem for Linux
- **Dependencies:** Open-source libraries only
- **Architecture:** Modular, agent-based
- **Output formats:** JSON, Markdown, PDF
- **Integrations:** Sysmon, Suricata, Zeek, Sigma rules, MITRE ATT&CK

## Community & Collaboration

PTAF aims to be a collaboration point for SOC analysts, threat hunters, red teamers, blue teamers, purple teamers, and AI-security researchers.

Contributors are encouraged to:

- Add new modules
- Improve detection logic
- Submit Purple Team exercises
- Share defensive tuning strategies

## Installation (Kali Linux / Ubuntu / WSL)

```bash
git clone https://github.com/Mangesh-Bhattacharya/Purple-Team-Automation-Framework.git
cd Purple-Team-Automation-Framework
sudo chmod +x install.sh
./install.sh
```

`install.sh` creates a virtual environment and installs `requirements.txt`.
For development (tests/lint), also install `requirements-dev.txt`:

```bash
pip install -r requirements-dev.txt
```

## Usage Example

```bash
# Run the offensive simulation stubs and print structured findings
python -m modules.offensive.emulation

# Check which simulated techniques currently have no detection rule
python -m modules.defensive.validate_detections

# Run the test suite
pytest
```

See [docs/example_workflow.md](docs/example_workflow.md) for a full walkthrough, and [docs/architecture.md](docs/architecture.md) for how the modules fit together (with a diagram).

> **Status note:** PTAF is early-stage scaffolding. The capabilities listed
> above describe the intended architecture; each module currently ships
> the interface plus one or two fully-working, safe example
> implementations (not a complete, production SIEM/EDR/ML integration).
> See [Contributing](#contributing) to help build it out.

## Repository Structure

```
PTAF/
├── install.sh               # Setup script
├── requirements.txt         # Runtime Python dependencies
├── requirements-dev.txt     # Test/lint tooling
├── pytest.ini
├── modules/
│   ├── offensive/           # Safe, controlled simulation modules
│   │   ├── emulation.py
│   │   └── attack_techniques.yaml
│   ├── defensive/           # Detection & defensive automation modules
│   │   ├── log_parser.py
│   │   ├── validate_detections.py
│   │   └── (rules moved to ptaf/rules/)
│   └── ai_analysis/         # AI-driven analysis plugins
│       ├── clustering.py
│       └── config.yaml
├── tests/                   # pytest suite
├── docs/                    # Architecture + example workflow
└── .github/                 # Issue/PR templates, CI workflow
```

## Documentation

- [docs/architecture.md](docs/architecture.md) — how the modules fit together, with a diagram
- [docs/example_workflow.md](docs/example_workflow.md) — a runnable, end-to-end walkthrough
- Module READMEs: [offensive](modules/offensive/README.md), [defensive](modules/defensive/README.md), [ai_analysis](modules/ai_analysis/README.md)
- [CONTRIBUTING.md](CONTRIBUTING.md) — safety bar, dev setup, PR process
- [SECURITY.md](SECURITY.md) — how to report a vulnerability
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Contributing

Contributions are welcome, including:

- New attack simulation modules
- New defensive detection logic
- New AI-analysis plugins
- Documentation improvements
- Purple Team exercises

Open an issue (bug report or feature request template) or submit a pull request using the PR template. See [CONTRIBUTING.md](CONTRIBUTING.md) for the safety bar offensive/defensive contributions must meet.

## About the Author

Mangesh Bhattacharya is a cybersecurity practitioner and Master's student in Complex Networks / AI-Security (MITS, Ontario Tech University), building AI-driven security automation tools including [CyberSentinel-AI](https://github.com/Mangesh-Bhattacharya/CyberSentinel-AI) and [AI-Automated-Security-Engineer](https://github.com/Mangesh-Bhattacharya/AI-Automated-Security-Engineer).

## License

Released under the [MIT License](LICENSE).
