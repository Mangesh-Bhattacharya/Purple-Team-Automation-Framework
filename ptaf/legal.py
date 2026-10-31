"""The short legal notice shown by ``ptaf legal`` and at start-up. The full texts are in the repository."""

REPO = "https://github.com/Mangesh-Bhattacharya/Purple-Team-Automation-Framework"

ACCEPTABLE_USE = (
    "Use PTAF only on systems you own or are explicitly authorized to test. "
    "Its tests can trigger security alerts. Run `ptaf legal` for terms."
)

NOTICE = f"""PTAF Sentinel: legal notice

LICENSE      MIT. Copyright (c) 2026 Bhattacharya, Mangesh, and contributors.
             You may use, copy, modify and distribute it under the MIT License.

AUTHORIZED   Use PTAF only on systems you own, or where the owner has given you explicit written
USE ONLY     permission to run security testing. Do not use it to attack or disrupt anything.
             The maintainers do not authorize unlawful use and are not responsible for it.

ALERTS       PTAF's tests are harmless, but they are designed to look like attacker behavior to your
             security tools, so they can trigger alerts. Get change approval and tell your security team
             first. `ptaf canaries` lists exactly what will run, without running anything.

NO GUARANTEE A passing result means one specific harmless test was caught by one rule on that machine
             at that time. It is not a guarantee that you are protected. PTAF is provided "as is",
             without warranty of any kind.

PRIVACY      No telemetry, no accounts, no outbound connections by the agent. Everything stays on this
             machine (default: ~/.ptaf). Logs can contain command lines, which can contain secrets.

THIRD PARTY  MITRE ATT&CK(R) is a registered trademark of The MITRE Corporation. Other names belong to
             their owners. See THIRD_PARTY_NOTICES.md.

FULL TEXTS   {REPO}
             TERMS.md  PRIVACY.md  COPYRIGHT.md  TRADEMARK.md  THIRD_PARTY_NOTICES.md  SECURITY.md

These are plain-language documents, not legal advice.
"""
