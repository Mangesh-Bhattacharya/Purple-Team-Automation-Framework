# Terms of Use and Acceptable Use

*Last updated: 2026-10-31. These documents are plain-language drafts written by the maintainers, not
legal advice. If you deploy PTAF in an organization, have your own counsel review them.*

## 1. What governs what

PTAF Sentinel ("PTAF") is software released under the **MIT License** (see [LICENSE](LICENSE)). The MIT
License is the only thing that grants you rights to the code, and nothing on this page narrows it.
This page adds two things: a statement of the use PTAF is **intended** for, and a plain statement of
what the maintainers do and do not promise.

## 2. Authorized use only

PTAF runs harmless imitations of attacker behavior ("canaries") on the machine it is installed on.
Use it **only on systems you own, or where you have explicit written permission from the owner** to
run security testing. Do not use PTAF, or anything built from it, to attack, disrupt, or gain
unauthorized access to any system or person. The maintainers do not authorize, support or accept
responsibility for unlawful use. You are responsible for complying with the laws that apply to you
(for example computer-misuse and unauthorized-access laws, and employment, privacy and
monitoring laws).

## 3. What the canaries do, and what you must do before running them

Canaries are local no-ops: they sleep, decode a constant, run a read-only system query, or run a
security tool with a flag that only prints its version or usage. They make no network connections,
write no files outside PTAF's own state folder, touch no credentials and install no persistence.
This is enforced by automated tests in the repository.

They are *designed to look like attacker behavior to your detection tools*, so they **can and will
trigger alerts**. Before you run PTAF on a managed machine you should:

- get change approval (`ptaf canaries` prints exactly what will run, without running anything);
- tell your security operations team, or allowlist the tag `ptaf-canary` where your policy allows;
- not run it on systems where a test alert could cause an automated response you have not planned for.

## 4. A passing result is not a guarantee of security

"Verified" means: on that machine, at that time, a specific harmless test was caught by a specific
rule. It does **not** mean you are protected against that technique in general, that a real attacker's
variant would be caught, that rules have no false positives, or that the machine is secure. Coverage
figures count only techniques that have a test. PTAF is a tool that helps you find silent failures;
it is not a security product that prevents or guarantees anything.

## 5. No warranty, limitation of liability

PTAF is provided **"as is", without warranty of any kind**, as set out in the MIT License. To the
maximum extent permitted by law, the authors and contributors are not liable for any claim, damage or
loss arising from the use of PTAF, including loss caused by alerts, interruptions, missed detections,
or decisions made on the basis of its output.

## 6. Running the dashboard safely

The dashboard binds to `127.0.0.1` by default and refuses to bind to a network address without an
access token. Dashboards and exported snapshots can contain hostnames, usernames and command lines
that may be sensitive: you are responsible for who can see them. Do not expose the dashboard to the
internet.

## 7. Third-party material

MITRE ATT&CK®, Sigma, Kali Linux and other names belong to their owners. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [TRADEMARK.md](TRADEMARK.md). Use of those names
does not imply endorsement by, or affiliation with, their owners.

## 8. Data and privacy

See [PRIVACY.md](PRIVACY.md). In short: PTAF collects nothing about you and sends nothing anywhere.

## 9. Changes and contact

These documents may change; the history is in git. Questions and corrections: open a GitHub issue.
Security vulnerabilities: follow [SECURITY.md](SECURITY.md). Copyright concerns:
see [COPYRIGHT.md](COPYRIGHT.md).
