# Third-Party Notices

PTAF includes or depends on the following. Versions are those the project was tested with; each package's
own distribution carries its authoritative license text.

## Runtime dependencies (installed with `pip`)

| Package | License | Copyright |
|---|---|---|
| [psutil](https://github.com/giampaolo/psutil) | BSD-3-Clause | (c) 2009, Jay Loden, Dave Daeschler, Giampaolo Rodola |
| [Click](https://github.com/pallets/click) | BSD-3-Clause | Copyright 2014 Pallets |
| [PyYAML](https://github.com/yaml/pyyaml) | MIT | (c) 2017-2021 Ingy döt Net; (c) 2006-2016 Kirill Simonov |

The BSD-3-Clause license requires that redistributions (including the single-file applications built
with `packaging/build.py`) keep the copyright notice, the license conditions and the disclaimer. Their
full texts ship inside each package's `*.dist-info/` folder; the applications bundle those packages.

## Build and test tools (not part of the installed package)

- **PyInstaller** (GPL-2.0-or-later with a bootloader exception) is used only to *build* the optional
  standalone applications. Its license's exception permits distributing the applications it builds
  under the application's own license.
- **Node.js** and **Google Chrome** are used only by the test suite, to check the browser Detection Lab
  and the dashboard. Nothing from them is distributed.

## MITRE ATT&CK®

Technique names and identifiers (for example T1059.001) and tactic names come from MITRE ATT&CK®.

> ATT&CK® is a registered trademark of The MITRE Corporation. © The MITRE Corporation. The ATT&CK
> knowledge base is reproduced and distributed with the permission of The MITRE Corporation, under its
> [Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

The short explanations in `ptaf/knowledge.py` are written by the PTAF maintainers for defenders and are
not MITRE text. Check the current MITRE terms before redistributing ATT&CK content beyond identifiers
and names.

## Sigma

PTAF reads rules in the [Sigma](https://github.com/SigmaHQ/sigma) format. The rules in `ptaf/rules/` are
original to this project. PTAF does **not** bundle rules from the SigmaHQ repository, which are published
under the [Detection Rule License](https://github.com/SigmaHQ/Detection-Rule-License). The coverage
analysis in `docs/sigmahq-coverage.md` read those rules from a local copy for measurement only and
redistributes none of them.

## Fonts

The dashboard names IBM Plex Sans and IBM Plex Mono in its CSS but does **not** bundle or download them;
if they are not installed on the viewer's machine the browser's system fonts are used. IBM Plex is
licensed under the SIL Open Font License 1.1.
