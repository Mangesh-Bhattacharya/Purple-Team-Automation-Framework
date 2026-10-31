# Privacy

*Last updated: 2026-10-31. A plain-language description of what the software does with data. Not legal
advice.*

## The short version

PTAF has **no telemetry, no accounts, no analytics and no phone-home**. The agent itself makes no
**outbound** network connections (the dashboard listens on your own machine; see below). Everything it records stays on the machine it runs on, in a folder you control.

## What PTAF records, and where

By default in `~/.ptaf` (or the folder in the `PTAF_HOME` environment variable; on POSIX systems the
folder is created private to your user, mode `0700`):

| File | Contents |
|---|---|
| `history.jsonl` | the result of each self-test: host name, OS, which tests ran, which were detected |
| `alerts.jsonl` | rule matches seen on the machine, including **process image paths, command lines and user names** |
| `status.json` | the agent's heartbeat: process id, state, counters |
| `state.json`, `badge.json`, `navigator_layer.json`, `doctor.json` | the latest summaries |
| `monitor.lock` | a single-instance lock |

Logs rotate at 10 MB and three generations are kept, so disk use is bounded.

**Command lines can contain secrets** (passwords or tokens typed as arguments). Treat the folder as
sensitive. To erase everything PTAF has recorded, stop the agent and delete the folder.

## The dashboard

`ptaf dashboard` and `ptaf up` serve a page from the same machine. By default it is reachable only
from that machine (`127.0.0.1`). Beyond that it requires a token that you choose. The page makes no
requests to any outside site and loads no external fonts, scripts or trackers.

Your browser keeps two small preferences in its own `localStorage`: whether animations are on, and
which fix-checklist boxes you ticked. They never leave your browser.

**Exported snapshots** (`ptaf dashboard --export`) and fleet summaries (`ptaf export summary`) contain
host names and may contain command lines. Share them as carefully as the underlying logs.

## If you run PTAF for an organization

Usernames and command lines can be personal data under laws such as the GDPR. If you deploy PTAF on
machines used by employees or customers, **you** decide the purpose and retention, and you are
responsible for any notices, legal basis and monitoring-law compliance that apply to you. The
maintainers do not receive or process any of this data.

## Things outside PTAF's control

Installing PTAF with `pip` downloads packages from the Python Package Index, and cloning or reading
this repository uses GitHub. Those services have their own privacy policies.
