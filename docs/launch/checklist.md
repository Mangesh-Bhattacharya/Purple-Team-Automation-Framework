# Launch checklist (what actually moves GitHub stars)

No tool can promise #1. These are the things that reliably help, in order:

- [ ] CI matrix green on Windows, macOS and Linux. Fill the blog's "what passed" line.
- [x] 10 canaries / 15 rules shipped. Next: 25+ and a native collector so short-lived commands are caught.
- [ ] 20-second screen recording: `ptaf selftest` -> drift -> dashboard. Put it at the top of the README.
- [x] README clone URLs fixed.
- [ ] Consider renaming the repo for discoverability (e.g. `ptaf-sentinel`).
- [ ] GitHub topics: `purple-team`, `detection-engineering`, `sigma`, `mitre-attack`, `blue-team`, `cybersecurity`.
- [ ] Tagged release v0.2.0 with notes; add a social preview image from the dashboard.
- [ ] Publish the blog first, then LinkedIn linking to it, then Show HN / r/blueteamsec / r/netsec with the "found a bug in my own rule" story, not a feature list.
- [ ] Add a GitHub Action so others can run `ptaf selftest` in their pipelines.
- [ ] Reply to every issue/PR in the first two weeks.
