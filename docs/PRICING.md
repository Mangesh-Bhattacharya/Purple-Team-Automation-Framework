# Pricing

**The software is free.** PTAF Sentinel is open source (MIT). Install it, run it, modify it, use it at work. No licence key, no seat limit, no telemetry.

You only pay if you want a person to help. All prices are in **US dollars**, and every service is deliberately small and fixed-price so a solo engineer or a small team can say yes without a procurement process.

| Service | Price (USD) | What you get |
|---|---|---|
| **Community** | Free | The tool, the docs, and best-effort help through GitHub issues. |
| **Rules Health Check** | **$149** one-time | You run `ptaf rules check` and `ptaf selftest` on your own machine and send me the exported summary. I send back a written report within 3 business days: which of your Sigma rules PTAF can run, which tests were missed, and the fixes I would make first. **I never get access to your systems.** |
| **Detection Assurance Assessment** | **$790** one-time | Everything in the Health Check for up to 5 machines and up to 50 rules, plus a 60-minute call to walk through results. Report within 5 business days. |
| **Support** | **$49** / month (solo or up to 3 machines) · **$149** / month (up to 25 machines) | Email help with a response within 2 business days, a monthly look at your drift report, and priority on your bug reports. Best effort, **no uptime or response guarantee**. Cancel any month. |
| **Team workshop** | **$390** per session | 90 minutes, remote, up to 10 people: set up PTAF, read the results, write your first custom check. |

## Honest terms

- This is a **beta** (v0.2.0). It tests process creation only, and a pass means one harmless test was caught by one rule on that machine at that time. It is not a security guarantee. See [Honest limits](../README.md#honest-limits).
- Only test systems you own or are authorized to test. For client work, get written authorization first; its tests can trigger security alerts.
- Prices may change for new customers. A price you agreed to stays the same for that engagement.
- Taxes (such as GST/HST or VAT) are added where they apply.

## How to buy

Open an issue titled **"Services"** or message the maintainer through the contact on the [author page](https://mangesh-bhattacharya.github.io). Payment links are being set up; until then, agree scope and price by email first, and pay by invoice.

## Why these numbers

They are starting points, not market research. They are meant to be low enough that a one-person team can pay from a discretionary budget. They will be adjusted from real conversations.
