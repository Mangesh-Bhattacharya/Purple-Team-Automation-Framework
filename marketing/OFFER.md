# Offer: earning revenue within 30 days from an MIT-licensed tool

> **Pricing update (Oct 2026):** the public price list is `docs/PRICING.md` (USD, deliberately low: $149 / $790 / $49-149 per month / $390). The higher figures below were the first hypotheses and are superseded. The owner earns in CAD; at an assumed 1 USD = 1.35-1.40 CAD (check the real rate when invoicing, and the payment provider's fee) $149 is about C$200 and $790 about C$1,070. To reach a given CAD monthly target, divide it by about 1.37 and by the number of services you can deliver.


**No revenue can be promised.** The ledger records no customers, users, downloads or stars, and no pricing is in effect [FACTS.md "NOT true"]. Everything below is a plan to test, not a forecast. All prices are **HYPOTHESES**.

The tool itself stays free: MIT-licensed, open source [F2]. Anyone can run it without paying. What can be sold is the owner's time, judgment and a defined deliverable, not the software. It is a beta [F3], so every offer must state the limits [L1-L7].

## Primary offer: Detection Assurance Assessment (fixed scope, fixed price)

**One-sentence description:** The owner runs PTAF Sentinel on a small, agreed set of client machines and delivers an evidence-based report of which harmless attacker-behavior tests the client's Sigma rules caught, missed, or "no telemetry" on, with prioritized fixes [F1].

### What the client gets
- A written report per machine class: caught / missed / no-telemetry results, with the rule-gap versus blind-sensor distinction [F1, S3].
- A runnability review of up to N of the client's own Sigma rules via `ptaf rules check`, listing which can run and why not [F17, F18].
- A prioritized fix list, reviewed by a human (the tool's analysis agents are rule-based, not AI, and are a starting point only).
- A 60-minute readout call and the raw outputs (exported dashboard snapshot, JUnit from `ptaf selftest`).
- A written statement of limits and what was not tested [L1-L7].

### What is run
- `ptaf doctor` (how much the sensor can see), `ptaf canaries` (agreed list shown before anything executes), `ptaf selftest`, `ptaf rules check <dir>`.
- Only the 19 shipped canaries, which are harmless imitations [F22]. No custom exploit work, no network or credential testing.

### Scope (hypothesis)
- Up to 5 machines (mix of Windows / macOS / Linux that the client names), up to 50 client Sigma rules.
- Process-creation telemetry only [L1]. Short-lived processes may be missed on polling sensors [L2].

### Timeline (hypothesis: 10 business days from signed authorization)
- Days 1-2: scoping call, authorization signed, canary list agreed.
- Days 3-6: runs on the agreed machines, in an agreed window.
- Days 7-9: analysis and report drafting.
- Day 10: readout call, report delivered.

### Out of scope (state in writing)
Network, file, registry, authentication and cloud telemetry [L1]; hardened, EDR-protected or domain-joined fleets unless separately agreed and risk-assessed [L3]; ARM, NetHunter, physical devices [L3]; remediation work; compliance attestation or certification; any guarantee of protection [L6]; incident response.

### Client must provide
1. **Signed written authorization** naming systems, dates, and a contact (template needed; see checklist).
2. Named technical contact, access to the machines (or a person who runs commands), and an agreed test window.
3. Their Sigma rules (a directory) and a description of their SOC/EDR so alerts are expected, not mistaken for an incident.
4. Acceptance that the tests can trigger security alerts [F23] and that the tool is unsigned beta software, which may cause OS warnings [L4].

### Pricing hypothesis
- **Hypothesis A: CAD/USD 2,500 fixed** for the scope above.
- Reasoning to test: roughly 25-35 owner-hours (scoping, runs, analysis, report, readout) at an assumed value of USD 75-100 per hour. This is the owner's assumption, not market data; no market-size or competitor price is claimed.
- How to test: quote three price points (e.g. 1,500 / 2,500 / 4,000) across conversations; record where prospects hesitate; adjust. Consider a clearly labeled discounted first-engagement in exchange for permission to publish an anonymized case study only if the client actually agrees in writing. Never imply a discount is time-limited unless it truly is.
- If hours exceed 35, the scope was too wide; narrow the next quote rather than silently absorbing.

## Secondary offer 1: Paid support / retainer (hypothesis)
- **What:** Monthly rule-regression run on a client's machines (scripted `ptaf selftest`, JUnit into their CI), a drift review, and email support for the open-source tool for that client.
- **Price hypothesis:** USD 500-800 per month for up to 5 machines. Reasoning: 4-6 hours/month at the same assumed hourly value. Test it only after a primary assessment, since it needs a client who has seen the value.
- **Limits:** best-effort support on a beta [F3]; no SLA unless the owner decides to offer one (a DECISION below). No central console [L5], so the "fleet" view merges exported summaries manually.

## Secondary offer 2: Workshop (hypothesis)
- **What:** A 3-hour hands-on session: "Testing whether your detections fire" for a security team. Covers running `ptaf up`, reading caught / missed / no-telemetry, writing a rule and checking it in the Detection Lab, and the limits of the method [F1, F20, L6].
- **Price hypothesis:** USD 1,200-2,000 per session for up to 12 attendees, delivered remotely. Reasoning: about 10-14 hours including preparation. A public community session at low cost or free may be a better first step for learning what resonates.
- **Prerequisite:** attendees use machines they own or are authorized to test.

## Where leads could come from (no results claimed)
Direct outreach to people the owner already knows professionally; sharing the repo and the honest bug stories [S1-S6] in security communities; the landing page CTA to GitHub. Do not buy fake engagement or imply traction that does not exist. Conversion numbers are unknown; treat the first 30 days as a learning exercise, and treat zero sales as a possible outcome.

## Offer must-haves before selling (DECISIONS FOR THE OWNER)

- [ ] **Legal entity:** sole proprietorship versus incorporation; business registration and tax registration in the owner's jurisdiction. Consult an accountant or lawyer.
- [ ] **Invoicing and payment:** invoice tool, currency, payment terms, taxes (e.g. sales tax or VAT), payment method.
- [ ] **Authorization letter template:** written permission naming systems, IP ranges or hostnames, dates, tests to be run, emergency contact, and indemnity wording. Have a lawyer review; this is the most important document. This note is not legal advice (TERMS.md and the README are plain-language, not legal advice either).
- [ ] **Liability and insurance:** is professional liability / errors-and-omissions or cyber insurance needed before touching client machines? Does the contract cap liability? MIT and TERMS.md disclaim warranty for the tool, but that does not necessarily cover a paid service. Ask an insurer and a lawyer.
- [ ] **Master services agreement and SOW:** scope, exclusions, deliverables, acceptance, confidentiality, limitation of liability.
- [ ] **Data handling per PRIVACY.md:** the tool sends no telemetry and the agent makes no outbound connections [F2], but the owner will hold client results. Decide where they are stored, how long, how they are encrypted and deleted, and whether any process names, user names or paths in the results are sensitive. Confirm against PRIVACY.md before promising anything to a client.
- [ ] **Employment conflicts:** check whether any current employer or school (e.g. the owner's program) restricts outside paid work or IP.
- [ ] **Run the assessment on your own machines first** and keep the output as a sample redacted report. Do not call it a client example.
- [ ] **Decide on SLAs, refunds and what happens if a test causes an outage.**
- [ ] **Trademark and naming:** review TRADEMARK.md before using the PTAF name commercially.

## Ethical-selling rules
1. Never promise revenue, security outcomes, or protection. A pass is not a guarantee [L6].
2. State the beta status and limits in every proposal [F3, L1-L7].
3. Written authorization before any test; never test a system the client does not control.
4. No fake social proof, invented customers, testimonials or inflated numbers; if there are none, say nothing about it.
5. No false urgency or scarcity (no countdown discounts, no "only 2 slots" unless true).
6. Do not call the rule-based analysis agents AI.
7. Do not disparage other tools; do not claim anything about competitors that cannot be cited.
8. Be upfront that the software is free and what the client is paying for (time and expertise).
9. Decline work outside the owner's competence or the tool's tested scope [L3].
10. Treat client results as confidential.

## 30-day sketch (a plan, not a prediction)
- Week 1: resolve the DECISIONS above; dry-run on own machines.
- Week 2: publish the landing page; contact people the owner knows.
- Weeks 3-4: scoping calls; deliver an assessment if one is signed. Review what was learned, including prices that failed.
