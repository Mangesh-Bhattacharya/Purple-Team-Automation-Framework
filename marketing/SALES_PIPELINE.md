# Sales pipeline: Detection Assurance Assessment

Draft for the human owner. Price, scope details and legal terms are owner decisions; see `marketing/OFFER.md`
(written by another agent; read it first and keep this file consistent with it). Nothing is sent by an agent.
Product claims use ledger IDs from `marketing/FACTS.md`. No customers, results or testimonials exist; never
imply them. Every named organization or community must be verified before use.

## 1. What is being sold (stay inside the ledger)

A fixed-scope engagement in which, **with written authorization** on systems the client owns, you run the PTAF
Sentinel harmless tests [F1], run the client's Sigma rules against that machine's own process telemetry, and
deliver a report of what was caught, missed and newly stopped being caught. Be explicit with the client:

- Beta software [F3]. Process-creation telemetry only [L1]. Short-lived processes can be missed [L2].
- Not tested on hardened/EDR-protected fleets [L3]. A pass is one test, one rule, one machine, one moment
  [L6]; it is not a security guarantee or certification.
- It does not replace a SIEM, EDR or penetration test. Never use words like "complete coverage" or "enterprise
  ready".

## 2. Ideal customer profile (HYPOTHESES to test, not market data)

Good fit (hypothesis): small security teams or MSSPs that write or tune their own Sigma rules, run Windows or
Linux endpoints, have a detection engineer or security lead who can sign authorization, and want evidence that
rules fire.
Poor fit: organizations needing network/cloud/identity coverage (L1), compliance certification, 24/7 response,
or testing on production-critical systems without a maintenance window.

Track which segments actually respond; revise this section after ten conversations.

## 3. Qualification questions

1. Who writes and maintains your detection rules, and how do you know a rule still fires?
2. Do you use Sigma (or convert it)? Roughly how many rules, and which log sources?
3. Which endpoints (Windows, Linux, macOS) and sensors (EDR, Sysmon, auditd) are in scope?
4. Is process-creation coverage useful to you, given the other telemetry types are out of scope today [L1]?
5. Who can sign written authorization for testing named systems, and in what time window?
6. Are there systems that must not be touched (production, regulated, medical, OT)?
7. Will the security tooling alert on the tests, and who must be told in advance so it is not treated as an
   incident?
8. What decision would a result change (rule fixes, tool purchase, report to management)?
9. Timeline, budget owner and procurement steps?
10. Do you have an existing assessment vendor or internal red/purple team we should coordinate with?

Disqualify politely when: no authorization authority, systems are not theirs, the need is outside process
telemetry, or they want guarantees.

## 4. Written authorization (required before ANY testing)

No test runs on any system until the client has signed a written authorization. Have it reviewed by a lawyer
(PLAN_30_DAYS gate 0.5); this outline is not legal advice.

Minimum contents (checklist):
- Legal entity and signatory with authority over the systems.
- Exact in-scope hosts (names/IPs), operating systems and the testing window (dates, times, timezone).
- Statement that PTAF runs harmless tests which can trigger security alerts, and that the SOC/MSSP and any
  third-party hosting provider have been informed or have consented.
- Permitted actions (installing the agent, running listed canaries) and prohibited actions (anything outside the
  listed canaries, data access, persistence, network testing).
- Canary list attached: output of `ptaf canaries` (it lists what will run without executing anything).
- Emergency contact for both sides and a stop procedure (`Ctrl-C` stops cleanly [README]).
- Data handling: what leaves the machine (the agent makes no outbound connections [F2]; deliverable is created
  by the assessor), retention and deletion.
- Liability, warranty disclaimer and confidentiality, as drafted by counsel. Reference TERMS.md only as the
  tool's license terms, not as the engagement contract.

Refuse to proceed on verbal approval, email from someone without authority, or systems owned by a third party
(for example cloud-hosted machines) without that third party's consent.

## 5. Discovery call script (30 minutes)

1. **Open (2 min).** "Thanks for the time. I'll ask about how you handle detection rules, tell you what I do and
   don't do, and we can both decide whether it's worth a next step. It's fine to say no at any point."
2. **Their situation (10 min).** Ask qualification questions 1-3, 7, 8. Listen; take notes in their words.
3. **Tool and honesty (5 min).** Describe the harmless tests and results [F1]. State: beta [F3], process
   telemetry only [L1], not tested on hardened/EDR fleets [L3], a pass is not a guarantee [L6]. Offer a free
   look at the open-source tool first.
4. **Assessment outline (5 min).** Scope, deliverable, duration, authorization requirement (section 4), and
   that price and terms are in a written proposal.
5. **Fit check (5 min).** Ask question 4, 5, 6, 9. Say plainly if they are not a good fit and suggest what might
   serve them better.
6. **Close (3 min).** Agree one next step with a date (proposal, a technical call, or "no thanks"). Send notes
   the same day.

Do not quote a price on the call unless OFFER.md defines it; do not promise outcomes.

## 6. One-page proposal outline

1. **Objective** in the client's words from discovery.
2. **Scope:** hosts, OS, rule set (count and source), telemetry type (process creation), window.
3. **Method:** harmless tests listed via `ptaf canaries`; rules executed on the host's own telemetry; drift
   comparison if a prior baseline exists.
4. **Deliverables:** findings list (caught / missed / no telemetry), rule fixes suggested, rerun after fixes if
   included, a handover session.
5. **Limits and assumptions:** the L1-L6 list as it applies, plus client responsibilities.
6. **Authorization:** signed document required before start; testing date contingent on it.
7. **Timeline** (owner to set) and **fee / terms** (owner to set per OFFER.md).
8. **Out of scope:** network/cloud/identity testing, remediation, incident response, certification.
9. **Acceptance:** how completion is judged; one revision round.
10. **Next step and validity date.**

## 7. Objection handling (honest answers)

| Objection | Response |
|---|---|
| "It's beta." | Yes [F3]. That is why scope is fixed and limits are written down; the code is open for inspection (MIT) [F2]. |
| "We already have an EDR." | PTAF does not replace it [not a claim]. It checks whether your rules fire on your telemetry; an EDR update that changes reporting is exactly the drift case [F1]. Not tested on EDR-protected fleets [L3], so scope that explicitly. |
| "Can you prove we're covered?" | No. A pass is one test caught by one rule at one time [L6]. |
| "Why pay if it's free?" | The tool is free. The engagement covers setup, execution under authorization, interpretation and rule fixes. If you'd rather run it yourself, I'll help you start. |
| "No reference customers?" | Correct, there are none. I can show the open code, CI results [F10] and the bugs I found in my own work [S1]. A reduced-scope pilot is an option if the owner offers one. |
| "Will this trigger our SOC?" | Possibly. That is why the authorization names who is informed and the window. |
| "Is it safe?" | The tests are designed to be harmless (sleep, decode a constant, read-only queries, print versions) and a test enforces it [README]. Safe-by-design is not safe-by-guarantee; review the canary list first. |
| "Covers only processes?" | Yes [L1]. If you need more, this isn't the right engagement yet. |
| "Is it AI?" | No. The analysis agents are rule-based and local. |
| "Price too high / no budget." | Accept it; offer the free tool and a check-in later. |

## 8. Outreach templates (personalized, honest, easy to decline)

Rules: only contact people with a plausible, specific reason; use their public work; one message and at most
one follow-up after about a week; no purchased lists, no scraping private data, no bulk automation, no
misleading subject lines; comply with the anti-spam law that applies (for example CAN-SPAM, GDPR/PECR, CASL;
ask counsel). Include a clear way to opt out and honor it immediately. Do not ask for introductions through
people you do not know.

**A. Peer / practitioner (LinkedIn message or email)**
> Hi <name>, I read your <specific post/talk> on <topic> and it matched a problem I've been working on: rules
> that silently stop firing. I'm the author of PTAF Sentinel, a free open-source beta that runs harmless tests
> and checks whether Sigma rules fire [F1, F2, F3]. I'm looking for feedback from detection engineers, not a
> sale. If you're open to a 15-minute chat or would rather just look at the repo (<link>), either is welcome.
> If it isn't relevant, ignore this and I won't follow up more than once.

**B. Possible assessment lead (after they replied or showed interest)**
> Hi <name>, thanks for your reply. You mentioned <their words>. I offer a fixed-scope assessment where, with
> written authorization, I run the tests on named systems and report which of your rules fired. It is beta
> software and covers process creation only [F3, L1]. Would a 30-minute call be useful, or would you prefer a
> one-page outline first? Happy to leave it here if now isn't the time.

**C. Follow-up (once, ~7 days later)**
> Hi <name>, a quick follow-up in case my note was buried. No problem if this isn't relevant; I'll close the
> loop on my side either way.

**D. Decline reply**
> Thanks for letting me know. I've removed you from my list. If you ever want to try the open-source tool, the
> repo is <link>.

## 9. CRM table template

Keep in a private spreadsheet. Store only information the person has made public or given you, with a purpose
and deletion date; delete on request.

| ID | Date added | Name / role | Organization | Source (how I found them, public link) | Consent to contact? (Y/N, how) | Stage | Last contact | Next step + date | Notes (their words) | Authorization signed? | Outcome | Delete by |
|----|-----------|-------------|--------------|-----------------------------------------|-------------------------------|-------|-------------|------------------|--------------------|----------------------|---------|-----------|
| 1 | | | | | | Identified | | | | N/A | | |
| 2 | | | | | | Replied | | | | N/A | | |
| 3 | | | | | | Discovery | | | | N/A | | |
| 4 | | | | | | Proposal sent | | | | No | | |
| 5 | | | | | | Authorized | | | | Yes | | |
| 6 | | | | | | Delivered | | | | Yes | | |

Stages: Identified, Contacted, Replied, Discovery done, Proposal sent, Authorization signed, Testing window
scheduled, Delivered, Closed (won / lost / declined / not a fit). Never move a lead to "Testing" without a
signed authorization on file.

## 10. Pipeline hygiene

- Review weekly with the metrics routine in PLAN_30_DAYS.md.
- Record reasons for "lost" in the client's words; they feed the ICP.
- Never state pipeline numbers publicly as traction. Count only what happened.
