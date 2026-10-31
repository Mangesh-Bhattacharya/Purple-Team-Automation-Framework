# 30-day launch plan: PTAF Sentinel (beta)

Draft for the human owner. Nothing here is posted or sent by an agent. Product claims carry ledger IDs from
`marketing/FACTS.md` (for example [F12]). All numeric targets are **HYPOTHESES**, not forecasts: no baseline
exists, and nothing here implies current users, stars or traffic.

Principles: lead with the honest bug stories (S1-S6), say "beta" [F3] in every post, state the limits (L1-L7)
when making broad claims, never call the analysis agents AI (they are rule-based), and give value before asking
for anything. Every named community, newsletter, conference or contact below is **unverified: verify it exists and
read its current rules before use.**

## Phase 0: finish assets first (owner decisions, before Day 1)

Do not start Day 1 until the gate items are done. Each is the owner's call.

| # | Item | Why it gates launch | Owner decision |
|---|------|---------------------|----------------|
| 0.1 | Merge PRs #4 and #5 | Launch should point at the code you describe | merge / defer, after review |
| 0.2 | Tag v0.2.0 with release notes | F3 says "not yet tagged"; posts must not say "released" until true | tag now / launch from main and say so |
| 0.3 | Record the demo (~20 s: `ptaf selftest` to drift to dashboard) | Checklist says it goes at the top of the README | record / use screenshots only |
| 0.4 | Republish the demo page | Visitors land there from posts; must show current numbers | republish / link to README instead |
| 0.5 | Legal review of TERMS / PRIVACY / assessment authorization wording | Required before selling anything (see SALES_PIPELINE.md) | engage reviewer; no paid work before |
| 0.6 | Refresh `docs/launch/blog.md` against FACTS.md | Draft is stale: it says "ten canaries / only a few rules"; ledger says 19 canaries, 21 rules, and describes sensor/privileges differently | rewrite from ledger, then re-verify every sentence |
| 0.7 | GitHub topics, social preview image, optional repo rename | Discoverability; rename breaks old links, decide once | do / skip |
| 0.8 | Set up measurement: a spreadsheet, GitHub Insights access, UTM-tagged links | Without it the metrics table below is blank | done by Day 0 |
| 0.9 | Block calendar time for Days 1-14 replies | Checklist: reply to every issue/PR in two weeks | confirm availability |

Also on Day 0: do a clean-machine run of the README "Try it" steps and confirm they work as written. Fix the README
before directing strangers to it. Read the release-app caveat: apps are unsigned [L4], so prefer the pip/pipx path
in posts.

Launch-day timing (day of week, hour, timezone) is a guess; check when your target audience is active and
choose deliberately. Do not launch on a day you cannot reply for several hours.

## Week 1: day by day

**Day 1 (Mon): publish the blog, quietly.**
- Publish the revised blog on your own site/Medium first (checklist order). Link the repo. State beta [F3].
- Pin the repo's README demo; confirm the links in the post resolve.
- Post nothing else today except a plain announcement to people who already know you, who may ask questions.
- Time budget: 2 h writing/QA, then be reachable.

**Day 2 (Tue): LinkedIn.**
- Use the LinkedIn draft in `CHANNELS.md`. Link the blog, not just the repo. Reply to every comment within hours.
- Add UTM tags to links so traffic can be attributed (method in metrics table).

**Day 3 (Wed): Show HN (the main bet).**
- Re-read the current Show HN guidelines first. Post only if you can stay online and answer for several hours.
- Title and first-comment draft in `CHANNELS.md`. Do not ask friends to upvote; that violates HN rules and is
  astroturfing. If it gets no traction, that is information; do not repost repeatedly.
- Be ready for hard questions: "polling misses short processes" [L2], "unsigned" [L4], "94% is not cross-checked
  with pySigma" [L7]. Answer plainly; do not defend.

**Day 4 (Thu): security subreddits, one at a time.**
- r/netsec and r/blueteamsec each have their own rules about self-promotion, formats and ratios. Re-read both.
  Post to one per day at most, with a distinct, topic-fit angle (see `CHANNELS.md`). If a sub forbids tool
  announcements, do not post there; contribute in discussion threads instead.

**Day 5 (Fri): triage and fix.**
- Collect every piece of feedback, issue and confusion into one list. Fix README clarity problems and quick bugs.
- Post a short "what I learned from launch feedback" reply or update only if there is real substance.

**Day 6 (Sat): rest or light replies.** No new posts. Review issues.

**Day 7 (Sun): week-1 review** (routine below). Decide what to repeat, drop or change in week 2.

## Weeks 2-4: week by week

**Week 2: Content cadence begins; community presence.**
- Publish video 1 and 2 from `marketing/videos/` (see that folder for the filenames and order; another agent is
  writing them). Reference them as `marketing/videos/<filename>` in your own calendar; verify they exist.
- Cut each into a Short/vertical clip only if the script supports it; same claims, same limits.
- Reply to every issue and PR (checklist). Label 3-5 beginner-friendly issues ("good first canary") per
  CONTRIBUTING.md to invite contributions.
- Community participation: answer 3-5 questions per week in security communities **where you have no link to
  drop**. Examples: explaining why a Sigma field matters, or how to test a rule. Only mention PTAF when it is
  directly relevant and the community allows it.
- Optional: send ONE respectful note to a maintainer-run newsletter or podcast using the template in
  `SALES_PIPELINE.md` section 8 (verify it exists and accepts submissions first).

**Week 3: Depth content and first outreach.**
- Publish video 3 and 4 from `marketing/videos/`.
- Write one technical post from facts you can re-run: the OriginalFileName story [F18, F19] or the rule-checker
  run over SigmaHQ [F17]. Include the L7 caveat. Re-run the command yourself before publishing and update the
  numbers if they changed.
- Begin discovery outreach for the assessment (SALES_PIPELINE.md), only after item 0.5 (legal review) and a
  finished `marketing/OFFER.md`. Cap at a small number of personalized messages per week (target in table).
- Submit a talk or lightning-talk proposal to a community security event if a call for papers is open
  (verify event, dates, rules). Propose a practical session on the bugs found by running rules (S1, S5).

**Week 4: Consolidate and decide.**
- Publish the remaining videos from `marketing/videos/` and a short "30 days in" post: what shipped, what broke,
  what you learned. Use only measured numbers, with your own real traffic figures if you choose to share them.
- Close the loop with everyone who gave feedback.
- Run the 30-day review (below) and write a go/no-go note: continue channel X, drop channel Y, continue or pause
  the assessment offer.

## Metrics (all targets are HYPOTHESES)

No baseline exists. Targets are placeholders to be replaced after Week 1. A missed target is information, not
failure. Do not buy stars, views or installs, and do not ask for upvotes.

| Metric | Day-30 HYPOTHESIS | How measured | Caveat |
|--------|-------------------|--------------|--------|
| GitHub stars | 100 (guess) | Repo page / Insights, weekly snapshot in the sheet | Vanity; weak signal of use |
| Installs / clones | Unknown | GitHub Insights > Traffic > Git clones (14-day window, unique cloners). No PyPI yet [F3], so no download count | Clones include bots and CI; export weekly because history is short |
| GitHub traffic (views, unique visitors) | Track only | Insights > Traffic; referrers table shows which channel sent people | 14-day retention: copy figures every week |
| Referrers by channel | Track only | UTM-tagged links + Insights referrers | Not all clicks carry referrers |
| Issues/PRs from non-owners | 5 (guess) | Count in GitHub | Quality over count |
| Video views / watch time | Track only | Platform analytics | Per-platform definitions differ |
| Discovery calls booked | 3 (guess) | CRM table in SALES_PIPELINE.md | Only from consented, personalized contact |
| Assessments sold | 0 to 1 (guess) | CRM table | One sale in 30 days is a good result; zero is normal |
| Reply time to issues | under 24 h | Manual log | Matters for early trust |

Analytics rule: no tracking pixels or telemetry may be added to the product (F2 says no telemetry). Measurement
uses only GitHub's own insights and link tags.

## Weekly review routine (30 minutes, same time every week)

1. Copy GitHub traffic (views, uniques, clones, referrers) and star count into the sheet before the 14-day window
   rolls off.
2. List posts published this week and the traffic/replies each produced (via UTM).
3. Read every comment and issue again; tag themes: confusion, bug, feature request, objection, praise.
4. Check claims: did anything posted this week say more than FACTS.md allows? Correct it publicly if so.
5. Check the CRM table: every lead has a next step and date; remove anyone who declined or went silent after two
   respectful follow-ups.
6. Decide the single most valuable next piece of content, and one thing to stop doing.
7. Update FACTS.md only with newly verified results (re-run, do not recall).

## Risks to watch

- Overclaiming under pressure in comments. Fix: quote the ledger ID or say "not tested".
- Launching while the README path is broken. Fix: Day 0 clean-machine run.
- Selling before legal review. Fix: gate 0.5.
- Treating one thread's silence or criticism as the whole market. It is one data point.
