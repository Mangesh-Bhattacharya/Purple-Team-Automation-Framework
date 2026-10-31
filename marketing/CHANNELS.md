# Channel playbooks: PTAF Sentinel (beta)

Drafts for the human owner to edit and post personally. An agent never posts. Claims use only ledger facts
(`marketing/FACTS.md`); IDs are in brackets and must be deleted from the text before posting. Targets are in
PLAN_30_DAYS.md and are hypotheses.

## Rules for every channel

1. **Re-read that community's CURRENT rules before posting.** Self-promotion, link, flair, ratio, account-age and
   format rules change. If the rules forbid tool announcements, do not post; contribute elsewhere.
2. **Every named newsletter, community, conference, podcast or contact here is unverified: verify it exists and
   check its current submission rules before use.** The agent that wrote this could not check any of them.
3. Disclose that you are the author. Say it is a **beta** [F3]. Include a limit when you make a broad claim.
4. No upvote requests, no alt accounts, no coordinated "support" comments, no bought stars/views, no mass DMs.
5. Never say "AI-powered": the five analysis agents are rule-based and local.
6. Never claim customers, users, stars or testimonials. None exist in the ledger.
7. Be reachable for several hours after posting. Answer criticism with facts, not defense.

Common honest limits to have ready: process-creation telemetry only [L1]; 50 ms polling can miss very short
processes [L2]; tested on CI runners and one dev Mac, not hardened/EDR fleets [L3]; unsigned apps [L4]; a pass is
one test caught by one rule at one time, not a guarantee [L6]; 94% is not cross-checked with pySigma [L7].

---

## 1. Hacker News: Show HN

**Angle:** a small tool plus the honest story that "the rule passed syntax checks for weeks and could never
match" [S1]. HN favors something people can try right now, plainly described.

**Before posting:** read the current Show HN guidelines. Make sure the README install works on a clean machine.

**Title draft (edit, keep it factual, no superlatives):**
`Show HN: PTAF Sentinel - run harmless attacker-style tests to check your Sigma rules fire (beta)`

**First comment draft (post as the author):**
> I built this because detection rules fail silently: a rule gets edited or a pipeline breaks and nothing errors.
> PTAF Sentinel runs harmless imitations of attacker behavior on a machine, runs Sigma rules against that
> machine's own process telemetry, and reports what was caught, missed, or newly stopped being caught [F1].
> It is MIT-licensed Python with no telemetry [F2], and it is a beta (v0.2.0, not on PyPI, unsigned apps) [F3].
>
> A story that convinced me: my own example PowerShell rule had a doubled backslash and could never match a real
> Windows path, yet it passed syntax checks for weeks. I only found it the first time the rules were executed [S1].
> Another: on Windows the API reported cmd.exe's original name as "Cmd.Exe.MUI", so rules for cmd.exe would have
> silently missed [S5].
>
> What I measured: a rule-checker over all 3,161 public SigmaHQ rules had 0 load errors [F17]; 1,304 of 1,383
> process-creation rules (94%) are runnable by it, meaning it can evaluate them, not that they are good, and I
> have not cross-checked the figure against pySigma [F18, L7]. On a real Linux kernel with the event-driven
> sensor 9 of 9 canaries were detected, including real nmap, hydra, sqlmap and tcpdump [F12].
>
> Limits: process-creation telemetry only [L1]; the default sensor polls every 50 ms and can miss very short
> processes [L2]; tested on CI runners and one developer Mac, not hardened or EDR-protected fleets [L3].
> Only use it on systems you are authorized to test. Feedback on the limits is the most useful thing you can give.

**Rule reminder:** HN prohibits soliciting votes and manipulating ranking. Do not share the link asking people to
upvote, even privately.

## 2. r/netsec

**Angle:** technical write-up, not a product pitch. r/netsec generally favors technical content over marketing.
Candidate: "What I found by actually executing my detection rules" (S1, S2, S3, S5), with the tool as a footnote.

**Before posting:** read the sidebar rules and check whether tool/self-promotion posts are allowed and how they
must be tagged. If a technical post is the only fit, link the blog post, not the repo.

**Draft:**
> Title: Four ways my detection rules were silently broken, found only by executing them
>
> I wrote a small open-source harness that runs harmless attacker-style tests and checks whether Sigma rules
> fire. The bugs it surfaced in my own setup: (1) an example PowerShell rule with a doubled backslash that could
> never match a Windows path and passed syntax checks for weeks [S1]; (2) a normal `pip install` that shipped the
> agent with zero rules [S2]; (3) a blind sensor that exited 0 and could have passed a CI gate, now exit code 3
> [S3]; (4) cmd.exe's original name reported as "Cmd.Exe.MUI" on Windows [S5]. Write-up and the tool (beta, MIT)
> in the link. I'm the author. Limits: process-creation telemetry only, tested on CI runners and one dev Mac
> [L1, L3].

## 3. r/blueteamsec

**Angle:** defender workflow. Detection engineers care about regression testing: "did this rule stop firing?"
and "is the sensor blind or is the rule wrong?" [F1, README: missed vs no telemetry].

**Before posting:** read the rules; the community is link-oriented and may have its own format conventions.

**Draft:**
> Title: PTAF Sentinel (beta): drift alerts for detection rules, with a "rule gap" vs "blind sensor" distinction
>
> Runs harmless attacker-behavior tests, executes your Sigma rules against the host's own process telemetry, and
> reports caught / missed / newly stopped being caught [F1]. It separates a missed rule from a sensor that can't
> see (exit 1 vs exit 3, JUnit output available) so a blind sensor can't pass a CI gate [S3, F22].
> `ptaf rules check <dir>` reports which of your rules it can evaluate and why not for the rest [F17, F18].
> MIT, no telemetry [F2]. Beta; process-creation only [L1]. I'm the author and would value critique from
> detection engineers.

## 4. LinkedIn

**Angle:** the "smoke alarm with no battery" analogy from the blog, for security leads and practitioners. A
plain-language story, then link to the blog. Most useful for later discovery conversations.

**Before posting:** check LinkedIn's current professional community policies; do not tag people who have not
agreed; no engagement pods.

**Draft:**
> A smoke alarm with a dead battery looks exactly like one that works. Detection rules can be the same.
>
> A rule gets edited, a log pipeline breaks, nothing errors, and quiet looks like safe.
>
> I've been building PTAF Sentinel, an open-source (MIT) beta that runs harmless imitations of attacker behavior,
> runs Sigma rules against the machine's own telemetry, and tells you what was caught, missed, or newly stopped
> being caught [F1, F2, F3].
>
> The most useful lesson so far: my own example PowerShell rule could never match a real Windows path and passed
> syntax checks for weeks. I only found out by running it [S1].
>
> It is early. It checks process-creation behavior only, and one passing test is not a guarantee of protection
> [L1, L6]. I'd welcome feedback from detection engineers. Blog and repo in the first comment.

## 5. X (Twitter)

**Angle:** one concrete bug per post, with the demo clip. Short, no hype threads.

**Before posting:** check the current platform rules on automation and links. Do not use bots or purchased reach.

**Draft thread:**
> 1/ Detection rules fail silently. Mine did: an example PowerShell rule with a doubled backslash could never
> match a real Windows path, and passed syntax checks for weeks [S1].
> 2/ PTAF Sentinel (beta, MIT) runs harmless attacker-style tests, runs your Sigma rules on the machine's own
> process telemetry, and reports caught / missed / newly stopped [F1, F2, F3].
> 3/ It tells a rule gap from a blind sensor with different exit codes, so a blind sensor can't pass CI [S3].
> 4/ Limits: process-creation only, 50 ms polling can miss short processes, tested on CI runners and one dev Mac
> [L1, L2, L3]. Repo: <link>

## 6. YouTube and Shorts

**Angle:** show it working. Scripts come from `marketing/videos/` (another agent is writing them; reference by
filename once they exist, and verify each script's claims against the ledger before recording).

**Before posting:** read YouTube's current policies on security demonstrations; present only harmless tests, on
a machine you own. Add the beta note and limits in the description. Avoid reproducing any real-malware content.

**Description draft:**
> PTAF Sentinel (beta, MIT) runs harmless imitations of attacker behavior and checks whether your Sigma rules
> catch them [F1, F2, F3]. Only process-creation telemetry is covered; one passing test is not a guarantee
> [L1, L6]. Use only on systems you are authorized to test. Repo: <link>

Shorts: one bug story each (S1, S5, S6). Keep the on-screen numbers to measured ones [F13: ~1.9 s to server,
~10.8 s to first results, measured once on macOS].

## 7. Security newsletters and podcasts

**Angle:** pitch the story (rules fail silently, found by executing them), not the product. Offer to share
lessons or answer questions.

**Before using:** I cannot confirm any specific newsletter or podcast exists, is active, or accepts
submissions. Search for current security newsletters and podcasts in your field; open each one's submission or
contact page; verify it exists and its current submission rules before use. Pitch only if their stated format
fits. Send at most one message per outlet and accept silence or "no" gracefully. Do not pay for placement
while implying editorial coverage.

**Pitch draft (see SALES_PIPELINE.md section 8 for tone):**
> Subject: A detection-testing lesson: my own rule passed syntax checks for weeks and could never match
>
> Hi <name>, I read <specific recent item>. I'm the author of PTAF Sentinel, an open-source (MIT) beta that
> runs harmless attacker-style tests and checks whether Sigma rules fire [F1, F2, F3]. The story that might
> interest your readers: my own example rule had a doubled backslash and never matched a real Windows path
> [S1]. Happy to write 400 words on it or answer questions; no problem at all if it isn't a fit.

## 8. BSides / DEF CON-type community talks

**Angle:** a practical 20-30 minute talk or lightning talk: "What happens when you actually run your detection
rules." Content: S1, S2, S3, S5, plus the missed-vs-blind-sensor distinction, with honest limits.

**Before use:** I cannot verify any specific event, date or call for papers. Find current events, confirm they
exist, read each event's CFP rules, deadlines and speaker requirements, and follow code-of-conduct and
sponsorship rules. Do not use a talk as a sales pitch if the event bans it.

**Abstract draft:**
> Detection rules fail silently. This talk walks through bugs found only by executing rules: a PowerShell rule
> that could never match a real Windows path and passed syntax checks for weeks [S1], a package that shipped
> with zero rules [S2], and a sensor that could be blind yet exit 0 [S3]. We show a free, open-source beta
> harness [F2, F3] and the limits of what it can tell you [L1, L6]. Attendees leave with a checklist for
> regression-testing their own rules.

Prepare a live-demo fallback (screenshots or a recorded run) because live demos fail.
