# Voice ads (scripts and production notes)

Audio is **not generated yet**. Generating spends ElevenLabs credits, so it needs a go-ahead.
Voice direction for all three: warm, unhurried, conversational, a person talking to
a colleague, not an announcer. Slight smile on the last line. No hype words.

## 15s: "The battery"
> A smoke alarm with a dead battery looks fine. Until it doesn't.
> Your detection rules can fail the same way, silently.
> PTAF Sentinel tests them on every machine, and tells you when one stops working.
> Open source. Search PTAF on GitHub.

## 30s: "The backslash"
> I found a bug in my own security rule last week.
> One extra backslash. It meant the rule could never match a real Windows path.
> It had passed every check for weeks, because nothing ever actually ran it.
> So I built PTAF Sentinel. It safely imitates attacker behavior on your machines,
> and checks whether your alarms really ring.
> If one goes quiet, you hear about it first.
> PTAF Sentinel. Open source, on GitHub.

## 45s: "Quiet isn't safe" (for clients)
> When your security dashboard is quiet, that feels like good news.
> But quiet can also mean something broke.
> A rule was edited. A log stopped flowing. An update changed how things are reported.
> PTAF Sentinel checks, all day, on Windows, Mac and Linux, even inside virtual machines.
> It runs harmless tests that look like real attacks, and tells you in plain English
> what it caught, what it missed, and what to do about it.
> No jargon. No guessing.
> PTAF Sentinel. Free and open source. Find it on GitHub.

## Storyboard for a 30s video cut
0-5s dashboard hero line; 5-12s the doubled-backslash diff; 12-22s terminal:
`ptaf selftest` showing DETECTED, then DRIFT; 22-30s dashboard turning from amber
to green, end card with repo URL. Use the site theme (amber on dark brown).

## Disclosure
Label as AI-generated voice wherever the platform asks. Do not imitate a real person's voice.
