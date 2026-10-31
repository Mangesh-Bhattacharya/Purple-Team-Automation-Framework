"""Local analysis agents for the dashboard.

Five small, single-purpose analysers turn the numbers on the page into decisions:

* Triage    - ranks what needs attention and says WHY it ranks there
* Explain   - plain-language guidance for each technique (from ptaf.knowledge)
* Fix       - a step-by-step checklist per gap or blind spot, with the exact commands
* Planner   - what to test next to widen verified coverage
* Readiness - a transparent checklist score for "is this deployment ready to rely on"

They are RULE-BASED and run entirely on data already on this machine: no model, no network, no
data leaves. The dashboard says so. They are deterministic, so the same input always gives the same
advice, which makes them testable and auditable. They never invent facts: where the knowledge base
has nothing, they say so.
"""

from __future__ import annotations

from typing import Any

from . import knowledge

DISCLOSURE = (
    "These agents are rule-based and run locally on this page's own data. No AI model is "
    "called and nothing leaves this machine."
)

_RANK = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
_WHY = {
    "drift": "A behavior that WAS protected stopped being protected. Something changed recently, "
    "so the cause is usually the cheapest to find and fix.",
    "gap": "A safe test of this behavior ran and nothing alerted. This is a proven hole, not a guess.",
    "blind": "You cannot tell whether you are covered. Unknown is not safe: fix the sensor first.",
    "agent": "If the agent is not running, nothing is being checked and a silent failure would go "
    "unnoticed.",
    "overdue": "Checks are the early-warning system; overdue checks mean stale assurance.",
    "sensor": "The sensor is how the tool sees anything at all. Errors here weaken every result.",
    "rules": "A rule that fails to load protects nothing.",
    "health": "A failed health check is a precondition problem that makes other results unreliable.",
    "info": "Not urgent, but it limits what the tool can verify.",
    "ok": "Everything checked is healthy.",
}


def triage(attention: list[dict[str, str]]) -> list[dict[str, Any]]:
    out = []
    for i, item in enumerate(sorted(attention, key=lambda a: _RANK.get(a["level"], 9))):
        out.append(
            {
                **item,
                "rank": i + 1,
                "because": _WHY.get(item.get("kind", "info"), _WHY["info"]),
            }
        )
    return out


def explain(matrix: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Guidance for every technique on the matrix, keyed by technique id."""
    out = {}
    for cell in matrix:
        info = knowledge.lookup(cell["technique_id"])
        out[cell["technique_id"]] = {
            "name": info["name"],
            "tactics": info["tactics"],
            "why": info["why"],
            "signal": info["signal"],
            "fp": info["fp"],
            "telemetry": info["telemetry"],
            "url": info["url"],
            "curated": info["curated"],
            "state": cell["state"],
        }
    return out


def _canary_for(summary: dict[str, Any], technique_id: str) -> str | None:
    for r in (summary.get("latest") or {}).get("results", []):
        if r.get("technique_id") == technique_id:
            return r.get("canary_id")
    return None


def fix(summary: dict[str, Any], rule_titles: dict[str, list[str]]) -> list[dict[str, Any]]:
    """A checklist for each gap or blind spot. Commands are real `ptaf` commands."""
    items = []
    for cell in summary.get("matrix", []):
        if cell["state"] not in ("gap", "blind"):
            continue
        tid = cell["technique_id"]
        info = knowledge.lookup(tid)
        canary = _canary_for(summary, tid)
        only = f" --only {canary}" if canary else ""
        steps: list[dict[str, str]] = []
        if cell["state"] == "blind":
            steps = [
                {"text": "Run the preflight and read the process-visibility and sensor lines.",
                 "command": "ptaf doctor"},
                {"text": "On Linux or Kali, run as root to get the event-driven sensor and full "
                 "visibility.", "command": 'sudo "$(command -v ptaf)" doctor'},
                {"text": "Re-run just this test once the sensor is healthy.",
                 "command": f"ptaf selftest{only}"},
            ]  # fmt: skip
        elif info["telemetry"] != "process_creation":
            steps = [
                {"text": f"PTAF verifies process-creation telemetry. This technique needs "
                 f"'{info['telemetry']}' telemetry, so confirm the detection in your SIEM or EDR "
                 "instead; the starter rule below is a place to begin."},
                {"text": "Replay a safe version of the behavior on a test machine and confirm an "
                 "alert fires in your own tooling."},
            ]  # fmt: skip
        else:
            shipped = rule_titles.get(tid, [])
            steps = [
                {
                    "text": "Re-run the test and read what the sensor actually observed.",
                    "command": f"ptaf selftest{only} --format json",
                },
                {
                    "text": "Compare the observed Image and CommandLine with the rule's selection. "
                    "A path, flag or case difference is the usual cause."
                },
            ]
            if shipped:
                steps.append({"text": f"A shipped rule maps here ({shipped[0]}) but did not match. "
                              "Widen or correct its selection, then check the rule loads.",
                              "command": "ptaf rules check --strict"})  # fmt: skip
            else:
                steps.append({"text": "No rule maps to this technique. Start from the template below "
                              "and drop it in your rules directory."})  # fmt: skip
            steps.append({"text": "Re-test; a fix should turn this tile green.",
                          "command": f"ptaf selftest{only}"})  # fmt: skip
        items.append(
            {
                "technique_id": tid,
                "name": info["name"],
                "state": cell["state"],
                "canary_id": canary,
                "telemetry": info["telemetry"],
                "steps": steps,
                "starter": info.get("starter"),
                "false_positives": info["fp"],
            }
        )
    return items


def planner(summary: dict[str, Any]) -> list[dict[str, Any]]:
    """What to verify next, most valuable first."""
    matrix = summary.get("matrix", [])
    verified_tactics = {
        t
        for c in matrix
        if c["state"] == "verified"
        for t in knowledge.lookup(c["technique_id"])["tactics"]
    }
    out: list[dict[str, Any]] = []
    for c in matrix:
        if c["state"] != "unverified":
            continue
        info = knowledge.lookup(c["technique_id"])
        new_tactic = [t for t in info["tactics"] if t not in verified_tactics]
        out.append(
            {
                "kind": "test",
                "title": f"Verify {c['technique_id']} ({info['name']})",
                "why": "A rule claims to cover this but nothing has ever tested it on this machine."
                + (
                    f" It would be your first verified coverage of {new_tactic[0]}."
                    if new_tactic
                    else ""
                ),
                "action": "Add a canary for it (a harmless local command shaped like the behavior). "
                "See CONTRIBUTING.md for the safety bar.",
                "score": 2 + (1 if new_tactic else 0),
            }
        )
    for tactic in knowledge.TACTIC_ORDER:
        if tactic in verified_tactics:
            continue
        if any(tactic in knowledge.lookup(c["technique_id"])["tactics"] for c in matrix):
            continue  # already represented (as gap/blind/unverified), covered by the items above
        out.append(
            {
                "kind": "tactic",
                "title": f"No coverage at all in {tactic}",
                "why": knowledge.TACTIC_STORY[tactic],
                "action": "Pick a technique in this tactic, write a rule and a canary for it.",
                "score": 1,
            }
        )
    return sorted(out, key=lambda x: -x["score"])


def readiness(summary: dict[str, Any]) -> dict[str, Any]:
    """A transparent checklist, NOT a risk rating. Every point is explained."""
    agent = summary.get("agent") or {}
    latest = summary.get("latest") or {}
    col = agent.get("collector") or {}
    host_os = (summary.get("host") or {}).get("os")
    factors: list[dict[str, Any]] = []

    def factor(name: str, weight: int, earned: float, detail: str, nxt: str = "") -> None:
        status = "ok" if earned >= weight else "warn" if earned > 0 else "fail"
        factors.append({"name": name, "weight": weight, "earned": round(earned, 1),
                        "status": status, "detail": detail, "next": nxt})  # fmt: skip

    health = agent.get("health", "never")
    factor("Agent is running", 25, {"online": 25, "stale": 12}.get(health, 0),
           f"Agent is {health}.", "" if health == "online" else "Start it: ptaf monitor")  # fmt: skip

    kind = col.get("kind")
    if host_os == "linux":
        factor("Event-driven sensor", 15, 15 if kind == "event" else 5 if kind == "poll" else 0,
               "Event-driven sensor in use." if kind == "event" else "Polling sensor: can miss "
               "very short-lived commands.",
               "" if kind == "event" else 'Run as root: sudo "$(command -v ptaf)" monitor')  # fmt: skip
    else:
        factor("Sensor working", 15, 15 if kind else 0,
               f"Sensor: {col.get('name', 'none')}.", "" if kind else "Run ptaf doctor")  # fmt: skip

    vis = next((c for c in (summary.get("health_checks") or {}).get("checks", [])
                if c.get("name") == "process visibility"), None)  # fmt: skip
    if vis is None:
        factor("Process visibility", 15, 0, "No health check recorded yet.", "Run ptaf doctor")
    else:
        factor(
            "Process visibility",
            15,
            15 if vis["status"] == "ok" else 7 if vis["status"] == "warn" else 0,
            vis["detail"],
            "" if vis["status"] == "ok" else "Run the agent as root/Administrator",
        )

    loaded, errors = latest.get("rules_loaded", 0), len(latest.get("rule_errors") or [])
    ratio = (loaded / (loaded + errors)) if (loaded + errors) else 0
    factor("Rules load cleanly", 15, 15 * ratio, f"{loaded} loaded, {errors} failed.",
           "" if not errors else "Fix them: ptaf rules check")  # fmt: skip

    cov = latest.get("coverage_percent")
    factor("Verified coverage", 20, 0 if cov is None else 20 * cov / 100,
           "No results yet." if cov is None else f"{cov:g}% of testable behaviors detected.",
           "" if cov == 100 else "Work the Fix agent's checklist")  # fmt: skip

    overdue = any(i.get("kind") == "overdue" for i in summary.get("attention", []))
    factor("Checks are current", 10, 0 if overdue or not latest else 10,
           "Self-tests are overdue." if overdue else "Self-tests are on schedule.",
           "Check the agent is not stuck" if overdue else "")  # fmt: skip

    total = sum(f["weight"] for f in factors)
    score = round(100 * sum(f["earned"] for f in factors) / total)
    # A deployment with an open gap or a regression is not "ready", however healthy the plumbing.
    open_findings = [i for i in summary.get("attention", []) if i.get("kind") in ("gap", "drift")]
    capped = bool(open_findings) and score > 79
    if capped:
        score = 79
    band = "ready" if score >= 85 else "nearly" if score >= 60 else "not yet"
    return {
        "score": score,
        "band": band,
        "capped": capped,
        "factors": factors,
        "note": "A transparent checklist, not a risk rating. It says how far this deployment is "
        "from being something you can rely on, and what to do next.",
    }


def killchain(summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Tactics left to right, each with the techniques PTAF knows about and their state."""
    by_tactic: dict[str, list[dict[str, Any]]] = {t: [] for t in knowledge.TACTIC_ORDER}
    for c in summary.get("matrix", []):
        info = knowledge.lookup(c["technique_id"])
        tactic = (info["tactics"] or [None])[0]
        if tactic in by_tactic:
            by_tactic[tactic].append(
                {
                    "id": c["technique_id"],
                    "name": info["name"],
                    "state": c["state"],
                    "why": info["why"],
                }
            )
    return [
        {"tactic": t, "story": knowledge.TACTIC_STORY[t], "techniques": by_tactic[t]}
        for t in knowledge.TACTIC_ORDER
    ]


def run_agents(
    summary: dict[str, Any], rule_titles: dict[str, list[str]] | None = None
) -> dict[str, Any]:
    rule_titles = rule_titles or {}
    return {
        "disclosure": DISCLOSURE,
        "triage": triage(summary.get("attention", [])),
        "explain": explain(summary.get("matrix", [])),
        "fix": fix(summary, rule_titles),
        "planner": planner(summary),
        "readiness": readiness(summary),
        "killchain": killchain(summary),
    }
