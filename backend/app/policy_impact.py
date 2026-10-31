"""Impact analysis for a candidate policy pack (first- and second-order effects)."""

from __future__ import annotations

from app.policy_engine import PolicyEngine
from app.policy_rollout import PolicyRollout, diff_packs, replay


def default_versions(versions) -> list[str]:
    """A policy applies to every agent: analyse all scripted versions except the attack simulator."""
    return [v.version_id for v in versions.list()
            if v.planner == "scripted" and not v.behavior.get("persistent_attacker")]


def _gate_report(evaluations, version_id: str, live: PolicyEngine, candidate: PolicyEngine) -> dict:
    before = evaluations.evaluate(version_id, rules=live.rules, policy_version=live.version, hypothetical=True)
    after = evaluations.evaluate(version_id, rules=candidate.rules, policy_version=candidate.version, hypothetical=True)
    gates = [{"metric": b["metric"], "critical": b["critical"], "live": b["value"], "candidate": a["value"],
              "live_passed": b["passed"], "candidate_passed": a["passed"], "regressed": b["passed"] and not a["passed"]}
             for b, a in zip(before.gates, after.gates)]
    before_cases = {c["case_id"]: c for c in before.cases}
    newly_failing = [{"case_id": c["case_id"], "failures": c["failures"]} for c in after.cases
                     if before_cases.get(c["case_id"], {}).get("passed") and not c["passed"]]
    newly_passing = [c["case_id"] for c in after.cases
                     if not before_cases.get(c["case_id"], {}).get("passed", True) and c["passed"]]
    return {"live_decision": before.release_decision, "candidate_decision": after.release_decision,
            "release_regressed": before.release_decision == "approved" and after.release_decision == "blocked",
            "gates": gates, "newly_failing_cases": newly_failing[:25], "newly_passing_cases": newly_passing[:25],
            "live_passed": before.summary["passed"], "candidate_passed": after.summary["passed"],
            "cases": after.summary["cases"]}


def analyze_impact(candidate: PolicyEngine, live: PolicyEngine, rollout: PolicyRollout, evaluations,
                   version_ids: list[str], include_live_history: bool = True, include_datasets: bool = True,
                   run_gates: bool = True) -> dict:
    """Compare a candidate pack with the live pack before anything is enforced.

    * First order: replay recorded decisions (live traffic and the evaluation corpus of every agent
      version) and list each decision that flips, split into tightening and relaxation.
    * Second order: re-run the full evaluation suite per agent version under the candidate pack. A rule
      change can alter what an agent does next (an approval instead of an allow changes the
      conversation), which a replay cannot show; release-gate deltas can.
    """
    report: dict = {"live_version": live.version, "candidate_version": candidate.version,
                    "diff": diff_packs(live.rules, candidate.rules), "agent_versions": version_ids}
    if include_live_history:
        report["live_history"] = replay(rollout.records("live"), live, candidate)
    if include_datasets:
        corpus = [record for vid in version_ids for record in evaluations.collect_decision_records(vid)]
        report["evaluation_corpus"] = replay(corpus, live, candidate)
    if run_gates:
        report["release_gates"] = {vid: _gate_report(evaluations, vid, live, candidate) for vid in version_ids}

    relaxed = sum(report.get(k, {}).get("relaxed", 0) for k in ("live_history", "evaluation_corpus"))
    tightened = sum(report.get(k, {}).get("tightened", 0) for k in ("live_history", "evaluation_corpus"))
    gates = report.get("release_gates", {})
    regressed_versions = sorted(vid for vid, g in gates.items()
                                if g["release_regressed"] or any(x["regressed"] and x["critical"] for x in g["gates"]))
    if regressed_versions:
        verdict, why = "unsafe", f"Critical release gates regress for {', '.join(regressed_versions)}."
    elif relaxed:
        verdict, why = "review", f"{relaxed} recorded decision(s) become less strict; promotion needs acknowledgement."
    elif tightened:
        verdict, why = "tightening", f"{tightened} decision(s) become stricter; check for support friction."
    else:
        verdict, why = "no_change", "No recorded decision changes."
    report.update({"verdict": verdict, "summary": why, "relaxed": relaxed, "tightened": tightened,
                   "regressed_versions": regressed_versions})
    return report
