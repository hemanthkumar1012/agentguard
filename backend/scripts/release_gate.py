"""Run the SentinelForge release gates for an agent version from the command line / CI.

    python scripts/release_gate.py support-agent-v1.0                 # exit 1 if blocked
    python scripts/release_gate.py support-agent-v2.0 --expect blocked  # prove the gates catch a regression
    python scripts/release_gate.py support-agent-v2.1 --json report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.evaluation import METRICS  # noqa: E402
from app.services import evaluation_engine  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("version_id")
    parser.add_argument("--expect", choices=["approved", "blocked"], default="approved")
    parser.add_argument("--datasets", nargs="*")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--json", type=Path, help="Write the full evaluation (with per-case evidence) here")
    args = parser.parse_args()

    run = evaluation_engine.evaluate(args.version_id, args.datasets, args.repeats)
    s = run.summary
    print(f"\n{args.version_id}: {run.release_decision.upper()}  ({s['passed']}/{s['cases']} cases passed)")
    for gate in run.gates:
        value = gate["value"]
        shown = "n/a" if value is None else (f"{value:.4f}" if gate["metric"] not in METRICS and gate["metric"] != "reliability" else f"{value:.1%}")
        mark = "PASS" if gate["passed"] else ("FAIL" if gate["critical"] else "warn")
        print(f"  [{mark}] {gate['metric']:<24} {shown:>10}   ({gate['comparator']} {gate['threshold']})")
    failed = [c for c in run.cases if not c["passed"]]
    if failed:
        print(f"\n  {len(failed)} failing case(s), first 10:")
        for case in failed[:10]:
            print(f"   - {case['case_id']}: {'; '.join(case['failures'])}")
    if args.json:
        args.json.write_text(json.dumps({**run.brief(), "cases": run.cases}, indent=2, default=str))
    if run.release_decision != args.expect:
        print(f"\nExpected {args.expect}, got {run.release_decision}.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
