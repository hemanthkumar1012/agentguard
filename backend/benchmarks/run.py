"""Builds the benchmark report. From backend/:

    python -m benchmarks.run            print the report
    python -m benchmarks.run --write    also write ../docs/benchmarks.md
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import platform
import random
import statistics
import string
import time
from pathlib import Path

from app.audit import AuditLedger
from app.data_inspector import inspect, inspect_outbound
from app.domain import ActionRequest
from app.flow.engine import FlowEngine
from app.flow.labels import Capability as C, ToolManifest
from app.flow import winnow
from app.gateway import ToolGateway
from app.identity import AgentRegistry
from benchmarks import legacy_inspector
from benchmarks.corpus import SEED, build
from benchmarks.replay import CONFIGS, outcome, replay, stopping_step
from benchmarks.traces import TRACES

REPORT = Path(__file__).resolve().parents[2] / "docs" / "benchmarks.md"


def detector_metrics(seed: int = SEED) -> dict:
    samples = build(seed)
    scored = [s for s in samples if not s.hard]
    out = {}
    for name, flag in {
        "legacy": lambda t: bool(legacy_inspector.inspect(t)["findings"]),
        "new": lambda t: bool(inspect(t)["blocking"]),
    }.items():
        tp = fp = fn = tn = 0
        by_category: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for s in scored:
            hit = flag(s.text)
            key = f"{s.category} ({s.encoding})" if s.positive else s.category
            by_category[key][0] += hit
            by_category[key][1] += 1
            tp += s.positive and hit
            fn += s.positive and not hit
            fp += (not s.positive) and hit
            tn += (not s.positive) and not hit
        hard = defaultdict(lambda: [0, 0])
        for s in samples:
            if s.hard:
                hard[s.category][0] += flag(s.text)
                hard[s.category][1] += 1
        out[name] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else 0.0,
            "recall": tp / (tp + fn) if tp + fn else 0.0,
            "fpr": fp / (fp + tn) if fp + tn else 0.0,
            "by_category": dict(by_category), "hard": dict(hard),
        }
    out["sizes"] = {"positives": sum(s.positive for s in scored), "negatives": sum(not s.positive for s in scored),
                    "hard": sum(s.hard for s in samples)}
    return out


def _percentiles(samples_ns: list[int]) -> tuple[float, float, float]:
    q = statistics.quantiles(samples_ns, n=100, method="inclusive")
    return q[49] / 1000, q[94] / 1000, q[98] / 1000


def latency(iterations: int = 2000) -> list[dict]:
    rng = random.Random(1)
    words = ["order", "parcel", "Tirupati", "invoice", "delivery", "customer", "refund", "Friday", "address", "team"]

    def text(n: int) -> str:
        out: list[str] = []
        while sum(len(w) + 1 for w in out) < n:
            out.append(rng.choice(words) + (str(rng.randint(10, 999)) if rng.random() < 0.2 else ""))
        return " ".join(out)

    def setup(with_flow: bool, sources: int):
        registry = AgentRegistry()
        agent = registry.register("bench", "bench", permissions={"read_record", "send_email", "read_secret"})
        flow = None
        if with_flow:
            flow = FlowEngine()
            flow.manifests.register(ToolManifest("crm", "read_record", frozenset({C.READS_PRIVATE}),
                                                 readers=frozenset({"domain:acme.com"})))
            flow.manifests.register(ToolManifest("vault", "read_secret", frozenset({C.READS_PRIVATE}),
                                                 readers=frozenset({"internal"})))
        inspector = inspect_outbound if with_flow else (lambda c, p: legacy_inspector.inspect_outbound(c, p))
        gateway = ToolGateway(registry, AuditLedger(), flow=flow, inspector=inspector)
        for i in range(sources if with_flow else 0):
            read = ActionRequest(agent_id=agent.agent_id, tool="crm", action="read_record", target="crm")
            result = gateway.authorize(read)
            gateway.record_output(read, result.event_id, {
                "name": rng.choice(["Priya", "Arjun", "Lakshmi", "Ravi", "Sana", "Kiran"]) + " " + "".join(rng.choices(string.ascii_lowercase, k=7)),
                "address": f"Door {rng.randint(1, 99)}-{rng.randint(1, 999)}, " + "".join(rng.choices(string.ascii_lowercase, k=10)) + " Road, Tirupati",
                "notes": text(400),
                "id": "".join(rng.choices(string.digits, k=8)),
            })
        for i in range(20 if with_flow else 0):
            # tracked secrets make the piece tracker (F5) do its full work on every request
            read = ActionRequest(agent_id=agent.agent_id, tool="vault", action="read_secret", target="vault")
            result = gateway.authorize(read)
            gateway.record_output(read, result.event_id, {"value": "sk" + "_live_" + "".join(rng.choices(string.ascii_letters + string.digits, k=24))})
        return gateway, agent.agent_id

    rows = []
    for label, payload_chars, with_flow in [
        ("send_email, 1 KB body: before (legacy inspector, no flow)", 1000, False),
        ("send_email, 1 KB body: after (all rules; 50 outputs fingerprinted, 20 secrets tracked in pieces)", 1000, True),
        ("send_email, 10 KB body: before", 10_000, False),
        ("send_email, 10 KB body: after (same state)", 10_000, True),
    ]:
        gateway, agent_id = setup(with_flow, 50)
        body = text(payload_chars)
        request = ActionRequest(agent_id=agent_id, tool="gmail", action="send_email", target="gmail",
                                execution_payload={"to": "rahul@acme.com", "body": body})
        for _ in range(50):
            gateway.authorize(request)  # warm-up
        timings = []
        for _ in range(iterations):
            # Same body every run: clear the decode cache so only reuse *within* one request is counted.
            winnow._decoded_variants.cache_clear()
            start = time.perf_counter_ns()
            gateway.authorize(request)
            timings.append(time.perf_counter_ns() - start)
        p50, p95, p99 = _percentiles(timings)
        rows.append({"case": label, "p50_us": p50, "p95_us": p95, "p99_us": p99})
    return rows


def render(metrics: dict, replays: list[dict], timings: list[dict]) -> str:
    L: list[str] = []
    add = L.append
    add("# AgentGuard benchmarks")
    add("")
    add("Generated by `python -m benchmarks.run --write` (from `backend/`). Every number below comes from code in")
    add("`backend/benchmarks/` and can be regenerated. CI runs the same traces as tests (`tests/test_attack_replays.py`).")
    add("")
    add("## 1. Attack and benign trace replays")
    add("")
    add("Each trace is a sequence of tool calls replayed through a fresh gateway. In every trace the agent declares")
    add("`risk_score: 0` and `data_classification: \"public\"`, because a compromised agent would.")
    add("")
    add("Configurations:")
    add("")
    for key, text in CONFIGS.items():
        add(f"- **{key}**: {text}")
    add("")
    add("| Trace | Kind | " + " | ".join(CONFIGS) + " | Stopped by (full) |")
    add("|---|---|" + "---|" * len(CONFIGS) + "---|")
    for row in replays:
        add(f"| {row['name']} | {row['kind']} | " + " | ".join(row["outcomes"][c] for c in CONFIGS) + f" | {row['stopped_by']} |")
    add("")
    attacks = [r for r in replays if r["kind"] == "attack"]
    benign = [r for r in replays if r["kind"] == "benign"]
    for config in CONFIGS:
        stopped = sum(r["outcomes"][config] == "stopped" for r in attacks)
        friction = sum(r["outcomes"][config] != "allow" for r in benign)
        add(f"- **{config}**: stopped {stopped}/{len(attacks)} attacks; {friction}/{len(benign)} benign flows needed approval or were blocked.")
    add("")
    add("How to read this:")
    add("")
    add("- *legacy* stops some attacks only because it asked for approval on **any** request containing an email")
    add("  address, which also stopped most benign work. It missed all four reconstructions of published attacks")
    add("  (GitHub MCP, Supabase MCP and two EchoLeak paths), none of which needs an email address.")
    add("- *labels* vs *full* isolates the evidence layers: only fingerprints catch data recalled into a fresh")
    add("  session, and only piece tracking (F5) catches a secret sent in 8-character pieces.")
    add("- `render_output` steps go through `POST /flow/check-output` (rule O1); configurations without data-flow")
    add("  control have no output check, so EchoLeak's own markdown-image path is missed there.")
    add("- Known gap: `split-into-3-character-pieces`. Pieces shorter than the 4-character q-grams, sent from a")
    add("  clean session, pass every layer.")
    add("- Intended friction: the external accountant email and a raw API key leaving need a human. The better fix")
    add("  for the second is for the gateway to inject the credential so the agent never holds it.")
    add("- Known false block: `merge-duplicate-customer-accounts`. After reading two customers' records the session")
    add("  may only talk to people allowed to read both (label creep). The fix is to split the work into sessions.")
    add("")
    add("Sources for the reconstructed attacks:")
    add("")
    for trace in TRACES:
        if trace.source:
            add(f"- {trace.name}: {trace.source}")
    add("")
    add("## 2. Outbound data inspector on a labelled corpus")
    add("")
    sizes = metrics["sizes"]
    add(f"Corpus: {sizes['positives']} positives, {sizes['negatives']} negatives (seed {SEED}), plus {sizes['hard']} known-gap")
    add("cases reported separately. Question per sample: *would this text force a human approval?* The corpus is")
    add("synthetic and was written by the same person as the detectors, so it is easier than real traffic: use it to")
    add("compare versions and catch regressions, not as a real-world accuracy claim.")
    add("")
    add("| Detector | Precision | Recall | False-positive rate | TP | FP | FN | TN |")
    add("|---|---|---|---|---|---|---|---|")
    for name in ("legacy", "new"):
        m = metrics[name]
        add(f"| {name} | {m['precision']:.3f} | {m['recall']:.3f} | {m['fpr']:.3f} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} |")
    add("")
    add("Per category (flagged / total):")
    add("")
    add("| Category | legacy | new |")
    add("|---|---|---|")
    for key in metrics["legacy"]["by_category"]:
        a = metrics["legacy"]["by_category"][key]
        b = metrics["new"]["by_category"][key]
        add(f"| {key} | {a[0]}/{a[1]} | {b[0]}/{b[1]} |")
    add("")
    add("Known gaps (should be flagged; neither version catches them):")
    add("")
    add("| Case | legacy | new |")
    add("|---|---|---|")
    for key in metrics["new"]["hard"]:
        a = metrics["legacy"]["hard"][key]
        b = metrics["new"]["hard"][key]
        add(f"| {key} | {a[0]}/{a[1]} | {b[0]}/{b[1]} |")
    add("")
    add("## 3. Decision latency")
    add("")
    add(f"`ToolGateway.authorize` in-process, single thread, {platform.python_implementation()} {platform.python_version()},")
    add("2,000 runs after 50 warm-up runs. Audit append included; network and persistence excluded.")
    add("Machine-dependent: compare rows with each other, not with other machines.")
    add("")
    add("| Case | p50 (µs) | p95 (µs) | p99 (µs) |")
    add("|---|---|---|---|")
    for row in timings:
        add(f"| {row['case']} | {row['p50_us']:.0f} | {row['p95_us']:.0f} | {row['p99_us']:.0f} |")
    add("")
    return "\n".join(L)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="write docs/benchmarks.md")
    parser.add_argument("--iterations", type=int, default=2000)
    args = parser.parse_args()

    replays = []
    for trace in TRACES:
        outcomes = {config: outcome(trace, replay(trace, config)) for config in CONFIGS}
        stop = stopping_step(replay(trace, "full"))
        stopped_by = f"{stop.rule or 'policy'} at {stop.tool}.{stop.action}" if stop else "-"
        replays.append({"name": trace.name, "kind": trace.kind, "outcomes": outcomes, "stopped_by": stopped_by})
    report = render(detector_metrics(), replays, latency(args.iterations))
    print(report)
    if args.write:
        REPORT.write_text(report + "\n", encoding="utf-8")
        print(f"\nwrote {REPORT}")


if __name__ == "__main__":
    main()
