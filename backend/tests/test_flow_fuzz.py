"""Model-based fuzzing of the data-flow rules.

Thousands of random worlds (tools with random capabilities and readers, random destinations) and random
traces (reads, copies of earlier private output in various encodings, sends to random destinations,
switching sessions, lying about risk) are run through the real gateway. After every step an
independent oracle, written without using app.flow.labels, checks the security invariants:

  I1  no allowed send whose audience includes someone who may not read ALL private data the session read
  I2  if the session also read untrusted content, such a send is blocked, not just sent for approval
  I3  labels only grow: untrusted and holds_private never reset, readers never widen between steps
  I4  a refused step does not change the label
  I5  the flow verdict does not depend on the agent's declared risk_score or data_classification
  I6  an unknown session is always blocked

The oracle is deliberately naive: it checks each private source separately instead of using the
meet, so a bug in `meet` or `covers` shows up as a disagreement.
"""
from __future__ import annotations

import base64
from fnmatch import fnmatchcase
import os
import random

import pytest

from app.audit import AuditLedger
from app.domain import ActionRequest, Decision
from app.flow.engine import FlowEngine, default_manifests
from app.flow.labels import Capability as C, DestinationRegistry, ManifestRegistry, ToolManifest, meet, flows_to
from app.gateway import ToolGateway
from app.identity import AgentRegistry

SEED = 7_2026_11_27
WORLDS = int(os.getenv("AGENTGUARD_FUZZ_WORLDS", "400"))   # CI default; raise it locally for longer runs
STEPS = 14

PEOPLE = ["user:priya@gmail.com", "user:arjun@yahoo.com", "user:rahul@acme.com", "user:sana@acme.com"]
PRINCIPALS = ["internal", "domain:acme.com", "group:eng", *PEOPLE]
# look-alike domains catch a "contains the domain" bug in covers(); mutation testing found the fuzzer missed it
ADDRESSES = ["priya@gmail.com", "arjun@yahoo.com", "rahul@acme.com", "sana@acme.com", "drop@evil.io",
             "rahul@acme.com.evil.io", "ceo@notacme.com"]
OTHER_DESTINATIONS = ["slack:#eng", "slack:#public", "s3://acme-internal/x", "https://paste.evil.io/new", "github:acme/private-api"]


# --- oracle (independent of app.flow.labels) ------------------------------------------------------

def o_covers(readers: set[str], principal: str) -> bool:
    if "*" in readers or principal in readers:
        return True
    if principal.startswith("user:") and "@" in principal:
        return f"domain:{principal.split('@', 1)[1]}" in readers
    return False


def o_audience(destination: str, rules: list[tuple[str, frozenset[str]]]) -> set[str]:
    for pattern, audience in rules:
        if fnmatchcase(destination.lower(), pattern.lower()):
            return set(audience)
    if "@" in destination and "://" not in destination and " " not in destination:
        return {f"user:{destination.lower()}"}
    return {"*"}


def o_may_send(private_readers: list[set[str]], audience: set[str]) -> bool:
    for readers in private_readers:
        if "*" in readers:
            continue
        if "*" in audience:
            return False
        if not all(o_covers(readers, p) for p in audience):
            return False
    return True


def readers_at_least_as_strict(new, old) -> bool:
    """Every principal allowed by `new` was allowed by `old` (None = unconstrained)."""
    if old is None:
        return True
    if new is None:
        return False
    probe = set(PRINCIPALS) | {"*", "user:nobody@nowhere.example"}
    return all(not o_covers(set(new), p) or o_covers(set(old), p) for p in probe)


# --- random world ---------------------------------------------------------------------------------

def random_world(rng: random.Random):
    manifests, readers_of = [], {}
    for i in range(rng.randint(1, 3)):
        readers = frozenset(rng.sample(PRINCIPALS, rng.randint(1, 3)))
        owner_field = ("email",) if rng.random() < 0.5 else ()
        manifests.append(ToolManifest(f"src{i}", "read", frozenset({C.READS_PRIVATE}), readers=readers, readers_from=owner_field))
        readers_of[f"src{i}"] = (readers, owner_field)
    manifests.append(ToolManifest("web", "fetch_page", frozenset({C.INGESTS_UNTRUSTED})))
    manifests.append(ToolManifest("mail", "send", frozenset({C.EGRESS}), destination_field="to"))
    manifests.append(ToolManifest("chat", "post", frozenset({C.EGRESS}), destination_field="channel"))
    rules = []
    for pattern in rng.sample(["slack:#eng", "s3://acme-internal/*", "github:acme/private-*", "*@acme.com"], rng.randint(0, 3)):
        rules.append((pattern, frozenset(rng.sample(PRINCIPALS, rng.randint(1, 2)))))
    return manifests, readers_of, rules


def encode(rng: random.Random, text: str) -> str:
    choice = rng.random()
    if choice < 0.2:
        return base64.b64encode(text.encode()).decode()
    if choice < 0.3:
        return text.upper().replace(" ", "  ")
    return text


@pytest.mark.parametrize("world", range(WORLDS))
def test_random_traces_respect_the_flow_invariants(world, monkeypatch):
    # A tiny label size makes compaction happen inside short traces, so its bugs are reachable.
    monkeypatch.setattr("app.flow.session.MAX_SOURCES_PER_LABEL", 2 + world % 3)
    rng = random.Random(SEED + world)
    manifests, readers_of, rules = random_world(rng)
    destinations = DestinationRegistry()
    for pattern, audience in rules:
        destinations.register(pattern, audience)
    flow = FlowEngine(manifests=ManifestRegistry(default_manifests() + manifests), destinations=destinations)
    registry = AgentRegistry()
    agent = registry.register("fuzz", "fuzz", permissions={"read", "fetch_page", "send", "post"})
    gateway = ToolGateway(registry, AuditLedger(), flow=flow)

    sessions = {name: flow.sessions.create(agent.agent_id, name).session_id for name in ("a", "b")}
    sessions["default"] = None
    model = {name: {"untrusted": False, "private": []} for name in sessions}
    seen_private_texts: list[str] = []

    for step in range(STEPS):
        name = rng.choice(list(sessions))
        sid = sessions[name]
        label = flow.sessions.resolve(agent.agent_id, sid)
        before = (label.untrusted, label.holds_private, label.readers, len(label.private_sources), len(label.untrusted_sources))
        declared = dict(risk_score=rng.choice([0, 0, 40, 90]), data_classification=rng.choice(["public", "pii", "secret"]))
        kind = rng.random()

        if kind < 0.35 and readers_of:
            tool = rng.choice(list(readers_of))
            owners = rng.sample(ADDRESSES[:4], rng.choice([1, 1, 2]))
            rows = [{"email": o, "note": f"private-{world}-{step}-{o}-" + "".join(rng.choices("abcdefghij", k=24))} for o in owners]
            output = rows[0] if len(rows) == 1 else {"rows": rows}
            request = ActionRequest(agent_id=agent.agent_id, tool=tool, action="read", target=tool, session_id=sid, **declared)
            result = gateway.authorize(request)
            if result.decision.decision == Decision.ALLOW:
                gateway.record_output(request, result.event_id, output)
                static, owner_field = readers_of[tool]
                readers = set(static)
                if owner_field and len(owners) == 1:
                    readers.add(f"user:{owners[0]}")
                model[name]["private"].append(readers)
                seen_private_texts.extend(r["note"] for r in rows)
        elif kind < 0.5:
            request = ActionRequest(agent_id=agent.agent_id, tool="web", action="fetch_page", target="web", session_id=sid, **declared)
            result = gateway.authorize(request)
            if result.decision.decision == Decision.ALLOW:
                model[name]["untrusted"] = True
        else:
            tool, action, field, pool = (("mail", "send", "to", ADDRESSES) if rng.random() < 0.6
                                         else ("chat", "post", "channel", OTHER_DESTINATIONS))
            destination = rng.choice(pool)
            body = encode(rng, rng.choice(seen_private_texts)) if seen_private_texts and rng.random() < 0.6 else "hello there"
            request = ActionRequest(agent_id=agent.agent_id, tool=tool, action=action, target=tool, session_id=sid,
                                    execution_payload={field: destination, "body": body}, **declared)

            # I5: the flow verdict ignores what the agent says about itself
            liar = request.model_copy(update={"risk_score": 0, "data_classification": "public"})
            honest = request.model_copy(update={"risk_score": 100, "data_classification": "secret"})
            assert flow.check(liar).decision == flow.check(honest).decision, (world, step)

            result = gateway.authorize(request)
            decision = result.decision.decision
            audience = o_audience(destination, rules)
            allowed_by_oracle = o_may_send(model[name]["private"], audience)
            if not allowed_by_oracle:
                assert decision != Decision.ALLOW, (world, step, name, destination, model[name], result.decision.reason)  # I1
                if model[name]["untrusted"]:
                    assert decision == Decision.BLOCK, (world, step, name, destination, result.decision.reason)  # I2
            if decision != Decision.ALLOW:
                after = flow.sessions.resolve(agent.agent_id, sid)
                assert (after.untrusted, after.holds_private, len(after.private_sources)) == before[:2] + (before[3],)  # I4

        after = flow.sessions.resolve(agent.agent_id, sid)
        assert after.untrusted >= before[0] and after.holds_private >= before[1]          # I3
        assert readers_at_least_as_strict(after.readers, before[2]), (world, step, after.readers, before[2])
        assert after.untrusted == model[name]["untrusted"]

    # I6
    ghost = ActionRequest(agent_id=agent.agent_id, tool="mail", action="send", target="mail",
                          session_id="ses_never_issued", execution_payload={"to": "priya@gmail.com"})
    assert gateway.authorize(ghost).decision.decision == Decision.BLOCK


def test_meet_is_never_more_permissive_than_either_side_and_never_stricter_than_needed():
    rng = random.Random(SEED)
    pool = PRINCIPALS + ["*"]
    audiences = [frozenset({p}) for p in pool] + [frozenset(rng.sample(PEOPLE, 2)) for _ in range(20)]
    for _ in range(5000):
        a = frozenset(rng.sample(pool, rng.randint(1, 3)))
        b = frozenset(rng.sample(pool, rng.randint(1, 3)))
        m = meet(a, b)
        assert m == meet(b, a) or all(flows_to(m, aud) == flows_to(meet(b, a), aud) for aud in audiences)
        for audience in audiences:
            both = flows_to(a, audience) and flows_to(b, audience)
            assert flows_to(m, audience) == both, (a, b, m, audience)
