"""The data-flow rules. Pure functions: label + manifest + destination + matches in, verdict out.

Rules, in the order they are checked:

F1  Lethal trifecta. The session read untrusted content AND private data, and this request sends
    data to a destination whose audience may not read that data  -> block.
    (Simon Willison's "lethal trifecta"; Meta's "Agents Rule of Two" says the same thing.)
F2  Private data, no untrusted content, destination outside the data's readers -> human approval.
    Nothing is steering the agent, but the flow still breaks the data's reader policy.
F3  Fingerprint evidence. Private data AgentGuard saw earlier (in any of this agent's sessions)
    is inside the request and the destination may not read it -> block if the session is
    untrusted, otherwise approval. This catches leaks across sessions that F1/F2 cannot see.
F4  Untrusted content steering a state change. The session read untrusted content and the
    request is a high-impact state change -> human approval. The Rule of Two treats
    "untrusted input + change state" as acceptable; F4 exists because it is not when the
    change is a deletion or a payment.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.domain import Decision
from app.flow.fingerprints import Match
from app.flow.labels import Capability, ToolManifest, covers, flows_to
from app.flow.session import SessionLabel

HIGH_IMPACT_ACTIONS = {"delete", "transfer_funds", "rotate_credentials", "export_data", "update_permissions"}
SEVERITY = {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 1, Decision.BLOCK: 2}


@dataclass(frozen=True)
class FlowVerdict:
    decision: Decision = Decision.ALLOW
    reason: str | None = None
    rule: str | None = None
    factors: list[str] = field(default_factory=list)
    lineage: list[dict] = field(default_factory=list)


def stricter(a: Decision, b: Decision) -> Decision:
    return a if SEVERITY[a] >= SEVERITY[b] else b


def _names(sources) -> str:
    seen: list[str] = []
    for source in sources:
        name = f"{source.tool}.{source.action}"
        if name not in seen:
            seen.append(name)
    return ", ".join(seen[:3]) + (" and others" if len(seen) > 3 else "")


def _principals(values) -> str:
    return ", ".join(sorted(values)) if values else "nobody"


def evaluate_flow(*, action: str, manifest: ToolManifest, label: SessionLabel, destination: str,
                  audience: frozenset[str], matches: list[Match]) -> FlowVerdict:
    factors: list[str] = []
    if label.untrusted:
        factors.append("session-ingested-untrusted-content")
    if label.holds_private:
        factors.append("session-holds-private-data")
    lineage = [m.as_dict() for m in matches]
    if matches:
        factors.append("private-data-fingerprint-match")

    egress = manifest.has(Capability.EGRESS)
    decision, reason, rule = Decision.ALLOW, None, None

    if egress and label.holds_private and not flows_to(label.readers, audience):
        factors.append("destination-outside-data-readers")
        where = f"{destination} (read by {_principals(audience)})"
        allowed = _principals(label.readers or frozenset())
        if label.untrusted:
            decision, rule = Decision.BLOCK, "F1"
            reason = (f"Lethal trifecta: this session read untrusted content ({_names(label.untrusted_sources)}) "
                      f"and private data ({_names(label.private_sources)}, readable by {allowed}). "
                      f"Sending to {where} could leak it, so the request was blocked.")
        else:
            decision, rule = Decision.REQUIRE_APPROVAL, "F2"
            reason = (f"This session read private data ({_names(label.private_sources)}, readable by {allowed}) "
                      f"and {where} is outside that audience, so a human must approve it.")

    leaking = [m for m in matches if egress and not all(covers(m.source.readers, p) for p in audience)]
    if leaking:
        first = leaking[0]
        evidence = (f"{first.shared} fingerprints of the output of {first.source.tool}.{first.source.action} "
                    f"(event {first.source.source_id}, session {first.source.session_id})"
                    + (f", {first.encoding}-encoded" if first.encoding != "plain" else ""))
        f3 = Decision.BLOCK if label.untrusted else Decision.REQUIRE_APPROVAL
        if SEVERITY[f3] > SEVERITY[decision]:
            decision, rule = f3, "F3"
            reason = (f"Private data is inside this request: {evidence}. Its readers "
                      f"({_principals(first.source.readers)}) do not include {destination}.")
        elif reason is not None:
            reason += f" Evidence: {evidence}."

    if (decision == Decision.ALLOW and label.untrusted and action in HIGH_IMPACT_ACTIONS
            and manifest.has(Capability.MUTATES)):
        decision, rule = Decision.REQUIRE_APPROVAL, "F4"
        reason = (f"This session read untrusted content ({_names(label.untrusted_sources)}) and "
                  f"'{action}' is a high-impact change, so a human must approve it.")

    if rule:
        factors.append(f"flow-rule-{rule}")
    return FlowVerdict(decision=decision, reason=reason, rule=rule, factors=factors, lineage=lineage)
