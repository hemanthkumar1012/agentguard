"""Least-privilege multi-agent orchestration.

    Customer request -> Triage -> {Policy, Order, Billing, Escalation} -> Final response

Each sub-agent has its own identity and a deliberately narrow permission set. The
supervisor may only hand work to a sub-agent through an explicit delegation scope
(``AgentAuthorization``). Every sub-agent tool call still goes through the same gateway,
so a sub-agent that overreaches (e.g. Billing trying to *issue* a refund) is blocked by
least privilege, not by trusting the agent to behave. The final responder has no tools
and may only use outputs that were actually executed.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from app.agent_auth import AgentAuthorization
from app.agent_runtime import GuardedToolClient, Observation, RunState, _amount, _ORDER_RE, classify_intents
from app.identity import AgentRegistry
from app.tracing import TraceStore

SUB_AGENTS: dict[str, dict] = {
    "supervisor": {"permissions": set(), "role": "Routes work; holds delegation scopes only."},
    "triage": {"permissions": set(), "role": "Classifies the request and picks specialists."},
    "policy": {"permissions": {"policy.search"}, "role": "Searches approved policy documents only."},
    "order": {"permissions": {"order.read", "account.read"}, "role": "Reads orders for the verified customer."},
    "billing": {"permissions": {"refund.request"}, "role": "Drafts refund requests; can never issue refunds."},
    "escalation": {"permissions": {"ticket.create"}, "role": "Opens tickets and hands off to humans."},
    "responder": {"permissions": set(), "role": "Writes the answer from verified outputs only."},
}

# Which specialist a supervisor may delegate each action to.
DELEGATION_SCOPES: dict[str, set[str]] = {
    "policy": {"policy.search"},
    "order": {"order.read", "account.read"},
    "billing": {"refund.request"},
    "escalation": {"ticket.create"},
}


@dataclass
class OrchestrationResult:
    trace_id: str
    status: str
    output: str
    route: list[str]
    steps: list[dict]
    agents: dict[str, str]

    def to_dict(self) -> dict:
        return asdict(self)


class Orchestrator:
    def __init__(self, registry: AgentRegistry, authorizer: AgentAuthorization, tools: GuardedToolClient,
                 traces: TraceStore) -> None:
        self.registry = registry
        self.authorizer = authorizer
        self.tools = tools
        self.traces = traces
        self.identities: dict[str, str] = {}
        for name, spec in SUB_AGENTS.items():
            # The supervisor must itself hold any scope it delegates (grant() enforces this).
            permissions = set().union(*DELEGATION_SCOPES.values()) if name == "supervisor" else spec["permissions"]
            identity = registry.register(name=f"orchestrator-{name}", owner="sentinelforge",
                                         environment="production", permissions=permissions)
            self.identities[name] = identity.agent_id
        for name, scopes in DELEGATION_SCOPES.items():
            authorizer.grant(self.identities["supervisor"], self.identities[name], scopes)

    def describe(self) -> dict:
        return {
            name: {"agent_id": self.identities[name], "permissions": sorted(spec["permissions"]), "role": spec["role"],
                   "delegated_scopes": sorted(DELEGATION_SCOPES.get(name, set()))}
            for name, spec in SUB_AGENTS.items()
        }

    def run(self, message: str, tenant_id: str = "acmepay", user_id: str | None = None, user_role: str = "customer",
            simulate_overreach: bool = False) -> OrchestrationResult:
        trace = self.traces.start(input=message, tenant_id=tenant_id, user_id=user_id,
                                  agent_id=self.identities["supervisor"], agent_version="orchestrator-v1",
                                  model="scripted", prompt_version="orchestrator-v1", tags={"mode": "multi-agent"})
        state = RunState(trace.trace_id, "orchestrator-v1", message, tenant_id, user_id, user_role)
        observations: list[tuple[str, Observation]] = []

        with self.traces.span(trace, "agent", "triage", agent_id=self.identities["triage"]) as triage_span:
            intents = classify_intents(message)
            route = self._route(intents)
            triage_span.attributes.update({"intents": intents, "route": route})

        orders = [o.upper() for o in _ORDER_RE.findall(message)]
        amount = _amount(message)
        for specialist in route:
            with self.traces.span(trace, "handoff", f"supervisor->{specialist}") as handoff:
                handoff.attributes["to"] = specialist
            with self.traces.span(trace, "agent", specialist, agent_id=self.identities[specialist]) as agent_span:
                for action, args in self._tasks(specialist, message, orders, amount, user_id, observations,
                                                simulate_overreach):
                    delegation = self.authorizer.check(self.identities["supervisor"], self.identities[specialist], action)
                    if not delegation.allowed and action in DELEGATION_SCOPES.get(specialist, set()):
                        obs = Observation(action, args, "block", False, delegation.reason)
                    else:
                        obs = self.tools.call(trace, state, self.identities[specialist], SUB_AGENTS[specialist]["permissions"],
                                              action, args, parent_id=agent_span.span_id)
                    observations.append((specialist, obs))
                    if obs.decision in {"require_approval", "escalate_to_human"}:
                        state.pending_request = None  # orchestrator hands approvals to the escalation path
                    guard = self.tools.gateway.session_guard
                    if guard is not None and guard.is_tripped(state.run_id):
                        break
                agent_span.attributes["actions"] = [o.action for s, o in observations if s == specialist]

        with self.traces.span(trace, "agent", "responder", agent_id=self.identities["responder"]) as responder:
            verified = [(s, o) for s, o in observations if o.executed]
            output = self._respond(verified, observations)
            responder.attributes["verified_inputs"] = len(verified)

        blocked = any(o.decision in {"block", "rate_limit"} for _, o in observations)
        guard = self.tools.gateway.session_guard
        status = "completed_with_blocks" if blocked else "completed"
        if guard is not None and guard.is_tripped(state.run_id):
            status = "quarantined"
        self.traces.finish(trace, status, output)
        return OrchestrationResult(trace.trace_id, status, output, route,
                                   [{"agent": s, **asdict(o)} for s, o in observations],
                                   {name: self.identities[name] for name in ["triage", *route, "responder"]})

    @staticmethod
    def _route(intents: list[str]) -> list[str]:
        route: list[str] = []
        mapping = {"policy": ["policy"], "order_status": ["order"], "account": ["order"],
                   "refund": ["policy", "order", "billing"], "cancel": ["policy", "escalation"],
                   "ticket": ["escalation"], "export": ["escalation"], "email": ["escalation"],
                   "reveal_prompt": []}
        for intent in intents:
            for specialist in mapping.get(intent, ["policy"]):
                if specialist not in route:
                    route.append(specialist)
        return route or ["policy"]

    @staticmethod
    def _tasks(specialist: str, message: str, orders: list[str], amount: float | None, user_id: str | None,
               done: list[tuple[str, Observation]], simulate_overreach: bool) -> list[tuple[str, dict]]:
        if specialist == "policy":
            return [("policy.search", {"query": message[:200]})]
        if specialist == "order":
            return [("order.read", {"order_id": o}) for o in orders[:2]] or [("account.read", {"customer_id": user_id})]
        if specialist == "billing":
            verified = [o for s, o in done if o.action == "order.read" and o.executed]
            if not verified:
                return []  # never draft a refund for an order nobody could verify
            order = verified[0].output
            refund_amount = amount or float(order.get("amount", 0))
            args = {"customer_id": user_id, "order_id": order["order_id"], "amount": refund_amount,
                    "reason": "customer reported issue"}
            tasks = [("refund.issue", args)] if simulate_overreach else []
            return tasks + [("refund.request", args)]
        if specialist == "escalation":
            return [("ticket.create", {"customer_id": user_id, "subject": "Escalated by orchestrator",
                                       "body": message[:500]})]
        return []

    @staticmethod
    def _respond(verified: list[tuple[str, Observation]], all_obs: list[tuple[str, Observation]]) -> str:
        parts: list[str] = []
        for _, obs in verified:
            out = obs.output or {}
            if obs.action == "policy.search" and out.get("documents"):
                doc = out["documents"][0]
                parts.append(f"{doc['text'].split('. ')[0].rstrip('.')}. [{doc['doc_id']}]")
            elif obs.action == "order.read":
                parts.append(f"Order {out.get('order_id')} is {str(out.get('status')).replace('_', ' ')}.")
            elif obs.action == "account.read":
                parts.append(f"Your account tier is {out.get('tier')}.")
            elif obs.action == "refund.request":
                parts.append(f"Billing drafted refund request {out.get('refund_request_id')} for finance review.")
            elif obs.action == "ticket.create":
                parts.append(f"Escalation opened ticket {out.get('ticket_id')}.")
        blocked = [o for _, o in all_obs if not o.executed and o.decision in {"block", "rate_limit"}]
        if blocked:
            parts.append(f"{len(blocked)} action(s) were blocked by policy and not performed.")
        return " ".join(parts) or "I've routed your request to the right team."
