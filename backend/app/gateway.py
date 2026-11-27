from collections.abc import Callable
from dataclasses import dataclass

from app.audit import AuditLedger
from app.approvals import ApprovalStore
from app.config import settings
from app.data_inspector import inspect_outbound
from app.domain import ActionRequest, Decision, DecisionResponse
from app.flow.engine import FlowEngine
from app.flow.policy import SEVERITY, FlowVerdict
from app.flow.session import FlowStateUnavailable
from app.identity import AgentRegistry, AgentStatus
from app.opa_client import PolicyEngineUnavailable, decide as opa_decide
from app.policy import evaluate
from app.risk import assess
from app.vault import SecretVault, handles_in


SENSITIVE_OUTBOUND_REASON = "Sensitive data was found in the outbound request, so a human must approve it."
FLOW_STATE_UNAVAILABLE_REASON = "Session labels could not be read or written, so the request was blocked (fail closed)."

Inspector = Callable[[str | None, dict | None], dict]


@dataclass(frozen=True)
class GatewayResult:
    decision: DecisionResponse
    event_id: str


class ToolGateway:
    """Single enforcement point between agents and external tools.

    Order: identity -> permission -> session -> scoped credential -> content inspection and risk
    -> policy (Python or OPA) -> data-flow rules -> approval -> audit -> label update.
    The data-flow rules can only make a decision stricter, never looser.
    """

    def __init__(self, registry: AgentRegistry, audit: AuditLedger, credentials=None,
                 approvals: ApprovalStore | None = None, flow: FlowEngine | None = None,
                 inspector: Inspector = inspect_outbound, vault: SecretVault | None = None) -> None:
        self.registry = registry
        self.audit = audit
        self.credentials = credentials
        self.approvals = approvals
        self.flow = flow
        self.inspector = inspector
        self.vault = vault

    def authorize(self, request: ActionRequest, consume_approval: bool = False) -> GatewayResult:
        agent = self.registry.get(request.agent_id)
        factors: list[str] = []
        findings: list[str] = []
        lineage: list[dict] = []
        flow_rule: str | None = None

        if agent is None:
            response = self._blocked(request, "Unknown agent identity.")
        elif agent.status != AgentStatus.ACTIVE:
            response = self._blocked(request, f"Agent identity is {agent.status.value} and cannot execute tools.")
        elif request.action not in agent.permissions:
            response = self._blocked(request, "Agent does not have permission for this action.")
        elif self.flow is not None and (session_state := self._session_state(request)) != "valid":
            if session_state == "unavailable":
                response = self._blocked(request, FLOW_STATE_UNAVAILABLE_REASON)
                factors = ["flow-state-unavailable"]
            else:
                response = self._blocked(request, "Session does not exist, is closed, or belongs to another agent.")
            flow_rule = "F0"
        elif self.vault is not None and (secret_problem := self._secret_problem(request)) is not None:
            response = self._blocked(request, secret_problem)
            factors = ["secret-handle-misuse"]
            flow_rule = "S1"
        elif request.tool and self.credentials and (not request.credential_id or not request.credential_token):
            response = self._blocked(request, "Tool execution requires a scoped credential and token.")
        elif request.tool and self.credentials and not self.credentials.validate(
            request.credential_id,
            request.agent_id,
            request.tool,
            request.action,
            request.credential_token,
        ):
            response = self._blocked(request, "Scoped credential is invalid, expired, revoked, or insufficient.")
        else:
            response, factors, findings = self._evaluate(request, self.inspector)
            if self.flow is not None and response.decision != Decision.BLOCK:
                try:
                    verdict = self.flow.check(request)
                except FlowStateUnavailable:
                    verdict = FlowVerdict(decision=Decision.BLOCK, rule="F0", reason=FLOW_STATE_UNAVAILABLE_REASON,
                                          factors=["flow-state-unavailable"])
                factors = factors + verdict.factors
                lineage = verdict.lineage
                findings = findings + [f"lineage:{item['source_event_id']}" for item in lineage]
                if SEVERITY[verdict.decision] > SEVERITY[response.decision]:
                    flow_rule = verdict.rule
                    response = response.model_copy(update={"decision": verdict.decision, "reason": verdict.reason})

        if response.decision == Decision.REQUIRE_APPROVAL and request.approval_id and self.approvals is not None:
            try:
                if consume_approval:
                    self.approvals.consume(request.approval_id, request)
                else:
                    self.approvals.validate_approved(request.approval_id, request)
                response = response.model_copy(
                    update={
                        "decision": Decision.ALLOW,
                        "reason": "Human approval was granted for this exact request.",
                    }
                )
            except ValueError as exc:
                response = self._blocked(request, str(exc))

        response = response.model_copy(update={
            "risk_factors": factors,
            "data_findings": findings,
            "session_id": request.session_id,
            "flow_rule": flow_rule,
            "lineage": lineage,
        })
        event = self.audit.append(
            agent_id=response.agent_id,
            action=response.action,
            target=response.target,
            decision=response.decision.value,
            risk_score=response.risk_score,
            reason=response.reason,
            risk_factors=factors,
            data_findings=findings,
            tool=request.tool,
            credential_id=request.credential_id,
            correlation_id=request.correlation_id,
            policy_version=settings.policy_version,
        )
        if response.decision == Decision.REQUIRE_APPROVAL and self.approvals is not None:
            approval = self.approvals.create(
                requested_by=request.agent_id,
                event_id=event.event_id,
                request_fingerprint=self.approvals.fingerprint(request),
            )
            response = response.model_copy(update={"approval_id": approval.approval_id})
        if response.decision == Decision.ALLOW and self.flow is not None:
            try:
                self.flow.on_allowed(request, event.event_id)
            except FlowStateUnavailable:
                # The taint could not be recorded. Letting the call through would leave the label clean
                # while the agent receives the data, so the allow is withdrawn.
                response = self._blocked(request, FLOW_STATE_UNAVAILABLE_REASON).model_copy(
                    update={"risk_factors": [*factors, "flow-state-unavailable"], "flow_rule": "F0",
                            "session_id": request.session_id})
                event = self.audit.append(
                    agent_id=request.agent_id, action=request.action, target=request.target,
                    decision=Decision.BLOCK.value, risk_score=response.risk_score, reason=response.reason,
                    risk_factors=response.risk_factors, tool=request.tool, credential_id=request.credential_id,
                    correlation_id=request.correlation_id, policy_version=settings.policy_version,
                    event_type="flow.label.error",
                )
        return GatewayResult(decision=response, event_id=event.event_id)

    def _session_state(self, request: ActionRequest) -> str:
        try:
            return "valid" if self.flow.session_valid(request) else "invalid"
        except FlowStateUnavailable:
            return "unavailable"

    def _secret_problem(self, request: ActionRequest) -> str | None:
        extra = [request.content or "", request.target]
        if not (handles_in(request.execution_payload) or handles_in(extra)):
            return None
        destinations = self.flow.destination_list(request) if self.flow is not None else [request.target]
        return self.vault.check(request.agent_id, request.execution_payload, extra, destinations)

    def prepare_execution(self, request: ActionRequest) -> dict:
        """The payload the tool receives: secret handles replaced by real values (allowed requests only)."""
        return self.vault.inject(request.execution_payload) if self.vault is not None else request.execution_payload

    def finish_execution(self, request: ActionRequest, event_id: str, output) -> tuple[object, dict]:
        """What the agent receives: secrets scrubbed back to handles, private data labelled."""
        if self.vault is not None:
            output = self.vault.scrub(output)
        return output, self.record_output(request, event_id, output)

    def record_output(self, request: ActionRequest, event_id: str, output) -> dict:
        """Called after AgentGuard executed an allowed tool, with what the tool returned."""
        if self.flow is None:
            return {}
        return self.flow.record_output(request, event_id, output)

    @staticmethod
    def _blocked(request: ActionRequest, reason: str) -> DecisionResponse:
        return DecisionResponse(
            decision=Decision.BLOCK,
            reason=reason,
            agent_id=request.agent_id,
            action=request.action,
            target=request.target,
            risk_score=request.risk_score,
        )

    @staticmethod
    def _evaluate(request: ActionRequest, inspector: Inspector = inspect_outbound) -> tuple[DecisionResponse, list[str], list[str]]:
        # Inspect everything that leaves through the tool, not only the declared content.
        inspection = inspector(request.content, request.execution_payload)
        findings: list[str] = inspection["findings"]
        # Only high-severity findings drive the decision; low ones (an email address) are audit evidence.
        blocking: list[str] = inspection.get("blocking", findings)

        assessment = assess(request)
        factors = list(assessment.factors)
        score = assessment.score
        if blocking:
            score = min(100, score + 20)
            factors.append("sensitive-content-detected")

        effective = request.model_copy(update={"risk_score": score})

        if settings.opa_url:
            try:
                decision, reason = opa_decide(settings.opa_url, request, blocking)
            except PolicyEngineUnavailable:
                factors.append("policy-engine-unavailable")
                blocked = ToolGateway._blocked(effective, "Policy engine unavailable, so the request was blocked (fail closed).")
                return blocked, factors, findings
            response = DecisionResponse(decision=decision, reason=reason, agent_id=request.agent_id,
                                        action=request.action, target=request.target, risk_score=score)
            return response, factors, findings

        response = evaluate(effective)
        if blocking and response.decision == Decision.ALLOW:
            # Detected secrets or personal data must never leave without a human decision.
            response = response.model_copy(update={
                "decision": Decision.REQUIRE_APPROVAL,
                "reason": SENSITIVE_OUTBOUND_REASON,
            })
        return response, factors, findings
