from dataclasses import dataclass

from app.audit import AuditLedger
from app.approvals import ApprovalStore
from app.config import settings
from app.data_inspector import inspect
from app.domain import ActionRequest, Decision, DecisionResponse
from app.identity import AgentRegistry, AgentStatus
from app.policy import evaluate
from app.risk import assess


@dataclass(frozen=True)
class GatewayResult:
    decision: DecisionResponse
    event_id: str


class ToolGateway:
    """Single enforcement point between agents and external tools."""

    def __init__(self, registry: AgentRegistry, audit: AuditLedger, credentials=None, approvals: ApprovalStore | None = None) -> None:
        self.registry = registry
        self.audit = audit
        self.credentials = credentials
        self.approvals = approvals

    def authorize(self, request: ActionRequest, consume_approval: bool = False) -> GatewayResult:
        agent = self.registry.get(request.agent_id)
        factors: list[str] = []
        findings: list[str] = []

        if agent is None:
            response = self._blocked(request, "Unknown agent identity.")
        elif agent.status != AgentStatus.ACTIVE:
            response = self._blocked(request, f"Agent identity is {agent.status.value} and cannot execute tools.")
        elif request.action not in agent.permissions:
            response = self._blocked(request, "Agent does not have permission for this action.")
        elif request.tool and self.credentials:
            if not request.credential_id or not request.credential_token:
                response = self._blocked(request, "Tool execution requires a scoped credential and token.")
            elif not self.credentials.validate(
                request.credential_id,
                request.agent_id,
                request.tool,
                request.action,
                request.credential_token,
            ):
                response = self._blocked(request, "Scoped credential is invalid, expired, revoked, or insufficient.")
            else:
                response, factors, findings = self._evaluate(request)
        else:
            response, factors, findings = self._evaluate(request)

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

        response = response.model_copy(update={"risk_factors": factors, "data_findings": findings})
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
        return GatewayResult(decision=response, event_id=event.event_id)

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
    def _evaluate(request: ActionRequest) -> tuple[DecisionResponse, list[str], list[str]]:
        findings: list[str] = []
        if request.content:
            findings = inspect(request.content)["findings"]

        assessment = assess(request)
        factors = list(assessment.factors)
        score = assessment.score
        if findings:
            score = min(100, score + 20)
            factors.append("sensitive-content-detected")

        effective = request.model_copy(update={"risk_score": score})
        return evaluate(effective), factors, findings
