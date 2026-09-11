from dataclasses import dataclass

from app.audit import AuditLedger
from app.identity import AgentRegistry, AgentStatus
from app.policy import evaluate
from app.domain import ActionRequest, Decision, DecisionResponse


@dataclass(frozen=True)
class GatewayResult:
    decision: DecisionResponse
    event_id: str


class ToolGateway:
    """Single enforcement point between agents and external tools."""

    def __init__(self, registry: AgentRegistry, audit: AuditLedger) -> None:
        self.registry = registry
        self.audit = audit

    def authorize(self, request: ActionRequest) -> GatewayResult:
        agent = self.registry.get(request.agent_id)
        if agent is None:
            response = DecisionResponse(
                decision=Decision.BLOCK,
                reason="Unknown agent identity.",
                agent_id=request.agent_id,
                action=request.action,
                target=request.target,
                risk_score=request.risk_score,
            )
        elif agent.status != AgentStatus.ACTIVE:
            response = DecisionResponse(
                decision=Decision.BLOCK,
                reason=f"Agent identity is {agent.status.value} and cannot execute tools.",
                agent_id=request.agent_id,
                action=request.action,
                target=request.target,
                risk_score=request.risk_score,
            )
        elif request.action not in agent.permissions:
            response = DecisionResponse(
                decision=Decision.BLOCK,
                reason="Agent does not have permission for this action.",
                agent_id=request.agent_id,
                action=request.action,
                target=request.target,
                risk_score=request.risk_score,
            )
        else:
            response = evaluate(request)

        event = self.audit.append(
            agent_id=response.agent_id,
            action=response.action,
            target=response.target,
            decision=response.decision.value,
            risk_score=response.risk_score,
            reason=response.reason,
        )
        return GatewayResult(decision=response, event_id=event.event_id)
