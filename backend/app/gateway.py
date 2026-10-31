import json
from dataclasses import dataclass

from app.audit import AuditLedger
from app.approvals import ApprovalStore
from app.config import settings
from app.data_inspector import inspect
from app.domain import ActionRequest, Decision, DecisionResponse
from app.identity import AgentRegistry, AgentStatus
from app.injection import scan
from app.policy import evaluate
from app.policy_engine import PolicyContext, PolicyEngine, PolicyOutcome, _PRECEDENCE, default_engine
from app.redaction import redact_text, redact_value
from app.risk import assess


@dataclass(frozen=True)
class GatewayResult:
    decision: DecisionResponse
    event_id: str


@dataclass(frozen=True)
class _Evaluation:
    response: DecisionResponse
    factors: list[str]
    findings: list[str]
    redaction_matched: bool


class ToolGateway:
    """Single enforcement point between agents and external tools.

    Order: identify -> least privilege -> scoped credential -> inspect content ->
    score risk -> baseline policy + declarative rules (strictest wins) ->
    approval binding -> audit -> approval request.
    """

    def __init__(
        self,
        registry: AgentRegistry,
        audit: AuditLedger,
        credentials=None,
        approvals: ApprovalStore | None = None,
        engine: PolicyEngine | None = None,
    ) -> None:
        self.registry = registry
        self.audit = audit
        self.credentials = credentials
        self.approvals = approvals
        self.engine = engine if engine is not None else default_engine()

    # ------------------------------------------------------------------ public
    def authorize(self, request: ActionRequest, consume_approval: bool = False) -> GatewayResult:
        evaluation = self._authorize_without_side_effects(request)
        response = evaluation.response

        if response.decision.needs_human and request.approval_id and self.approvals is not None:
            try:
                if consume_approval:
                    self.approvals.consume(request.approval_id, request)
                else:
                    self.approvals.validate_approved(request.approval_id, request)
                approved_decision = Decision.ALLOW_WITH_REDACTION if evaluation.redaction_matched else Decision.ALLOW
                response = response.model_copy(
                    update={
                        "decision": approved_decision,
                        "reason": "Human approval was granted for this exact request.",
                        "approver_role": None,
                    }
                )
                if approved_decision == Decision.ALLOW_WITH_REDACTION:
                    response = self._apply_redaction(request, response)
            except ValueError as exc:
                response = self._blocked(request, str(exc))

        response = response.model_copy(update={"risk_factors": evaluation.factors, "data_findings": evaluation.findings})
        event = self.audit.append(
            agent_id=response.agent_id,
            action=response.action,
            target=response.target,
            decision=response.decision.value,
            risk_score=response.risk_score,
            reason=response.reason,
            risk_factors=evaluation.factors,
            data_findings=evaluation.findings,
            tool=request.tool,
            credential_id=request.credential_id,
            correlation_id=request.correlation_id,
            policy_version=settings.policy_version,
            policy_id=response.policy_id,
            trace_id=request.correlation_id,
            tenant_id=request.tenant_id,
        )
        if response.decision.needs_human and self.approvals is not None:
            approval = self.approvals.create(
                requested_by=request.agent_id,
                event_id=event.event_id,
                request_fingerprint=self.approvals.fingerprint(request),
                approver_role=response.approver_role,
                context=self._approval_context(request, response, evaluation),
            )
            response = response.model_copy(update={"approval_id": approval.approval_id})
        return GatewayResult(decision=response, event_id=event.event_id)

    def dry_run(self, request: ActionRequest) -> DecisionResponse:
        """Evaluate a request without auditing, approvals or consuming rate-limit tokens."""
        evaluation = self._authorize_without_side_effects(request, dry_run=True)
        return evaluation.response.model_copy(
            update={"risk_factors": evaluation.factors, "data_findings": evaluation.findings}
        )

    # ---------------------------------------------------------------- internals
    def _authorize_without_side_effects(self, request: ActionRequest, dry_run: bool = False) -> _Evaluation:
        agent = self.registry.get(request.agent_id)
        if agent is None:
            return _Evaluation(self._blocked(request, "Unknown agent identity."), [], [], False)
        if agent.status != AgentStatus.ACTIVE:
            return _Evaluation(
                self._blocked(request, f"Agent identity is {agent.status.value} and cannot execute tools."), [], [], False
            )
        if request.action not in agent.permissions:
            return _Evaluation(self._blocked(request, "Agent does not have permission for this action."), [], [], False)
        if request.tool and self.credentials:
            if not request.credential_id or not request.credential_token:
                return _Evaluation(
                    self._blocked(request, "Tool execution requires a scoped credential and token."), [], [], False
                )
            if not self.credentials.validate(
                request.credential_id,
                request.agent_id,
                request.tool,
                request.action,
                request.credential_token,
            ):
                return _Evaluation(
                    self._blocked(request, "Scoped credential is invalid, expired, revoked, or insufficient."),
                    [],
                    [],
                    False,
                )
        # The agent's registered environment is authoritative; a caller cannot claim
        # "development" to dodge production-only rules.
        if agent.environment and request.environment != agent.environment:
            request = request.model_copy(update={"environment": agent.environment})
        return self._evaluate(request, dry_run=dry_run)

    def _evaluate(self, request: ActionRequest, dry_run: bool = False) -> _Evaluation:
        findings: set[str] = set()
        if request.content:
            findings.update(inspect(request.content)["findings"])
        if request.execution_payload:
            findings.update(inspect(json.dumps(request.execution_payload, default=str))["findings"])

        assessment = assess(request)
        factors = list(assessment.factors)
        score = assessment.score
        if findings:
            score = min(100, score + 20)
            factors.append("sensitive-content-detected")

        injection = scan(request.content, request.content_source)
        if injection.score:
            score = min(100, score + injection.score * 0.5)
            factors.extend(f"prompt-injection:{category}" for category in injection.categories)
        if request.content_source != "user" and request.content:
            factors.append(f"untrusted-source:{request.content_source}")

        effective = request.model_copy(update={"risk_score": score})
        baseline = evaluate(effective)
        ctx = PolicyContext(
            request=request,
            risk_score=score,
            findings=tuple(sorted(findings)),
            injection_score=injection.score,
            injection_detected=injection.detected,
        )
        outcome = self._engine_evaluate(ctx, dry_run)
        response = self._merge(baseline, outcome)
        redaction_matched = bool(outcome and any(self._is_redaction_rule(rid) for rid in outcome.matched))
        if response.decision == Decision.ALLOW_WITH_REDACTION:
            response = self._apply_redaction(request, response)
        return _Evaluation(response, factors, sorted(findings), redaction_matched)

    def _engine_evaluate(self, ctx: PolicyContext, dry_run: bool) -> PolicyOutcome | None:
        if not dry_run:
            return self.engine.evaluate(ctx)
        # Dry runs ignore rate-limit rules so that previewing never consumes tokens.
        static = PolicyEngine([r for r in self.engine.rules if r.decision != Decision.RATE_LIMIT], self.engine.version)
        return static.evaluate(ctx)

    def _is_redaction_rule(self, rule_id: str) -> bool:
        return any(rule.id == rule_id and rule.decision == Decision.ALLOW_WITH_REDACTION for rule in self.engine.rules)

    @staticmethod
    def _merge(baseline: DecisionResponse, outcome: PolicyOutcome | None) -> DecisionResponse:
        if outcome is None:
            return baseline.model_copy(update={"policy_id": "baseline"})
        matched = list(outcome.matched)
        if _PRECEDENCE[baseline.decision] > _PRECEDENCE[outcome.decision]:
            return baseline.model_copy(update={"policy_id": "baseline", "matched_policies": matched})
        return baseline.model_copy(
            update={
                "decision": outcome.decision,
                "reason": outcome.reason,
                "policy_id": outcome.policy_id,
                "matched_policies": matched,
                "approver_role": outcome.approver_role,
                "retry_after_seconds": outcome.retry_after_seconds,
            }
        )

    @staticmethod
    def _apply_redaction(request: ActionRequest, response: DecisionResponse) -> DecisionResponse:
        redacted_content = redact_text(request.content)[0] if request.content else None
        redacted_payload, _ = redact_value(request.execution_payload)
        return response.model_copy(update={"redacted_content": redacted_content, "redacted_payload": redacted_payload})

    @staticmethod
    def _approval_context(request: ActionRequest, response: DecisionResponse, evaluation: _Evaluation) -> dict:
        safe_payload, _ = redact_value(request.execution_payload)
        return {
            "action": request.action,
            "tool": request.tool,
            "target": request.target,
            "arguments": safe_payload,
            "tenant_id": request.tenant_id,
            "user_id": request.user_id,
            "resource_owner_id": request.resource_owner_id,
            "risk_score": response.risk_score,
            "reason": response.reason,
            "policy_id": response.policy_id,
            "matched_policies": response.matched_policies,
            "risk_factors": evaluation.factors,
            "data_findings": evaluation.findings,
            "decision": response.decision.value,
            "trace_id": request.correlation_id,
        }

    @staticmethod
    def _blocked(request: ActionRequest, reason: str) -> DecisionResponse:
        return DecisionResponse(
            decision=Decision.BLOCK,
            reason=reason,
            agent_id=request.agent_id,
            action=request.action,
            target=request.target,
            risk_score=request.risk_score,
            policy_id="identity" if "agent" in reason.lower() or "credential" in reason.lower() else None,
        )
