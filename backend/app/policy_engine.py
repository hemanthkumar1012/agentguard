"""Declarative, deterministic policy engine for agent tool calls.

Rules are plain data (Python dicts, JSON or YAML) so they can be reviewed, versioned
and diffed. Conditions inside a rule's `when` block are ANDed. Unknown condition keys
are rejected when a rule pack loads: a typo must never silently weaken a policy.

Precedence when several rules match (most restrictive wins):

    DENY (block) > ESCALATE_TO_HUMAN > REQUIRE_APPROVAL > ALLOW_WITH_REDACTION
        > RATE_LIMIT (only when the limit is exceeded) > ALLOW
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.domain import ActionRequest, Decision
from app.rate_limit import RateLimiter

_PRECEDENCE: dict[Decision, int] = {
    Decision.BLOCK: 6,
    Decision.ESCALATE_TO_HUMAN: 5,
    Decision.REQUIRE_APPROVAL: 4,
    Decision.ALLOW_WITH_REDACTION: 3,
    Decision.RATE_LIMIT: 2,
    Decision.ALLOW: 1,
}

# Aliases make hand-written YAML friendlier: `deny` and `require_human_approval` are accepted.
_DECISION_ALIASES = {
    "deny": Decision.BLOCK,
    "block": Decision.BLOCK,
    "allow": Decision.ALLOW,
    "require_approval": Decision.REQUIRE_APPROVAL,
    "require_human_approval": Decision.REQUIRE_APPROVAL,
    "allow_with_redaction": Decision.ALLOW_WITH_REDACTION,
    "rate_limit": Decision.RATE_LIMIT,
    "escalate_to_human": Decision.ESCALATE_TO_HUMAN,
}

_LIST_KEYS = {"tool", "action", "environment", "user_role", "data_classification", "content_source", "tenant_id"}
_BOOL_KEYS = {"has_findings", "injection_detected", "target_external", "owner_mismatch", "tenant_mismatch"}
_NUMBER_KEYS = {"amount_greater_than", "amount_at_most", "risk_at_least", "risk_below", "session_risk_at_least"}
_ALLOWED_KEYS = _LIST_KEYS | {f"not_{key}" for key in _LIST_KEYS} | _BOOL_KEYS | _NUMBER_KEYS | {"arg_equals"}


class RateLimitSpec(BaseModel):
    limit: int = Field(ge=1)
    window_seconds: int = Field(default=60, ge=1)
    scope: str = Field(default="agent")  # agent | tenant | global

    @field_validator("scope")
    @classmethod
    def _scope(cls, value: str) -> str:
        if value not in {"agent", "tenant", "global"}:
            raise ValueError("rate limit scope must be agent, tenant or global")
        return value


class PolicyRule(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    description: str = ""
    when: dict[str, Any] = Field(default_factory=dict)
    decision: Decision
    reason: str | None = None
    approver_role: str | None = None
    rate_limit: RateLimitSpec | None = None

    @field_validator("decision", mode="before")
    @classmethod
    def _decision(cls, value: Any) -> Any:
        if isinstance(value, str) and value.lower() in _DECISION_ALIASES:
            return _DECISION_ALIASES[value.lower()]
        return value

    @field_validator("when")
    @classmethod
    def _when(cls, value: dict[str, Any]) -> dict[str, Any]:
        unknown = sorted(set(value) - _ALLOWED_KEYS)
        if unknown:
            raise ValueError(f"unknown policy condition(s): {', '.join(unknown)}")
        for key in _BOOL_KEYS:
            if key in value and not isinstance(value[key], bool):
                raise ValueError(f"condition '{key}' must be true or false")
        for key in _NUMBER_KEYS:
            if key in value and (isinstance(value[key], bool) or not isinstance(value[key], (int, float))):
                raise ValueError(f"condition '{key}' must be a number")
        if "arg_equals" in value and not isinstance(value["arg_equals"], dict):
            raise ValueError("condition 'arg_equals' must be a mapping")
        return value

    def model_post_init(self, __context: Any) -> None:
        if self.decision == Decision.RATE_LIMIT and self.rate_limit is None:
            raise ValueError(f"rule '{self.id}' uses RATE_LIMIT and needs a rate_limit block")


@dataclass(frozen=True)
class PolicyContext:
    request: ActionRequest
    risk_score: float
    findings: tuple[str, ...] = ()
    injection_score: int = 0
    injection_detected: bool = False
    session_risk: float = 0.0
    internal_domains: tuple[str, ...] = ("acmepay.example", "internal")

    @property
    def amount(self) -> float | None:
        raw = self.request.execution_payload.get("amount")
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            return None
        return float(raw)

    @property
    def target_external(self) -> bool:
        target = self.request.target.lower()
        if "external" in target or target.startswith(("http://", "https://")):
            return True
        if "@" in target:
            return not target.endswith(tuple(f"@{d}" for d in self.internal_domains)) and not any(
                target.endswith(f".{d}") for d in self.internal_domains
            )
        return False

    @property
    def tenant_mismatch(self) -> bool:
        req = self.request
        return bool(req.tenant_id and req.resource_tenant_id and req.tenant_id != req.resource_tenant_id)

    @property
    def owner_mismatch(self) -> bool:
        req = self.request
        return bool(req.user_id and req.resource_owner_id and req.user_id != req.resource_owner_id)


@dataclass(frozen=True)
class PolicyOutcome:
    decision: Decision
    reason: str
    policy_id: str | None
    matched: tuple[str, ...] = ()
    approver_role: str | None = None
    retry_after_seconds: int | None = None
    redact: bool = False


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def _matches(rule: PolicyRule, ctx: PolicyContext) -> bool:
    req = ctx.request
    values = {
        "tool": req.tool,
        "action": req.action,
        "environment": req.environment,
        "user_role": req.user_role,
        "data_classification": req.data_classification,
        "content_source": req.content_source,
        "tenant_id": req.tenant_id,
    }
    for key, expected in rule.when.items():
        if key in _LIST_KEYS:
            if values[key] not in _as_list(expected):
                return False
        elif key.startswith("not_") and key[4:] in _LIST_KEYS:
            # An absent value is not "in" the excluded set, so the negation holds.
            if values[key[4:]] in _as_list(expected):
                return False
        elif key == "amount_greater_than":
            if ctx.amount is None or not ctx.amount > expected:
                return False
        elif key == "amount_at_most":
            if ctx.amount is None or not ctx.amount <= expected:
                return False
        elif key == "risk_at_least":
            if not ctx.risk_score >= expected:
                return False
        elif key == "risk_below":
            if not ctx.risk_score < expected:
                return False
        elif key == "session_risk_at_least":
            if not ctx.session_risk >= expected:
                return False
        elif key == "has_findings":
            if bool(ctx.findings) != expected:
                return False
        elif key == "injection_detected":
            if ctx.injection_detected != expected:
                return False
        elif key == "target_external":
            if ctx.target_external != expected:
                return False
        elif key == "owner_mismatch":
            if ctx.owner_mismatch != expected:
                return False
        elif key == "tenant_mismatch":
            if ctx.tenant_mismatch != expected:
                return False
        elif key == "arg_equals":
            if any(req.execution_payload.get(k) != v for k, v in expected.items()):
                return False
    return True


class PolicyEngine:
    def __init__(self, rules: list[PolicyRule] | None = None, version: str = "unversioned") -> None:
        self.version = version
        self._rules: list[PolicyRule] = []
        self._limiters: dict[str, RateLimiter] = {}
        self.load(rules or [])

    # ------------------------------------------------------------------ loading
    def load(self, rules: list[PolicyRule]) -> None:
        ids = [rule.id for rule in rules]
        duplicates = sorted({rid for rid in ids if ids.count(rid) > 1})
        if duplicates:
            raise ValueError(f"duplicate policy ids: {', '.join(duplicates)}")
        self._rules = list(rules)
        self._limiters = {
            rule.id: RateLimiter(rule.rate_limit.limit, rule.rate_limit.window_seconds)
            for rule in rules
            if rule.rate_limit is not None
        }

    @classmethod
    def from_dicts(cls, items: list[dict], version: str = "unversioned") -> "PolicyEngine":
        return cls([PolicyRule(**item) for item in items], version=version)

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        path = Path(path)
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in {".yaml", ".yml"}:
            try:
                import yaml
            except ImportError as exc:  # pragma: no cover - exercised only without PyYAML
                raise RuntimeError("PyYAML is required to load YAML policy files") from exc
            document = yaml.safe_load(text)
        else:
            document = json.loads(text)
        if isinstance(document, list):
            document = {"policies": document}
        if not isinstance(document, dict) or not isinstance(document.get("policies"), list):
            raise ValueError("policy file must contain a 'policies' list")
        return cls.from_dicts(document["policies"], version=str(document.get("version", path.stem)))

    @property
    def rules(self) -> list[PolicyRule]:
        return list(self._rules)

    def describe(self) -> dict:
        return {"version": self.version, "policies": [rule.model_dump(mode="json") for rule in self._rules]}

    # --------------------------------------------------------------- evaluation
    def matching_rules(self, ctx: PolicyContext) -> list[PolicyRule]:
        return [rule for rule in self._rules if _matches(rule, ctx)]

    def evaluate(self, ctx: PolicyContext) -> PolicyOutcome | None:
        """Return the winning outcome, or None when no rule matches (caller falls back)."""
        matched = self.matching_rules(ctx)
        if not matched:
            return None
        ids = tuple(rule.id for rule in matched)
        static = [rule for rule in matched if rule.decision != Decision.RATE_LIMIT]
        winner = max(static, key=lambda r: _PRECEDENCE[r.decision], default=None)

        # Rate limits only matter when nothing stricter already stops the request, and a
        # token is only consumed by requests that would otherwise run.
        if winner is None or winner.decision in {Decision.ALLOW, Decision.ALLOW_WITH_REDACTION}:
            for rule in matched:
                if rule.decision != Decision.RATE_LIMIT:
                    continue
                allowed, retry_after = self._limiters[rule.id].allow(self._rate_key(rule, ctx))
                if not allowed:
                    return PolicyOutcome(
                        Decision.RATE_LIMIT,
                        rule.reason or f"Rate limit '{rule.id}' exceeded.",
                        rule.id,
                        ids,
                        retry_after_seconds=retry_after,
                    )
        if winner is None:
            return PolicyOutcome(Decision.ALLOW, "Within configured rate limits.", matched[0].id, ids)

        return PolicyOutcome(
            winner.decision,
            winner.reason or winner.description or f"Policy '{winner.id}' applied.",
            winner.id,
            ids,
            approver_role=winner.approver_role,
            redact=winner.decision == Decision.ALLOW_WITH_REDACTION,
        )

    @staticmethod
    def _rate_key(rule: PolicyRule, ctx: PolicyContext) -> str:
        scope = rule.rate_limit.scope if rule.rate_limit else "agent"
        if scope == "global":
            return "global"
        if scope == "tenant":
            return f"tenant:{ctx.request.tenant_id or 'default'}"
        return f"agent:{ctx.request.agent_id}"


# --------------------------------------------------------------------------- defaults
PRIVILEGED_ACTIONS = ["email.send", "customers.export", "refund.issue", "subscription.cancel", "db.write", "permissions.change"]


def default_rules() -> list[dict]:
    """Fintech support-operations rule pack (mirrored in policy/rules/fintech_support.yaml)."""
    return [
        {
            "id": "cross-tenant-access",
            "description": "Agents may never touch another tenant's resources.",
            "when": {"tenant_mismatch": True},
            "decision": "deny",
            "reason": "Cross-tenant access is never permitted.",
        },
        {
            "id": "cross-customer-data-access",
            "description": "A customer-facing session may only access the requesting customer's own records.",
            "when": {"owner_mismatch": True, "not_user_role": ["admin", "support_manager"]},
            "decision": "deny",
            "reason": "Resource belongs to a different customer than the authenticated user.",
        },
        {
            "id": "injected-instruction-privileged-action",
            "description": "Instructions found inside untrusted content must not trigger privileged tools.",
            "when": {"injection_detected": True, "action": PRIVILEGED_ACTIONS},
            "decision": "deny",
            "reason": "Prompt-injection indicators detected on a privileged action.",
        },
        {
            "id": "bulk-export-denied",
            "description": "Customer exports are restricted to admin and compliance roles.",
            "when": {"action": "customers.export", "not_user_role": ["admin", "compliance_officer"]},
            "decision": "deny",
            "reason": "Bulk customer export is not permitted for this role.",
        },
        {
            "id": "bulk-export-approval",
            "description": "Even permitted roles need a compliance officer's approval to export.",
            "when": {"action": "customers.export", "user_role": ["admin", "compliance_officer"]},
            "decision": "require_human_approval",
            "approver_role": "compliance_officer",
        },
        {
            "id": "refund-requires-order",
            "description": "Every refund must reference a specific order (found by the v2.0 evaluation run).",
            "when": {"action": ["refund.issue", "refund.request"], "arg_equals": {"order_id": None}},
            "decision": "deny",
            "reason": "Refunds must reference a verified order.",
        },
        {
            "id": "refund-hard-cap",
            "description": "No single refund above 1,00,000 can be issued by an agent.",
            "when": {"action": "refund.issue", "amount_greater_than": 100000},
            "decision": "deny",
            "reason": "Refund exceeds the absolute per-transaction cap.",
        },
        {
            "id": "refund-above-threshold",
            "description": "Refunds above 5,000 need finance manager approval.",
            "when": {"action": "refund.issue", "amount_greater_than": 5000},
            "decision": "require_human_approval",
            "approver_role": "finance_manager",
        },
        {
            "id": "subscription-cancel-approval",
            "description": "Cancelling a subscription is account-impacting and needs a human.",
            "when": {"action": "subscription.cancel"},
            "decision": "require_human_approval",
            "approver_role": "support_manager",
        },
        {
            "id": "external-email-approval",
            "description": "Email to an external recipient needs human approval.",
            "when": {"action": "email.send", "target_external": True},
            "decision": "require_human_approval",
            "approver_role": "support_manager",
        },
        {
            "id": "production-write-escalation",
            "description": "Production data writes and permission changes are escalated to a human operator.",
            "when": {"environment": "production", "action": ["db.write", "permissions.change"]},
            "decision": "escalate_to_human",
            "approver_role": "platform_admin",
        },
        {
            "id": "elevated-session-privileged-approval",
            "description": "Once a session's cumulative risk is elevated, privileged actions need a human.",
            "when": {"session_risk_at_least": 60, "action": PRIVILEGED_ACTIONS},
            "decision": "require_human_approval",
            "approver_role": "support_manager",
            "reason": "Session risk is elevated; privileged actions now require human approval.",
        },
        {
            "id": "outbound-pii-redaction",
            "description": "Sensitive findings in outbound content are redacted instead of sent.",
            "when": {"action": ["email.send", "ticket.create"], "has_findings": True},
            "decision": "allow_with_redaction",
        },
        {
            "id": "refund-request-rate-limit",
            "description": "At most 5 refund requests per agent per minute.",
            "when": {"action": "refund.request"},
            "decision": "rate_limit",
            "rate_limit": {"limit": 5, "window_seconds": 60, "scope": "agent"},
        },
        {
            "id": "ticket-rate-limit",
            "description": "At most 20 tickets per agent per minute.",
            "when": {"action": "ticket.create"},
            "decision": "rate_limit",
            "rate_limit": {"limit": 20, "window_seconds": 60, "scope": "agent"},
        },
        {
            "id": "order-read-rate-limit",
            "description": "At most 60 order reads per agent per minute.",
            "when": {"action": "order.read"},
            "decision": "rate_limit",
            "rate_limit": {"limit": 60, "window_seconds": 60, "scope": "agent"},
        },
    ]


def default_engine() -> PolicyEngine:
    return PolicyEngine.from_dicts(default_rules(), version="fintech-support-2026.10")
