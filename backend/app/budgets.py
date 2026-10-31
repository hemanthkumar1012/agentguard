"""Token and cost budgets ("unbounded consumption" control, OWASP LLM10).

Budgets are enforced *before* every model call. Spend is tracked per tenant for the
current UTC day and per agent run, so one runaway loop cannot drain a tenant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock

# INR per 1K tokens (input, output). Illustrative list prices for cost estimates.
MODEL_PRICES_INR_PER_1K: dict[str, tuple[float, float]] = {
    "scripted-planner": (0.0, 0.0),
    "gpt-4o-mini": (0.0126, 0.0504),
    "gpt-4.1-mini": (0.0336, 0.1344),
    "gpt-4o": (0.21, 0.84),
    "gemini-2.0-flash": (0.0084, 0.0336),
}
_DEFAULT_PRICE = (0.05, 0.15)


def estimate_cost_inr(model: str, input_tokens: int, output_tokens: int) -> float:
    price_in, price_out = MODEL_PRICES_INR_PER_1K.get(model, _DEFAULT_PRICE)
    return round(input_tokens / 1000 * price_in + output_tokens / 1000 * price_out, 6)


def estimate_tokens(text: str) -> int:
    """Cheap, deterministic token estimate (~4 chars per token) for providers without usage data."""
    return max(1, (len(text) + 3) // 4)


@dataclass
class BudgetPolicy:
    daily_tokens: int = 2_000_000
    daily_cost_inr: float = 500.0
    run_tokens: int = 40_000
    run_cost_inr: float = 10.0
    max_steps: int = 12


@dataclass
class _Usage:
    tokens: int = 0
    cost_inr: float = 0.0


@dataclass(frozen=True)
class BudgetCheck:
    allowed: bool
    reason: str | None = None


@dataclass
class BudgetManager:
    default: BudgetPolicy = field(default_factory=BudgetPolicy)
    per_tenant: dict[str, BudgetPolicy] = field(default_factory=dict)
    _daily: dict[tuple[str, str], _Usage] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def policy_for(self, tenant_id: str | None) -> BudgetPolicy:
        return self.per_tenant.get(tenant_id or "default", self.default)

    def set_policy(self, tenant_id: str, policy: BudgetPolicy) -> None:
        self.per_tenant[tenant_id] = policy

    @staticmethod
    def _day() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def check(self, tenant_id: str | None, run_tokens: int, run_cost: float, steps: int) -> BudgetCheck:
        policy = self.policy_for(tenant_id)
        with self._lock:
            usage = self._daily.get((tenant_id or "default", self._day()), _Usage())
        if steps >= policy.max_steps:
            return BudgetCheck(False, f"Run exceeded the {policy.max_steps}-step limit.")
        if run_tokens >= policy.run_tokens:
            return BudgetCheck(False, f"Run exceeded its {policy.run_tokens}-token budget.")
        if run_cost >= policy.run_cost_inr:
            return BudgetCheck(False, f"Run exceeded its ₹{policy.run_cost_inr:.2f} cost budget.")
        if usage.tokens >= policy.daily_tokens:
            return BudgetCheck(False, "Tenant exhausted its daily token budget.")
        if usage.cost_inr >= policy.daily_cost_inr:
            return BudgetCheck(False, "Tenant exhausted its daily cost budget.")
        return BudgetCheck(True)

    def record(self, tenant_id: str | None, tokens: int, cost_inr: float) -> None:
        key = (tenant_id or "default", self._day())
        with self._lock:
            usage = self._daily.setdefault(key, _Usage())
            usage.tokens += tokens
            usage.cost_inr = round(usage.cost_inr + cost_inr, 6)

    def usage(self, tenant_id: str | None) -> dict:
        policy = self.policy_for(tenant_id)
        with self._lock:
            usage = self._daily.get((tenant_id or "default", self._day()), _Usage())
        return {
            "tenant_id": tenant_id or "default",
            "day": self._day(),
            "tokens_used": usage.tokens,
            "cost_inr": round(usage.cost_inr, 4),
            "daily_tokens": policy.daily_tokens,
            "daily_cost_inr": policy.daily_cost_inr,
        }
