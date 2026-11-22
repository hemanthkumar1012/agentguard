"""Optional OPA policy evaluation.

When AGENTGUARD_OPA_URL is set, the gateway asks an OPA server for the decision, using the
policy in policy/opa/agentguard.rego. If OPA cannot be reached or returns anything unexpected,
the request is blocked: the gateway fails closed, never open.
When the variable is not set, the same rules run in Python (app/policy.py); the parity test
(tests/test_policy_parity.py) checks that both give the same decisions.
"""
import httpx

from app.domain import ActionRequest, Decision

OPA_TIMEOUT_SECONDS = 2.0


class PolicyEngineUnavailable(Exception):
    pass


def build_input(request: ActionRequest, findings: list[str]) -> dict:
    # Identity, permission and credential were already checked by the gateway before this point,
    # so they are passed as valid; OPA still re-checks them.
    return {
        "agent": {"status": "active", "permissions": {request.action: True}},
        "action": request.action,
        "target": request.target,
        "data_classification": request.data_classification,
        "risk_score": request.risk_score,
        "credential_valid": True,
        "data_findings": findings,
    }


def decide(opa_url: str, request: ActionRequest, findings: list[str]) -> tuple[Decision, str]:
    url = opa_url.rstrip("/") + "/v1/data/agentguard"
    try:
        response = httpx.post(url, json={"input": build_input(request, findings)}, timeout=OPA_TIMEOUT_SECONDS)
        response.raise_for_status()
        result = response.json().get("result") or {}
        return Decision(result["decision"]), str(result.get("reason") or "Decided by OPA policy.")
    except Exception as exc:  # network error, timeout, bad status, missing or unknown decision
        raise PolicyEngineUnavailable(str(exc)) from exc
