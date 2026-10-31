from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, ValidationError

from app.domain import ActionRequest
from app.policy_engine import PolicyRule
from app.services import policy_engine, tool_gateway

router = APIRouter(prefix="/policies", tags=["policies"])
_history: list[dict] = [{"version": policy_engine.version, "loaded_at": datetime.now(timezone.utc).isoformat(),
                         "rules": len(policy_engine.rules), "source": "startup"}]


class PolicyPack(BaseModel):
    version: str = Field(min_length=1, max_length=100)
    policies: list[dict] = Field(min_length=1, max_length=500)


def _parse(pack: PolicyPack) -> list[PolicyRule]:
    try:
        rules = [PolicyRule(**item) for item in pack.policies]
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    ids = [rule.id for rule in rules]
    if len(ids) != len(set(ids)):
        raise HTTPException(status_code=422, detail="Duplicate policy ids")
    return rules


@router.get("")
def list_policies():
    return policy_engine.describe()


@router.get("/history")
def policy_history():
    return {"history": list(reversed(_history))}


@router.post("/validate")
def validate_pack(pack: PolicyPack):
    rules = _parse(pack)
    return {"valid": True, "version": pack.version, "rules": len(rules)}


@router.post("")
def replace_pack(pack: PolicyPack):
    """Atomically replace the live rule pack (admin only). Invalid packs never load."""
    rules = _parse(pack)
    policy_engine.load(rules)
    policy_engine.version = pack.version
    _history.append({"version": pack.version, "loaded_at": datetime.now(timezone.utc).isoformat(),
                     "rules": len(rules), "source": "api"})
    return policy_engine.describe()


@router.post("/simulate")
def simulate(request: ActionRequest):
    """Preview a decision without auditing, creating approvals or consuming rate limits."""
    decision = tool_gateway.dry_run(request)
    return {"decision": decision, "policy_version": policy_engine.version}
