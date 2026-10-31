from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, ValidationError

from app.domain import ActionRequest
from app.policy_engine import PolicyEngine, PolicyRule
from app.policy_impact import analyze_impact, default_versions
from app.policy_rollout import record_dict, replay
from app.services import agent_versions, evaluation_engine, policy_engine, policy_rollout, tool_gateway

router = APIRouter(prefix="/policies", tags=["policies"])
_history: list[dict] = [{"version": policy_engine.version, "loaded_at": datetime.now(timezone.utc).isoformat(),
                         "rules": len(policy_engine.rules), "source": "startup"}]


class PolicyPack(BaseModel):
    version: str = Field(min_length=1, max_length=100)
    policies: list[dict] = Field(min_length=1, max_length=500)
    acknowledge_relaxations: bool = Field(default=False, description="Required to load a pack that loosens recorded decisions.")


class ImpactRequest(PolicyPack):
    agent_versions: list[str] | None = Field(default=None, max_length=10,
                                             description="Defaults to every scripted agent version.")
    include_live_history: bool = True
    include_datasets: bool = True
    run_gates: bool = True


class CanaryRequest(PolicyPack):
    tenants: list[str] = Field(default_factory=list, max_length=50)
    percent: int = Field(default=0, ge=0, le=50)
    auto_rollback: bool = True


class PromoteRequest(BaseModel):
    acknowledge_relaxations: bool = False


def _parse(pack: PolicyPack) -> PolicyEngine:
    try:
        rules = [PolicyRule(**item) for item in pack.policies]
        return PolicyEngine(rules, version=pack.version)
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _guard_relaxations(candidate: PolicyEngine, acknowledged: bool) -> dict:
    """Refuse to enforce a pack that loosens recorded live decisions unless explicitly acknowledged."""
    impact = replay(policy_rollout.records("live"), policy_engine, candidate)
    if impact["relaxed"] and not acknowledged:
        raise HTTPException(status_code=409, detail={
            "message": f"{impact['relaxed']} recorded decision(s) would become less strict. "
                       "Review /policies/impact and resend with acknowledge_relaxations=true.",
            "relaxation_examples": impact["relaxation_examples"][:5]})
    return impact


def _load_live(candidate: PolicyEngine, source: str) -> dict:
    policy_engine.load(candidate.rules)
    policy_engine.version = candidate.version
    _history.append({"version": candidate.version, "loaded_at": datetime.now(timezone.utc).isoformat(),
                     "rules": len(candidate.rules), "source": source})
    return policy_engine.describe()


@router.get("")
def list_policies():
    return policy_engine.describe()


@router.get("/history")
def policy_history():
    return {"history": list(reversed(_history)), "rollout_events": policy_rollout.stats()["events"]}


@router.post("/validate")
def validate_pack(pack: PolicyPack):
    candidate = _parse(pack)
    return {"valid": True, "version": pack.version, "rules": len(candidate.rules)}


@router.post("")
def replace_pack(pack: PolicyPack):
    """Atomically replace the live rule pack (admin only). Invalid packs never load."""
    candidate = _parse(pack)
    _guard_relaxations(candidate, pack.acknowledge_relaxations)
    return _load_live(candidate, "api")


@router.post("/simulate")
def simulate(request: ActionRequest):
    """Preview a decision without auditing, creating approvals or consuming rate limits."""
    decision = tool_gateway.dry_run(request)
    return {"decision": decision, "policy_version": policy_engine.version}


# ---------------------------------------------------------------- impact analysis
@router.post("/impact")
def impact(request: ImpactRequest):
    candidate = _parse(request)
    version_ids = request.agent_versions or default_versions(agent_versions)
    missing = [v for v in version_ids if agent_versions.get(v) is None]
    if missing:
        raise HTTPException(status_code=404, detail=f"Unknown agent version(s): {missing}")
    return analyze_impact(candidate, policy_engine, policy_rollout, evaluation_engine, version_ids,
                          request.include_live_history, request.include_datasets, request.run_gates)


@router.get("/decision-log")
def decision_log(limit: int = Query(default=100, ge=1, le=1000)):
    records = policy_rollout.records()[-limit:]
    return {"total": len(policy_rollout.log), "records": [record_dict(r) for r in reversed(records)]}


# ---------------------------------------------------------------- shadow mode
@router.post("/shadow")
def start_shadow(pack: PolicyPack):
    policy_rollout.start_shadow(_parse(pack))
    return policy_rollout.shadow_report()


@router.get("/shadow")
def shadow_report():
    return policy_rollout.shadow_report()


@router.post("/shadow/stop")
def stop_shadow():
    report = policy_rollout.shadow_report()
    policy_rollout.stop_shadow()
    return report


# ---------------------------------------------------------------- canary
@router.post("/canary")
def start_canary(request: CanaryRequest):
    candidate = _parse(request)
    _guard_relaxations(candidate, request.acknowledge_relaxations)
    try:
        policy_rollout.start_canary(candidate, request.tenants, request.percent, request.auto_rollback)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return policy_rollout.canary_status()


@router.get("/canary")
def canary_status():
    return {"canary": policy_rollout.canary_status()}


@router.post("/canary/promote")
def promote_canary(request: PromoteRequest):
    canary = policy_rollout.canary
    if canary is None:
        raise HTTPException(status_code=404, detail="No canary is running")
    _guard_relaxations(canary.engine, request.acknowledge_relaxations)
    described = _load_live(PolicyEngine(canary.engine.rules, canary.engine.version), "canary-promotion")
    policy_rollout._history("canary_promoted", canary.engine.version, health=canary.health())
    policy_rollout.canary = None
    return described


@router.post("/canary/rollback")
def rollback_canary():
    if policy_rollout.canary is None:
        raise HTTPException(status_code=404, detail="No canary is running")
    policy_rollout.rollback_canary("manual")
    return {"canary": None, "live": policy_engine.version}
