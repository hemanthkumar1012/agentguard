from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.evaluation import DATASETS, DEFAULT_GATES, ReleaseGate, dataset_summary, load_cases
from app.services import evaluation_engine

router = APIRouter(tags=["evaluations"])


class GateOverride(BaseModel):
    metric: str
    threshold: float
    comparator: str = Field(default=">=", pattern=r"^(>=|<=)$")
    critical: bool = True


class EvaluationRequest(BaseModel):
    version_id: str = Field(min_length=1, max_length=60)
    datasets: list[str] | None = None
    case_ids: list[str] | None = Field(default=None, max_length=500)
    repeats: int = Field(default=1, ge=1, le=5)
    gates: list[GateOverride] | None = None


class CompareRequest(BaseModel):
    baseline_id: str
    candidate_id: str


class RedTeamRequest(BaseModel):
    version_id: str = Field(min_length=1, max_length=60)
    attack_types: list[str] | None = None


@router.get("/evaluations/datasets")
def datasets():
    return {"datasets": dataset_summary(), "default_gates": [g.__dict__ for g in DEFAULT_GATES]}


@router.get("/evaluations/datasets/{name}")
def dataset_cases(name: str):
    if name not in DATASETS:
        raise HTTPException(status_code=404, detail="Dataset not found")
    return {"name": name, "cases": load_cases([name])}


@router.post("/evaluations", status_code=201)
def run_evaluation(request: EvaluationRequest):
    if request.datasets and set(request.datasets) - set(DATASETS):
        raise HTTPException(status_code=422, detail=f"Unknown datasets; choose from {DATASETS}")
    gates = [ReleaseGate(**g.model_dump()) for g in request.gates] if request.gates else None
    try:
        run = evaluation_engine.evaluate(request.version_id, request.datasets, request.repeats, gates, request.case_ids)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return run.brief()


@router.get("/evaluations")
def list_evaluations():
    return {"evaluations": evaluation_engine.list()}


@router.get("/evaluations/{evaluation_id}")
def get_evaluation(evaluation_id: str, failed_only: bool = False):
    run = evaluation_engine.get(evaluation_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Evaluation not found")
    cases = [c for c in run.cases if not failed_only or not c["passed"]]
    return {**run.brief(), "cases": cases}


@router.post("/evaluations/compare")
def compare(request: CompareRequest):
    try:
        return evaluation_engine.compare(request.baseline_id, request.candidate_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/redteam/run")
def red_team(request: RedTeamRequest):
    """Run the attack datasets and report each attack the way a red-team report would."""
    try:
        run = evaluation_engine.evaluate(request.version_id,
                                         ["prompt_injection_cases", "pii_leakage_cases", "tool_misuse_cases"])
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    results = []
    for case in run.cases:
        if request.attack_types and case["attack_type"] not in request.attack_types:
            continue
        results.append({
            "case_id": case["case_id"],
            "attack_type": case["attack_type"],
            "input_source": case["input_source"],
            "severity": case["severity"],
            "agent_response": case["output"],
            "tool_calls_attempted": [{"action": a["action"], "decision": a["decision"], "policy": a["policy_id"],
                                      "executed": a["executed"]} for a in case["attempted"]],
            "sensitive_data_exposed": case["metrics"]["privacy"] is False or case["metrics"]["containment"] is False,
            "agent_resisted": case["metrics"]["injection_resistance"] is not False,
            "gateway_contained": case["metrics"]["containment"] is not False,
            "passed": case["passed"],
            "failures": case["failures"],
            "remediation": case["remediation"],
            "trace_id": case["trace_id"],
        })
    return {"evaluation_id": run.evaluation_id, "version_id": run.version_id,
            "release_decision": run.release_decision, "summary": run.summary["by_attack_type"],
            "total": len(results), "passed": sum(r["passed"] for r in results), "results": results}
