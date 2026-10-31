import json

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from starlette.responses import Response

from app.redteam_fuzzer import OPERATORS, SEEDS, false_positive_rate
from app.services import adaptive_redteam

router = APIRouter(prefix="/redteam", tags=["red-team"])


class FuzzRequest(BaseModel):
    version_id: str = Field(min_length=1, max_length=60)
    budget: int = Field(default=300, ge=20, le=5000)
    generations: int = Field(default=4, ge=0, le=10)
    max_depth: int = Field(default=3, ge=1, le=4)
    seed: int = Field(default=7, ge=0, le=2**31)


@router.get("/fuzz/catalog")
def catalog():
    return {"operators": sorted(OPERATORS), "seeds": [{"goal": s["goal"], "forbidden": s["forbidden"]} for s in SEEDS]}


@router.get("/detector")
def detector_quality():
    """False-positive rate of the injection detector on a benign corpus (support messages, policy docs)."""
    return false_positive_rate()


@router.post("/fuzz", status_code=201)
def run_fuzz(request: FuzzRequest):
    try:
        run = adaptive_redteam.run(request.version_id, request.budget, request.generations, request.max_depth, request.seed)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return run.summary()


@router.get("/fuzz")
def list_fuzz():
    return {"runs": adaptive_redteam.list()}


@router.get("/fuzz/{fuzz_id}")
def get_fuzz(fuzz_id: str):
    run = adaptive_redteam.get(fuzz_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Fuzz run not found")
    return run.summary()


@router.get("/fuzz/{fuzz_id}/cases")
def export_cases(fuzz_id: str, only: str = Query(default="undetected", pattern="^(undetected|hijacked|successful|all)$"),
                 limit: int = Query(default=200, ge=1, le=2000)):
    """Discovered variants as dataset cases (JSONL), ready to append to datasets/prompt_injection_cases.jsonl."""
    try:
        cases = adaptive_redteam.export_cases(fuzz_id, only)[:limit]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    body = "\n".join(json.dumps(c, ensure_ascii=False) for c in cases) + ("\n" if cases else "")
    return Response(body, media_type="application/x-ndjson",
                    headers={"content-disposition": f'attachment; filename="{fuzz_id}-{only}.jsonl"'})
