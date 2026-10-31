from fastapi import APIRouter, HTTPException, Query

from app.services import agent_versions, evaluation_engine, session_guard, train_session_models

router = APIRouter(prefix="/sessions", tags=["session-guard"])


@router.get("")
def list_sessions(tripped_only: bool = False, min_risk: float = Query(default=0, ge=0),
                  limit: int = Query(default=100, ge=1, le=1000)):
    return {"stats": session_guard.stats(), "sessions": session_guard.list(limit, tripped_only, min_risk)}


@router.get("/quarantine")
def quarantine_log():
    return {"events": session_guard.quarantine_log()}


@router.get("/models/{version_id}")
def model(version_id: str):
    described = session_guard.describe_model(version_id)
    if described is None:
        raise HTTPException(status_code=404, detail="No sequence model for this version")
    return {"version_id": version_id, **described}


@router.post("/models/retrain")
def retrain():
    """Relearn each version's normal tool-call sequences from benign evaluation cases it passes."""
    return {"trained": train_session_models(evaluation_engine, agent_versions)}


@router.get("/{session_id}")
def get_session(session_id: str):
    state = session_guard.get(session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return state.to_dict(full=True)
