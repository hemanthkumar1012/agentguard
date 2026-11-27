from fastapi import APIRouter, HTTPException

from app.config import settings
from app.services import audit_ledger, flow_engine, persistence

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
def health():
    # Liveness only: this endpoint intentionally does not require persistence.
    return {"status": "ok", "service": "agentguard-api"}


@router.get("/ready")
def readiness():
    checks = {
        "runtime": "ok",
        "policy_engine": "ok",
        "audit_ledger": "ok" if audit_ledger.verify_integrity() else "failed",
    }

    if persistence is None:
        checks["persistence"] = "failed" if settings.environment.lower() == "production" else "not_configured"
    else:
        try:
            persistence.healthcheck()
            checks["persistence"] = "ok"
        except Exception:
            checks["persistence"] = "failed"

    store = flow_engine.sessions
    if hasattr(store, "ping"):
        try:
            checks["flow_labels"] = "ok" if store.ping() else "failed"
        except Exception:
            checks["flow_labels"] = "failed"
    else:
        # Labels in process memory are lost on restart and not shared between workers.
        checks["flow_labels"] = "process_memory"

    if settings.environment.lower() == "production" and not settings.api_key:
        checks["api_authentication"] = "failed"
    else:
        checks["api_authentication"] = "ok" if settings.api_key else "development_only"

    if "failed" in checks.values():
        raise HTTPException(
            status_code=503,
            detail={"status": "not_ready", "service": settings.app_name, "checks": checks},
        )

    return {
        "status": "ready",
        "service": settings.app_name,
        "environment": settings.environment,
        "checks": checks,
    }
