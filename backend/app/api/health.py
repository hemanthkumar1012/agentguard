from fastapi import APIRouter, HTTPException

from app.config import settings
from app.services import audit_ledger, persistence

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
def health():
    # Keep the compact response stable for existing integrations.
    return {"status": "ok", "service": "agentguard-api"}


@router.get("/ready")
def readiness():
    checks = {
        "runtime": "ok",
        "policy_engine": "ok",
        "audit_ledger": "ok" if audit_ledger.verify_integrity() else "failed",
    }

    if persistence is not None:
        try:
            persistence.healthcheck()
            checks["persistence"] = "ok"
        except Exception:
            checks["persistence"] = "failed"

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
