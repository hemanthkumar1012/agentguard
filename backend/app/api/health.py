from fastapi import APIRouter

from app.config import settings

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
def health():
    # Keep the compact response stable for existing integrations.
    return {"status": "ok", "service": "agentguard-api"}


@router.get("/ready")
def readiness():
    return {
        "status": "ready",
        "service": settings.app_name,
        "environment": settings.environment,
        "checks": {"runtime": "ok", "policy_engine": "ok", "audit_ledger": "ok"},
    }
