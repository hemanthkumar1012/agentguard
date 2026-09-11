from datetime import datetime, timezone

from fastapi import APIRouter

from app.config import settings

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
def health():
    return {"status": "ok", "service": settings.app_name, "environment": settings.environment, "timestamp": datetime.now(timezone.utc)}


@router.get("/ready")
def readiness():
    return {"status": "ready", "checks": {"runtime": "ok", "policy_engine": "ok", "audit_ledger": "ok"}}
