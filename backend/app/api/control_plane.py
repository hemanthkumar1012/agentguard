from fastapi import APIRouter

from app.metrics import snapshot
from app.services import agent_registry, audit_ledger

router = APIRouter(prefix="/control-plane", tags=["control-plane"])


@router.get("/snapshot")
def get_control_plane_snapshot():
    return snapshot(agent_registry, audit_ledger)
