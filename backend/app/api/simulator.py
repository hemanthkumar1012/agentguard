from fastapi import APIRouter, HTTPException

from app.services import agent_registry
from app.simulator import RedTeamSimulator

router = APIRouter(prefix="/simulator", tags=["red-team"])
simulator = RedTeamSimulator()


@router.post("/{agent_id}/run")
def run_simulation(agent_id: str):
    if agent_registry.get(agent_id) is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    results = simulator.run(agent_id)
    return {
        "agent_id": agent_id,
        "total": len(results),
        "passed": sum(item["passed"] for item in results),
        "results": results,
    }
