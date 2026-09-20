from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.anomaly import BehaviorBaseline

router = APIRouter(prefix="/anomaly", tags=["anomaly"])


class AnomalyRequest(BaseModel):
    observed_rate_per_minute: float = Field(ge=0)
    normal_rate_per_minute: float = Field(default=10.0, ge=0)
    deviation: float = Field(default=5.0, gt=0)


@router.post("/assess")
def assess_anomaly(request: AnomalyRequest):
    assessment = BehaviorBaseline(
        normal_rate_per_minute=request.normal_rate_per_minute,
        deviation=request.deviation,
    ).assess(request.observed_rate_per_minute)
    return {
        "score": assessment.score,
        "is_anomalous": assessment.is_anomalous,
        "reason": assessment.reason,
    }
