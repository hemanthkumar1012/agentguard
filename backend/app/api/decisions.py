from fastapi import APIRouter

from app.domain import ActionRequest, DecisionResponse
from app.policy import evaluate

router = APIRouter(prefix="/decisions", tags=["decisions"])


@router.post("", response_model=DecisionResponse)
def create_decision(request: ActionRequest) -> DecisionResponse:
    return evaluate(request)
