from dataclasses import dataclass

from app.domain import ActionRequest


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    factors: tuple[str, ...]


def assess(request: ActionRequest) -> RiskAssessment:
    score = float(request.risk_score)
    factors: list[str] = []
    if request.data_classification in {"pii", "financial", "credentials", "secret"}:
        score += 15
        factors.append("sensitive-data")
    if request.action in {"delete", "export_data", "transfer_funds", "rotate_credentials"}:
        score += 20
        factors.append("high-impact-action")
    if request.target.startswith("http://"):
        score += 10
        factors.append("unencrypted-target")
    if "external" in request.target.lower():
        score += 10
        factors.append("external-target")
    return RiskAssessment(score=min(score, 100), factors=tuple(factors))
