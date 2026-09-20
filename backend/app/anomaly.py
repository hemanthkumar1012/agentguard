from dataclasses import dataclass
from math import sqrt


@dataclass(frozen=True)
class AnomalyAssessment:
    score: float
    is_anomalous: bool
    reason: str


class BehaviorBaseline:
    """Small dependency-free baseline for agent tool-call behavior.

    Production deployments can replace this contract with a trained model.
    The baseline deliberately uses robust, explainable statistics so the
    security decision remains inspectable during the early project phases.
    """

    def __init__(self, normal_rate_per_minute: float = 10.0, deviation: float = 5.0):
        if normal_rate_per_minute < 0 or deviation <= 0:
            raise ValueError("normal_rate_per_minute must be >= 0 and deviation > 0")
        self.normal_rate_per_minute = normal_rate_per_minute
        self.deviation = deviation

    def assess(self, observed_rate_per_minute: float) -> AnomalyAssessment:
        if observed_rate_per_minute < 0:
            raise ValueError("observed_rate_per_minute must be >= 0")
        z_score = abs(observed_rate_per_minute - self.normal_rate_per_minute) / self.deviation
        score = min(100.0, round(z_score * 25.0, 2))
        anomalous = z_score >= 3.0
        if anomalous:
            reason = "Tool-call rate is materially outside the agent baseline."
        else:
            reason = "Tool-call rate is within the learned baseline range."
        return AnomalyAssessment(score=score, is_anomalous=anomalous, reason=reason)


def euclidean_rate_distance(observed: tuple[float, ...], baseline: tuple[float, ...]) -> float:
    """Utility for extending the baseline to multi-feature behavior vectors."""
    if len(observed) != len(baseline):
        raise ValueError("observed and baseline vectors must have equal length")
    return sqrt(sum((a - b) ** 2 for a, b in zip(observed, baseline)))
