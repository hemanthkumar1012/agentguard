import pytest

from app.anomaly import BehaviorBaseline, euclidean_rate_distance


def test_normal_behavior_is_not_anomalous():
    result = BehaviorBaseline(normal_rate_per_minute=10, deviation=5).assess(12)
    assert result.is_anomalous is False
    assert result.score == 10.0


def test_spike_is_anomalous():
    result = BehaviorBaseline(normal_rate_per_minute=10, deviation=5).assess(30)
    assert result.is_anomalous is True
    assert result.score == 100.0


def test_behavior_vector_distance_is_deterministic():
    assert euclidean_rate_distance((3, 4), (0, 0)) == 5


def test_invalid_behavior_rate_is_rejected():
    with pytest.raises(ValueError):
        BehaviorBaseline().assess(-1)
