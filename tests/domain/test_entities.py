"""Tests for domain entities."""
import pytest
from domain.entities import AnalysisResult, Severity
from uuid import UUID

def test_analysis_result_defaults():
    result = AnalysisResult()
    assert isinstance(result.id, UUID)
    assert result.title == ""
    assert result.severity == Severity.INFO

def test_risk_score_value_object():
    from domain.value_objects import RiskScore
    score = RiskScore(5.5)
    assert score.value == 5.5
    with pytest.raises(ValueError):
        RiskScore(11.0)
    with pytest.raises(ValueError):
        RiskScore(-1.0)