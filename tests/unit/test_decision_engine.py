"""
Unit tests for DecisionEngine (Module 5).
Maps to: UT18–UT22 from D04 test plan.
Run: pytest tests/unit/test_decision_engine.py -v
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

import pytest
from decision_engine import DecisionEngine, Decision
from dataclasses import dataclass


@dataclass
class FakeRuleResult:
    matched: bool
    rule_id: str = "SQLi_001"
    category: str = "SQLi"


@dataclass
class FakeMLResult:
    probability: float


MATCH    = FakeRuleResult(matched=True)
NO_MATCH = FakeRuleResult(matched=False)


class TestDecisionEngine:

    def test_rule_only_block(self):
        """UT18: rule_only + MATCH -> BLOCK."""
        de = DecisionEngine(mode="rule_only")
        d  = de.decide(MATCH, FakeMLResult(0.1))
        assert d.action == "BLOCK"
        assert "rule" in d.reason.lower()

    def test_rule_only_allow(self):
        """UT19: rule_only + NO_MATCH -> ALLOW."""
        de = DecisionEngine(mode="rule_only")
        d  = de.decide(NO_MATCH, FakeMLResult(0.1))
        assert d.action == "ALLOW"

    def test_ml_only_block(self):
        """UT20: ml_only + score >= threshold -> BLOCK."""
        de = DecisionEngine(mode="ml_only", threshold=0.5)
        d  = de.decide(NO_MATCH, FakeMLResult(0.9))
        assert d.action == "BLOCK"

    def test_ml_only_allow(self):
        """ml_only + score < threshold -> ALLOW."""
        de = DecisionEngine(mode="ml_only", threshold=0.5)
        d  = de.decide(NO_MATCH, FakeMLResult(0.2))
        assert d.action == "ALLOW"

    def test_hybrid_both_agree_attack(self):
        """Both MATCH and ML >= threshold -> BLOCK."""
        de = DecisionEngine(mode="hybrid", threshold=0.5)
        d  = de.decide(MATCH, FakeMLResult(0.9))
        assert d.action == "BLOCK"
        assert "both agree" in d.reason.lower()

    def test_hybrid_case_a(self):
        """UT22: Case A – rule fires, ML scores benign -> BLOCK (rule wins)."""
        de = DecisionEngine(mode="hybrid", threshold=0.5)
        d  = de.decide(MATCH, FakeMLResult(0.2))
        assert d.action == "BLOCK"
        assert "Case A" in d.reason

    def test_hybrid_case_b(self):
        """UT21: Case B – no rule fires, ML scores malicious -> BLOCK."""
        de = DecisionEngine(mode="hybrid", threshold=0.5)
        d  = de.decide(NO_MATCH, FakeMLResult(0.85))
        assert d.action == "BLOCK"
        assert "Case B" in d.reason

    def test_hybrid_both_agree_clean(self):
        """Both NO_MATCH and ML < threshold -> ALLOW."""
        de = DecisionEngine(mode="hybrid", threshold=0.5)
        d  = de.decide(NO_MATCH, FakeMLResult(0.1))
        assert d.action == "ALLOW"

    def test_invalid_mode_raises(self):
        """Invalid mode raises ValueError."""
        with pytest.raises(ValueError):
            DecisionEngine(mode="invalid_mode")

    def test_http_status(self):
        """BLOCK -> 403, ALLOW -> 200."""
        de = DecisionEngine(mode="hybrid")
        block = de.decide(MATCH, FakeMLResult(0.9))
        allow = de.decide(NO_MATCH, FakeMLResult(0.1))
        assert block.http_status() == 403
        assert allow.http_status() == 200
