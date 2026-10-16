"""
Unit tests for Logger (Module 6): event log, error log and summary.
Maps to: FR12, FR15, NFR03.
Run: pytest tests/unit/test_logger.py -v
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

import pytest
from dataclasses import dataclass
from feature_extractor import HTTPRequest
from decision_engine import Decision
from logger import Logger, print_summary


@dataclass
class FakeRuleResult:
    matched: bool
    rule_id: str = None
    category: str = None


@dataclass
class FakeMLResult:
    probability: float


def make_logger(tmp_path):
    return Logger(log_file=str(tmp_path / "events.csv"),
                  alert_file=str(tmp_path / "alerts.log"),
                  error_file=str(tmp_path / "errors.csv"))


def log_one(lg, action, reason, rule_id=None, category=None, score=0.1):
    req = HTTPRequest("GET", "/x", "id=1", {}, "", "10.0.0.5")
    dec = Decision(action=action, reason=reason, rule_id=rule_id,
                   ml_score=score, mode="hybrid")
    lg.log_event(req, dec, FakeRuleResult(rule_id is not None, rule_id, category),
                 FakeMLResult(score))


def test_ut_l1_summary_counts(tmp_path):
    lg = make_logger(tmp_path)
    log_one(lg, "ALLOW", "Both agree, legitimate")
    log_one(lg, "BLOCK", "Both agree: confirmed attack", "SQLi_002", "SQLi", 0.99)
    log_one(lg, "BLOCK", "Case A - rule wins", "XSS_001", "XSS", 0.2)
    log_one(lg, "BLOCK", "Case B - ML catches obfuscated payload", None, None, 0.7)
    s = lg.summarise()
    assert s["total"] == 4 and s["blocked"] == 3 and s["allowed"] == 1
    assert s["case_a"] == 1 and s["case_b"] == 1
    assert s["by_category"] == {"SQLi": 1, "XSS": 1, "ML-only (Case B)": 1}
    assert s["block_rate"] == "75.0%"


def test_ut_l2_block_writes_alert(tmp_path):
    lg = make_logger(tmp_path)
    log_one(lg, "BLOCK", "Both agree: confirmed attack", "SQLi_002", "SQLi", 0.99)
    assert "BLOCKED SQLi_002" in (tmp_path / "alerts.log").read_text()


def test_ut_l3_error_log_is_separate(tmp_path):
    lg = make_logger(tmp_path)
    log_one(lg, "ALLOW", "Both agree, legitimate")
    lg.log_error("10.0.0.9", "GET", "/y", "Backend failure: refused")
    lg.log_error("10.0.0.9", "", "", "HTTP 400 Bad request syntax")
    s = lg.summarise()
    assert s["total"] == 1          # errors do not count as requests judged
    assert s["errors"] == 2
    text = (tmp_path / "errors.csv").read_text()
    assert "Backend failure" in text and "HTTP 400" in text


def test_ut_l4_summary_missing_file(tmp_path):
    lg = Logger(log_file=str(tmp_path / "events.csv"))
    os.remove(lg.log_file)
    assert lg.summarise() == {}


def test_ut_l5_print_summary_output(tmp_path, capsys):
    lg = make_logger(tmp_path)
    log_one(lg, "BLOCK", "Case B - ML catches obfuscated payload", None, None, 0.7)
    print_summary(lg.summarise())
    out = capsys.readouterr().out
    assert "Detection Summary" in out
    assert "Blocked : 1" in out
    assert "ML-only (Case B) : 1" in out
