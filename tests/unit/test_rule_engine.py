"""
Unit tests for RuleEngine (Module 3).
Maps to: UT09–UT13 from D04 test plan.
Run: pytest tests/unit/test_rule_engine.py -v
"""
import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

import pytest
from rule_engine import RuleEngine, RuleResult

RULES_FILE = os.path.join(
    os.path.dirname(__file__), '../../rules/rules.txt'
)


@pytest.fixture
def engine():
    return RuleEngine(RULES_FILE)


class TestRuleEngine:

    def test_sqli_detected(self, engine):
        """UT09: UNION SELECT triggers SQLi rule."""
        result = engine.evaluate("UNION SELECT * FROM users")
        assert result.matched is True
        assert result.category == "SQLi"

    def test_xss_detected(self, engine):
        """UT10: <script> tag triggers XSS rule."""
        result = engine.evaluate("<script>alert(1)</script>")
        assert result.matched is True
        assert result.category == "XSS"

    def test_path_traversal_detected(self, engine):
        """UT11: ../ sequence triggers PATH rule."""
        result = engine.evaluate("GET /../../etc/passwd")
        assert result.matched is True
        assert result.category == "PATH"

    def test_clean_request(self, engine):
        """UT12: Clean request returns NO_MATCH."""
        result = engine.evaluate("GET /index.html?q=shoes")
        assert result.matched is False
        assert result.rule_id is None

    def test_invalid_regex_skipped(self, tmp_path):
        """UT13: Invalid regex is skipped; valid rules still load."""
        rules_content = (
            "GOOD_001 | SQLi | (?i)(union)\n"
            "BAD_001  | SQLi | (?i)([invalid regex\n"   # invalid
            "GOOD_002 | XSS  | (?i)(<script)\n"
        )
        rules_file = tmp_path / "test_rules.txt"
        rules_file.write_text(rules_content)
        engine = RuleEngine(str(rules_file))
        assert len(engine.rules) == 2   # only the 2 valid rules

    def test_is_match_method(self, engine):
        """RuleResult.is_match() mirrors the matched attribute."""
        result = engine.evaluate("' OR 1=1 --")
        assert result.is_match() == result.matched

    def test_stacked_query_detected(self, engine):
        """UT14: Semicolon-chained query triggers SQLi rule (SQLi_013)."""
        result = engine.evaluate("id=1; DROP TABLE users")
        assert result.matched is True
        assert result.category == "SQLi"

    def test_xp_cmdshell_detected(self, engine):
        """UT15: xp_cmdshell triggers SQLi rule (SQLi_014)."""
        result = engine.evaluate("'; EXEC xp_cmdshell('dir') --")
        assert result.matched is True
        assert result.category == "SQLi"

    def test_blind_sqli_function_detected(self, engine):
        """UT16: SUBSTRING used for blind SQLi triggers SQLi rule (SQLi_015)."""
        result = engine.evaluate("id=1 AND SUBSTRING(password,1,1)='a'")
        assert result.matched is True
        assert result.category == "SQLi"

    def test_data_uri_xss_detected(self, engine):
        """UT17: data:text/html URI triggers XSS rule (XSS_013)."""
        result = engine.evaluate('<a href="data:text/html,<script>alert(1)</script>">')
        assert result.matched is True
        assert result.category == "XSS"

    def test_vbscript_xss_detected(self, engine):
        """UT18: vbscript: URI triggers XSS rule (XSS_014)."""
        result = engine.evaluate('<a href="vbscript:msgbox(1)">')
        assert result.matched is True
        assert result.category == "XSS"

    def test_srcdoc_xss_detected(self, engine):
        """UT19: iframe srcdoc attribute triggers XSS rule (XSS_015)."""
        result = engine.evaluate('<iframe srcdoc="<script>alert(1)</script>">')
        assert result.matched is True
        assert result.category == "XSS"

    def test_php_stream_wrapper_detected(self, engine):
        """UT20: php://filter stream wrapper triggers PATH rule (PATH_013)."""
        result = engine.evaluate("page=php://filter/convert.base64-encode/resource=index.php")
        assert result.matched is True
        assert result.category == "PATH"

    def test_ssh_key_path_detected(self, engine):
        """UT21: .ssh/id_rsa path triggers PATH rule (PATH_014)."""
        result = engine.evaluate("file=../../.ssh/id_rsa")
        assert result.matched is True
        assert result.category == "PATH"

    def test_web_config_detected(self, engine):
        """UT22: web.config path triggers PATH rule (PATH_015)."""
        result = engine.evaluate("file=../web.config")
        assert result.matched is True
        assert result.category == "PATH"

    def test_stacked_query_detected(self, engine):
        """UT14: Semicolon-chained query triggers SQLi rule (SQLi_013)."""
        result = engine.evaluate("id=1; DROP TABLE users")
        assert result.matched is True
        assert result.category == "SQLi"

    def test_xp_cmdshell_detected(self, engine):
        """UT15: xp_cmdshell triggers SQLi rule (SQLi_014)."""
        result = engine.evaluate("'; EXEC xp_cmdshell('dir') --")
        assert result.matched is True
        assert result.category == "SQLi"

    def test_blind_sqli_function_detected(self, engine):
        """UT16: SUBSTRING used for blind SQLi triggers SQLi rule (SQLi_015)."""
        result = engine.evaluate("id=1 AND SUBSTRING(password,1,1)='a'")
        assert result.matched is True
        assert result.category == "SQLi"

    def test_data_uri_xss_detected(self, engine):
        """UT17: data:text/html URI triggers XSS rule (XSS_013)."""
        result = engine.evaluate('<a href="data:text/html,<script>alert(1)</script>">')
        assert result.matched is True
        assert result.category == "XSS"

    def test_vbscript_xss_detected(self, engine):
        """UT18: vbscript: URI triggers XSS rule (XSS_014)."""
        result = engine.evaluate('<a href="vbscript:msgbox(1)">')
        assert result.matched is True
        assert result.category == "XSS"

    def test_srcdoc_xss_detected(self, engine):
        """UT19: iframe srcdoc attribute triggers XSS rule (XSS_015)."""
        result = engine.evaluate('<iframe srcdoc="<script>alert(1)</script>">')
        assert result.matched is True
        assert result.category == "XSS"

    def test_php_stream_wrapper_detected(self, engine):
        """UT20: php://filter stream wrapper triggers PATH rule (PATH_013)."""
        result = engine.evaluate("page=php://filter/convert.base64-encode/resource=index.php")
        assert result.matched is True
        assert result.category == "PATH"

    def test_ssh_key_path_detected(self, engine):
        """UT21: .ssh/id_rsa path triggers PATH rule (PATH_014)."""
        result = engine.evaluate("file=../../.ssh/id_rsa")
        assert result.matched is True
        assert result.category == "PATH"

    def test_web_config_detected(self, engine):
        """UT22: web.config path triggers PATH rule (PATH_015)."""
        result = engine.evaluate("file=../web.config")
        assert result.matched is True
        assert result.category == "PATH"
