"""
Unit tests for FeatureExtractor (Module 2).
Maps to: UT04-UT08 from D04 test plan.
Run: pytest tests/unit/test_feature_extractor.py -v
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

import pytest
from feature_extractor import FeatureExtractor, HTTPRequest, FeatureVector


@pytest.fixture
def extractor():
    return FeatureExtractor()


def make_request(body="", path="/", qs=""):
    return HTTPRequest(
        method="GET", path=path,
        query_string=qs, headers={}, body=body
    )


class TestFeatureExtractor:

    def test_sqli_payload(self, extractor):
        """UT04: SQL injection payload produces expected feature values."""
        req = make_request(body="' OR 1=1 --")
        fv = extractor.extract(req)
        assert fv.F2_special_chars >= 3
        assert fv.F3_sql_keywords >= 1
        assert fv.F4_script_flag == 0

    def test_xss_payload(self, extractor):
        """UT05: XSS payload sets F4 flag to 1."""
        req = make_request(body="<script>alert(1)</script>")
        fv = extractor.extract(req)
        assert fv.F4_script_flag == 1
        assert fv.F2_special_chars >= 2

    def test_path_traversal(self, extractor):
        """UT06: Path traversal sequences counted in F5."""
        req = make_request(path="../../etc/passwd")
        fv = extractor.extract(req)
        assert fv.F5_traversal >= 2

    def test_empty_input(self, extractor):
        """UT07: Empty input returns all zeros, no exceptions."""
        req = make_request(body="", path="", qs="")
        fv = extractor.extract(req)
        assert fv.F1_length == 2
        assert fv.F2_special_chars == 0
        assert fv.F3_sql_keywords == 0
        assert fv.F4_script_flag == 0
        assert fv.F5_traversal == 0
        assert fv.F6_entropy == 0.0

    def test_clean_request(self, extractor):
        """UT08: Clean request has low feature values."""
        req = make_request(path="/search", qs="q=shoes")
        fv = extractor.extract(req)
        assert fv.F3_sql_keywords == 0
        assert fv.F4_script_flag == 0
        assert fv.F5_traversal == 0
        assert 2.0 <= fv.F6_entropy <= 5.0

    def test_entropy_encoded_payload(self, extractor):
        """High encoding increases F6 entropy above clean baseline."""
        clean = make_request(body="shoes")
        encoded = make_request(body="%27%20OR%20%271%27%3D%271")
        fv_clean = extractor.extract(clean)
        fv_encoded = extractor.extract(encoded)
        assert fv_encoded.F6_entropy > fv_clean.F6_entropy

    def test_to_list_length(self, extractor):
        """FeatureVector.to_list() returns exactly 6 elements."""
        req = make_request(body="test")
        fv = extractor.extract(req)
        assert len(fv.to_list()) == 6
