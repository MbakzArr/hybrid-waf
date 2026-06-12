"""
Module 2: Feature Extractor
Hybrid WAF – IT28X87 Honours Project
Mbadaliga, AB (219044112)

Computes the six-feature vector [F1–F6] from every parsed HTTP request.
All methods are pure functions operating on the concatenated analysis string.
No external libraries required – standard library only.
"""
import re
import math
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class HTTPRequest:
    """Data transfer object representing a parsed HTTP request."""
    method: str
    path: str
    query_string: str
    headers: Dict[str, str]
    body: str
    source_ip: str = "0.0.0.0"

    def full_text(self) -> str:
        """Returns concatenated path + query string + body for analysis."""
        return f"{self.path} {self.query_string} {self.body}"

    def is_malformed(self) -> bool:
        """Returns True if the request is missing required fields."""
        return not self.method or not self.path


@dataclass
class FeatureVector:
    """
    Six-feature vector extracted from one HTTP request.

    F1 – request_length     : total character count of path+qs+body
    F2 – special_char_count : count of attack-relevant special characters
    F3 – sql_keyword_count  : count of SQL keyword boundary matches
    F4 – script_tag_flag    : 1 if XSS patterns present, else 0
    F5 – path_traversal_cnt : count of ../ traversal sequences
    F6 – entropy            : Shannon entropy of character distribution
    """
    F1_length: int
    F2_special_chars: int
    F3_sql_keywords: int
    F4_script_flag: int
    F5_traversal: int
    F6_entropy: float

    def to_list(self) -> List[float]:
        """Returns features as a plain list for ML input."""
        return [
            self.F1_length,
            self.F2_special_chars,
            self.F3_sql_keywords,
            self.F4_script_flag,
            self.F5_traversal,
            self.F6_entropy,
        ]


class FeatureExtractor:
    """
    Stateless feature extractor. All keyword lists and regex patterns
    are compiled once at class load time (ClassVar), not per instance.
    """

    SQL_KEYWORDS = [
        "SELECT", "UNION", "DROP", "INSERT",
        "UPDATE", "DELETE", "OR", "WHERE", "FROM"
    ]
    SPECIAL_CHARS = set("'\";<>()=-#")

    _TRAVERSAL_PAT = re.compile(
        r'(\.\./|%2e%2e%2f|%2e%2e/|\.\.\\)',
        re.IGNORECASE
    )
    _SCRIPT_PAT = re.compile(
        r'(<script[\s>\/]|onerror\s*=|onload\s*=|javascript\s*:)',
        re.IGNORECASE
    )

    def extract(self, req: HTTPRequest) -> FeatureVector:
        """
        Main public method. Takes an HTTPRequest, returns a FeatureVector.
        Called by TrafficReader for every intercepted request.
        """
        s = req.full_text()
        return FeatureVector(
            F1_length        = len(s),
            F2_special_chars = self._f2_specials(s),
            F3_sql_keywords  = self._f3_sql(s),
            F4_script_flag   = 1 if self._SCRIPT_PAT.search(s) else 0,
            F5_traversal     = len(self._TRAVERSAL_PAT.findall(s)),
            F6_entropy       = self._f6_entropy(s),
        )

    def _f2_specials(self, s: str) -> int:
        return sum(1 for c in s if c in self.SPECIAL_CHARS)

    def _f3_sql(self, s: str) -> int:
        upper = s.upper()
        return sum(
            1 for kw in self.SQL_KEYWORDS
            if re.search(r'\b' + kw + r'\b', upper)
        )

    def _f6_entropy(self, s: str) -> float:
        """
        Shannon entropy: H(s) = -sum(p_c * log2(p_c))
        where p_c = count(c) / len(s).
        Returns 0.0 for empty strings to avoid ZeroDivisionError.
        """
        if not s:
            return 0.0
        freq: Dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((cnt / n) * math.log2(cnt / n)
                    for cnt in freq.values())
