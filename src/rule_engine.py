"""
Module 3: Rule-Based Engine
Hybrid WAF – IT28X87 Honours Project
Mbadaliga, AB (219044112)

Loads detection rules from a plain-text file and evaluates each HTTP
request against compiled regex patterns. Returns a RuleResult indicating
whether a match was found and which category triggered it.

Rule file format (one rule per line):
    RULE_ID | CATEGORY | REGEX_PATTERN
Lines starting with # are treated as comments and ignored.
"""
import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Rule:
    """Represents a single detection rule loaded from the rules file."""
    rule_id: str
    category: str          # SQLi | XSS | PATH
    pattern: re.Pattern
    raw_pattern: str

    def matches(self, text: str) -> bool:
        return bool(self.pattern.search(text))


@dataclass
class RuleResult:
    """Output from RuleEngine.evaluate(). Passed to DecisionEngine."""
    matched: bool
    rule_id: Optional[str] = None
    category: Optional[str] = None

    def is_match(self) -> bool:
        return self.matched

    def summary(self) -> str:
        if self.matched:
            return f"MATCH – rule={self.rule_id} category={self.category}"
        return "NO_MATCH"


class RuleEngine:
    """
    Loads rules at start-up, compiles regex patterns once, then
    evaluates every incoming request string against them in order.
    Returns on the first match (fail-fast strategy).
    """

    def __init__(self, rules_file: str):
        self.rules_file = rules_file
        self.rules: List[Rule] = []
        self.load_rules()

    def load_rules(self) -> None:
        """
        Reads the rules file and compiles each valid regex.
        Invalid regex patterns are skipped with a warning – the engine
        continues loading remaining rules (NFR03: no crashes).
        """
        self.rules = []
        with open(self.rules_file, 'r') as f:
            for line_number, line in enumerate(f, start=1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                rule = self._parse_line(line, line_number)
                if rule:
                    self.rules.append(rule)
        print(f"[INFO] RuleEngine: loaded {len(self.rules)} rules "
              f"from '{self.rules_file}'")

    def _parse_line(self, line: str,
                    line_number: int) -> Optional[Rule]:
        parts = [p.strip() for p in line.split('|', 2)]
        if len(parts) != 3:
            print(f"[WARN] Line {line_number}: "
                  f"expected 3 fields, got {len(parts)} – skipped")
            return None
        rule_id, category, raw_pat = parts
        try:
            compiled = re.compile(raw_pat, re.IGNORECASE)
            return Rule(rule_id, category, compiled, raw_pat)
        except re.error as e:
            print(f"[WARN] Line {line_number}: "
                  f"invalid regex in {rule_id} ({e}) – skipped")
            return None

    def evaluate(self, text: str) -> RuleResult:
        """
        Iterates through loaded rules in order.
        Returns on the first match. Returns NO_MATCH if no rule fires.
        """
        for rule in self.rules:
            if rule.matches(text):
                return RuleResult(
                    matched=True,
                    rule_id=rule.rule_id,
                    category=rule.category
                )
        return RuleResult(matched=False)
