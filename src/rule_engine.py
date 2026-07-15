"""
Module 3: Rule-Based Engine
Hybrid WAF - IT28X87 Honours Project
Mbadaliga, AB (219044112)

Loads detection rules from a plain-text file and evaluates each HTTP
request against compiled regex patterns. Returns a RuleResult indicating
whether a match was found and which category triggered it.

Rule file format (one rule per line):
    RULE_ID | CATEGORY | REGEX_PATTERN
Lines starting with # are treated as comments and ignored.

Auto-reload: the engine checks the file modification time on each call
to evaluate(). If the file has changed since the last load, it reloads
automatically. This means a new rule takes effect on the next request
without restarting the WAF - which is what the D05 document describes
and what the live mode-switch demo demonstrates.
"""
import re
import os
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
            return f"MATCH - rule={self.rule_id} category={self.category}"
        return "NO_MATCH"


class RuleEngine:
    """
    Loads rules at start-up, compiles regex patterns once, then
    evaluates every incoming request string against them in order.
    Returns on the first match (fail-fast strategy).

    Rules reload automatically when the file changes on disk,
    detected via modification time on each evaluate() call.
    """

    def __init__(self, rules_file: str):
        self.rules_file = rules_file
        self.rules: List[Rule] = []
        self._last_mtime: float = 0.0
        self.load_rules()

    def load_rules(self) -> None:
        """
        Reads the rules file and compiles each valid regex.
        Invalid regex patterns are skipped with a warning.
        Records the file modification time for change detection.
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
        try:
            self._last_mtime = os.path.getmtime(self.rules_file)
        except OSError:
            self._last_mtime = 0.0
        print(f"[INFO] RuleEngine: loaded {len(self.rules)} rules "
              f"from '{self.rules_file}'")

    def _reload_if_changed(self) -> None:
        """
        Checks the rules file modification time. Reloads only if it
        changed since the last load. Called on each evaluate().
        """
        try:
            current_mtime = os.path.getmtime(self.rules_file)
        except OSError:
            return
        if current_mtime > self._last_mtime:
            print("\n[INFO] RuleEngine: rules file changed, reloading...")
            self.load_rules()

    def reload(self) -> int:
        """Forces a reload regardless of modification time."""
        self.load_rules()
        return len(self.rules)

    def get_rule_count(self) -> int:
        return len(self.rules)

    def _parse_line(self, line: str,
                    line_number: int) -> Optional[Rule]:
        parts = [p.strip() for p in line.split('|', 2)]
        if len(parts) != 3:
            print(f"[WARN] Line {line_number}: "
                  f"expected 3 fields, got {len(parts)} - skipped")
            return None
        rule_id, category, raw_pat = parts
        try:
            compiled = re.compile(raw_pat, re.IGNORECASE)
            return Rule(rule_id, category, compiled, raw_pat)
        except re.error as e:
            print(f"[WARN] Line {line_number}: "
                  f"invalid regex in {rule_id} ({e}) - skipped")
            return None

    def evaluate(self, text: str) -> RuleResult:
        """
        Checks for file changes then iterates through loaded rules.
        Returns on the first match. Returns NO_MATCH if no rule fires.
        """
        self._reload_if_changed()
        for rule in self.rules:
            if rule.matches(text):
                return RuleResult(
                    matched=True,
                    rule_id=rule.rule_id,
                    category=rule.category
                )
        return RuleResult(matched=False)
