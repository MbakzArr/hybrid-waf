"""
Module 5: Decision Engine
Hybrid WAF – IT28X87 Honours Project
Mbadaliga, AB (219044112)

Receives a RuleResult from Module 3 and an MLResult from Module 4.
Applies the decision table logic and returns a Decision object.

Supports three operating modes:
    rule_only  – rule engine result only
    ml_only    – ML classifier result only
    hybrid     – both combined (the proposed system)

Decision table for hybrid mode:
    Rule=MATCH,    ML>=theta  -> BLOCK (both agree: confirmed attack)
    Rule=MATCH,    ML< theta  -> BLOCK (Case A: rule wins, conservative)
    Rule=NO_MATCH, ML>=theta  -> BLOCK (Case B: ML catches obfuscated)
    Rule=NO_MATCH, ML< theta  -> ALLOW (both agree: legitimate)
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone, timezone
from typing import Optional


@dataclass
class Decision:
    """Output from DecisionEngine.decide(). Passed to Logger."""
    action: str             # "BLOCK" or "ALLOW"
    reason: str
    rule_id: Optional[str] = None
    ml_score: float = 0.0
    mode: str = "hybrid"
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc))

    def is_block(self) -> bool:
        return self.action == "BLOCK"

    def http_status(self) -> int:
        """Returns HTTP status code for the WAF response."""
        return 403 if self.is_block() else 200


class DecisionEngine:
    """
    Stateless decision component. Mode and threshold are set at
    construction time from the configuration file.

    threshold (float): ML probability cutoff. Default 0.5.
        Raising it reduces false positives but may miss obfuscated attacks.
        Lowering it increases sensitivity but raises false positives.
    """

    VALID_MODES = {"rule_only", "ml_only", "hybrid"}

    def __init__(self, mode: str = "hybrid",
                 threshold: float = 0.5):
        if mode not in self.VALID_MODES:
            raise ValueError(
                f"Invalid mode '{mode}'. "
                f"Choose from: {self.VALID_MODES}"
            )
        self.mode = mode
        self.threshold = threshold

    def decide(self, rule_result, ml_result) -> Decision:
        """
        Main entry point. Dispatches to mode-specific logic.
        Both rule_result and ml_result must be provided in all modes
        so that the log always contains both signals.
        """
        if self.mode == "rule_only":
            return self._rule_only(rule_result, ml_result)
        elif self.mode == "ml_only":
            return self._ml_only(rule_result, ml_result)
        return self._hybrid(rule_result, ml_result)

    # ── Mode implementations ─────────────────────────────────────

    def _rule_only(self, rr, mr) -> Decision:
        if rr.matched:
            return Decision(
                action="BLOCK",
                reason=f"Rule match: {rr.rule_id} [{rr.category}]",
                rule_id=rr.rule_id,
                ml_score=mr.probability,
                mode=self.mode
            )
        return Decision(
            action="ALLOW",
            reason="No rule matched",
            ml_score=mr.probability,
            mode=self.mode
        )

    def _ml_only(self, rr, mr) -> Decision:
        if mr.probability >= self.threshold:
            return Decision(
                action="BLOCK",
                reason=(f"ML score {mr.probability:.4f} "
                        f">= threshold {self.threshold}"),
                ml_score=mr.probability,
                mode=self.mode
            )
        return Decision(
            action="ALLOW",
            reason=(f"ML score {mr.probability:.4f} "
                    f"< threshold {self.threshold}"),
            ml_score=mr.probability,
            mode=self.mode
        )

    def _hybrid(self, rr, mr) -> Decision:
        above = mr.probability >= self.threshold

        if rr.matched and above:
            return Decision(
                action="BLOCK",
                reason="Both agree: confirmed attack",
                rule_id=rr.rule_id,
                ml_score=mr.probability,
                mode=self.mode
            )

        if rr.matched and not above:
            # Case A: rule fires but ML scores benign.
            # Conservative choice: rule takes priority.
            # Example: legitimate product description containing "SELECT".
            return Decision(
                action="BLOCK",
                reason=(f"Case A – rule wins "
                        f"[rule={rr.rule_id}, "
                        f"ML={mr.probability:.4f} < {self.threshold}]"),
                rule_id=rr.rule_id,
                ml_score=mr.probability,
                mode=self.mode
            )

        if not rr.matched and above:
            # Case B: no rule fires but ML scores malicious.
            # Attacker modified payload to evade rules;
            # statistical signature (entropy, char distribution) still
            # looks like an attack. ML catches what the rule engine missed.
            return Decision(
                action="BLOCK",
                reason=(f"Case B – ML catches obfuscated payload "
                        f"[score={mr.probability:.4f} "
                        f">= {self.threshold}]"),
                ml_score=mr.probability,
                mode=self.mode
            )

        # Both agree: legitimate request
        return Decision(
            action="ALLOW",
            reason="Both agree: legitimate request",
            ml_score=mr.probability,
            mode=self.mode
        )
