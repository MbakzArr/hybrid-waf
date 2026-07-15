#!/usr/bin/env python3
"""
D05 Interactive Demo - Hybrid WAF
IT28X87 Honours Project | Mbadaliga, AB (219044112)

Run from the project root:
    python3 demo/interactive_demo.py

Type any payload at the prompt and see it processed through the full
pipeline in real time: Feature Extraction -> Rule Engine -> ML Classifier
-> Decision Engine. Each result is printed with the reasoning.

Commands:
    mode <rule_only|ml_only|hybrid>   change operating mode
    threshold <0.0-1.0>               change ML decision threshold
    rules                             show all loaded rules
    quit                              exit

Note on ML: uses an entropy-based stub until the trained LR model
is integrated at D07. Scores above 0.5 indicate likely malicious.
"""
import sys
import os
import math

# ── Path setup (run from project root or demo/ folder) ──────────
_here = os.path.dirname(os.path.abspath(__file__))
_root = _here if os.path.isdir(os.path.join(_here, 'src')) \
        else os.path.dirname(_here)
sys.path.insert(0, os.path.join(_root, 'src'))

from feature_extractor import FeatureExtractor, HTTPRequest, FeatureVector
from rule_engine import RuleEngine, RuleResult
from decision_engine import DecisionEngine, Decision
from dataclasses import dataclass


# ── ML stub ──────────────────────────────────────────────────────
@dataclass
class MLResult:
    """
    Stub ML result using normalised Shannon entropy as the score.
    Replaced by the trained LogisticRegressionModel at D07.
    Justification: entropy is a legitimate signal - obfuscated payloads
    tend to have higher character diversity than benign requests.
    """
    probability: float
    pipeline: str = "entropy_stub"


def ml_stub(fv: FeatureVector, threshold: float = 0.5) -> MLResult:
    """
    Score based on a weighted combination of features, not just entropy.
    This gives cleaner Case A / Case B separation on demo payloads and
    avoids the false-positive on short clean strings that pure entropy
    produced in earlier testing.

    Weights are set manually to approximate what the trained LR model
    learned: special chars and SQL keywords carry the most signal.
    """
    score = 0.0
    score += min(fv.F2_special_chars * 0.12, 0.35)   # special chars
    score += min(fv.F3_sql_keywords  * 0.18, 0.45)   # SQL keywords
    score += fv.F4_script_flag       * 0.30           # script tag
    score += min(fv.F5_traversal     * 0.25, 0.50)   # traversal
    score += min(fv.F6_entropy       * 0.04, 0.20)   # entropy
    score = min(score, 0.99)
    return MLResult(probability=round(score, 4))


# ── Terminal colours ─────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

RULES_FILE = os.path.join(_root, 'rules', 'rules.txt')


def banner(mode: str, threshold: float, rule_count: int):
    print(f"""
{BOLD}{CYAN}{'='*62}
  Hybrid WAF  -  D05 Interactive Demo
  IT28X87 Honours Project  |  Mbadaliga, AB (219044112)
{'='*62}{RESET}
  Mode: {YELLOW}{mode}{RESET}  |  Threshold: {YELLOW}{threshold}{RESET}  |  Rules loaded: {YELLOW}{rule_count}{RESET}

  Commands:
    {YELLOW}mode <rule_only|ml_only|hybrid>{RESET}
    {YELLOW}threshold <0.0-1.0>{RESET}
    {YELLOW}rules{RESET}
    {YELLOW}quit{RESET}
{'='*62}
""")


def print_result(fv: FeatureVector, rr: RuleResult,
                 ml: MLResult, dec: Decision, threshold: float):

    print(f"\n  {CYAN}-- Feature Extraction (M2) --{RESET}")
    print(f"    F1 length        : {fv.F1_length}")
    print(f"    F2 special chars : {fv.F2_special_chars}")
    print(f"    F3 SQL keywords  : {fv.F3_sql_keywords}")
    print(f"    F4 script flag   : {fv.F4_script_flag}")
    print(f"    F5 traversal     : {fv.F5_traversal}")
    print(f"    F6 entropy       : {fv.F6_entropy:.3f}")

    print(f"\n  {CYAN}-- Rule Engine (M3) --{RESET}")
    if rr.matched:
        print(f"    {RED}MATCH{RESET} - rule {rr.rule_id} [{rr.category}]")
    else:
        print(f"    {GREEN}NO_MATCH{RESET} - no rule fired")

    print(f"\n  {CYAN}-- ML Classifier (M4) --{RESET}")
    col = RED if ml.probability >= threshold else GREEN
    print(f"    Score : {col}{ml.probability:.4f}{RESET}  "
          f"(threshold = {threshold})  [{ml.pipeline}]")

    print(f"\n  {CYAN}-- Decision Engine (M5) --{RESET}")
    if dec.is_block():
        print(f"    {RED}{BOLD}>>> BLOCK <<< {RESET}")
    else:
        print(f"    {GREEN}{BOLD}>>> ALLOW <<< {RESET}")
    print(f"    Reason : {dec.reason}")
    print(f"    Mode   : {dec.mode}\n")


def main():
    if not os.path.exists(RULES_FILE):
        print(f"[ERROR] Rules file not found: {RULES_FILE}")
        print("Run from the project root: python3 demo/interactive_demo.py")
        sys.exit(1)

    extractor = FeatureExtractor()
    rule_engine = RuleEngine(RULES_FILE)
    mode = "hybrid"
    threshold = 0.5
    decision_engine = DecisionEngine(mode=mode, threshold=threshold)

    banner(mode, threshold, len(rule_engine.rules))

    while True:
        try:
            payload = input(f"{BOLD}payload>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not payload:
            continue

        # ── Commands ────────────────────────────────────────────
        if payload.lower() == "quit":
            print("Exiting.")
            break

        if payload.lower() == "rules":
            print(f"\n  {CYAN}Loaded rules ({len(rule_engine.rules)}):{RESET}")
            for r in rule_engine.rules:
                print(f"  {r.rule_id:6s} | {r.category:5s} | {r.raw_pattern}")
            print()
            continue

        if payload.lower().startswith("mode "):
            new_mode = payload.split(None, 1)[1].strip()
            try:
                decision_engine = DecisionEngine(
                    mode=new_mode, threshold=threshold
                )
                mode = new_mode
                print(f"\n  Mode changed to: {YELLOW}{mode}{RESET}\n")
            except ValueError as e:
                print(f"\n  {RED}{e}{RESET}\n")
            continue

        if payload.lower().startswith("threshold "):
            try:
                new_t = float(payload.split(None, 1)[1])
                if not 0.0 <= new_t <= 1.0:
                    raise ValueError("Must be between 0.0 and 1.0")
                threshold = new_t
                decision_engine = DecisionEngine(
                    mode=mode, threshold=threshold
                )
                print(f"\n  Threshold changed to: {YELLOW}{threshold}{RESET}\n")
            except ValueError as e:
                print(f"\n  {RED}{e}{RESET}\n")
            continue

        # ── Process payload ──────────────────────────────────────
        req = HTTPRequest(
            method="POST",
            path="/login",
            query_string=payload,
            headers={},
            body="",
            source_ip="127.0.0.1"
        )

        fv  = extractor.extract(req)
        rr  = rule_engine.evaluate(req.full_text())
        ml  = ml_stub(fv, threshold)
        dec = decision_engine.decide(rr, ml)

        print_result(fv, rr, ml, dec, threshold)


if __name__ == "__main__":
    main()
