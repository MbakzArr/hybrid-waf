"""
Hybrid WAF – D04 Prototype Demo
Mbadaliga, AB (219044112)

Demonstrates the core detection pipeline end-to-end in hybrid mode.
The ML component uses a stub (entropy-based proxy) at this stage.
The real trained model (LR + RF) will be integrated in D07.

Run from the project root:
    python demo/demo.py

Requirements: standard library only (no pip installs needed for demo).
"""
import sys
import os

# Allow imports from src/ regardless of working directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from feature_extractor import FeatureExtractor, HTTPRequest
from rule_engine import RuleEngine
from decision_engine import DecisionEngine
from dataclasses import dataclass


@dataclass
class MLStub:
    """
    Temporary ML stub for demo purposes.
    Uses normalised Shannon entropy as a proxy probability score.
    This is replaced by the trained LR/RF model in D07.

    Limitation: a very short legitimate request (e.g. 'shoes') may
    have entropy close to the threshold. The trained model trained on
    CSIC 2010 will correctly score these as benign.
    """
    probability: float


def run_demo():
    # Initialise modules
    extractor = FeatureExtractor()
    engine    = RuleEngine(os.path.join(
        os.path.dirname(__file__), '..', 'rules', 'rules.txt'))
    decision  = DecisionEngine(mode="hybrid", threshold=0.5)

    # Test payloads covering all three attack types plus evasion
    payloads = [
        # (label, body, path, method)
        ("SQLi",         "' OR 1=1 --",
         "/login", "POST"),
        ("XSS",          "<script>alert(document.cookie)</script>",
         "/search", "GET"),
        ("PathTrav",     "../../etc/passwd",
         "/files", "GET"),
        ("Clean",        "product=shoes&size=10",
         "/shop", "GET"),
        ("ObfSQLi",      "%27%20OR%20%271%27%3D%271",  # URL-encoded SQLi
         "/login", "POST"),
        ("HexSQLi",      "0x53454c454354202a2046524f4d207573657273",
         "/api", "POST"),
    ]

    header = (
        f"{'Payload':<12} {'F1':>5} {'F2':>4} {'F3':>4} "
        f"{'F4':>3} {'F5':>4} {'F6':>7}  "
        f"{'Rule':<10}  {'ML':>6}  Decision"
    )
    print("\n" + "=" * len(header))
    print("Hybrid WAF – D04 Prototype Demo")
    print("Mode: hybrid | Threshold: 0.5")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    for name, body, path, method in payloads:
        req = HTTPRequest(
            method=method, path=path,
            query_string="", headers={}, body=body
        )
        fv  = extractor.extract(req)
        rr  = engine.evaluate(req.full_text())

        # Stub ML score: normalised entropy proxy
        sim_prob = min(fv.F6_entropy / 6.0, 1.0)
        mr = MLStub(probability=sim_prob)

        dec      = decision.decide(rr, mr)
        rule_str = rr.category if rr.matched else "NO_MATCH"

        print(
            f"{name:<12} {fv.F1_length:>5} "
            f"{fv.F2_special_chars:>4} {fv.F3_sql_keywords:>4} "
            f"{fv.F4_script_flag:>3} {fv.F5_traversal:>4} "
            f"{fv.F6_entropy:>7.3f}  "
            f"{rule_str:<10}  {sim_prob:>6.3f}  {dec.action}"
        )
        if dec.is_block():
            print(f"             >> {dec.reason}")

    print("-" * len(header))
    print("\nNote: ML column uses entropy proxy (stub).")
    print("Trained LR/RF model integrated in D07 (Alpha version).\n")


if __name__ == "__main__":
    run_demo()
