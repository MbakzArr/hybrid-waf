"""
diagnose_rule_matching.py
Hybrid WAF -- IT28X87 Honours Project
Mbadaliga, AB (219044112)

evaluate_configurations.py reported rule_only catching ZERO of 7366 real
attacks, exactly zero, not just low recall. This script exists to find
out why, using real evidence from the actual merged_dataset.csv and the
real RuleEngine, rather than guessing.

It does three things:
  1. Sanity-checks the rule engine against known hardcoded attack strings
     that MUST match if the engine works at all.
  2. Prints the first 15 real attack rows from merged_dataset.csv exactly
     as stored, so we can see what the text actually looks like.
  3. Runs each of those 15 real rows through the real rule engine and
     reports match or no match.

Run from the repo root:
    cd ~/HYP_Project/hybrid-waf
    python3 diagnose_rule_matching.py
"""
import os
import sys
import csv

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
from rule_engine import RuleEngine  # noqa: E402

RULES_PATH = os.path.join(REPO_ROOT, "rules", "rules.txt")
DATA_PATH = os.path.join(REPO_ROOT, "data", "merged_dataset.csv")


def main():
    print("=== STEP 1: sanity check against known hardcoded attack strings ===")
    rule_engine = RuleEngine(RULES_PATH)

    known_attacks = [
        ("' OR '1'='1", "should match SQLi_002"),
        ("<script>alert(1)</script>", "should match XSS_001"),
        ("../../../etc/passwd", "should match PATH_001 and PATH_005"),
        ("DROP TABLE users", "should match SQLi_004"),
    ]
    for text, expectation in known_attacks:
        result = rule_engine.evaluate(text)
        print(f"  {expectation}")
        print(f"    input : {text!r}")
        print(f"    result: {result.summary()}")

    print("\n=== STEP 2 and 3: real attack rows from merged_dataset.csv ===")
    if not os.path.exists(DATA_PATH):
        print(f"  {DATA_PATH} not found. Run build_dataset.py first.")
        return

    shown = 0
    with open(DATA_PATH, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)  # header
        for row in reader:
            raw_text, *_features, label = row
            if label != "1":
                continue
            result = rule_engine.evaluate(raw_text)
            print(f"\n  raw_text (repr, exact bytes): {raw_text!r}")
            print(f"  rule engine result: {result.summary()}")
            shown += 1
            if shown >= 15:
                break

    print(f"\nShown {shown} real attack rows. If STEP 1 all matched but "
          f"STEP 2/3 mostly show NO_MATCH, the real attack text stored in "
          f"merged_dataset.csv looks different from what the rules expect, "
          f"likely still URL-encoded, HTML-escaped, or otherwise not in the "
          f"plain form the regex patterns were written for.")


if __name__ == "__main__":
    main()
