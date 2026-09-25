"""
dataset_attack_breakdown.py
Hybrid WAF -- IT28X87 Honours Project
Mbadaliga, AB (219044112)

Answers the D07 moderator question: what contributes to the attacks
in the merged dataset, broken down by category, not just benign/attack.

Two different methods are used, deliberately kept separate and labelled,
because they are not the same kind of evidence:

  1. HTTPParams: the raw source CSV carries its own attack-type label
     (sqli, xss, cmdi, path-traversal). This is real ground truth from
     the dataset itself.
  2. CSIC 2010's anomalousTrafficTest.txt: CSIC 2010 was built as a
     binary normal/anomalous dataset only, it carries no attack subtype
     at all. There is no ground truth to pull. Instead, each attack
     row's own text is run through the real RuleEngine (the same 45
     rules used in production), and categorised by whichever rule
     fires. Rows that fire no rule are reported honestly as
     uncategorised, not guessed at, since that is real information,
     it is the same population Case B depends on.

Run from the repo root:
    python3 dataset_attack_breakdown.py
"""
import sys
import os
import csv
from collections import Counter

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
sys.path.insert(0, REPO_ROOT)

from rule_engine import RuleEngine
from build_dataset import parse_csic_file, DATASETS_DIR

RULES_FILE = os.path.join(REPO_ROOT, "rules", "rules.txt")


def httpparams_breakdown():
    """Ground truth breakdown from HTTPParams' own attack_type column."""
    path = os.path.join(DATASETS_DIR, "httpparams", "payload_full.csv")
    counts = Counter()
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            attack_type = (row.get("attack_type", "") or "").strip().lower()
            if attack_type and attack_type != "norm":
                counts[attack_type] += 1
    return counts


def csic_breakdown(rule_engine):
    """
    Rule-engine-based categorisation of CSIC 2010's attack rows, since
    CSIC 2010 itself carries no attack subtype. This is an inferred
    breakdown, not ground truth, and is reported as such.
    """
    path = os.path.join(DATASETS_DIR, "csic_2010", "anomalousTrafficTest.txt")
    attack_requests = parse_csic_file(path, label=1)

    counts = Counter()
    for req, _ in attack_requests:
        result = rule_engine.evaluate(req.full_text())
        if result.matched:
            counts[result.category] += 1
        else:
            counts["uncategorised (no rule matched)"] += 1
    return counts, len(attack_requests)


def main():
    print("=" * 62)
    print("Dataset Attack Contribution Breakdown")
    print("=" * 62)

    print("\n--- HTTPParams (ground truth from dataset's own attack_type column) ---")
    hp_counts = httpparams_breakdown()
    hp_total = sum(hp_counts.values())
    for category, count in hp_counts.most_common():
        pct = 100 * count / hp_total
        print(f"  {category:20s} {count:6d}  ({pct:5.1f}%)")
    print(f"  {'TOTAL':20s} {hp_total:6d}")

    print("\n--- CSIC 2010 anomalousTrafficTest.txt ---")
    print("--- (inferred via RuleEngine, CSIC 2010 has no ground truth subtype) ---")
    rule_engine = RuleEngine(RULES_FILE)
    csic_counts, csic_total = csic_breakdown(rule_engine)
    for category, count in csic_counts.most_common():
        pct = 100 * count / csic_total
        print(f"  {category:30s} {count:6d}  ({pct:5.1f}%)")
    print(f"  {'TOTAL':30s} {csic_total:6d}")

    print("\nDone.")


if __name__ == "__main__":
    main()
