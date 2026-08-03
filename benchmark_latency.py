"""
benchmark_latency.py
Hybrid WAF -- IT28X87 Honours Project
Mbadaliga, AB (219044112)

Systematic per-stage latency benchmark, replacing the ad hoc single
manually-typed-request observations reported earlier with real
statistics (mean, median, 95th percentile) over the full held-out test
set, using the real RuleEngine, the real trained Random Forest, and
the real DecisionEngine in hybrid mode.

Uses the IDENTICAL train/test split as train_models.py and
evaluate_configurations.py (same random_state=42, same test_size,
same input order), so this benchmark runs on the exact same 25,627
test requests already used for every other table in the paper.

Run from the repo root, after build_dataset.py and train_models.py
have produced data/merged_dataset.csv and
models/pipeline2_random_forest.pkl:
    cd ~/HYP_Project/hybrid-waf
    python3 benchmark_latency.py

Output:
    evaluation/results/latency_benchmark.csv
    (mean, median, 95th percentile in milliseconds, for the rule
    engine alone, the classifier alone, and the full pipeline,
    entrance to decision, matching Table 2 in the paper)
"""
import os
import sys
import csv
import time
import pickle
import statistics

import numpy as np
from sklearn.model_selection import train_test_split

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
sys.path.insert(0, os.path.join(REPO_ROOT, "pipelines"))
from feature_extractor import FeatureExtractor, HTTPRequest  # noqa: E402
from rule_engine import RuleEngine  # noqa: E402
from decision_engine import DecisionEngine  # noqa: E402
from random_forest import RandomForestModel  # noqa: E402

DATA_PATH = os.path.join(REPO_ROOT, "data", "merged_dataset.csv")
RULES_PATH = os.path.join(REPO_ROOT, "rules", "rules.txt")
RF_MODEL_PATH = os.path.join(REPO_ROOT, "models", "pipeline2_random_forest.pkl")
OUTPUT_PATH = os.path.join(REPO_ROOT, "evaluation", "results", "latency_benchmark.csv")


class MLResult:
    def __init__(self, probability):
        self.probability = probability


def load_dataset_with_text(path):
    raw_texts, rows, labels = [], [], []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)  # header
        for row in reader:
            raw_text, *features, label = row
            raw_texts.append(raw_text)
            rows.append([float(v) for v in features])
            labels.append(int(label))
    X = np.array(rows, dtype=np.float64)
    y = np.array(labels, dtype=np.int64)
    return raw_texts, X, y


def percentile(data, pct):
    data_sorted = sorted(data)
    k = (len(data_sorted) - 1) * (pct / 100)
    f = int(k)
    c = min(f + 1, len(data_sorted) - 1)
    if f == c:
        return data_sorted[f]
    return data_sorted[f] + (data_sorted[c] - data_sorted[f]) * (k - f)


def main():
    print("Loading merged dataset (with raw text)...")
    raw_texts, X, y = load_dataset_with_text(DATA_PATH)
    print(f"  Loaded {len(y)} rows.")

    # Identical split to every other evaluation script in this repo.
    raw_train, raw_test, X_train, X_test, y_train, y_test = train_test_split(
        raw_texts, X, y, test_size=0.2, stratify=y, random_state=42
    )
    n = len(y_test)
    print(f"  Benchmarking on the same {n}-row test set used throughout "
          f"this project.")

    print(f"Loading rule engine from {RULES_PATH}...")
    rule_engine = RuleEngine(RULES_PATH)
    print(f"  {rule_engine.get_rule_count()} rules loaded")

    print(f"Loading trained Random Forest from {RF_MODEL_PATH}...")
    with open(RF_MODEL_PATH, "rb") as f:
        rf_data = pickle.load(f)
    rf_model = RandomForestModel()
    rf_model.model = rf_data["model"]
    rf_model.scaler = rf_data["scaler"]
    rf_model.trained = rf_data["trained"]

    decision_engine = DecisionEngine(mode="hybrid", threshold=0.5)

    rule_times, ml_times, total_times = [], [], []

    print("Timing every request in the test set, entrance to decision...")
    for i in range(n):
        text = raw_test[i]
        x = X_test[i]

        t_start = time.perf_counter()

        t0 = time.perf_counter()
        rule_result = rule_engine.evaluate(text)
        t_rule = time.perf_counter() - t0

        t0 = time.perf_counter()
        proba = rf_model.predict_proba(x)
        t_ml = time.perf_counter() - t0
        ml_result = MLResult(probability=proba)

        decision_engine.decide(rule_result, ml_result)

        t_total = time.perf_counter() - t_start

        rule_times.append(t_rule * 1000)
        ml_times.append(t_ml * 1000)
        total_times.append(t_total * 1000)

        if (i + 1) % 5000 == 0:
            print(f"  timed {i + 1}/{n}")

    def stats_row(name, values):
        return {
            "stage": name,
            "mean_ms": round(statistics.mean(values), 4),
            "median_ms": round(statistics.median(values), 4),
            "p95_ms": round(percentile(values, 95), 4),
            "min_ms": round(min(values), 4),
            "max_ms": round(max(values), 4),
        }

    results = [
        stats_row("Rule engine (M3)", rule_times),
        stats_row("Classifier (M4)", ml_times),
        stats_row("Full pipeline (M2-M5)", total_times),
    ]

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "stage", "mean_ms", "median_ms", "p95_ms", "min_ms", "max_ms",
        ])
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print(f"\n{'Stage':<24} {'Mean':>8} {'Median':>8} {'95th pct':>10} "
          f"{'Min':>8} {'Max':>8}")
    for row in results:
        print(f"{row['stage']:<24} {row['mean_ms']:>8.3f} "
              f"{row['median_ms']:>8.3f} {row['p95_ms']:>10.3f} "
              f"{row['min_ms']:>8.3f} {row['max_ms']:>8.3f}")

    print(f"\nDone. Latency benchmark written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
