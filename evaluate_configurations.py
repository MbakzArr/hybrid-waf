"""
evaluate_configurations.py
Hybrid WAF -- IT28X87 Honours Project
Mbadaliga, AB (219044112)

Extends the pipeline evaluation to two more configurations: rule_only
and hybrid, using the REAL RuleEngine and DecisionEngine from src/,
and the trained Pipeline 2 (Random Forest) model as the ML signal.

ml_only is NOT recomputed here. Pipeline2_RandomForest's row in
evaluation/results/pipeline_metrics.csv already IS the ml_only
configuration: DecisionEngine._ml_only() blocks when
mr.probability >= threshold, which is exactly the same >= 0.5 check
train_models.py already applied to Pipeline 2's predict_proba output.
Recomputing it here would just reproduce the same numbers a second
time, so this script reads that row straight from the file instead.

Random Forest (Pipeline 2) is used as "the" ML signal for rule_only
and hybrid scoring because it was the strongest performer in the
pipeline comparison. This is a stated choice, not a hidden default,
if hybrid should be measured against Pipeline 1 instead, that is a
one-line change (see load the RF model section below).

Run from the repo root, after train_models.py has produced
models/pipeline2_random_forest.pkl and evaluation/results/pipeline_metrics.csv:
    cd ~/HYP_Project/hybrid-waf
    python3 evaluate_configurations.py

Output:
    evaluation/results/four_configuration_comparison.csv
    (rule_only, ml_only, hybrid rows populated; modsecurity_crs_v4
    left blank until that baseline is stood up separately)
"""
import os
import sys
import csv
import pickle

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score, recall_score, f1_score, confusion_matrix, accuracy_score,
)

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
sys.path.insert(0, os.path.join(REPO_ROOT, "pipelines"))
from rule_engine import RuleEngine  # noqa: E402
from decision_engine import DecisionEngine  # noqa: E402
from random_forest import RandomForestModel  # noqa: E402

DATA_PATH = os.path.join(REPO_ROOT, "data", "merged_dataset.csv")
RULES_PATH = os.path.join(REPO_ROOT, "rules", "rules.txt")
RF_MODEL_PATH = os.path.join(REPO_ROOT, "models", "pipeline2_random_forest.pkl")
EXISTING_METRICS_PATH = os.path.join(REPO_ROOT, "evaluation", "results", "pipeline_metrics.csv")
OUTPUT_PATH = os.path.join(REPO_ROOT, "evaluation", "results", "four_configuration_comparison.csv")


class MLResult:
    """
    Minimal stand-in so DecisionEngine.decide() has the .probability
    attribute it expects. There is no MLResult class in the repo,
    decide() only ever reads .probability off whatever it is given, so
    this is a container for a number we already have from the trained
    model, not a new WAF component.
    """
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


def evaluate(name, y_true, y_pred):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    print(f"\n[{name}] TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"[{name}] Accuracy={acc:.4f} Precision={prec:.4f} "
          f"Recall={rec:.4f} F1={f1:.4f} FPR={fpr:.4f}")
    return {
        "pipeline": name, "accuracy": acc, "precision": prec,
        "recall": rec, "f1": f1, "fpr": fpr,
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def main():
    print("Loading merged dataset (with raw text)...")
    raw_texts, X, y = load_dataset_with_text(DATA_PATH)
    print(f"  Loaded {len(y)} rows.")

    # Identical split to train_models.py: same random_state, same
    # test_size, same stratify target, same input row order, so this
    # reproduces the exact same test set without needing to save indices.
    (raw_train, raw_test,
     X_train, X_test,
     y_train, y_test) = train_test_split(
        raw_texts, X, y, test_size=0.2, stratify=y, random_state=42
    )
    print(f"  Test set: {len(y_test)} rows (same split train_models.py used)")

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

    decision_rule_only = DecisionEngine(mode="rule_only", threshold=0.5)
    decision_hybrid = DecisionEngine(mode="hybrid", threshold=0.5)

    preds_rule_only = []
    preds_hybrid = []
    case_b_count = 0  # rule missed it, ML caught it, this project's core contribution

    print("Scoring test set through RuleEngine + DecisionEngine...")
    n = len(y_test)
    for i in range(n):
        text = raw_test[i]
        x = X_test[i]

        rule_result = rule_engine.evaluate(text)
        ml_probability = rf_model.predict_proba(x)
        ml_result = MLResult(probability=ml_probability)

        d_rule = decision_rule_only.decide(rule_result, ml_result)
        d_hybrid = decision_hybrid.decide(rule_result, ml_result)

        preds_rule_only.append(1 if d_rule.is_block() else 0)
        preds_hybrid.append(1 if d_hybrid.is_block() else 0)

        if "Case B" in d_hybrid.reason:
            case_b_count += 1

        if (i + 1) % 5000 == 0:
            print(f"  scored {i + 1}/{n}")

    print(f"\nCase B fired (rule missed it, ML caught it) on {case_b_count} "
          f"of {n} test requests ({100 * case_b_count / n:.2f}%).")

    all_metrics = []
    all_metrics.append(evaluate("rule_only", y_test, preds_rule_only))

    ml_only_row = None
    if os.path.exists(EXISTING_METRICS_PATH):
        with open(EXISTING_METRICS_PATH, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row["pipeline"] == "Pipeline2_RandomForest":
                    ml_only_row = {
                        "pipeline": "ml_only",
                        "accuracy": float(row["accuracy"]),
                        "precision": float(row["precision"]),
                        "recall": float(row["recall"]),
                        "f1": float(row["f1"]),
                        "fpr": float(row["fpr"]),
                        "tp": int(row["tp"]), "fp": int(row["fp"]),
                        "tn": int(row["tn"]), "fn": int(row["fn"]),
                    }
    if ml_only_row is None:
        print(f"WARNING: could not find Pipeline2_RandomForest row in "
              f"{EXISTING_METRICS_PATH}. Run train_models.py first. "
              "ml_only row will be left blank.")
        ml_only_row = {"pipeline": "ml_only", "accuracy": "", "precision": "",
                        "recall": "", "f1": "", "fpr": "", "tp": "", "fp": "",
                        "tn": "", "fn": ""}
    print(f"\n[ml_only] (reused from Pipeline2_RandomForest, not recomputed) "
          f"Precision={ml_only_row['precision']} Recall={ml_only_row['recall']} "
          f"F1={ml_only_row['f1']} FPR={ml_only_row['fpr']}")
    all_metrics.append(ml_only_row)

    all_metrics.append(evaluate("hybrid", y_test, preds_hybrid))

    all_metrics.append({
        "pipeline": "modsecurity_crs_v4", "accuracy": "", "precision": "",
        "recall": "", "f1": "", "fpr": "", "tp": "", "fp": "", "tn": "", "fn": "",
    })

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "pipeline", "accuracy", "precision", "recall", "f1", "fpr",
            "tp", "fp", "tn", "fn",
        ])
        writer.writeheader()
        for row in all_metrics:
            writer.writerow(row)

    print(f"\nDone. Four-configuration comparison written to {OUTPUT_PATH}")
    print("modsecurity_crs_v4 row left blank, that baseline still needs to be "
          "stood up separately on the VM.")


if __name__ == "__main__":
    main()
