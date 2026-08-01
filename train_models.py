"""
train_models.py
Hybrid WAF -- IT28X87 Honours Project
Mbadaliga, AB (219044112)

Loads data/merged_dataset.csv, trains all three classifier pipelines,
evaluates each on a held-out test split, and writes:
  - evaluation/results/pipeline_metrics.csv  (precision/recall/F1/FPR per pipeline)
  - models/pipeline1_logreg.pkl
  - models/pipeline2_random_forest.pkl
  - models/pipeline3_sklearn_logreg.pkl

Run this from the repo root, after build_dataset.py has produced
data/merged_dataset.csv:
    cd ~/HYP_Project/hybrid-waf
    python3 train_models.py

DESIGN DECISIONS MADE HERE (state these in the paper, they are yours
to own, not hidden defaults):

1. Train/test split: 80/20, stratified by label, random_state=42.
   Stratified so the attack/benign ratio is preserved in both splits.
   Fixed random_state so the split is reproducible if you rerun this.
   This is standard practice, not sourced from a specific paper.

2. Feature scaling for Pipeline 1 (custom Logistic Regression):
   Pipeline 1's fit() takes raw X with no internal scaling, unlike
   Pipeline 2 (Random Forest) which scales internally. The six features
   sit on very different scales (F1_length can be in the hundreds,
   F6_entropy sits around 0-6), which slows and distorts gradient
   descent convergence. A StandardScaler is fit on the TRAINING split
   only (never on test, to avoid leakage) and applied to both LR
   pipelines (1 and 3). Random Forest (2) is left on raw features
   since it scales internally on its own.

3. Pipeline 3 (sklearn LogisticRegression) is defined inline here,
   not as its own pipelines/ file, since D06 described it as a small
   validation model whose only purpose is checking Pipeline 1's
   correctness, not a separate architectural component. max_iter is
   raised to 1000 (sklearn's default is 100) purely to let it converge
   without a warning; this is not a tuning choice, it is avoiding an
   under-trained baseline.
"""
import os
import sys
import csv
import pickle

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression as SklearnLogisticRegression
from sklearn.metrics import (
    precision_score, recall_score, f1_score, confusion_matrix, accuracy_score,
)

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(REPO_ROOT, "pipelines"))
from logistic_regression import LogisticRegressionModel  # noqa: E402
from random_forest import RandomForestModel  # noqa: E402

DATA_PATH = os.path.join(REPO_ROOT, "data", "merged_dataset.csv")
MODELS_DIR = os.path.join(REPO_ROOT, "models")
RESULTS_DIR = os.path.join(REPO_ROOT, "evaluation", "results")
RESULTS_PATH = os.path.join(RESULTS_DIR, "pipeline_metrics.csv")


def load_dataset(path):
    rows, labels = [], []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)  # header
        for row in reader:
            # row layout: raw_text, F1..F6, label
            _raw_text, *features, label = row
            rows.append([float(v) for v in features])
            labels.append(int(label))
    X = np.array(rows, dtype=np.float64)
    y = np.array(labels, dtype=np.int64)
    return X, y


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
    print("Loading merged dataset...")
    X, y = load_dataset(DATA_PATH)
    print(f"  Loaded {len(y)} rows. Benign: {(y == 0).sum()}  Attack: {(y == 1).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    print(f"  Train: {len(y_train)}  Test: {len(y_test)}")

    shared_scaler = StandardScaler()
    X_train_scaled = shared_scaler.fit_transform(X_train)
    X_test_scaled = shared_scaler.transform(X_test)

    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    all_metrics = []

    # ---------------- Pipeline 1: custom Logistic Regression ----------------
    # n_epochs raised from the class default (1000) to 5000. On the first
    # run, loss was still dropping meaningfully at epoch 900 (0.4637 to
    # 0.4605), meaning training had not settled yet. This gives it more
    # epochs to converge before we judge it, learning_rate is left at the
    # class default (0.01), no other hyperparameters are touched.
    print("\n=== Training Pipeline 1: custom Logistic Regression ===")
    model1 = LogisticRegressionModel(n_epochs=5000)
    model1.fit(X_train_scaled, y_train)
    print("  Scoring test set...")
    preds1 = []
    for i, row in enumerate(X_test_scaled):
        preds1.append(1 if model1.predict_proba(row) >= 0.5 else 0)
        if (i + 1) % 5000 == 0:
            print(f"    scored {i + 1}/{len(X_test_scaled)}")
    all_metrics.append(evaluate("Pipeline1_CustomLR", y_test, preds1))
    model1.save(os.path.join(MODELS_DIR, "pipeline1_logreg.pkl"))

    # ---------------- Pipeline 2: Random Forest ----------------
    # n_jobs=1 is passed at construction below via RandomForestModel's
    # own default (n_jobs=-1 inside random_forest.py). scikit-learn's
    # RandomForestClassifier is not always bit-for-bit reproducible
    # across runs when n_jobs=-1, because parallel tree-building can sum
    # floating point splits in a different thread order each run, even
    # with a fixed random_state. random_state controls the random number
    # stream, not thread scheduling. Forcing single-threaded training
    # here trades some speed for exact reproducibility, so the numbers
    # in the paper do not shift if this script is rerun later.
    print("\n=== Training Pipeline 2: Random Forest ===")
    model2 = RandomForestModel()
    model2.model.n_jobs = 1
    model2.fit(X_train, y_train)  # raw features, scales internally
    print("  Scoring test set...")
    preds2 = []
    for i, row in enumerate(X_test):
        preds2.append(1 if model2.predict_proba(row) >= 0.5 else 0)
        if (i + 1) % 5000 == 0:
            print(f"    scored {i + 1}/{len(X_test)}")
    all_metrics.append(evaluate("Pipeline2_RandomForest", y_test, preds2))
    model2.save(os.path.join(MODELS_DIR, "pipeline2_random_forest.pkl"))

    # ---------------- Pipeline 3: sklearn Logistic Regression (validation only) ----------------
    print("\n=== Training Pipeline 3: sklearn Logistic Regression (validates Pipeline 1) ===")
    model3 = SklearnLogisticRegression(max_iter=1000)
    model3.fit(X_train_scaled, y_train)
    preds3 = model3.predict(X_test_scaled)
    all_metrics.append(evaluate("Pipeline3_SklearnLR", y_test, preds3))
    with open(os.path.join(MODELS_DIR, "pipeline3_sklearn_logreg.pkl"), "wb") as f:
        pickle.dump({"model": model3, "scaler": shared_scaler}, f)

    # ---------------- Write results table ----------------
    with open(RESULTS_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "pipeline", "accuracy", "precision", "recall", "f1", "fpr",
            "tp", "fp", "tn", "fn",
        ])
        writer.writeheader()
        for row in all_metrics:
            writer.writerow(row)

    print(f"\nDone. Metrics written to {RESULTS_PATH}")
    print(f"Models saved to {MODELS_DIR}/")


if __name__ == "__main__":
    main()
