"""
export_test_set_for_modsec.py
Hybrid WAF -- IT28X87 Honours Project
Mbadaliga, AB (219044112)

Exports the exact same held-out test set used by train_models.py and
evaluate_configurations.py (identical random_state=42, test_size=0.2,
stratify=y, same input row order), so the ModSecurity baseline is
measured against the same 25,627 requests as every other
configuration in this project, not a different sample.

Run on the Kali host, in the repo root, after build_dataset.py has
produced data/merged_dataset.csv:
    cd ~/HYP_Project/hybrid-waf
    python3 export_test_set_for_modsec.py

Output:
    modsec_test_set.csv (raw_text, label only)
    Copy this file to the VM with scp, e.g.:
    scp -P 2222 modsec_test_set.csv waf@localhost:~/
"""
import os
import csv

import numpy as np
from sklearn.model_selection import train_test_split

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(REPO_ROOT, "data", "merged_dataset.csv")
OUTPUT_PATH = os.path.join(REPO_ROOT, "modsec_test_set.csv")


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


def main():
    print("Loading merged dataset...")
    raw_texts, X, y = load_dataset_with_text(DATA_PATH)
    print(f"  Loaded {len(y)} rows.")

    raw_train, raw_test, X_train, X_test, y_train, y_test = train_test_split(
        raw_texts, X, y, test_size=0.2, stratify=y, random_state=42
    )
    print(f"  Test set: {len(y_test)} rows (same split used throughout "
          f"this project)")

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["raw_text", "label"])
        for text, label in zip(raw_test, y_test):
            writer.writerow([text, int(label)])

    print(f"Done. Wrote {OUTPUT_PATH}")
    print("Copy this to the VM with:")
    print(f"  scp -P 2222 {OUTPUT_PATH} waf@localhost:~/")


if __name__ == "__main__":
    main()
