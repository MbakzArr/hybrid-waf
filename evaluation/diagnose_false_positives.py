#!/usr/bin/env python3
"""
diagnose_false_positives.py - why does the model block normal short requests?

Looks at the training data (data/merged_dataset.csv) and, for a few example
requests, counts how many benign and attack training rows sit in the same
region of feature space. Read only. Nothing is retrained or changed.

    python evaluation/diagnose_false_positives.py
"""
import csv
import os
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from feature_extractor import FeatureExtractor, HTTPRequest

DATA = os.path.join(ROOT, "data", "merged_dataset.csv")

# (label, path, query). Same shape the proxy builds: path + " " + query + " " + body
EXAMPLES = [
    ("normal, bare root",               "/", ""),
    ("normal, two params",              "/products", "sort=price&order=asc"),
    ("normal, two params",              "/cart", "item=17&qty=2"),
    ("normal, hyphen in name",          "/user", "name=Anna-Marie"),
    ("normal, apostrophe in name",      "/search", "name=O'Brien"),
    ("normal, plain word",              "/login.php", ""),
    ("attack, CASE WHEN (Case B demo)", "/", "id=CASE WHEN 1=1 THEN 1 ELSE 0 END"),
    ("attack, classic SQLi",            "/item", "id=1' OR '1'='1"),
]


def load():
    rows, labels, texts = [], [], []
    with open(DATA, newline="") as f:
        r = csv.reader(f)
        next(r)
        for line in r:
            texts.append(line[0])
            rows.append([float(x) for x in line[1:7]])
            labels.append(int(line[7]))
    return np.array(rows), np.array(labels), texts


def main():
    if not os.path.exists(DATA):
        sys.exit(f"{DATA} not found. Run build_dataset.py first.")
    X, y, texts = load()
    n_b, n_a = int((y == 0).sum()), int((y == 1).sum())
    print(f"Training data: {len(y)} rows ({n_b} benign, {n_a} attack)\n")

    print("1. Short requests (F1 <= 40 characters)")
    short = X[:, 0] <= 40
    print(f"   benign {int((short & (y == 0)).sum())} of {n_b}"
          f"   attack {int((short & (y == 1)).sum())} of {n_a}")

    amp = np.array(["&" in t for t in texts])
    print("\n2. Rows that contain '&' (more than one parameter)")
    print(f"   benign {int((amp & (y == 0)).sum())} of {n_b}"
          f"   attack {int((amp & (y == 1)).sum())} of {n_a}")

    empty_q = np.array([len(t.strip()) <= 3 for t in texts])
    print("\n3. Rows with almost no content (3 characters or fewer after trimming)")
    print(f"   benign {int((empty_q & (y == 0)).sum())}   attack {int((empty_q & (y == 1)).sum())}")

    print("\n4. Neighbourhood of example requests")
    print("   Same F2, F3, F4, F5 and F1 within 6 characters of the example.")
    print(f"   {'example':<34}{'F1':>4}{'F2':>4}{'F3':>4}{'F6':>7}{'benign':>8}{'attack':>8}{'attack%':>9}")
    fe = FeatureExtractor()
    for name, path, qs in EXAMPLES:
        v = fe.extract(HTTPRequest("GET", path, qs, {}, "", "0.0.0.0"))
        m = ((X[:, 1] == v.F2_special_chars) & (X[:, 2] == v.F3_sql_keywords) &
             (X[:, 3] == v.F4_script_flag) & (X[:, 4] == v.F5_traversal) &
             (np.abs(X[:, 0] - v.F1_length) <= 6))
        b, a = int((m & (y == 0)).sum()), int((m & (y == 1)).sum())
        pct = f"{100 * a / (a + b):.0f}%" if a + b else "n/a"
        print(f"   {name:<34}{v.F1_length:>4}{v.F2_special_chars:>4}{v.F3_sql_keywords:>4}"
              f"{v.F6_entropy:>7.2f}{b:>8}{a:>8}{pct:>9}")


if __name__ == "__main__":
    main()
