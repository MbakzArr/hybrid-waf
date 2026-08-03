"""
build_dataset.py
Hybrid WAF -- IT28X87 Honours Project
Mbadaliga, AB (219044112)

Loads CSIC 2010 and HTTPParams, parses each into HTTPRequest objects,
runs every request through the REAL FeatureExtractor from src/feature_extractor.py,
and writes one merged labeled CSV ready for training.

Run this from the repo root:
    cd ~/HYP_Project/hybrid-waf
    python3 build_dataset.py

Output:
    data/merged_dataset.csv
    columns: F1_length,F2_special_chars,F3_sql_keywords,F4_script_flag,F5_traversal,F6_entropy,label
    label: 0 = benign, 1 = attack
"""
import sys
import os
import re
import csv

# Make src/ importable so we use the REAL extractor, not a copy of it.
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
from feature_extractor import FeatureExtractor, HTTPRequest  # noqa: E402

DATASETS_DIR = os.path.join(REPO_ROOT, "datasets")
OUTPUT_PATH = os.path.join(REPO_ROOT, "data", "merged_dataset.csv")

# Matches "GET http://host/path HTTP/1.1" or "POST /path HTTP/1.1" etc.
REQUEST_LINE_RE = re.compile(r'^(GET|POST|PUT)\s+(\S+)\s+HTTP/1\.\d\s*$')
# Matches "Header-Name: value"
HEADER_LINE_RE = re.compile(r'^([A-Za-z][\w-]*):\s?(.*)$')


def parse_csic_file(path, label):
    """
    Parses one CSIC 2010 raw-text file into a list of (HTTPRequest, label).

    Confirmed structure for this file (checked against the real files
    before writing this parser, not assumed):
      - No blank lines anywhere, including between requests.
      - A line starting with GET/POST/PUT HTTP/1.1 marks a new request.
      - Lines that look like "Header: value" between the request line and
        the next request-start line are headers.
      - For POST requests, exactly one line after the last header, which
        does NOT match the header pattern, is the body. GET/PUT requests
        have no such line.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    requests = []
    i = 0
    n = len(lines)

    while i < n:
        m = REQUEST_LINE_RE.match(lines[i])
        if not m:
            # Not a request-start line and we're not inside a request.
            # Skip it. (Should not normally happen in this dataset.)
            i += 1
            continue

        method = m.group(1)
        url = m.group(2)

        # Strip scheme+host if present, e.g. http://localhost:8080/tienda1/x
        path_only = re.sub(r'^https?://[^/]+', '', url)
        if "?" in path_only:
            path_part, query_part = path_only.split("?", 1)
        else:
            path_part, query_part = path_only, ""

        i += 1
        headers = {}

        # Consume header lines until either the next request starts
        # (no body) or we hit a non-header line (start of body).
        while i < n:
            if REQUEST_LINE_RE.match(lines[i]):
                break
            hm = HEADER_LINE_RE.match(lines[i])
            if hm:
                headers[hm.group(1)] = hm.group(2)
                i += 1
            else:
                break

        # Whatever is left before the next request-start line is the body.
        body_lines = []
        while i < n and not REQUEST_LINE_RE.match(lines[i]):
            body_lines.append(lines[i])
            i += 1
        body = "".join(body_lines)

        req = HTTPRequest(
            method=method,
            path=path_part,
            query_string=query_part,
            headers=headers,
            body=body,
        )
        requests.append((req, label))

    return requests


def parse_httpparams_file(path):
    """
    Parses the HTTPParams CSV. Each row is a bare payload string, not a
    full request, so we place it directly as the query string.

    NOTE: earlier versions of this script wrapped the payload as
    "param={payload}", which guaranteed every single HTTPParams row,
    benign or attack, contained at least one '=' character from the
    wrapper itself, not from the real content. Combined with CSIC's
    benign traffic (long e-commerce query strings, several real '='
    signs), this left almost no short, zero-special-character benign
    training example, exactly the shape of a plain English word or
    phrase. The trained model then had no real basis for classifying
    that region of feature space as benign, and defaulted toward
    attack-leaning scores for ordinary text (observed directly: typing
    "login", "hello world", and random short strings into the demo
    all scored above the 0.5 threshold on the previously trained
    model). Using the payload directly, with no injected characters,
    removes that artificial signal.

    Label rule unchanged: the dataset's own 'label' column says 'norm'
    for benign rows and 'sqli' / 'xss' / 'cmdi' / 'path-traversal' for
    attack rows. 'norm' maps to 0, everything else to 1.
    """
    requests = []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            payload = row.get("payload", "") or ""
            label_raw = (row.get("label", "") or "").strip().lower()
            label = 0 if label_raw == "norm" else 1

            req = HTTPRequest(
                method="GET",
                path="/",
                query_string=payload,
                headers={},
                body="",
            )
            requests.append((req, label))
    return requests


def main():
    extractor = FeatureExtractor()
    all_requests = []

    print("Parsing CSIC 2010...")
    csic_normal_train = parse_csic_file(
        os.path.join(DATASETS_DIR, "csic_2010", "normalTrafficTraining.txt"), label=0
    )
    csic_normal_test = parse_csic_file(
        os.path.join(DATASETS_DIR, "csic_2010", "normalTrafficTest.txt"), label=0
    )
    csic_anomalous = parse_csic_file(
        os.path.join(DATASETS_DIR, "csic_2010", "anomalousTrafficTest.txt"), label=1
    )
    print(f"  normalTrafficTraining.txt : {len(csic_normal_train)} requests (label 0)")
    print(f"  normalTrafficTest.txt     : {len(csic_normal_test)} requests (label 0)")
    print(f"  anomalousTrafficTest.txt  : {len(csic_anomalous)} requests (label 1)")

    all_requests += csic_normal_train + csic_normal_test + csic_anomalous
    csic_total = len(all_requests)
    print(f"  CSIC 2010 subtotal: {csic_total}")

    print("Parsing HTTPParams...")
    httpparams = parse_httpparams_file(
        os.path.join(DATASETS_DIR, "httpparams", "payload_full.csv")
    )
    print(f"  HTTPParams subtotal: {len(httpparams)}")
    all_requests += httpparams

    total = len(all_requests)
    benign = sum(1 for _, lbl in all_requests if lbl == 0)
    attack = sum(1 for _, lbl in all_requests if lbl == 1)
    print(f"Combined total: {total}  (benign: {benign}, attack: {attack})")

    print("Extracting features with the real FeatureExtractor...")
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow([
            "raw_text",
            "F1_length", "F2_special_chars", "F3_sql_keywords",
            "F4_script_flag", "F5_traversal", "F6_entropy", "label",
        ])
        for idx, (req, label) in enumerate(all_requests):
            fv = extractor.extract(req)
            # req.full_text() is the exact same string the extractor
            # analysed internally. Saving it here means the rule engine
            # can later be run on the identical text, so rule-only,
            # ML-only and hybrid evaluation all see the same input.
            writer.writerow([req.full_text()] + fv.to_list() + [label])
            if (idx + 1) % 20000 == 0:
                print(f"  processed {idx + 1}/{total}")

    print(f"Done. Merged dataset written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
