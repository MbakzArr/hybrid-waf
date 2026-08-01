"""
diagnose_csic_parsing.py
Hybrid WAF -- IT28X87 Honours Project
Mbadaliga, AB (219044112)

diagnose_rule_matching.py showed the first 15 real attack rows in
merged_dataset.csv have raw_text that is just a bare number, like '175'
or '106'. Those numbers look exactly like Content-Length header values.
This script re-parses the real anomalousTrafficTest.txt with the exact
same parser build_dataset.py uses, finds every request whose full_text()
comes out as just a bare number, and prints every field of that request
(method, path, query_string, body, headers) so we can see precisely
what went wrong, rather than guess.

Run from the repo root:
    cd ~/HYP_Project/hybrid-waf
    python3 diagnose_csic_parsing.py
"""
import os
import sys
import re

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
sys.path.insert(0, REPO_ROOT)
from feature_extractor import HTTPRequest  # noqa: E402
from build_dataset import parse_csic_file  # noqa: E402

ANOMALOUS_PATH = os.path.join(REPO_ROOT, "datasets", "csic_2010", "anomalousTrafficTest.txt")


def main():
    print(f"Parsing {ANOMALOUS_PATH} with the real parser...")
    requests = parse_csic_file(ANOMALOUS_PATH, label=1)
    print(f"  Parsed {len(requests)} requests total.")

    bare_number_re = re.compile(r'^\s*\d+\s*$')
    broken = []
    for req, label in requests:
        full = req.full_text()
        if bare_number_re.match(full):
            broken.append(req)

    print(f"\nFound {len(broken)} requests out of {len(requests)} "
          f"({100*len(broken)/len(requests):.1f}%) whose full_text() is just a bare number.")

    print("\n=== First 5 broken requests, every field shown ===")
    for i, req in enumerate(broken[:5]):
        print(f"\n--- broken request {i+1} ---")
        print(f"  method       : {req.method!r}")
        print(f"  path         : {req.path!r}")
        print(f"  query_string : {req.query_string!r}")
        print(f"  body         : {req.body!r}")
        print(f"  headers      : {req.headers}")
        print(f"  full_text()  : {req.full_text()!r}")

    print("\n=== For comparison, first 3 NON-broken (normal) requests ===")
    shown = 0
    for req, label in requests:
        full = req.full_text()
        if not bare_number_re.match(full):
            print(f"\n--- normal request {shown+1} ---")
            print(f"  method       : {req.method!r}")
            print(f"  path         : {req.path!r}")
            print(f"  query_string : {req.query_string!r}")
            print(f"  body         : {req.body!r}")
            shown += 1
            if shown >= 3:
                break


if __name__ == "__main__":
    main()
