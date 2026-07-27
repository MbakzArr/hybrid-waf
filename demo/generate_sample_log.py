#!/usr/bin/env python3
"""
Generate sample detection log for dashboard demo (enhanced).
Run ONCE before starting the dashboard:
    python3 demo/generate_sample_log.py

Creates logs/detection_log.csv with realistic entries. This version puts real
attack strings in the path so the payload and detail view on the dashboard shows
meaningful content, and it computes the six features from each payload with the real
feature extractor so the feature vector shown matches the payload.
"""
import csv
import os
import random
import sys
from datetime import datetime, timedelta

random.seed(42)

_here = os.path.dirname(os.path.abspath(__file__))
_root = _here if os.path.exists(os.path.join(_here, 'logs')) \
        else os.path.dirname(_here)
sys.path.insert(0, os.path.join(_root, 'src'))

from feature_extractor import FeatureExtractor, HTTPRequest

LOG_DIR = os.path.join(_root, 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'detection_log.csv')

FIELDS = [
    "timestamp", "source_ip", "method", "path", "mode",
    "rule_id", "rule_category", "ml_score", "ml_pipeline",
    "action", "reason", "F1", "F2", "F3", "F4", "F5", "F6"
]

IPS = ["192.168.56.1", "10.0.2.15", "192.168.1.100", "172.16.0.5"]

CLEAN_PATHS = [
    "/index.html", "/login", "/api/users?id=42", "/style.css",
    "/about", "/contact", "/products?category=shoes", "/search?q=running+shoes",
    "/dashboard", "/images/logo.png", "/help/faq", "/blog/how-to-tie-laces",
]

# (path with real payload, method, rule_id, category, rule_matches)
SQLI = [
    ("/search?q=' OR '1'='1", "GET", "R001", "SQLi", True),
    ("/login", "POST", "R003", "SQLi", True),          # body: user=admin'--
    ("/api/users?id=1 UNION SELECT username,password FROM users", "GET", "R001", "SQLi", True),
    ("/product?id=5; DROP TABLE users--", "GET", "R004", "SQLi", True),
    ("/item?id=1%27%20OR%201%3D1", "GET", "NONE", "SQLi", False),  # encoded, Case B
]
XSS = [
    ("/comment?text=<script>alert(1)</script>", "POST", "R010", "XSS", True),
    ("/search?q=<img src=x onerror=alert(document.cookie)>", "GET", "R011", "XSS", True),
    ("/profile?bio=<svg/onload=alert(1)>", "POST", "R010", "XSS", True),
    ("/note?c=%3Cscript%3Ealert(1)%3C/script%3E", "GET", "NONE", "XSS", False),  # encoded, Case B
]
PATH = [
    ("/files?name=../../../etc/passwd", "GET", "R018", "PATH", True),
    ("/download?file=..%2f..%2f..%2fetc%2fpasswd", "GET", "R019", "PATH", True),
    ("/view?p=....//....//etc/passwd", "GET", "NONE", "PATH", False),  # evasion, Case B
]

fx = FeatureExtractor()


def features_for(path):
    req = HTTPRequest(method="GET", path=path, query_string="", headers={}, body="")
    fv = fx.extract(req)
    return fv.F1_length, fv.F2_special_chars, fv.F3_sql_keywords, \
        fv.F4_script_flag, fv.F5_traversal, round(fv.F6_entropy, 3)


def clean_row(ts):
    path = random.choice(CLEAN_PATHS)
    f1, f2, f3, f4, f5, f6 = features_for(path)
    return {
        "timestamp": ts.isoformat(), "source_ip": random.choice(IPS),
        "method": "GET", "path": path, "mode": "hybrid",
        "rule_id": "NONE", "rule_category": "NONE",
        "ml_score": f"{random.uniform(0.05, 0.38):.4f}", "ml_pipeline": "lr",
        "action": "ALLOW", "reason": "Both agree: legitimate request",
        "F1": f1, "F2": f2, "F3": f3, "F4": f4, "F5": f5, "F6": f6,
    }


def attack_row(ts):
    kind = random.choices(["sqli", "xss", "path"], weights=[50, 30, 20])[0]
    pool = {"sqli": SQLI, "xss": XSS, "path": PATH}[kind]
    path, method, rule_id, category, rule_hits = random.choice(pool)
    f1, f2, f3, f4, f5, f6 = features_for(path)

    if not rule_hits:
        score = random.uniform(0.72, 0.97)
        rule_out = "NONE"
        reason = f"Case B - ML catches obfuscated payload [score={score:.4f} >= 0.5]"
    else:
        score = random.uniform(0.55, 0.97)
        rule_out = rule_id
        if score >= 0.5:
            reason = "Both agree: confirmed attack"
        else:
            reason = f"Case A - rule wins [rule={rule_id}, ML={score:.4f} < 0.5]"
    return {
        "timestamp": ts.isoformat(), "source_ip": random.choice(IPS),
        "method": method, "path": path, "mode": "hybrid",
        "rule_id": rule_out, "rule_category": category,
        "ml_score": f"{score:.4f}", "ml_pipeline": "lr",
        "action": "BLOCK", "reason": reason,
        "F1": f1, "F2": f2, "F3": f3, "F4": f4, "F5": f5, "F6": f6,
    }


def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    now = datetime.now()
    start = now - timedelta(hours=2)
    rows = []
    for i in range(250):
        ts = start + timedelta(seconds=i * 29 + random.randint(0, 8))
        rows.append(attack_row(ts) if random.random() < 0.18 else clean_row(ts))
    with open(LOG_FILE, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    blocked = sum(1 for r in rows if r["action"] == "BLOCK")
    print(f"[OK] {len(rows)} entries ({blocked} blocks, {len(rows)-blocked} allows)")
    print(f"[OK] {LOG_FILE}")


if __name__ == "__main__":
    main()
