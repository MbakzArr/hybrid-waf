#!/usr/bin/env python3
"""
Generate sample detection log for dashboard demo.
Run ONCE before starting the dashboard:
    python3 demo/generate_sample_log.py

Creates logs/detection_log.csv with realistic entries so the
dashboard has data to display during the presentation.
"""
import csv
import os
import random
from datetime import datetime, timedelta

random.seed(42)

_here = os.path.dirname(os.path.abspath(__file__))
_root = _here if os.path.exists(os.path.join(_here, 'logs')) \
        else os.path.dirname(_here)

LOG_DIR  = os.path.join(_root, 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'detection_log.csv')

FIELDS = [
    "timestamp", "source_ip", "method", "path", "mode",
    "rule_id", "rule_category", "ml_score", "ml_pipeline",
    "action", "reason", "F1", "F2", "F3", "F4", "F5", "F6"
]

IPS = ["192.168.56.1", "10.0.2.15", "192.168.1.100", "172.16.0.5"]
CLEAN_PATHS = [
    "/index.html", "/login", "/api/users", "/style.css",
    "/about", "/contact", "/products", "/search?q=shoes",
    "/dashboard", "/images/logo.png", "/help/faq",
]
SQLI = [
    ("/login",      "POST", "R003", "SQLi"),
    ("/search",     "GET",  "R001", "SQLi"),
    ("/api/users",  "POST", "R004", "SQLi"),
]
XSS = [
    ("/comment",    "POST", "R010", "XSS"),
    ("/search",     "GET",  "R011", "XSS"),
    ("/profile",    "POST", "R010", "XSS"),
]
PATH = [
    ("/files",      "GET",  "R018", "PATH"),
    ("/download",   "GET",  "R019", "PATH"),
]


def clean_row(ts):
    return {
        "timestamp":    ts.isoformat(),
        "source_ip":    random.choice(IPS),
        "method":       "GET",
        "path":         random.choice(CLEAN_PATHS),
        "mode":         "hybrid",
        "rule_id":      "NONE",
        "rule_category":"NONE",
        "ml_score":     f"{random.uniform(0.05, 0.38):.4f}",
        "ml_pipeline":  "lr",
        "action":       "ALLOW",
        "reason":       "Both agree: legitimate request",
        "F1": random.randint(10, 60), "F2": random.randint(0, 2),
        "F3": 0, "F4": 0, "F5": 0,
        "F6": f"{random.uniform(2.5, 3.8):.3f}",
    }


def attack_row(ts):
    kind = random.choices(["sqli","xss","path"], weights=[50,30,20])[0]
    pool = {"sqli": SQLI, "xss": XSS, "path": PATH}[kind]
    path, method, rule_id, category = random.choice(pool)
    score = random.uniform(0.55, 0.97)
    is_case_b = random.random() < 0.25
    if is_case_b:
        rule_out = "NONE"
        reason = f"Case B - ML catches obfuscated payload [score={score:.4f} >= 0.5]"
    else:
        rule_out = rule_id
        if score >= 0.5:
            reason = "Both agree: confirmed attack"
        else:
            reason = f"Case A - rule wins [rule={rule_id}, ML={score:.4f} < 0.5]"
    return {
        "timestamp":    ts.isoformat(),
        "source_ip":    random.choice(IPS),
        "method":       method,
        "path":         path,
        "mode":         "hybrid",
        "rule_id":      rule_out,
        "rule_category": category,
        "ml_score":     f"{score:.4f}",
        "ml_pipeline":  "lr",
        "action":       "BLOCK",
        "reason":       reason,
        "F1": random.randint(15, 80), "F2": random.randint(3, 12),
        "F3": random.randint(0, 4),   "F4": 1 if kind=="xss" else 0,
        "F5": random.randint(1, 3) if kind=="path" else 0,
        "F6": f"{random.uniform(3.5, 5.5):.3f}",
    }


def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    now   = datetime.now()
    start = now - timedelta(hours=2)
    rows  = []

    for i in range(250):
        ts = start + timedelta(seconds=i * 29 + random.randint(0, 8))
        if random.random() < 0.10:
            rows.append(attack_row(ts))
        else:
            rows.append(clean_row(ts))

    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    blocked = sum(1 for r in rows if r["action"] == "BLOCK")
    print(f"[OK] {len(rows)} log entries written "
          f"({blocked} blocks, {len(rows)-blocked} allows)")
    print(f"[OK] {LOG_FILE}")


if __name__ == "__main__":
    main()
