"""
Module 6: Logger and Alert System
Hybrid WAF – IT28X87 Honours Project
Mbadaliga, AB (219044112)

Writes structured CSV log entries for every processed request.
Generates console alerts for BLOCK decisions.
Provides a summarise() method for the CLI statistics tool.
Thread-safe: uses a lock to prevent concurrent write corruption.
"""
import csv
import os
import threading
from datetime import datetime
from typing import Dict, Optional


class Logger:
    """
    Appends one CSV row per request to the log file.
    Prints [ALERT] messages to stdout on BLOCK decisions.

    CSV columns:
        timestamp, source_ip, method, url, mode,
        rule_id, ml_score, action, reason
    """

    FIELDNAMES = [
        "timestamp", "source_ip", "method", "url",
        "mode", "rule_id", "ml_score", "action", "reason"
    ]

    def __init__(self, log_file: str = "waf_events.csv",
                 alert_file: str = "waf_alerts.log"):
        self.log_file = log_file
        self.alert_file = alert_file
        self._lock = threading.Lock()
        self._init_log_file()

    def _init_log_file(self) -> None:
        """Creates the log file with header row if it does not exist."""
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.FIELDNAMES)
                writer.writeheader()

    def log_event(self, req, decision, rule_result,
                  ml_result) -> None:
        """Appends one row to the CSV log. Thread-safe."""
        row = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": getattr(req, 'source_ip', '0.0.0.0'),
            "method":    req.method,
            "url":       req.path,
            "mode":      decision.mode,
            "rule_id":   rule_result.rule_id or "NONE",
            "ml_score":  f"{ml_result.probability:.4f}",
            "action":    decision.action,
            "reason":    decision.reason,
        }
        with self._lock:
            with open(self.log_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.FIELDNAMES)
                writer.writerow(row)

        if decision.is_block():
            self.alert(decision, req)

    def alert(self, decision, req) -> None:
        """Prints a formatted alert to stdout and appends to alert log."""
        category = decision.rule_id or "ML-detection"
        msg = (f"[ALERT] {datetime.utcnow().isoformat()} "
               f"BLOCKED {category} "
               f"from {getattr(req, 'source_ip', '0.0.0.0')} "
               f"at {req.path} "
               f"| {decision.reason}")
        print(msg)
        with self._lock:
            with open(self.alert_file, 'a') as f:
                f.write(msg + "\n")

    def summarise(self) -> Dict:
        """
        Reads the log file and returns summary statistics.
        Used by the CLI statistics tool (FR15).
        """
        if not os.path.exists(self.log_file):
            return {}

        total = 0
        blocked = 0
        allowed = 0
        by_category: Dict[str, int] = {}
        ml_scores = []

        with open(self.log_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                total += 1
                if row["action"] == "BLOCK":
                    blocked += 1
                    cat = row["rule_id"] if row["rule_id"] != "NONE" \
                          else "ML-only"
                    by_category[cat] = by_category.get(cat, 0) + 1
                else:
                    allowed += 1
                try:
                    ml_scores.append(float(row["ml_score"]))
                except ValueError:
                    pass

        avg_ml = sum(ml_scores) / len(ml_scores) if ml_scores else 0.0

        return {
            "total":        total,
            "blocked":      blocked,
            "allowed":      allowed,
            "block_rate":   f"{(blocked/total*100):.1f}%" if total else "0%",
            "avg_ml_score": f"{avg_ml:.4f}",
            "by_category":  by_category,
        }
