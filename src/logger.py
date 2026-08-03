"""
Module 6: Logger and Alert System
Hybrid WAF - IT28X87 Honours Project
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
    FIELDNAMES = [
        "timestamp", "source_ip", "method", "path", "payload",
        "mode", "rule_id", "rule_category", "ml_score", "action", "reason",
        "F1", "F2", "F3", "F4", "F5", "F6",
        "t_extract_ms", "t_rule_ms", "t_ml_ms", "t_decide_ms", "t_total_ms",
    ]

    def __init__(self, log_file: str = "waf_events.csv",
                 alert_file: str = "waf_alerts.log"):
        self.log_file = log_file
        self.alert_file = alert_file
        self._lock = threading.Lock()
        self._init_log_file()

    def _init_log_file(self) -> None:
        if not os.path.exists(self.log_file):
            os.makedirs(os.path.dirname(self.log_file) or ".", exist_ok=True)
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.FIELDNAMES)
                writer.writeheader()

    def log_event(self, req, decision, rule_result, ml_result,
                  feature_vector=None, timings=None) -> None:
        """
        Appends one row to the CSV log. Thread-safe.

        feature_vector: the FeatureVector for this request (optional, for
            backward compatibility with old callers that don't pass it).
        timings: dict with keys extract, rule, ml, decide, total, each a
            float in SECONDS (converted to ms here). Optional for the
            same reason.
        """
        fv = feature_vector
        t = timings or {}

        def ms(key):
            return f"{t[key]*1000:.3f}" if key in t else ""

        row = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": getattr(req, 'source_ip', '0.0.0.0'),
            "method":    req.method,
            "path":      req.path,
            "payload":   req.full_text().strip(),
            "mode":      decision.mode,
            "rule_id":   rule_result.rule_id or "NONE",
            "rule_category": rule_result.category or "",
            "ml_score":  f"{ml_result.probability:.4f}",
            "action":    decision.action,
            "reason":    decision.reason,
            "F1": fv.F1_length if fv else "",
            "F2": fv.F2_special_chars if fv else "",
            "F3": fv.F3_sql_keywords if fv else "",
            "F4": fv.F4_script_flag if fv else "",
            "F5": fv.F5_traversal if fv else "",
            "F6": f"{fv.F6_entropy:.3f}" if fv else "",
            "t_extract_ms": ms("extract"),
            "t_rule_ms":    ms("rule"),
            "t_ml_ms":      ms("ml"),
            "t_decide_ms":  ms("decide"),
            "t_total_ms":   ms("total"),
        }
        with self._lock:
            with open(self.log_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.FIELDNAMES)
                writer.writerow(row)

        if decision.is_block():
            self.alert(decision, req)

    def alert(self, decision, req) -> None:
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
                    cat = row.get("rule_id") if row.get("rule_id") != "NONE" else "ML-only"
                    by_category[cat] = by_category.get(cat, 0) + 1
                else:
                    allowed += 1
                try:
                    ml_scores.append(float(row["ml_score"]))
                except (ValueError, KeyError):
                    pass
        avg_ml = sum(ml_scores) / len(ml_scores) if ml_scores else 0.0
        return {
            "total": total, "blocked": blocked, "allowed": allowed,
            "block_rate": f"{(blocked/total*100):.1f}%" if total else "0%",
            "avg_ml_score": f"{avg_ml:.4f}",
            "by_category": by_category,
        }
