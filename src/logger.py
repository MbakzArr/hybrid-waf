"""
Module 6: Logger and Alert System
Hybrid WAF - IT28X87 Honours Project
Mbadaliga, AB (219044112)

Writes structured CSV log entries for every processed request.
Generates console alerts for BLOCK decisions.
Provides a summarise() method and a command line summary (FR15):
    python src/logger.py --summary
Errors (malformed requests, backend failures) go to a separate file so
the main event log only holds BLOCK and ALLOW decisions (NFR03).
Thread-safe: uses a lock to prevent concurrent write corruption.
"""
import argparse
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

    ERROR_FIELDS = ["timestamp", "source_ip", "method", "path", "error"]

    def __init__(self, log_file: str = "waf_events.csv",
                 alert_file: str = "waf_alerts.log",
                 error_file: Optional[str] = None):
        self.log_file = log_file
        self.alert_file = alert_file
        # Default sits next to the event log, e.g. logs/waf_errors.csv
        self.error_file = error_file or os.path.join(
            os.path.dirname(log_file) or ".", "waf_errors.csv")
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

    def log_error(self, source_ip: str, method: str, path: str,
                  error: str) -> None:
        """
        Records a request the WAF could not judge, a malformed request
        or a backend that could not be reached (NFR03). Thread-safe.
        """
        os.makedirs(os.path.dirname(self.error_file) or ".", exist_ok=True)
        row = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": source_ip or "0.0.0.0",
            "method": method or "",
            "path": path or "",
            "error": error,
        }
        with self._lock:
            new_file = not os.path.exists(self.error_file)
            with open(self.error_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.ERROR_FIELDS)
                if new_file:
                    writer.writeheader()
                writer.writerow(row)

    def alert(self, decision, req) -> None:
        category = decision.rule_id or "ML-detection"
        msg = (f"[ALERT] {datetime.utcnow().isoformat()} "
               f"BLOCKED {category} "
               f"from {getattr(req, 'source_ip', '0.0.0.0')} "
               f"at {req.path} "
               f"| {decision.reason}")
        print(msg)
        with self._lock:
            os.makedirs(os.path.dirname(self.alert_file) or ".", exist_ok=True)
            with open(self.alert_file, 'a') as f:
                f.write(msg + "\n")

    def summarise(self) -> Dict:
        if not os.path.exists(self.log_file):
            return {}
        total = 0
        blocked = 0
        allowed = 0
        case_a = 0
        case_b = 0
        by_category: Dict[str, int] = {}
        ml_scores = []
        with open(self.log_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                total += 1
                if row["action"] == "BLOCK":
                    blocked += 1
                    reason = row.get("reason", "")
                    if "Case A" in reason:
                        case_a += 1
                    elif "Case B" in reason:
                        case_b += 1
                    if row.get("rule_id") != "NONE":
                        cat = row.get("rule_category") or row.get("rule_id")
                    else:
                        cat = "ML-only (Case B)"
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
            "case_a": case_a, "case_b": case_b,
            "by_category": by_category,
            "errors": self._count_errors(),
        }

    def _count_errors(self) -> int:
        if not os.path.exists(self.error_file):
            return 0
        with open(self.error_file, 'r', newline='') as f:
            return sum(1 for _ in csv.DictReader(f))


def print_summary(stats: Dict) -> None:
    print("Hybrid WAF - Detection Summary")
    print("-" * 31)
    print(f"Total requests processed : {stats['total']}")
    print(f"Blocked : {stats['blocked']} ({stats['block_rate']})")
    print(f"Allowed : {stats['allowed']}")
    print(f"Average ML score : {stats['avg_ml_score']}")
    print(f"Case A (rule, low ML score) : {stats['case_a']}")
    print(f"Case B (ML only) : {stats['case_b']}")
    print("Blocked by category:")
    if not stats["by_category"]:
        print("  none")
    for cat, n in sorted(stats["by_category"].items(),
                         key=lambda kv: -kv[1]):
        print(f"  {cat} : {n}")
    print(f"Errors logged (malformed or backend failure) : {stats['errors']}")
    print("-" * 31)


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    parser = argparse.ArgumentParser(description="Hybrid WAF log tools")
    parser.add_argument("--summary", action="store_true",
                        help="print detection statistics from the log file")
    parser.add_argument("--log-file",
                        default=os.path.join(root, "logs", "waf_events.csv"))
    args = parser.parse_args()
    if not args.summary:
        parser.print_help()
        return 0
    if not os.path.exists(args.log_file):
        print(f"No log file found at {args.log_file}")
        return 1
    print_summary(Logger(log_file=args.log_file).summarise())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
