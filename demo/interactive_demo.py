#!/usr/bin/env python3
"""
D07 Interactive Demo - Hybrid WAF
IT28X87 Honours Project | Mbadaliga, AB (219044112)

Run from the project root:
    python3 demo/interactive_demo.py

Type any payload at the prompt and see it processed through the full
pipeline in real time: Feature Extraction -> Rule Engine -> ML Classifier
-> Decision Engine. Each result is printed with timing for every stage.

Commands:
    mode <rule_only|ml_only|hybrid>   change operating mode
    threshold <0.0-1.0>               change ML decision threshold
    rules                             show all loaded rules
    quit                              exit

D07 UPDATE: the entropy-based stub used at D05/D06 has been replaced
with the real trained Pipeline 2 (Random Forest) model, loaded from
models/pipeline2_random_forest.pkl. Random Forest was chosen because
it was the strongest performer in the pipeline comparison (see
evaluation/results/pipeline_metrics.csv). If that model file is
missing, the demo falls back to the old stub and says so clearly,
so a missing model file never silently gives fake results.

Every stage is timed with time.perf_counter(), which measures wall
time in-process only. This does NOT include network round-trip, since
this demo calls the pipeline directly with no real socket involved.
That matches how the rest of this project's latency figures are
defined (see NFR01 in the design docs).
"""
import sys
import os
import time
import pickle

# ── Path setup (run from project root or demo/ folder) ──────────
_here = os.path.dirname(os.path.abspath(__file__))
_root = _here if os.path.isdir(os.path.join(_here, 'src')) \
        else os.path.dirname(_here)
sys.path.insert(0, os.path.join(_root, 'src'))
sys.path.insert(0, os.path.join(_root, 'pipelines'))

from feature_extractor import FeatureExtractor, HTTPRequest, FeatureVector
from rule_engine import RuleEngine, RuleResult
from decision_engine import DecisionEngine, Decision
from logger import Logger
from dataclasses import dataclass

try:
    import numpy as np
    from random_forest import RandomForestModel
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


# ── ML result container ──────────────────────────────────────────
@dataclass
class MLResult:
    probability: float
    pipeline: str = "entropy_stub"


def ml_stub(fv: FeatureVector, threshold: float = 0.5) -> MLResult:
    """
    Fallback only, used if the trained model file cannot be loaded.
    Kept so the demo never crashes if run before train_models.py.
    """
    score = 0.0
    score += min(fv.F2_special_chars * 0.12, 0.35)
    score += min(fv.F3_sql_keywords  * 0.18, 0.45)
    score += fv.F4_script_flag       * 0.30
    score += min(fv.F5_traversal     * 0.25, 0.50)
    score += min(fv.F6_entropy       * 0.04, 0.20)
    score = min(score, 0.99)
    return MLResult(probability=round(score, 4), pipeline="entropy_stub")


def ml_predict_rf(fv: FeatureVector, rf_model) -> MLResult:
    """Real inference using the trained Pipeline 2 Random Forest."""
    x = np.array(fv.to_list(), dtype=np.float64)
    proba = rf_model.predict_proba(x)
    return MLResult(probability=round(proba, 4), pipeline="pipeline2_random_forest")


def load_rf_model(models_dir):
    """Returns a loaded RandomForestModel, or None if unavailable.
    Prints the real reason on failure instead of silently falling back,
    so a stub fallback is never a silent mystery."""
    if not NUMPY_AVAILABLE:
        print(f"\n{YELLOW}[WARN] numpy or sklearn import failed, "
              f"cannot load trained model.{RESET}\n")
        return None
    path = os.path.join(models_dir, "pipeline2_random_forest.pkl")
    if not os.path.exists(path):
        print(f"\n{YELLOW}[WARN] Model file does not exist at: {path}{RESET}\n")
        return None
    try:
        with open(path, "rb") as f:
            data = pickle.load(f)
        model = RandomForestModel()
        model.model = data["model"]
        model.scaler = data["scaler"]
        model.trained = data["trained"]
        return model
    except Exception as e:
        print(f"\n{YELLOW}[WARN] Found {path} but failed to load it: "
              f"{type(e).__name__}: {e}{RESET}\n")
        return None


# ── Terminal colours ─────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

RULES_FILE = os.path.join(_root, 'rules', 'rules.txt')
MODELS_DIR = os.path.join(_root, 'models')
LOG_FILE = os.path.join(_root, 'logs', 'detection_log.csv')


def banner(mode: str, threshold: float, rule_count: int, ml_source: str):
    print(f"""
{BOLD}{CYAN}{'='*62}
  Hybrid WAF  -  D07 Interactive Demo
  IT28X87 Honours Project  |  Mbadaliga, AB (219044112)
{'='*62}{RESET}
  Mode: {YELLOW}{mode}{RESET}  |  Threshold: {YELLOW}{threshold}{RESET}  |  Rules loaded: {YELLOW}{rule_count}{RESET}
  ML source: {YELLOW}{ml_source}{RESET}

  Commands:
    {YELLOW}mode <rule_only|ml_only|hybrid>{RESET}
    {YELLOW}threshold <0.0-1.0>{RESET}
    {YELLOW}rules{RESET}
    {YELLOW}quit{RESET}
{'='*62}
""")


def print_result(fv, rr, ml, dec, threshold, timings):
    print(f"\n  {CYAN}-- Feature Extraction (M2) --{RESET}  "
          f"{GREY}[{timings['extract']*1000:.3f} ms]{RESET}")
    print(f"    F1 length        : {fv.F1_length}")
    print(f"    F2 special chars : {fv.F2_special_chars}")
    print(f"    F3 SQL keywords  : {fv.F3_sql_keywords}")
    print(f"    F4 script flag   : {fv.F4_script_flag}")
    print(f"    F5 traversal     : {fv.F5_traversal}")
    print(f"    F6 entropy       : {fv.F6_entropy:.3f}")

    print(f"\n  {CYAN}-- Rule Engine (M3) --{RESET}  "
          f"{GREY}[{timings['rule']*1000:.3f} ms]{RESET}")
    if rr.matched:
        print(f"    {RED}MATCH{RESET} - rule {rr.rule_id} [{rr.category}]")
    else:
        print(f"    {GREEN}NO_MATCH{RESET} - no rule fired")

    print(f"\n  {CYAN}-- ML Classifier (M4) --{RESET}  "
          f"{GREY}[{timings['ml']*1000:.3f} ms]{RESET}")
    col = RED if ml.probability >= threshold else GREEN
    print(f"    Score : {col}{ml.probability:.4f}{RESET}  "
          f"(threshold = {threshold})  [{ml.pipeline}]")

    print(f"\n  {CYAN}-- Decision Engine (M5) --{RESET}  "
          f"{GREY}[{timings['decide']*1000:.3f} ms]{RESET}")
    if dec.is_block():
        print(f"    {RED}{BOLD}>>> BLOCK <<< {RESET}")
    else:
        print(f"    {GREEN}{BOLD}>>> ALLOW <<< {RESET}")
    print(f"    Reason : {dec.reason}")
    print(f"    Mode   : {dec.mode}")
    print(f"\n  {BOLD}Total pipeline time (M2-M5): "
          f"{timings['total']*1000:.3f} ms{RESET}\n")


def main():
    if not os.path.exists(RULES_FILE):
        print(f"[ERROR] Rules file not found: {RULES_FILE}")
        print("Run from the project root: python3 demo/interactive_demo.py")
        sys.exit(1)

    extractor = FeatureExtractor()
    rule_engine = RuleEngine(RULES_FILE)
    logger = Logger(log_file=LOG_FILE)

    rf_model = load_rf_model(MODELS_DIR)
    if rf_model is not None:
        ml_source = "pipeline2_random_forest (trained)"
    else:
        ml_source = "entropy_stub (FALLBACK - run train_models.py for real scoring)"
        print(f"\n{YELLOW}[WARN] Trained model not found at "
              f"{MODELS_DIR}/pipeline2_random_forest.pkl{RESET}")
        print(f"{YELLOW}       Falling back to the entropy stub. "
              f"Run train_models.py to get real scoring.{RESET}\n")

    mode = "hybrid"
    threshold = 0.5
    decision_engine = DecisionEngine(mode=mode, threshold=threshold)

    banner(mode, threshold, len(rule_engine.rules), ml_source)

    while True:
        try:
            payload = input(f"{BOLD}payload>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not payload:
            continue

        if payload.lower() == "quit":
            print("Exiting.")
            break

        if payload.lower() == "rules":
            print(f"\n  {CYAN}Loaded rules ({len(rule_engine.rules)}):{RESET}")
            for r in rule_engine.rules:
                print(f"  {r.rule_id:6s} | {r.category:5s} | {r.raw_pattern}")
            print()
            continue

        if payload.lower().startswith("mode "):
            new_mode = payload.split(None, 1)[1].strip()
            try:
                decision_engine = DecisionEngine(mode=new_mode, threshold=threshold)
                mode = new_mode
                print(f"\n  Mode changed to: {YELLOW}{mode}{RESET}\n")
            except ValueError as e:
                print(f"\n  {RED}{e}{RESET}\n")
            continue

        if payload.lower().startswith("threshold "):
            try:
                new_t = float(payload.split(None, 1)[1])
                if not 0.0 <= new_t <= 1.0:
                    raise ValueError("Must be between 0.0 and 1.0")
                threshold = new_t
                decision_engine = DecisionEngine(mode=mode, threshold=threshold)
                print(f"\n  Threshold changed to: {YELLOW}{threshold}{RESET}\n")
            except ValueError as e:
                print(f"\n  {RED}{e}{RESET}\n")
            continue

        # ── Process payload, timed stage by stage ────────────────
        req = HTTPRequest(
            method="POST", path="/login", query_string=payload,
            headers={}, body="", source_ip="127.0.0.1"
        )

        t_start = time.perf_counter()

        t0 = time.perf_counter()
        fv = extractor.extract(req)
        t_extract = time.perf_counter() - t0

        t0 = time.perf_counter()
        rr = rule_engine.evaluate(req.full_text())
        t_rule = time.perf_counter() - t0

        t0 = time.perf_counter()
        if rf_model is not None:
            ml = ml_predict_rf(fv, rf_model)
        else:
            ml = ml_stub(fv, threshold)
        t_ml = time.perf_counter() - t0

        t0 = time.perf_counter()
        dec = decision_engine.decide(rr, ml)
        t_decide = time.perf_counter() - t0

        t_total = time.perf_counter() - t_start

        timings = {
            "extract": t_extract, "rule": t_rule,
            "ml": t_ml, "decide": t_decide, "total": t_total,
        }

        logger.log_event(req, dec, rr, ml, feature_vector=fv, timings=timings)

        print_result(fv, rr, ml, dec, threshold, timings)


if __name__ == "__main__":
    main()
