#!/usr/bin/env python3
"""
run_waf.py - starts the live Hybrid WAF reverse proxy (M1). New for D8.

Usage:
    python3 run_waf.py --backend http://127.0.0.1:8081   # DVWA
    python3 run_waf.py --backend http://127.0.0.1:3000   # Juice Shop
"""
import argparse
import os
import sys
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from traffic_reader import WAFHandler, ThreadingHTTPServer, load_rf_model
from feature_extractor import FeatureExtractor
from rule_engine import RuleEngine
from decision_engine import DecisionEngine
from logger import Logger

ROOT = os.path.dirname(os.path.abspath(__file__))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=os.path.join(ROOT, "config", "config.yaml"))
    parser.add_argument("--backend", default=None,
                         help="Override backend_url, e.g. http://127.0.0.1:8081")
    parser.add_argument("--mode", default=None,
                         help="Override detection mode: rule_only | ml_only | hybrid")
    args = parser.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    host = cfg["server"]["host"]
    port = cfg["server"]["port"]
    backend_url = args.backend or cfg["server"]["backend_url"]
    mode = args.mode or cfg["detection"]["mode"]
    threshold = cfg["detection"]["threshold"]
    rules_file = os.path.join(ROOT, cfg["rules"]["file"])
    log_file = os.path.join(ROOT, cfg["logging"]["log_file"])
    models_dir = os.path.join(ROOT, "models")

    extractor = FeatureExtractor()
    rule_engine = RuleEngine(rules_file)
    rf_model = load_rf_model(models_dir)
    if rf_model is None:
        print("[WARN] Random Forest model not loaded, ML score will be 0.0 for every request.")
    decision_engine = DecisionEngine(mode=mode, threshold=threshold)
    logger = Logger(log_file=log_file)

    WAFHandler.configure(extractor, rule_engine, rf_model, decision_engine, logger, backend_url)

    print(f"Hybrid WAF listening on {host}:{port}")
    print(f"  mode        : {mode}")
    print(f"  threshold   : {threshold}")
    print(f"  rules       : {len(rule_engine.rules)} loaded from {rules_file}")
    print(f"  ML model    : {'pipeline2_random_forest' if rf_model else 'UNAVAILABLE'}")
    print(f"  backend_url : {backend_url}")

    server = ThreadingHTTPServer((host, port), WAFHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
