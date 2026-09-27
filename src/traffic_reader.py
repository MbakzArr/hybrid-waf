#!/usr/bin/env python3
"""
M1 - TrafficReader (src/traffic_reader.py)
Hybrid WAF | Mbadaliga, AB (219044112)

New for D8. D07's demo called the pipeline directly in Python with no
real socket. This module actually binds a port, receives real HTTP
requests, runs them through M2-M5, and either forwards to the backend
(ALLOW) or returns 403 without touching the backend (BLOCK).
"""
import os
import sys
import pickle
import time
import http.server
import http.client
import socketserver
import urllib.parse

_here = os.path.dirname(os.path.abspath(__file__))
_root = os.path.dirname(_here)
sys.path.insert(0, _here)
sys.path.insert(0, os.path.join(_root, 'pipelines'))

from feature_extractor import FeatureExtractor, HTTPRequest
from rule_engine import RuleEngine
from decision_engine import DecisionEngine
from logger import Logger

try:
    import numpy as np
    from random_forest import RandomForestModel
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


def load_rf_model(models_dir):
    """Same loading logic as demo/interactive_demo.py, kept identical
    on purpose so the demo and the live proxy trust the same file in
    the same format."""
    if not NUMPY_AVAILABLE:
        return None
    path = os.path.join(models_dir, "pipeline2_random_forest.pkl")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as f:
            data = pickle.load(f)
        model = RandomForestModel()
        model.model = data["model"]
        model.scaler = data["scaler"]
        model.trained = data["trained"]
        return model
    except Exception:
        return None


class MLResult:
    def __init__(self, probability, pipeline="pipeline2_random_forest"):
        self.probability = probability
        self.pipeline = pipeline


def ml_predict_rf(fv, rf_model):
    x = np.array(fv.to_list(), dtype=np.float64)
    proba = rf_model.predict_proba(x)
    return MLResult(probability=round(proba, 4))


class WAFHandler(http.server.BaseHTTPRequestHandler):
    """
    M1 TrafficReader. Shared pipeline objects are set once as class
    attributes via configure(), since BaseHTTPRequestHandler creates a
    new instance per connection and rules/models must load once only.
    """
    extractor = None
    rule_engine = None
    rf_model = None
    decision_engine = None
    logger = None
    backend_url = None

    @classmethod
    def configure(cls, extractor, rule_engine, rf_model, decision_engine,
                  logger, backend_url):
        cls.extractor = extractor
        cls.rule_engine = rule_engine
        cls.rf_model = rf_model
        cls.decision_engine = decision_engine
        cls.logger = logger
        cls.backend_url = backend_url

    def log_message(self, fmt, *args):
        pass  # M6 Logger handles this, not stderr

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

    def _handle(self, method):
        t_start = time.perf_counter()
        parsed = urllib.parse.urlsplit(self.path)
        body = self._read_body() if method == "POST" else ""

        req = HTTPRequest(
            method=method,
            path=urllib.parse.unquote(parsed.path),
            query_string=urllib.parse.unquote(parsed.query),
            headers=dict(self.headers.items()), body=body,
            source_ip=self.client_address[0],
        )

        t0 = time.perf_counter()
        fv = self.extractor.extract(req)
        t_extract = time.perf_counter() - t0

        t0 = time.perf_counter()
        rr = self.rule_engine.evaluate(req.full_text())
        t_rule = time.perf_counter() - t0

        t0 = time.perf_counter()
        ml = ml_predict_rf(fv, self.rf_model) if self.rf_model else MLResult(0.0, "unavailable")
        t_ml = time.perf_counter() - t0

        t0 = time.perf_counter()
        dec = self.decision_engine.decide(rr, ml)
        t_decide = time.perf_counter() - t0

        timings = {"extract": t_extract, "rule": t_rule, "ml": t_ml,
                   "decide": t_decide, "total": time.perf_counter() - t_start}

        self.logger.log_event(req, dec, rr, ml, feature_vector=fv, timings=timings)

        if dec.is_block():
            self._build_403(dec)
        else:
            self._forward_to_backend(method, parsed, body)

    def _build_403(self, dec):
        body = f"403 Forbidden\n\nBlocked by Hybrid WAF.\nReason: {dec.reason}\n".encode()
        self.send_response(403)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _build_502(self):
        body = b"502 Bad Gateway\n\nBackend unreachable.\n"
        self.send_response(502)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _forward_to_backend(self, method, parsed, body):
        backend = urllib.parse.urlsplit(self.backend_url)
        conn = http.client.HTTPConnection(backend.hostname, backend.port, timeout=5)
        try:
            target_path = parsed.path + (("?" + parsed.query) if parsed.query else "")
            fwd_headers = {k: v for k, v in self.headers.items() if k.lower() != "host"}
            conn.request(method, target_path, body=body, headers=fwd_headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in ("transfer-encoding", "content-length"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        except Exception:
            self._build_502()
        finally:
            conn.close()

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
