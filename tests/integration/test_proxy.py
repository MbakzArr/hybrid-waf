"""
Integration tests for the live reverse proxy (M1) with M2 to M6 behind it.
Maps to: FR01, FR10, FR11, FR14, NFR03, UC05 (rule hot reload).

A small stub backend runs on a free local port. The proxy runs on another.
Real HTTP requests are sent with http.client, so the whole path is used.

Run: pytest tests/integration/test_proxy.py -v
"""
import http.client
import http.server
import os
import shutil
import socket
import sys
import threading
import time

ROOT = os.path.join(os.path.dirname(__file__), '../..')
sys.path.insert(0, os.path.join(ROOT, 'src'))

import pytest
from traffic_reader import WAFHandler, ThreadingHTTPServer, load_rf_model
from feature_extractor import FeatureExtractor
from rule_engine import RuleEngine
from decision_engine import DecisionEngine
from logger import Logger

RULES = os.path.join(ROOT, 'rules', 'rules.txt')
MODELS = os.path.join(ROOT, 'models')
MODEL_FILE = 'pipeline2_random_forest_aug.pkl'   # the model the proxy runs with (config/waf_config.yaml)
HAVE_MODEL = os.path.exists(os.path.join(MODELS, MODEL_FILE))
needs_model = pytest.mark.skipif(not HAVE_MODEL, reason="trained model not found")


class StubBackend(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        StubBackend.hits.append(self.path)
        body = b"backend ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def start(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Proxy:
    """Starts a stub backend and the WAF proxy for one test."""

    def __init__(self, tmp_path, mode="hybrid", rules=RULES, use_model=False,
                 backend_up=True):
        StubBackend.hits = []
        self.backend = None
        self.backend_port = free_port()
        if backend_up:
            self.backend = http.server.HTTPServer(("127.0.0.1", self.backend_port), StubBackend)
            start(self.backend)
        self.logger = Logger(log_file=str(tmp_path / "events.csv"),
                             alert_file=str(tmp_path / "alerts.log"),
                             error_file=str(tmp_path / "errors.csv"))
        self.rule_engine = RuleEngine(rules)
        rf = load_rf_model(MODELS, MODEL_FILE) if use_model else None
        WAFHandler.configure(FeatureExtractor(), self.rule_engine, rf,
                             DecisionEngine(mode=mode, threshold=0.5),
                             self.logger, f"http://127.0.0.1:{self.backend_port}")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), WAFHandler)
        self.port = self.server.server_address[1]
        start(self.server)

    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", path)
        r = c.getresponse()
        body = r.read().decode(errors="replace")
        c.close()
        return r.status, body

    def raw(self, data: bytes):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(data)
        out = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
        except socket.timeout:
            pass
        s.close()
        return out.decode(errors="replace")

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        if self.backend:
            self.backend.shutdown()
            self.backend.server_close()


@pytest.fixture
def make_proxy(tmp_path):
    made = []

    def _make(**kw):
        p = Proxy(tmp_path, **kw)
        made.append(p)
        return p
    yield _make
    for p in made:
        p.stop()


def test_it01_clean_request_is_forwarded(make_proxy):
    p = make_proxy()
    status, body = p.get("/login.php")
    assert status == 200 and body == "backend ok"
    assert StubBackend.hits == ["/login.php"]


def test_it02_attack_gets_403_and_backend_not_touched(make_proxy):
    p = make_proxy()
    status, body = p.get("/item?id=1'%20OR%20'1'='1")
    assert status == 403
    assert "Blocked by Hybrid WAF" in body
    assert StubBackend.hits == []


def test_it03_url_encoded_attack_is_decoded_and_blocked(make_proxy):
    p = make_proxy()
    status, _ = p.get("/item?id=1%27%20OR%20%271%27%3D%271")
    assert status == 403


def test_it04_backend_down_gives_502_and_logs_error(make_proxy, tmp_path):
    p = make_proxy(backend_up=False)
    status, body = p.get("/login.php")
    assert status == 502
    assert "Backend failure" in (tmp_path / "errors.csv").read_text()


def test_it05_malformed_request_is_logged_and_server_survives(make_proxy, tmp_path):
    p = make_proxy()
    reply = p.raw(b"THIS IS NOT HTTP\r\n\r\n")
    assert "400" in reply
    assert "HTTP 400" in (tmp_path / "errors.csv").read_text()
    status, _ = p.get("/login.php")      # still serving
    assert status == 200


def test_it06_rule_hot_reload_through_proxy(make_proxy, tmp_path):
    rules_copy = str(tmp_path / "rules.txt")
    shutil.copy(RULES, rules_copy)
    p = make_proxy(rules=rules_copy)
    status, _ = p.get("/page?q=zebracrossing")
    assert status == 200                          # no rule yet
    with open(rules_copy, "a") as f:
        f.write("\nTEST_999 | SQLi | (zebracrossing)\n")
    later = time.time() + 5                       # avoid same-second mtime
    os.utime(rules_copy, (later, later))
    status, _ = p.get("/page?q=zebracrossing")
    assert status == 403                          # rule picked up, no restart
    assert p.rule_engine.get_rule_count() >= 46 - 1


def test_it07_logging_failure_does_not_stop_enforcement(make_proxy, monkeypatch):
    p = make_proxy()

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(p.logger, "log_event", boom)
    assert p.get("/item?id=1'%20OR%20'1'='1")[0] == 403
    assert p.get("/login.php")[0] == 200


# No rule matches this one but the model scores it 0.97 in the live replay (Case B)
CASE_B = "/vulnerabilities/sqli/?id=%27%20OR%20%27a%27%3D%27a&Submit=Submit"


@needs_model
def test_it08_hybrid_blocks_case_b_payload(make_proxy):
    p = make_proxy(mode="hybrid", use_model=True)
    status, body = p.get(CASE_B)
    assert status == 403 and "Case B" in body


@needs_model
def test_it09_rule_only_mode_lets_case_b_payload_through(make_proxy):
    p = make_proxy(mode="rule_only", use_model=True)
    assert p.get(CASE_B)[0] == 200                # no rule matches it
    assert p.get("/item?id=1'%20OR%20'1'='1")[0] == 403   # rules still work


@needs_model
def test_it10_ml_only_mode_blocks_case_b_payload(make_proxy):
    p = make_proxy(mode="ml_only", use_model=True)
    assert p.get(CASE_B)[0] == 403
