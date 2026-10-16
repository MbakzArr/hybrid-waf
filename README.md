# Hybrid Web Application Firewall

**Honours Year Project, IT28X87**
University of Johannesburg, Academy of Computer Science and Software Engineering

**Student:** Mbadaliga, AB (219044112)

## Project summary

A web application firewall (WAF) that combines a rule engine with a small
machine learning model. It runs as a reverse proxy in front of a web
application and blocks SQL injection, cross-site scripting (XSS) and path
traversal requests. The rule engine catches known patterns. The Random Forest
catches requests that avoid every rule but still look like an attack. The
decision engine joins the two.

## How a request is handled

| Module | File | Job |
|--------|------|-----|
| M1 Traffic Reader | `src/traffic_reader.py` | Reverse proxy. Reads the request, decodes the path and query once and forwards clean requests to the backend |
| M2 Feature Extractor | `src/feature_extractor.py` | Six features: length, special characters, SQL keywords, script flag, path traversal count and entropy |
| M3 Rule Engine | `src/rule_engine.py` | 45 regex rules from `rules/rules.txt`. Reloads when the file changes |
| M4 Classifier | `pipelines/random_forest.py` | Random Forest, 100 trees, depth 10, seed 42 |
| M5 Decision Engine | `src/decision_engine.py` | Modes `rule_only`, `ml_only` and `hybrid` |
| M6 Logger | `src/logger.py` | Event log, alert log, error log and a summary command |
| Dashboard | `src/dashboard.py` | Web view of the logs on port 8082 |

Hybrid decision (threshold 0.5): a rule match always blocks (Case A when the
model disagrees). No rule match and a model score of 0.5 or higher also blocks
(Case B, the model catches what the rules missed). Everything else is allowed.

## Setup

Python 3.10 or newer (tested on 3.12).

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt` pins the exact versions the results were produced with.

## Run the WAF

```bash
python run_waf.py --backend http://127.0.0.1:8081    # DVWA
python run_waf.py --backend http://127.0.0.1:3000    # Juice Shop
```

It listens on port 8080. Settings are in `config/waf_config.yaml` (mode,
threshold, rule file, model file, log files and the 10 ms latency warning).
`--mode rule_only|ml_only|hybrid` overrides the mode.

Logs are written to `logs/`: `waf_events.csv`, `waf_alerts.log` and
`waf_errors.csv` (malformed requests and backend failures).

```bash
python src/logger.py --summary     # totals, Case A and Case B counts, blocks by category
python src/dashboard.py            # then open http://localhost:8082
python demo/interactive_demo.py    # type a payload and see each module's decision
```

## Tests

```bash
python -m pytest -q
```

47 tests: unit tests for each module and integration tests that start the real
proxy in front of a stub backend. The tests that need the model skip themselves
if `models/pipeline2_random_forest_aug.pkl` is missing.

## Live replay tests

These send requests through a running proxy and count what was blocked (HTTP 403).

```bash
python3 evaluation/replay_attacks.py --target http://localhost:8080   # 93 requests
python3 evaluation/replay_holdout.py --target http://localhost:8080   # 60 requests
```

`replay_holdout.py` uses different paths and words and was written before the
retrained model existed. It is the cleaner test of the false positive fix.

## Reproduce the offline results

Download the datasets first (see `datasets/README.md`). Run from the repo root.

```bash
python3 build_dataset.py              # data/merged_dataset.csv
python3 train_models.py               # models/ and evaluation/results/pipeline_metrics.csv
python3 evaluate_configurations.py    # evaluation/results/four_configuration_comparison.csv
python3 benchmark_latency.py          # evaluation/results/latency_benchmark.csv
python3 augment_and_retrain.py        # second model: models/pipeline2_random_forest_aug.pkl
```

`evaluate_configurations.py` and `benchmark_latency.py` take `--model` and `--out`
to score the second model without overwriting the first results.

The ModSecurity baseline needs Apache with ModSecurity and OWASP CRS v4:
`export_test_set_for_modsec.py` writes the test set and `benchmark_modsecurity.py`
sends it to the local Apache. The CRS paranoia level was not changed from the
default (level 1).

## Results

Two Random Forest models exist. The first (v1) was trained on the merged
dataset as it was. The second (v2, deployed) was trained after removing 215
empty attack rows from the training part and adding 4,000 synthetic normal
requests. Both use the same 25,627 row test set.

**Offline test set**

| Configuration | Precision | Recall | F1 | False positive rate |
|---------------|-----------|--------|----|---------------------|
| Rules only (45 rules) | 1.000 | 0.293 | 0.453 | 0.000 |
| Random Forest only, v1 | 0.980 | 0.713 | 0.825 | 0.006 |
| Hybrid, v1 | 0.980 | 0.714 | 0.826 | 0.006 |
| Hybrid, v2 (deployed) | 0.978 | 0.695 | 0.813 | 0.006 |
| ModSecurity with CRS v4 (paranoia level 1) | 0.799 | 0.440 | 0.568 | 0.045 |
| Custom logistic regression | 0.651 | 0.423 | 0.512 | 0.092 |

Batch latency for the full pipeline with v1: mean 3.33 ms and 95th percentile
3.72 ms per request (`evaluation/results/latency_benchmark.csv`).

**Live replay through the proxy**

| Set | Model | Normal requests blocked | Attacks caught | F1 |
|-----|-------|-------------------------|----------------|----|
| Replay (43 attacks and 40 normal) | v1 | 15 of 40 | 43 of 43 | 0.851 |
| Replay (43 attacks and 40 normal) | v2 | 6 of 40 | 41 of 43 | 0.911 |
| Holdout (20 attacks and 40 normal) | v1 | 24 of 40 | 17 of 20 | 0.557 |
| Holdout (20 attacks and 40 normal) | v2 | 7 of 40 | 17 of 20 | 0.773 |

Raw output for every row above is saved in `evaluation/results/`.

## Known limitations

- The project target of F1 0.85 was not met (0.826 for v1 and 0.813 for v2).
- The proxy still blocks 15% to 17.5% of normal requests in the replay tests.
  In the replay run all 6 of those blocks came from the model (Case B) and
  none from the rules.
- The path and query are decoded once. Double encoded payloads and URL encoded
  form bodies can get through.
- The holdout set shows missed attacks for `/etc/group` and for the command
  injection payloads `| whoami` and `&& id`.
- The training data has little normal traffic with several parameters. The
  synthetic requests reduce this problem but do not remove it.
- v1 was saved with scikit-learn 1.9.0 and v2 with 1.9.1.

## Repository layout

| Folder or file | Contents |
|----------------|----------|
| `src/` | The six modules and the dashboard |
| `pipelines/` | Custom logistic regression and the Random Forest wrapper |
| `rules/` | Detection rules |
| `config/` | `waf_config.yaml` |
| `models/` | Trained models |
| `tests/` | Unit and integration tests |
| `demo/` | Interactive demo and sample log generator |
| `evaluation/` | Replay scripts and saved results |
| `datasets/` | Download instructions only (data is not committed) |
| `docs/` | LaTeX source for the deliverables |
