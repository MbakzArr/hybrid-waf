# Hybrid Web Application Firewall

**Honours Year Project – IT28X87**
University of Johannesburg, Academy of Computer Science and Software Engineering

**Student:** Mbadaliga, AB (219044112)
**Supervisor:** [Your supervisor's name]

## Project Summary

This project designs and evaluates a hybrid Web Application Firewall (WAF) that
combines a rule-based detection engine with a lightweight machine learning classifier.
The system targets SQL Injection, Cross-Site Scripting (XSS), and Path Traversal attacks.

## Repository Structure

| Folder | Contents |
|--------|----------|
| `src/` | Core pipeline modules (Traffic Reader, Feature Extractor, Rule Engine, ML Classifier, Decision Engine, Logger) |
| `pipelines/` | Pipeline 1 (custom Logistic Regression) and Pipeline 2 (scikit-learn Random Forest) |
| `rules/` | Plain-text WAF detection rules |
| `config/` | System configuration files |
| `tests/` | Unit and integration test suites |
| `demo/` | Demo script for live testing against DVWA and Juice Shop |
| `datasets/` | Dataset download instructions (data not committed) |
| `evaluation/` | Evaluation results and analysis scripts |
| `docs/` | LaTeX source for all project deliverables |

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run Demo

```bash
python demo/demo.py
```

## Requirements

- Python 3.10+
- Ubuntu 22.04 (VM recommended for isolation)
- See requirements.txt for Python dependencies
