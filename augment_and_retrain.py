"""
augment_and_retrain.py
Hybrid WAF -- IT28X87 Honours Project
Mbadaliga, AB (219044112)

Tries to fix the false positives on normal requests.

Why: the replay test (93 requests through the live proxy) blocked 15 of
40 normal requests. The training data has almost no normal short or
multi parameter requests, so the Random Forest learned that this region
of the six features is attack. Also 259 CSIC attack rows have no text
at all (only spaces, "/" or "/~"), so an empty request was labelled
attack.

What this script does:
  1. Rebuilds the SAME 80/20 split as train_models.py (stratified,
     random_state=42), so the test set is the same 25,627 rows.
  2. Drops the 259 empty attack rows from the TRAINING part only.
  3. Adds synthetic normal requests to the TRAINING part only.
  4. Trains a Random Forest with the same settings as before.
  5. Scores the old and the new model on the untouched test set
     (ml_only and hybrid) and prints a PASS or FAIL for the first limit.
  6. Saves the new model to a NEW file. The old model is not changed.

Limits that were fixed BEFORE running (see the project notes):
  - hybrid F1 on the original test set must stay at or above 0.80
  - false positive rate on the 40 normal replay requests must be 0.20
    or lower (checked after this, with replay_attacks.py through the proxy)
  - recall on the 43 replay attacks must stay at or above 0.90 (same)
If any limit fails the old model stays and the finding is reported as
a limitation.

The synthetic requests are made by code written with AI help. The
word lists below are kept different from the words in
evaluation/replay_attacks.py and evaluation/replay_holdout.py, so the
model is not simply memorising the test words.

Run from the repo root:
    python3 augment_and_retrain.py
"""
import os
import sys
import random
import pickle
import argparse
import urllib.parse

import numpy as np
from sklearn.model_selection import train_test_split

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
sys.path.insert(0, os.path.join(REPO_ROOT, "pipelines"))
from feature_extractor import FeatureExtractor, HTTPRequest  # noqa: E402
from rule_engine import RuleEngine  # noqa: E402
from decision_engine import DecisionEngine  # noqa: E402
from random_forest import RandomForestModel  # noqa: E402
from evaluate_configurations import (  # noqa: E402
    MLResult, load_dataset_with_text, evaluate,
)

DATA_PATH = os.path.join(REPO_ROOT, "data", "merged_dataset.csv")
RULES_PATH = os.path.join(REPO_ROOT, "rules", "rules.txt")
OLD_MODEL = os.path.join(REPO_ROOT, "models", "pipeline2_random_forest.pkl")
NEW_MODEL = os.path.join(REPO_ROOT, "models", "pipeline2_random_forest_aug.pkl")

N_SYNTHETIC = 4000     # about 4% of the training rows, chosen once and not tuned
SEED = 42

# ---------------------------------------------------------------- vocabulary
PATHS = ["/shop", "/catalog", "/blog", "/news", "/forum/thread", "/account/settings",
         "/api/widgets", "/gallery", "/events", "/download", "/faq", "/support/tickets",
         "/profile", "/outlet/deals", "/jobs", "/careers", "/manuals/guide", "/members",
         "/reports/monthly", "/schedule"]
SHORT_PATHS = ["/", "/home", "/faq", "/news", "/blog", "/jobs", "/events", "/gallery",
               "/home.htm", "/reach-us.htm", "/terms", "/privacy", "/sitemap.xml",
               "/favicon.ico", "/manifest.json", "/logout", "/register", "/dashboard"]
KEYS = ["term", "keyword", "sort_by", "limit", "offset", "view", "tab", "section",
        "ticket", "lang_code", "year", "month", "filter", "start", "end", "rating",
        "brand", "colour", "group", "uid", "tid", "post", "topic", "region", "mode"]
WORDS = ["garden", "kettle", "notebook", "bicycle", "coffee", "guitar", "hiking",
         "tickets", "resume", "invoice", "winter", "museum", "pizza", "camera",
         "backpack", "sneakers", "headphones", "printer", "blanket", "umbrella",
         "football", "recipe", "holiday", "concert", "tractor", "sunscreen"]
NAMES = ["Sipho", "Lerato", "Naledi", "Pieter", "Zanele", "Mary-Jane", "D'Angelo",
         "Nomsa", "Kagiso", "Johan", "Fatima", "Tshepo", "Anke", "Mpho-Lee"]
PHRASES = ["where can I buy a used bicycle", "buy from the winter sale or the summer sale",
           "please delete my old account", "how to insert a new sim",
           "update my phone number", "select the green one", "union of south africa history",
           "drop off point near me", "where do I find my receipt",
           "it's not working for me", "I don't see my parcel", "shoe 9 (wide fit)",
           "from monday to friday", "buy one get one free", "best pizza nearby",
           "set up a new pin", "what's on this weekend", "return or swap",
           "where is my parcel from last week", "two-factor guidance"]
FORM_KEYS = ["fullname", "phone", "message", "subject", "address", "suburb", "company"]


def make_values(rng):
    """Picks one value of a random kind for a query parameter."""
    kind = rng.choice(["num", "word", "name", "date", "email", "phrase", "words2"])
    if kind == "num":
        return str(rng.randint(1, 5000))
    if kind == "word":
        return rng.choice(WORDS)
    if kind == "name":
        return rng.choice(NAMES)
    if kind == "date":
        return "%d-%02d-%02d" % (rng.randint(2022, 2026), rng.randint(1, 12), rng.randint(1, 28))
    if kind == "email":
        return rng.choice(NAMES).lower().replace("'", "") + "@mail.co.za"
    if kind == "phrase":
        return rng.choice(PHRASES)
    return rng.choice(WORDS) + " " + rng.choice(WORDS)


def make_requests(n, seed=SEED):
    """
    Returns n synthetic normal requests as (method, path, query, body).
    Mix (fixed, not tuned): 60% GET with 1 to 3 parameters, 10% GET with
    a path only, 15% GET with a natural language sentence (this is where
    the SQL words and quotes show up in normal use), 15% POST forms.
    """
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        roll = rng.random()
        if roll < 0.60:
            k = rng.choice([1, 2, 2, 3])
            keys = rng.sample(KEYS, k)
            qs = "&".join("%s=%s" % (key, make_values(rng)) for key in keys)
            out.append(("GET", rng.choice(PATHS), qs, ""))
        elif roll < 0.70:
            out.append(("GET", rng.choice(SHORT_PATHS), "", ""))
        elif roll < 0.85:
            qs = "%s=%s" % (rng.choice(["term", "keyword", "message", "subject"]),
                            rng.choice(PHRASES))
            if rng.random() < 0.4:
                qs += "&%s=%s" % (rng.choice(KEYS), make_values(rng))
            out.append(("GET", rng.choice(PATHS), qs, ""))
        else:
            fields = rng.sample(FORM_KEYS, rng.choice([2, 3, 4]))
            pairs = [(f, make_values(rng)) for f in fields]
            # a browser leaves the body percent encoded and the proxy does
            # not decode bodies, so the training body is encoded as well
            out.append(("POST", rng.choice(PATHS), "", urllib.parse.urlencode(pairs)))
    return out


def to_features(extractor, reqs):
    """Runs the REAL FeatureExtractor, same as the live proxy and build_dataset.py."""
    texts, feats = [], []
    for method, path, qs, body in reqs:
        req = HTTPRequest(method=method, path=path, query_string=qs,
                          headers={}, body=body)
        texts.append(req.full_text())
        feats.append(extractor.extract(req).to_list())
    return texts, np.array(feats, dtype=np.float64)


def score(model, rule_results, X, y, label):
    """ml_only and hybrid metrics for one model on one set."""
    probs = model.model.predict_proba(model.scaler.transform(X))[:, 1]
    ml_only, hybrid = [], []
    de_h = DecisionEngine(mode="hybrid", threshold=0.5)
    for rr, p in zip(rule_results, probs):
        ml_only.append(1 if p >= 0.5 else 0)
        hybrid.append(1 if de_h.decide(rr, MLResult(probability=float(p))).is_block() else 0)
    m_ml = evaluate(label + " ml_only", y, ml_only)
    m_hy = evaluate(label + " hybrid", y, hybrid)
    return m_ml, m_hy, probs


def load_model(path):
    m = RandomForestModel()
    with open(path, "rb") as f:
        d = pickle.load(f)
    m.model, m.scaler, m.trained = d["model"], d["scaler"], d["trained"]
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DATA_PATH)
    ap.add_argument("--out", default=NEW_MODEL)
    ap.add_argument("--n", type=int, default=N_SYNTHETIC)
    args = ap.parse_args()

    print("Loading dataset...")
    raw, X, y = load_dataset_with_text(args.data)
    raw_tr, raw_te, X_tr, X_te, y_tr, y_te = train_test_split(
        raw, X, y, test_size=0.2, stratify=y, random_state=42)
    print("  train %d  test %d  (same split as train_models.py)" % (len(y_tr), len(y_te)))

    # 1. drop the empty attack rows from the training part only
    empty = np.array([(lab == 1 and len(t.strip()) <= 3) for t, lab in zip(raw_tr, y_tr)])
    empty_te = np.array([(lab == 1 and len(t.strip()) <= 3) for t, lab in zip(raw_te, y_te)])
    print("  empty attack rows: %d in train (dropped)  %d in test (kept)"
          % (empty.sum(), empty_te.sum()))
    X_keep, y_keep = X_tr[~empty], y_tr[~empty]

    # 2. add the synthetic normal requests
    ext = FeatureExtractor()
    syn_text, X_syn = to_features(ext, make_requests(args.n))
    y_syn = np.zeros(len(X_syn), dtype=np.int64)
    print("  synthetic normal requests added: %d" % len(X_syn))
    print("  sample: %r" % syn_text[:3])

    X_new = np.vstack([X_keep, X_syn])
    y_new = np.concatenate([y_keep, y_syn])
    print("  new training set: %d rows (benign %d  attack %d)"
          % (len(y_new), (y_new == 0).sum(), (y_new == 1).sum()))

    # 3. train with the same settings as train_models.py
    print("\nTraining Random Forest (100 trees  depth 10  seed 42  n_jobs 1)...")
    new = RandomForestModel()
    new.model.n_jobs = 1
    new.fit(X_new, y_new)
    new.save(args.out)

    # 4. score old and new on the untouched test set
    print("\nScoring the test set with the rule engine (once)...")
    engine = RuleEngine(RULES_PATH)
    rule_results = [engine.evaluate(t) for t in raw_te]
    old = load_model(OLD_MODEL)

    print("\n================ OLD MODEL, original test set ================")
    _, old_hy, old_p = score(old, rule_results, X_te, y_te, "old")
    print("\n================ NEW MODEL, original test set ================")
    _, new_hy, new_p = score(new, rule_results, X_te, y_te, "new")

    # same comparison without the empty attack rows, for the write up only
    keep = ~empty_te
    rr_keep = [r for r, k in zip(rule_results, keep) if k]
    print("\n---- same test set without its %d empty attack rows (information only) ----"
          % empty_te.sum())
    score(old, rr_keep, X_te[keep], y_te[keep], "old, no empties")
    score(new, rr_keep, X_te[keep], y_te[keep], "new, no empties")

    # 5. a few direct probes, old against new
    print("\n---- direct probes (probability of attack, old -> new) ----")
    probes = [("GET", "/", "", ""),
              ("GET", "/products", "page=2&sort=price", ""),
              ("GET", "/archive", "year=2025&month=7", ""),
              ("GET", "/search", "q=blue socks", ""),
              ("GET", "/item", "id=1' OR '1'='1", ""),
              ("GET", "/", "id=CASE WHEN 1=1 THEN 1 ELSE 0 END", "")]
    pt, pX = to_features(ext, probes)
    po = old.model.predict_proba(old.scaler.transform(pX))[:, 1]
    pn = new.model.predict_proba(new.scaler.transform(pX))[:, 1]
    for t, a, b in zip(pt, po, pn):
        print("  %-55r %.4f -> %.4f" % (t, a, b))

    # 6. first limit
    print("\n================ FIRST LIMIT ================")
    ok = new_hy["f1"] >= 0.80
    print("hybrid F1 on original test set: old %.4f  new %.4f  (limit 0.80)  %s"
          % (old_hy["f1"], new_hy["f1"], "PASS" if ok else "FAIL"))
    print("Next: point config models.rf_model_path at %s and run replay_attacks.py"
          % os.path.relpath(args.out, REPO_ROOT))
    print("The other two limits (replay FPR <= 0.20  replay recall >= 0.90) are checked there.")


if __name__ == "__main__":
    main()
