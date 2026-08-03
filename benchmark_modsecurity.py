"""
benchmark_modsecurity.py
Hybrid WAF -- IT28X87 Honours Project
Mbadaliga, AB (219044112)

Fires every request in the held-out test set at the local Apache +
ModSecurity + OWASP CRS v4 instance and records whether it was
blocked (403) or allowed (anything else), then computes the same
precision/recall/F1/FPR metrics reported for every other
configuration in this project.

Uses only the Python standard library (urllib), no extra packages
needed on the VM.

Run on the VM, after modsec_test_set.csv has been copied over:
    python3 benchmark_modsecurity.py

Output:
    modsecurity_results.csv (raw metrics + confusion matrix)
"""
import csv
import time
import urllib.request
import urllib.parse
import urllib.error

INPUT_PATH = "modsec_test_set.csv"
OUTPUT_PATH = "modsecurity_results.csv"
TARGET_URL = "http://localhost/"
TIMEOUT = 5


def send_request(raw_text):
    """
    Sends raw_text as a URL-encoded query parameter value. Returns the
    HTTP status code, or None if the request failed entirely (treated
    as a separate error count, not silently folded into either class).
    """
    encoded = urllib.parse.urlencode({"payload": raw_text})
    url = f"{TARGET_URL}?{encoded}"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        # ModSecurity blocks return here, not as a normal 200 response
        return e.code
    except Exception:
        return None


def main():
    print(f"Loading test set from {INPUT_PATH}...")
    rows = []
    with open(INPUT_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append((row["raw_text"], int(row["label"])))
    n = len(rows)
    print(f"  Loaded {n} rows.")

    tp = fp = tn = fn = errors = 0
    t_start = time.time()

    for i, (text, label) in enumerate(rows):
        status = send_request(text)

        if status is None:
            errors += 1
        else:
            predicted_attack = (status == 403)
            if label == 1 and predicted_attack:
                tp += 1
            elif label == 1 and not predicted_attack:
                fn += 1
            elif label == 0 and predicted_attack:
                fp += 1
            else:
                tn += 1

        if (i + 1) % 1000 == 0:
            elapsed = time.time() - t_start
            rate = (i + 1) / elapsed
            remaining = (n - (i + 1)) / rate if rate > 0 else 0
            print(f"  {i + 1}/{n} done, {rate:.1f} req/s, "
                  f"~{remaining/60:.1f} min remaining")

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    print(f"\nTP={tp} FP={fp} TN={tn} FN={fn} ERRORS={errors}")
    print(f"Accuracy={accuracy:.4f} Precision={precision:.4f} "
          f"Recall={recall:.4f} F1={f1:.4f} FPR={fpr:.4f}")

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["pipeline", "accuracy", "precision", "recall",
                          "f1", "fpr", "tp", "fp", "tn", "fn", "errors"])
        writer.writerow(["modsecurity_crs_v4", round(accuracy, 4),
                          round(precision, 4), round(recall, 4),
                          round(f1, 4), round(fpr, 4), tp, fp, tn, fn, errors])

    print(f"\nDone. Written to {OUTPUT_PATH}")
    if errors > 0:
        print(f"WARNING: {errors} requests failed entirely (connection "
              f"error or timeout), excluded from the metrics above. If "
              f"this number is large relative to {n}, investigate before "
              f"trusting these numbers.")


if __name__ == "__main__":
    main()
