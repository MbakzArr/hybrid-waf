#!/usr/bin/env python3
"""
replay_holdout.py - a second replay set that was written BEFORE the
retrained model existed. replay_attacks.py was used to find the false
positive problem, so it is no longer a clean test of the fix. This set
uses different paths and words and was never used to build or tune
anything.

    python3 evaluation/replay_holdout.py --target http://localhost:8080

Uses send() and the helpers from replay_attacks.py (same folder).
Same rule as before: 403 = blocked, 502 or no answer = error.
"""
import os
import sys
import argparse
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from replay_attacks import send, enc_query, q  # noqa: E402

ATTACKS = [
    # (path, raw payload sent as the value of one parameter)
    ("/members", "id", "1' OR 'x'='x"),
    ("/members", "id", "admin' OR '1'='1'--"),
    ("/members", "id", "1 UNION ALL SELECT 1,2,3--"),
    ("/orders", "ref", "'; DROP TABLE orders;--"),
    ("/orders", "ref", "1' AND 1=2 UNION SELECT username,pass FROM members--"),
    ("/orders", "ref", "x' OR 1=1 LIMIT 1--"),
    ("/orders", "ref", "1; DELETE FROM sessions WHERE 1=1--"),
    ("/view", "page", "<script>alert('xss')</script>"),
    ("/view", "page", "<img src=1 onerror=alert(2)>"),
    ("/view", "page", "<svg/onload=alert(3)>"),
    ("/view", "page", "'><script>alert(5)</script>"),
    ("/view", "page", "<body onload=alert(6)>"),
    ("/files", "name", "../../../../etc/hosts"),
    ("/files", "name", "..\\..\\boot.ini"),
    ("/files", "name", "/etc/group"),
    ("/ping", "host", "127.0.0.1; cat /etc/passwd"),
    ("/ping", "host", "8.8.8.8 | whoami"),
    ("/ping", "host", "localhost && id"),
    ("/members", "id", "1 OR 2>1"),
    ("/members", "id", "1' OR SLEEP(3)#"),
]

# normal traffic: (path, query string written the way a person would type it)
LEGIT = [
    ("/bargains", "maker=Nike&shade=black"), ("/bargains", "maker=Puma"),
    ("/toys", "kind=lego&take=20&skip=40"), ("/toys", "layout=grid"),
    ("/weather", "area=gauteng&regarding=rain"), ("/bulletin/2026/10", ""),
    ("/discuss", "post_id=9912&p=3"), ("/discuss", "post_id=9912"),
    ("/preferences", "pane=billing"), ("/preferences", "pane=security&src=sms"),
    ("/rest/v1/gizmos", "gid=8841"), ("/rest/v1/gizmos", "p=2&rows=25"),
    ("/shows", "day_of=2026-12-24"), ("/shows", "place=Durban&genre=music"),
    ("/papers", "doc=annual-report.pdf"), ("/pictures", "pic_set=17&latest=1"),
    ("/vacancies", "lookup=data analyst&place=Pretoria"), ("/vacancies", "pg=4"),
    ("/hotels", "adults=2&children=1&nights=3"), ("/hotels", "place=Knysna"),
    ("/signin", "goto=/preferences"), ("/unsubscribe", "sub=3382&code=9f8e7d"),
    ("/track", "consignment=ZA1234567"), ("/rates", "from=ZAR&to=USD"),
    ("/menu", "day=tuesday"), ("/photos", "when=2024"),
    ("/", ""), ("/welcome.html", ""), ("/conditions", ""), ("/health", ""),
]
# normal text that looks a little like SQL or code, one parameter each
LEGIT_HARD = [
    "ask=is it open now", "remark=kindly update or cancel my booking",
    "memo=select seat 12A", "surname=D'Souza", "label=Rock & Roll (live)",
    "words=delete this draft", "info=open from 9 to 5", "ask=insert card now",
    "memo=drop the keys at reception", "ask=1 or 2 nights",
]


def build():
    reqs = []
    for path, key, val in ATTACKS:
        reqs.append(("attack", "block", path, key + "=" + q(val)))
    for path, qs in LEGIT:
        reqs.append(("legit", "allow", path, enc_query(qs)))
    for qs in LEGIT_HARD:
        k, _, v = qs.partition("=")
        reqs.append(("legit_hard", "allow", "/search", k + "=" + q(v)))
    return reqs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://localhost:8080")
    args = ap.parse_args()
    u = urllib.parse.urlsplit(args.target)
    host, port = u.hostname, u.port or 80

    tp = fn = fp = tn = err = 0
    wrong = []
    for group, expect, path, qs in build():
        status, _text, _ms = send(host, port, "GET", path, qs, "")
        if status in (0, 502):
            err += 1
            continue
        got = "block" if status == 403 else "allow"
        if expect == "block":
            tp += got == "block"
            fn += got == "allow"
        else:
            fp += got == "block"
            tn += got == "allow"
        if got != expect:
            wrong.append((group, "MISSED" if expect == "block" else "FALSE POSITIVE",
                          path + "?" + qs[:70]))

    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    print("\nHoldout set against %s  |  errors %d" % (args.target, err))
    print("  attacks %d  normal %d" % (tp + fn, fp + tn))
    print("  TP %d   FN %d   FP %d   TN %d" % (tp, fn, fp, tn))
    print("  precision %.3f   recall %.3f   F1 %.3f   FPR %.3f" % (prec, rec, f1, fpr))
    print("\nMismatches:")
    for g, what, r in wrong:
        print("  %-15s[%s] %s" % (what, g, r))
    if not wrong:
        print("  none")


if __name__ == "__main__":
    main()
