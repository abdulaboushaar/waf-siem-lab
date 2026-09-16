#!/usr/bin/env python3
"""Summarize the paranoia sweep into one table across PL1..PL4.

Reads the per-run report JSON files that report.py writes
(results/pl<N>-attacks_report.json and results/pl<N>-benign_report.json) and
prints one row per paranoia level. Also writes docs/summary.md.

Columns:
  PL | attacks blocked | attacks reached app | SQLi that errored the DB
     | benign blocked | FP rate

Standard library only. Run from the harness/ directory after run_matrix.sh.
"""
import json
import os

RESULTS = "results"
DOCS = os.path.join("..", "docs")
ATTACK_CATS = ("sqli", "xss", "traversal")


def load(label):
    path = os.path.join(RESULTS, f"{label}_report.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def pct(num, den):
    return round(100.0 * num / den, 1) if den else 0.0


def main():
    rows = []
    for pl in (1, 2, 3, 4):
        atk = load(f"pl{pl}-attacks")
        ben = load(f"pl{pl}-benign")
        if atk is None or ben is None:
            rows.append((pl, None))
            continue

        cats = atk.get("categories", {})
        sent = sum(cats.get(c, {}).get("sent", 0) for c in ATTACK_CATS)
        blocked = sum(cats.get(c, {}).get("blocked", 0) for c in ATTACK_CATS)
        reached = sum(cats.get(c, {}).get("reached_app", 0) for c in ATTACK_CATS)
        sqli_dberr = cats.get("sqli", {}).get("db_error_count", 0)

        bcats = ben.get("categories", {})
        b = bcats.get("benign", {})
        b_sent = b.get("sent", 0)
        b_blocked = b.get("blocked", 0)
        fp = ben.get("benign_false_positive_rate_pct", pct(b_blocked, b_sent))

        rows.append((pl, {
            "atk_blocked": blocked, "atk_sent": sent,
            "atk_reached": reached, "sqli_dberr": sqli_dberr,
            "ben_blocked": b_blocked, "ben_sent": b_sent, "fp": fp,
        }))

    md = []
    md.append("# Paranoia sweep summary\n")
    md.append("| PL | Attacks blocked | Attacks reached app | SQLi errored DB | Benign blocked | FP rate |")
    md.append("|----|-----------------|---------------------|-----------------|----------------|--------:|")
    for pl, r in rows:
        if r is None:
            md.append(f"| {pl} | (no data) | | | | |")
            continue
        blk = f"{r['atk_blocked']}/{r['atk_sent']} ({pct(r['atk_blocked'], r['atk_sent'])}%)"
        ben = f"{r['ben_blocked']}/{r['ben_sent']}"
        md.append(f"| {pl} | {blk} | {r['atk_reached']} | {r['sqli_dberr']} "
                  f"| {ben} | {r['fp']}% |")
    md.append("")
    md.append("Attacks blocked and benign blocked come from the HTTP response the "
              "WAF returned (403). Attacks reached app and SQLi errored DB come "
              "from the app log, joined on request_id. FP rate is benign blocked "
              "over benign sent.")
    text = "\n".join(md)

    os.makedirs(DOCS, exist_ok=True)
    out = os.path.join(DOCS, "summary.md")
    with open(out, "w") as f:
        f.write(text + "\n")
    print(text)
    print(f"\n(wrote {out})")


if __name__ == "__main__":
    main()
