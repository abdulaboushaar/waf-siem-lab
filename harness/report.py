#!/usr/bin/env python3
"""Join replay results with the WAF and app logs on request_id, and report.

Three inputs, keyed on the correlation id:
  results/<label>.csv       what the replay sent and the status it got back
  waf_events.jsonl          normalizer output, one flat JSON object per WAF event
  app.log                   the app's own log, one JSON object per request

The WAF log and the app log arrive in later steps. If either file is missing
this still runs and reports what it can, so the harness is usable before the
SIEM pipeline exists. reached_app is only trustworthy once app.log is wired in.

Dependencies: stdlib only.
"""
import argparse
import csv
import json
import os
from collections import defaultdict


def load_app_log(path):
    # request_id -> {"reached": True, "db_error": bool}
    index = {}
    if not path or not os.path.exists(path):
        return index, False
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rid = rec.get("request_id")
            if not rid or rid == "none":
                continue
            index[rid] = {
                "reached": True,
                "db_error": bool(rec.get("db_error")),
            }
    return index, True


def load_waf_events(path):
    # request_id -> True (the WAF logged an event for this request)
    index = {}
    if not path or not os.path.exists(path):
        return index, False
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rid = rec.get("request_id")
            if rid and rid != "none":
                index[rid] = True
    return index, True


def pct(num, den):
    return round(100.0 * num / den, 1) if den else 0.0


def main():
    ap = argparse.ArgumentParser(description="Report on a replay run.")
    ap.add_argument("--label", required=True, help="reads results/<label>.csv")
    ap.add_argument("--results-dir", default="results")
    ap.add_argument("--waf-events", default=None,
                    help="path to normalizer output (default results/waf_events.jsonl)")
    ap.add_argument("--app-log", default=None,
                    help="path to the app log (default results/app.log)")
    args = ap.parse_args()

    results_csv = os.path.join(args.results_dir, f"{args.label}.csv")
    if not os.path.exists(results_csv):
        raise SystemExit(f"no results at {results_csv}; run replay.py --label {args.label} first")

    waf_path = args.waf_events or os.path.join(args.results_dir, "waf_events.jsonl")
    app_path = args.app_log or os.path.join(args.results_dir, "app.log")
    app_index, app_present = load_app_log(app_path)
    waf_index, waf_present = load_waf_events(waf_path)

    with open(results_csv, newline="") as fh:
        rows = list(csv.DictReader(fh))

    # Aggregate per category.
    agg = defaultdict(lambda: {"sent": 0, "blocked": 0, "reached_app": 0,
                               "db_error": 0, "expected_block": 0})
    for r in rows:
        cat = r["category"]
        a = agg[cat]
        a["sent"] += 1
        if r["blocked"] == "1":
            a["blocked"] += 1
        if r["expected"] == "block":
            a["expected_block"] += 1
        info = app_index.get(r["request_id"])
        if info:
            a["reached_app"] += 1
            if info["db_error"]:
                a["db_error"] += 1

    # Per-category rows. block_rate means detection for attack categories and
    # false-positive rate for benign; the callout below states each plainly.
    report = {"label": args.label, "categories": {}, "notes": []}
    for cat in sorted(agg):
        a = agg[cat]
        report["categories"][cat] = {
            "sent": a["sent"],
            "blocked": a["blocked"],
            "reached_app": a["reached_app"],
            "db_error_count": a["db_error"],
            "block_rate_pct": pct(a["blocked"], a["sent"]),
        }

    benign = agg.get("benign", {"sent": 0, "blocked": 0})
    fp_rate = pct(benign["blocked"], benign["sent"])
    report["benign_false_positive_rate_pct"] = fp_rate

    if not app_present:
        report["notes"].append(
            f"app log not found at {app_path}: reached_app and db_error_count are 0 (wired in Step 4).")
    if not waf_present:
        report["notes"].append(
            f"waf events not found at {waf_path}: WAF-side view unavailable (wired in Step 3).")

    # Markdown.
    md = []
    md.append(f"# Replay report: {args.label}\n")
    md.append("| Category | Sent | Blocked | Reached app | DB errors | Block rate |")
    md.append("|----------|-----:|--------:|------------:|----------:|-----------:|")
    for cat in sorted(report["categories"]):
        c = report["categories"][cat]
        md.append(f"| {cat} | {c['sent']} | {c['blocked']} | {c['reached_app']} "
                  f"| {c['db_error_count']} | {c['block_rate_pct']}% |")
    md.append("")
    md.append(f"**Benign false positive rate: {fp_rate}%** "
              f"({benign['blocked']} of {benign['sent']} benign requests blocked)")
    md.append("")
    for note in report["notes"]:
        md.append(f"> note: {note}")
    md_text = "\n".join(md)

    json_path = os.path.join(args.results_dir, f"{args.label}_report.json")
    with open(json_path, "w") as fh:
        json.dump(report, fh, indent=2)

    print(md_text)
    print(f"\n(wrote {json_path})")


if __name__ == "__main__":
    main()
