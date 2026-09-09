#!/usr/bin/env python3
"""Replay a labeled payload corpus through the lab target and record results.

Each payload is sent once with a fresh uuid4 in the X-Lab-Request-Id header.
That id is the correlation key: the WAF audit log and the app log both record
it, so report.py can later line up the WAF's decision with what the app did for
the exact same request.

Dependencies: requests, pyyaml, stdlib only.
"""
import argparse
import csv
import glob
import os
import sys
import time
import uuid
from datetime import datetime, timezone

import yaml
import requests

VALID_CATEGORIES = {"benign", "sqli", "xss", "traversal", "bruteforce", "enum"}
VALID_EXPECTED = {"allow", "block"}
REQUIRED = {"id", "category", "endpoint", "method", "params", "expected"}


def validate(entry, src):
    missing = REQUIRED - set(entry)
    if missing:
        raise SystemExit(f"{src}: payload {entry.get('id', '?')} missing fields {sorted(missing)}")
    if entry["category"] not in VALID_CATEGORIES:
        raise SystemExit(f"{src}: {entry['id']} bad category {entry['category']}")
    if entry["expected"] not in VALID_EXPECTED:
        raise SystemExit(f"{src}: {entry['id']} bad expected {entry['expected']}")


def load_sets(paths):
    payloads, seen = [], set()
    for p in paths:
        if os.path.isdir(p):
            files = sorted(glob.glob(os.path.join(p, "*.yaml")) +
                           glob.glob(os.path.join(p, "*.yml")))
        else:
            files = [p]
        for f in files:
            with open(f) as fh:
                docs = yaml.safe_load(fh) or []
            for entry in docs:
                # Fail loud on a malformed corpus. A silently dropped attack
                # payload would make the block rate look better than it is.
                validate(entry, f)
                if entry["id"] in seen:
                    raise SystemExit(f"duplicate payload id {entry['id']} in {f}")
                seen.add(entry["id"])
                payloads.append(entry)
    return payloads


def send_one(target, entry, timeout):
    request_id = str(uuid.uuid4())
    url = target.rstrip("/") + entry["endpoint"]
    method = entry.get("method", "GET").upper()
    params = entry.get("params") or {}
    headers = dict(entry.get("headers") or {})
    # The correlation id. Regenerated per send so replays never collide.
    headers["X-Lab-Request-Id"] = request_id

    try:
        if method == "GET":
            r = requests.get(url, params=params, headers=headers,
                             timeout=timeout, allow_redirects=False)
        else:
            # Do not follow redirects: a successful login or a stored comment
            # answers 302, and we want that status, not the redirect target's.
            r = requests.request(method, url, data=params, headers=headers,
                                 timeout=timeout, allow_redirects=False)
        status = r.status_code
    except requests.RequestException:
        # 0 marks a transport failure (timeout, connection refused). It is
        # distinct from any real HTTP status so the report never mistakes a
        # dropped connection for an allowed request.
        status = 0

    # CRS in blocking mode returns 403 when a rule fires. That is the signal.
    blocked = 1 if status == 403 else 0
    return {
        "request_id": request_id,
        "payload_id": entry["id"],
        "category": entry["category"],
        "expected": entry["expected"],
        "status": status,
        "blocked": blocked,
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
    }


def main():
    ap = argparse.ArgumentParser(description="Replay payloads through the lab target.")
    ap.add_argument("--set", action="append", required=True, dest="sets",
                    help="a YAML payload file or a directory of them (repeatable)")
    ap.add_argument("--label", required=True, help="names the output results/<label>.csv")
    ap.add_argument("--target", default="http://localhost:8080",
                    help="base URL of the entry point (default the app/WAF on 8080)")
    ap.add_argument("--delay", type=float, default=0.05,
                    help="seconds to sleep between requests")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="per-request timeout; raise it above any time-based SLEEP payload")
    args = ap.parse_args()

    payloads = load_sets(args.sets)
    if not payloads:
        raise SystemExit("no payloads loaded")

    os.makedirs("results", exist_ok=True)
    out_path = os.path.join("results", f"{args.label}.csv")
    cols = ["request_id", "payload_id", "category", "expected", "status", "blocked", "ts"]

    counts = {}
    with open(out_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for i, entry in enumerate(payloads, 1):
            row = send_one(args.target, entry, args.timeout)
            w.writerow(row)
            counts[row["category"]] = counts.get(row["category"], 0) + 1
            mark = "BLOCK" if row["blocked"] else f"{row['status']:>3}"
            print(f"[{i:>3}/{len(payloads)}] {mark}  {row['payload_id']}",
                  file=sys.stderr)
            if args.delay:
                time.sleep(args.delay)

    print(f"\nwrote {out_path}  ({len(payloads)} requests)")
    for cat in sorted(counts):
        print(f"  {cat:<11} {counts[cat]}")


if __name__ == "__main__":
    main()
