#!/usr/bin/env python3
"""Turn a raw PayloadsAllTheThings payload file into a cited YAML payload set.

You copy a raw list (one payload per line) into payloads/raw/<name>.txt, then
run this once per style. It reads N lines and emits schema-conformant YAML with
a per-entry `source` that pins the upstream repo, commit and line number, so the
provenance of every attack payload is auditable. It never invents a payload.

Example:
  python3 build_attacks.py \
      --raw raw/sqli_auth_bypass.txt \
      --category sqli --style classic \
      --endpoint /search.php --param q \
      --commit 3f1a9c2 \
      --src-path "SQL Injection/Intruder/Auth_Bypass.txt" \
      --limit 10 --out sqli.yaml --append

The correlation between --param and the endpoint is up to you: search.php reads
q, download.php reads file, and so on.
"""
import argparse
import os
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = "PayloadsAllTheThings"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True, help="raw/<file>.txt, one payload per line")
    ap.add_argument("--category", required=True, choices=["sqli", "xss", "traversal"])
    ap.add_argument("--style", required=True,
                    help="classic|comment|encoding|time|scripttag|eventhandler|encoded|...")
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--param", required=True, help="query/form field the payload goes into")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--commit", required=True, help="short commit hash you copied from")
    ap.add_argument("--src-path", required=True, help="path of the file inside the repo")
    ap.add_argument("--limit", type=int, default=0, help="take the first N non-blank lines (0 = all)")
    ap.add_argument("--out", required=True, help="output yaml filename in this dir")
    ap.add_argument("--append", action="store_true", help="append to --out instead of overwriting")
    args = ap.parse_args()

    raw_path = args.raw if os.path.isabs(args.raw) else os.path.join(HERE, args.raw)
    rows = []
    kept = 0
    with open(raw_path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            payload = line.rstrip("\n")
            # Skip blank lines and comment markers a raw file may carry, but
            # count the real source line number so the citation is exact.
            if payload.strip() == "" or payload.lstrip().startswith("#"):
                continue
            if args.limit and kept >= args.limit:
                break
            kept += 1
            pid = f"{args.category}-{args.style}-{kept:03d}"
            rows.append({
                "id": pid,
                "category": args.category,
                "endpoint": args.endpoint,
                "method": args.method,
                "params": {args.param: payload},
                "expected": "block",  # signature payloads CRS is meant to catch
                "source": f"{REPO}@{args.commit}:{args.src_path}:L{lineno}",
            })

    out_path = os.path.join(HERE, args.out)
    existing = []
    if args.append and os.path.exists(out_path):
        with open(out_path) as fh:
            existing = yaml.safe_load(fh) or []
    combined = existing + rows

    ids = [r["id"] for r in combined]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise SystemExit(f"duplicate ids after merge: {sorted(dupes)}")

    with open(out_path, "w") as fh:
        yaml.safe_dump(combined, fh, sort_keys=False, allow_unicode=True, width=1000)
    print(f"{args.out}: +{len(rows)} {args.category}/{args.style}  (total {len(combined)})")


if __name__ == "__main__":
    main()
