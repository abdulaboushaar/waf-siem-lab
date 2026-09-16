#!/usr/bin/env bash
#
# Paranoia sweep: for CRS paranoia levels 1..4, point the WAF at that level,
# replay the attack and benign corpora, let the SIEM ingest, and write a
# per-level results doc. Run from the harness/ directory:
#
#   ./run_matrix.sh
#
# Prerequisites:
#   - the lab stack is up (docker compose up -d in the repo root)
#   - harness/payloads/ has sqli.yaml, xss.yaml, traversal.yaml, benign.yaml
#   - the WAF rule engine is On (waf/common.env: MODSEC_RULE_ENGINE=On)
#
set -euo pipefail

cd "$(dirname "$0")"                       # harness/
REPO_ROOT="$(cd .. && pwd)"                # repo root, holds docker-compose.yml
PY="./.venv/bin/python"; [ -x "$PY" ] || PY="python3"
TARGET="http://localhost:8080"            # localhost, NOT 127.0.0.1 (rule 920350)

ATTACK_SETS=(--set payloads/sqli.yaml --set payloads/xss.yaml --set payloads/traversal.yaml)
BENIGN_SETS=(--set payloads/benign.yaml)

mkdir -p results "$REPO_ROOT/docs"

# Wait until the WAF answers on 8080. Any HTTP status (200, 403, ...) means it is
# up; only "000" means no connection yet.
wait_for_waf() {
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET/index.php" 2>/dev/null || echo 000)
    if [ "$code" != "000" ]; then
      echo "  WAF responding (HTTP $code)"
      return 0
    fi
    sleep 2
  done
  echo "  ERROR: WAF did not respond on 8080" >&2
  return 1
}

for PL in 1 2 3 4; do
  echo "=== Paranoia level $PL ==="

  # Switch the WAF to this paranoia level. Only the WAF container is recreated;
  # the app, db, normalizer and volumes stay up, so logs accumulate and the
  # request_id join in report.py keeps each run's numbers separate.
  ( cd "$REPO_ROOT" && WAF_PL="pl$PL" docker compose up -d --force-recreate waf )
  wait_for_waf

  # Replay. --timeout 15 so any time-based SLEEP payload is not misread as a
  # transport failure.
  $PY replay.py "${ATTACK_SETS[@]}" --label "pl$PL-attacks" --target "$TARGET" --timeout 15
  $PY replay.py "${BENIGN_SETS[@]}" --label "pl$PL-benign"  --target "$TARGET" --timeout 15

  echo "  waiting 30s for SIEM ingestion..."
  sleep 30

  # Snapshot the logs report.py joins against (they live inside the containers).
  ( cd "$REPO_ROOT" && docker compose exec -T app       cat /var/log/app/app.log )          > results/app.log
  ( cd "$REPO_ROOT" && docker compose exec -T normalizer cat /var/log/lab/waf_events.jsonl ) > results/waf_events.jsonl

  # Per-level results doc.
  {
    echo "# Results: paranoia level $PL"
    echo
    echo "_Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by run_matrix.sh_"
    echo
    echo "## Attacks (expected: block)"
    echo
    $PY report.py --label "pl$PL-attacks"
    echo
    echo "## Benign (expected: allow)"
    echo
    $PY report.py --label "pl$PL-benign"
  } > "$REPO_ROOT/docs/results-pl$PL.md"

  echo "  wrote docs/results-pl$PL.md"
done

echo
echo "All levels done. Build the summary with:  $PY summarize.py"
