# Results: paranoia level 3

_Generated 2026-09-16T03:08:23Z by run_matrix.sh_

## Attacks (expected: block)

# Replay report: pl3-attacks

| Category | Sent | Blocked | Reached app | DB errors | Block rate |
|----------|-----:|--------:|------------:|----------:|-----------:|
| sqli | 40 | 34 | 2 | 0 | 85.0% |
| traversal | 20 | 20 | 0 | 0 | 100.0% |
| xss | 30 | 20 | 10 | 0 | 66.7% |

**Benign false positive rate: 0.0%** (0 of 0 benign requests blocked)


(wrote results/pl3-attacks_report.json)

## Benign (expected: allow)

# Replay report: pl3-benign

| Category | Sent | Blocked | Reached app | DB errors | Block rate |
|----------|-----:|--------:|------------:|----------:|-----------:|
| benign | 100 | 19 | 81 | 10 | 19.0% |

**Benign false positive rate: 19.0%** (19 of 100 benign requests blocked)


(wrote results/pl3-benign_report.json)
