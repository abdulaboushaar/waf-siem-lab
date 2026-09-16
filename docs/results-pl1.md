# Results: paranoia level 1

_Generated 2026-09-16T03:06:56Z by run_matrix.sh_

## Attacks (expected: block)

# Replay report: pl1-attacks

| Category | Sent | Blocked | Reached app | DB errors | Block rate |
|----------|-----:|--------:|------------:|----------:|-----------:|
| sqli | 40 | 29 | 7 | 2 | 72.5% |
| traversal | 20 | 20 | 0 | 0 | 100.0% |
| xss | 30 | 20 | 10 | 0 | 66.7% |

**Benign false positive rate: 0.0%** (0 of 0 benign requests blocked)


(wrote results/pl1-attacks_report.json)

## Benign (expected: allow)

# Replay report: pl1-benign

| Category | Sent | Blocked | Reached app | DB errors | Block rate |
|----------|-----:|--------:|------------:|----------:|-----------:|
| benign | 100 | 4 | 96 | 10 | 4.0% |

**Benign false positive rate: 4.0%** (4 of 100 benign requests blocked)


(wrote results/pl1-benign_report.json)
