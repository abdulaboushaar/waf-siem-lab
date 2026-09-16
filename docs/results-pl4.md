# Results: paranoia level 4

_Generated 2026-09-16T03:09:06Z by run_matrix.sh_

## Attacks (expected: block)

# Replay report: pl4-attacks

| Category | Sent | Blocked | Reached app | DB errors | Block rate |
|----------|-----:|--------:|------------:|----------:|-----------:|
| sqli | 40 | 34 | 2 | 0 | 85.0% |
| traversal | 20 | 20 | 0 | 0 | 100.0% |
| xss | 30 | 20 | 10 | 0 | 66.7% |

**Benign false positive rate: 0.0%** (0 of 0 benign requests blocked)


(wrote results/pl4-attacks_report.json)

## Benign (expected: allow)

# Replay report: pl4-benign

| Category | Sent | Blocked | Reached app | DB errors | Block rate |
|----------|-----:|--------:|------------:|----------:|-----------:|
| benign | 100 | 70 | 30 | 0 | 70.0% |

**Benign false positive rate: 70.0%** (70 of 100 benign requests blocked)


(wrote results/pl4-benign_report.json)
