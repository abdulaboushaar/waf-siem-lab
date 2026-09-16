# Results: paranoia level 2

_Generated 2026-09-16T03:07:40Z by run_matrix.sh_

## Attacks (expected: block)

# Replay report: pl2-attacks

| Category | Sent | Blocked | Reached app | DB errors | Block rate |
|----------|-----:|--------:|------------:|----------:|-----------:|
| sqli | 40 | 33 | 3 | 1 | 82.5% |
| traversal | 20 | 20 | 0 | 0 | 100.0% |
| xss | 30 | 20 | 10 | 0 | 66.7% |

**Benign false positive rate: 0.0%** (0 of 0 benign requests blocked)


(wrote results/pl2-attacks_report.json)

## Benign (expected: allow)

# Replay report: pl2-benign

| Category | Sent | Blocked | Reached app | DB errors | Block rate |
|----------|-----:|--------:|------------:|----------:|-----------:|
| benign | 100 | 9 | 91 | 10 | 9.0% |

**Benign false positive rate: 9.0%** (9 of 100 benign requests blocked)


(wrote results/pl2-benign_report.json)
