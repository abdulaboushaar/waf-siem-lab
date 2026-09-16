# WAF-to-SIEM Detection Pipeline

> This repository contains a deliberately vulnerable web application. It has working SQL injection, stored cross-site scripting, path traversal, and broken access control. It is built to be attacked in a lab, on a machine that is not reachable from anywhere else. Do not deploy it, and do not expose it to a network you do not control.

This project measures what a web application firewall actually buys you, instead of assuming it. A deliberately vulnerable PHP and MySQL application runs behind ModSecurity with the OWASP Core Rule Set, a Python harness replays a labeled corpus of attack and benign requests through it at each of the four CRS paranoia levels, and a normalizer feeds both the WAF and application logs into Wazuh where custom rules turn them into alerts. Every request carries a correlation ID so the firewall's decision and the application's response can be joined for the same request. The output is a block rate and a false positive rate per paranoia level, and a per-endpoint decision about which level to ship, backed by the numbers rather than by intuition.

## Architecture

```
  replay.py                 ModSecurity v3 + OWASP CRS            PHP 8.3 app            MySQL 8
  (labeled corpus)          (nginx reverse proxy)                 (deliberately vuln)
      |                            |                                   |                    |
      |  HTTP + X-Lab-Request-Id   |            allowed traffic        |     SQL            |
      +--------------------------> |  -------------------------------> |  ----------------> |
                                   |                                   |                    |
                                   | JSON audit log                    | app.log (JSON,     |
                                   |     |                             | one line/request)  |
                                   |     v                             |     |              |
                                   | normalizer.py                     |     |              |
                                   | (flatten to waf_events.jsonl)     |     |              |
                                   |     |                             |     |              |
                                   |     +-----------+     +-----------+     |              |
                                   |                 v     v                 |              |
                                   |            Wazuh manager  <-------------+              |
                                   |          (JSON decoders + local_rules.xml)            |
                                   |                 |                                      |
                                   |                 v                                      |
                                   |        Wazuh indexer + dashboard                      |
                                   |                                                       |
                                   +--- report.py joins results + logs on request_id ------+
                                              |
                                              v
                                   docs/summary.md  (block rate + FP rate per PL)
```

The correlation ID is the load-bearing part. The harness stamps every request with `X-Lab-Request-Id`, the WAF records it in its audit log, the application records it in its own log, and the two are joined on that ID. Without it there would be two unrelated piles of logs.

## Results

Corpus: 90 attack payloads (40 SQLi, 30 XSS, 20 traversal, sourced from PayloadsAllTheThings) and 100 benign requests designed to be plausible false positives. Blocking mode, one enforced run per paranoia level.

| PL | Attacks blocked | Attacks reached app | SQLi errored DB | Benign blocked | FP rate |
|----|-----------------|---------------------|-----------------|----------------|--------:|
| 1  | 69/90 (76.7%)   | 17                  | 2               | 4/100          | 4.0%    |
| 2  | 73/90 (81.1%)   | 13                  | 1               | 9/100          | 9.0%    |
| 3  | 74/90 (82.2%)   | 12                  | 0               | 19/100         | 19.0%   |
| 4  | 74/90 (82.2%)   | 12                  | 0               | 70/100         | 70.0%   |

Per class, SQLi detection rose from 72.5 percent at PL1 to 85 percent at PL3 and then stopped improving, traversal was blocked 100 percent at every level, and XSS held flat at 66.7 percent at every level.

Recommended paranoia levels are chosen per endpoint. Login runs at PL1, because the WAF does nothing against brute force, which is the real threat on a login form, and the SIEM is what actually detects it, so a higher paranoia level would only add lockout risk for no gain. Search runs at PL2, because going from PL2 to PL3 catches only one more attack but doubles the false positive rate, and the real fix for search is parameterizing the query, after which SQLi cannot reach the database at any level. Product pages run at PL1, because a product view has almost no attack surface and nothing to false-positive on, and the real cross-site scripting defense is output encoding when the app renders comments. Across the sweep only SQLi detection responded to paranoia at all, and most of the roughly 18 percent of attacks that leak are XSS that no paranoia level closes, which only application-side output encoding does. PL4 is never worth shipping here, since it catches no more attacks than PL3 while blocking 70 percent of legitimate traffic through its strict-character rules.

## How to run it

```
cp .env.example .env      # then edit .env and set your own passwords
docker compose up -d --build
curl -s -H 'X-Lab-Request-Id: smoke' http://localhost:8080/index.php | head
```

That brings up the vulnerable app and the WAF on `http://localhost:8080`. Standing up Wazuh and wiring it to the log volumes is documented separately in `siem/README.md`, and the paranoia sweep is `harness/run_matrix.sh` followed by `harness/summarize.py`.

## Detections

Custom Wazuh rules in `wazuh/local_rules.xml`, each with a MITRE ATT&CK technique. A subset is also written as vendor-neutral Sigma in `detections/sigma/`.

| Rule | Level | Detects | MITRE |
|------|------:|---------|-------|
| 100110 | 5  | WAF blocked SQLi | T1190 |
| 100111 | 5  | WAF blocked XSS | T1059.007 |
| 100112 | 5  | WAF blocked path traversal | T1083 |
| 100113 | 10 | SQLi reached the application (search.php db error) | T1190 |
| 100114 | 9  | Stored XSS written via a comment | T1059.007 |
| 100116 | 10 | Brute force from one source (10 fails / 60s) | T1110.001 |
| 100117 | 12 | Distributed brute force on one account | T1110.001 |
| 100119 | 8  | Enumeration sweep (30 x 404 / 60s) | T1595.003 |
| 100120 | 12 | Admin panel reached by a non-admin role | T1548 |
| 100121 | 7  | High WAF anomaly score but not blocked | T1190 |

The WAF-block rules (100110 to 100112) fire on single requests. The brute force, distributed brute force, and enumeration rules are correlation rules, because no single login attempt or single 404 is blockable on its own, which is why those attacks are the SIEM's job and not the WAF's.

## What broke and what I would do differently

The two hardest problems were both in getting Wazuh to read the JSON correctly. Wazuh matches JSON fields in rules by their bare key name, not the `data.` prefix that appears in the alert output, and a few keys such as `status` and the mapped `dstuser` are static fields that must be matched with their own tags rather than a generic field condition. Getting either wrong makes analysisd refuse to load the whole ruleset. On top of that, a single-file bind mount pins to an inode, so replacing `local_rules.xml` on the host does nothing until the container is recreated with `--force-recreate`, and the manager only copies its config on recreate, not on restart. All of that is documented in `siem/README.md` so it does not have to be rediscovered.

The most important lesson was in the measurement itself. The first sweep reported an 80 percent false positive rate at paranoia level 2, which is not real CRS behavior. Tallying the blocked requests showed all of them tripped one rule, 913100, flagging the `python-requests` User-Agent as a scripting client. The harness was measuring itself, not the traffic. Sending a browser User-Agent by default fixed it and the real curve emerged. The general point is that a measurement tool that is distinguishable from real traffic measures its own fingerprint, and the only way I caught it was by not trusting a number that looked wrong and reading the rule that produced it.

Three detections currently need pipeline additions to fire on live data, and they are documented as such: stored XSS needs the comment body logged, the enumeration rule needs a 404 source ingested since the app logs no line for a missing path and the WAF audit excludes 404, and the broken-access-control rule needs the authenticated session role logged separately because the app currently logs the client-controlled cookie value in that field. Given more time I would add those fields, ingest the nginx access log for 404 visibility, and break the block rate down by attack style rather than by broad class, since the blended figure hides which specific evasions leak. The single most valuable follow-up is per-style block rate, because it would show exactly which XSS and SQLi variants the rule set misses.

## Sources and credits

OWASP Core Rule Set, the rule set under test, at https://coreruleset.org. Wazuh, the SIEM, at https://wazuh.com, deployed from the official wazuh-docker single-node stack at https://github.com/wazuh/wazuh-docker. The WAF container is the official `owasp/modsecurity-crs` nginx image at https://github.com/coreruleset/modsecurity-crs-docker, pinned by digest so the four paranoia levels are compared against one fixed rule set version. The attack corpus is copied from PayloadsAllTheThings at https://github.com/swisskyrepo/PayloadsAllTheThings, with the commit hash and licence recorded in `harness/payloads/ATTACKS.md`; those payload files are not committed to this repository and are rebuilt locally per that document.
