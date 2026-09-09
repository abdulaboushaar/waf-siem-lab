# Attack payload provenance

The `sqli`, `xss` and `traversal` sets are not hand written. They are copied from
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) and
converted to the YAML schema by `build_attacks.py`, which stamps every entry with
a citation of the form:

    PayloadsAllTheThings@<commit>:<path inside repo>:L<line>

## Before you copy anything

1. Clone the repo somewhere OUTSIDE this project so it never gets committed here:

       git clone https://github.com/swisskyrepo/PayloadsAllTheThings ~/patp
       cd ~/patp && git rev-parse --short HEAD    # record this commit hash

2. Read `~/patp/LICENSE`. Record the licence and the commit hash in this file
   under "Provenance" below. Do not skip this. Citing someone else's payload
   corpus without recording its licence is exactly the kind of thing a security
   employer notices.

3. The repo is reorganised often, so the paths below are the ones that existed
   when this lab was built. If a path has moved, find the current file in the
   repo tree and use that path in `--src-path`. Verify each file exists before
   copying rather than trusting this list.

## The mapping

Copy the lines you want from each source file into `payloads/raw/<name>.txt`
(one payload per line), then run the matching `build_attacks.py` command. The
`--limit` values below produce the target counts: 40 SQLi, 30 XSS, 20 traversal.

### SQL injection (40: 10 per style)

| Style | Source file (verify path) | raw file | limit |
|-------|---------------------------|----------|------:|
| classic | `SQL Injection/Intruder/Auth_Bypass.txt` | `raw/sqli_classic.txt` | 10 |
| comment | `SQL Injection/Intruder/Generic_SQLI.txt` | `raw/sqli_comment.txt` | 10 |
| encoding | `SQL Injection/Intruder/SQLI_Polyglots.txt` | `raw/sqli_encoding.txt` | 10 |
| time | `SQL Injection/MySQL Injection.md` (the SLEEP/BENCHMARK lines) | `raw/sqli_time.txt` | 10 |

    python3 build_attacks.py --raw raw/sqli_classic.txt  --category sqli --style classic  --endpoint /search.php --param q --commit <hash> --src-path "SQL Injection/Intruder/Auth_Bypass.txt"   --limit 10 --out sqli.yaml
    python3 build_attacks.py --raw raw/sqli_comment.txt  --category sqli --style comment  --endpoint /search.php --param q --commit <hash> --src-path "SQL Injection/Intruder/Generic_SQLI.txt"  --limit 10 --out sqli.yaml --append
    python3 build_attacks.py --raw raw/sqli_encoding.txt --category sqli --style encoding --endpoint /search.php --param q --commit <hash> --src-path "SQL Injection/Intruder/SQLI_Polyglots.txt" --limit 10 --out sqli.yaml --append
    python3 build_attacks.py --raw raw/sqli_time.txt     --category sqli --style time     --endpoint /search.php --param q --commit <hash> --src-path "SQL Injection/MySQL Injection.md"          --limit 10 --out sqli.yaml --append

Time-based payloads sleep on the server. Run replay with `--timeout 15` or they
register as transport failures. The report cannot see timing, so a time-based
payload that is not blocked shows as reaching the app with status 200; that is a
known limitation of a status-only harness, worth stating in your write-up.

### XSS (30: 10 per style)

| Style | Source file (verify path) | raw file | limit |
|-------|---------------------------|----------|------:|
| scripttag | `XSS Injection/Intruders/xss_alert.txt` | `raw/xss_scripttag.txt` | 10 |
| eventhandler | `XSS Injection/README.md` (the `onerror`/`onload` sections) | `raw/xss_eventhandler.txt` | 10 |
| encoded | `XSS Injection/Intruders/XSS_Polyglots.txt` | `raw/xss_encoded.txt` | 10 |

XSS in this app is stored, through the comment form, so these go to
`comment.php` as POST with the payload in `body`. The converter puts the payload
in whatever `--param` you name, so also give static fields by hand if you want a
valid `product_id`; simplest is to target `/search.php?q=` for the reflected
surface instead, since the point here is whether CRS blocks the payload, not
whether it stores. Pick one and note the choice:

    python3 build_attacks.py --raw raw/xss_scripttag.txt    --category xss --style scripttag    --endpoint /search.php --param q --commit <hash> --src-path "XSS Injection/Intruders/xss_alert.txt"      --limit 10 --out xss.yaml
    python3 build_attacks.py --raw raw/xss_eventhandler.txt --category xss --style eventhandler --endpoint /search.php --param q --commit <hash> --src-path "XSS Injection/README.md"                       --limit 10 --out xss.yaml --append
    python3 build_attacks.py --raw raw/xss_encoded.txt      --category xss --style encoded      --endpoint /search.php --param q --commit <hash> --src-path "XSS Injection/Intruders/XSS_Polyglots.txt"   --limit 10 --out xss.yaml --append

### Path traversal (20: mixed encodings)

| Style | Source file (verify path) | raw file | limit |
|-------|---------------------------|----------|------:|
| plain | `Directory Traversal/Intruder/directory_traversal.txt` | `raw/trav_plain.txt` | 10 |
| encoded | `Directory Traversal/Intruder/deep_traversal.txt` and the URL/double/UTF-8 encoded sections of `Directory Traversal/README.md` | `raw/trav_encoded.txt` | 10 |

    python3 build_attacks.py --raw raw/trav_plain.txt   --category traversal --style plain   --endpoint /download.php --param file --commit <hash> --src-path "Directory Traversal/Intruder/directory_traversal.txt" --limit 10 --out traversal.yaml
    python3 build_attacks.py --raw raw/trav_encoded.txt --category traversal --style encoded --endpoint /download.php --param file --commit <hash> --src-path "Directory Traversal/Intruder/deep_traversal.txt"      --limit 10 --out traversal.yaml --append

## Why bruteforce and enum are labeled `expected: allow`

They are attacks, but not ones a signature WAF blocks on a single request. One
login attempt and one request for `/wp-login.php` look ordinary; the attack is
the volume. CRS will not return 403 for them, so labeling them `block` would
score the WAF as failing at something it structurally cannot do. Their detection
belongs to the SIEM in Step 4, by correlating a burst of `login_failed` outcomes
or 404s from one client. Marking them `allow` keeps the WAF block rate honest and
leaves the correlation work where it belongs.

## Provenance

Fill this in when you clone the corpus:

- PayloadsAllTheThings commit: `________`
- Licence (from its LICENSE file): `________`
- Date copied: `________`
