# WAF-to-SIEM Detection Pipeline

> ## Warning
>
> This repository contains a **deliberately vulnerable web application**. It has
> working SQL injection, stored cross-site scripting, path traversal and broken
> access control. It is built to be attacked, in a lab, on a machine that is not
> reachable from anywhere else.
>
> Do not deploy it. Do not expose it to a network you do not control. The Compose
> file binds the application to `127.0.0.1` on purpose; do not change that to
> `0.0.0.0`.

## What this measures

A web application firewall is standard advice. What it actually buys you is
rarely measured. This project measures it.

A labeled corpus of attack and benign HTTP requests is replayed through
ModSecurity v3 running the OWASP Core Rule Set, at each of the four CRS
paranoia levels, against an application whose vulnerabilities are known and
real. Every request carries a correlation ID, so the firewall's decision and the
application's response can be lined up for the same request. The output is a
block rate and a false positive rate per paranoia level.

The goal is a defensible sentence of the form: *"at paranoia level N the rule
set stopped X percent of attacks and wrongly stopped Y percent of legitimate
traffic, and here is the specific legitimate request it broke."*

## Architecture

```mermaid
flowchart LR
    H["Replay harness<br/>labeled payloads"] -->|X-Lab-Request-Id| W["ModSecurity v3<br/>+ OWASP CRS<br/>(nginx)"]
    W -->|allowed| A["PHP 8.3 app<br/>deliberately vulnerable"]
    A --> D[("MySQL 8")]
    W --> AUD["ModSecurity<br/>JSON audit log"]
    A --> APP["app.log<br/>one JSON line per request"]
    AUD --> N["Python normalizer<br/>flattens audit JSON"]
    N --> Z["Wazuh manager<br/>indexer + dashboard"]
    APP --> Z
    Z --> R["Report:<br/>block rate + FP rate<br/>per paranoia level"]
```

The correlation ID is the load-bearing part. The harness stamps every request
with `X-Lab-Request-Id`. The WAF records it, the application records it, and the
SIEM can therefore join the firewall's decision to what the application actually
did. Without it there are two unrelated piles of logs.

## Status

| Step | Component | State |
|------|-----------|-------|
| 0 | Host environment (WSL2, Docker, toolchain) | Done |
| 1 | Vulnerable PHP app, MySQL, structured request log | Done |
| 2 | ModSecurity + CRS reverse proxy | Not started |
| 3 | Python normalizer for the ModSecurity audit log | Not started |
| 4 | Wazuh single-node ingest and detection rules | Not started |
| 5 | Replay harness and paranoia-level report | Not started |

## Host prerequisites

Developed on Windows 11 with WSL2 (Ubuntu 24.04) and Docker Desktop with WSL
integration enabled. Any Linux host with Docker and Compose v2 will work for
steps 0 and 1.

The repository must live on the Linux filesystem (`~/waf-siem-lab`), not under
`/mnt/c`. See D-0001 in `DECISIONS.md`.

Wazuh's indexer requires `vm.max_map_count` of at least 262144. On WSL2 this is
set for the whole VM, outside this repository, in `%UserProfile%\.wslconfig`:

```ini
[wsl2]
kernelCommandLine = sysctl.vm.max_map_count=1048576
memory=12GB
processors=4
swap=4GB
```

Apply it with `wsl --shutdown` and verify with `cat /proc/cmdline` inside WSL.
See D-0002.

## Quick start

```bash
cp .env.example .env
# edit .env and set your own values
docker compose up -d --build
docker compose ps            # wait for lab-db to report healthy
```

Then open <http://127.0.0.1:8080>.

Reseeding the database requires destroying the volume, because MySQL only runs
`db/init/` on an empty data directory:

```bash
docker compose down -v && docker compose up -d --build
```

## Test accounts

Weak on purpose, so the replay harness can succeed against them.

| Username | Password   | Role  |
|----------|------------|-------|
| admin    | admin123   | admin |
| alice    | password1  | user  |
| bob      | hunter2    | user  |

## The deliberate vulnerabilities

Each endpoint carries exactly one primary defect and uses correct practice
everywhere else, so that a blocked request can be attributed to one known
weakness. See D-0005.

| Endpoint | Class | CWE | Demo | Fix |
|----------|-------|-----|------|-----|
| `search.php` | SQL injection | CWE-89 | `?q=' OR '1'='1` returns all rows | Prepared statement with a bound parameter |
| `product.php` | Stored XSS | CWE-79 | Post a comment containing an `onerror` payload | Escape on output with `htmlspecialchars` |
| `download.php` | Path traversal | CWE-22 | `?file=../../../../etc/passwd` | `realpath()` then verify the resolved path stays under the base directory |
| `admin.php` | Broken access control | CWE-565 | `curl -b 'role=admin'` returns the account table | Read the role from server-side session state and re-check it in the database |
| `login.php` | Username enumeration | CWE-204 | "No such user" differs from "Wrong password" | One identical message for both failures, plus a dummy hash comparison so timing matches |
| `login.php` | No authentication throttling | CWE-307 | Unlimited attempts | Per-account and per-IP failure counters with backoff or lockout |

Secondary issues are annotated in the source but are not the targets of the
replay harness: verbose SQL error disclosure (CWE-209) in `search.php`, and a
missing CSRF token (CWE-352) on the comment form.

Every deliberate weakness is marked in the source with a `VULNERABILITY:`
comment naming the CWE and the one-line fix.

## Application log schema

Every request appends exactly one JSON object to `/var/log/app/app.log`, which
lives on the `app_logs` named volume so later containers can read it. See
D-0004.

| Field | Meaning |
|-------|---------|
| `ts` | RFC 3339 UTC timestamp with milliseconds |
| `request_id` | Value of the `X-Lab-Request-Id` header, or `"none"` |
| `method` | HTTP method |
| `path` | Request path, query string excluded |
| `client_ip` | First value of `X-Forwarded-For`, else the socket peer |
| `user` | Authenticated username, or `null` |
| `role` | Role in effect for the request, or `null` |
| `outcome` | Short result token, for example `search_ok`, `download_denied`, `admin_allowed` |
| `db_error` | PDO error text when a query failed, else `null` |

An `outcome` of `unhandled` means the request died before setting one, which is
itself a signal worth alerting on.

Inspect it with:

```bash
docker compose exec -T app cat /var/log/app/app.log | jq -c '[.request_id, .outcome]'
```

## Repository layout

```
waf-siem-lab/
├── DECISIONS.md            architecture decision log
├── docker-compose.yml
├── .env.example            copy to .env; .env is never committed
├── app/
│   ├── Dockerfile          php:8.3-apache + pdo_mysql
│   ├── src/                application source
│   └── specs/              spec sheets, outside the document root
└── db/
    └── init/               schema and seed, run once on first start
```

## Decisions

`DECISIONS.md` records every non-obvious choice made while building this, with
the alternative that was rejected and why. Read it before the code.

## Secrets

No credentials, private keys or certificates are committed. `.env` is ignored;
`.env.example` documents the shape. Wazuh's TLS material is generated locally in
step 4 and is excluded by `.gitignore`, which means a fresh clone needs the
generation step rather than working immediately. That tradeoff is deliberate and
is recorded in `DECISIONS.md`.
