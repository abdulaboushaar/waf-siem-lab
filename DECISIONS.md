# Decisions

Architecture decision log for the WAF-to-SIEM Detection Pipeline.
One entry per decision. Append new entries at the bottom. Never rewrite an
accepted entry; if a decision changes, add a new entry that supersedes it.

Status values: proposed | accepted | superseded by D-XXXX | reverted

---

## D-0001: Repo lives in the WSL2 ext4 filesystem, not under /mnt/c

- **Date:** 2026-09-08
- **Status:** accepted

**Context.** The lab runs entirely in Docker Desktop on WSL2. Compose files
bind mount source directories into the app, WAF, normalizer and Wazuh
containers. The repo could live on the Windows drive and be reached through
the /mnt/c DrvFs mount, or on the Linux ext4 filesystem inside the distro.

**Decision.** The repo lives at ~/waf-siem-lab on ext4. Windows editors reach
it over the \\wsl.localhost\Ubuntu-24.04\ UNC path or the VS Code WSL remote
extension.

**Alternative rejected.** Keeping the repo on C: and bind mounting through
/mnt/c. Rejected for 9P translation overhead and, more importantly, because
DrvFs does not faithfully represent Linux ownership and permission bits,
which the Wazuh TLS material, container entrypoints and SSH keys depend on.

**Consequences.** Windows-native tools must use the UNC path. Backup means
pushing to GitHub, since the ext4 volume is not covered by Windows backup.

**Verify.** `pwd` inside the repo prints /home/abdul/waf-siem-lab.

---

## D-0002: Pin vm.max_map_count in .wslconfig rather than rely on the WSL default

- **Date:** 2026-09-08
- **Status:** accepted

**Context.** The Wazuh indexer requires vm.max_map_count of at least 262144.
Standard Linux defaults to 65530, but WSL kernel 6.18.33.2 on this machine
defaults to 1048576, so the requirement was already met without action.

**Decision.** Set kernelCommandLine = sysctl.vm.max_map_count=1048576 in
%UserProfile%\.wslconfig, alongside memory=12GB, processors=4 and swap=4GB.
The value matches the observed kernel default so nothing is lowered, while
the lab's dependency is stated in configuration.

**Alternative rejected.** Relying on the kernel default and documenting it in
the README. Rejected because a kernel default is not a stable contract; a WSL
update could restore 65530 and produce an indexer crash loop with no artifact
in the repo pointing at the cause.

**Consequences.** .wslconfig is a Windows-side file outside the repo, so it is
not version controlled with the project. The README must list it as a host
prerequisite with its full contents.

**Verify.** `cat /proc/cmdline` inside WSL contains
sysctl.vm.max_map_count=1048576, and `free -h` reports roughly 12GB total.

---

## D-0003: Docker Desktop with WSL integration, not a native engine install

- **Date:** 2026-09-08
- **Status:** accepted

**Context.** Docker can run on this host either through Docker Desktop with
WSL2 integration, or by installing the Docker engine directly inside the
Ubuntu distro with apt.

**Decision.** Docker Desktop, with WSL integration enabled for Ubuntu-24.04.

**Alternative rejected.** Native engine inside Ubuntu. It is leaner and closer
to how this stack would run on a real Linux host, but running both is a known
conflict, and hand-managing a daemon on WSL is time spent away from the
project. Desktop also manages the VM memory ceiling and lifecycle.

**Consequences.** Docker Desktop requires a paid licence at larger companies,
so the setup is not portable to every environment. The docker group membership
Desktop configures is root equivalent: any member can bind mount / into a
container and read or write the host filesystem as root with no sudo prompt.
Acceptable on a single-user lab machine, not on a shared host.

**Verify.** `docker version` reports both Client and Server sections, and
`docker run --rm hello-world` succeeds.

---

## D-0004: One structured log line per request, written from a shutdown handler

- **Date:** 2026-09-09
- **Status:** accepted

**Context.** The pipeline needs application-side evidence for every request, in
a form a SIEM can index, correlatable with the WAF's own record of the same
request. The log line could be written by each endpoint at the end of its own
code path, or centrally by one handler that always runs.

**Decision.** `bootstrap.php` builds a static array of the log fields at request
start, endpoints mutate it as they go, and a `register_shutdown_function`
handler serialises it with `json_encode` and appends one line to
`/var/log/app/app.log`. `outcome` defaults to `unhandled`. The file lives on the
`app_logs` named volume so the normalizer and the Wazuh agent can mount it
read-only in later steps. `request_id` comes from the `X-Lab-Request-Id` header,
or the literal string `none`.

**Alternative rejected.** An explicit `log_event()` call at the end of each
endpoint. It is easier to read and keeps the logging local to the code that
knows the outcome. Rejected because it emits zero lines when a script dies on a
fatal error or an uncaught exception, and duplicate lines on any path that
forgets to return. Silently dropping exactly the requests that crashed the
application is the worst available failure mode for a detection pipeline: it is
incomplete in a way that looks complete.

**Consequences.** Endpoints share mutable static state and must remember to set
`outcome`; the `unhandled` default turns that omission into a visible signal
rather than a missing field. The line is built with `json_encode` and never with
string concatenation, because attacker-controlled values reach it and
`json_encode` escapes the newlines and quotes that would otherwise let an
attacker forge an additional log record (CWE-117). The `app_logs` volume name is
now a contract with steps 3 and 4.

**Verify.** `docker compose exec -T app cat /var/log/app/app.log | jq -c
'[.request_id, .outcome]'` prints exactly one line per request with the
correlation ID intact.

---

## D-0005: Exactly one primary vulnerability class per endpoint

- **Date:** 2026-09-09
- **Status:** accepted

**Context.** The application has to be genuinely exploitable, otherwise the
report measures a firewall blocking attacks that could never have worked. Beyond
that, the defects could be spread realistically across the code, the way a real
legacy application accumulates them, or placed precisely, one class per
endpoint.

**Decision.** Each endpoint carries one deliberate defect and uses correct
practice everywhere else. `product.php` parameterises its lookup and fails only
on output encoding. `comment.php` parameterises its insert and fails only by
storing raw markup. `search.php` concatenates. Every deliberate weakness is
annotated in the source with its CWE identifier and its one-line fix, and the
full mapping is tabulated in the README.

**Alternative rejected.** Broadly sloppy code across all endpoints, which is far
more representative of real vulnerable applications. Rejected because step 5
measures block rate and false positive rate per CRS paranoia level, and that
requires attributing each blocked request to one known defect. If a single
request could have been blocked by an SQL injection rule or an XSS rule because
the endpoint is vulnerable to both, the resulting percentages cannot be
interpreted and the report is worthless.

**Consequences.** The application is less realistic than production legacy code,
and that limitation belongs in any write-up of the results. Secondary issues
that are free to point out are documented in comments rather than removed
(CWE-209 verbose SQL errors in `search.php`, CWE-352 missing CSRF token on the
comment form), so the code stays honest about what else is wrong while the
harness still targets one defect per endpoint. Adding a second targeted defect
to an existing endpoint later would invalidate any report already generated.

**Verify.** Every `VULNERABILITY:` comment in `app/src/` names a CWE, and each
endpoint's primary defect matches one row of the README table.

--- 

## D-0006: Attack payloads sourced from PayloadsAllTheThings and cited, not invented

- **Date:** 2026-09-09
- **Status:** accepted

**Context.** The harness needs a corpus of SQLi, XSS and traversal payloads to
fire at the WAF. These could be hand written, or copied from an established
public payload collection.

**Decision.** The attack sets are copied from PayloadsAllTheThings and converted
to the YAML schema by build_attacks.py, which stamps every entry with a
citation of the form PayloadsAllTheThings@<commit>:<path>:L<line>. The
repository commit and licence are recorded in payloads/ATTACKS.md. No attack
payload is invented.

**Alternative rejected.** Hand authoring the payloads. Rejected for two reasons.
Payloads I write would be biased toward the exact evasions I already know CRS
catches, which would silently inflate the block rate and make the measurement
circular. And a public portfolio that copies a payload corpus without recording
its source and licence is a provenance failure a security employer will notice.

**Consequences.** The repository does not ship the third-party payloads
themselves (harness/payloads/raw/ is gitignored), so a fresh clone must follow
the ATTACKS.md procedure to rebuild the attack YAML. The benign, bruteforce and
enum sets have no upstream source and are generated locally by gen_corpus.py.

**Verify.** Every entry in sqli.yaml, xss.yaml and traversal.yaml has a source
field beginning with PayloadsAllTheThings@, and ATTACKS.md records the commit
and licence.

---

## D-0007: bruteforce and enum payloads are labeled expected:allow

- **Date:** 2026-09-09
- **Status:** accepted

**Context.** The corpus includes brute-force login attempts and enumeration
requests for paths that do not exist. Each payload carries an expected value of
allow or block, which is what the report scores the WAF against.

**Decision.** bruteforce and enum payloads are labeled expected:allow. Only the
single-request signature attacks (sqli, xss, traversal) are labeled block.

**Alternative rejected.** Labeling bruteforce and enum as block. Rejected
because no single login attempt or single request for a missing path is a
WAF-blockable event; each one looks identical to legitimate traffic. The attack
is the volume, which a signature WAF cannot see. Scoring CRS as failing to block
them would produce a dishonest block rate and would hide the reason the SIEM
half of the project exists.

**Consequences.** These categories will show a near-zero block rate at the WAF
and that is the correct result, not a gap. Their detection is deferred to Wazuh
correlation rules in Step 5 (a burst of login_failed outcomes or 404s grouped by
client IP over a time window). The report must present WAF block rate and SIEM
correlation detection as answering different questions.

**Verify.** grep 'expected: block' across the payload sets returns only sqli,
xss and traversal entries; bruteforce.yaml and enum.yaml contain only
expected: allow.

---

## D-0008: WAF config split into common.env plus per-paranoia-level files

Date: 2026-09-11
Status: accepted

Context. The WAF is run four times, once per CRS paranoia level, and the runs must be identical in every respect except the paranoia level, or the comparison between them is not valid. The configuration could be four self-contained env files, or one shared file plus a tiny per-level file.

Decision. waf/common.env holds every shared setting (BACKEND, rule engine, JSON audit logging, anomaly thresholds). waf/pl1.env through pl4.env set only BLOCKING_PARANOIA. Compose loads common.env plus one pl file selected by the WAF_PL variable in .env.

Alternative rejected. Four self-contained env files. Rejected because the moment a shared setting changes it must be edited in four places, they drift, and the guarantee that runs differ only in paranoia level silently rots, which would invalidate the comparison the whole report rests on.

Consequences. Switching level is WAF_PL=pl2 docker compose up -d. The variable name is BLOCKING_PARANOIA in the current image; older images used PARANOIA. Verified against this image with docker exec lab-waf env | grep -i paranoia.

Verify. diff waf/pl1.env waf/pl4.env differs only in the level digit.

--- 

## D-0009: DetectionOnly for bring-up, enforced blocking for measurement
Date: 2026-09-11
Status: accepted

Context. ModSecurity can inspect and score without blocking (DetectionOnly) or inspect and enforce (On). With MODSEC_AUDIT_ENGINE=RelevantOnly the audit log records only transactions with a relevant response status (4xx or 5xx, not 404) or a rule that forces logging. A detected request that is not blocked returns 200 and is not written to the audit log.

Decision. Bring the WAF up in DetectionOnly to confirm plumbing without breaking traffic, then switch MODSEC_RULE_ENGINE to On for the measurement runs. In enforced mode a blocked request returns 403, which is a relevant status, so RelevantOnly logs exactly the blocked requests: attacks caught and benign false positives. Allowed requests produce no WAF audit event, which is correct; the report treats absence of a WAF event as allowed.

Alternative rejected. Measuring in DetectionOnly. Rejected because with RelevantOnly a detected-but-not-blocked request returns 200 and is never logged, so the WAF's decisions would be invisible. Capturing them in detection mode would require MODSEC_AUDIT_ENGINE=On, which logs every request and is heavier; enforced blocking plus RelevantOnly yields the exact events the report needs.

Consequences. Measurement runs actually block, so the vulnerable app is protected during a run, which is faithful to production. Sub-threshold detections (scored but below the block threshold) are not visible in enforced mode; that is acceptable because the report counts blocked versus not blocked. Replay must use http://localhost:8080, not 127.0.0.1: a numeric-IP Host header trips rule 920350 and adds score to every request, which would contaminate the false positive rate.

Verify. With the engine On, a traversal at /download.php returns 403 and the audit log's last entry shows http_code 403 and rule 949110.

--- 

## D-0010: Apostrophe exclusion is a documented remediation, measured separately
Date: 2026-09-11
Status: accepted

Context. A benign apostrophe in the search box (for example "Builder's Choice") is a classic SQLi false positive. A custom exclusion can remove SQLi detection from ARGS:q on /search.php. But the SQLi attack corpus also fires at /search.php?q=, so an active exclusion would suppress those attacks and understate the SQLi block rate. The exclusion and the attack corpus target the same parameter.

Decision. Measure raw CRS first with no exclusion, reporting the apostrophe false positive as one of the false positives. Then, as a separate tuned run, enable the exclusion and show the before-and-after: the false positive disappears and the SQLi block rate on that path drops as the cost. The exclusion mount is commented out in docker-compose.yml by default. The exclusion is scoped to /search.php and ARGS:q using a runtime ctl action in a before-CRS file.

Alternative rejected. Shipping the exclusion active, or disabling the SQLi rules globally. An active exclusion corrupts the raw measurement. A global disable (SecRuleRemoveById) blinds the signature for every parameter and path, not just the one false positive.

Consequences. The tuned run demonstrates the real tradeoff: even a correctly scoped exclusion allows real SQLi through q on /search.php, because the same parameter cannot be both excluded from SQLi detection and protected against it. The exclusion is a compensating control; the actual fix is a prepared statement in the app. Filling the exclusion in correctly requires reading the matched rule IDs from the audit log, not trusting a hard-coded list.

Verify. With the exclusion mount off, a SQLi at /search.php?q= returns 403; with it on, the same request is allowed while a SQLi on another path still blocks.

D-0011: A one-shot init container fixes the audit-volume ownership
Date: 2026-09-11
Status: accepted

Context. The WAF image runs as the unprivileged nginx user (uid 101). The modsec_audit named volume mounts in owned by root, so nginx cannot create the audit log inside it and ModSecurity silently writes nothing.

Decision. A one-shot waf-init container (busybox) chowns the volume to uid 101 and exits. The WAF depends on it with condition: service_completed_successfully, so the volume is writable before ModSecurity starts, on every up and on a fresh clone, with no manual step.

Alternative rejected. A manual chown, or running the WAF as root. A manual chown resets on docker compose down -v and is a step a teammate will forget. Running the WAF as root discards the image's unprivileged posture.

Consequences. One extra short-lived container in the stack. The fix is in version control rather than in a person's shell history, so the audit log is reproducibly writable.

Verify. docker exec lab-waf ls -la /var/log/modsec/ shows the directory owned by nginx, and the audit log file appears after the first blocked request.

---

## D-XXXX: <short imperative title>

- **Date:** YYYY-MM-DD
- **Status:** proposed

**Context.** What forced a choice here. What constraint or failure made this a
question rather than a default.

**Decision.** What we are doing, stated so someone can act on it without
reading the rest.

**Alternative rejected.** The one real other option and the specific reason it
lost. Not a strawman.

**Consequences.** What this costs, what it now makes hard, what follow-on work
it creates.

**Verify.** The command, log line or doc page that proves the decision is in
effect.
