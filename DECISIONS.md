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
