# SIEM setup (Wazuh)

The SIEM is the official Wazuh single-node Docker stack, run as a **separate
project** from this repository. This repo does not vendor the Wazuh stack, its
generated certificates, or its passwords. This file is how you reproduce the SIEM
half and wire it to the lab. See D-0013.

## Why it is separate

`wazuh-docker` is a maintained upstream unit with its own compose file, cert
generation, and versioning. Folding it into this repo's `docker-compose.yml`
would mean owning all of that by hand and re-merging on every Wazuh release. So
it runs on its own and simply reads this project's log volumes.

## Prerequisites

- The lab stack in this repo is up (`docker compose up -d`), so the named volumes
  `waf-siem-lab_lab_logs` and `waf-siem-lab_app_logs` exist. Confirm with
  `docker volume ls | grep waf-siem-lab`.
- `vm.max_map_count` is at least 262144 (already set for WSL in `.wslconfig`,
  see D-0002).

## 1. Clone the Wazuh stack

Clone OUTSIDE this repo so it is not nested. Use the latest 4.x tag (this lab
used v4.14.7; check https://github.com/wazuh/wazuh-docker/releases for newer).

```bash
cd ~
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.7
cd wazuh-docker/single-node/
```

## 2. Reduce the indexer heap (optional, for low-RAM hosts)

In `docker-compose.yml`, set the `wazuh.indexer` heap so it cannot starve the lab:

```yaml
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
```

## 3. Generate certificates and start

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Dashboard: https://localhost:443 (accept the self-signed cert). Default login is
`admin` / `SecretPassword`.

## 4. Change the default password

Do not leave the default. Summary (full steps in the Wazuh docs, "Changing the
default password"):

1. Generate a hash:
   `docker run --rm -ti wazuh/wazuh-indexer:4.14.7 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh`
2. Put the hash in `config/wazuh_indexer/internal_users.yml` under `admin`.
3. Replace the plaintext `SecretPassword` in both `INDEXER_PASSWORD` lines of
   `docker-compose.yml` (manager and dashboard).
4. Apply it with `securityadmin.sh` inside the indexer container. NOTE: on this
   image the certs are under `/usr/share/wazuh-indexer/config/certs/`, not
   `/usr/share/wazuh-indexer/certs/`:

   ```bash
   docker exec single-node-wazuh.indexer-1 bash -c '
   export JAVA_HOME=/usr/share/wazuh-indexer/jdk
   D=/usr/share/wazuh-indexer
   bash $D/plugins/opensearch-security/tools/securityadmin.sh \
     -cd $D/config/opensearch-security/ -nhnv -icl -p 9200 \
     -cacert $D/config/certs/root-ca.pem \
     -cert   $D/config/certs/admin.pem \
     -key    $D/config/certs/admin-key.pem'
   ```
5. Verify: `curl -sk -u admin:NEWPASS https://localhost:9200/_cluster/health`
   returns status green.

## 5. Wire the lab logs into the manager

In the Wazuh `docker-compose.yml`, add to the `wazuh.manager` service `volumes:`
(read-only, so the SIEM cannot alter the logs it monitors):

```yaml
      - waf-siem-lab_lab_logs:/var/log/lab:ro
      - waf-siem-lab_app_logs:/var/log/app:ro
      - /home/abdul/waf-siem-lab/wazuh/local_rules.xml:/var/ossec/etc/rules/local_rules.xml
```

Declare the two volumes external at the bottom `volumes:` block:

```yaml
  waf-siem-lab_lab_logs:
    external: true
  waf-siem-lab_app_logs:
    external: true
```

Add the localfile blocks to `config/wazuh_cluster/wazuh_manager.conf` inside
`<ossec_config>`:

```xml
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/lab/waf_events.jsonl</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/app/app.log</location>
  </localfile>
```

## 6. Load it

```bash
docker compose up -d --force-recreate wazuh.manager
```

## Two gotchas (both cost time to learn; do not skip)

- **Config changes need --force-recreate, not restart.** The manager copies
  `config/wazuh_cluster/wazuh_manager.conf` from `/wazuh-config-mount` to
  `/var/ossec/etc/ossec.conf` only when its entrypoint runs, which a plain
  `docker compose restart` does not do. Always use
  `docker compose up -d --force-recreate wazuh.manager`.
- **The single-file rules mount pins to an inode.** Replacing
  `wazuh/local_rules.xml` on the host (any editor that writes a new file) does
  NOT reflect in the container until you `--force-recreate` the manager. Editing
  in place would, but recreate is the reliable habit.

## Verifying ingestion

Temporarily set `<logall_json>yes</logall_json>` in the `<global>` block of
`wazuh_manager.conf`, `--force-recreate` the manager, generate lab traffic, then:

```bash
docker exec single-node-wazuh.manager-1 tail -f /var/ossec/logs/archives/archives.json
```

Look for events carrying your `request_id`. Then set it back to `no` and
`--force-recreate` again (archiving everything fills disk).

## Detection rules

`wazuh/local_rules.xml` (in this repo) is bind-mounted to
`/var/ossec/etc/rules/local_rules.xml`. Test any rule without restarting the
manager only if the manager already loaded the current file; after editing the
file, `--force-recreate` first, then:

```bash
echo '<a JSON log line>' | docker exec -i single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

See `detections/SAMPLES.md` for a sample line, command, and expected output per
rule. Field-naming notes: JSON keys match as bare names in rules (`blocked`,
`top_message`, `client_ip`), except reserved static fields (`status`, `dstuser`)
which use their own tags (`<status>`, `<same_user/>`).

## What is intentionally not in this repo

- The `wazuh-docker` clone itself (it is upstream; clone it per step 1).
- Generated TLS certificates (produced locally in step 3; never commit private keys).
- The indexer password (set locally in step 4; the Wazuh compose is outside this repo).
