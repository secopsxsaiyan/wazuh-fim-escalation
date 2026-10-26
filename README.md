# FIM Escalation Rules for Wazuh

Re-rate **file-integrity-monitoring (FIM/syscheck) changes to security-critical paths** so a
sudoers backdoor, a rogue SSH key, tampered SIEM credentials or rewritten audit rules are paged,
instead of landing at the same level as a routine package-update mtime touch.

Stock Wazuh FIM rules treat every monitored-file change identically — `550` (modified),
`553` (deleted), `554` (added), all level 7. This pack adds **children** of those parents that
match the decoded path via `<field name="file">` and escalate (or deliberately hold below a
triage gate) based on the sensitivity of the file.

> **Home-grown** — not part of the stock Wazuh ruleset. Companion packs:
> [wazuh-threat-detection](https://github.com/secopsxsaiyan/wazuh-threat-detection) (adds a
> `/boot` bootkit rule on the same FIM parents),
> [wazuh-misp-ioc](https://github.com/secopsxsaiyan/wazuh-misp-ioc) (FIM hash IOC matching),
> [wazuh-windows](https://github.com/secopsxsaiyan/wazuh-windows).

## Layout

```
custom_rules/fim_escalation_rules.xml   # children of stock FIM rules 550/553/554
```

## Rules

| ID | Level | Detects | MITRE |
|----|-------|---------|-------|
| 100035 | **10** | `/etc/sudoers` and `/etc/sudoers.d/*` add/modify/delete | T1548.003 |
| 100036 | 8 | cron config changed (`crontab`, `/etc/cron.{d,hourly,daily,weekly,monthly}`) | T1053.003 |
| 100037 | 8 | PAM config changed (`/etc/pam.d/`) | T1556.003 |
| 100038 | 8 | core account DB modified (`/etc/{,g}passwd`, `/etc/{,g}shadow`) | T1078 |
| 100039 | **10** | SSH key file changed (`.ssh/{authorized_keys,config,known_hosts}`) | T1098.004 |
| 101440 | **10** | Wazuh / SIEM credential material changed or deleted (`/var/ossec/etc/{client.keys,authd.pass,sslmanager.key,sslmanager.cert}`, `/etc/wazuh-indexer/certs/`, `…/opensearch-security/internal_users.yml`) | T1552, T1485 |
| 101441 | **10** | auditd rule files changed or deleted (`/etc/audit/rules.d/`) — audit-trail tampering | T1562.001 |

### Level discipline
- **L10 (sudoers, SSH keys, SIEM credentials, audit rules)** — genuinely rare / high-value; meant
  to page. `101441` also fires on a planned audit-rule roll-out; one outside a change window is the
  signal.
- **L8 (cron, PAM, passwd/shadow)** — elevated, indexed, MITRE-tagged, but kept **below** a
  level-10 triage gate because package installs touch `/etc/cron.d` and `libpam` updates touch
  every `/etc/pam.d/common-*` at once. L8 surfaces them on Auth/FIM dashboards without
  auto-triaging benign bursts. Re-rate to your own taste.

## Requirements

These rules fire on `syscheck` events (`550/553/554`), so the monitored paths must be in your
agents' `<syscheck><directories>` config. For the SSH-key rule (100039) in particular, add
realtime monitoring of the relevant `.ssh` directories, e.g.:

```xml
<syscheck>
  <directories realtime="yes" check_all="yes">/root/.ssh</directories>
  <directories check_all="yes">/etc/sudoers.d,/etc/pam.d,/etc/cron.d</directories>
</syscheck>
```

### SIEM credential material (101440) and audit rules (101441)

These paths are **not** in Wazuh's default FIM scope (`/var/ossec` is not monitored at all, and
`/etc` is scheduled-scan only). Add them to the `<syscheck>` block of the hosts that hold them —
the Wazuh manager for `/var/ossec/etc/...`, the indexer node(s) for `/etc/wazuh-indexer/...`, and
every Linux host for `/etc/audit/rules.d`:

```xml
<syscheck>
  <!-- Wazuh manager: agent keys, enrollment password, enrollment TLS key/cert -->
  <directories realtime="yes" check_all="yes">/var/ossec/etc/client.keys,/var/ossec/etc/authd.pass,/var/ossec/etc/sslmanager.key,/var/ossec/etc/sslmanager.cert</directories>
  <!-- Wazuh indexer: node/admin certificates and security-plugin users -->
  <directories realtime="yes" check_all="yes">/etc/wazuh-indexer/certs,/etc/wazuh-indexer/opensearch-security</directories>
  <!-- every Linux host running auditd -->
  <directories realtime="yes" check_all="yes">/etc/audit/rules.d</directories>
  <nodiff type="sregex">client\.keys$|authd\.pass$|\.key$|\.pem$|internal_users\.yml$</nodiff>
</syscheck>
```

The `<nodiff>` line matters only if you also set `report_changes="yes"` on these directories:
it stops FIM from storing and alerting with the *content diff* of the secret files. `client.keys` also changes legitimately whenever an agent is enrolled or removed,
so expect `101440` alongside the enrollment. `101440`'s `file` pattern matches
`internal_users.yml` under any `opensearch-security/` directory, so containerised indexers with a
different config root are covered as long as that path is monitored. To cover your own secrets
(backup repository keys, `.env` files, vault exports), add their paths to the `<syscheck>` block
and extend the rule's `file` regex, e.g. `…|^/srv/backup/keys/|/\.env$`.

> **Note:** the rules fire wherever FIM runs — on enrolled agents, and on the manager itself if
> its own `<syscheck>` block monitors these paths. Only the monitored paths can alert.

## Install

```bash
# 1. copy the rules into the manager's custom rules dir
cp custom_rules/fim_escalation_rules.xml /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/rules/fim_escalation_rules.xml

# 2. (single-file bind-mount deployments) make it world-readable for analysisd
chmod 0644 /var/ossec/etc/rules/fim_escalation_rules.xml

# 3. confirm the 100035-100039 and 101440-101441 ranges are free on your manager (expect empty):
grep -rhoE --exclude=fim_escalation_rules.xml 'rule id="(10003[5-9]|10144[01])"' /var/ossec/etc/rules/ /var/ossec/ruleset/rules/

# 4. test + restart
/var/ossec/bin/wazuh-analysisd -t
/var/ossec/bin/wazuh-control restart
```

FIM events can't be fed through `wazuh-logtest`; to verify, touch a monitored file on an agent
(e.g. add a comment line to a file in `/etc/sudoers.d/`) and look for rule `100035` in the alerts.
Likewise, adding a comment to a file in `/etc/audit/rules.d/` should raise `101441`.

> If you mount this file as a **single-file Docker bind mount**, an in-place editor (`sed -i`,
> most IDEs) replaces the inode and the container keeps serving the old content on a plain
> `reload`. Use `docker compose up -d --force-recreate <manager>` to re-resolve the mount.

## ID range / collisions

Uses **100035-100039** and **101440-101441** — clear of stock Wazuh and the other secopsxsaiyan
packs (100030-100034 are skipped because community rulesets commonly use them). Verify it is also free on your manager before installing (step 3 above).

## License

MIT — see [LICENSE](LICENSE).
