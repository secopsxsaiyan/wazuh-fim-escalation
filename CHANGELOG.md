# Changelog

All notable changes to this pack are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-10-26

- Initial public release: FIM escalation rules **100035–100039** (sudoers L10, cron L8,
  PAM L8, passwd/shadow L8, SSH key files L10) as children of stock FIM rules 550/553/554.
- Rule **101440** (L10): Wazuh / SIEM credential material changed or deleted (agent keys,
  enrollment password, enrollment TLS key/cert, indexer certificates, indexer
  `internal_users.yml`).
- Rule **101441** (L10): `/etc/audit/rules.d/` changed or deleted (audit-trail tampering).
- README: `<syscheck>` snippet for the manager/indexer credential paths and audit rules
  (not in Wazuh's default FIM scope).
