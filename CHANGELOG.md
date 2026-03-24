# Changelog

## [0.2.0] - 2026-03-25

### Added
- `postgres-security.sh` — PostgreSQL hardening (SSL, scram-sha-256, pgaudit, performance tuning, fail2ban, UFW)
- HA-aware PostgreSQL hardening (Patroni, repmgr, pg_auto_failover)
- RAM/CPU/storage-aware performance tuning for PostgreSQL
- Security status command and reapply mode for PostgreSQL

### Changed
- Separated fail2ban enable and restart to avoid silent failures
- Updated README to match actual script features

## [0.1.0] - 2025-10-11

### Initial Release
- SSH hardening (key-only auth, modern ciphers, drop-in config)
- Admin user creation with SSH key setup
- fail2ban with automatic IP whitelisting
- UFW firewall with default deny and SSH rate limiting
- Docker CE install with UFW bypass fix and daemon hardening
- Kernel hardening via sysctl
- auditd with immutable audit rules
- Unattended security updates
