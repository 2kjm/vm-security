# VM Security Hardening

> **This project is in active testing. Use with caution — review the scripts before running on production systems.**

Automated security hardening for Ubuntu VMs. Two scripts: `vm-security.sh` for base OS hardening, and `postgres-security.sh` for PostgreSQL-specific hardening.

---

## What It Does

### vm-security.sh

- **Admin user** — creates non-root sudo user with SSH key auth
- **SSH hardening** — key-only auth, no root login, modern ciphers (ChaCha20, AES-GCM), drop-in config
- **fail2ban** — SSH jail with configurable thresholds, automatic IP whitelisting
- **UFW firewall** — default deny, SSH rate limiting, HTTP/HTTPS allowed
- **Docker** — official CE install, UFW bypass prevention, hardened daemon config
- **Auto updates** — unattended-upgrades for security patches only
- **Kernel hardening** — sysctl tuning (network stack, ICMP, redirects, ASLR, core dumps)
- **auditd** — system call and file access logging with immutable rules

### postgres-security.sh

- **Kernel tuning** — overcommit, swappiness, THP disabled, dirty page ratios
- **Resource limits** — ulimits and systemd overrides for PostgreSQL
- **SSL/TLS** — self-signed cert generation, TLSv1.2 minimum
- **Config hardening** — scram-sha-256 auth, logging, connection limits
- **Performance tuning** — RAM/CPU/storage-aware (shared_buffers, work_mem, WAL, parallelism)
- **pg_hba.conf** — SSL-only remote connections, no trust/md5
- **pgaudit** — DDL and role change audit logging
- **fail2ban** — PostgreSQL auth failure jail
- **UFW rules** — port restricted to configured subnets
- **HA-aware** — detects Patroni/repmgr/pg_auto_failover, prints config instead of overwriting

---

## Prerequisites

- Ubuntu 22.04 or 24.04 LTS
- Root/sudo access
- SSH key pair (`ssh-keygen -t ed25519` on your local machine)
- Console access via your VPS provider (emergency fallback)

---

## Quick Start

Many VM providers give you a bare Ubuntu image with only root access and no security configuration — no firewall, no fail2ban, no SSH hardening. These scripts handle all of that.

### Run directly from GitHub

```bash
# VM hardening (run first)
curl -fsSL https://raw.githubusercontent.com/2kjm/vm-security/main/vm-security.sh -o vm-security.sh
sudo bash vm-security.sh

# PostgreSQL hardening (run after vm-security.sh)
curl -fsSL https://raw.githubusercontent.com/2kjm/vm-security/main/postgres-security.sh -o postgres-security.sh
sudo bash postgres-security.sh setup
```

### Or clone the repo

```bash
git clone https://github.com/2kjm/vm-security.git
cd vm-security
sudo bash vm-security.sh
```

### PostgreSQL commands

```bash
sudo bash postgres-security.sh setup    # Interactive hardening
sudo bash postgres-security.sh status   # Security health check
sudo bash postgres-security.sh reapply  # Re-apply non-interactively
```

The VM script will interactively ask for: username, SSH public key, fail2ban whitelist strategy, and Docker/PostgreSQL workload choice.

---

## Configuration

Edit variables at the top of `vm-security.sh` before running:

```bash
SSH_PORT=22
FAIL2BAN_MAXRETRY=5
FAIL2BAN_BANTIME=3600
FAIL2BAN_FINDTIME=600
ALLOWED_HTTP_PORTS="80,443"
ENABLE_AUTO_UPDATES=true
```

---

## After Setup

**Test SSH immediately in a new terminal before closing your current session:**

```bash
ssh -p 22 your_user@your_server_ip
sudo whoami
```

If locked out, access via your VPS console and run:

```bash
sudo fail2ban-client unban YOUR_IP
```

---

## File Locations

| File | Purpose |
|------|---------|
| `/etc/ssh/sshd_config.d/99-hardening.conf` | SSH hardening |
| `/etc/fail2ban/jail.local` | fail2ban config (sshd) |
| `/etc/fail2ban/jail.d/postgresql.conf` | fail2ban config (PostgreSQL) |
| `/etc/ufw/after.rules` | Docker-UFW integration |
| `/etc/audit/rules.d/security.rules` | Audit rules |
| `/etc/sysctl.d/99-security.conf` | Kernel security params |
| `/etc/sysctl.d/99-postgresql.conf` | PostgreSQL kernel tuning |
| `/root/security-setup-*.log` | VM setup log |
| `/root/pg-security-*.log` | PostgreSQL setup log |

---

## License

MIT
