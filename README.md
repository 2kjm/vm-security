# VM Security Management Tool

> **Enterprise-grade VM security hardening with SOC2-aligned controls and zero-configuration deployment.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Ubuntu 24.04](https://img.shields.io/badge/Ubuntu-24.04-orange.svg)](https://ubuntu.com)
[![Bash](https://img.shields.io/badge/Bash-5.0%2B-green.svg)](https://www.gnu.org/software/bash/)

Transform your Ubuntu server into a security-hardened VM in minutes. Automated setup with intelligent defaults, comprehensive monitoring, and built-in safeguards against lockouts.

---

## 🎯 Why This Tool?

**Problem**: Manual security hardening is complex, time-consuming, and error-prone. One misconfiguration can lock you out permanently.

**Solution**: Automated, battle-tested security setup with:
- ✅ **Smart Anti-Lockout**: Automatic IP whitelisting, dynamic range support, pre-flight validation
- ✅ **SOC2 Ready**: Audit logging, file integrity monitoring, 365-day log retention
- ✅ **Zero Config**: Sensible defaults, interactive prompts, validate-before-apply

---

## ✨ Features

### 🔐 **Core Security**
- **SSH Hardening** - Key-only authentication, modern ciphers (ChaCha20, AES-GCM), root login disabled
- **Intrusion Prevention** - fail2ban with configurable thresholds and intelligent IP banning
- **Firewall Management** - UFW with default-deny policy and rate limiting
- **Docker Security** - Prevents Docker from bypassing UFW rules (common misconfiguration)

### 📊 **Compliance & Auditing**
- **Audit Logging (auditd)** - Track system calls, file modifications, user actions
- **File Integrity (AIDE)** - Daily checks for unauthorized system changes
- **Log Retention** - 365-day retention for SOC2/ISO compliance
- **Time Synchronization** - chrony for accurate audit timestamps

### 🛠️ **Management & Monitoring**
- **Real-time Status Dashboard** - Security health scores, active threats, exposed services
- **Interactive Log Viewer** - Browse SSH failures, bans, firewall blocks, audit events
- **Whitelist Manager** - Dynamic IP helper for changing IPs
- **One-Command Updates** - Safe reapplication of security policies

---

## 🚀 Quick Start

### Prerequisites

- **OS**: Ubuntu 24.04 LTS (22.04 compatible)
- **Access**: Root/sudo privileges
- **SSH Key**: Generate with `ssh-keygen -t ed25519` on your local machine
- **Backup Access**: Console access via VPS control panel (emergency use)

### Installation

```bash
# Download the script
curl -fsSL https://raw.githubusercontent.com/2kjm/vm-security/main/vm-security.sh -o vm-security.sh

# Make executable
chmod +x vm-security.sh

# Install system-wide (recommended)
sudo ./vm-security.sh install

# Run interactive setup
sudo vm-security setup
```

### Setup Wizard

The interactive setup will guide you through:

1. **Admin User Creation** - Create non-root admin with sudo privileges
2. **SSH Key Configuration** - Paste your public key (`cat ~/.ssh/id_ed25519.pub`)
3. **Whitelist Strategy** - Choose IP whitelisting approach:
   - Single IP (⚠️ risky for dynamic IPs)
   - /24 network range (✅ recommended - covers 256 IPs)
   - /16 network range (broader coverage)
   - Custom ranges

### ⚠️ Critical: Test Before Logout

**ALWAYS test SSH in a new terminal before closing your current session:**

```bash
# In a NEW terminal window
ssh -p 22 your_username@your_vm_ip

# Once logged in, test sudo
sudo whoami
```

**DO NOT logout until verified!** Keep your original session open as backup.

---

## 📖 Usage

### Status & Monitoring

```bash
# Quick security overview
vm-security status

# Detailed analysis with attack metrics
sudo vm-security status --detailed

# Shorter aliases (after install)
security-status
vm-security-status
```

**Status Output Includes:**
- Service health (SSH, fail2ban, UFW, auditd, chrony)
- Active bans and attack statistics
- Exposed services and ports
- Docker firewall bypass detection
- Security health score (0-100)

### Log Management

```bash
# Interactive log viewer
vm-security logs
```

**Available Logs:**
1. Recent SSH Failed Logins (50)
2. Currently Banned IPs
3. Recent UFW Blocks (50)
4. Audit Activity (50)
5. AIDE Integrity Reports
6. Setup Log
7. Exit (with confirmation)

### Reapply Security

Safe to run multiple times - backs up configs before changes:

```bash
sudo vm-security reapply
```

### Emergency Operations

```bash
# Unban specific IP
sudo vm-security unban 203.0.113.45

# Unban all IPs
sudo vm-security unban all

# Add IP to whitelist (dynamic IP helper)
sudo vm-security whitelist
```

### Help

```bash
vm-security help
```

---

## ⚙️ Configuration

### Pre-Setup Configuration

Edit variables at the top of `vm-security.sh` before running setup:

```bash
NEW_USER=""                          # Admin username (leave empty for interactive prompt)
SSH_PUBLIC_KEY=""                    # SSH public key (leave empty for prompt)
SSH_PORT=22                          # SSH port (change only if needed)
CHANGE_SSH_PORT=false                # Set true to change from default port 22

# fail2ban Settings
FAIL2BAN_MAXRETRY=5                 # Failed attempts before ban
FAIL2BAN_BANTIME=3600               # Ban duration in seconds (1 hour)
FAIL2BAN_FINDTIME=600               # Time window for failed attempts (10 min)
FAIL2BAN_IGNOREIP="127.0.0.1/8"     # Whitelisted IPs/ranges (space-separated)

# Additional Settings
ALLOWED_HTTP_PORTS="80,443"         # HTTP/HTTPS ports (comma-separated)
ENABLE_AUTO_UPDATES=true            # Automatic security updates
```

### Dynamic IP Protection

**Most ISPs assign dynamic IPs that change on router restart or lease renewal.** Whitelist your network range:

```bash
# Find your current IP
curl ifconfig.me
# Example output: 203.0.113.45

# Option 1: /24 range (Recommended)
# Whitelists 203.0.113.0 - 203.0.113.255 (256 IPs)
FAIL2BAN_IGNOREIP="127.0.0.1/8 203.0.113.0/24"

# Option 2: /16 range (Broader)
# Whitelists 203.0.0.0 - 203.0.255.255 (65,536 IPs)
FAIL2BAN_IGNOREIP="127.0.0.1/8 203.0.0.0/16"

# Option 3: Multiple ranges/IPs
FAIL2BAN_IGNOREIP="127.0.0.1/8 203.0.113.0/24 198.51.100.0/24 192.0.2.10"
```

The setup wizard validates IP/CIDR notation and detects your current IP automatically.

---

## 🔧 Post-Installation Tasks

### Add Additional Users

```bash
# Create new user with sudo privileges
sudo adduser alice
sudo usermod -aG sudo alice

# Set up their SSH key
sudo mkdir -p /home/alice/.ssh
echo "ssh-ed25519 AAAAC3Nz...alice@laptop" | sudo tee /home/alice/.ssh/authorized_keys
sudo chmod 700 /home/alice/.ssh
sudo chmod 600 /home/alice/.ssh/authorized_keys
sudo chown -R alice:alice /home/alice/.ssh

# Generate password for sudo/console access
sudo passwd alice
```

### Open Additional Ports

```bash
# Allow specific port
sudo ufw allow 8080/tcp

# Allow port range
sudo ufw allow 8000:8100/tcp

# Allow from specific IP
sudo ufw allow from 203.0.113.45 to any port 5432

# View all rules
sudo ufw status numbered

# Delete rule by number
sudo ufw delete 3
```

### Update Whitelist (Post-Setup)

```bash
# Method 1: Interactive helper (recommended)
sudo vm-security whitelist

# Method 2: Manual edit
sudo nano /etc/fail2ban/jail.local
# Update: ignoreip = 127.0.0.1/8 203.0.113.0/24 198.51.100.0/24
sudo systemctl restart fail2ban
```

### Docker Container Security

```bash
# Bind only to localhost (recommended)
docker run -p 127.0.0.1:8080:80 nginx

# Then expose via reverse proxy (e.g., nginx, caddy)
sudo ufw allow 80/tcp  # Only allow proxy port
```

---

## 🆘 Troubleshooting

### Locked Out by fail2ban

**Symptom**: SSH connection refused or "Connection closed by remote host"

**Solution** (via console access):

```bash
# Check if banned
sudo fail2ban-client status sshd

# Unban your IP
sudo fail2ban-client unban 203.0.113.45

# Or unban everyone
sudo fail2ban-client unban --all

# Add your IP to whitelist permanently
sudo vm-security whitelist
```

### Can't SSH After Setup

**Symptom**: "Permission denied (publickey)" or connection timeout

**Diagnosis** (via console):

```bash
# Check SSH service status
sudo systemctl status sshd

# Test configuration validity
sudo sshd -T

# Check if SSH is listening
sudo ss -tlnp | grep :22

# View recent SSH logs
sudo tail -50 /var/log/auth.log
```

**Fix - SSH Key Issues**:

```bash
# Verify key file permissions
ls -la /home/YOUR_USER/.ssh/

# Fix permissions
sudo chmod 700 /home/YOUR_USER/.ssh
sudo chmod 600 /home/YOUR_USER/.ssh/authorized_keys
sudo chown -R YOUR_USER:YOUR_USER /home/YOUR_USER/.ssh

# Verify key format
cat /home/YOUR_USER/.ssh/authorized_keys
# Should start with: ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256, etc.
```

**Emergency: Temporarily Disable Hardening**:

```bash
sudo mv /etc/ssh/sshd_config.d/99-hardening.conf /root/99-hardening.conf.backup
sudo systemctl restart sshd
# Test SSH, then restore: sudo mv /root/99-hardening.conf.backup /etc/ssh/sshd_config.d/99-hardening.conf
```

### UFW Blocking Legitimate Traffic

```bash
# Check current rules
sudo ufw status numbered

# Check logs for blocks
sudo tail -100 /var/log/ufw.log

# Temporarily disable (for testing only)
sudo ufw disable

# Re-enable after fixing rules
sudo ufw enable
```

### AIDE Reports Not Generating

```bash
# Check if AIDE database exists
ls -lh /var/lib/aide/aide.db

# Manually run check
sudo /etc/cron.daily/aide-check

# View report
sudo ls -lh /var/log/aide/
sudo cat /var/log/aide/aide-check-*.log | tail -50
```

### Forgot Admin Username

```bash
# List all sudo users (via console)
getent group sudo

# Or check all users
cat /etc/passwd | grep -v nologin | grep -v false | cut -d: -f1
```

### High CPU Usage

```bash
# Check service resource usage
systemctl status auditd fail2ban

# View top processes
htop

# If AIDE is running (daily scan)
ps aux | grep aide
# This is normal - scan takes 2-10 minutes

# Reduce auditd rules if needed
sudo nano /etc/audit/rules.d/soc2-compliance.rules
sudo systemctl restart auditd
```

---

## 📊 What Gets Configured

### Security Components

| Component | Configuration | Impact |
|-----------|---------------|--------|
| **SSH** | • No root login<br>• Key-only authentication (password auth disabled)<br>• Modern ciphers (ChaCha20, AES-GCM)<br>• MaxAuthTries: 3<br>• Verbose logging | High |
| **fail2ban** | • 5 attempts → 1hr ban<br>• 10min time window<br>• Current IP auto-whitelisted<br>• SSH jail enabled | High |
| **UFW Firewall** | • Default deny incoming<br>• Default allow outgoing<br>• SSH + HTTP/HTTPS allowed<br>• Rate limiting on SSH | High |
| **Docker** | • Cannot bypass UFW<br>• Inter-container communication disabled<br>• No new privileges<br>• Logging enabled | High |
| **auditd** | • System call logging<br>• File access monitoring<br>• User/group changes tracked<br>• 8192-entry buffer | Medium |
| **AIDE** | • Daily integrity checks<br>• Critical file monitoring<br>• Change reports to `/var/log/aide/` | Low |
| **chrony** | • NTP time sync<br>• Multiple pool sources<br>• Clock drift tracking | Low |
| **Password Policy** | • 14 character minimum<br>• Complexity requirements<br>• 90-day expiration<br>• User uniqueness check | Medium |
| **Kernel** | • SYN cookies enabled<br>• IP forwarding restricted<br>• ICMP redirects blocked<br>• Martian packet logging | Medium |
| **Log Retention** | • 365 days for auth/syslog<br>• Compressed rotation<br>• SOC2 compliant | Low |

### Performance Impact

| Service | CPU | Memory | Disk I/O | Notes |
|---------|-----|--------|----------|-------|
| fail2ban | ~1-2% | 30-50 MB | Low | Increases with attack volume |
| auditd | ~2-5% | 20-40 MB | Medium | Depends on audit rules |
| UFW | <0.1% | 10-20 MB | Minimal | iptables is very efficient |
| AIDE | 10-30% | 50-100 MB | High | Only during daily scan (2-10 min) |
| Other | <1% | 50-100 MB | Minimal | Combined overhead |
| **Total** | **~5-8%** | **~200 MB** | **Low** | Continuous (except AIDE) |

**Recommendation**: For production workloads, allocate at least 2 vCPU and 2GB RAM.

---

## 📝 File Locations

### Configuration Files

| File | Purpose |
|------|---------|
| `/etc/ssh/sshd_config.d/99-hardening.conf` | SSH security settings |
| `/etc/fail2ban/jail.local` | fail2ban rules and whitelist |
| `/etc/ufw/after.rules` | Docker-UFW integration |
| `/etc/audit/rules.d/soc2-compliance.rules` | Audit rules |
| `/etc/aide/aide.conf` | File integrity monitoring config |
| `/etc/sysctl.d/99-soc2-hardening.conf` | Kernel security parameters |

### Log Files

| Log | Path | Retention |
|-----|------|-----------|
| Setup Log | `/root/security-setup-YYYYMMDD-HHMMSS.log` | Manual |
| SSH Authentication | `/var/log/auth.log` | 365 days |
| fail2ban | `/var/log/fail2ban.log` | 365 days |
| Audit Logs | `/var/log/audit/audit.log` | Permanent |
| AIDE Reports | `/var/log/aide/aide-check-YYYYMMDD.log` | Manual |
| Firewall | `/var/log/ufw.log` | 365 days |
| System Log | `/var/log/syslog` | 365 days |

### View Logs

```bash
# Interactive viewer
vm-security logs

# Direct access
sudo tail -50 /var/log/auth.log
sudo journalctl -u sshd -n 50
sudo fail2ban-client status sshd
```

---

## 🔒 Anti-Lockout Protections

This tool includes multiple safeguards to prevent accidental lockouts:

- ✅ **Automatic IP Detection** - Detects your connection IP via multiple methods
- ✅ **Pre-Whitelist** - Your IP is whitelisted before fail2ban starts
- ✅ **Network Range Support** - Whitelist entire subnets for dynamic IPs
- ✅ **SSH Key Validation** - Keys are tested before applying SSH hardening
- ✅ **Configuration Testing** - `sshd -T` validation before restart
- ✅ **Increased Retry Limit** - 5 attempts (vs default 3) reduces false bans
- ✅ **Localhost Exemption** - Local connections never banned
- ✅ **Interactive Prompts** - Confirm before applying critical changes
- ✅ **Multiple Warnings** - Repeated reminders to test before logout
- ✅ **Backup Configs** - Original configs saved before modification
- ✅ **Console Fallback** - Password auth still works via console

---

## 🧪 Testing & Validation

### Test Security Setup

```bash
# 1. Check service status
vm-security status

# 2. Verify firewall rules
sudo ufw status verbose

# 3. Test from external machine
nmap -p 1-1000 YOUR_VM_IP
# Should only show allowed ports (SSH, 80, 443)

# 4. Test fail2ban (from another IP)
ssh wrong_user@YOUR_VM_IP
# Enter wrong password 5+ times

# 5. Verify ban
sudo fail2ban-client status sshd
# Should show the attacking IP in banned list

# 6. Check audit logs
sudo ausearch -i --start recent | head -20

# 7. Test SSH key auth
ssh -v -p 22 your_user@YOUR_VM_IP
# Should login without password prompt
```

### Validate Configurations

```bash
# SSH configuration syntax
sudo sshd -T

# fail2ban status
sudo fail2ban-client ping
sudo fail2ban-client status

# Audit daemon
sudo auditctl -l

# AIDE database
sudo aide --config=/etc/aide/aide.conf --check

# System logs
sudo journalctl -xe | tail -50
```

---

## 🏢 Use Cases

### Development VMs
- Quick setup for testing environments
- Automatic security without manual config
- Easy port management for dev servers

### Production Servers
- SOC2/ISO compliance ready
- 365-day audit trail
- Real-time intrusion detection

### CI/CD Runners
- Secure build environments
- Audit logging for compliance
- Prevents lateral movement

### Client Hosting
- Multi-tenant security isolation
- Comprehensive logging for disputes
- Professional security posture

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Test thoroughly on Ubuntu 24.04
4. Submit pull request with clear description

### Testing Checklist

- [ ] Fresh Ubuntu 24.04 VM
- [ ] Setup completes without errors
- [ ] SSH access works after setup
- [ ] fail2ban bans working
- [ ] All status checks pass
- [ ] Logs viewer functional
- [ ] Reapply works without issues

---

## 📜 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## 🆘 Support

### Locked Out?

1. **Access via Console** (VPS control panel, not SSH)
2. **Follow Troubleshooting** (see above)
3. **Open GitHub Issue** with:
   - OS version (`lsb_release -a`)
   - Command that failed
   - Error messages
   - Last 50 lines of `/root/security-setup-*.log`

### Bug Reports

Open an issue with:
- **Environment**: OS version, RAM, vCPU
- **Command**: Exact command run
- **Expected**: What should happen
- **Actual**: What actually happened
- **Logs**: Relevant log excerpts

### Feature Requests

Suggest improvements via GitHub Issues. Include:
- Use case / problem statement
- Proposed solution
- Alternative approaches considered

---

## 🙏 Acknowledgments

Built with guidance from:
- [CIS Ubuntu Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [DevSec Hardening Framework](https://dev-sec.io/)
- [fail2ban Documentation](https://fail2ban.readthedocs.io/)

---

## 📚 Additional Resources

- [SSH Key Management Best Practices](https://www.ssh.com/academy/ssh/public-key-authentication)
- [Understanding fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page)
- [UFW Firewall Guide](https://help.ubuntu.com/community/UFW)
- [Linux Audit Framework](https://linux-audit.com/configuring-and-auditing-linux-systems-with-audit-daemon/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)

---

<div align="center">

**⚡ Secure your VM in 5 minutes. Test in 1. Deploy with confidence. ⚡**

[![GitHub](https://img.shields.io/github/stars/2kjm/vm-security?style=social)](https://github.com/2kjm/vm-security)

**[Get Started](#-quick-start)** • **[Documentation](#-usage)** • **[Support](#-support)**

</div>

---

**⚠️ Remember**: Always test SSH access in a new terminal before logging out of your current session! 🔒
