# 🛡️ VM Security Management Tool

**Complete VM security hardening in one command** - SOC2-aligned controls, anti-lockout protections, and comprehensive monitoring.

## ✨ Features

- **SSH Hardening** - Key-only auth, modern ciphers, root login disabled
- **Intrusion Prevention** - fail2ban with automatic IP banning
- **Firewall** - UFW with default deny + explicit allow rules
- **Docker Security** - Prevents Docker from bypassing firewall
- **SOC2 Controls** - Audit logging, file integrity (AIDE), 365-day retention
- **Auto Updates** - Automatic security patches
- **Password Policies** - 14-char minimum, 90-day rotation
- **Kernel Hardening** - Network security and privilege restrictions

## 🚀 Quick Start

### Prerequisites

- Ubuntu 24.04
- Root/sudo access
- Your SSH public key (from `cat ~/.ssh/id_ed25519.pub` on your local machine)
- **Console access** available as backup

### Installation

```bash
# Download
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/vm-security/main/vm-security.sh -o vm-security.sh
chmod +x vm-security.sh

# Install system-wide (optional but recommended)
sudo ./vm-security.sh install

# Run setup (interactive)
sudo vm-security setup
```

During setup you'll be prompted for:
1. Admin username
2. SSH public key
3. Whitelist strategy (recommended: /24 network range for dynamic IPs)

### ⚠️ Critical: Test Before Logout

Open a **NEW terminal** and test SSH access:

```bash
ssh -p 22 your_username@your_vm_ip
```

**DO NOT logout until you've verified SSH works!**

## 📖 Usage

```bash
# Check security status
vm-security status
vm-security status --detailed

# View logs
vm-security logs

# Re-apply security hardening
sudo vm-security reapply

# Emergency unban
sudo vm-security unban YOUR_IP
sudo vm-security unban all
```

## ⚙️ Configuration

Edit these at the top of the script before running setup:

```bash
NEW_USER=""                          # Admin username (or leave empty for prompt)
SSH_PUBLIC_KEY=""                    # SSH public key (or leave empty for prompt)
SSH_PORT=22                          # SSH port
FAIL2BAN_MAXRETRY=5                 # Failed attempts before ban
FAIL2BAN_BANTIME=3600               # Ban duration (seconds)
FAIL2BAN_IGNOREIP="127.0.0.1/8"     # Whitelisted IPs/ranges (space-separated)
ALLOWED_HTTP_PORTS="80,443"         # Ports to allow
ENABLE_AUTO_UPDATES=true            # Auto security updates
```

### Whitelist Your Network Range (Recommended)

**Most ISPs use dynamic IPs that change frequently!** Whitelist your network range instead:

```bash
# Find your IP
curl ifconfig.me
# Example: 203.0.113.45

# Whitelist /24 range (recommended - 256 IPs)
FAIL2BAN_IGNOREIP="127.0.0.1/8 203.0.113.0/24"

# Or /16 range (65K IPs - less secure but more convenient)
FAIL2BAN_IGNOREIP="127.0.0.1/8 203.0.0.0/16"
```

The script will prompt you for this during setup with validation.

## 🔧 Post-Installation

### Add More Users

```bash
sudo adduser newuser
sudo usermod -aG sudo newuser

# Add their SSH key
sudo mkdir -p /home/newuser/.ssh
echo "their-ssh-public-key" | sudo tee /home/newuser/.ssh/authorized_keys
sudo chmod 700 /home/newuser/.ssh
sudo chmod 600 /home/newuser/.ssh/authorized_keys
sudo chown -R newuser:newuser /home/newuser/.ssh
```

### Allow Additional Ports

```bash
sudo ufw allow 8080/tcp
sudo ufw status numbered
```

### Update Whitelist

```bash
sudo nano /etc/fail2ban/jail.local
# Add to ignoreip line: 127.0.0.1/8 203.0.113.0/24 198.51.100.0/24
sudo systemctl restart fail2ban
```

## 🆘 Troubleshooting

### Locked Out via fail2ban

Use console access:

```bash
sudo fail2ban-client unban YOUR_IP
# Or unban all
sudo fail2ban-client unban --all
```

### Can't SSH After Setup

Via console:

```bash
# Check SSH status
sudo systemctl status sshd

# Check if banned
sudo fail2ban-client status sshd

# Test SSH config
sudo sshd -T

# Temporarily disable hardening
sudo mv /etc/ssh/sshd_config.d/99-hardening.conf /root/
sudo systemctl restart sshd
```

### SSH Key Not Working

```bash
# Fix permissions
sudo chmod 700 /home/YOUR_USER/.ssh
sudo chmod 600 /home/YOUR_USER/.ssh/authorized_keys
sudo chown -R YOUR_USER:YOUR_USER /home/YOUR_USER/.ssh
```

### Forgot Username

```bash
# List sudo users
getent group sudo
```

## 📊 What Gets Configured

| Component | Settings |
|-----------|----------|
| **SSH** | No root login, key-only auth, modern ciphers, verbose logging |
| **fail2ban** | 5 attempts → 1hr ban, current IP whitelisted |
| **UFW** | Default deny, SSH + HTTP/HTTPS allowed, rate limiting |
| **Docker** | Can't bypass UFW, container isolation, no privilege escalation |
| **auditd** | System call & file access logging |
| **AIDE** | Daily file integrity checks |
| **chrony** | Time synchronization |
| **Passwords** | 14-char min, complexity rules, 90-day expiry |
| **Logs** | 365-day retention (SOC2 compliant) |

## 📝 Log Files

| Log | Path |
|-----|------|
| Setup | `/root/security-setup-*.log` |
| Authentication | `/var/log/auth.log` |
| fail2ban | `/var/log/fail2ban.log` |
| Audit | `/var/log/audit/audit.log` |
| AIDE reports | `/var/log/aide/aide-check-*.log` |
| Firewall | `/var/log/ufw.log` |

View logs: `vm-security logs`

## 🔒 Anti-Lockout Features

- ✅ Current SSH IP auto-whitelisted
- ✅ SSH key validation before applying
- ✅ Increased retry limit (5 attempts)
- ✅ Localhost never banned
- ✅ Network range support for dynamic IPs
- ✅ Pre-flight safety checks
- ✅ Multiple warnings to test before logout

## 🧪 Testing

```bash
# Check all services
vm-security status

# Test fail2ban (from another machine)
ssh wrong_user@your_vm  # Try wrong password 5+ times
# Then check: sudo fail2ban-client status sshd

# Test firewall
sudo ufw status verbose
nmap -p 1-1000 your_vm_ip  # Only allowed ports should be open
```

## 📜 License

MIT License - See LICENSE file

## 🆘 Support

**Locked out?**
1. Use console access (VPS control panel)
2. Check troubleshooting section above
3. Open GitHub issue with details

**Found a bug?**
Open an issue with:
- OS version
- Command run
- Error message
- Last few lines of `/root/security-setup-*.log`

---

**Remember**: Always test SSH in a new terminal before logging out! 🔒
