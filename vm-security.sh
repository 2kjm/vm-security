#!/bin/bash
################################################################################
# VM Security Hardening
#
# One-shot hardening for Ubuntu VMs (idempotent, safe to re-run).
# Features: SSH hardening, UFW, fail2ban, Docker (official install + UFW fix),
#           auditd, auto updates, kernel hardening.
#
# Usage: curl -fsSL <url> -o vm-security.sh && sudo bash vm-security.sh
# Author: 2kjm (https://github.com/2kjm)
# Version: 0.2.0
################################################################################

set -Eeuo pipefail

# Require Ubuntu
if ! grep -qi 'ubuntu' /etc/os-release 2>/dev/null; then
    echo "ERROR: This script requires Ubuntu. Detected: $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo "unknown")" >&2
    exit 1
fi

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# Configuration
NEW_USER=""
SSH_PORT=22
CHANGE_SSH_PORT=false
SSH_PUBLIC_KEY=""
FAIL2BAN_BANTIME=3600
FAIL2BAN_MAXRETRY=5
FAIL2BAN_FINDTIME=600
FAIL2BAN_IGNOREIP="127.0.0.1/8"
ENABLE_AUTO_UPDATES=true
INSTALL_DOCKER=true
SETUP_POSTGRES=false
ALLOWED_HTTP_PORTS="80,443"
CURRENT_IP=""
USER_PASSWORD=""

################################################################################
# Helpers
################################################################################

print_status()  { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error()   { echo -e "${RED}[-]${NC} $1"; }

print_header() {
    echo ""
    echo -e "${CYAN}--- $1 ---${NC}"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then print_error "Must be run as root (use sudo)"; exit 1; fi
}

# Validate SSH port number
validate_ssh_port() {
    local port="$1"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        print_error "Invalid SSH port: $port (must be 1-65535)"
        exit 1
    fi
}

# Validate sshd config and restart — prevents lockout from broken config
safe_restart_sshd() {
    if sshd -T >/dev/null 2>&1; then
        systemctl restart sshd 2>/dev/null || systemctl restart ssh
    else
        print_error "SSH config validation failed — sshd NOT restarted to prevent lockout"
        sshd -T
        return 1
    fi
}

# Validate IP address or CIDR notation (space-separated list)
validate_ip_or_cidr() {
    local input="$1"
    # shellcheck disable=SC2086 -- intentional word split for multi-IP input
    for entry in $input; do
        # IPv6 (with optional CIDR)
        if [[ "$entry" == *:* ]]; then
            local ip6_part="${entry%%/*}"
            if ! [[ "$ip6_part" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]] \
               && ! [[ "$ip6_part" =~ ^::$ ]] \
               && ! [[ "$ip6_part" =~ ^(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?$ ]]; then
                return 1
            fi
            if [[ "$entry" == */* ]]; then
                local mask6="${entry##*/}"
                if ! [[ "$mask6" =~ ^[0-9]+$ ]] || [ "$mask6" -gt 128 ]; then
                    return 1
                fi
            fi
        # IPv4 (with optional CIDR)
        elif [[ "$entry" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
            local ip_part="${entry%%/*}"
            IFS='.' read -ra octets <<< "$ip_part"
            for octet in "${octets[@]}"; do
                if ! [[ "$octet" =~ ^[0-9]+$ ]] || [ "$octet" -gt 255 ]; then
                    return 1
                fi
            done
            if [[ "$entry" == */* ]]; then
                local mask="${entry##*/}"
                if ! [[ "$mask" =~ ^[0-9]+$ ]] || [ "$mask" -gt 32 ]; then
                    return 1
                fi
            fi
        else
            return 1
        fi
    done
    return 0
}

# Detect current SSH client IP (single function, no duplication)
detect_client_ip() {
    local ip=""
    [ -n "${SSH_CONNECTION:-}" ] && ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    [ -z "$ip" ] && [ -n "${SSH_CLIENT:-}" ] && ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
    if [ -z "$ip" ] && [ -n "${SUDO_USER:-}" ]; then
        ip=$(ps -eo user,cmd,args 2>/dev/null | grep "^${SUDO_USER}.*sshd:" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
    fi
    [ -z "$ip" ] && ip=$(who am i 2>/dev/null | awk '{print $5}' | sed 's/[()]//g' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
    [ -z "$ip" ] && ip=$(w -h 2>/dev/null | grep "$(whoami)\|${SUDO_USER:-nobody}" | head -1 | awk '{print $3}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
    [ -z "$ip" ] && ip=$(last -i 2>/dev/null | grep "still logged in" | head -1 | awk '{print $3}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
    [ -z "$ip" ] && [ -n "${PAM_RHOST:-}" ] && ip="$PAM_RHOST"
    if [ -n "$ip" ] && [ "$ip" != "127.0.0.1" ] && [ "$ip" != "0.0.0.0" ]; then
        echo "$ip"
    fi
    return 0
}

# Generate and set a random password for a user
setup_user_password() {
    local user="$1"
    local random_pass
    # Generate password meeting PAM complexity: upper + lower + digit + special
    local base
    base=$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 24)
    random_pass="${base}@Kz5"

    if chpasswd <<< "$user:$random_pass"; then
        USER_PASSWORD="$random_pass"
        return 0
    else
        print_error "Failed to set password"
        return 1
    fi
}

################################################################################
# INTERACTIVE PROMPTS
################################################################################
prompt_user_config() {
    # Username
    if [ -z "$NEW_USER" ]; then
        print_header "Step 1: Create Admin User"
        echo "Create a non-root admin user with sudo privileges."
        echo ""
        while true; do
            read -rp "Enter username: " NEW_USER
            [ -z "$NEW_USER" ] && print_error "Cannot be empty" && continue
            [ "$NEW_USER" = "root" ] && print_error "Cannot use 'root'" && continue
            [[ ! "$NEW_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] && print_error "Invalid format (lowercase, numbers, hyphens, underscores)" && continue
            if id "$NEW_USER" &>/dev/null; then
                print_warning "User '$NEW_USER' already exists — using existing user."
                break
            fi
            read -rp "Create user '$NEW_USER'? (y/n) " -n 1; echo
            [[ $REPLY =~ ^[Yy]$ ]] && break || NEW_USER=""
        done
    fi

    # SSH key
    if [ -z "$SSH_PUBLIC_KEY" ]; then
        print_header "Step 2: SSH Key"
        echo "On your LOCAL machine, run: cat ~/.ssh/id_ed25519.pub"
        echo "Copy the output and paste below."
        echo ""
        print_warning "Without a valid SSH key you WILL be locked out."
        echo ""
        read -rp "Have your SSH public key ready? (y/n) " -n 1; echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then print_error "Get your SSH key first."; exit 1; fi

        read -rp "Paste your SSH public key: " -r SSH_PUBLIC_KEY

        if [[ "$SSH_PUBLIC_KEY" =~ ^ssh-dss ]]; then
            print_error "DSA keys are deprecated and insecure. Use: ssh-keygen -t ed25519"
            exit 1
        fi
        if [[ ! "$SSH_PUBLIC_KEY" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519|sk-ecdsa-sha2-nistp256) ]]; then
            print_error "Invalid SSH key format"; exit 1
        fi

        # Validate key with ssh-keygen using secure temp file
        local tmpkey
        tmpkey=$(mktemp)
        chmod 600 "$tmpkey"
        echo "$SSH_PUBLIC_KEY" > "$tmpkey"
        if ! ssh-keygen -l -f "$tmpkey" >/dev/null 2>&1; then
            rm -f "$tmpkey"
            print_error "Malformed SSH key"
            exit 1
        fi
        rm -f "$tmpkey"
        print_success "SSH key validated"
    fi

    # Whitelist
    CURRENT_IP=$(detect_client_ip)

    echo ""
    print_header "Step 3: fail2ban Whitelist"
    echo "Whitelist trusted IPs to prevent accidental lockouts."
    echo "Most ISPs use dynamic IPs — whitelist your /24 subnet to stay safe."
    echo ""

    if [ -n "$CURRENT_IP" ]; then
        local network_prefix="${CURRENT_IP%.*}"
        local suggested_24="${network_prefix}.0/24"
        local suggested_16="${CURRENT_IP%%.*}.${CURRENT_IP#*.}"; suggested_16="${CURRENT_IP%.*.*}.0.0/16"
        print_success "Detected your IP: $CURRENT_IP"
        echo ""
        echo "1) Current IP only        — $CURRENT_IP (risky if IP changes)"
        echo "2) /24 network range      — $suggested_24 (recommended, 256 IPs)"
        echo "3) /16 network range      — $suggested_16 (broad, 65K IPs)"
        echo "4) Custom                 — enter your own IP(s)/range(s)"
        echo "5) Use configured default — $FAIL2BAN_IGNOREIP"
        local menu_max=5
    else
        print_warning "Could not detect your IP (console/VNC session)"
        echo ""
        echo "1) Enter IP manually"
        echo "2) Use configured default — $FAIL2BAN_IGNOREIP (localhost only!)"
        local menu_max=2
    fi
    echo ""

    while true; do
        read -rp "Select (1-$menu_max): " choice
        if [ -n "$CURRENT_IP" ]; then
            case $choice in
                1) FAIL2BAN_IGNOREIP="127.0.0.1/8 $CURRENT_IP"
                   print_warning "Using single IP: $CURRENT_IP — risky if it changes"; break ;;
                2) FAIL2BAN_IGNOREIP="127.0.0.1/8 $suggested_24"
                   print_success "Using /24 range: $suggested_24"; break ;;
                3) FAIL2BAN_IGNOREIP="127.0.0.1/8 $suggested_16"
                   print_warning "Using /16 range: $suggested_16 (broad)"; break ;;
                4) read -rp "Enter IP(s)/range(s): " custom
                   [ -z "$custom" ] && print_error "Cannot be empty" && continue
                   validate_ip_or_cidr "$custom" || { print_error "Invalid format"; continue; }
                   FAIL2BAN_IGNOREIP="127.0.0.1/8 $custom"; break ;;
                5) break ;;
                *) print_error "Invalid option" ;;
            esac
        else
            case $choice in
                1) read -rp "Enter IP(s)/range(s): " manual_ip
                   [ -z "$manual_ip" ] && print_error "Cannot be empty" && continue
                   validate_ip_or_cidr "$manual_ip" || { print_error "Invalid format"; continue; }
                   FAIL2BAN_IGNOREIP="127.0.0.1/8 $manual_ip"
                   CURRENT_IP=$(echo "$manual_ip" | awk '{print $1}' | cut -d'/' -f1); break ;;
                2) print_warning "Using localhost only!"
                   read -rp "Type 'yes' to confirm: " confirm
                   [ "$confirm" = "yes" ] && break ;;
                *) print_error "Invalid option" ;;
            esac
        fi
    done
    print_success "Whitelist: $FAIL2BAN_IGNOREIP"

    # Docker / PostgreSQL (mutually exclusive)
    print_header "Step 4: Docker / PostgreSQL"
    local pg_detected=false
    local docker_detected=false
    { command -v psql &>/dev/null || command -v pg_lsclusters &>/dev/null; } && pg_detected=true || true
    command -v docker &>/dev/null && docker_detected=true || true

    if [ "$docker_detected" = true ] && [ "$pg_detected" = true ]; then
        print_warning "Both Docker and PostgreSQL detected on this system."
        print_warning "Running Docker and PostgreSQL on the same VM is not recommended."
        print_warning "Docker will be hardened since it's already installed."
        INSTALL_DOCKER=true
        SETUP_POSTGRES=false
    elif [ "$docker_detected" = true ]; then
        print_status "Docker is already installed — will harden existing installation"
        INSTALL_DOCKER=true
    elif [ "$pg_detected" = true ]; then
        print_status "PostgreSQL detected — skipping Docker"
        print_status "Docker and PostgreSQL should not run on the same VM."
        INSTALL_DOCKER=false
        SETUP_POSTGRES=true
    else
        echo "Choose your workload (Docker and PostgreSQL should not share a VM):"
        echo ""
        echo "1) Install Docker CE"
        echo "2) Prepare for PostgreSQL (run postgres-security.sh setup after)"
        echo "3) Neither"
        echo ""
        while true; do
            read -rp "Select (1-3): " choice
            case $choice in
                1) INSTALL_DOCKER=true; SETUP_POSTGRES=false; break ;;
                2) INSTALL_DOCKER=false; SETUP_POSTGRES=true; break ;;
                3) INSTALL_DOCKER=false; SETUP_POSTGRES=false; break ;;
                *) print_error "Invalid option" ;;
            esac
        done
    fi

    # Confirmation
    echo ""
    echo "Configuration:"
    echo "  User:        $NEW_USER"
    echo "  SSH Port:    $SSH_PORT"
    echo "  Docker:      $( [ "$INSTALL_DOCKER" = true ] && echo "yes" || echo "no" )"
    echo "  PostgreSQL:  $( [ "$SETUP_POSTGRES" = true ] && echo "yes (run postgres-security.sh setup after)" || echo "no" )"
    echo "  fail2ban:    $FAIL2BAN_MAXRETRY attempts, ${FAIL2BAN_BANTIME}s ban"
    echo "  Whitelist:   $FAIL2BAN_IGNOREIP"
    echo ""
    print_warning "Test SSH in a NEW terminal BEFORE closing this one!"
    echo ""
    read -rp "Continue? (y/n) " -n 1; echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then exit 0; fi
}

################################################################################
# APPLY HARDENING (the actual security work)
################################################################################
apply_hardening() {
    LOG_FILE="/root/security-setup-$(date +%Y%m%d-%H%M%S).log"
    trap 'print_error "Failed at line $LINENO"; trap - ERR; exit 1' ERR

    print_warning "DO NOT close this terminal until you have tested SSH in a new window"
    echo ""
    validate_ssh_port "$SSH_PORT"

    # 1. System update (security-critical packages only — full upgrade deferred to unattended-upgrades)
    print_header "1. System Update"
    apt-get update -qq
    apt-get install -y --only-upgrade -qq openssh-server 2>/dev/null || true
    print_success "System updated"

    # 2. Admin user + SSH key
    print_header "2. Admin User"
    USER_PASSWORD=""
    if ! id "$NEW_USER" &>/dev/null; then
        adduser --disabled-password --gecos "" "$NEW_USER"
        usermod -aG sudo "$NEW_USER"
        setup_user_password "$NEW_USER"
        print_success "User $NEW_USER created"
    else
        print_warning "User $NEW_USER already exists"
        read -rp "Reset password? (y/n) " -n 1 < /dev/tty; echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then setup_user_password "$NEW_USER"; fi
    fi

    mkdir -p "/home/$NEW_USER/.ssh"
    chmod 700 "/home/$NEW_USER/.ssh"
    touch "/home/$NEW_USER/.ssh/authorized_keys"
    chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
    if ! grep -qF "$SSH_PUBLIC_KEY" "/home/$NEW_USER/.ssh/authorized_keys" 2>/dev/null; then
        echo "$SSH_PUBLIC_KEY" >> "/home/$NEW_USER/.ssh/authorized_keys"
    fi
    chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.ssh"
    print_success "SSH key configured"

    # 3. SSH hardening (idempotent with markers)
    print_header "3. SSH Hardening"
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.backup-$(date +%Y%m%d)" 2>/dev/null || true

    # Ensure sshd_config loads drop-in configs (missing on Ubuntu 20.04)
    mkdir -p /etc/ssh/sshd_config.d
    if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config 2>/dev/null; then
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
        print_status "Added Include directive to sshd_config"
    fi

    # Override cloud-init SSH settings that conflict with hardening
    if [ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]; then
        print_status "Overriding cloud-init SSH config (50-cloud-init.conf)"
        echo "PasswordAuthentication no" > /etc/ssh/sshd_config.d/50-cloud-init.conf
    fi

    # Drop-in config (always overwritten, idempotent)
    cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
AllowGroups sudo
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
EOF

    # Modify main config via sed (idempotent — sed replaces in-place)
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config

    # Add if missing
    grep -qE "^#?PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
    grep -qE "^#?PasswordAuthentication" /etc/ssh/sshd_config || echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
    grep -qE "^#?PubkeyAuthentication" /etc/ssh/sshd_config || echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config

    # Force block with markers (idempotent — remove old, write new)
    sed -i '/^# vm-security-force-begin$/,/^# vm-security-force-end$/d' /etc/ssh/sshd_config
    cat >> /etc/ssh/sshd_config << 'EOF'
# vm-security-force-begin
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin no
# vm-security-force-end
EOF

    if [ "$CHANGE_SSH_PORT" = true ]; then sed -i "s/^#\\?Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config; fi

    mkdir -p /run/sshd && chmod 0755 /run/sshd
    if ! sshd -T >/dev/null 2>&1; then
        print_error "SSH config validation failed!"
        sshd -T
        exit 1
    fi
    print_success "SSH hardened and validated"

    # 4. Docker install (official repo) — optional
    if [ "$INSTALL_DOCKER" = true ]; then
    print_header "4. Docker (Official Repo)"
    if ! command -v docker &>/dev/null || ! docker --version 2>/dev/null | grep -q "Docker"; then
        print_status "Installing Docker CE from official repository..."
        # Remove conflicting packages
        apt-get remove -y docker.io docker-compose docker-compose-v2 \
            docker-doc podman-docker containerd runc 2>/dev/null || true

        # Set up official apt repository
        apt-get install -y ca-certificates curl -qq
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
        chmod a+r /etc/apt/keyrings/docker.asc

        # shellcheck disable=SC1091
        tee /etc/apt/sources.list.d/docker.sources >/dev/null <<DEOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
DEOF

        apt-get update -qq
        apt-get install -y docker-ce docker-ce-cli containerd.io \
            docker-buildx-plugin docker-compose-plugin -qq
        print_success "Docker CE installed"
    else
        print_status "Docker already installed: $(docker --version 2>/dev/null)"
    fi
    usermod -aG docker "$NEW_USER" 2>/dev/null || true

    # 5. Docker hardening + UFW bypass fix
    print_header "5. Docker Security"
    if command -v docker &>/dev/null; then
        mkdir -p /etc/docker
        [ -f /etc/docker/daemon.json ] && cp /etc/docker/daemon.json "/etc/docker/daemon.json.backup-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true

        cat > /etc/docker/daemon.json << 'EOF'
{
  "iptables": true,
  "userland-proxy": false,
  "icc": false,
  "log-driver": "json-file",
  "log-opts": {"max-size": "10m", "max-file": "5"},
  "live-restore": true,
  "no-new-privileges": true
}
EOF

        # UFW bypass fix — route Docker traffic through UFW
        cp /etc/ufw/after.rules "/etc/ufw/after.rules.backup-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
        sed -i '/# Docker UFW Integration/,/^COMMIT$/d' /etc/ufw/after.rules 2>/dev/null || true

        local docker_rules_tmp
        docker_rules_tmp=$(mktemp)
        chmod 600 "$docker_rules_tmp"
        cat > "$docker_rules_tmp" << 'EOF'
# Docker UFW Integration - PREVENTS BYPASS
*filter
:ufw-user-forward - [0:0]
:ufw-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -i docker0 -j ACCEPT
-A DOCKER-USER -i br-+ -o br-+ -j ACCEPT
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-USER -m conntrack --ctstate INVALID -j DROP
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -j ufw-docker-logging-deny
-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP
COMMIT

EOF

        local ufw_tmp
        ufw_tmp=$(mktemp)
        chmod 600 "$ufw_tmp"
        cat "$docker_rules_tmp" /etc/ufw/after.rules > "$ufw_tmp"
        cat "$ufw_tmp" > /etc/ufw/after.rules
        rm -f "$ufw_tmp" "$docker_rules_tmp"
        print_success "Docker secured — cannot bypass UFW"
    fi
    else
        print_header "4. Docker"
        print_status "Docker installation skipped (disabled)"
    fi

    # 6. fail2ban
    print_header "6. fail2ban"
    apt-get install -y fail2ban -qq

    # Re-detect IP to ensure whitelist is current
    local detected_ip
    detected_ip=$(detect_client_ip) || true
    if [ -n "$detected_ip" ]; then CURRENT_IP="$detected_ip"; fi

    local whitelist_ips="$FAIL2BAN_IGNOREIP"
    if [ -n "$CURRENT_IP" ]; then
        echo " $whitelist_ips " | grep -qw "$CURRENT_IP" || whitelist_ips="$whitelist_ips $CURRENT_IP"
        print_status "Your IP ($CURRENT_IP) added to whitelist"
    fi

    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = $FAIL2BAN_BANTIME
findtime = $FAIL2BAN_FINDTIME
maxretry = $FAIL2BAN_MAXRETRY
ignoreip = $whitelist_ips

[sshd]
enabled = true
port = $SSH_PORT
maxretry = $FAIL2BAN_MAXRETRY
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
    print_success "fail2ban configured"

    # 7. UFW firewall (rules applied in-place — no disable/enable gap)
    print_header "7. UFW Firewall"
    apt-get install -y ufw -qq
    sed -i 's/^IPV6=no/IPV6=yes/' /etc/default/ufw
    ufw default deny incoming
    ufw default allow outgoing

    # Delete any existing allow rule for SSH so limit rule is not shadowed
    ufw delete allow "$SSH_PORT/tcp" 2>/dev/null || true
    ufw limit "$SSH_PORT/tcp"

    if [ -n "$ALLOWED_HTTP_PORTS" ]; then
        IFS=',' read -ra ports <<< "$ALLOWED_HTTP_PORTS"
        for port in "${ports[@]}"; do ufw allow "$port/tcp"; done
    fi
    ufw --force enable
    print_success "UFW configured (default deny, IPv6 enabled)"

    # 8. Auto security updates
    print_header "8. Auto Security Updates"
    if [ "$ENABLE_AUTO_UPDATES" = true ]; then
        apt-get install -y unattended-upgrades apt-listchanges -qq

        cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

        cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

        systemctl enable unattended-upgrades && systemctl start unattended-upgrades
        print_success "Auto-updates enabled (security only)"
    fi

    # 9. Kernel hardening
    print_header "9. Kernel Hardening"
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
# IPv4 - all interfaces
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
# IPv4 - default (new interfaces: Docker bridges, VPNs, etc.)
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.rp_filter = 1
# IPv4 - global
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
# IPv6
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# Kernel
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
# Filesystem
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
EOF

    local sysctl_errors
    if sysctl_errors=$(sysctl -p /etc/sysctl.d/99-security.conf 2>&1 >/dev/null); then
        print_success "Kernel hardened (IPv4, IPv6, core dumps)"
    else
        print_warning "Kernel hardening applied with warnings (some params may not be supported):"
        echo "$sysctl_errors" | while read -r line; do
            echo "    $line"
        done
    fi

    # 10. auditd
    print_header "10. Audit Logging (auditd)"
    apt-get install -y auditd audispd-plugins -qq

    cat > /etc/audit/rules.d/security.rules << 'EOF'
-D
-b 8192
-f 1
-w /var/log/audit/ -k auditlog
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd_config
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-w /usr/sbin/useradd -p x -k user_mod
-w /usr/sbin/usermod -p x -k user_mod
-w /etc/hosts -p wa -k network
EOF

    # Docker audit rules BEFORE immutable flag
    # NOTE: Do NOT watch /var/lib/docker — every container write generates an audit
    # event through the overlay filesystem, flooding logs (GBs/day on active systems).
    # Watch the binary and config only.
    if command -v docker &>/dev/null; then
        cat >> /etc/audit/rules.d/security.rules << 'EOF'
-w /usr/bin/docker -p wa -k docker
-w /etc/docker -p wa -k docker
-w /usr/bin/dockerd -p wa -k docker
-w /usr/bin/containerd -p wa -k docker
EOF
    fi

    # Immutable flag must be LAST (requires reboot to modify rules after this)
    print_warning "Audit rules will be IMMUTABLE — changes require a reboot"
    echo "-e 2" >> /etc/audit/rules.d/security.rules

    systemctl enable auditd && systemctl restart auditd
    print_success "Audit logging configured"

    # 11. Restart services + summary
    print_header "11. Restarting Services"
    safe_restart_sshd
    command -v docker &>/dev/null && systemctl restart docker 2>/dev/null || true
    ufw reload

    # Summary
    local server_ip
    server_ip=$(hostname -I | awk '{print $1}')

    print_header "Setup Complete"
    print_warning ">>> TEST NOW: ssh -p $SSH_PORT $NEW_USER@$server_ip <<<"
    echo ""
    echo "Test SSH now:  ssh -p $SSH_PORT $NEW_USER@$server_ip"
    echo ""
    echo "Server:        $server_ip"
    echo "SSH Port:      $SSH_PORT"
    echo "Admin User:    $NEW_USER"
    echo "Your IP:       ${CURRENT_IP:-not detected}"
    echo "Whitelist:     $FAIL2BAN_IGNOREIP"
    echo ""
    echo "Applied:"
    echo "  SSH hardening     — key-only, no root, strong ciphers"
    echo "  fail2ban          — $FAIL2BAN_MAXRETRY attempts, ${FAIL2BAN_BANTIME}s ban"
    echo "  UFW firewall      — default deny, SSH + HTTP(S) allowed"
    if [ "$INSTALL_DOCKER" = true ]; then
    echo "  Docker            — official CE, UFW bypass prevented, hardened daemon"
    fi
    echo "  Auto updates      — security patches only"
    echo "  Kernel hardening  — network stack secured"
    echo "  auditd            — system call and file access logging"
    echo ""
    if [ "$SETUP_POSTGRES" = true ]; then
        print_header "Next: PostgreSQL Hardening"
        echo "  Run: sudo bash postgres-security.sh setup"
        echo ""
    fi
    echo "Config files:"
    echo "  Setup log:       $LOG_FILE"
    echo "  SSH config:      /etc/ssh/sshd_config.d/99-hardening.conf"
    echo "  fail2ban config: /etc/fail2ban/jail.local"
    echo ""

    if [ -n "$CURRENT_IP" ]; then
        print_warning "If your IP changes and you get locked out:"
        echo "  1. Access via cloud console"
        echo "  2. Run: sudo fail2ban-client unban YOUR_IP"
        echo ""
    fi

    print_warning "Emergency unban: sudo fail2ban-client unban YOUR_IP"
    print_warning "Console access uses password (set during setup)"
    echo ""

    # Password display
    if [ -n "$USER_PASSWORD" ]; then
        echo ""
        echo -e "${GREEN}--- GENERATED PASSWORD (save now, shown once) ---${NC}"
        echo -e "  Username: ${CYAN}$NEW_USER${NC}"
        echo -e "  Password: ${YELLOW}$USER_PASSWORD${NC}"
        echo -e "  Use for:  sudo, console access, recovery"
        echo -e "${GREEN}--------------------------------------------------${NC}"
        echo ""
    fi

    print_success "Done. Test SSH before closing this terminal!"

    trap - ERR
}

################################################################################
# MAIN
################################################################################
check_root
prompt_user_config
apply_hardening
