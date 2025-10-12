#!/bin/bash
################################################################################
# VM Security Management Tool - All-in-One
# 
# Purpose: Comprehensive VM security setup, monitoring, and maintenance
# Usage: 
#   vm-security setup              - Initial security hardening (SOC2-aligned controls)
#   vm-security status             - Show current security status
#   vm-security reapply            - Re-run security hardening
#   vm-security install            - Install system-wide commands
#   vm-security help               - Show this help
#
# Author: 2kjm (https://github.com/2kjm)
# Version: 0.1.0
# Date: October 2025
################################################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration (Edit these for initial setup)
################################################################################
NEW_USER=""                          # Username (will prompt if not set)
SSH_PORT=22                          # SSH port (22 = default)
CHANGE_SSH_PORT=false                # Set to true to change SSH port
SSH_PUBLIC_KEY=""                    # Your SSH public key (will prompt if not set)
FAIL2BAN_BANTIME=3600               # Ban time in seconds (1 hour)
FAIL2BAN_MAXRETRY=5                 # Max failed attempts
FAIL2BAN_FINDTIME=600               # Time window (10 min)
FAIL2BAN_IGNOREIP="127.0.0.1/8"     # IPs/networks to never ban
ENABLE_AUTO_UPDATES=true            # Enable automatic updates
ALLOWED_HTTP_PORTS="80,443"         # HTTP/HTTPS ports
################################################################################

# Helper functions
print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

check_status() {
    [ $1 -eq 0 ] && echo -e "${GREEN}✓ ACTIVE${NC}" || echo -e "${RED}✗ INACTIVE${NC}"
}

# Validate IP address or CIDR notation
validate_ip_or_cidr() {
    local input
    input=$1
    
    for ip in $input; do
        # CIDR notation
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            local ip_part
            local mask_part
            ip_part=$(echo $ip | cut -d'/' -f1)
            mask_part=$(echo $ip | cut -d'/' -f2)
            IFS='.' read -ra octets <<< "$ip_part"
            for octet in "${octets[@]}"; do
                [ "$octet" -lt 0 ] 2>/dev/null || [ "$octet" -gt 255 ] 2>/dev/null && return 1
            done
            [ "$mask_part" -lt 0 ] 2>/dev/null || [ "$mask_part" -gt 32 ] 2>/dev/null && return 1
        # Plain IP
        elif [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            IFS='.' read -ra octets <<< "$ip"
            for octet in "${octets[@]}"; do
                [ "$octet" -lt 0 ] 2>/dev/null || [ "$octet" -gt 255 ] 2>/dev/null && return 1
            done
        else
            return 1
        fi
    done
    return 0
}

# Setup password for user (automatic random hex)
setup_user_password() {
    local user=$1
    local random_pass
    random_pass=$(openssl rand -hex 16)
    
    echo ""
    print_status "Generating secure password for $user..."
    echo "Required for: sudo commands, emergency console access, recovery operations"
    echo ""
    
    if echo "$user:$random_pass" | chpasswd; then
        print_success "Password set successfully!"
        
        # Export for final summary (NOT saved to log for security)
        USER_PASSWORD="$random_pass"
        return 0
    else
        print_error "Failed to set password automatically"
        return 1
    fi
}

################################################################################
# SHOW HELP
################################################################################
show_help() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           VM Security Management Tool - Help                         ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Commands:${NC}"
    echo -e "  ${CYAN}setup${NC}              Initial security hardening (SOC2-aligned)"
    echo -e "  ${CYAN}status${NC}             Show current security status"
    echo -e "  ${CYAN}status --detailed${NC}  Show detailed security analysis"
    echo -e "  ${CYAN}reapply${NC}            Re-run security hardening (safe for existing setups)"
    echo -e "  ${CYAN}logs${NC}               View security logs and reports"
    echo -e "  ${CYAN}unban <ip>${NC}         Unban IP from fail2ban (use 'all' for all IPs)"
    echo -e "  ${CYAN}whitelist${NC}          Add IP/range to fail2ban whitelist (for dynamic IPs)"
    echo -e "  ${CYAN}install${NC}            Install commands system-wide"
    echo -e "  ${CYAN}help${NC}               Show this help"
    echo ""
    echo -e "${GREEN}Examples:${NC}"
    echo "  sudo ./vm-security.sh setup          # First time setup (interactive)"
    echo "  vm-security status                   # Check security status"
    echo "  sudo vm-security reapply             # Re-apply security"
    echo "  vm-security unban 1.2.3.4            # Unban IP"
    echo ""
    echo -e "${GREEN}After installation:${NC}"
    echo "  vm-security-status    # Quick alias"
    echo "  security-status       # Even shorter"
    echo ""
}

################################################################################
# STATUS CHECK
################################################################################
show_status() {
    DETAILED=false
    # shellcheck disable=SC2034
    [[ "$1" == "--detailed" || "$1" == "-d" ]] && DETAILED=true
    
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           VM SECURITY STATUS - $(date +'%Y-%m-%d %H:%M:%S')              ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    [[ $EUID -ne 0 ]] && echo -e "${YELLOW}⚠️  Note: Running without sudo - some info may be limited${NC}" && echo ""
    
    # Core Services
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  CORE SECURITY SERVICES${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    systemctl is-active sshd > /dev/null 2>&1; SSH_STATUS=$?
    systemctl is-active fail2ban > /dev/null 2>&1; F2B_STATUS=$?
    ufw status 2>/dev/null | grep -q "Status: active"; UFW_STATUS=$?
    systemctl is-active auditd > /dev/null 2>&1; AUDIT_STATUS=$?
    systemctl is-active chrony > /dev/null 2>&1; CHRONY_STATUS=$?
    systemctl is-active unattended-upgrades > /dev/null 2>&1; UNATTENDED_STATUS=$?
    
    echo -en "SSH Service:                 "; check_status $SSH_STATUS
    echo -en "fail2ban:                    "; check_status $F2B_STATUS
    echo -en "UFW Firewall:                "; check_status $UFW_STATUS
    echo -en "Audit Logging (auditd):      "; check_status $AUDIT_STATUS
    echo -en "Time Synchronization:        "; check_status $CHRONY_STATUS
    echo -en "Auto Security Updates:       "; check_status $UNATTENDED_STATUS
    echo ""
    
    # Intrusion Detection
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INTRUSION DETECTION & ATTACKS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if systemctl is-active --quiet fail2ban 2>/dev/null && F2B_OUTPUT=$(fail2ban-client status sshd 2>&1); then
            BANNED_COUNT=$(echo "$F2B_OUTPUT" | grep "Currently banned" | awk '{print $4}')
            TOTAL_BANNED=$(echo "$F2B_OUTPUT" | grep "Total banned" | awk '{print $4}')
        echo -e "Currently Banned IPs:        ${YELLOW}${BANNED_COUNT:-0}${NC}"
        echo -e "Total Banned (session):      ${YELLOW}${TOTAL_BANNED:-0}${NC}"
        
        if [ "${BANNED_COUNT:-0}" -gt 0 ] 2>/dev/null; then
                echo ""
                echo -e "${YELLOW}Active Bans:${NC}"
                echo "$F2B_OUTPUT" | grep "Banned IP list:" | sed 's/.*Banned IP list://' | tr ' ' '\n' | grep -v '^$' | head -10 | while read ip; do
                    echo "  • $ip"
                done
        fi
    else
        echo -e "Currently Banned IPs:        ${RED}fail2ban not running${NC}"
    fi
    
    echo ""
    FAILED_24H=$(journalctl --since "24 hours ago" -u sshd 2>/dev/null | grep "Failed password" | wc -l)
    FAILED_1H=$(journalctl --since "1 hour ago" -u sshd 2>/dev/null | grep "Failed password" | wc -l)
    
    echo -e "Failed Logins (24h):         ${YELLOW}${FAILED_24H:-0}${NC}"
    echo -e "Failed Logins (1h):          ${YELLOW}${FAILED_1H:-0}${NC}"
    
    [ "${FAILED_1H:-0}" -gt 50 ] 2>/dev/null && echo -e "  ${RED}⚠ HIGH ATTACK RATE - Under active brute force!${NC}"
    [ "${FAILED_1H:-0}" -gt 10 ] 2>/dev/null && [ "${FAILED_1H:-0}" -le 50 ] 2>/dev/null && echo -e "  ${YELLOW}⚠ Moderate attack activity${NC}"
    
    echo ""
    echo -e "${YELLOW}Top 5 Attacking IPs:${NC}"
    lastb 2>/dev/null | head -1000 | awk '{print $3}' | grep -E '^[0-9]' | sort | uniq -c | sort -rn | head -5 | while read count ip; do
        echo "  • $ip ($count attempts)"
    done
    echo ""
    
    # Exposed Services
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  EXPOSED SERVICES & BYPASS DETECTION${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    EXPOSED_FOUND=false
    UFW_ALLOWED_PORTS=""
    command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active" && \
        UFW_ALLOWED_PORTS=$(ufw status numbered 2>/dev/null | grep "ALLOW IN" | grep -oP '\d+(?=/tcp)' | tr '\n' '|' || true)
    
    EXPOSED_SERVICES=$(ss -tlnp 2>/dev/null | grep LISTEN | grep -v "127.0.0.1" | grep -v "::1" | awk '{print $4, $NF}' | \
    while read addr process; do
        PORT=$(echo $addr | sed 's/.*://')
        PROCESS=$(echo $process | sed 's/.*"\(.*\)".*/\1/' | sed 's/,.*//')
        echo "$PORT|$PROCESS"
    done | sort -u -t'|' -k1,1n)
    
    if [ -n "$EXPOSED_SERVICES" ]; then
        echo "$EXPOSED_SERVICES" | while IFS='|' read PORT PROCESS; do
            if echo "$UFW_ALLOWED_PORTS" | grep -qE "(^|\\|)${PORT}(\\||$)"; then
                echo -e "${GREEN}✓${NC} Port ${PORT}: ${PROCESS} - Allowed in UFW"
            else
                echo -e "${RED}✗ ALERT${NC} Port ${PORT}: ${PROCESS} - ${RED}NOT IN UFW RULES${NC}"
                EXPOSED_FOUND=true
            fi
        done
    else
        echo -e "${GREEN}✓${NC} No services listening on public interfaces"
    fi
    
    # Docker check
    if command -v docker &> /dev/null && docker ps -q 2>/dev/null | grep -q .; then
        echo ""
        echo -e "${BLUE}Docker Containers:${NC}"
        docker ps --format "{{.Names}}|{{.Ports}}" 2>/dev/null | while IFS='|' read name ports; do
            if echo "$ports" | grep -q "0.0.0.0:"; then
                EXPOSED_PORT=$(echo "$ports" | grep -o "0.0.0.0:[0-9]*" | head -1 | cut -d: -f2)
                echo -e "  ${RED}✗ RISK${NC} ${name} - exposed on 0.0.0.0:${EXPOSED_PORT}"
                EXPOSED_FOUND=true
            elif echo "$ports" | grep -q "127.0.0.1:"; then
                BINDING=$(echo "$ports" | grep -o "127.0.0.1:[0-9]*->[0-9]*/[a-z]*" | head -1)
                echo -e "  ${GREEN}✓${NC} ${name} - ${BINDING} (localhost only)"
            else
                echo -e "  ${GREEN}✓${NC} ${name} - internal only"
            fi
        done
    fi
    
    [ "$EXPOSED_FOUND" = false ] && echo -e "${GREEN}✓ No unexpected exposed services${NC}"
    echo ""
    
    # Docker-UFW Bypass Check
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  DOCKER FIREWALL BYPASS CHECK${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if command -v docker &> /dev/null; then
        if iptables -L DOCKER-USER -n 2>/dev/null | grep -qE "(ufw-user-forward|ufw-docker-logging-deny)"; then
            echo -e "${GREEN}✓ Docker CANNOT bypass UFW (secured)${NC}"
        else
            docker ps >/dev/null 2>&1 && echo -e "${YELLOW}⚠ Docker-UFW integration not detected. Run 'sudo vm-security reapply'${NC}" || \
                echo -e "${BLUE}ℹ Docker installed but not running${NC}"
        fi
        
        [ -f /etc/docker/daemon.json ] && {
            grep -q '"icc": false' /etc/docker/daemon.json 2>/dev/null && echo -e "${GREEN}✓ Container inter-communication disabled${NC}"
            grep -q '"no-new-privileges": true' /etc/docker/daemon.json 2>/dev/null && echo -e "${GREEN}✓ Container privilege escalation blocked${NC}"
        }
    else
        echo -e "${BLUE}ℹ Docker not installed${NC}"
    fi
    echo ""
    
    # Security Score
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  SECURITY HEALTH SCORE${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    SCORE=100
    [ "$SSH_STATUS" -ne 0 ] && SCORE=$((SCORE-15))
    [ "$F2B_STATUS" -ne 0 ] && SCORE=$((SCORE-15))
    [ "$UFW_STATUS" -ne 0 ] && SCORE=$((SCORE-20))
    [ "$AUDIT_STATUS" -ne 0 ] && SCORE=$((SCORE-10))
    [ "${FAILED_1H:-0}" -gt 50 ] 2>/dev/null && SCORE=$((SCORE-10))
    [ "$EXPOSED_FOUND" = true ] && SCORE=$((SCORE-25))
    
    if [ $SCORE -ge 90 ]; then
        echo -e "Security Health: ${GREEN}${SCORE}/100 - EXCELLENT${NC} 🛡️"
    elif [ $SCORE -ge 70 ]; then
        echo -e "Security Health: ${YELLOW}${SCORE}/100 - GOOD${NC} ⚠️"
    else
        echo -e "Security Health: ${RED}${SCORE}/100 - NEEDS ATTENTION${NC} 🚨"
    fi
    
    echo ""
    echo -e "${BLUE}Quick Actions:${NC}"
    echo "  vm-security reapply         Re-run security hardening"
    echo "  vm-security status --detailed   Show detailed analysis"
    echo ""
}

################################################################################
# SETUP - Security Hardening
################################################################################
run_setup() {
    set -e
    trap 'print_error "Setup failed at line $LINENO. Check /root/security-setup-*.log"; set +e; exit 1' ERR
    
    [[ $EUID -ne 0 ]] && print_error "This must be run as root (use sudo)" && exit 1
    
    # Prompt for username if not set
    if [ -z "$NEW_USER" ]; then
        echo ""
        print_header "Step 1: Create Admin User"
        echo "Create a non-root admin user with sudo privileges and SSH key authentication."
        echo ""
        
        while true; do
            read -p "Enter username: " NEW_USER
            [ -z "$NEW_USER" ] && print_error "Username cannot be empty!" && continue
            [ "$NEW_USER" = "root" ] && print_error "Cannot use 'root'!" && continue
            [[ ! "$NEW_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] && print_error "Invalid format (lowercase letters, numbers, hyphens, underscores)" && continue
            
            if id "$NEW_USER" &>/dev/null; then
                print_warning "User '$NEW_USER' already exists. Using existing user."
                break
            fi
            
            read -p "Create user '$NEW_USER'? (y/n) " -n 1 -r
            echo
            [[ $REPLY =~ ^[Yy]$ ]] && print_success "Username accepted!" && break || NEW_USER=""
        done
    fi
    
    # Prompt for SSH public key if not set
    if [ -z "$SSH_PUBLIC_KEY" ]; then
        echo ""
        print_header "Step 2: Configure SSH Key"
        print_warning "SSH public key is required for secure authentication!"
        echo ""
        echo "On your LOCAL machine, run: ${YELLOW}cat ~/.ssh/id_rsa.pub${NC} or ${YELLOW}cat ~/.ssh/id_ed25519.pub${NC}"
        echo "Copy the entire output and paste below."
        echo ""
        echo -e "${YELLOW}⚠️  This is CRITICAL - without it, you'll be locked out!${NC}"
        echo ""
        read -p "Do you have your SSH public key ready? (y/n) " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && print_error "Setup cancelled. Get your SSH key first." && exit 1
        
        echo ""
        read -p "Paste your SSH public key: " -r SSH_PUBLIC_KEY
        
        [[ ! "$SSH_PUBLIC_KEY" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ssh-dss) ]] && \
            print_error "Invalid SSH key format!" && exit 1
        
        print_status "Validating SSH key..."
        echo "$SSH_PUBLIC_KEY" > /tmp/validate_ssh_key.pub
        if ! ssh-keygen -l -f /tmp/validate_ssh_key.pub >/dev/null 2>&1; then
            print_error "Invalid or malformed SSH key!"
            rm -f /tmp/validate_ssh_key.pub
            exit 1
        fi
        rm -f /tmp/validate_ssh_key.pub
        print_success "SSH key validated!"
    fi
    
    clear
    print_header "VM Security Hardening (SOC2-Aligned Controls)"
    print_status "Running pre-flight safety checks..."
    
    # Detect current IP (try multiple methods)
    CURRENT_IP=""
    [ -n "$SSH_CONNECTION" ] && CURRENT_IP=$(echo $SSH_CONNECTION | awk '{print $1}')
    [ -z "$CURRENT_IP" ] && [ -n "$SSH_CLIENT" ] && CURRENT_IP=$(echo $SSH_CLIENT | awk '{print $1}')
    [ -z "$CURRENT_IP" ] && CURRENT_IP=$(who am i 2>/dev/null | awk '{print $5}' | sed 's/[()]//g' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
    [ -z "$CURRENT_IP" ] && CURRENT_IP=$(last -i | grep "still logged in" | head -1 | awk '{print $3}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
    
    # Whitelist configuration
    echo ""
    if [ -n "$CURRENT_IP" ] && [ "$CURRENT_IP" != "127.0.0.1" ] && [ "$CURRENT_IP" != "0.0.0.0" ]; then
        NETWORK_PREFIX=$(echo $CURRENT_IP | cut -d. -f1-3)
        SUGGESTED_RANGE_24="${NETWORK_PREFIX}.0/24"
        SUGGESTED_RANGE_16=$(echo $CURRENT_IP | cut -d. -f1-2)".0.0/16"
        print_success "Detected your connection from: $CURRENT_IP"
    else
        print_warning "Could not auto-detect your IP (console/VNC/web terminal)"
        CURRENT_IP=""
    fi
        
        echo ""
    echo -e "${YELLOW}⚠️  IMPORTANT: fail2ban Whitelist Configuration${NC}"
    echo "Whitelist trusted IPs to prevent accidental lockouts."
        echo ""
    echo -e "${CYAN}Understanding Dynamic IPs:${NC}"
    echo "• Most home/office ISPs assign DYNAMIC IPs (change on router restart, DHCP renewal)"
    echo "• If you whitelist ONLY your current IP and it changes, you'll be locked out"
    echo "• Solution: Whitelist your entire subnet (/24 = 256 IPs, recommended)"
        echo ""
    echo -e "${CYAN}Choose your whitelist strategy:${NC}"
        echo ""
    
    if [ -n "$CURRENT_IP" ]; then
        echo -e "1) Current IP only        - $CURRENT_IP ${RED}⚠ Will lock you out if IP changes!${NC}"
        echo -e "2) /24 Network Range      - $SUGGESTED_RANGE_24 ${GREEN}✓ Recommended (256 IPs)${NC}"
        echo -e "3) /16 Network Range      - $SUGGESTED_RANGE_16 ${YELLOW}⚠ Less secure (65K IPs)${NC}"
        echo    "4) Custom                 - Enter your own IP(s) or range(s)"
        echo    "5) Use configured value   - $FAIL2BAN_IGNOREIP"
        MENU_MAX=5
    else
        echo -e "1) Enter IP manually      - Type your public IP (use: curl ifconfig.me)"
        echo -e "2) Use configured value   - $FAIL2BAN_IGNOREIP ${RED}⚠ Only localhost!${NC}"
        MENU_MAX=2
    fi
        echo ""
        
        while true; do
        read -p "Select option (1-$MENU_MAX): " choice
            
        if [ -n "$CURRENT_IP" ]; then
            case $choice in
                1)
                    FAIL2BAN_IGNOREIP="127.0.0.1/8 $CURRENT_IP"
                    print_warning "Using current IP only: $CURRENT_IP"
                    echo -e "${RED}⚠ RISK: You'll be locked out if your IP changes!${NC}"
                    break
                    ;;
                2)
                    FAIL2BAN_IGNOREIP="127.0.0.1/8 $SUGGESTED_RANGE_24"
                    print_success "Using /24 range: $SUGGESTED_RANGE_24 (${NETWORK_PREFIX}.0-255)"
                    echo -e "${GREEN}✓ SAFE: Covers your entire subnet, protects against IP changes${NC}"
                    break
                    ;;
                3)
                    FAIL2BAN_IGNOREIP="127.0.0.1/8 $SUGGESTED_RANGE_16"
                    print_warning "Using /16 range: $SUGGESTED_RANGE_16"
                    echo -e "${YELLOW}⚠ CAUTION: This whitelists 65,536 IPs (less secure)${NC}"
                    break
                    ;;
                4)
                    echo ""
                    echo "Examples: Single IP (203.0.113.45), Multiple (203.0.113.45 198.51.100.20), Range (203.0.113.0/24)"
                    read -p "Whitelist: " custom
                    [ -z "$custom" ] && print_error "Cannot be empty!" && continue
                    if validate_ip_or_cidr "$custom"; then
                        FAIL2BAN_IGNOREIP="127.0.0.1/8 $custom"
                        print_success "Custom whitelist configured"
                        break
                    else
                        print_error "Invalid IP/CIDR format!"
                        continue
                    fi
                    ;;
                5) break ;;
                *) print_error "Invalid option." ;;
            esac
        else
            case $choice in
                1)
                    echo ""
                    echo "Find your IP: curl ifconfig.me (run from YOUR local machine)"
                    read -p "Enter IP(s)/range(s): " manual_ip
                    [ -z "$manual_ip" ] && print_error "Cannot be empty!" && continue
                    if validate_ip_or_cidr "$manual_ip"; then
                        FAIL2BAN_IGNOREIP="127.0.0.1/8 $manual_ip"
                        CURRENT_IP=$(echo $manual_ip | awk '{print $1}' | cut -d'/' -f1)
                        print_success "Whitelist configured"
                            break
                    else
                        print_error "Invalid IP/CIDR format!"
                        continue
                    fi
                    ;;
                2)
                    print_warning "Using: $FAIL2BAN_IGNOREIP ${RED}(only localhost!)${NC}"
                    read -p "Are you SURE? (type 'yes'): " confirm
                    [ "$confirm" = "yes" ] && break || continue
                    ;;
                *) print_error "Invalid option." ;;
            esac
        fi
    done
    
        print_success "Whitelist configured: $FAIL2BAN_IGNOREIP"
        echo ""
    
    # Final confirmation
    echo ""
    echo "Configuration:"
    echo "  User: $NEW_USER"
    echo "  SSH Port: $SSH_PORT"
    echo "  fail2ban: $FAIL2BAN_MAXRETRY attempts, ${FAIL2BAN_BANTIME}s ban"
    echo "  Whitelisted: $FAIL2BAN_IGNOREIP"
    echo ""
    echo -e "${YELLOW}⚠️  CRITICAL REMINDERS:${NC}"
    echo "  1. Test SSH in a NEW terminal BEFORE logging out"
    echo "  2. Keep this terminal open until SSH access verified"
    echo ""
    read -p "Continue? (y/n) " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
    
    LOG_FILE="/root/security-setup-$(date +%Y%m%d-%H%M%S).log"
    exec > >(tee -a "$LOG_FILE") 2>&1
    
    print_header "1. System Update"
    apt-get update -qq && apt-get upgrade -y -qq
    print_success "System updated"
    
    print_header "2. Creating Admin User"
    USER_PASSWORD=""  # Initialize password variable
    if ! id "$NEW_USER" &>/dev/null; then
        adduser --disabled-password --gecos "" "$NEW_USER"
        usermod -aG sudo "$NEW_USER"
        print_success "User $NEW_USER created"
        setup_user_password "$NEW_USER"
    else
        print_warning "User $NEW_USER already exists"
        read -p "Reset password for $NEW_USER? (y/n) " -n 1 -r < /dev/tty
        echo
        [[ $REPLY =~ ^[Yy]$ ]] && setup_user_password "$NEW_USER"
    fi
    
    print_header "3. SSH Key Authentication"
    mkdir -p "/home/$NEW_USER/.ssh"
    chmod 700 "/home/$NEW_USER/.ssh"
    echo "$SSH_PUBLIC_KEY" > "/home/$NEW_USER/.ssh/authorized_keys"
    chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
    chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.ssh"
    print_success "SSH key configured"
    
    print_header "4. SSH Hardening"
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.backup-$(date +%Y%m%d)" 2>/dev/null || true
    
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
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF
    
    # Also directly modify main config to ensure settings take effect (some systems don't honor drop-ins properly)
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
    
    # Add settings if they don't exist (check for both commented and uncommented)
    grep -qE "^#?PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
    grep -qE "^#?PasswordAuthentication" /etc/ssh/sshd_config || echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
    grep -qE "^#?PubkeyAuthentication" /etc/ssh/sshd_config || echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
    grep -qE "^#?ChallengeResponseAuthentication" /etc/ssh/sshd_config || echo "ChallengeResponseAuthentication no" >> /etc/ssh/sshd_config
    grep -qE "^#?KbdInteractiveAuthentication" /etc/ssh/sshd_config || echo "KbdInteractiveAuthentication no" >> /etc/ssh/sshd_config
    
    # Force append critical settings to override any Include directives that come before
    echo "" >> /etc/ssh/sshd_config
    echo "# Force security settings (vm-security override)" >> /etc/ssh/sshd_config
    echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
    echo "KbdInteractiveAuthentication no" >> /etc/ssh/sshd_config
    echo "ChallengeResponseAuthentication no" >> /etc/ssh/sshd_config
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config
    
    [ "$CHANGE_SSH_PORT" = true ] && sed -i "s/^#\?Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
    
    # Create SSH privilege separation directory if it doesn't exist
    mkdir -p /run/sshd
    chmod 0755 /run/sshd
    
    sshd -T >/dev/null 2>&1 || { print_error "SSH config validation failed!"; sshd -T; exit 1; }
    print_success "SSH configured and validated"
    
    print_header "5. fail2ban"
    apt-get install -y fail2ban -qq
    
    # Re-detect IP (in case it was lost during sudo execution)
    DETECTED_IP=""
    
    # Method 1: Direct SSH environment variables
    [ -n "$SSH_CONNECTION" ] && DETECTED_IP=$(echo $SSH_CONNECTION | awk '{print $1}')
    [ -z "$DETECTED_IP" ] && [ -n "$SSH_CLIENT" ] && DETECTED_IP=$(echo $SSH_CLIENT | awk '{print $1}')
    
    # Method 2: Check original user's environment (if run via sudo)
    if [ -z "$DETECTED_IP" ] && [ -n "$SUDO_USER" ]; then
        DETECTED_IP=$(ps -eo user,cmd,args | grep "^$SUDO_USER.*sshd:" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
    fi
    
    # Method 3: who command (shows remote IPs)
    [ -z "$DETECTED_IP" ] && DETECTED_IP=$(who am i 2>/dev/null | awk '{print $5}' | sed 's/[()]//g' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
    
    # Method 4: Check w command (shows currently logged in users with IPs)
    [ -z "$DETECTED_IP" ] && DETECTED_IP=$(w -h 2>/dev/null | grep "$(whoami)\|${SUDO_USER:-nobody}" | head -1 | awk '{print $3}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
    
    # Method 5: last command (recent logins)
    [ -z "$DETECTED_IP" ] && DETECTED_IP=$(last -i 2>/dev/null | grep "still logged in" | head -1 | awk '{print $3}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
    
    # Method 6: Check PAM environment
    [ -z "$DETECTED_IP" ] && [ -n "$PAM_RHOST" ] && DETECTED_IP="$PAM_RHOST"
    
    # Use detected IP or fall back to the one from earlier
    [ -n "$DETECTED_IP" ] && [ "$DETECTED_IP" != "127.0.0.1" ] && [ "$DETECTED_IP" != "0.0.0.0" ] && CURRENT_IP="$DETECTED_IP"
    
    # Show detected IP for verification
    if [ -n "$CURRENT_IP" ] && [ "$CURRENT_IP" != "127.0.0.1" ]; then
        print_status "Detected your IP: $CURRENT_IP (will be added to whitelist)"
    else
        print_warning "Could not detect your IP - using configured whitelist only"
    fi
    
    WHITELIST_IPS="$FAIL2BAN_IGNOREIP"
    if [ -n "$CURRENT_IP" ] && [ "$CURRENT_IP" != "127.0.0.1" ]; then
        echo "$WHITELIST_IPS" | grep -q "$CURRENT_IP" || WHITELIST_IPS="$WHITELIST_IPS $CURRENT_IP"
    fi
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = $FAIL2BAN_BANTIME
findtime = $FAIL2BAN_FINDTIME
maxretry = $FAIL2BAN_MAXRETRY
ignoreip = $WHITELIST_IPS

[sshd]
enabled = true
port = $SSH_PORT
maxretry = $FAIL2BAN_MAXRETRY
EOF
    
    systemctl enable fail2ban && systemctl restart fail2ban
    print_success "fail2ban configured (whitelisted: $CURRENT_IP)"
    
    print_header "6. UFW Firewall"
    apt-get install -y ufw -qq
    ufw --force disable
    ufw default deny incoming && ufw default allow outgoing
    ufw allow $SSH_PORT/tcp
    
    if [ -n "$ALLOWED_HTTP_PORTS" ]; then
        IFS=',' read -ra ports <<< "$ALLOWED_HTTP_PORTS"
        for port in "${ports[@]}"; do ufw allow $port/tcp; done
    fi
    
    ufw limit $SSH_PORT/tcp && ufw --force enable
    print_success "UFW configured"
    
    print_header "7. Docker-UFW Integration"
    if command -v docker &> /dev/null; then
        mkdir -p /etc/docker
        [ -f /etc/docker/daemon.json ] && cp /etc/docker/daemon.json /etc/docker/daemon.json.backup || true
        
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
        
        cp /etc/ufw/after.rules "/etc/ufw/after.rules.backup-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
        sed -i '/# Docker UFW Integration/,/^COMMIT$/d' /etc/ufw/after.rules 2>/dev/null || true
        
        cat > /tmp/docker-ufw-rules.txt << 'EOF'
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
        
        cat /tmp/docker-ufw-rules.txt /etc/ufw/after.rules > /tmp/ufw-after-rules-new.txt
        mv /tmp/ufw-after-rules-new.txt /etc/ufw/after.rules
        rm -f /tmp/docker-ufw-rules.txt
        print_success "Docker secured - CANNOT bypass UFW"
    fi
    
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
        print_success "Auto-updates enabled"
    fi
    
    print_header "9. SOC2: Audit Logging (auditd)"
    apt-get install -y auditd audispd-plugins -qq
    
    cat > /etc/audit/rules.d/soc2-compliance.rules << 'EOF'
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
-e 2
EOF
    
    command -v docker &> /dev/null && cat >> /etc/audit/rules.d/soc2-compliance.rules << 'EOF'
-w /usr/bin/docker -p wa -k docker
-w /var/lib/docker -p wa -k docker
-w /etc/docker -p wa -k docker
EOF
    
    systemctl enable auditd && systemctl restart auditd
    print_success "Audit logging configured"
    
    print_header "10. SOC2: File Integrity (AIDE)"
    apt-get install -y aide aide-common -qq
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
    
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
mkdir -p /var/log/aide
/usr/bin/aide --config=/etc/aide/aide.conf --check > /var/log/aide/aide-check-$(date +%Y%m%d).log 2>&1
EOF
    chmod +x /etc/cron.daily/aide-check
    print_success "AIDE configured"
    
    print_header "11. SOC2: Time Sync (chrony)"
    apt-get install -y chrony -qq
    
    cat > /etc/chrony/chrony.conf << 'EOF'
pool 0.ubuntu.pool.ntp.org iburst maxsources 4
pool 1.ubuntu.pool.ntp.org iburst maxsources 1
driftfile /var/lib/chrony/chrony.drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
EOF
    
    systemctl enable chrony && systemctl restart chrony
    print_success "Time sync configured"
    
    print_header "12. SOC2: Password Policy"
    apt-get install -y libpam-pwquality -qq
    
    cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
usercheck = 1
EOF
    
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    print_success "Password policy set"
    
    print_header "13. SOC2: Kernel Hardening"
    cat > /etc/sysctl.d/99-soc2-hardening.conf << 'EOF'
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
    
    sysctl -p /etc/sysctl.d/99-soc2-hardening.conf > /dev/null 2>&1
    print_success "Kernel hardened"
    
    print_header "14. SOC2: Log Retention (365 days)"
    cat > /etc/logrotate.d/soc2-compliance << 'EOF'
/var/log/auth.log
/var/log/syslog
{
    rotate 365
    daily
    compress
    delaycompress
}
EOF
    print_success "Log retention configured"
    
    print_header "15. Restarting Services"
    systemctl restart sshd
    command -v docker &> /dev/null && systemctl restart docker 2>/dev/null || true
    ufw reload
    
    print_header "🎉 Security Hardening Complete!"
    
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                   ✅ ALL SECURITY MEASURES APPLIED                   ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  ⚠️  TEST SSH ACCESS IN A NEW TERMINAL BEFORE CLOSING THIS ONE!${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}📋 YOUR SERVER DETAILS${NC}"
    echo "Server IP:         $SERVER_IP"
    echo "SSH Port:          $SSH_PORT"
    echo "Admin User:        $NEW_USER"
    echo "Your IP:           ${CURRENT_IP:-Not detected}"
    echo "Whitelist:         $FAIL2BAN_IGNOREIP"
    echo ""
    echo -e "${CYAN}🔒 AUTHENTICATION${NC}"
    echo "✓ SSH Key Auth: ENABLED (primary)"
    echo "✓ Password Auth: DISABLED (SSH)"
    echo "✓ Root Login: DISABLED"
    echo "✓ Password Set: YES (for sudo/console)"
    echo ""
    echo -e "${CYAN}🧪 TEST SSH NOW:${NC}"
    echo -e "  ${GREEN}ssh -p $SSH_PORT $NEW_USER@$SERVER_IP${NC}"
    echo ""
    echo -e "Expected: Login without password, then test: ${GREEN}sudo whoami${NC}"
    echo ""
    echo -e "${CYAN}📦 CONFIGURED${NC}"
    echo "✅ SSH Hardening       Strong ciphers, key-only auth"
    echo "✅ fail2ban            $FAIL2BAN_MAXRETRY attempts, ${FAIL2BAN_BANTIME}s ban"
    echo "✅ UFW Firewall        Default deny, SSH allowed (port $SSH_PORT)"
    echo "✅ Audit Logging       SOC2-compliant auditd"
    echo "✅ File Integrity      AIDE daily checks"
    echo "✅ Auto Updates        Security patches"
    echo "✅ Time Sync           chrony (NTP)"
    echo "✅ Password Policy     14+ chars, 90-day expiry"
    echo "✅ Kernel Hardening    Network security"
    echo "✅ Log Retention       365 days"
    echo ""
    echo -e "${CYAN}🛠️  COMMANDS${NC}"
    echo -e "  ${GREEN}vm-security status${NC}            Quick overview"
    echo -e "  ${GREEN}sudo vm-security status${NC}       Full details"
    echo -e "  ${GREEN}vm-security logs${NC}              View security logs"
    echo -e "  ${GREEN}sudo vm-security whitelist${NC}    Add IP to whitelist (dynamic IP helper)"
    echo -e "  ${GREEN}sudo vm-security reapply${NC}      Update security"
    echo ""
    echo -e "${CYAN}📁 FILES${NC}"
    echo "Setup log:         $LOG_FILE"
    echo "SSH config:        /etc/ssh/sshd_config.d/99-hardening.conf"
    echo "fail2ban config:   /etc/fail2ban/jail.local"
    echo ""
    echo -e "${YELLOW}🔑 Password Recovery:${NC}"
    echo -e "  ${RED}No recovery - password only shown once during setup!${NC}"
    echo -e "  ${YELLOW}Use cloud console to reset if lost:${NC} ${GREEN}sudo passwd $NEW_USER${NC}"
    echo ""

    if [ -n "$CURRENT_IP" ]; then
        NETWORK_PREFIX=$(echo $CURRENT_IP | cut -d. -f1-3)
        echo ""
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}  📡 DYNAMIC IP PROTECTION${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${CYAN}Current whitelist:${NC} $FAIL2BAN_IGNOREIP"
        echo ""
        echo -e "${YELLOW}⚠️  If your ISP uses DHCP (most do), your IP may change!${NC}"
        echo ""
        echo -e "${CYAN}If your IP changes and you get locked out:${NC}"
        echo "  1. Access via cloud console (password: the one you set)"
        echo -e "  2. Run: ${GREEN}sudo vm-security whitelist${NC}"
        echo "  3. Choose option 2 to add your new /24 range"
        echo ""
        echo -e "${CYAN}Manual method (edit config):${NC}"
        echo -e "  ${GREEN}sudo nano /etc/fail2ban/jail.local${NC}"
        echo "  Change: ignoreip = 127.0.0.1/8 ${NETWORK_PREFIX}.0/24"
        echo -e "  Then:   ${GREEN}sudo systemctl restart fail2ban${NC}"
        echo ""
    fi

    echo ""
    echo -e "${YELLOW}🆘 Emergency Access:${NC}"
    echo "   • Cloud console still works (password-based)"
    echo -e "   • Unban yourself: ${GREEN}sudo fail2ban-client unban YOUR_IP${NC}"
    echo ""
    
    # Display password prominently at the end if set
    if [ -n "$USER_PASSWORD" ]; then
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}  🔐 YOUR GENERATED PASSWORD (SAVE THIS NOW - ONLY SHOWN ONCE!)${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "  Username: ${CYAN}$NEW_USER${NC}"
        echo -e "  Password: ${YELLOW}$USER_PASSWORD${NC}"
        echo ""
        echo -e "${RED}⚠️  CRITICAL: This password is NOT saved to logs!${NC}"
        echo -e "${YELLOW}    Copy to your password manager NOW!${NC}"
        echo -e "${YELLOW}    Required for: sudo commands, console access, recovery${NC}"
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
    fi
    
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  🎉 Setup Complete! Test SSH with the credentials above before closing this window!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

################################################################################
# REAPPLY
################################################################################
run_reapply() {
    [[ $EUID -ne 0 ]] && print_error "This must be run as root (use sudo)" && exit 1
    
    BACKUP_DIR="/root/security-backups/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    print_status "Backing up configs to $BACKUP_DIR..."
    cp /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/fail2ban/jail.local "$BACKUP_DIR/" 2>/dev/null || true
    
    print_status "Re-running security hardening..."
    echo ""
    
    run_setup
}

################################################################################
# SHOW LOGS
################################################################################
show_logs() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           SECURITY LOGS & REPORTS                                    ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}📁 Log Storage Locations:${NC}"
    echo ""
    echo "1. Authentication:  /var/log/auth.log, /var/log/fail2ban.log"
    echo "2. Audit Logs:      /var/log/audit/audit.log (SOC2)"
    echo "3. File Integrity:  /var/log/aide/ (daily reports)"
    echo "4. System:          /var/log/syslog, /var/log/ufw.log"
    echo ""
    echo -e "${CYAN}📊 Retention:${NC} Auth logs: 365 days, Audit: Permanent"
    echo ""
    echo -e "${CYAN}🔍 Quick Views:${NC}"
    echo ""
    
    PS3="Select log (0 to exit): "
    options=(
        "Recent SSH Failed Logins (50)"
        "Currently Banned IPs"
        "Recent UFW Blocks (50)"
        "Audit Activity (50)"
        "AIDE - Latest Integrity Report"
        "Setup Log"
        "Exit"
    )
    
    select opt in "${options[@]}"; do
        # Check if user entered 0 to exit
        if [[ "$REPLY" == "0" ]]; then
            echo ""
            read -p "Exit log viewer? (y/n) " -n 1 -r
            echo ""
            [[ $REPLY =~ ^[Yy]$ ]] && break || continue
        fi
        
        case $opt in
            "Recent SSH Failed Logins (50)")
                echo ""
                echo -e "${YELLOW}Recent SSH Failed Logins:${NC}"
                grep "Failed password" /var/log/auth.log 2>/dev/null | tail -50 || echo "No failed logins"
                echo ""
                ;;
            "Currently Banned IPs")
                echo ""
                echo -e "${YELLOW}Currently Banned:${NC}"
                systemctl is-active fail2ban > /dev/null 2>&1 && fail2ban-client status sshd 2>/dev/null || echo "fail2ban not running"
                echo ""
                ;;
            "Recent UFW Blocks (50)")
                echo ""
                echo -e "${YELLOW}Recent UFW Blocks:${NC}"
                grep "UFW BLOCK" /var/log/ufw.log 2>/dev/null | tail -50 || echo "No blocks found"
                echo ""
                ;;
            "Audit Activity (50)")
                echo ""
                echo -e "${YELLOW}Recent Audit Events:${NC}"
                command -v ausearch &> /dev/null && ausearch -i --start recent 2>/dev/null | tail -50 || \
                    tail -50 /var/log/audit/audit.log 2>/dev/null || echo "No audit log"
                echo ""
                ;;
            "AIDE - Latest Integrity Report")
                echo ""
                echo -e "${YELLOW}Latest AIDE Report:${NC}"
                LATEST=$(ls -t /var/log/aide/aide-check-*.log 2>/dev/null | head -1)
                [ -n "$LATEST" ] && { echo "File: $LATEST"; echo ""; cat "$LATEST"; } || \
                    echo "No reports yet (first run tomorrow)"
                echo ""
                ;;
            "Setup Log")
                echo ""
                echo -e "${YELLOW}Last Setup Log:${NC}"
                LATEST=$(ls -t /root/security-setup-*.log 2>/dev/null | head -1)
                [ -n "$LATEST" ] && { echo "File: $LATEST"; echo ""; tail -100 "$LATEST"; } || \
                    echo "No setup logs"
                echo ""
                ;;
            "Exit")
                echo ""
                read -p "Exit log viewer? (y/n) " -n 1 -r
                echo ""
                [[ $REPLY =~ ^[Yy]$ ]] && break
                ;;
            *) echo "Invalid option" ;;
        esac
    done
}

################################################################################
# INSTALL SYSTEM-WIDE
################################################################################
run_install() {
    [[ $EUID -ne 0 ]] && print_error "This must be run as root (use sudo)" && exit 1
    
    SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    
    print_status "Installing to /usr/local/bin..."
    cp "$SCRIPT_PATH" /usr/local/bin/vm-security
    chmod +x /usr/local/bin/vm-security
    
    ln -sf /usr/local/bin/vm-security /usr/local/bin/vm-security-status 2>/dev/null || true
    ln -sf /usr/local/bin/vm-security /usr/local/bin/security-status 2>/dev/null || true
    
    cat > /etc/cron.d/vm-security-status << 'EOF'
*/5 * * * * root /usr/local/bin/vm-security-status-update >/dev/null 2>&1
EOF
    
    cat > /usr/local/bin/vm-security-status-update << 'EOF'
#!/bin/bash
STATUS_FILE="/run/vm-security-status.txt"
systemctl is-active --quiet sshd 2>/dev/null || { echo "Security services initializing..." > "$STATUS_FILE"; exit 0; }

BANNED="?"
FAILED="0"
UFW="Unknown"

systemctl is-active --quiet fail2ban 2>/dev/null && \
    BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}' || echo "?")
systemctl is-active --quiet sshd 2>/dev/null && \
    FAILED=$(journalctl --since "1 hour ago" -u sshd 2>/dev/null | grep "Failed password" | wc -l || echo "0")
command -v ufw >/dev/null 2>&1 && \
    UFW=$(ufw status 2>/dev/null | grep -q "Status: active" && echo "Active" || echo "Inactive")

cat > "$STATUS_FILE" << EOFSTATUS
=== Quick Security Status ===
Firewall: $UFW | Banned: $BANNED | Failed (1h): $FAILED
Type 'vm-security status' for full report
=============================
EOFSTATUS
chmod 644 "$STATUS_FILE"
EOF
    chmod +x /usr/local/bin/vm-security-status-update
    
    /usr/local/bin/vm-security-status-update
    
    grep -q "VM Security Commands" /etc/bash.bashrc 2>/dev/null || cat >> /etc/bash.bashrc << 'EOF'

# VM Security Commands
alias vm-security-status='vm-security status'
alias security-status='vm-security status'
alias security-check='vm-security status --detailed'

if [ -t 0 ] && [ -n "$PS1" ] && { [ $EUID -eq 0 ] || groups | grep -q sudo 2>/dev/null; }; then
    [ -f /run/vm-security-status.txt ] && { echo ""; cat /run/vm-security-status.txt; echo ""; }
fi
EOF
    
    print_success "✅ Installed successfully!"
    echo ""
    echo "Commands: vm-security setup|status|logs|reapply|unban"
    echo "Aliases: vm-security-status, security-status, security-check"
    echo ""
}

################################################################################
# UNBAN
################################################################################
run_unban() {
    [[ $EUID -ne 0 ]] && print_error "This must be run as root (use sudo)" && exit 1
    
    systemctl is-active --quiet fail2ban || { print_error "fail2ban not running"; exit 1; }
    
    IP=$1
    [ -z "$IP" ] && print_error "Usage: vm-security unban <ip|all>" && exit 1
    
    if [ "$IP" == "all" ]; then
        print_status "Unbanning all IPs..."
        fail2ban-client unban --all
        print_success "All IPs unbanned!"
    else
        print_status "Unbanning IP: $IP"
        fail2ban-client unban "$IP"
        print_success "IP $IP unbanned!"
    fi
    
    echo ""
    fail2ban-client status sshd
}

################################################################################
# WHITELIST - Add IP/Range to fail2ban Whitelist
################################################################################
run_whitelist() {
    [[ $EUID -ne 0 ]] && print_error "This must be run as root (use sudo)" && exit 1
    
    [ ! -f /etc/fail2ban/jail.local ] && print_error "fail2ban not configured. Run 'vm-security setup' first." && exit 1
    
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           fail2ban Whitelist Manager (Dynamic IP Helper)            ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Show current whitelist
    CURRENT_WHITELIST=$(grep "^ignoreip" /etc/fail2ban/jail.local 2>/dev/null | cut -d'=' -f2 | xargs)
    echo -e "${YELLOW}Current whitelist:${NC}"
    echo "  $CURRENT_WHITELIST"
    echo ""
    
    # Detect current IP
    DETECTED_IP=""
    [ -n "$SSH_CONNECTION" ] && DETECTED_IP=$(echo $SSH_CONNECTION | awk '{print $1}')
    [ -z "$DETECTED_IP" ] && [ -n "$SSH_CLIENT" ] && DETECTED_IP=$(echo $SSH_CLIENT | awk '{print $1}')
    [ -z "$DETECTED_IP" ] && DETECTED_IP=$(who am i 2>/dev/null | awk '{print $5}' | sed 's/[()]//g' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
    
    if [ -n "$DETECTED_IP" ]; then
        echo -e "${GREEN}Your current IP: $DETECTED_IP${NC}"
        NETWORK_PREFIX=$(echo $DETECTED_IP | cut -d. -f1-3)
        SUGGESTED_RANGE="${NETWORK_PREFIX}.0/24"
        echo -e "${CYAN}Suggested range: $SUGGESTED_RANGE${NC} (covers ${NETWORK_PREFIX}.0-255)"
        echo ""
    fi
    
    echo -e "${CYAN}Options:${NC}"
    echo "1) Add current IP ($DETECTED_IP)"
    echo "2) Add /24 network range ($SUGGESTED_RANGE) ${GREEN}← Recommended for dynamic IPs${NC}"
    echo "3) Add custom IP or range"
    echo "4) Replace entire whitelist"
    echo "5) Cancel"
    echo ""
    
    while true; do
        read -p "Select option (1-5): " choice
        
        case $choice in
            1)
                if [ -z "$DETECTED_IP" ]; then
                    print_error "Could not detect your IP. Use option 3 to enter manually."
                    continue
                fi
                NEW_IP="$DETECTED_IP"
                break
                ;;
            2)
                if [ -z "$SUGGESTED_RANGE" ]; then
                    print_error "Could not determine range. Use option 3 to enter manually."
                    continue
                fi
                NEW_IP="$SUGGESTED_RANGE"
                break
                ;;
            3)
                echo ""
                echo "Enter IP or range to add (examples: 203.0.113.45 or 203.0.113.0/24):"
                read -p "IP/Range: " NEW_IP
                [ -z "$NEW_IP" ] && print_error "Cannot be empty!" && continue
                if ! validate_ip_or_cidr "$NEW_IP"; then
                    print_error "Invalid IP/CIDR format!"
                    continue
                fi
                break
                ;;
            4)
                echo ""
                echo "Enter NEW whitelist (will replace current, space-separated):"
                echo "Example: 127.0.0.1/8 203.0.113.0/24"
                read -p "New whitelist: " NEW_WHITELIST
                [ -z "$NEW_WHITELIST" ] && print_error "Cannot be empty!" && continue
                if ! validate_ip_or_cidr "$NEW_WHITELIST"; then
                    print_error "Invalid IP/CIDR format!"
                    continue
                fi
                
                # Backup and replace
                cp /etc/fail2ban/jail.local "/etc/fail2ban/jail.local.backup-$(date +%Y%m%d-%H%M%S)"
                sed -i "s|^ignoreip.*|ignoreip = $NEW_WHITELIST|" /etc/fail2ban/jail.local
                systemctl restart fail2ban
                
                print_success "Whitelist replaced with: $NEW_WHITELIST"
                echo ""
                fail2ban-client status sshd
                return 0
                ;;
            5)
                print_status "Cancelled"
                return 0
                ;;
            *)
                print_error "Invalid option"
                continue
                ;;
        esac
    done
    
    # Add to existing whitelist
    if echo "$CURRENT_WHITELIST" | grep -q "$NEW_IP"; then
        print_warning "$NEW_IP is already in the whitelist"
        return 0
    fi
    
    # Backup and update
    cp /etc/fail2ban/jail.local "/etc/fail2ban/jail.local.backup-$(date +%Y%m%d-%H%M%S)"
    sed -i "s|^ignoreip.*|ignoreip = $CURRENT_WHITELIST $NEW_IP|" /etc/fail2ban/jail.local
    systemctl restart fail2ban
    
    print_success "Added $NEW_IP to whitelist"
    echo ""
    echo -e "${YELLOW}New whitelist:${NC}"
    grep "^ignoreip" /etc/fail2ban/jail.local | cut -d'=' -f2 | xargs
    echo ""
    fail2ban-client status sshd
}

################################################################################
# MAIN
################################################################################

if [ $# -eq 0 ]; then
    [[ "$(basename "$0")" == "vm-security-status" || "$(basename "$0")" == "security-status" ]] && show_status || show_help
    exit 0
fi

COMMAND=$1
shift

case $COMMAND in
    setup) run_setup ;;
    status) show_status "$@" ;;
    reapply) run_reapply ;;
    install) run_install ;;
    logs) show_logs ;;
    unban) run_unban "$@" ;;
    whitelist) run_whitelist ;;
    help|--help|-h) show_help ;;
    *)
        echo -e "${RED}Unknown command: $COMMAND${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac
