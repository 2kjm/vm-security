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
# Version: 0.1.0
# Date: October 2025
################################################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Configuration (Edit these for initial setup)
################################################################################
NEW_USER=""                          # Username (will prompt if not set)
SSH_PORT=22                          # SSH port (22 = default)
CHANGE_SSH_PORT=false                # Set to true to change SSH port
SSH_PUBLIC_KEY=""                    # Your SSH public key (will prompt if not set)
FAIL2BAN_BANTIME=3600               # Ban time in seconds (1 hour)
FAIL2BAN_MAXRETRY=5                 # Max failed attempts (increased from 3 to prevent lockouts)
FAIL2BAN_FINDTIME=600               # Time window (10 min)
FAIL2BAN_IGNOREIP="127.0.0.1/8"     # IPs/networks to never ban (use /24 ranges for dynamic ISPs)
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
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ ACTIVE${NC}"
    else
        echo -e "${RED}✗ INACTIVE${NC}"
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
    echo "Usage: vm-security <command> [options]"
    echo ""
    echo -e "${GREEN}Commands:${NC}"
    echo ""
    echo -e "  ${CYAN}setup${NC}              Run initial security hardening (SOC2-aligned controls)"
    echo "                     • Creates admin user with SSH key"
    echo "                     • Hardens SSH, enables fail2ban, configures UFW"
    echo "                     • Sets up audit logging, file integrity monitoring"
    echo "                     • Prevents Docker from bypassing firewall"
    echo "                     • Configures password policies and kernel hardening"
    echo ""
    echo -e "  ${CYAN}status${NC}             Show current security status"
    echo "                     • Check all security services"
    echo "                     • Detect intrusion attempts"
    echo "                     • Find exposed services"
    echo "                     • Verify Docker isn't bypassing firewall"
    echo ""
    echo -e "  ${CYAN}status --detailed${NC}  Show detailed security analysis"
    echo ""
    echo -e "  ${CYAN}reapply${NC}            Re-run security hardening (safe for existing setups)"
    echo "                     • Updates all security configurations"
    echo "                     • Backs up existing configs first"
    echo ""
    echo -e "  ${CYAN}logs${NC}               View security logs and reports"
    echo "                     • Browse authentication logs, banned IPs"
    echo "                     • View audit logs and AIDE integrity reports"
    echo "                     • All logs stored automatically (365 days)"
    echo ""
    echo -e "  ${CYAN}unban <ip>${NC}         Unban an IP address from fail2ban"
    echo "                     • Unban yourself if accidentally locked out"
    echo "                     • Use 'unban all' to unban all IPs"
    echo ""
    echo -e "  ${CYAN}install${NC}            Install commands system-wide"
    echo "                     • Creates /usr/local/bin/vm-security"
    echo "                     • Adds security status to login banner"
    echo ""
    echo -e "  ${CYAN}help${NC}               Show this help message"
    echo ""
    echo -e "${GREEN}Examples:${NC}"
    echo ""
    echo "  # First time setup (interactive - will prompt for username & SSH key)"
    echo "  sudo ./vm-security.sh setup"
    echo ""
    echo "  # Or pre-configure by editing the script first"
    echo "  sudo vim vm-security.sh  # Set NEW_USER & SSH_PUBLIC_KEY"
    echo "  sudo ./vm-security.sh setup"
    echo ""
    echo "  # Check security status"
    echo "  vm-security status"
    echo ""
    echo "  # Re-apply security after system changes"
    echo "  sudo vm-security reapply"
    echo ""
    echo -e "${GREEN}After installation, use these shortcuts:${NC}"
    echo "  vm-security-status         # Quick alias"
    echo "  security-status            # Even shorter"
    echo ""
}

################################################################################
# STATUS CHECK
################################################################################
show_status() {
    DETAILED=false
    if [ "$1" == "--detailed" ] || [ "$1" == "-d" ]; then
        DETAILED=true
    fi
    
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           VM SECURITY STATUS - $(date +'%Y-%m-%d %H:%M:%S')              ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Core Services
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  CORE SECURITY SERVICES${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    systemctl is-active sshd > /dev/null 2>&1; SSH_STATUS=$?
    systemctl is-active fail2ban > /dev/null 2>&1; F2B_STATUS=$?
    ufw status | grep -q "Status: active"; UFW_STATUS=$?
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
    
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        # Check if fail2ban-client is working
        if F2B_OUTPUT=$(fail2ban-client status sshd 2>&1); then
            BANNED_COUNT=$(echo "$F2B_OUTPUT" | grep "Currently banned" | awk '{print $4}')
            TOTAL_BANNED=$(echo "$F2B_OUTPUT" | grep "Total banned" | awk '{print $4}')
            
            BANNED_COUNT=${BANNED_COUNT:-0}
            TOTAL_BANNED=${TOTAL_BANNED:-0}
            
            echo -e "Currently Banned IPs:        ${YELLOW}$BANNED_COUNT${NC}"
            echo -e "Total Banned (session):      ${YELLOW}$TOTAL_BANNED${NC}"
            
            if [ "$BANNED_COUNT" -gt 0 ] 2>/dev/null; then
                echo ""
                echo -e "${YELLOW}Active Bans:${NC}"
                echo "$F2B_OUTPUT" | grep "Banned IP list:" | sed 's/.*Banned IP list://' | tr ' ' '\n' | grep -v '^$' | head -10 | while read ip; do
                    echo "  • $ip"
                done
            fi
        else
            echo -e "Currently Banned IPs:        ${RED}Error querying fail2ban${NC}"
        fi
    else
        echo -e "Currently Banned IPs:        ${RED}fail2ban not running${NC}"
    fi
    
    echo ""
    FAILED_24H=$(journalctl --since "24 hours ago" -u sshd 2>/dev/null | grep "Failed password" | wc -l)
    FAILED_1H=$(journalctl --since "1 hour ago" -u sshd 2>/dev/null | grep "Failed password" | wc -l)
    
    # Ensure we have numeric values
    FAILED_24H=${FAILED_24H:-0}
    FAILED_1H=${FAILED_1H:-0}
    
    echo -e "Failed Logins (24h):         ${YELLOW}$FAILED_24H${NC}"
    echo -e "Failed Logins (1h):          ${YELLOW}$FAILED_1H${NC}"
    
    if [ "$FAILED_1H" -gt 50 ] 2>/dev/null; then
        echo -e "  ${RED}⚠ HIGH ATTACK RATE - Under active brute force!${NC}"
    elif [ "$FAILED_1H" -gt 10 ] 2>/dev/null; then
        echo -e "  ${YELLOW}⚠ Moderate attack activity${NC}"
    fi
    
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
    
    # Get UFW allowed ports for cross-reference
    UFW_ALLOWED_PORTS=""
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        UFW_ALLOWED_PORTS=$(ufw status numbered 2>/dev/null | grep "ALLOW IN" | grep -oP '\d+(?=/tcp)' | tr '\n' '|' || true)
    fi
    
    # Scan for exposed services (deduplicate by port)
    EXPOSED_SERVICES=$(ss -tlnp 2>/dev/null | grep LISTEN | grep -v "127.0.0.1" | grep -v "::1" | awk '{print $4, $NF}' | \
    while read addr process; do
        PORT=$(echo $addr | sed 's/.*://')
        PROCESS=$(echo $process | sed 's/.*"\(.*\)".*/\1/' | sed 's/,.*//')
        echo "$PORT|$PROCESS"
    done | sort -u -t'|' -k1,1n)
    
    if [ -n "$EXPOSED_SERVICES" ]; then
        echo "$EXPOSED_SERVICES" | while IFS='|' read PORT PROCESS; do
            # Check if port is in UFW allowed list
            if echo "$UFW_ALLOWED_PORTS" | grep -qE "(^|\\|)${PORT}(\\||$)"; then
                # Port is explicitly allowed in firewall
                REASON="Allowed in UFW"
                echo -e "${GREEN}✓${NC} Port ${PORT}: ${PROCESS} - ${REASON}"
            else
                # Port is exposed but not in UFW - potential bypass
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
                # Show the port binding nicely
                BINDING=$(echo "$ports" | grep -o "127.0.0.1:[0-9]*->[0-9]*/[a-z]*" | head -1)
                echo -e "  ${GREEN}✓${NC} ${name} - ${BINDING} (localhost only)"
            else
                echo -e "  ${GREEN}✓${NC} ${name} - internal only"
            fi
        done
    fi
    
    if [ "$EXPOSED_FOUND" = false ]; then
        echo -e "${GREEN}✓ No unexpected exposed services${NC}"
    fi
    
    echo ""
    
    # Docker-UFW Bypass Check
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  DOCKER FIREWALL BYPASS CHECK${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if command -v docker &> /dev/null; then
        DOCKER_UFW_INTEGRATED=false
        
        # Check for ufw-docker-logging-deny or ufw-user-forward in DOCKER-USER chain
        if iptables -L DOCKER-USER -n 2>/dev/null | grep -qE "(ufw-user-forward|ufw-docker-logging-deny)"; then
            echo -e "${GREEN}✓ Docker CANNOT bypass UFW (secured)${NC}"
            DOCKER_UFW_INTEGRATED=true
        else
            # Check if Docker is even running
            if docker ps >/dev/null 2>&1; then
                echo -e "${YELLOW}⚠ Docker-UFW integration not detected${NC}"
                echo -e "  ${YELLOW}Recommendation: Run 'sudo vm-security reapply' to secure Docker${NC}"
            else
                echo -e "${BLUE}ℹ Docker installed but not running${NC}"
            fi
        fi
        
        # Check daemon.json for additional security
        if [ -f /etc/docker/daemon.json ]; then
            if grep -q '"icc": false' /etc/docker/daemon.json 2>/dev/null; then
                echo -e "${GREEN}✓ Container inter-communication disabled${NC}"
            fi
            if grep -q '"no-new-privileges": true' /etc/docker/daemon.json 2>/dev/null; then
                echo -e "${GREEN}✓ Container privilege escalation blocked${NC}"
            fi
        fi
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
    [ "$FAILED_1H" -gt 50 ] 2>/dev/null && SCORE=$((SCORE-10))
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
# SETUP - Security Hardening (Implements SOC2-aligned technical controls)
################################################################################
run_setup() {
    # Exit on error for setup - critical for security
    set -e
    trap 'print_error "Setup failed at line $LINENO. Check /root/security-setup-*.log for details."; set +e; exit 1' ERR
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
       print_error "This must be run as root (use sudo)"
       exit 1
    fi
    
    # Prompt for username if not set
    if [ -z "$NEW_USER" ]; then
        echo ""
        print_header "Step 1: Create Admin User"
        echo "You need to create a non-root admin user with sudo privileges."
        echo "This user will have SSH key-based authentication."
        echo ""
        
        while true; do
            read -p "Enter username for the new admin user: " NEW_USER
            
            # Validate username
            if [ -z "$NEW_USER" ]; then
                print_error "Username cannot be empty!"
                continue
            fi
            
            if [ "$NEW_USER" = "root" ]; then
                print_error "Cannot use 'root' as the username!"
                continue
            fi
            
            if ! [[ "$NEW_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
                print_error "Invalid username format!"
                echo "Username must:"
                echo "  - Start with a lowercase letter or underscore"
                echo "  - Contain only lowercase letters, numbers, hyphens, or underscores"
                continue
            fi
            
            if id "$NEW_USER" &>/dev/null; then
                print_warning "User '$NEW_USER' already exists. Using existing user."
                break
            fi
            
            # Confirm username
            echo ""
            read -p "Create user '$NEW_USER'? (y/n) " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                print_success "Username '$NEW_USER' accepted!"
                break
            else
                echo "Let's try again..."
                NEW_USER=""
            fi
        done
    fi
    
    # Prompt for SSH public key if not set
    if [ -z "$SSH_PUBLIC_KEY" ]; then
        echo ""
        print_header "Step 2: Configure SSH Key Authentication"
        print_warning "SSH public key is required for secure authentication!"
        echo ""
        echo -e "${CYAN}How to get your SSH public key:${NC}"
        echo "  1. On your LOCAL machine (not this VM), run:"
        echo -e "     ${YELLOW}cat ~/.ssh/id_rsa.pub${NC}"
        echo "     OR"
        echo -e "     ${YELLOW}cat ~/.ssh/id_ed25519.pub${NC}"
        echo ""
        echo "  2. Copy the entire output (starts with 'ssh-rsa' or 'ssh-ed25519')"
        echo "  3. Paste it below when prompted"
        echo ""
        echo -e "${YELLOW}⚠️  This is CRITICAL - without it, you'll be locked out!${NC}"
        echo ""
        read -p "Do you have your SSH public key ready? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo ""
            print_error "Setup cancelled. Get your SSH key first, then run again."
            echo ""
            echo "Alternatively, you can edit this script and add your key to the SSH_PUBLIC_KEY variable (line 38)"
            exit 1
        fi
        
        echo ""
        echo -e "${CYAN}Paste your SSH public key below and press Enter:${NC}"
        read -r SSH_PUBLIC_KEY
        
        # Validate the key format (basic check)
        if [[ ! "$SSH_PUBLIC_KEY" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ssh-dss) ]]; then
            print_error "Invalid SSH key format!"
            echo "SSH keys should start with: ssh-rsa, ssh-ed25519, or ecdsa-sha2-nistp256"
            echo ""
            echo "What you entered: ${SSH_PUBLIC_KEY:0:50}..."
            exit 1
        fi
        
        # Validate the key is actually valid using ssh-keygen
        print_status "Validating SSH key..."
        echo "$SSH_PUBLIC_KEY" > /tmp/validate_ssh_key.pub
        if ! ssh-keygen -l -f /tmp/validate_ssh_key.pub >/dev/null 2>&1; then
            print_error "The provided SSH key is invalid or malformed!"
            echo ""
            echo "Please ensure you copied the ENTIRE key, including:"
            echo "  - The key type (ssh-rsa, ssh-ed25519, etc.)"
            echo "  - The full key data"
            echo "  - The comment at the end (optional but recommended)"
            echo ""
            echo "Example of a valid key:"
            echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@hostname"
            rm -f /tmp/validate_ssh_key.pub
            exit 1
        fi
        rm -f /tmp/validate_ssh_key.pub
        
        print_success "SSH key validated successfully!"
        echo ""
    fi
    
    clear
    print_header "VM Security Hardening (SOC2-Aligned Controls)"
    
    # PRE-FLIGHT SAFETY CHECKS
    print_status "Running pre-flight safety checks..."
    
    # Check if we're in an SSH session
    CURRENT_IP=$(echo $SSH_CONNECTION | awk '{print $1}')
    if [ -n "$CURRENT_IP" ]; then
        # Calculate the /24 network range for the current IP
        NETWORK_PREFIX=$(echo $CURRENT_IP | cut -d. -f1-3)
        SUGGESTED_RANGE_24="${NETWORK_PREFIX}.0/24"
        SUGGESTED_RANGE_16=$(echo $CURRENT_IP | cut -d. -f1-2)".0.0/16"
        
        print_warning "You are connected via SSH from: $CURRENT_IP"
        echo ""
        echo -e "${YELLOW}⚠️  IMPORTANT: Dynamic IP Warning${NC}"
        echo "Most ISPs use dynamic IPs that change frequently (DHCP, router restart, etc.)"
        echo ""
        echo -e "${CYAN}Choose your fail2ban whitelist strategy:${NC}"
        echo ""
        echo "1) Current IP only        - $CURRENT_IP"
        echo "   ${RED}⚠ Will lock you out if your IP changes!${NC}"
        echo ""
        echo "2) /24 Network Range      - $SUGGESTED_RANGE_24"
        echo "   ${GREEN}✓ Recommended - Covers $NETWORK_PREFIX.0-255 (256 IPs)${NC}"
        echo ""
        echo "3) /16 Network Range      - $SUGGESTED_RANGE_16"
        echo "   ${YELLOW}⚠ Less secure - Covers $(echo $CURRENT_IP | cut -d. -f1-2).0.0-255.255 (65K IPs)${NC}"
        echo ""
        echo "4) Custom                 - Enter your own IP(s) or range(s)"
        echo ""
        echo "5) Use configured value   - $FAIL2BAN_IGNOREIP"
        echo ""
        
        WHITELIST_CHOICE=""
        while true; do
            read -p "Select option (1-5): " WHITELIST_CHOICE
            
            case $WHITELIST_CHOICE in
                1)
                    # Current IP only
                    FAIL2BAN_IGNOREIP="127.0.0.1/8 $CURRENT_IP"
                    print_warning "Using current IP only: $CURRENT_IP"
                    echo -e "${RED}Remember: You may be locked out if your ISP changes your IP!${NC}"
                    break
                    ;;
                2)
                    # /24 range (recommended)
                    FAIL2BAN_IGNOREIP="127.0.0.1/8 $SUGGESTED_RANGE_24"
                    print_success "Using /24 range: $SUGGESTED_RANGE_24 (recommended)"
                    break
                    ;;
                3)
                    # /16 range
                    FAIL2BAN_IGNOREIP="127.0.0.1/8 $SUGGESTED_RANGE_16"
                    print_warning "Using /16 range: $SUGGESTED_RANGE_16"
                    echo -e "${YELLOW}Note: This is a large range. Consider /24 for better security.${NC}"
                    break
                    ;;
                4)
                    # Custom input
                    echo ""
                    echo -e "${CYAN}Enter custom whitelist (space-separated):${NC}"
                    echo "Examples:"
                    echo "  Single IP:        203.0.113.45"
                    echo "  Multiple IPs:     203.0.113.45 198.51.100.20"
                    echo "  Network range:    203.0.113.0/24"
                    echo "  Mixed:            203.0.113.0/24 198.51.100.20"
                    echo ""
                    read -p "Whitelist: " CUSTOM_WHITELIST
                    
                    # Validate input
                    if [ -z "$CUSTOM_WHITELIST" ]; then
                        print_error "Cannot be empty!"
                        continue
                    fi
                    
                    # Validate each IP/CIDR
                    VALIDATION_FAILED=false
                    for ip in $CUSTOM_WHITELIST; do
                        # Check if it's CIDR notation (IP/mask)
                        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
                            # Validate CIDR
                            IP_PART=$(echo $ip | cut -d'/' -f1)
                            MASK_PART=$(echo $ip | cut -d'/' -f2)
                            
                            # Validate IP octets
                            IFS='.' read -ra OCTETS <<< "$IP_PART"
                            for octet in "${OCTETS[@]}"; do
                                if [ "$octet" -lt 0 ] 2>/dev/null || [ "$octet" -gt 255 ] 2>/dev/null; then
                                    print_error "Invalid IP octet in $ip: $octet (must be 0-255)"
                                    VALIDATION_FAILED=true
                                    break 2
                                fi
                            done
                            
                            # Validate CIDR mask
                            if [ "$MASK_PART" -lt 0 ] 2>/dev/null || [ "$MASK_PART" -gt 32 ] 2>/dev/null; then
                                print_error "Invalid CIDR mask in $ip: /$MASK_PART (must be /0-/32)"
                                VALIDATION_FAILED=true
                                break
                            fi
                        # Check if it's a plain IP
                        elif [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                            # Validate IP octets
                            IFS='.' read -ra OCTETS <<< "$ip"
                            for octet in "${OCTETS[@]}"; do
                                if [ "$octet" -lt 0 ] 2>/dev/null || [ "$octet" -gt 255 ] 2>/dev/null; then
                                    print_error "Invalid IP octet in $ip: $octet (must be 0-255)"
                                    VALIDATION_FAILED=true
                                    break 2
                                fi
                            done
                        else
                            print_error "Invalid format: $ip"
                            echo "Must be either:"
                            echo "  - IP address: 203.0.113.45"
                            echo "  - CIDR range: 203.0.113.0/24"
                            VALIDATION_FAILED=true
                            break
                        fi
                    done
                    
                    if [ "$VALIDATION_FAILED" = true ]; then
                        continue
                    fi
                    
                    FAIL2BAN_IGNOREIP="127.0.0.1/8 $CUSTOM_WHITELIST"
                    print_success "Custom whitelist configured: $CUSTOM_WHITELIST"
                    break
                    ;;
                5)
                    # Use pre-configured value
                    print_status "Using configured value: $FAIL2BAN_IGNOREIP"
                    break
                    ;;
                *)
                    print_error "Invalid option. Please select 1-5."
                    ;;
            esac
        done
        
        echo ""
        print_success "Whitelist configured: $FAIL2BAN_IGNOREIP"
        echo ""
    fi
    
    # Verify SSH key is valid
    if [ -n "$SSH_PUBLIC_KEY" ]; then
        echo "$SSH_PUBLIC_KEY" > /tmp/validate_ssh_key_final.pub
        if ! ssh-keygen -l -f /tmp/validate_ssh_key_final.pub >/dev/null 2>&1; then
            print_error "SSH key validation failed! This would lock you out."
            rm -f /tmp/validate_ssh_key_final.pub
            exit 1
        fi
        rm -f /tmp/validate_ssh_key_final.pub
        print_success "SSH key validated ✓"
    fi
    
    echo ""
    echo "This will configure comprehensive security measures."
    echo ""
    echo "Configuration:"
    echo "  New User: $NEW_USER"
    echo "  SSH Port: $SSH_PORT"
    echo "  fail2ban: $FAIL2BAN_MAXRETRY attempts, ${FAIL2BAN_BANTIME}s ban"
    echo "  Whitelisted: $FAIL2BAN_IGNOREIP"
    echo ""
    echo -e "${YELLOW}⚠️  CRITICAL SAFETY REMINDERS:${NC}"
    echo "  1. Test SSH in a NEW terminal BEFORE logging out"
    echo "  2. Your current IP ($CURRENT_IP) will be whitelisted"
    echo "  3. Keep this terminal open until you verify SSH access"
    echo ""
    read -p "Continue? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
    
    LOG_FILE="/root/security-setup-$(date +%Y%m%d-%H%M%S).log"
    exec > >(tee -a "$LOG_FILE") 2>&1
    
    print_header "1. System Update"
    apt-get update -qq && apt-get upgrade -y -qq
    print_success "System updated"
    
    print_header "2. Creating Admin User"
    if ! id "$NEW_USER" &>/dev/null; then
        adduser --disabled-password --gecos "" "$NEW_USER"
        usermod -aG sudo "$NEW_USER"
        print_success "User $NEW_USER created"
    else
        print_warning "User $NEW_USER exists"
    fi
    
    print_header "3. SSH Key Authentication"
    mkdir -p /home/$NEW_USER/.ssh
    chmod 700 /home/$NEW_USER/.ssh
    echo "$SSH_PUBLIC_KEY" > /home/$NEW_USER/.ssh/authorized_keys
    chmod 600 /home/$NEW_USER/.ssh/authorized_keys
    chown -R $NEW_USER:$NEW_USER /home/$NEW_USER/.ssh
    print_success "SSH key configured"
    
    print_header "4. SSH Hardening"
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup-$(date +%Y%m%d) || true
    
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
    
    if [ "$CHANGE_SSH_PORT" = true ]; then
        sed -i "s/^#\?Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
    fi
    
    # Validate SSH config with full test including all drop-in files
    if ! sshd -T >/dev/null 2>&1; then
        print_error "SSH configuration validation failed!"
        sshd -T
        exit 1
    fi
    print_success "SSH configured and validated"
    
    print_header "5. fail2ban (Anti-Lockout Configuration)"
    apt-get install -y fail2ban -qq
    
    # Get current SSH connection IP to whitelist it
    CURRENT_IP=$(echo $SSH_CONNECTION | awk '{print $1}')
    WHITELIST_IPS="$FAIL2BAN_IGNOREIP"
    
    # Only add current IP if not already in the whitelist
    if [ -n "$CURRENT_IP" ] && [ "$CURRENT_IP" != "127.0.0.1" ]; then
        if ! echo "$WHITELIST_IPS" | grep -q "$CURRENT_IP"; then
            print_warning "Adding your current IP to whitelist: $CURRENT_IP"
            WHITELIST_IPS="$WHITELIST_IPS $CURRENT_IP"
        fi
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
    print_success "fail2ban configured (your IP whitelisted: $CURRENT_IP)"
    
    print_header "6. UFW Firewall"
    apt-get install -y ufw -qq
    ufw --force disable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow $SSH_PORT/tcp
    
    if [ -n "$ALLOWED_HTTP_PORTS" ]; then
        IFS=',' read -ra PORTS <<< "$ALLOWED_HTTP_PORTS"
        for port in "${PORTS[@]}"; do
            ufw allow $port/tcp
        done
    fi
    
    ufw limit $SSH_PORT/tcp
    ufw --force enable
    print_success "UFW configured"
    
    print_header "7. Docker-UFW Integration (Prevents Bypass)"
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
        
        # Backup current rules
        cp /etc/ufw/after.rules /etc/ufw/after.rules.backup-$(date +%Y%m%d-%H%M%S) 2>/dev/null || true
        
        # Remove any existing Docker rules from current file
        sed -i '/# Docker UFW Integration/,/^COMMIT$/d' /etc/ufw/after.rules 2>/dev/null || true
        
        # Prepend Docker rules to the file
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
    
    if command -v docker &> /dev/null; then
        cat >> /etc/audit/rules.d/soc2-compliance.rules << 'EOF'
-w /usr/bin/docker -p wa -k docker
-w /var/lib/docker -p wa -k docker
-w /etc/docker -p wa -k docker
EOF
    fi
    
    systemctl enable auditd && systemctl restart auditd
    print_success "Audit logging configured"
    
    print_header "10. SOC2: File Integrity (AIDE)"
    apt-get install -y aide aide-common -qq
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
    
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
mkdir -p /var/log/aide
/usr/bin/aide --check > /var/log/aide/aide-check-$(date +%Y%m%d).log 2>&1
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
    print_success "Password policy set (14 char, 90 day expiry)"
    
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
    
    print_header "🎉 Security Hardening Complete! (SOC2-Aligned Controls Implemented)"
    echo ""
    echo -e "${GREEN}✅ ALL SECURITY MEASURES APPLIED${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  CRITICAL: Test SSH in a NEW terminal before logging out!${NC}"
    echo ""
    echo "Test with:"
    echo "  ssh -p $SSH_PORT $NEW_USER@$(hostname -I | awk '{print $1}')"
    echo ""
    echo -e "${CYAN}🔒 Anti-Lockout Protections:${NC}"
    echo "  ✓ Your current IP whitelisted: $CURRENT_IP"
    echo "  ✓ fail2ban allows $FAIL2BAN_MAXRETRY failed attempts"
    echo "  ✓ SSH key authentication verified"
    echo ""
    if [ -n "$CURRENT_IP" ]; then
        NETWORK_PREFIX=$(echo $CURRENT_IP | cut -d. -f1-3)
        echo -e "${YELLOW}⚠️  Dynamic IP Warning:${NC}"
        echo "  Your IP may change if your ISP uses DHCP (most do)."
        echo "  Consider whitelisting your network range: ${NETWORK_PREFIX}.0/24"
        echo "  Edit /etc/fail2ban/jail.local and add to ignoreip line"
        echo ""
    fi
    echo -e "${CYAN}Emergency Unbanning (if needed):${NC}"
    echo "  If locked out, access via console and run:"
    echo "  sudo fail2ban-client unban $CURRENT_IP"
    echo "  sudo fail2ban-client unban --all   (unban all IPs)"
    echo ""
    echo "Run 'vm-security status' to verify configuration."
    echo ""
    echo -e "${GREEN}Setup log saved to: $LOG_FILE${NC}"
    echo ""
}

################################################################################
# REAPPLY
################################################################################
run_reapply() {
    if [[ $EUID -ne 0 ]]; then
       print_error "This must be run as root (use sudo)"
       exit 1
    fi
    
    BACKUP_DIR="/root/security-backups/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    print_status "Backing up configs to $BACKUP_DIR..."
    cp /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/fail2ban/jail.local "$BACKUP_DIR/" 2>/dev/null || true
    
    print_status "Re-running security hardening..."
    echo ""
    
    # Run setup (it's idempotent)
    run_setup
}

################################################################################
# SHOW LOGS - View Security Logs
################################################################################
show_logs() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           SECURITY LOGS & REPORTS                                    ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${CYAN}📁 Automatic Log Storage Locations:${NC}"
    echo ""
    echo "1. Authentication & SSH Attacks:"
    echo "   /var/log/auth.log         (All SSH attempts, logins, sudo)"
    echo "   /var/log/fail2ban.log     (Banned IPs, attack patterns)"
    echo ""
    echo "2. Audit Logs (SOC2 Compliance):"
    echo "   /var/log/audit/audit.log  (System calls, file access, user actions)"
    echo ""
    echo "3. File Integrity (AIDE):"
    echo "   /var/log/aide/            (Daily integrity check reports)"
    echo ""
    echo "4. System Logs:"
    echo "   /var/log/syslog           (General system events)"
    echo "   /var/log/ufw.log          (Firewall blocks)"
    echo ""
    echo -e "${CYAN}📊 Log Retention:${NC}"
    echo "   • Auth logs: 365 days (SOC2 compliant)"
    echo "   • Audit logs: Permanent until manually rotated"
    echo "   • AIDE reports: Daily snapshots stored indefinitely"
    echo ""
    echo -e "${CYAN}🔍 Quick Log Views:${NC}"
    echo ""
    
    PS3="Select log to view (0 to exit): "
    options=(
        "Recent SSH Failed Logins (last 50)"
        "Currently Banned IPs (fail2ban)"
        "Recent UFW Blocks (last 50)"
        "Audit Log - Recent Activity (last 50)"
        "AIDE - Latest Integrity Report"
        "Setup Log - Last Installation"
        "Exit"
    )
    
    select opt in "${options[@]}"
    do
        case $opt in
            "Recent SSH Failed Logins (last 50)")
                echo ""
                echo -e "${YELLOW}Recent SSH Failed Login Attempts:${NC}"
                grep "Failed password" /var/log/auth.log 2>/dev/null | tail -50 || echo "No failed logins found"
                echo ""
                ;;
            "Currently Banned IPs (fail2ban)")
                echo ""
                echo -e "${YELLOW}Currently Banned IPs:${NC}"
                if systemctl is-active fail2ban > /dev/null 2>&1; then
                    fail2ban-client status sshd 2>/dev/null || echo "fail2ban not configured for sshd"
                else
                    echo "fail2ban is not running"
                fi
                echo ""
                ;;
            "Recent UFW Blocks (last 50)")
                echo ""
                echo -e "${YELLOW}Recent UFW Firewall Blocks:${NC}"
                grep "UFW BLOCK" /var/log/ufw.log 2>/dev/null | tail -50 || echo "No UFW blocks found"
                echo ""
                ;;
            "Audit Log - Recent Activity (last 50)")
                echo ""
                echo -e "${YELLOW}Recent Audit Events:${NC}"
                if command -v ausearch &> /dev/null; then
                    ausearch -i --start recent 2>/dev/null | tail -50 || echo "No recent audit events"
                else
                    tail -50 /var/log/audit/audit.log 2>/dev/null || echo "Audit log not found"
                fi
                echo ""
                ;;
            "AIDE - Latest Integrity Report")
                echo ""
                echo -e "${YELLOW}Latest AIDE File Integrity Report:${NC}"
                LATEST_AIDE=$(ls -t /var/log/aide/aide-check-*.log 2>/dev/null | head -1)
                if [ -n "$LATEST_AIDE" ]; then
                    echo "File: $LATEST_AIDE"
                    echo ""
                    cat "$LATEST_AIDE"
                else
                    echo "No AIDE reports found yet. First report will be generated after tomorrow."
                fi
                echo ""
                ;;
            "Setup Log - Last Installation")
                echo ""
                echo -e "${YELLOW}Last Security Setup Log:${NC}"
                LATEST_SETUP=$(ls -t /root/security-setup-*.log 2>/dev/null | head -1)
                if [ -n "$LATEST_SETUP" ]; then
                    echo "File: $LATEST_SETUP"
                    echo ""
                    tail -100 "$LATEST_SETUP"
                else
                    echo "No setup logs found"
                fi
                echo ""
                ;;
            "Exit")
                break
                ;;
            *) echo "Invalid option";;
        esac
    done
}

################################################################################
# INSTALL SYSTEM-WIDE
################################################################################
run_install() {
    if [[ $EUID -ne 0 ]]; then
       print_error "This must be run as root (use sudo)"
       exit 1
    fi
    
    SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    
    print_status "Installing to /usr/local/bin..."
    cp "$SCRIPT_PATH" /usr/local/bin/vm-security
    chmod +x /usr/local/bin/vm-security
    
    # Create convenient aliases
    ln -sf /usr/local/bin/vm-security /usr/local/bin/vm-security-status 2>/dev/null || true
    ln -sf /usr/local/bin/vm-security /usr/local/bin/security-status 2>/dev/null || true
    
    # Create cron job to update security status (efficient, non-blocking)
    cat > /etc/cron.d/vm-security-status << 'EOF'
# Update security status every 5 minutes
*/5 * * * * root /usr/local/bin/vm-security-status-update >/dev/null 2>&1
EOF
    
    # Create the status update script
    cat > /usr/local/bin/vm-security-status-update << 'EOF'
#!/bin/bash
# Update security status for login banner
STATUS_FILE="/run/vm-security-status.txt"

# Only run if services are active
if ! systemctl is-active --quiet sshd 2>/dev/null; then
    echo "Security services initializing..." > "$STATUS_FILE"
    exit 0
fi

# Gather status (runs as root via cron, so no sudo needed)
BANNED="?"
FAILED="0"
UFW="Unknown"

if systemctl is-active --quiet fail2ban 2>/dev/null; then
    BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}' || echo "?")
fi

if systemctl is-active --quiet sshd 2>/dev/null; then
    FAILED=$(journalctl --since "1 hour ago" -u sshd 2>/dev/null | grep "Failed password" | wc -l || echo "0")
fi

if command -v ufw >/dev/null 2>&1; then
    UFW=$(ufw status 2>/dev/null | grep -q "Status: active" && echo "Active" || echo "Inactive")
fi

# Write to status file
cat > "$STATUS_FILE" << EOFSTATUS
=== Quick Security Status ===
Firewall: $UFW | Banned: $BANNED | Failed (1h): $FAILED
Type 'vm-security status' for full report
=============================
EOFSTATUS

chmod 644 "$STATUS_FILE"
EOF
    chmod +x /usr/local/bin/vm-security-status-update
    
    # Run once immediately
    /usr/local/bin/vm-security-status-update
    
    # Add to bash profile (just reads the pre-generated file)
    if ! grep -q "VM Security Commands" /etc/bash.bashrc 2>/dev/null; then
        cat >> /etc/bash.bashrc << 'EOF'

# VM Security Commands
alias vm-security-status='vm-security status'
alias security-status='vm-security status'
alias security-check='vm-security status --detailed'

# Security banner on login (reads pre-generated status file)
if [ -t 0 ] && [ -n "$PS1" ] && { [ $EUID -eq 0 ] || groups | grep -q sudo 2>/dev/null; }; then
    if [ -f /run/vm-security-status.txt ]; then
        echo ""
        cat /run/vm-security-status.txt
        echo ""
    fi
fi
EOF
    fi
    
    print_success "✅ Installed successfully!"
    echo ""
    echo "Available commands:"
    echo "  vm-security setup"
    echo "  vm-security status"
    echo "  vm-security status --detailed"
    echo "  vm-security reapply"
    echo ""
    echo "Aliases:"
    echo "  vm-security-status"
    echo "  security-status"
    echo "  security-check"
    echo ""
}

################################################################################
# UNBAN - Emergency IP Unbanning
################################################################################
run_unban() {
    if [[ $EUID -ne 0 ]]; then
       print_error "This must be run as root (use sudo)"
       exit 1
    fi
    
    if ! systemctl is-active --quiet fail2ban; then
        print_error "fail2ban is not running"
        exit 1
    fi
    
    IP=$1
    
    if [ -z "$IP" ]; then
        print_error "Usage: vm-security unban <ip_address|all>"
        echo ""
        echo "Examples:"
        echo "  vm-security unban 1.2.3.4"
        echo "  vm-security unban all"
        exit 1
    fi
    
    if [ "$IP" == "all" ]; then
        print_status "Unbanning all IPs from all jails..."
        fail2ban-client unban --all
        print_success "All IPs unbanned!"
    else
        print_status "Unbanning IP: $IP"
        fail2ban-client unban "$IP"
        print_success "IP $IP unbanned!"
    fi
    
    echo ""
    echo "Current fail2ban status:"
    fail2ban-client status sshd
}

################################################################################
# MAIN
################################################################################

# If no arguments and executed directly
if [ $# -eq 0 ]; then
    if [[ "$(basename "$0")" == "vm-security-status" ]] || [[ "$(basename "$0")" == "security-status" ]]; then
        show_status
    else
        show_help
    fi
    exit 0
fi

# Parse command
COMMAND=$1
shift

case $COMMAND in
    setup)
        run_setup
        ;;
    status)
        show_status "$@"
        ;;
    reapply)
        run_reapply
        ;;
    install)
        run_install
        ;;
    logs)
        show_logs
        ;;
    unban)
        run_unban "$@"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}Unknown command: $COMMAND${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac