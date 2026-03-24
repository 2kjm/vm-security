#!/bin/bash
################################################################################
# PostgreSQL Security Hardening
#
# Hardens a bare-metal/VM PostgreSQL installation for production HA workloads.
# Features: kernel tuning, SSL/TLS, auth hardening, pgaudit, fail2ban,
#           UFW rules, file permissions, resource limits,
#           RAM/CPU-aware performance tuning (shared_buffers, work_mem, etc.).
#
# Usage: pg-security {setup|status|reapply|help}
# Author: 2kjm (https://github.com/2kjm)
# Version: 0.1.0
################################################################################

set -Eeuo pipefail

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# Configuration
PG_VERSION=""
PG_CLUSTER="main"
PG_DATA_DIR=""
PG_CONF_DIR=""
PG_BIN_DIR=""
PG_PORT=5432
PG_INSTALL_VERSION="18"
PG_LISTEN="localhost"
ALLOWED_SUBNETS=""
REPLICATION_PEERS=""
HA_TOOL=""
REAPPLY_MODE=false

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

validate_ip_or_cidr() {
    local input="$1"
    for entry in $input; do
        # IPv6 (with optional CIDR)
        if [[ "$entry" == *:* ]]; then
            local ip6_part="${entry%%/*}"
            # Basic IPv6 structure check: 1-8 groups of hex separated by colons, allow ::
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

################################################################################
# Install PostgreSQL (Ubuntu — official PGDG repo)
################################################################################

install_pg() {
    if command -v psql &>/dev/null || command -v pg_lsclusters &>/dev/null; then
        return 0
    fi

    print_warning "PostgreSQL is not installed."
    read -rp "Install PostgreSQL ${PG_INSTALL_VERSION} from the official PGDG repository? (y/n) " -n 1; echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then print_error "PostgreSQL is required. Exiting."; exit 1; fi

    print_status "Setting up PostgreSQL apt repository..."
    apt-get install -y curl ca-certificates -qq

    install -d /usr/share/postgresql-common/pgdg
    curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail \
        https://www.postgresql.org/media/keys/ACCC4CF8.asc

    . /etc/os-release
    echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list

    apt-get update -qq

    print_status "Installing PostgreSQL ${PG_INSTALL_VERSION}..."
    if ! apt-get install -y "postgresql-${PG_INSTALL_VERSION}" -qq; then
        print_error "Failed to install PostgreSQL ${PG_INSTALL_VERSION}"
        exit 1
    fi

    print_success "PostgreSQL ${PG_INSTALL_VERSION} installed"
}

################################################################################
# System Detection (RAM, CPU, storage)
################################################################################

TOTAL_RAM_KB=0
TOTAL_RAM_MB=0
TOTAL_RAM_GB=0
CPU_CORES=1
STORAGE_IS_SSD=false

detect_system() {
    # Total RAM in kB
    if [ -f /proc/meminfo ]; then
        TOTAL_RAM_KB=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    else
        # macOS / BSD fallback
        TOTAL_RAM_KB=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1024 ))
    fi
    TOTAL_RAM_MB=$(( TOTAL_RAM_KB / 1024 ))
    TOTAL_RAM_GB=$(( TOTAL_RAM_MB / 1024 ))

    # CPU cores
    if command -v nproc &>/dev/null; then
        CPU_CORES=$(nproc)
    elif [ -f /proc/cpuinfo ]; then
        CPU_CORES=$(grep -c '^processor' /proc/cpuinfo)
    else
        CPU_CORES=$(sysctl -n hw.ncpu 2>/dev/null || echo 1)
    fi

    # Storage type detection (SSD vs HDD)
    # Uses lsblk to resolve the underlying physical device, which handles
    # LVM, device-mapper, RAID, and NVMe correctly without fragile sed parsing.
    STORAGE_IS_SSD=false
    if [ -n "$PG_DATA_DIR" ] && command -v lsblk &>/dev/null; then
        local mount_dev
        mount_dev=$(df "$PG_DATA_DIR" 2>/dev/null | awk 'NR==2 {print $1}')
        if [ -n "$mount_dev" ]; then
            # lsblk -no ROTA gives 0 for SSD, 1 for HDD
            # -d resolves to the physical device even through LVM/dm layers
            local rota
            rota=$(lsblk -dno ROTA "$mount_dev" 2>/dev/null | head -1 | tr -d '[:space:]')
            if [ "$rota" = "0" ]; then
                STORAGE_IS_SSD=true
            fi
        fi
    fi

    print_success "System: ${TOTAL_RAM_MB}MB RAM, ${CPU_CORES} CPU cores, storage=$([ "$STORAGE_IS_SSD" = true ] && echo 'SSD' || echo 'HDD')"
}

################################################################################
# Detection
################################################################################

detect_pg() {
    if ! command -v pg_lsclusters &>/dev/null; then
        if command -v psql &>/dev/null; then
            PG_VERSION=$(psql --version 2>/dev/null | grep -oP '\d+' | head -1 || true)
        fi
        if [ -z "$PG_VERSION" ]; then
            print_error "PostgreSQL not found. Run 'pg-security setup' to install."
            exit 1
        fi
        # Fallback path detection for non-Debian systems
        PG_DATA_DIR=$(sudo -u postgres psql -tAc "SHOW data_directory;" 2>/dev/null || true)
        PG_CONF_DIR=$(sudo -u postgres psql -tAc "SHOW config_file;" 2>/dev/null | xargs dirname || true)
        PG_PORT=$(sudo -u postgres psql -tAc "SHOW port;" 2>/dev/null || echo "5432")
        if [ -z "$PG_DATA_DIR" ] || [ -z "$PG_CONF_DIR" ]; then
            print_error "Cannot detect PostgreSQL paths. Is it running?"
            exit 1
        fi
        return
    fi

    local clusters
    clusters=$(pg_lsclusters -h 2>/dev/null || true)
    local count
    count=$(echo "$clusters" | grep -c . || echo 0)

    if [ "$count" -eq 0 ] || [ -z "$clusters" ]; then
        print_error "No PostgreSQL clusters found"
        exit 1
    elif [ "$count" -eq 1 ]; then
        PG_VERSION=$(echo "$clusters" | awk '{print $1}')
        PG_CLUSTER=$(echo "$clusters" | awk '{print $2}')
        PG_PORT=$(echo "$clusters" | awk '{print $3}')
        PG_DATA_DIR=$(echo "$clusters" | awk '{print $6}')
    else
        echo "Multiple PostgreSQL clusters found:"
        echo ""
        printf "  %-4s %-8s %-8s %-6s %-10s %s\n" "#" "Version" "Cluster" "Port" "Status" "Data Dir"
        local i=1
        while IFS= read -r line; do
            local ver cl port status _owner datadir
            read -r ver cl port status _owner datadir <<< "$line"
            printf "  %-4s %-8s %-8s %-6s %-10s %s\n" "$i" "$ver" "$cl" "$port" "$status" "$datadir"
            i=$((i + 1))
        done <<< "$clusters"
        echo ""
        while true; do
            read -rp "Select cluster (1-$count): " choice
            if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "$count" ]; then
                local selected
                selected=$(echo "$clusters" | sed -n "${choice}p")
                PG_VERSION=$(echo "$selected" | awk '{print $1}')
                PG_CLUSTER=$(echo "$selected" | awk '{print $2}')
                PG_PORT=$(echo "$selected" | awk '{print $3}')
                PG_DATA_DIR=$(echo "$selected" | awk '{print $6}')
                break
            fi
            print_error "Invalid choice"
        done
    fi

    PG_CONF_DIR="/etc/postgresql/${PG_VERSION}/${PG_CLUSTER}"
    PG_BIN_DIR="/usr/lib/postgresql/${PG_VERSION}/bin"
}

detect_ha() {
    if systemctl is-active --quiet patroni 2>/dev/null || command -v patronictl &>/dev/null; then
        HA_TOOL="patroni"
    elif command -v repmgr &>/dev/null; then
        HA_TOOL="repmgr"
    elif command -v pg_autoctl &>/dev/null; then
        HA_TOOL="pg_auto_failover"
    fi
}

################################################################################
# HELP
################################################################################

show_help() {
    echo ""
    echo "PostgreSQL Security Hardening"
    echo ""
    echo "Usage: pg-security <command>"
    echo ""
    echo "Commands:"
    echo "  setup       Interactive security hardening"
    echo "  status      Security status overview"
    echo "  reapply     Re-apply hardening (non-interactive)"
    echo "  help        Show this help"
    echo ""
    echo "Applies:"
    echo "  Kernel tuning (overcommit, swappiness, dirty pages, THP)"
    echo "  Resource limits (ulimits, systemd overrides)"
    echo "  SSL/TLS (certificate generation + enforcement)"
    echo "  postgresql.conf hardening (auth, logging, connections)"
    echo "  Performance tuning (RAM/CPU-aware: shared_buffers, work_mem, etc.)"
    echo "  pg_hba.conf hardening (scram-sha-256, subnet restrictions)"
    echo "  pgaudit extension (DDL + role audit logging)"
    echo "  fail2ban jail for PostgreSQL auth failures"
    echo "  UFW rules for PostgreSQL port"
    echo "  File permission hardening"
    echo ""
}

################################################################################
# Interactive Prompts
################################################################################

prompt_config() {
    print_header "Step 1: Detect PostgreSQL"

    # Docker + PostgreSQL mutual exclusion
    if command -v docker &>/dev/null; then
        echo ""
        print_warning "Docker is installed on this system."
        print_warning "Running Docker and PostgreSQL on the same VM is not recommended."
        read -rp "Continue anyway? (type 'yes' to confirm): " confirm
        if [ "$confirm" != "yes" ]; then print_error "Aborted. Remove Docker first or use a separate VM."; exit 1; fi
        print_warning "Proceeding despite Docker being present."
        echo ""
    fi

    install_pg
    detect_pg
    detect_ha
    detect_system

    print_success "Found PostgreSQL $PG_VERSION (cluster: $PG_CLUSTER)"
    echo "  Data dir: $PG_DATA_DIR"
    echo "  Config:   $PG_CONF_DIR"
    echo "  Port:     $PG_PORT"

    if [ -n "$HA_TOOL" ]; then
        echo ""
        print_warning "HA tool detected: $HA_TOOL"
        if [ "$HA_TOOL" = "patroni" ]; then
            print_warning "Patroni manages postgresql.conf and pg_hba.conf."
            print_warning "This script will apply OS-level hardening (kernel, SSL certs,"
            print_warning "fail2ban, UFW, permissions) but skip PG config files."
            print_warning "Add the printed PG settings to your Patroni YAML manually."
        fi
    fi

    # Listen address
    print_header "Step 2: Listen Address"
    echo "Where should PostgreSQL accept connections from?"
    echo ""
    echo "1) localhost only      — single node, local connections"
    echo "2) Private IP          — HA cluster on private network (recommended)"
    echo "3) All interfaces      — 0.0.0.0 (use only with strict UFW rules)"
    echo ""

    while true; do
        read -rp "Select (1-3): " choice
        case $choice in
            1) PG_LISTEN="localhost"; break ;;
            2)
                local private_ip
                private_ip=$(hostname -I | awk '{print $1}')
                if [ -n "$private_ip" ]; then
                    print_status "Detected private IP: $private_ip"
                    read -rp "Use $private_ip? (y/n) " -n 1; echo
                    if [[ $REPLY =~ ^[Yy]$ ]]; then
                        PG_LISTEN="localhost,$private_ip"
                    else
                        read -rp "Enter IP to listen on: " custom_ip
                        validate_ip_or_cidr "$custom_ip" || { print_error "Invalid IP address"; exit 1; }
                        PG_LISTEN="localhost,$custom_ip"
                    fi
                else
                    read -rp "Enter private IP: " custom_ip
                    validate_ip_or_cidr "$custom_ip" || { print_error "Invalid IP address"; exit 1; }
                    PG_LISTEN="localhost,$custom_ip"
                fi
                break ;;
            3) PG_LISTEN="*"
               print_warning "Listening on all interfaces — ensure UFW is restrictive"
               break ;;
            *) print_error "Invalid option" ;;
        esac
    done

    # Allowed subnets
    print_header "Step 3: Allowed Client Networks"
    echo "Which networks can connect to PostgreSQL?"
    echo "Enter CIDR ranges separated by spaces (e.g., 10.0.0.0/24 192.168.1.0/24)"
    echo ""
    if [ "$PG_LISTEN" = "localhost" ]; then
        print_status "Listen is localhost-only — remote clients won't connect."
        echo "You can still configure subnets for future use."
    fi
    echo ""
    read -rp "Allowed subnets (empty to skip): " ALLOWED_SUBNETS
    if [ -n "$ALLOWED_SUBNETS" ]; then
        validate_ip_or_cidr "$ALLOWED_SUBNETS" || { print_error "Invalid subnet format"; exit 1; }
    fi

    # Replication peers
    print_header "Step 4: HA Replication Peers"
    echo "Enter IPs or CIDRs of replication peers (for streaming replication)."
    echo "These will be allowed in pg_hba.conf and UFW for replication traffic."
    echo ""
    read -rp "Replication peers (empty to skip): " REPLICATION_PEERS
    if [ -n "$REPLICATION_PEERS" ]; then
        validate_ip_or_cidr "$REPLICATION_PEERS" || { print_error "Invalid peer format"; exit 1; }
    fi

    # Confirm
    echo ""
    echo "Configuration:"
    echo "  PostgreSQL:    $PG_VERSION ($PG_CLUSTER)"
    echo "  Port:          $PG_PORT"
    echo "  Listen:        $PG_LISTEN"
    echo "  Client nets:   ${ALLOWED_SUBNETS:-none}"
    echo "  HA peers:      ${REPLICATION_PEERS:-none}"
    echo "  HA tool:       ${HA_TOOL:-none detected}"
    echo ""
    print_warning "PostgreSQL will be reloaded after changes."
    echo ""
    read -rp "Continue? (y/n) " -n 1; echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then exit 0; fi
}

################################################################################
# Kernel Tuning
################################################################################

setup_kernel() {
    print_header "1. Kernel Tuning"

    # Detect Docker — overcommit_memory=2 can cause Docker OOM kills
    local overcommit_val=2
    local overcommit_note="overcommit=2"
    if command -v docker &>/dev/null && systemctl is-active --quiet docker 2>/dev/null; then
        overcommit_val=0
        overcommit_note="overcommit=0 (Docker detected — mode 2 causes container OOM kills)"
        print_warning "Docker detected: using vm.overcommit_memory=0 instead of 2"
    fi

    cat > /etc/sysctl.d/99-postgresql.conf << EOF
# PostgreSQL kernel tuning — managed by pg-security

# Memory
vm.overcommit_memory = ${overcommit_val}
vm.swappiness = 1

# Dirty page flushing (optimized for DB write patterns)
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10

# NUMA
vm.zone_reclaim_mode = 0
EOF

    if ! sysctl -p /etc/sysctl.d/99-postgresql.conf >/dev/null 2>&1; then
        print_warning "Some sysctl parameters could not be applied (container or unsupported kernel?)"
    fi
    print_success "Sysctl tuned (${overcommit_note}, swappiness=1)"

    # Disable Transparent Huge Pages
    if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
        echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled
        echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true

        # Persist across reboots
        cat > /etc/systemd/system/disable-thp.service << 'EOF'
[Unit]
Description=Disable Transparent Huge Pages (PostgreSQL)
DefaultDependencies=no
After=sysinit.target local-fs.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled && echo never > /sys/kernel/mm/transparent_hugepage/defrag'

[Install]
WantedBy=basic.target
EOF
        systemctl daemon-reload
        systemctl enable disable-thp.service >/dev/null 2>&1
        print_success "Transparent Huge Pages disabled (persistent)"
    fi
}

################################################################################
# Resource Limits
################################################################################

setup_limits() {
    print_header "2. Resource Limits"

    cat > /etc/security/limits.d/99-postgresql.conf << 'EOF'
postgres soft nofile 65536
postgres hard nofile 65536
postgres soft nproc 65536
postgres hard nproc 65536
postgres soft memlock unlimited
postgres hard memlock unlimited
EOF

    # systemd override for the PostgreSQL service
    local pg_service="postgresql"
    if systemctl list-units --type=service --all 2>/dev/null | grep -q "postgresql@${PG_VERSION}-${PG_CLUSTER}"; then
        pg_service="postgresql@${PG_VERSION}-${PG_CLUSTER}"
    fi

    mkdir -p "/etc/systemd/system/${pg_service}.service.d"
    cat > "/etc/systemd/system/${pg_service}.service.d/limits.conf" << 'EOF'
[Service]
LimitNOFILE=65536
LimitNPROC=65536
LimitMEMLOCK=infinity
EOF

    systemctl daemon-reload
    print_success "Resource limits set (nofile=65536, memlock=unlimited)"
}

################################################################################
# SSL/TLS
################################################################################

setup_ssl() {
    print_header "3. SSL/TLS Certificates"

    local ssl_dir="$PG_DATA_DIR"
    local cert_file="${ssl_dir}/server.crt"
    local key_file="${ssl_dir}/server.key"

    if [ -f "$cert_file" ] && [ -f "$key_file" ]; then
        local expiry days_left
        expiry=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
        days_left=$(( ( $(date -d "$expiry" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
        print_status "Existing certificate expires: $expiry ($days_left days)"

        if [ "$days_left" -gt 90 ]; then
            if [ "$REAPPLY_MODE" = true ]; then
                print_status "Certificate valid — skipping regeneration"
                return 0
            fi
            read -rp "Certificate still valid. Regenerate? (y/n) " -n 1 < /dev/tty; echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then return 0; fi
        else
            print_warning "Certificate expires in $days_left days — regenerating"
        fi
    fi

    local fqdn
    fqdn=$(hostname -f)
    openssl req -new -x509 -days 825 -nodes \
        -newkey rsa:4096 \
        -keyout "$key_file" \
        -out "$cert_file" \
        -subj "/CN=${fqdn}/O=PostgreSQL/OU=Database" \
        -addext "subjectAltName=DNS:${fqdn},DNS:localhost,IP:127.0.0.1" \
        2>/dev/null

    chown postgres:postgres "$key_file" "$cert_file"
    chmod 600 "$key_file"
    chmod 644 "$cert_file"
    print_success "SSL certificate generated (RSA-4096, 825 days)"
}

################################################################################
# PostgreSQL Config Hardening
################################################################################

setup_pg_config() {
    print_header "4. PostgreSQL Config"

    if [ "$HA_TOOL" = "patroni" ]; then
        print_warning "Patroni manages postgresql.conf — printing settings to add to Patroni YAML:"
        echo ""
        cat << EOF
  postgresql:
    parameters:
      ssl: 'on'
      ssl_min_protocol_version: 'TLSv1.2'
      ssl_ciphers: 'HIGH:!aNULL:!MD5:!3DES:!RC4'
      password_encryption: 'scram-sha-256'
      authentication_timeout: '30s'
      log_connections: 'on'
      log_disconnections: 'on'
      log_statement: 'ddl'
      log_line_prefix: '%t [%p]: user=%u,db=%d,app=%a,client=%h '
      log_min_duration_statement: '1000'
      log_file_mode: '0600'
      shared_preload_libraries: 'pgaudit'
      pgaudit.log: 'ddl,role'
      pgaudit.log_catalog: 'off'
      wal_level: 'replica'
      row_security: 'on'
EOF
        echo ""
        print_warning "Copy the above into your Patroni YAML config."
        return
    fi

    # Detect existing shared_preload_libraries
    local current_libs=""
    if sudo -u postgres psql -tAc "SELECT 1;" &>/dev/null; then
        current_libs=$(sudo -u postgres psql -tAc "SHOW shared_preload_libraries;" 2>/dev/null || true)
    else
        current_libs=$(grep -E "^\s*shared_preload_libraries\s*=" "${PG_CONF_DIR}/postgresql.conf" 2>/dev/null \
            | tail -1 | sed "s/.*=\s*'\?\([^']*\)'\?.*/\1/" || true)
    fi

    # Preserve existing libs — pgaudit is added by setup_pgaudit after package install confirmed
    local new_libs="$current_libs"

    # Create conf.d include directory
    local conf_d="${PG_CONF_DIR}/conf.d"
    mkdir -p "$conf_d"

    # Ensure include_dir is enabled in main config
    if ! grep -qE "^\s*include_dir\s*=\s*'conf.d'" "${PG_CONF_DIR}/postgresql.conf" 2>/dev/null; then
        local pg_conf_backup="${PG_CONF_DIR}/postgresql.conf.backup-$(date +%Y%m%d-%H%M%S)"
        cp "${PG_CONF_DIR}/postgresql.conf" "$pg_conf_backup"
        print_status "Backed up postgresql.conf to $pg_conf_backup"

        # Uncomment if it exists commented out, otherwise append
        if grep -qE "^#\s*include_dir\s*=\s*'conf.d'" "${PG_CONF_DIR}/postgresql.conf" 2>/dev/null; then
            sed -i "s|^#\s*include_dir\s*=\s*'conf.d'|include_dir = 'conf.d'|" "${PG_CONF_DIR}/postgresql.conf"
        else
            echo "include_dir = 'conf.d'" >> "${PG_CONF_DIR}/postgresql.conf"
        fi
    fi

    # Determine wal_level line
    local wal_line=""
    if [ -n "$REPLICATION_PEERS" ]; then
        wal_line="wal_level = replica"
    fi

    cat > "${conf_d}/security.conf" << EOF
# PostgreSQL Security Hardening — managed by pg-security

# SSL/TLS
ssl = on
ssl_min_protocol_version = 'TLSv1.2'
ssl_ciphers = 'HIGH:!aNULL:!MD5:!3DES:!RC4'
ssl_cert_file = '${PG_DATA_DIR}/server.crt'
ssl_key_file = '${PG_DATA_DIR}/server.key'

# Authentication
password_encryption = 'scram-sha-256'
authentication_timeout = '30s'

# Connection
listen_addresses = '${PG_LISTEN}'
port = ${PG_PORT}

# Logging
log_connections = on
log_disconnections = on
log_statement = 'ddl'
log_line_prefix = '%t [%p]: user=%u,db=%d,app=%a,client=%h '
log_min_duration_statement = 1000
log_destination = 'stderr'
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d.log'
log_file_mode = 0600
log_rotation_age = 1d
log_rotation_size = 100MB

# Audit
shared_preload_libraries = '${new_libs}'

# Security
row_security = on
${wal_line}
EOF

    chown postgres:postgres "${conf_d}/security.conf"
    chmod 600 "${conf_d}/security.conf"
    print_success "postgresql.conf hardened via ${conf_d}/security.conf"
}

################################################################################
# Performance Tuning (RAM/CPU-aware)
#
# Based on official PostgreSQL documentation:
#   https://www.postgresql.org/docs/current/runtime-config-resource.html
#   https://www.postgresql.org/docs/current/runtime-config-wal.html
#   https://www.postgresql.org/docs/current/runtime-config-query.html
################################################################################

setup_performance() {
    print_header "4b. Performance Tuning (system-aware)"

    if [ "$TOTAL_RAM_MB" -eq 0 ] || [ "$TOTAL_RAM_MB" -lt 256 ]; then
        print_warning "Could not detect RAM or RAM < 256MB — skipping performance tuning"
        return
    fi

    # --- shared_buffers: 25% of RAM (official doc recommendation for >= 1GB) ---
    # For < 1GB, use 15% to leave room for OS
    local shared_buffers_mb
    if [ "$TOTAL_RAM_MB" -ge 1024 ]; then
        shared_buffers_mb=$(( TOTAL_RAM_MB / 4 ))
    else
        shared_buffers_mb=$(( TOTAL_RAM_MB * 15 / 100 ))
    fi
    # Cap at 40% of RAM per doc guidance
    local max_shared=$(( TOTAL_RAM_MB * 40 / 100 ))
    if [ "$shared_buffers_mb" -gt "$max_shared" ]; then shared_buffers_mb=$max_shared; fi

    # --- effective_cache_size: 75% of RAM ---
    # Represents shared_buffers + OS page cache available to PG
    local effective_cache_mb=$(( TOTAL_RAM_MB * 75 / 100 ))

    # --- maintenance_work_mem: RAM/16, capped at 2GB ---
    local maint_work_mem_mb=$(( TOTAL_RAM_MB / 16 ))
    if [ "$maint_work_mem_mb" -lt 64 ]; then maint_work_mem_mb=64; fi
    if [ "$maint_work_mem_mb" -gt 2048 ]; then maint_work_mem_mb=2048; fi

    # --- work_mem: conservative — RAM / 32 / max_parallel_workers ---
    # The doc warns this is per-operation per-session, so keep it conservative
    local work_mem_mb=$(( TOTAL_RAM_MB / 32 ))
    if [ "$work_mem_mb" -lt 4 ]; then work_mem_mb=4; fi
    if [ "$work_mem_mb" -gt 256 ]; then work_mem_mb=256; fi

    # --- huge_pages: 'try' when >= 2GB RAM (doc: reduces page table overhead) ---
    local huge_pages="off"
    if [ "$TOTAL_RAM_MB" -ge 2048 ]; then huge_pages="try"; fi

    # --- wal_buffers: -1 lets PG auto-tune to 1/32 of shared_buffers (doc default) ---
    local wal_buffers="-1"

    # --- max_wal_size / min_wal_size: scale with RAM ---
    local max_wal_size_mb=1024
    local min_wal_size_mb=80
    if [ "$TOTAL_RAM_GB" -ge 8 ]; then
        max_wal_size_mb=2048
        min_wal_size_mb=512
    elif [ "$TOTAL_RAM_GB" -ge 4 ]; then
        max_wal_size_mb=1536
        min_wal_size_mb=256
    fi

    # --- Worker processes: scale with CPU cores ---
    # max_worker_processes: doc default 8, set to CPU cores (min 8)
    local max_workers=$CPU_CORES
    if [ "$max_workers" -lt 8 ]; then max_workers=8; fi

    # max_parallel_workers: doc says cannot exceed max_worker_processes
    local max_parallel=$CPU_CORES
    if [ "$max_parallel" -gt "$max_workers" ]; then max_parallel=$max_workers; fi

    # max_parallel_workers_per_gather: doc default 2, scale to CPU/2 capped at 4
    local parallel_per_gather=$(( CPU_CORES / 2 ))
    if [ "$parallel_per_gather" -lt 2 ]; then parallel_per_gather=2; fi
    if [ "$parallel_per_gather" -gt 4 ]; then parallel_per_gather=4; fi

    # max_parallel_maintenance_workers: doc default 2, scale to CPU/2 capped at 4
    local parallel_maint=$(( CPU_CORES / 2 ))
    if [ "$parallel_maint" -lt 2 ]; then parallel_maint=2; fi
    if [ "$parallel_maint" -gt 4 ]; then parallel_maint=4; fi

    # --- I/O settings based on storage type ---
    # Doc: effective_io_concurrency default 16; higher for SSDs
    # Doc: random_page_cost default 4.0; lower for SSDs (data likely cached)
    local effective_io_concurrency=2
    local random_page_cost="4.0"
    if [ "$STORAGE_IS_SSD" = true ]; then
        effective_io_concurrency=200
        random_page_cost="1.1"
    fi

    # --- Write performance config ---
    if [ "$HA_TOOL" = "patroni" ]; then
        print_warning "Patroni manages postgresql.conf — printing performance settings for Patroni YAML:"
        echo ""
        cat << EOF
  postgresql:
    parameters:
      # Memory (${TOTAL_RAM_MB}MB RAM detected)
      shared_buffers: '${shared_buffers_mb}MB'
      effective_cache_size: '${effective_cache_mb}MB'
      work_mem: '${work_mem_mb}MB'
      maintenance_work_mem: '${maint_work_mem_mb}MB'
      huge_pages: '${huge_pages}'
      # WAL
      wal_buffers: '${wal_buffers}'
      max_wal_size: '${max_wal_size_mb}MB'
      min_wal_size: '${min_wal_size_mb}MB'
      checkpoint_completion_target: '0.9'
      # Workers (${CPU_CORES} CPU cores detected)
      max_worker_processes: '${max_workers}'
      max_parallel_workers: '${max_parallel}'
      max_parallel_workers_per_gather: '${parallel_per_gather}'
      max_parallel_maintenance_workers: '${parallel_maint}'
      # I/O ($([ "$STORAGE_IS_SSD" = true ] && echo 'SSD' || echo 'HDD') detected)
      effective_io_concurrency: '${effective_io_concurrency}'
      random_page_cost: '${random_page_cost}'
EOF
        echo ""
        print_warning "Copy the above into your Patroni YAML config."
        return
    fi

    local conf_d="${PG_CONF_DIR}/conf.d"
    mkdir -p "$conf_d"

    cat > "${conf_d}/performance.conf" << EOF
# PostgreSQL Performance Tuning — managed by pg-security
# Auto-detected: ${TOTAL_RAM_MB}MB RAM, ${CPU_CORES} CPU cores, $([ "$STORAGE_IS_SSD" = true ] && echo 'SSD' || echo 'HDD')
#
# Based on official PostgreSQL documentation:
#   https://www.postgresql.org/docs/current/runtime-config-resource.html
#   https://www.postgresql.org/docs/current/runtime-config-wal.html
#   https://www.postgresql.org/docs/current/runtime-config-query.html

# Memory — shared_buffers = 25% of RAM (doc: recommended for systems >= 1GB)
shared_buffers = '${shared_buffers_mb}MB'

# effective_cache_size — 75% of RAM (planner hint, not allocation)
effective_cache_size = '${effective_cache_mb}MB'

# work_mem — per-operation sort/hash memory (doc: keep conservative, multiplied by concurrent ops)
work_mem = '${work_mem_mb}MB'

# maintenance_work_mem — VACUUM, CREATE INDEX (doc: set higher than work_mem)
maintenance_work_mem = '${maint_work_mem_mb}MB'

# huge_pages — reduces page table overhead (doc: beneficial for large shared_buffers)
huge_pages = '${huge_pages}'

# WAL — wal_buffers auto-tunes to 1/32 of shared_buffers (doc default)
wal_buffers = ${wal_buffers}
max_wal_size = '${max_wal_size_mb}MB'
min_wal_size = '${min_wal_size_mb}MB'
checkpoint_completion_target = 0.9

# Worker processes — scaled to CPU cores
max_worker_processes = ${max_workers}
max_parallel_workers = ${max_parallel}
max_parallel_workers_per_gather = ${parallel_per_gather}
max_parallel_maintenance_workers = ${parallel_maint}

# I/O — tuned for $([ "$STORAGE_IS_SSD" = true ] && echo 'SSD' || echo 'HDD')
effective_io_concurrency = ${effective_io_concurrency}
random_page_cost = ${random_page_cost}
EOF

    chown postgres:postgres "${conf_d}/performance.conf"
    chmod 600 "${conf_d}/performance.conf"

    echo ""
    echo "  shared_buffers:        ${shared_buffers_mb}MB (25% of ${TOTAL_RAM_MB}MB)"
    echo "  effective_cache_size:  ${effective_cache_mb}MB (75% of RAM)"
    echo "  work_mem:              ${work_mem_mb}MB"
    echo "  maintenance_work_mem:  ${maint_work_mem_mb}MB"
    echo "  huge_pages:            ${huge_pages}"
    echo "  wal_buffers:           auto (1/32 of shared_buffers)"
    echo "  max_wal_size:          ${max_wal_size_mb}MB"
    echo "  max_workers:           ${max_workers} (${CPU_CORES} cores)"
    echo "  parallel_per_gather:   ${parallel_per_gather}"
    echo "  effective_io_concurrency: ${effective_io_concurrency} ($([ "$STORAGE_IS_SSD" = true ] && echo 'SSD' || echo 'HDD'))"
    echo "  random_page_cost:      ${random_page_cost}"
    echo ""
    print_success "Performance config written to ${conf_d}/performance.conf"
}

################################################################################
# pg_hba.conf Hardening
################################################################################

setup_pg_hba() {
    print_header "5. pg_hba.conf"

    if [ "$HA_TOOL" = "patroni" ]; then
        print_warning "Patroni manages pg_hba.conf — printing entries to add to Patroni YAML:"
        echo ""
        echo "  postgresql:"
        echo "    pg_hba:"
        echo "      - local   all  postgres                peer"
        echo "      - local   all  all                     scram-sha-256"
        echo "      - host    all  all  127.0.0.1/32       scram-sha-256"
        echo "      - host    all  all  ::1/128            scram-sha-256"
        for subnet in $ALLOWED_SUBNETS; do
            echo "      - hostssl all  all  ${subnet}  scram-sha-256"
        done
        for peer in $REPLICATION_PEERS; do
            echo "      - hostssl replication  all  ${peer}  scram-sha-256"
        done
        echo ""
        return
    fi

    local hba="${PG_CONF_DIR}/pg_hba.conf"
    local backup="${hba}.backup-$(date +%Y%m%d-%H%M%S)"
    cp "$hba" "$backup"
    print_status "Backed up pg_hba.conf to $backup"

    # Check for insecure entries in original
    local insecure_count=0
    if grep -qE '^\s*(host|hostssl|hostnossl).*\btrust\b' "$backup" 2>/dev/null; then
        insecure_count=$((insecure_count + $(grep -cE '^\s*(host|hostssl|hostnossl).*\btrust\b' "$backup")))
        print_warning "Found 'trust' auth entries — these will be removed"
    fi
    if grep -qE '^\s*(host|hostssl|hostnossl).*\bmd5\b' "$backup" 2>/dev/null; then
        insecure_count=$((insecure_count + $(grep -cE '^\s*(host|hostssl|hostnossl).*\bmd5\b' "$backup")))
        print_warning "Found 'md5' auth entries — upgrading to scram-sha-256"
    fi
    if [ "$insecure_count" -gt 0 ]; then print_warning "Replacing $insecure_count insecure entries"; fi

    cat > "$hba" << 'EOF'
# PostgreSQL Client Authentication — managed by pg-security
#
# TYPE  DATABASE  USER      ADDRESS         METHOD

# Local socket connections (peer = OS user must match PG user)
local   all       postgres                  peer
local   all       all                       scram-sha-256

# Loopback
host    all       all       127.0.0.1/32    scram-sha-256
host    all       all       ::1/128         scram-sha-256
EOF

    if [ -n "$ALLOWED_SUBNETS" ]; then
        echo "" >> "$hba"
        echo "# Allowed client networks (SSL required)" >> "$hba"
        for subnet in $ALLOWED_SUBNETS; do
            printf "hostssl %-13s %-9s %-19s %s\n" "all" "all" "$subnet" "scram-sha-256" >> "$hba"
        done
    fi

    if [ -n "$REPLICATION_PEERS" ]; then
        echo "" >> "$hba"
        echo "# Replication peers — HA (SSL required)" >> "$hba"
        for peer in $REPLICATION_PEERS; do
            # Append /32 if no CIDR given
            local peer_cidr="$peer"
            if [[ "$peer" != */* ]]; then peer_cidr="${peer}/32"; fi
            printf "hostssl %-13s %-9s %-19s %s\n" "replication" "all" "$peer_cidr" "scram-sha-256" >> "$hba"
        done
    fi

    chown postgres:postgres "$hba"
    chmod 600 "$hba"
    print_success "pg_hba.conf hardened (scram-sha-256, SSL for remote)"
}

################################################################################
# pgaudit
################################################################################

setup_pgaudit() {
    print_header "6. pgaudit Extension"

    local pgaudit_pkg="postgresql-${PG_VERSION}-pgaudit"
    if dpkg -l "$pgaudit_pkg" 2>/dev/null | grep -q '^ii'; then
        print_status "pgaudit already installed"
    else
        print_status "Installing $pgaudit_pkg..."
        if apt-get install -y "$pgaudit_pkg" -qq 2>/dev/null; then
            print_success "pgaudit installed"
        else
            print_warning "pgaudit package not found — skipping"
            print_warning "Install manually: apt install $pgaudit_pkg"
            return
        fi
    fi

    # Add pgaudit to shared_preload_libraries only after package confirmed installed
    if [ "$HA_TOOL" != "patroni" ]; then
        local conf_d="${PG_CONF_DIR}/conf.d"
        if [ -f "${conf_d}/security.conf" ]; then
            if ! grep -qE "^shared_preload_libraries.*pgaudit" "${conf_d}/security.conf" 2>/dev/null; then
                local current_spl
                current_spl=$(sed -n "s/^shared_preload_libraries = '\(.*\)'/\1/p" "${conf_d}/security.conf")
                local new_spl
                [ -n "$current_spl" ] && new_spl="${current_spl}, pgaudit" || new_spl="pgaudit"
                sed -i "s|^shared_preload_libraries = .*|shared_preload_libraries = '${new_spl}'|" "${conf_d}/security.conf"
                print_status "Added pgaudit to shared_preload_libraries"
            fi

            if ! grep -q "pgaudit.log" "${conf_d}/security.conf" 2>/dev/null; then
                cat >> "${conf_d}/security.conf" << 'EOF'

# pgaudit settings
pgaudit.log = 'ddl,role'
pgaudit.log_catalog = off
pgaudit.log_client = off
pgaudit.log_level = 'log'
EOF
            fi
        fi
    fi

    print_success "pgaudit configured (extension enabled after restart)"
}

################################################################################
# fail2ban for PostgreSQL
################################################################################

setup_fail2ban_pg() {
    print_header "7. fail2ban (PostgreSQL)"

    if ! command -v fail2ban-client &>/dev/null; then
        print_status "Installing fail2ban..."
        if ! apt-get install -y fail2ban -qq 2>/dev/null; then
            print_warning "Failed to install fail2ban — skipping jail setup"
            return
        fi
    fi

    # Custom filter matching the log_line_prefix we set
    cat > /etc/fail2ban/filter.d/postgresql.conf << 'EOF'
[Definition]
# Matches log_line_prefix = '%t [%p]: user=%u,db=%d,app=%a,client=%h '
failregex = client=<HOST>\s+FATAL:\s+password authentication failed for user
            client=<HOST>\s+FATAL:\s+no pg_hba\.conf entry for host
            client=<HOST>\s+FATAL:\s+pg_hba\.conf rejects connection for host
ignoreregex =
EOF

    local pg_log_dir="${PG_DATA_DIR}/log"

    # Use jail.d drop-in so the PG jail survives vm-security.sh re-runs (which overwrites jail.local)
    mkdir -p /etc/fail2ban/jail.d
    cat > /etc/fail2ban/jail.d/postgresql.conf << EOF
[postgresql]
enabled = true
filter = postgresql
port = $PG_PORT
logpath = ${pg_log_dir}/postgresql-*.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

    # Clean up legacy entry from jail.local if present
    if grep -q '^\[postgresql\]' /etc/fail2ban/jail.local 2>/dev/null; then
        sed -i '/^\[postgresql\]/,/^$/d' /etc/fail2ban/jail.local
        print_status "Migrated PostgreSQL jail from jail.local to jail.d/postgresql.conf"
    fi

    systemctl restart fail2ban
    print_success "fail2ban jail active for PostgreSQL (port $PG_PORT)"
}

################################################################################
# UFW for PostgreSQL
################################################################################

setup_ufw_pg() {
    print_header "8. UFW Rules"

    if ! command -v ufw &>/dev/null; then
        print_warning "UFW not installed — skipping (install via vm-security.sh)"
        return
    fi

    # Remove stale PG port rules before adding current ones
    local stale_rules
    stale_rules=$(ufw status numbered 2>/dev/null | grep -E "\s${PG_PORT}/tcp\s" | sed -n 's/^\[\s*\([0-9]*\)\].*/\1/p' | sort -rn || true)
    if [ -n "$stale_rules" ]; then
        print_status "Cleaning existing UFW rules for port $PG_PORT..."
        for rule_num in $stale_rules; do
            yes | ufw delete "$rule_num" >/dev/null 2>&1 || true
        done
    fi

    local rules_added=0

    if [ -n "$ALLOWED_SUBNETS" ]; then
        for subnet in $ALLOWED_SUBNETS; do
            ufw allow from "$subnet" to any port "$PG_PORT" proto tcp >/dev/null
            print_status "Allowed $subnet -> port $PG_PORT"
            rules_added=$((rules_added + 1))
        done
    fi

    if [ -n "$REPLICATION_PEERS" ]; then
        for peer in $REPLICATION_PEERS; do
            local peer_cidr="$peer"
            if [[ "$peer" != */* ]]; then peer_cidr="${peer}/32"; fi
            ufw allow from "$peer_cidr" to any port "$PG_PORT" proto tcp >/dev/null
            print_status "Allowed replication peer $peer_cidr -> port $PG_PORT"
            rules_added=$((rules_added + 1))
        done
    fi

    if [ "$rules_added" -eq 0 ]; then
        print_status "No remote subnets configured — PostgreSQL port not opened in UFW"
    else
        ufw reload >/dev/null 2>&1 || print_warning "UFW reload failed"
        print_success "UFW: $rules_added rules added for port $PG_PORT"
    fi
}

################################################################################
# File Permissions
################################################################################

setup_permissions() {
    print_header "9. File Permissions"

    chmod 700 "$PG_DATA_DIR"
    chown postgres:postgres "$PG_DATA_DIR"

    if [ -d "$PG_CONF_DIR" ]; then
        chmod 700 "$PG_CONF_DIR"
        chown postgres:postgres "$PG_CONF_DIR"
        find "$PG_CONF_DIR" -name "*.conf" -exec chmod 600 {} \;
        find "$PG_CONF_DIR" -name "*.conf" -exec chown postgres:postgres {} \;
    fi

    local log_dir="${PG_DATA_DIR}/log"
    if [ -d "$log_dir" ]; then
        chmod 700 "$log_dir"
        chown postgres:postgres "$log_dir"
    fi

    print_success "Permissions locked down (data=700, configs=600)"
}

################################################################################
# Apply Hardening
################################################################################

apply_hardening() {
    LOG_FILE="/root/pg-security-$(date +%Y%m%d-%H%M%S).log"
    trap 'print_error "Failed at line $LINENO"; trap - ERR; exit 1' ERR

    setup_kernel
    setup_limits
    setup_ssl
    setup_pg_config
    setup_performance
    setup_pg_hba
    setup_pgaudit
    setup_fail2ban_pg
    setup_ufw_pg
    setup_permissions

    # Reload PostgreSQL
    print_header "10. Reload PostgreSQL"
    local pg_service="postgresql"
    if systemctl list-units --type=service --all 2>/dev/null | grep -q "postgresql@${PG_VERSION}-${PG_CLUSTER}"; then
        pg_service="postgresql@${PG_VERSION}-${PG_CLUSTER}"
    fi

    if [ "$HA_TOOL" = "patroni" ]; then
        print_warning "Patroni manages PostgreSQL — reload via: patronictl reload <cluster>"
        print_warning "Only OS-level hardening was applied (kernel, SSL certs, fail2ban, UFW, permissions)"
    else
        print_status "Restarting PostgreSQL (required for shared_preload_libraries)..."
        if systemctl restart "$pg_service" 2>/dev/null; then
            sleep 2
            if sudo -u postgres pg_isready -p "$PG_PORT" >/dev/null 2>&1; then
                print_success "PostgreSQL restarted and accepting connections"

                # Enable pgaudit extension in all databases
                local pgaudit_pkg="postgresql-${PG_VERSION}-pgaudit"
                if dpkg -l "$pgaudit_pkg" 2>/dev/null | grep -q '^ii'; then
                    local db
                    for db in $(sudo -u postgres psql -tAc "SELECT datname FROM pg_database WHERE datistemplate = false AND datallowconn = true;" 2>/dev/null); do
                        sudo -u postgres psql -d "$db" -c "CREATE EXTENSION IF NOT EXISTS pgaudit;" 2>/dev/null || true
                    done
                    print_success "pgaudit extension enabled in all databases"
                fi
            else
                print_error "PostgreSQL restarted but not accepting connections!"
                print_error "Check: journalctl -u $pg_service --no-pager -n 30"
                print_warning "Restore backup: cp ${PG_CONF_DIR}/pg_hba.conf.backup-* ${PG_CONF_DIR}/pg_hba.conf"
            fi
        else
            print_error "Failed to restart PostgreSQL"
            print_error "Check: journalctl -u $pg_service --no-pager -n 30"
        fi
    fi

    # Summary
    print_header "Setup Complete"
    echo ""
    echo "Applied:"
    echo "  Kernel tuning     — swappiness=1, THP disabled, overcommit tuned"
    echo "  Resource limits   — nofile=65536, memlock=unlimited"
    echo "  SSL/TLS           — RSA-4096, TLSv1.2 minimum"
    echo "  postgresql.conf   — scram-sha-256, logging, audit"
    echo "  Performance       — tuned for ${TOTAL_RAM_MB}MB RAM, ${CPU_CORES} CPUs"
    echo "  pg_hba.conf       — SSL-only remote, no trust/md5"
    echo "  pgaudit           — DDL + role change logging"
    echo "  fail2ban          — PostgreSQL auth failure jail"
    echo "  UFW               — port $PG_PORT restricted to allowed subnets"
    echo "  Permissions       — data dir 700, config files 600"
    echo ""
    echo "Files:"
    echo "  Setup log:        $LOG_FILE"
    if [ "$HA_TOOL" != "patroni" ]; then
        echo "  PG security conf: ${PG_CONF_DIR}/conf.d/security.conf"
        echo "  PG perf conf:     ${PG_CONF_DIR}/conf.d/performance.conf"
        echo "  pg_hba.conf:      ${PG_CONF_DIR}/pg_hba.conf"
    fi
    echo "  Kernel tuning:    /etc/sysctl.d/99-postgresql.conf"
    echo "  Resource limits:  /etc/security/limits.d/99-postgresql.conf"
    echo "  fail2ban filter:  /etc/fail2ban/filter.d/postgresql.conf"
    echo ""

    print_success "Done."
    trap - ERR
}

################################################################################
# Status
################################################################################

show_status() {
    if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
        print_warning "Running without root — some checks may be incomplete (use sudo for full status)"
    fi

    echo ""
    echo -e "${CYAN}PostgreSQL Security Status — $(date +'%Y-%m-%d %H:%M:%S')${NC}"
    echo ""

    detect_pg 2>/dev/null || { print_error "PostgreSQL not detected (is it running? do you have sudo access?)"; exit 1; }
    detect_ha

    print_success "PostgreSQL $PG_VERSION (cluster: $PG_CLUSTER, port: $PG_PORT)"
    if [ -n "$HA_TOOL" ]; then print_status "HA tool: $HA_TOOL"; fi
    echo ""

    local SCORE=100
    local svc_fmt="  %-36s %s\n"

    # PostgreSQL running
    print_header "Service"
    if sudo -u postgres pg_isready -p "$PG_PORT" >/dev/null 2>&1; then
        printf "$svc_fmt" "PostgreSQL:" "$(echo -e "${GREEN}RUNNING${NC}")"
    else
        printf "$svc_fmt" "PostgreSQL:" "$(echo -e "${RED}DOWN${NC}")"
        SCORE=$((SCORE - 25))
    fi

    # SSL
    print_header "SSL/TLS"
    local ssl_on
    ssl_on=$(sudo -u postgres psql -tAc "SHOW ssl;" 2>/dev/null || echo "unknown")
    if [ "$ssl_on" = "on" ]; then
        printf "$svc_fmt" "SSL:" "$(echo -e "${GREEN}ON${NC}")"
        local cert_file="${PG_DATA_DIR}/server.crt"
        if [ -f "$cert_file" ]; then
            local expiry days_left
            expiry=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
            days_left=$(( ( $(date -d "$expiry" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
            if [ "$days_left" -lt 30 ]; then
                printf "$svc_fmt" "Certificate:" "$(echo -e "${RED}EXPIRES IN $days_left DAYS${NC}")"
                SCORE=$((SCORE - 10))
            elif [ "$days_left" -lt 90 ]; then
                printf "$svc_fmt" "Certificate:" "$(echo -e "${YELLOW}expires in $days_left days${NC}")"
            else
                printf "$svc_fmt" "Certificate:" "$(echo -e "${GREEN}valid ($days_left days)${NC}")"
            fi
        fi
    else
        printf "$svc_fmt" "SSL:" "$(echo -e "${RED}OFF${NC}")"
        SCORE=$((SCORE - 20))
    fi

    # Authentication
    print_header "Authentication"
    local pw_enc
    pw_enc=$(sudo -u postgres psql -tAc "SHOW password_encryption;" 2>/dev/null || echo "unknown")
    if [ "$pw_enc" = "scram-sha-256" ]; then
        printf "$svc_fmt" "Password encryption:" "$(echo -e "${GREEN}scram-sha-256${NC}")"
    elif [ "$pw_enc" = "md5" ]; then
        printf "$svc_fmt" "Password encryption:" "$(echo -e "${RED}md5 (weak)${NC}")"
        SCORE=$((SCORE - 15))
    else
        printf "$svc_fmt" "Password encryption:" "$pw_enc"
    fi

    # Check pg_hba.conf for insecure entries
    local hba="${PG_CONF_DIR}/pg_hba.conf"
    if [ -f "$hba" ]; then
        local trust_count md5_count hostnossl_count
        trust_count=$(grep -cE '^\s*(host|hostssl|hostnossl)\s.*\btrust\b' "$hba" 2>/dev/null || echo 0)
        md5_count=$(grep -cE '^\s*(host|hostssl|hostnossl)\s.*\bmd5\b' "$hba" 2>/dev/null || echo 0)
        hostnossl_count=$(grep -cE '^\s*hostnossl\s' "$hba" 2>/dev/null || echo 0)

        if [ "$trust_count" -gt 0 ]; then
            printf "$svc_fmt" "pg_hba.conf 'trust' entries:" "$(echo -e "${RED}$trust_count FOUND${NC}")"
            SCORE=$((SCORE - 20))
        else
            printf "$svc_fmt" "pg_hba.conf 'trust' entries:" "$(echo -e "${GREEN}none${NC}")"
        fi
        if [ "$md5_count" -gt 0 ]; then
            printf "$svc_fmt" "pg_hba.conf 'md5' entries:" "$(echo -e "${YELLOW}$md5_count (upgrade to scram)${NC}")"
            SCORE=$((SCORE - 5))
        fi
        if [ "$hostnossl_count" -gt 0 ]; then
            printf "$svc_fmt" "pg_hba.conf unencrypted entries:" "$(echo -e "${YELLOW}$hostnossl_count${NC}")"
            SCORE=$((SCORE - 5))
        fi
    fi

    # Kernel tuning
    print_header "Kernel"
    local overcommit swappiness
    overcommit=$(sysctl -n vm.overcommit_memory 2>/dev/null || echo "unknown")
    swappiness=$(sysctl -n vm.swappiness 2>/dev/null || echo "unknown")

    local docker_running=false
    command -v docker &>/dev/null && systemctl is-active --quiet docker 2>/dev/null && docker_running=true

    if [ "$overcommit" = "2" ]; then
        if [ "$docker_running" = true ]; then
            printf "$svc_fmt" "vm.overcommit_memory:" "$(echo -e "${YELLOW}2 (may cause Docker OOM — consider 0)${NC}")"
        else
            printf "$svc_fmt" "vm.overcommit_memory:" "$(echo -e "${GREEN}2 (safe for PG)${NC}")"
        fi
    elif [ "$overcommit" = "0" ] && [ "$docker_running" = true ]; then
        printf "$svc_fmt" "vm.overcommit_memory:" "$(echo -e "${GREEN}0 (Docker-safe default)${NC}")"
    else
        printf "$svc_fmt" "vm.overcommit_memory:" "$(echo -e "${RED}$overcommit (should be 2, or 0 with Docker)${NC}")"
        SCORE=$((SCORE - 10))
    fi
    if [ "$swappiness" -le 1 ] 2>/dev/null; then
        printf "$svc_fmt" "vm.swappiness:" "$(echo -e "${GREEN}$swappiness${NC}")"
    else
        printf "$svc_fmt" "vm.swappiness:" "$(echo -e "${YELLOW}$swappiness (should be 0-1)${NC}")"
        SCORE=$((SCORE - 5))
    fi

    local thp="unknown"
    if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then thp=$(sed -n 's/.*\[\([^]]*\)\].*/\1/p' /sys/kernel/mm/transparent_hugepage/enabled); fi
    if [ "$thp" = "never" ]; then
        printf "$svc_fmt" "Transparent Huge Pages:" "$(echo -e "${GREEN}disabled${NC}")"
    else
        printf "$svc_fmt" "Transparent Huge Pages:" "$(echo -e "${RED}$thp (should be never)${NC}")"
        SCORE=$((SCORE - 5))
    fi

    # Performance tuning
    print_header "Performance Tuning"
    if ! detect_system 2>/dev/null; then
        print_warning "Could not detect system resources — skipping performance section"
        printf "$svc_fmt" "Performance tuning:" "$(echo -e "${YELLOW}detection failed${NC}")"
    else

    local shared_buf shared_buf_bytes
    shared_buf=$(sudo -u postgres psql -tAc "SHOW shared_buffers;" 2>/dev/null || echo "unknown")
    # Get the actual value in bytes via pg_settings — avoids parsing human-readable strings
    shared_buf_bytes=$(sudo -u postgres psql -tAc "SELECT setting::bigint * CASE unit WHEN '8kB' THEN 8192 WHEN 'kB' THEN 1024 WHEN 'MB' THEN 1048576 ELSE 1 END FROM pg_settings WHERE name = 'shared_buffers';" 2>/dev/null || echo "")
    if [ -n "$shared_buf_bytes" ] && [ "$TOTAL_RAM_MB" -gt 0 ]; then
        local sb_mb=$(( shared_buf_bytes / 1024 / 1024 ))
        local recommended_sb=$(( TOTAL_RAM_MB / 4 ))
        local sb_pct=$(( sb_mb * 100 / TOTAL_RAM_MB ))
        if [ "$sb_pct" -ge 15 ] && [ "$sb_pct" -le 45 ]; then
            printf "$svc_fmt" "shared_buffers (${shared_buf}):" "$(echo -e "${GREEN}${sb_pct}% of RAM${NC}")"
        elif [ "$sb_pct" -lt 15 ]; then
            printf "$svc_fmt" "shared_buffers (${shared_buf}):" "$(echo -e "${YELLOW}${sb_pct}% of RAM — recommend ~25% (${recommended_sb}MB)${NC}")"
            SCORE=$((SCORE - 5))
        else
            printf "$svc_fmt" "shared_buffers (${shared_buf}):" "$(echo -e "${YELLOW}${sb_pct}% of RAM — high, recommend ≤40%${NC}")"
        fi
    else
        printf "$svc_fmt" "shared_buffers:" "$shared_buf"
    fi

    local eff_cache
    eff_cache=$(sudo -u postgres psql -tAc "SHOW effective_cache_size;" 2>/dev/null || echo "unknown")
    printf "$svc_fmt" "effective_cache_size:" "$eff_cache"

    local wm
    wm=$(sudo -u postgres psql -tAc "SHOW work_mem;" 2>/dev/null || echo "unknown")
    printf "$svc_fmt" "work_mem:" "$wm"

    local mwm
    mwm=$(sudo -u postgres psql -tAc "SHOW maintenance_work_mem;" 2>/dev/null || echo "unknown")
    printf "$svc_fmt" "maintenance_work_mem:" "$mwm"

    local max_pw
    max_pw=$(sudo -u postgres psql -tAc "SHOW max_parallel_workers;" 2>/dev/null || echo "unknown")
    printf "$svc_fmt" "max_parallel_workers:" "${max_pw} (${CPU_CORES} cores)"

    if [ -f "${PG_CONF_DIR}/conf.d/performance.conf" ]; then
        printf "$svc_fmt" "Performance config:" "$(echo -e "${GREEN}managed by pg-security${NC}")"
    else
        printf "$svc_fmt" "Performance config:" "$(echo -e "${YELLOW}not managed — run setup to auto-tune${NC}")"
    fi

    fi  # end detect_system guard

    # pgaudit
    print_header "Audit"
    local pgaudit_loaded
    pgaudit_loaded=$(sudo -u postgres psql -tAc "SHOW shared_preload_libraries;" 2>/dev/null || echo "")
    if echo "$pgaudit_loaded" | grep -q "pgaudit"; then
        printf "$svc_fmt" "pgaudit:" "$(echo -e "${GREEN}loaded${NC}")"
    else
        printf "$svc_fmt" "pgaudit:" "$(echo -e "${YELLOW}not loaded${NC}")"
        SCORE=$((SCORE - 5))
    fi

    # fail2ban
    print_header "Intrusion Prevention"
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        if fail2ban-client status postgresql &>/dev/null; then
            local pg_banned
            pg_banned=$(fail2ban-client status postgresql 2>/dev/null | grep "Currently banned" | awk '{print $4}')
            printf "$svc_fmt" "fail2ban PostgreSQL jail:" "$(echo -e "${GREEN}ACTIVE${NC}") (banned: ${pg_banned:-0})"
        else
            printf "$svc_fmt" "fail2ban PostgreSQL jail:" "$(echo -e "${RED}NOT CONFIGURED${NC}")"
            SCORE=$((SCORE - 10))
        fi
    else
        printf "$svc_fmt" "fail2ban:" "$(echo -e "${RED}NOT RUNNING${NC}")"
        SCORE=$((SCORE - 10))
    fi

    # Permissions
    print_header "Permissions"
    local data_perms
    data_perms=$(stat -c '%a' "$PG_DATA_DIR" 2>/dev/null || stat -f '%Lp' "$PG_DATA_DIR" 2>/dev/null || echo "unknown")
    if [ "$data_perms" = "700" ]; then
        printf "$svc_fmt" "Data directory ($data_perms):" "$(echo -e "${GREEN}OK${NC}")"
    else
        printf "$svc_fmt" "Data directory ($data_perms):" "$(echo -e "${RED}should be 700${NC}")"
        SCORE=$((SCORE - 10))
    fi

    # Score
    print_header "Health Score"
    if [ "$SCORE" -lt 0 ]; then SCORE=0; fi
    if [ $SCORE -ge 90 ]; then
        echo -e "  ${GREEN}${SCORE}/100 — Excellent${NC}"
    elif [ $SCORE -ge 70 ]; then
        echo -e "  ${YELLOW}${SCORE}/100 — Good${NC}"
    else
        echo -e "  ${RED}${SCORE}/100 — Needs attention${NC}"
    fi
    echo ""
}

################################################################################
# Reapply (non-interactive)
################################################################################

run_reapply() {
    check_root
    REAPPLY_MODE=true

    if command -v docker &>/dev/null; then
        print_warning "Docker detected — Docker and PostgreSQL on the same VM is not recommended."
    fi

    detect_pg
    detect_ha
    detect_system

    # Recover config from last run
    if [ -f "${PG_CONF_DIR}/conf.d/security.conf" ]; then
        PG_LISTEN=$(grep -E "^listen_addresses" "${PG_CONF_DIR}/conf.d/security.conf" 2>/dev/null \
            | sed "s/.*=\s*'\([^']*\)'.*/\1/" || echo "localhost")
    fi

    # Recover allowed subnets from pg_hba.conf
    if [ -f "${PG_CONF_DIR}/pg_hba.conf" ]; then
        ALLOWED_SUBNETS=$(grep -E "^hostssl\s+all\s+all\s+" "${PG_CONF_DIR}/pg_hba.conf" 2>/dev/null \
            | awk '{print $4}' | tr '\n' ' ' || true)
        REPLICATION_PEERS=$(grep -E "^hostssl\s+replication\s+" "${PG_CONF_DIR}/pg_hba.conf" 2>/dev/null \
            | awk '{print $4}' | tr '\n' ' ' || true)
    fi

    print_status "Re-applying PostgreSQL hardening (v$PG_VERSION, cluster: $PG_CLUSTER)"
    apply_hardening
}

################################################################################
# Install
################################################################################

run_install() {
    check_root

    local script_path
    script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

    print_status "Installing to /usr/local/bin/pg-security..."
    cp "$script_path" /usr/local/bin/pg-security
    chmod +x /usr/local/bin/pg-security
    print_success "Installed. Command: pg-security {setup|status|reapply|help}"
}

################################################################################
# Main
################################################################################

if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

COMMAND=$1; shift

case $COMMAND in
    setup)
        check_root
        prompt_config
        apply_hardening
        ;;
    status)   show_status ;;
    reapply)  run_reapply ;;
    install)  run_install ;;
    help|--help|-h) show_help ;;
    *) print_error "Unknown command: $COMMAND"; show_help; exit 1 ;;
esac
