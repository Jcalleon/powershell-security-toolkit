#!/usr/bin/env bash
# =============================================================================
# CIS Rocky Linux 10 Benchmark v1.0.0 - Level 1 Server Hardening Script
# =============================================================================
# Reference: CIS Rocky Linux 10 Benchmark v1.0.0 (09-30-2025)
# Profile:   Level 1 - Server
#
# IMPORTANT:
#   - Run as root on a fresh/test system first before applying to production.
#   - Some controls (partition layout, bootloader password) require pre-planning.
#   - Manual/site-policy controls are noted but not auto-applied.
#   - Take a snapshot or backup before running.
#   - Review all changes before rebooting.
#
# Usage:  chmod +x cis_rocky10_level1_server.sh && sudo ./cis_rocky10_level1_server.sh
# =============================================================================

set -euo pipefail

# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #
LOGFILE="/var/log/cis_hardening_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
skip()    { echo -e "${YELLOW}[SKIP]${NC}  $*"; }
section() { echo -e "\n${RED}### $* ###${NC}"; }

require_root() {
    [[ $EUID -eq 0 ]] || { echo "Must be run as root."; exit 1; }
}

sysctl_set() {
    local param="$1" value="$2" file="/etc/sysctl.d/60-cis-hardening.conf"
    grep -qxF "${param} = ${value}" "$file" 2>/dev/null \
        || echo "${param} = ${value}" >> "$file"
    sysctl -w "${param}=${value}" &>/dev/null || true
}

disable_module() {
    local mod="$1"
    local conf="/etc/modprobe.d/60-cis-${mod}.conf"
    printf '\ninstall %s /bin/false\nblacklist %s\n' "$mod" "$mod" > "$conf"
    modprobe -r "$mod" 2>/dev/null || true
    rmmod "$mod" 2>/dev/null || true
    info "Kernel module disabled: $mod"
}

disable_service() {
    local svc="$1"
    if systemctl list-unit-files "${svc}" &>/dev/null | grep -q "${svc}"; then
        systemctl stop "${svc}" 2>/dev/null || true
        systemctl disable "${svc}" 2>/dev/null || true
        systemctl mask "${svc}" 2>/dev/null || true
        info "Service disabled/masked: $svc"
    else
        skip "Service not found (already absent): $svc"
    fi
}

remove_package() {
    local pkg="$1"
    if rpm -q "$pkg" &>/dev/null; then
        dnf remove -y "$pkg"
        info "Package removed: $pkg"
    else
        skip "Package not installed: $pkg"
    fi
}

require_root

echo "============================================================"
echo " CIS Rocky Linux 10 v1.0.0 - Level 1 Server Hardening"
echo " Started: $(date)"
echo " Log: $LOGFILE"
echo "============================================================"

# =============================================================================
# SECTION 1 — INITIAL SETUP
# =============================================================================

section "1.1.1 — Filesystem Kernel Modules"

# 1.1.1.1–1.1.1.10  Disable unneeded/dangerous filesystem & USB modules
for mod in cramfs freevxfs hfs hfsplus jffs2 squashfs udf firewire-core usb-storage; do
    disable_module "$mod"
done

# 1.1.1.6  overlay – disable unless Docker/containers are explicitly needed
# Comment the next line if you use container runtimes that require overlay.
disable_module "overlay"

section "1.1.2 — Filesystem Partitions"

# 1.1.2.1  /tmp — ensure it is a tmpfs or separate partition with mount options
info "Configuring /tmp mount options (tmpfs)"
systemctl unmask tmp.mount 2>/dev/null || true
systemctl enable tmp.mount 2>/dev/null || true

# Ensure /tmp has nodev, nosuid, noexec in fstab
if grep -qE '^\s*tmpfs\s+/tmp' /etc/fstab; then
    sed -i 's|^\(tmpfs\s\+/tmp\s\+tmpfs\s\+\)\([^#]*\)|\1defaults,rw,nosuid,nodev,noexec,relatime,size=2G|' /etc/fstab
else
    echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /etc/fstab
fi
mount -o remount /tmp 2>/dev/null || true
info "  /tmp: nodev, nosuid, noexec set"

# 1.1.2.2  /dev/shm — nodev, nosuid, noexec
if grep -qE '^\s*tmpfs\s+/dev/shm' /etc/fstab; then
    sed -i 's|^\(tmpfs\s\+/dev/shm\s\+tmpfs\s\+\)\([^#]*\)|\1defaults,rw,nosuid,nodev,noexec,relatime,size=2G|' /etc/fstab
else
    echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /etc/fstab
fi
mount -o remount /dev/shm 2>/dev/null || true
info "  /dev/shm: nodev, nosuid, noexec set"

# 1.1.2.3–1.1.2.7  Separate partitions for /home /var /var/tmp /var/log /var/log/audit
# These require pre-installation planning. Script checks and warns if missing.
for mnt in /home /var /var/tmp /var/log /var/log/audit; do
    if findmnt -kn "$mnt" &>/dev/null; then
        info "  Separate partition exists for $mnt — ✓"
    else
        warn "  No separate partition for $mnt (CIS 1.1.2.x). Strongly recommended to partition at install time."
    fi
done

# Apply mount options to existing separate /home, /var/tmp
for mnt_opts in "/home:nodev,nosuid" "/var:nodev,nosuid" "/var/tmp:nodev,nosuid,noexec" "/var/log:nodev,nosuid,noexec" "/var/log/audit:nodev,nosuid,noexec"; do
    mnt="${mnt_opts%%:*}"
    opts="${mnt_opts##*:}"
    if findmnt -kn "$mnt" &>/dev/null; then
        dev=$(findmnt -kno SOURCE "$mnt")
        fstype=$(findmnt -kno FSTYPE "$mnt")
        if grep -qE "^\s*${dev}\s+${mnt}" /etc/fstab 2>/dev/null; then
            sed -i "s|\(${dev}\s\+${mnt}\s\+${fstype}\s\+\)\([^#]*\)|\1${opts},relatime|" /etc/fstab
            mount -o remount "$mnt" 2>/dev/null || true
            info "  $mnt: mount options updated to $opts"
        fi
    fi
done

section "1.2 — Package Management"

# 1.2.1.2  Ensure gpgcheck is enabled globally
info "Ensuring gpgcheck is enabled in /etc/dnf/dnf.conf"
if grep -qiE '^\s*gpgcheck\s*=' /etc/dnf/dnf.conf; then
    sed -i 's/^\s*gpgcheck\s*=.*/gpgcheck=1/' /etc/dnf/dnf.conf
else
    echo "gpgcheck=1" >> /etc/dnf/dnf.conf
fi

# 1.2.1.5  Weak dependencies
if grep -qiE '^\s*install_weak_deps\s*=' /etc/dnf/dnf.conf; then
    sed -i 's/^\s*install_weak_deps\s*=.*/install_weak_deps=False/' /etc/dnf/dnf.conf
else
    echo "install_weak_deps=False" >> /etc/dnf/dnf.conf
fi
info "gpgcheck=1 and install_weak_deps=False configured"

section "1.3 — Mandatory Access Control (SELinux)"

# 1.3.1.1  Ensure SELinux is installed
if ! rpm -q libselinux &>/dev/null; then
    dnf install -y libselinux
fi

# 1.3.1.2  SELinux not disabled in bootloader
if grep -qiE 'selinux=0|enforcing=0' /etc/default/grub 2>/dev/null; then
    sed -i 's/selinux=0//g; s/enforcing=0//g' /etc/default/grub
    grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || true
    info "SELinux bootloader overrides removed"
else
    info "SELinux bootloader config OK"
fi

# 1.3.1.3  SELinux policy configured
if ! grep -qiE '^\s*SELINUXTYPE\s*=\s*targeted' /etc/selinux/config 2>/dev/null; then
    sed -i 's/^\s*SELINUXTYPE\s*=.*/SELINUXTYPE=targeted/' /etc/selinux/config
    info "SELINUXTYPE set to targeted"
fi

# 1.3.1.4/1.3.1.5  SELinux mode — enforcing
if ! grep -qiE '^\s*SELINUX\s*=\s*enforcing' /etc/selinux/config 2>/dev/null; then
    sed -i 's/^\s*SELINUX\s*=.*/SELINUX=enforcing/' /etc/selinux/config
    info "SELinux set to enforcing (takes full effect after reboot)"
fi
setenforce 1 2>/dev/null || warn "Could not set SELinux to enforcing live (may be in permissive/disabled mode — reboot required)"

# 1.3.1.7  Remove mcstrans
remove_package "mcstrans"

# 1.3.1.8  Remove setroubleshoot
remove_package "setroubleshoot"

section "1.4 — Bootloader"

# 1.4.2  Secure bootloader config file ownership/permissions
if [ -f /boot/grub2/grub.cfg ]; then
    chown root:root /boot/grub2/grub.cfg
    chmod og-rwx /boot/grub2/grub.cfg
    info "Bootloader config permissions secured"
fi
if [ -f /boot/grub2/user.cfg ]; then
    chown root:root /boot/grub2/user.cfg
    chmod og-rwx /boot/grub2/user.cfg
fi

# 1.4.1  Bootloader password — MANUAL STEP
warn "1.4.1 [MANUAL] Set a bootloader password with: grub2-setpassword"
warn "        Then run: grub2-mkconfig -o /boot/grub2/grub.cfg"

section "1.5 — Additional Process Hardening"

# 1.5.1  Core file size — disable core dumps via limits
if ! grep -qE '^\s*\*\s+hard\s+core\s+0' /etc/security/limits.conf; then
    echo "* hard core 0" >> /etc/security/limits.conf
fi
sysctl_set "fs.suid_dumpable" "0"     # 1.5.4
info "Core dumps disabled"

# 1.5.2  Protected hardlinks
sysctl_set "fs.protected_hardlinks" "1"

# 1.5.3  Protected symlinks
sysctl_set "fs.protected_symlinks" "1"

# 1.5.5  Restrict dmesg
sysctl_set "kernel.dmesg_restrict" "1"

# 1.5.6  Restrict kernel pointers
sysctl_set "kernel.kptr_restrict" "2"

# 1.5.7  Restrict ptrace
sysctl_set "kernel.yama.ptrace_scope" "1"

# 1.5.8  ASLR
sysctl_set "kernel.randomize_va_space" "2"

info "Kernel hardening sysctl values written to /etc/sysctl.d/60-cis-hardening.conf"

# 1.5.9  systemd-coredump ProcessSizeMax = 0
mkdir -p /etc/systemd/coredump.conf.d/
COREDUMP_CONF="/etc/systemd/coredump.conf.d/60-cis-coredump.conf"
cat > "$COREDUMP_CONF" <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
systemctl reload-or-restart systemd-coredump.socket 2>/dev/null || true
info "systemd-coredump: Storage=none, ProcessSizeMax=0"

section "1.6 — System-Wide Crypto Policy"

# 1.6.1  Not LEGACY
current_policy=$(update-crypto-policies --show 2>/dev/null || echo "UNKNOWN")
info "Current crypto policy: $current_policy"
if echo "$current_policy" | grep -qi "LEGACY"; then
    update-crypto-policies --set DEFAULT
    info "Crypto policy changed from LEGACY to DEFAULT"
fi

# 1.6.2–1.6.4  Disable SHA1, weak MACs, CBC for SSH
# Create crypto policy modules to strip weak algorithms
mkdir -p /etc/crypto-policies/policies/modules/

cat > /etc/crypto-policies/policies/modules/NO-SHA1.pmod <<'EOF'
# Disable SHA1 hash and signature support
hash = -SHA1
sign = -*-SHA1
EOF

cat > /etc/crypto-policies/policies/modules/NO-WEAKMAC.pmod <<'EOF'
# Disable weak MACs
mac@SSH = -HMAC-MD5 -UMAC-64 -HMAC-SHA1 -UMAC-128
EOF

cat > /etc/crypto-policies/policies/modules/NO-SSHCBC.pmod <<'EOF'
# Disable CBC mode ciphers for SSH
cipher@SSH = -AES-128-CBC -AES-192-CBC -AES-256-CBC -3DES-CBC
EOF

update-crypto-policies --set DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC 2>/dev/null || \
    warn "Could not apply full crypto policy modules — may need manual review"
info "Crypto policy updated: DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC"

section "1.7 — Warning Banners"

BANNER_TEXT="Authorized users only. All activity may be monitored and reported."

# 1.7.1  /etc/motd
echo "$BANNER_TEXT" > /etc/motd
# 1.7.2  /etc/issue
echo "$BANNER_TEXT" > /etc/issue
# 1.7.3  /etc/issue.net
echo "$BANNER_TEXT" > /etc/issue.net

# 1.7.4–1.7.6  Permissions
chmod 644 /etc/motd /etc/issue /etc/issue.net
chown root:root /etc/motd /etc/issue /etc/issue.net
info "Login banners configured"

section "1.8 — GNOME Display Manager"

if rpm -q gdm &>/dev/null; then
    # 1.8.1  Login banner
    mkdir -p /etc/dconf/profile /etc/dconf/db/gdm.d
    cat > /etc/dconf/profile/gdm <<'EOF'
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF
    cat > /etc/dconf/db/gdm.d/01-banner-message <<'EOF'
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized users only. All activity may be monitored and reported.'
disable-user-list=true
EOF
    # 1.8.3  Screen lock
    cat >> /etc/dconf/db/gdm.d/01-banner-message <<'EOF'

[org/gnome/desktop/session]
idle-delay=uint32 900

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 5
EOF
    # 1.8.4/1.8.5  Disable automount/autorun
    cat > /etc/dconf/db/local.d/00-media-automount <<'EOF'
[org/gnome/desktop/media-handling]
automount=false
automount-open=false
autorun-never=true
EOF
    dconf update 2>/dev/null || true
    info "GDM configured (banner, screen lock, automount disabled)"
    # 1.8.6  Xwayland
    if systemctl list-unit-files | grep -q xwayland; then
        systemctl disable xwayland 2>/dev/null || true
    fi
else
    skip "GDM not installed — skipping 1.8 GDM controls"
fi

# =============================================================================
# SECTION 2 — SERVICES
# =============================================================================

section "2.1 — Disable Unnecessary Server Services"

SERVER_SERVICES=(
    "autofs.service"            # 2.1.1
    "avahi-daemon.service"      # 2.1.2  (remove if not needed for mDNS)
    "avahi-daemon.socket"
    "cockpit.service"           # 2.1.3  (manage manually if needed)
    "cockpit.socket"
    "dhcpd.service"             # 2.1.4
    "dhcpd6.service"
    "named.service"             # 2.1.5
    "dnsmasq.service"           # 2.1.6
    "vsftpd.service"            # 2.1.7
    "ftpd.service"
    "dovecot.service"           # 2.1.8
    "cyrus-imapd.service"
    "nfs-server.service"        # 2.1.9
    "nfs-kernel-server.service"
    "cups.service"              # 2.1.10
    "cups.socket"
    "rpcbind.service"           # 2.1.11
    "rpcbind.socket"
    "rsync.service"             # 2.1.12  (rsyncd server)
    "smb.service"               # 2.1.13
    "nmb.service"
    "snmpd.service"             # 2.1.14
    "telnet.service"            # 2.1.15
    "tftp.service"              # 2.1.16
    "tftp.socket"
    "squid.service"             # 2.1.17
    "httpd.service"             # 2.1.18
    "nginx.service"
    "lighttpd.service"
    "gdm.service"               # 2.1.19  (GDM on a server)
    "xorg-x11-server.service"   # 2.1.20
    "xwayland.service"
)

for svc in "${SERVER_SERVICES[@]}"; do
    disable_service "$svc"
done

# 2.1.21  MTA local-only mode (postfix)
if rpm -q postfix &>/dev/null; then
    if grep -qiE '^\s*inet_interfaces\s*=' /etc/postfix/main.cf; then
        sed -i 's/^\s*inet_interfaces\s*=.*/inet_interfaces = loopback-only/' /etc/postfix/main.cf
    else
        echo "inet_interfaces = loopback-only" >> /etc/postfix/main.cf
    fi
    postfix check 2>/dev/null && systemctl restart postfix 2>/dev/null || true
    info "Postfix configured for local-only mode"
fi

section "2.2 — Remove Unnecessary Client Packages"

REMOVE_PKGS=(
    "ftp"           # 2.2.1
    "openldap-clients" # 2.2.2
    "telnet"        # 2.2.3
    "tftp"          # 2.2.4
)
for pkg in "${REMOVE_PKGS[@]}"; do
    remove_package "$pkg"
done

section "2.3 — Time Synchronization"

# 2.3.1  Ensure time sync is in use (chrony preferred on Rocky)
if ! rpm -q chrony &>/dev/null; then
    dnf install -y chrony
    info "chrony installed"
fi

# 2.3.2  Configure chrony servers if empty
if ! grep -qE '^\s*(server|pool)' /etc/chrony.conf 2>/dev/null; then
    echo "pool 2.rocky.pool.ntp.org iburst" >> /etc/chrony.conf
    warn "No NTP servers found in chrony.conf — added default Rocky pool. Update to your site's NTP server."
fi

# 2.3.3  Chrony not run as root
if ! grep -qiE '^\s*user\s+chrony' /etc/chrony.conf 2>/dev/null; then
    echo "user chrony" >> /etc/chrony.conf
fi
systemctl enable --now chronyd 2>/dev/null || true
info "chrony enabled and running"

section "2.4 — Job Schedulers"

# 2.4.1.1  cron enabled
systemctl enable --now crond 2>/dev/null || true

# 2.4.1.2–2.4.1.9  Restrict cron directories
for f in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    if [ -e "$f" ]; then
        chown root:root "$f"
        chmod og-rwx "$f"
    fi
done

# Remove cron.allow / at.allow if present to restrict access
[ -f /etc/cron.deny ] && rm -f /etc/cron.deny
touch /etc/cron.allow
chown root:root /etc/cron.allow
chmod 640 /etc/cron.allow

# 2.4.2.1  at access configured
[ -f /etc/at.deny ] && rm -f /etc/at.deny
touch /etc/at.allow
chown root:root /etc/at.allow
chmod 640 /etc/at.allow
info "cron/at access restricted to /etc/cron.allow and /etc/at.allow"

# =============================================================================
# SECTION 3 — NETWORK
# =============================================================================

section "3.1 — Network Devices"

# 3.1.2  Disable wireless interfaces
for iface in $(find /sys/class/net -type l -name 'wl*' -printf '%f\n' 2>/dev/null); do
    ip link set "$iface" down 2>/dev/null || true
    nmcli radio wifi off 2>/dev/null || true
    info "Wireless interface $iface disabled"
done

# 3.1.3  Bluetooth
disable_service "bluetooth.service"
disable_module "bluetooth"
disable_module "btusb"

section "3.2 — Network Kernel Modules"

for mod in atm can dccp tipc rds sctp; do
    disable_module "$mod"
done

section "3.3 — Network Kernel Parameters"

# IPv4 — Disable IP forwarding (not a router)
sysctl_set "net.ipv4.ip_forward" "0"
sysctl_set "net.ipv4.conf.all.forwarding" "0"
sysctl_set "net.ipv4.conf.default.forwarding" "0"

# Disable ICMP redirects
sysctl_set "net.ipv4.conf.all.send_redirects" "0"
sysctl_set "net.ipv4.conf.default.send_redirects" "0"
sysctl_set "net.ipv4.conf.all.accept_redirects" "0"
sysctl_set "net.ipv4.conf.default.accept_redirects" "0"
sysctl_set "net.ipv4.conf.all.secure_redirects" "0"
sysctl_set "net.ipv4.conf.default.secure_redirects" "0"

# Bogus ICMP / broadcast pings
sysctl_set "net.ipv4.icmp_ignore_bogus_error_responses" "1"
sysctl_set "net.ipv4.icmp_echo_ignore_broadcasts" "1"

# Reverse path filtering (anti-spoofing)
sysctl_set "net.ipv4.conf.all.rp_filter" "1"
sysctl_set "net.ipv4.conf.default.rp_filter" "1"

# Source routing
sysctl_set "net.ipv4.conf.all.accept_source_route" "0"
sysctl_set "net.ipv4.conf.default.accept_source_route" "0"

# Log martians
sysctl_set "net.ipv4.conf.all.log_martians" "1"
sysctl_set "net.ipv4.conf.default.log_martians" "1"

# SYN cookies
sysctl_set "net.ipv4.tcp_syncookies" "1"

# IPv6 — disable forwarding (keep consistent whether IPv6 is enabled or not)
sysctl_set "net.ipv6.conf.all.forwarding" "0"
sysctl_set "net.ipv6.conf.default.forwarding" "0"
sysctl_set "net.ipv6.conf.all.accept_redirects" "0"
sysctl_set "net.ipv6.conf.default.accept_redirects" "0"
sysctl_set "net.ipv6.conf.all.accept_source_route" "0"
sysctl_set "net.ipv6.conf.default.accept_source_route" "0"
sysctl_set "net.ipv6.conf.all.accept_ra" "0"
sysctl_set "net.ipv6.conf.default.accept_ra" "0"

sysctl --system &>/dev/null
info "Network sysctl parameters applied"

# =============================================================================
# SECTION 4 — HOST-BASED FIREWALL
# =============================================================================

section "4.1 — firewalld"

# 4.1.1  Install firewalld
if ! rpm -q firewalld &>/dev/null; then
    dnf install -y firewalld
fi

# 4.1.2  Backend = nftables
if grep -qiE '^\s*FirewallBackend\s*=' /etc/firewalld/firewalld.conf 2>/dev/null; then
    sed -i 's/^\s*FirewallBackend\s*=.*/FirewallBackend=nftables/' /etc/firewalld/firewalld.conf
else
    echo "FirewallBackend=nftables" >> /etc/firewalld/firewalld.conf
fi

# 4.1.3  Enable and start firewalld
systemctl unmask firewalld 2>/dev/null || true
systemctl enable --now firewalld

# 4.1.4  Set default zone drop target (block unexpected inbound traffic)
firewall-cmd --set-default-zone=drop 2>/dev/null || true
firewall-cmd --permanent --zone=drop --set-target=DROP 2>/dev/null || true

# Ensure SSH remains open (add to trusted or public if needed)
# Allow SSH before locking down — customize as needed
firewall-cmd --permanent --add-service=ssh 2>/dev/null || true
firewall-cmd --reload 2>/dev/null || true

info "firewalld configured (nftables backend, SSH allowed)"
warn "4.1.5–4.1.7 [MANUAL] Configure firewalld loopback rules and services/ports per your site policy"

# =============================================================================
# SECTION 5 — ACCESS CONTROL
# =============================================================================

section "5.1 — SSH Server"

SSHD_CONF="/etc/ssh/sshd_config"

# 5.1.1  Permissions on sshd_config
chmod 600 "$SSHD_CONF"
chown root:root "$SSHD_CONF"

# Secure all files in sshd_config.d
find /etc/ssh/sshd_config.d -type f -name '*.conf' 2>/dev/null | while read -r f; do
    chmod 600 "$f"; chown root:root "$f"
done

# 5.1.2  Private host keys: root:root, 0600
find /etc/ssh -type f 2>/dev/null | while read -r f; do
    if ssh-keygen -lf "$f" &>/dev/null && file "$f" | grep -qi 'private key'; then
        chmod 600 "$f"; chown root:root "$f"
    fi
done

# 5.1.3  Public host keys: root:root, 0644
find /etc/ssh -type f -name '*.pub' 2>/dev/null | while read -r f; do
    chmod 644 "$f"; chown root:root "$f"
done

# Write hardened SSH config into a drop-in file (CIS compliant)
cat > /etc/ssh/sshd_config.d/60-cis-hardening.conf <<'EOF'
# CIS Rocky Linux 10 Benchmark v1.0.0 - Level 1 Server SSH Hardening
# 5.1.5
Banner /etc/issue.net
# 5.1.7
ClientAliveInterval 15
ClientAliveCountMax 3
# 5.1.10
HostbasedAuthentication no
# 5.1.11
IgnoreRhosts yes
# 5.1.13
LoginGraceTime 60
# 5.1.14
LogLevel VERBOSE
# 5.1.16
MaxAuthTries 4
# 5.1.17
MaxStartups 10:30:60
# 5.1.18
MaxSessions 10
# 5.1.19
PermitEmptyPasswords no
# 5.1.20
PermitRootLogin no
# 5.1.21
PermitUserEnvironment no
# 5.1.22
UsePAM yes
EOF

chmod 600 /etc/ssh/sshd_config.d/60-cis-hardening.conf
chown root:root /etc/ssh/sshd_config.d/60-cis-hardening.conf

# 5.1.4  [MANUAL] AllowUsers or AllowGroups — must be site-specific
warn "5.1.4  [MANUAL] Add 'AllowUsers <userlist>' or 'AllowGroups <grouplist>' to $SSHD_CONF"

# 5.1.6 / 5.1.12 / 5.1.15  Ciphers, KexAlgorithms, MACs — handled via crypto-policy (Section 1.6)
# If crypto-policy is not available, uncomment below:
# cat >> /etc/ssh/sshd_config.d/60-cis-hardening.conf <<'SSHEOF'
# Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr
# MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
# KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
# SSHEOF

# 5.1.8  DisableForwarding — Level 2 for Server, but included here as good practice
# Uncomment to enable (breaks X11, tunnelling):
# echo "DisableForwarding yes" >> /etc/ssh/sshd_config.d/60-cis-hardening.conf

# 5.1.9  GSSAPIAuthentication — Level 2 for Server
# Uncomment to disable:
# echo "GSSAPIAuthentication no" >> /etc/ssh/sshd_config.d/60-cis-hardening.conf

systemctl reload-or-restart sshd
info "SSH hardened (sshd restarted)"

section "5.2 — Privilege Escalation (sudo)"

# 5.2.1  Install sudo
if ! rpm -q sudo &>/dev/null; then
    dnf install -y sudo
fi

# 5.2.2  sudo uses pty
SUDOERS_D="/etc/sudoers.d"
cat > "${SUDOERS_D}/60-cis-hardening" <<'EOF'
# CIS Rocky Linux 10 Benchmark v1.0.0 - Level 1 Server
# 5.2.2 — use pty
Defaults use_pty
# 5.2.3 — log file
Defaults logfile="/var/log/sudo.log"
# 5.2.4 — require password
Defaults !authenticate
# 5.2.6 — timestamp timeout 15 minutes
Defaults timestamp_timeout=15
EOF

# Fix 5.2.4: Defaults !authenticate sets nopasswd — revert to require password
# Correct approach: remove NOPASSWD from /etc/sudoers if present
sed -i '/NOPASSWD/s/^/# /' /etc/sudoers 2>/dev/null || true
sed -i '/!authenticate/d' "${SUDOERS_D}/60-cis-hardening"
cat >> "${SUDOERS_D}/60-cis-hardening" <<'EOF'
# 5.2.4 — require password for escalation (ensure no NOPASSWD in sudoers)
Defaults passwd_tries=3
EOF

# 5.2.5  Re-authentication not disabled
grep -qE '^\s*Defaults\s.*!authenticate' /etc/sudoers 2>/dev/null && \
    sed -i '/!authenticate/s/^/# /' /etc/sudoers

# 5.2.7  Restrict su to wheel group
if grep -qE '^\s*#\s*auth\s+required\s+pam_wheel' /etc/pam.d/su 2>/dev/null; then
    sed -i 's/^#\s*\(auth\s\+required\s\+pam_wheel\)/\1/' /etc/pam.d/su
else
    echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
fi
info "sudo configured (pty, log, timestamp, su restricted to wheel)"

section "5.3 — PAM Configuration"

# 5.3.1.1  authselect with pam modules (use sssd profile or local)
current_profile=$(authselect current 2>/dev/null | head -1 | awk '{print $NF}' || echo "")
if [ -z "$current_profile" ]; then
    authselect select sssd with-faillock with-pwhistory --force 2>/dev/null || \
    authselect select local with-faillock with-pwhistory --force 2>/dev/null || \
    warn "5.3.1.1 [MANUAL] Run: authselect select <profile> with-faillock with-pwhistory"
else
    authselect enable-feature with-faillock 2>/dev/null || true
    authselect enable-feature with-pwhistory 2>/dev/null || true
    info "authselect: faillock and pwhistory features enabled on profile $current_profile"
fi

# 5.3.2.1  pam_faillock — account lockout
FAILLOCK_CONF="/etc/security/faillock.conf"
{
    grep -qE '^\s*deny\s*=' "$FAILLOCK_CONF" 2>/dev/null && \
        sed -i 's/^\s*deny\s*=.*/deny = 5/' "$FAILLOCK_CONF" || \
        echo "deny = 5" >> "$FAILLOCK_CONF"
    grep -qE '^\s*unlock_time\s*=' "$FAILLOCK_CONF" 2>/dev/null && \
        sed -i 's/^\s*unlock_time\s*=.*/unlock_time = 900/' "$FAILLOCK_CONF" || \
        echo "unlock_time = 900" >> "$FAILLOCK_CONF"
    # 5.3.2.1.3 — apply to root
    grep -qE '^\s*even_deny_root' "$FAILLOCK_CONF" 2>/dev/null || \
        echo "even_deny_root" >> "$FAILLOCK_CONF"
}
info "pam_faillock: deny=5, unlock_time=900, even_deny_root"

# 5.3.2.2  pam_pwquality
PWQUALITY_CONF="/etc/security/pwquality.conf"
declare -A PW_SETTINGS=(
    ["minlen"]="14"        # 5.3.2.2.2 — min length 14
    ["difok"]="8"          # 5.3.2.2.1 — changed characters
    ["maxrepeat"]="3"      # 5.3.2.2.4 — same consecutive chars
    ["maxsequence"]="3"    # 5.3.2.2.5 — max sequential
    ["dictcheck"]="1"      # 5.3.2.2.6 — dictionary check
    ["enforce_for_root"]="1" # 5.3.2.2.7
    ["minclass"]="3"       # 5.3.2.2.3 — complexity (3 of 4 character classes)
)
for key in "${!PW_SETTINGS[@]}"; do
    val="${PW_SETTINGS[$key]}"
    grep -qE "^\s*${key}\s*=" "$PWQUALITY_CONF" 2>/dev/null && \
        sed -i "s/^\s*${key}\s*=.*/${key} = ${val}/" "$PWQUALITY_CONF" || \
        echo "${key} = ${val}" >> "$PWQUALITY_CONF"
done
info "pam_pwquality configured (minlen=14, difok=8, complexity enforced)"

# 5.3.2.3  pam_pwhistory — remember 24 passwords
PWHISTORY_CONF="/etc/security/pwhistory.conf"
if [ -f "$PWHISTORY_CONF" ]; then
    grep -qE '^\s*remember\s*=' "$PWHISTORY_CONF" && \
        sed -i 's/^\s*remember\s*=.*/remember = 24/' "$PWHISTORY_CONF" || \
        echo "remember = 24" >> "$PWHISTORY_CONF"
    grep -qE '^\s*enforce_for_root' "$PWHISTORY_CONF" || \
        echo "enforce_for_root" >> "$PWHISTORY_CONF"
fi
info "pam_pwhistory: remember=24, enforce_for_root"

# 5.3.2.4  pam_unix — no nullok, strong hashing
# Remove nullok from pam configs (authselect manages these, but check common-auth/password-auth)
for pam_file in /etc/pam.d/password-auth /etc/pam.d/system-auth; do
    [ -f "$pam_file" ] && sed -i 's/\bnullok\b//g' "$pam_file" || true
done
info "pam_unix nullok removed"

section "5.4 — User Accounts and Environment"

# 5.4.1  Shadow password suite
LOGINDEFS="/etc/login.defs"
declare -A LOGIN_SETTINGS=(
    ["PASS_MAX_DAYS"]="365"   # 5.4.1.1 — password expiration
    ["PASS_MIN_DAYS"]="1"     # 5.4.1.2 — min days between changes
    ["PASS_WARN_AGE"]="7"     # 5.4.1.3 — warn 7 days before expiry
    ["ENCRYPT_METHOD"]="SHA512" # 5.4.1.4 — strong hashing
)
for key in "${!LOGIN_SETTINGS[@]}"; do
    val="${LOGIN_SETTINGS[$key]}"
    grep -qE "^\s*${key}\s" "$LOGINDEFS" && \
        sed -i "s/^\s*${key}\s.*/${key} ${val}/" "$LOGINDEFS" || \
        echo "${key} ${val}" >> "$LOGINDEFS"
done

# 5.4.1.5  Inactive password lock after 30 days
useradd -D -f 30 2>/dev/null || true
info "login.defs: PASS_MAX_DAYS=365, PASS_MIN_DAYS=1, PASS_WARN_AGE=7, ENCRYPT_METHOD=SHA512"

# 5.4.2  Root and system accounts
# 5.4.2.1/5.4.2.2/5.4.2.3  root is only UID 0/GID 0
info "Checking for extra UID 0 / GID 0 accounts..."
awk -F: '($3==0 && $1!="root"){print "WARNING: Extra UID 0 account: "$1}' /etc/passwd
awk -F: '($4==0 && $1!="root"){print "WARNING: Extra GID 0 account: "$1}' /etc/passwd

# 5.4.2.4  Lock root direct login (console only via sulogin)
info "Ensuring root account password is set (not locked for recovery purposes)"
# Don't lock root password — just ensure it has no empty password
passwd -S root | grep -q "^root NP" && \
    warn "5.4.2.4 Root has no password! Set one with: passwd root" || \
    info "Root account has a password set"

# 5.4.2.5  Root PATH integrity — remove world-writable or empty entries
if echo "$PATH" | grep -q '::' || echo "$PATH" | grep -q ':$'; then
    warn "5.4.2.5 Root PATH contains empty entries — review /root/.bashrc and /root/.bash_profile"
fi

# 5.4.2.6  root umask
if ! grep -qE '^\s*umask\s+0?027' /root/.bashrc 2>/dev/null; then
    echo "umask 027" >> /root/.bashrc
fi

# 5.4.2.7  System accounts with no valid shell
while IFS=: read -r user _ uid _ _ _ shell; do
    if [ "$uid" -lt 1000 ] && [ "$user" != "root" ] && [ "$user" != "sync" ] && [ "$user" != "shutdown" ] && [ "$user" != "halt" ]; then
        if [ "$shell" != "/sbin/nologin" ] && [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
            usermod -s /sbin/nologin "$user" 2>/dev/null && info "System account shell locked: $user"
        fi
    fi
done < /etc/passwd

# 5.4.2.8  Lock accounts without valid login shell
while IFS=: read -r user _ uid _ _ _ shell; do
    if [ "$uid" -lt 1000 ] && [ "$user" != "root" ]; then
        if [ "$shell" = "/sbin/nologin" ] || [ "$shell" = "/usr/sbin/nologin" ] || [ "$shell" = "/bin/false" ]; then
            passwd -S "$user" | grep -qE "^$user P" && \
                usermod -L "$user" 2>/dev/null && info "Locked nologin account: $user"
        fi
    fi
done < /etc/passwd

# 5.4.3  User default environment
# 5.4.3.1  Remove nologin from /etc/shells
if grep -qE '^\s*/sbin/nologin|^\s*/usr/sbin/nologin' /etc/shells 2>/dev/null; then
    grep -vE '^\s*/(usr/)?sbin/nologin' /etc/shells > /tmp/shells.new
    mv /tmp/shells.new /etc/shells
    info "nologin removed from /etc/shells"
fi

# 5.4.3.2  Shell timeout TMOUT=900 (15 min)
PROFILE_D_TIMEOUT="/etc/profile.d/60-cis-timeout.sh"
cat > "$PROFILE_D_TIMEOUT" <<'EOF'
# CIS 5.4.3.2 — default shell timeout
TMOUT=900
readonly TMOUT
export TMOUT
EOF
chmod 644 "$PROFILE_D_TIMEOUT"

# 5.4.3.3  Default umask 027
PROFILE_D_UMASK="/etc/profile.d/60-cis-umask.sh"
cat > "$PROFILE_D_UMASK" <<'EOF'
# CIS 5.4.3.3 — default umask
umask 027
EOF
chmod 644 "$PROFILE_D_UMASK"
info "TMOUT=900, umask=027 written to /etc/profile.d/"

# =============================================================================
# SECTION 6 — LOGGING AND AUDITING
# =============================================================================

section "6.1 — Integrity Checking (AIDE)"

# 6.1.1  Install AIDE
if ! rpm -q aide &>/dev/null; then
    dnf install -y aide
    aide --init
    mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null || true
    info "AIDE installed and database initialized"
else
    info "AIDE already installed"
fi

# 6.1.2  Schedule regular AIDE checks
AIDE_CRON="/etc/cron.d/aide"
if [ ! -f "$AIDE_CRON" ]; then
    cat > "$AIDE_CRON" <<'EOF'
# CIS 6.1.2 — daily AIDE integrity check
0 5 * * * root /usr/sbin/aide --check | /bin/mail -s "AIDE Integrity Check - $(hostname)" root@localhost
EOF
    chmod 600 "$AIDE_CRON"
    info "AIDE daily cron job installed"
fi

# 6.1.3  Protect audit tools with AIDE (check aide.conf includes /sbin/audit*)
AIDE_CONF="/etc/aide.conf"
if [ -f "$AIDE_CONF" ] && ! grep -qE '^\s*/sbin/audit' "$AIDE_CONF"; then
    cat >> "$AIDE_CONF" <<'EOF'
# CIS 6.1.3 — protect audit tools
/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
EOF
    info "AIDE configured to protect audit tools"
fi

section "6.2 — System Logging"

# 6.2.1.1  journald active
systemctl enable --now systemd-journald 2>/dev/null || true

# 6.2.1.4  Only one logging system
# Prefer rsyslog (below) — disable if conflicting
# (on Rocky 10, journald + rsyslog co-exist as designed)

# 6.2.2.2  journald ForwardToSyslog disabled (rsyslog reads directly from journal)
JOURNALD_CONF="/etc/systemd/journald.conf.d/60-cis-hardening.conf"
mkdir -p /etc/systemd/journald.conf.d/
cat > "$JOURNALD_CONF" <<'EOF'
# CIS 6.2.2.2/6.2.2.3/6.2.2.4
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
systemctl reload-or-restart systemd-journald 2>/dev/null || true
info "journald: ForwardToSyslog=no, Compress=yes, Storage=persistent"

# 6.2.3.1  rsyslog installed
if ! rpm -q rsyslog &>/dev/null; then
    dnf install -y rsyslog
fi

# 6.2.3.2  rsyslog enabled
systemctl enable --now rsyslog 2>/dev/null || true

# 6.2.3.4  rsyslog log file creation mode
if ! grep -qE '^\$FileCreateMode\s+0640' /etc/rsyslog.conf 2>/dev/null; then
    sed -i '/^\$FileCreateMode/d' /etc/rsyslog.conf
    echo '$FileCreateMode 0640' >> /etc/rsyslog.conf
fi

# 6.2.3.7  rsyslog not receiving remote logs
for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf; do
    [ -f "$f" ] && sed -i 's/^\s*\$ModLoad\s\+imtcp/#&/' "$f"
    [ -f "$f" ] && sed -i 's/^\s*\$InputTCPServerRun/#&/' "$f"
    [ -f "$f" ] && sed -i 's/^\s*module(load="imtcp")/#&/' "$f"
done
systemctl restart rsyslog 2>/dev/null || true
info "rsyslog configured"

warn "6.2.3.5/6.2.3.6/6.2.3.8 [MANUAL] Configure rsyslog rules and remote log host in /etc/rsyslog.conf"

section "6.3 — System Auditing (auditd)"

# 6.3.1.1  Install auditd
if ! rpm -q audit &>/dev/null; then
    dnf install -y audit
fi

# 6.3.1.2  Audit processes that start before auditd (audit=1 in grub)
if ! grep -qE '\baudit=1\b' /etc/default/grub 2>/dev/null; then
    sed -i 's/\(GRUB_CMDLINE_LINUX="[^"]*\)"/\1 audit=1"/' /etc/default/grub
    grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || true
    info "audit=1 added to kernel command line"
fi

# 6.3.1.3  audit_backlog_limit
if ! grep -qE '\baudit_backlog_limit=\d+\b' /etc/default/grub 2>/dev/null; then
    sed -i 's/\(GRUB_CMDLINE_LINUX="[^"]*\)"/\1 audit_backlog_limit=8192"/' /etc/default/grub
    grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || true
    info "audit_backlog_limit=8192 added to kernel command line"
fi

# 6.3.1.4  Enable auditd
systemctl enable --now auditd 2>/dev/null || true

# 6.3.2  Data Retention
AUDITD_CONF="/etc/audit/auditd.conf"
{
    # 6.3.2.1  max_log_file = 100 MB
    sed -i 's/^\s*max_log_file\s*=.*/max_log_file = 100/' "$AUDITD_CONF"
    # 6.3.2.2  keep_logs (do not delete)
    sed -i 's/^\s*max_log_file_action\s*=.*/max_log_file_action = keep_logs/' "$AUDITD_CONF"
    # 6.3.2.3  halt when full
    sed -i 's/^\s*space_left_action\s*=.*/space_left_action = email/' "$AUDITD_CONF"
    sed -i 's/^\s*admin_space_left_action\s*=.*/admin_space_left_action = halt/' "$AUDITD_CONF"
    # 6.3.2.4  Warn when low space
    sed -i 's/^\s*space_left\s*=.*/space_left = 100/' "$AUDITD_CONF"
}
info "auditd retention configured (max_log_file=100MB, keep_logs, halt on full)"

# 6.3.3  auditd Rules
AUDIT_RULES="/etc/audit/rules.d/60-cis-hardening.rules"
cat > "$AUDIT_RULES" <<'AUDITEOF'
# CIS Rocky Linux 10 Benchmark v1.0.0 - Level 1 Server - Audit Rules
# 6.3.3.1 — sudoers changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# 6.3.3.2 — actions as another user (sudo usage)
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation

# 6.3.3.3 — sudo log file
-w /var/log/sudo.log -p wa -k sudo_log_file

# 6.3.3.4 — date/time changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime,stime -k time-change
-w /etc/localtime -p wa -k time-change

# 6.3.3.5 — hostname/domainname changes
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale

# 6.3.3.6 — /etc/issue and /etc/issue.net
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale

# 6.3.3.7 — /etc/hosts / hostname
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale

# 6.3.3.8 — network config
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/NetworkManager/system-connections/ -p wa -k system-locale

# 6.3.3.9 — NetworkManager directory
-w /etc/NetworkManager -p wa -k system-locale

# 6.3.3.11 — unsuccessful file access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

# 6.3.3.12 — /etc/group changes
-w /etc/group -p wa -k identity

# 6.3.3.13 — /etc/passwd changes
-w /etc/passwd -p wa -k identity

# 6.3.3.14 — /etc/shadow and /etc/gshadow
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

# 6.3.3.15 — /etc/security/opasswd
-w /etc/security/opasswd -p wa -k identity

# 6.3.3.16 — /etc/nsswitch.conf
-w /etc/nsswitch.conf -p wa -k nsswitch_changes

# 6.3.3.17 — PAM configuration
-w /etc/pam.conf -p wa -k pam_changes
-w /etc/pam.d/ -p wa -k pam_changes

# 6.3.3.18 — chmod events
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod

# 6.3.3.19 — chown events
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod

# 6.3.3.20 — xattr events
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

# 6.3.3.21 — successful mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts

# 6.3.3.22 — session initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# 6.3.3.23 — login/logout events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins

# 6.3.3.24 — unlink file deletions
-a always,exit -F arch=b64 -S unlink,unlinkat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat -F auid>=1000 -F auid!=unset -k delete

# 6.3.3.25 — rename file deletions
-a always,exit -F arch=b64 -S rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S rename,renameat -F auid>=1000 -F auid!=unset -k delete

# 6.3.3.26 — SELinux / MAC changes
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy

# 6.3.3.27 — chcon
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng

# 6.3.3.28 — setfacl
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng

# 6.3.3.29 — chacl
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng

# 6.3.3.30 — usermod
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod

# 6.3.3.31 — kernel module load/unload/modification
-a always,exit -F arch=b64 -S kmod -k kernel_modules
-a always,exit -F arch=b32 -S kmod -k kernel_modules

# 6.3.3.32 — init_module / finit_module
-a always,exit -F arch=b64 -S init_module,finit_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module,finit_module -k kernel_modules

# 6.3.3.33 — delete_module
-a always,exit -F arch=b64 -S delete_module -k kernel_modules
-a always,exit -F arch=b32 -S delete_module -k kernel_modules

# 6.3.3.35 — ensure errors do not halt audit loading
-i

# 6.3.3.36 — immutable (MUST BE LAST RULE — requires reboot to change rules)
-e 2
AUDITEOF

chmod 640 "$AUDIT_RULES"
chown root:root "$AUDIT_RULES"

# 6.3.3.10 — privileged commands (dynamically generate)
PRIV_RULES="/etc/audit/rules.d/61-cis-privileged.rules"
{
    echo "# 6.3.3.10 — privileged commands"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | \
        awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=unset -k privileged"}'
} > "$PRIV_RULES"
chmod 640 "$PRIV_RULES"

augenrules --load 2>/dev/null || auditctl -R "$AUDIT_RULES" 2>/dev/null || true
info "Audit rules loaded"

# 6.3.4  auditd file access
# 6.3.4.1  Audit log dir mode 0750
log_dir=$(grep -oP '(?<=log_file = ).*' "$AUDITD_CONF" 2>/dev/null | xargs dirname || echo "/var/log/audit")
chmod 750 "$log_dir" 2>/dev/null || true

# 6.3.4.2–6.3.4.10  Audit log file and tool permissions
find "$log_dir" -type f -exec chmod 640 {} \; 2>/dev/null || true
find "$log_dir" -exec chown root:root {} \; 2>/dev/null || true

for tool in /sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/autrace /sbin/augenrules; do
    [ -f "$tool" ] && chmod 755 "$tool" && chown root:root "$tool"
done

# 6.2.4.1  Logfile access
find /var/log -type f -exec chmod g-wx,o-rwx {} \; 2>/dev/null || true
info "Log file and audit tool permissions secured"

# =============================================================================
# SECTION 7 — SYSTEM MAINTENANCE
# =============================================================================

section "7.1 — System File and Directory Access"

# 7.1.1–7.1.10  Critical file permissions
declare -A FILE_PERMS=(
    ["/etc/passwd"]="644"
    ["/etc/passwd-"]="644"
    ["/etc/group"]="644"
    ["/etc/group-"]="644"
    ["/etc/shadow"]="000"
    ["/etc/shadow-"]="000"
    ["/etc/gshadow"]="000"
    ["/etc/gshadow-"]="000"
    ["/etc/shells"]="644"
    ["/etc/security/opasswd"]="600"
)
for file in "${!FILE_PERMS[@]}"; do
    perms="${FILE_PERMS[$file]}"
    if [ -f "$file" ]; then
        chmod "$perms" "$file"
        chown root:root "$file"
        info "  $file: permissions set to $perms"
    fi
done

# 7.1.11  World-writable files and directories — report only (do not auto-fix)
info "7.1.11 Scanning for world-writable files (output logged, no auto-fix)..."
find / -xdev -type f -perm -0002 2>/dev/null | tee /var/log/cis_worldwritable.log | wc -l | \
    xargs -I{} echo "  Found {} world-writable files — see /var/log/cis_worldwritable.log"

# 7.1.12  Files without owner/group — report only
info "7.1.12 Scanning for unowned files (output logged)..."
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | tee /var/log/cis_unowned.log | wc -l | \
    xargs -I{} echo "  Found {} unowned files — see /var/log/cis_unowned.log"

section "7.2 — Local User and Group Settings"

# 7.2.1  Shadowed passwords
pwck -s 2>/dev/null || true

# 7.2.2  No empty password fields
awk -F: '($2==""){print "WARNING: Empty password for user: "$1}' /etc/shadow

# 7.2.3–7.2.7  Duplicate checks
awk -F: '{ if ($4 in grp) print "WARNING: Duplicate GID", $4; else grp[$4]=$1 }' /etc/group
awk -F: '{ if ($3 in uid) print "WARNING: Duplicate UID", $3; else uid[$3]=$1 }' /etc/passwd
awk -F: '{ if ($1 in usr) print "WARNING: Duplicate username", $1; else usr[$1]=1 }' /etc/passwd
awk -F: '{ if ($1 in grp) print "WARNING: Duplicate group name", $1; else grp[$1]=1 }' /etc/group

# 7.2.8/7.2.9  Home directory permissions for interactive users
awk -F: '($3>=1000 && $3<65534 && $7!="/sbin/nologin" && $7!="/bin/false"){print $1":"$6}' /etc/passwd | \
while IFS=: read -r user homedir; do
    if [ -d "$homedir" ]; then
        mode=$(stat -c '%a' "$homedir")
        if [ "$((8#$mode & 8#022))" -ne 0 ]; then
            chmod g-w,o-rwx "$homedir"
            info "  $user home dir $homedir permissions tightened"
        fi
    fi
done

info "User/group checks complete"

# =============================================================================
# FINAL: Apply sysctl settings
# =============================================================================

section "Applying sysctl settings"
sysctl --system

# =============================================================================
# SUMMARY
# =============================================================================

echo ""
echo "============================================================"
echo " CIS Rocky Linux 10 Level 1 Server Hardening COMPLETE"
echo " Completed: $(date)"
echo " Log: $LOGFILE"
echo "============================================================"
echo ""
echo " MANUAL STEPS REQUIRED:"
echo "  1. 1.4.1   Set bootloader password: grub2-setpassword"
echo "  2. 5.1.4   Add AllowUsers/AllowGroups to /etc/ssh/sshd_config"
echo "  3. 4.1.5   Configure firewalld loopback traffic rules"
echo "  4. 4.1.7   Review firewalld services/ports for your environment"
echo "  5. 6.2.3.5 Configure rsyslog rules in /etc/rsyslog.conf"
echo "  6. 6.2.3.6 Configure rsyslog remote log host"
echo "  7. 1.1.2.3+ Verify separate partitions (best done at install time)"
echo "  8. 5.4.1.6 Audit users with future last password change dates:"
echo "             awk -F: '{if(\$9>$(date +%s)/86400){print \$1}}' /etc/shadow"
echo ""
echo " REBOOT RECOMMENDED to fully apply:"
echo "  - SELinux enforcing mode"
echo "  - Kernel module blacklists"
echo "  - Bootloader (audit=1, audit_backlog_limit)"
echo "  - Audit rule immutability (-e 2)"
echo "============================================================"
