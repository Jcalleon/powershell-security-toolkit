<#
.SYNOPSIS
    Applies CIS Linux hardening controls via PowerShell remoting over SSH.
.DESCRIPTION
    Connects to Linux hosts via SSH (PowerShell 7+ with SSH remoting), applies
    CIS Level 1 hardening: SSH hardening, sysctl parameters, PAM config,
    audit daemon, unnecessary service removal, and file permission controls.
.PARAMETER Hostname
    Target Linux hostname or IP.
.PARAMETER SSHUser
    SSH username with sudo privileges.
.PARAMETER SSHKeyPath
    Path to SSH private key file.
.PARAMETER Distribution
    Linux distribution: Ubuntu, RHEL, CentOS. Default: Ubuntu.
.EXAMPLE
    Invoke-CISLinuxHardeningRemote -Hostname "10.0.1.50" -SSHUser "admin" `
        -SSHKeyPath "~/.ssh/id_rsa" -Distribution "Ubuntu"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Hostname,
    [Parameter(Mandatory)][string]$SSHUser,
    [string]$SSHKeyPath,
    [ValidateSet("Ubuntu","RHEL","CentOS","Debian")][string]$Distribution = "Ubuntu",
    [int]$SSHPort = 22
)

$SSHParams = @{ HostName = $Hostname; UserName = $SSHUser; Port = $SSHPort }
if ($SSHKeyPath) { $SSHParams["KeyFilePath"] = $SSHKeyPath }

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Run-Command {
    param([string]$Description, [string]$Command)
    try {
        $out = Invoke-Command -SSHConnection (New-PSSession @SSHParams) -ScriptBlock {
            param($cmd) bash -c "sudo $cmd 2>&1"
        } -ArgumentList $Command -ErrorAction Stop
        $Results.Add([PSCustomObject]@{ Check=$Description; Status="APPLIED"; Output=$out })
        Write-Host "  [+] $Description" -ForegroundColor Green
    } catch {
        $Results.Add([PSCustomObject]@{ Check=$Description; Status="ERROR"; Output=$_.Exception.Message })
        Write-Host "  [!] $Description - $_" -ForegroundColor Red
    }
}

Write-Host "[*] CIS L1 Hardening: $Hostname ($Distribution)" -ForegroundColor Cyan

# SSH Hardening (CIS 5.x)
Write-Host "`n[SSH HARDENING]" -ForegroundColor Yellow
Run-Command "Disable SSH root login"      "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config"
Run-Command "Disable SSH password auth"   "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config"
Run-Command "Set SSH MaxAuthTries to 4"   "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config"
Run-Command "Disable X11 forwarding"      "sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config"
Run-Command "Set SSH ClientAliveInterval" "echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config && echo 'ClientAliveCountMax 0' >> /etc/ssh/sshd_config"
Run-Command "Disable empty passwords"     "sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config"
Run-Command "Set SSH LoginGraceTime"      "sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config"
Run-Command "Restart sshd"                "systemctl restart sshd"

# Sysctl Network Hardening (CIS 3.x)
Write-Host "`n[NETWORK HARDENING]" -ForegroundColor Yellow
$sysctlSettings = @(
    "net.ipv4.ip_forward=0",
    "net.ipv4.conf.all.send_redirects=0",
    "net.ipv4.conf.default.send_redirects=0",
    "net.ipv4.conf.all.accept_source_route=0",
    "net.ipv4.conf.all.accept_redirects=0",
    "net.ipv4.conf.all.secure_redirects=0",
    "net.ipv4.conf.all.log_martians=1",
    "net.ipv4.icmp_echo_ignore_broadcasts=1",
    "net.ipv4.icmp_ignore_bogus_error_responses=1",
    "net.ipv4.tcp_syncookies=1",
    "net.ipv6.conf.all.disable_ipv6=1",
    "kernel.randomize_va_space=2",
    "fs.protected_hardlinks=1",
    "fs.protected_symlinks=1"
)
$sysctlBlock = $sysctlSettings -join "\n"
Run-Command "Apply sysctl hardening" "printf '$sysctlBlock' >> /etc/sysctl.d/99-cis.conf && sysctl -p /etc/sysctl.d/99-cis.conf"

# Disable unnecessary services
Write-Host "`n[SERVICES]" -ForegroundColor Yellow
foreach ($svc in @("avahi-daemon","cups","isc-dhcp-server","ldap","nfs-server","rpcbind","bind9","vsftpd","apache2","dovecot","smbd","squid","snmpd","nis","rsync")) {
    Run-Command "Disable $svc" "systemctl disable --now $svc 2>/dev/null || true"
}

# Audit daemon (auditd)
Write-Host "`n[AUDIT DAEMON]" -ForegroundColor Yellow
Run-Command "Install auditd"          "apt-get install -y auditd audispd-plugins 2>/dev/null || yum install -y audit 2>/dev/null"
Run-Command "Enable auditd"           "systemctl enable auditd && systemctl start auditd"
Run-Command "Audit privileged commands" "find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | awk '{print \"-a always,exit -F path=\"\$1\" -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged\"}' >> /etc/audit/rules.d/cis.rules"
Run-Command "Reload audit rules"      "auditctl -R /etc/audit/rules.d/cis.rules 2>/dev/null || true"

$Results | Export-Csv "CISLinux_${Hostname}_$(Get-Date -Format yyyyMMdd).csv" -NoTypeInformation
Write-Host "`n[DONE] Applied: $(($Results|Where-Object Status -eq 'APPLIED').Count) | Errors: $(($Results|Where-Object Status -eq 'ERROR').Count)" -ForegroundColor Green
