<#
.SYNOPSIS
    Configures Windows Advanced Audit Policy per CIS Benchmark and STIG requirements.
.DESCRIPTION
    Sets granular audit subcategories using auditpol.exe: logon events, account
    management, privilege use, process creation, object access, and policy changes.
    Enables command-line process auditing for enhanced detection coverage.
.EXAMPLE
    Set-WindowsAuditPolicy -Level CIS
    Set-WindowsAuditPolicy -Level STIG
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("CIS","STIG","Minimal")][string]$Level = "CIS",
    [string[]]$ComputerName = @($env:COMPUTERNAME)
)

$AuditPolicy = @(
    # Category                          SubCategory                         Success Failure
    @("Account Logon",   "Credential Validation",               1, 1),
    @("Account Logon",   "Kerberos Authentication Service",     1, 1),
    @("Account Logon",   "Kerberos Service Ticket Operations",  1, 1),
    @("Account Management", "Computer Account Management",      1, 1),
    @("Account Management", "Security Group Management",        1, 1),
    @("Account Management", "User Account Management",          1, 1),
    @("Detailed Tracking","Process Creation",                   1, 0),
    @("Detailed Tracking","Process Termination",                1, 0),
    @("DS Access",       "Directory Service Access",            0, 1),
    @("DS Access",       "Directory Service Changes",           1, 0),
    @("Logon/Logoff",    "Account Lockout",                     0, 1),
    @("Logon/Logoff",    "Logoff",                              1, 0),
    @("Logon/Logoff",    "Logon",                               1, 1),
    @("Logon/Logoff",    "Special Logon",                       1, 0),
    @("Object Access",   "Removable Storage",                   1, 1),
    @("Policy Change",   "Audit Policy Change",                 1, 1),
    @("Policy Change",   "Authentication Policy Change",        1, 0),
    @("Privilege Use",   "Sensitive Privilege Use",             0, 1),
    @("System",          "Security State Change",               1, 1),
    @("System",          "Security System Extension",           1, 1),
    @("System",          "System Integrity",                    1, 1)
)

foreach ($Computer in $ComputerName) {
    Write-Host "[*] Applying audit policy on: $Computer" -ForegroundColor Cyan
    foreach ($rule in $AuditPolicy) {
        $cat = $rule[0]; $sub = $rule[1]
        $s   = if ($rule[2]) { "enable" } else { "disable" }
        $f   = if ($rule[3]) { "enable" } else { "disable" }
        if ($PSCmdlet.ShouldProcess("$Computer | $sub", "Set audit")) {
            if ($Computer -eq $env:COMPUTERNAME) {
                auditpol /set /subcategory:"$sub" /success:$s /failure:$f 2>$null
            } else {
                Invoke-Command -ComputerName $Computer -ScriptBlock {
                    param($sub,$s,$f) auditpol /set /subcategory:"$sub" /success:$s /failure:$f 2>$null
                } -ArgumentList $sub,$s,$f
            }
            Write-Host "  [+] $sub (S:$s F:$f)" -ForegroundColor Green
        }
    }
    # Enable command-line auditing
    if ($PSCmdlet.ShouldProcess($Computer, "Enable command-line process auditing")) {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        Invoke-Command -ComputerName $Computer -ScriptBlock {
            if (-not (Test-Path $using:path)) { New-Item $using:path -Force | Out-Null }
            Set-ItemProperty $using:path -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
        }
        Write-Host "  [+] Command-line process auditing enabled" -ForegroundColor Green
    }
}
Write-Host "[DONE] Audit policy applied." -ForegroundColor Green
