<#
.SYNOPSIS
    Applies CIS Benchmark Level 1 hardening controls to Windows systems.
.DESCRIPTION
    Configures registry keys, audit policies, services, and security settings
    per CIS Microsoft Windows Server 2019/2022 Benchmark. Run as Administrator.
.PARAMETER WhatIf
    Preview changes without applying them.
.PARAMETER BackupPath
    Path to save registry backup before making changes.
.EXAMPLE
    Set-CISWindowsHardening -BackupPath "C:\Backups" -WhatIf
    Set-CISWindowsHardening -BackupPath "C:\Backups"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupPath = "$env:TEMP\CIS_Backup_$(Get-Date -Format yyyyMMdd)"
)

#Requires -RunAsAdministrator

$ChangeLog = [System.Collections.Generic.List[PSObject]]::new()

function Set-HardeningKey {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord", [string]$Description)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value")) {
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
            $ChangeLog.Add([PSCustomObject]@{ Status="APPLIED"; Description=$Description; Path="$Path\$Name"; Value=$Value })
            Write-Host "  [+] $Description" -ForegroundColor Green
        } catch {
            $ChangeLog.Add([PSCustomObject]@{ Status="ERROR"; Description=$Description; Path="$Path\$Name"; Value=$_.Exception.Message })
            Write-Host "  [!] FAILED: $Description - $_" -ForegroundColor Red
        }
    }
}

# --- Backup registry hives ---
if (-not (Test-Path $BackupPath)) { New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null }
Write-Host "[*] Backing up registry hives to $BackupPath" -ForegroundColor Cyan
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "$BackupPath\Lsa.reg" /y 2>$null
reg export "HKLM\SOFTWARE\Policies\Microsoft" "$BackupPath\MsPolicies.reg" /y 2>$null

Write-Host "`n[*] Applying CIS L1 Hardening Controls..." -ForegroundColor Cyan

# --- Credential Protection ---
Write-Host "`n[CREDENTIAL PROTECTION]" -ForegroundColor Yellow
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" 0 "DWord" "Disable WDigest authentication"
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" 1 "DWord" "Enable LSASS Protected Process Light"
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" 5 "DWord" "Require NTLMv2, refuse LM/NTLM"
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" 1 "DWord" "Restrict anonymous access"
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" 1 "DWord" "Restrict anonymous SAM enumeration"
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity" 1 "DWord" "Enable VBS for Credential Guard"
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "RequirePlatformSecurityFeatures" 1 "DWord" "Require Secure Boot for VBS"

# --- Network Security ---
Write-Host "`n[NETWORK SECURITY]" -ForegroundColor Yellow
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" 0 "DWord" "Disable SMBv1"
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature" 1 "DWord" "Enable SMB signing (server)"
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" 1 "DWord" "Require SMB signing (server)"
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" 1 "DWord" "Require SMB signing (client)"
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting" 2 "DWord" "Disable IP source routing"
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect" 0 "DWord" "Disable ICMP redirects"
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting" 2 "DWord" "Disable IPv6 source routing"

# --- Remote Access ---
Write-Host "`n[REMOTE ACCESS]" -ForegroundColor Yellow
Set-HardeningKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "UserAuthentication" 1 "DWord" "Require NLA for RDP"
Set-HardeningKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel" 3 "DWord" "Set RDP encryption to High"
Set-HardeningKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm" 1 "DWord" "Disable drive redirection over RDP"

# --- PowerShell Logging ---
Write-Host "`n[POWERSHELL LOGGING]" -ForegroundColor Yellow
Set-HardeningKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" 1 "DWord" "Enable PowerShell script block logging"
Set-HardeningKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" 1 "DWord" "Enable PowerShell transcription"
Set-HardeningKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "OutputDirectory" "C:\PSTranscripts" "String" "Set transcription output path"
Set-HardeningKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" 1 "DWord" "Enable PowerShell module logging"

# --- System Hardening ---
Write-Host "`n[SYSTEM HARDENING]" -ForegroundColor Yellow
Set-HardeningKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 255 "DWord" "Disable AutoRun on all drives"
Set-HardeningKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume" 1 "DWord" "Disable AutoPlay for non-volume devices"
Set-HardeningKey "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "EnableCfg" 1 "DWord" "Enable Control Flow Guard"
Set-HardeningKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableLockScreenAppNotifications" 1 "DWord" "Disable lock screen app notifications"

# --- Disable Vulnerable Services ---
Write-Host "`n[SERVICES]" -ForegroundColor Yellow
$ServicesToDisable = @("LLMNR","NetTcpPortSharing","RemoteRegistry","Spooler","W3SVC","WinRM")
foreach ($svc in $ServicesToDisable) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        if ($PSCmdlet.ShouldProcess($svc, "Disable service")) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "  [+] Disabled service: $svc" -ForegroundColor Green
        }
    }
}

# --- Audit Policy ---
Write-Host "`n[AUDIT POLICY]" -ForegroundColor Yellow
$AuditSettings = @(
    @{ SubCategory="Credential Validation"; Success=1; Failure=1 },
    @{ SubCategory="Logon"; Success=1; Failure=1 },
    @{ SubCategory="Logoff"; Success=1; Failure=0 },
    @{ SubCategory="Account Lockout"; Success=0; Failure=1 },
    @{ SubCategory="Process Creation"; Success=1; Failure=0 },
    @{ SubCategory="Security Group Management"; Success=1; Failure=0 },
    @{ SubCategory="User Account Management"; Success=1; Failure=1 },
    @{ SubCategory="Policy Change"; Success=1; Failure=1 },
    @{ SubCategory="Privilege Use"; Success=0; Failure=1 }
)
foreach ($a in $AuditSettings) {
    $s = if ($a.Success) { "enable" } else { "disable" }
    $f = if ($a.Failure) { "enable" } else { "disable" }
    auditpol /set /subcategory:"$($a.SubCategory)" /success:$s /failure:$f 2>$null
    Write-Host "  [+] Audit: $($a.SubCategory) (S:$($a.Success) F:$($a.Failure))" -ForegroundColor Green
}

# --- Summary ---
$Applied = ($ChangeLog | Where-Object Status -eq "APPLIED").Count
$Errors  = ($ChangeLog | Where-Object Status -eq "ERROR").Count
Write-Host "`n[COMPLETE] Applied: $Applied | Errors: $Errors" -ForegroundColor $(if ($Errors -eq 0) { "Green" } else { "Yellow" })
Write-Host "[BACKUP]   Registry backup saved to: $BackupPath" -ForegroundColor Gray
