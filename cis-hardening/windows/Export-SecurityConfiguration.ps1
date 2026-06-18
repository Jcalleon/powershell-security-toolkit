<#
.SYNOPSIS
    Exports complete Windows security configuration as a structured JSON baseline.
.DESCRIPTION
    Captures all security-relevant settings into a single JSON document:
    LSA settings, audit policy, firewall config, PowerShell logging,
    password policy, and service states. Used for change detection and compliance.
.EXAMPLE
    Export-SecurityConfiguration -OutputPath "C:\Baselines"
#>
[CmdletBinding()]
param([string]$ComputerName = $env:COMPUTERNAME, [string]$OutputPath = $PWD)

$config = [ordered]@{
    ExportDate  = (Get-Date -Format "o")
    Computer    = $ComputerName
    LSA         = @{}
    Firewall    = @{}
    PowerShell  = @{}
    Services    = @{}
    AuditPolicy = @{}
}

# LSA / Credential protection
$lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
$config.LSA = @{
    RunAsPPL            = $lsa.RunAsPPL
    LmCompatibilityLevel= $lsa.LmCompatibilityLevel
    UseLogonCredential  = $lsa.UseLogonCredential
    RestrictAnonymous   = $lsa.RestrictAnonymous
}

# Firewall profiles
$config.Firewall = Get-NetFirewallProfile | ForEach-Object {
    @{ Profile=$_.Name; Enabled=$_.Enabled; DefaultInbound=$_.DefaultInboundAction; DefaultOutbound=$_.DefaultOutboundAction }
}

# PowerShell logging
$psLog = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
$config.PowerShell = @{ ScriptBlockLogging=$psLog.EnableScriptBlockLogging }

# Running services (security relevant)
$secServices = @("WinDefend","MsMpSvc","Sense","CsFalconService","SentinelAgent","SecurityHealthService","EventLog","Audit")
$config.Services = $secServices | ForEach-Object {
    $svc = Get-Service -Name $_ -ErrorAction SilentlyContinue
    @{ Name=$_; Status=if($svc){$svc.Status.ToString()}else{"NotFound"} }
}

# Audit policy (raw auditpol output)
$config.AuditPolicy = (auditpol /get /category:* 2>$null) -join "`n"

$jsonPath = Join-Path $OutputPath "SecConfig_${ComputerName}_$(Get-Date -Format yyyyMMdd_HHmm).json"
$config | ConvertTo-Json -Depth 6 | Out-File $jsonPath -Encoding UTF8
Write-Host "[DONE] Security configuration exported: $jsonPath" -ForegroundColor Green
