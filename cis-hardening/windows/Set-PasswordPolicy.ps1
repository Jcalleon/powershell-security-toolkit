<#
.SYNOPSIS
    Configures local or domain password policy per CIS Benchmark requirements.
.DESCRIPTION
    Sets enforce password history, max/min password age, minimum length,
    complexity requirements, and reversible encryption via secedit or
    Group Policy for domain-joined systems.
.EXAMPLE
    Set-PasswordPolicy -MinLength 14 -MaxAge 90 -HistoryCount 24
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [int]$MinLength     = 14,
    [int]$MaxAge        = 90,
    [int]$MinAge        = 1,
    [int]$HistoryCount  = 24,
    [switch]$Complexity = $true,
    [int]$LockoutThreshold = 10,
    [int]$LockoutDuration  = 15
)
#Requires -RunAsAdministrator

if ($PSCmdlet.ShouldProcess("Local password policy", "Apply CIS settings")) {
    $cfgFile = "$env:TEMP\secpol_cis.cfg"
    $db      = "$env:TEMP\secpol.sdb"
    # Export current
    secedit /export /cfg $cfgFile /quiet
    $cfg = Get-Content $cfgFile
    # Update values
    $cfg = $cfg -replace "MinimumPasswordLength\s*=.*",   "MinimumPasswordLength = $MinLength"
    $cfg = $cfg -replace "MaximumPasswordAge\s*=.*",      "MaximumPasswordAge = $MaxAge"
    $cfg = $cfg -replace "MinimumPasswordAge\s*=.*",      "MinimumPasswordAge = $MinAge"
    $cfg = $cfg -replace "PasswordHistorySize\s*=.*",     "PasswordHistorySize = $HistoryCount"
    $cfg = $cfg -replace "PasswordComplexity\s*=.*",      "PasswordComplexity = $(if ($Complexity) {1} else {0})"
    $cfg = $cfg -replace "ClearTextPassword\s*=.*",       "ClearTextPassword = 0"
    $cfg = $cfg -replace "LockoutBadCount\s*=.*",         "LockoutBadCount = $LockoutThreshold"
    $cfg = $cfg -replace "LockoutDuration\s*=.*",         "LockoutDuration = $LockoutDuration"
    $cfg | Set-Content $cfgFile
    secedit /configure /db $db /cfg $cfgFile /quiet
    Remove-Item $cfgFile,$db -ErrorAction SilentlyContinue
    Write-Host "[DONE] Password policy applied: MinLen=$MinLength MaxAge=$MaxAge History=$HistoryCount" -ForegroundColor Green
}
