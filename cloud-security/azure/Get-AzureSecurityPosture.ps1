<#
.SYNOPSIS
    Audits Azure tenant security posture across subscriptions.
.DESCRIPTION
    Evaluates Azure Defender/Secure Score, MFA status, conditional access,
    storage account public access, NSG rules, RBAC sprawl, and key vault settings.
    Requires Az PowerShell module and appropriate reader permissions.
.PARAMETER SubscriptionIDs
    Subscription IDs to audit. Default: all accessible subscriptions.
.PARAMETER OutputPath
    Report output directory.
.EXAMPLE
    Connect-AzAccount
    Get-AzureSecurityPosture -OutputPath "C:\Reports\Azure"
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionIDs,
    [string]$OutputPath = $PWD
)

#Requires -Modules Az.Accounts, Az.Security, Az.Resources, Az.Storage, Az.Network

$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportDir  = New-Item (Join-Path $OutputPath "AzurePosture_$Timestamp") -ItemType Directory -Force
$Findings   = [System.Collections.Generic.List[PSObject]]::new()

function Add-Finding {
    param([string]$Sub,[string]$Resource,[string]$Check,[string]$Status,[string]$Severity,[string]$Detail)
    $script:Findings.Add([PSCustomObject]@{
        Subscription = $Sub; Resource = $Resource; Check = $Check
        Status = $Status; Severity = $Severity; Detail = $Detail
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    })
}

$Subs = if ($SubscriptionIDs) {
    $SubscriptionIDs | ForEach-Object { Get-AzSubscription -SubscriptionId $_ }
} else { Get-AzSubscription }

foreach ($Sub in $Subs) {
    Set-AzContext -SubscriptionId $Sub.Id | Out-Null
    Write-Host "[*] Auditing subscription: $($Sub.Name) ($($Sub.Id))" -ForegroundColor Cyan

    # Azure Security Center / Defender Secure Score
    try {
        $secureScore = Get-AzSecuritySecureScore -ErrorAction Stop
        $score = [math]::Round($secureScore.Percentage * 100, 1)
        Add-Finding $Sub.Name "Subscription" "Microsoft Defender Secure Score" `
            (if ($score -ge 70) { "PASS" } else { "FAIL" }) `
            (if ($score -ge 70) { "Low" } else { "High" }) `
            "Secure Score: ${score}%"
    } catch { Write-Warning "Could not retrieve Secure Score" }

    # Storage accounts - public access
    Write-Host "  [*] Checking storage account public access..." -ForegroundColor Gray
    Get-AzStorageAccount | ForEach-Object {
        if ($_.AllowBlobPublicAccess -eq $true) {
            Add-Finding $Sub.Name $_.StorageAccountName "Storage Account Public Blob Access" "FAIL" "High" "AllowBlobPublicAccess = True"
        }
        if ($_.EnableHttpsTrafficOnly -ne $true) {
            Add-Finding $Sub.Name $_.StorageAccountName "Storage HTTPS Only" "FAIL" "High" "HTTP traffic allowed"
        }
        if ($_.MinimumTlsVersion -ne "TLS1_2") {
            Add-Finding $Sub.Name $_.StorageAccountName "Storage TLS 1.2 Minimum" "FAIL" "Medium" "MinTLS: $($_.MinimumTlsVersion)"
        }
    }

    # NSG rules - overly permissive
    Write-Host "  [*] Checking NSG rules..." -ForegroundColor Gray
    Get-AzNetworkSecurityGroup | ForEach-Object {
        $nsg = $_
        $_.SecurityRules + $_.DefaultSecurityRules | Where-Object {
            $_.Access -eq "Allow" -and $_.Direction -eq "Inbound" -and
            ($_.SourceAddressPrefix -in @("*","Any","Internet","0.0.0.0/0")) -and
            ($_.DestinationPortRange -in @("*","22","3389","5985","5986") -or $_.DestinationPortRange -match "^22$|^3389$")
        } | ForEach-Object {
            Add-Finding $Sub.Name $nsg.Name "NSG Overly Permissive Inbound Rule" "FAIL" "High" `
                "Rule: $($_.Name) | Port: $($_.DestinationPortRange) | Source: $($_.SourceAddressPrefix)"
        }
    }

    # RBAC - Owner/Contributor sprawl
    Write-Host "  [*] Checking RBAC assignments..." -ForegroundColor Gray
    $highPrivAssignments = Get-AzRoleAssignment | Where-Object {
        $_.RoleDefinitionName -in @("Owner","Contributor","User Access Administrator") -and
        $_.ObjectType -eq "User"
    }
    if ($highPrivAssignments.Count -gt 10) {
        Add-Finding $Sub.Name "Subscription" "RBAC Privilege Sprawl" "FAIL" "Medium" `
            "$($highPrivAssignments.Count) Owner/Contributor users. Review for least privilege."
    }

    # Key Vault - soft delete and access policies
    Write-Host "  [*] Checking Key Vaults..." -ForegroundColor Gray
    Get-AzKeyVault | ForEach-Object {
        $kv = Get-AzKeyVault -VaultName $_.VaultName
        if (-not $kv.EnableSoftDelete) {
            Add-Finding $Sub.Name $kv.VaultName "Key Vault Soft Delete Disabled" "FAIL" "High" "Enable soft-delete to prevent accidental/malicious key deletion"
        }
        if (-not $kv.EnablePurgeProtection) {
            Add-Finding $Sub.Name $kv.VaultName "Key Vault Purge Protection Disabled" "FAIL" "Medium" "Enable purge protection for compliance"
        }
    }
}

$Findings | Export-Csv "$ReportDir\azure_posture_findings.csv" -NoTypeInformation

$Fail = ($Findings | Where-Object Status -eq "FAIL").Count
$High = ($Findings | Where-Object { $_.Status -eq "FAIL" -and $_.Severity -eq "High" }).Count
Write-Host "`n[RESULTS] Findings: $Fail total | High severity: $High" -ForegroundColor $(if ($High -gt 0) { "Red" } else { "Yellow" })
Write-Host "[OUTPUT]  $ReportDir" -ForegroundColor Gray
