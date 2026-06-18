<#
.SYNOPSIS
    Audits Active Directory trust relationships for security risks.
.DESCRIPTION
    Enumerates all domain and forest trusts, evaluates trust direction,
    SID filtering status, selective authentication, and external trust risks.
.EXAMPLE
    Get-ADTrustAudit -OutputPath "C:\Reports"
#>
[CmdletBinding()]
param([string]$OutputPath = $PWD)
Import-Module ActiveDirectory
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$trusts = Get-ADTrust -Filter * -Properties *
$results = $trusts | ForEach-Object {
    $risk = @()
    if ($_.TrustDirection -eq "Bidirectional") { $risk += "Bidirectional trust - review necessity" }
    if (-not $_.SIDFilteringQuarantined -and $_.TrustType -eq "External") { $risk += "SID filtering disabled on external trust" }
    if (-not $_.SelectiveAuthentication) { $risk += "Selective authentication not enabled" }

    [PSCustomObject]@{
        TrustName              = $_.Name
        Source                 = $_.Source
        Target                 = $_.Target
        TrustDirection         = $_.TrustDirection
        TrustType              = $_.TrustType
        SIDFilteringEnabled    = $_.SIDFilteringQuarantined
        SelectiveAuthentication= $_.SelectiveAuthentication
        TransitiveTrust        = $_.TrustAttributes -band 0x8
        Created                = $_.Created
        RiskFlags              = ($risk -join " | ")
        RiskLevel              = if ($risk.Count -ge 2) { "HIGH" } elseif ($risk.Count -eq 1) { "MEDIUM" } else { "LOW" }
    }
}

$results | Export-Csv (Join-Path $OutputPath "ADTrustAudit_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] Trusts: $($results.Count) | High risk: $(($results|Where-Object RiskLevel -eq 'HIGH').Count)" -ForegroundColor Yellow
$results | Format-Table TrustName, TrustDirection, TrustType, RiskLevel, RiskFlags -AutoSize
