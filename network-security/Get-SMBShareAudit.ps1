<#
.SYNOPSIS
    Audits SMB shares across the enterprise for excessive permissions and sensitive data.
.DESCRIPTION
    Enumerates all SMB shares on target systems, retrieves ACLs, flags shares
    with Everyone/Authenticated Users full control, and checks for shares
    containing keywords suggesting sensitive data (credentials, finance, PII).
.EXAMPLE
    Get-SMBShareAudit -ComputerName (Get-ADComputer -Filter * | Select -Expand Name)
#>
[CmdletBinding()]
param([string[]]$ComputerName = @($env:COMPUTERNAME), [string]$OutputPath = $PWD)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Results   = [System.Collections.Generic.List[PSObject]]::new()
$SensitiveKeywords = @("password","cred","secret","backup","finance","payroll","ssn","pii","medical","hipaa")

foreach ($comp in $ComputerName) {
    try {
        $shares = Get-SmbShare -CimSession (New-CimSession -ComputerName $comp -ErrorAction Stop) |
            Where-Object { $_.Name -notmatch "^(IPC|ADMIN|print)\$" }
        foreach ($share in $shares) {
            $acl = Get-SmbShareAccess -Name $share.Name -CimSession (New-CimSession -ComputerName $comp) -ErrorAction SilentlyContinue
            $overPermissive = $acl | Where-Object { $_.AccountName -match "Everyone|Authenticated Users|ANONYMOUS" -and $_.AccessRight -match "Full|Change" }
            $sensitiveName  = $SensitiveKeywords | Where-Object { $share.Name -match $_ }
            $Results.Add([PSCustomObject]@{
                Computer        = $comp
                ShareName       = $share.Name
                Path            = $share.Path
                ACLEntries      = ($acl | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) -join "|"
                OverPermissive  = [bool]$overPermissive
                SensitiveName   = [bool]$sensitiveName
                RiskLevel       = if ($overPermissive -and $sensitiveName) { "CRITICAL" } elseif ($overPermissive) { "HIGH" } elseif ($sensitiveName) { "MEDIUM" } else { "LOW" }
            })
        }
    } catch { Write-Warning "Could not audit shares on $comp`: $_" }
}

$Results | Export-Csv (Join-Path $OutputPath "SMBShareAudit_$Timestamp.csv") -NoTypeInformation
$high = $Results | Where-Object { $_.RiskLevel -in "CRITICAL","HIGH" }
Write-Host "[DONE] Shares: $($Results.Count) | High/Critical risk: $($high.Count)" -ForegroundColor $(if ($high.Count -gt 0) { "Red" } else { "Green" })
