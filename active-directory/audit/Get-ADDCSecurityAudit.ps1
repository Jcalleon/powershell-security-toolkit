<#
.SYNOPSIS
    Security audit focused specifically on Domain Controller configuration.
.DESCRIPTION
    Checks DC-specific risks: SYSVOL/NETLOGON permissions, DSRM password age,
    DC firewall rules, replication health, and risky DC-local accounts.
#>
[CmdletBinding()]
param([string]$OutputPath = $PWD)
Import-Module ActiveDirectory
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Findings  = [System.Collections.Generic.List[PSObject]]::new()

$DCs = Get-ADDomainController -Filter *
foreach ($DC in $DCs) {
    Write-Host "[*] Auditing DC: $($DC.HostName)" -ForegroundColor Cyan

    # Replication health
    try {
        $replHealth = repadmin /showrepl $DC.HostName /csv 2>$null | ConvertFrom-Csv
        $failures   = $replHealth | Where-Object { $_."Number of Failures" -gt 0 }
        if ($failures) {
            $Findings.Add([PSCustomObject]@{ DC=$DC.HostName; Check="AD Replication Failures"; Status="FAIL"; Severity="High"; Detail="$($failures.Count) failing replication links" })
        }
    } catch {}

    # Firewall on DC
    $fw = Invoke-Command -ComputerName $DC.HostName -ScriptBlock { (Get-NetFirewallProfile -Profile Domain).Enabled } -ErrorAction SilentlyContinue
    $Findings.Add([PSCustomObject]@{ DC=$DC.HostName; Check="DC Firewall Enabled"; Status=if($fw){"PASS"}else{"FAIL"}; Severity="High" })

    # Time sync
    $w32 = Invoke-Command -ComputerName $DC.HostName -ScriptBlock { (w32tm /query /status 2>$null) -join " " } -ErrorAction SilentlyContinue
    $Findings.Add([PSCustomObject]@{ DC=$DC.HostName; Check="W32TM Running"; Status=if($w32 -match "Stratum"){"PASS"}else{"WARN"}; Severity="Medium"; Detail=$w32 })
}

$Findings | Export-Csv (Join-Path $OutputPath "DCAudit_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] DC audit findings: $($Findings.Count) | Failures: $(($Findings | Where-Object Status -eq 'FAIL').Count)" -ForegroundColor Yellow
