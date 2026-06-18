<#
.SYNOPSIS
    Audits Windows systems for missing patches and reports compliance status.
.DESCRIPTION
    Queries Windows Update API for missing updates, calculates patch age,
    and produces a compliance report with severity breakdown.
.PARAMETER ComputerName
    Target systems to audit. Defaults to local machine.
.PARAMETER MaxPatchAgedays
    Number of days since last patch before flagging as non-compliant. Default: 30.
.EXAMPLE
    Invoke-WindowsPatchAudit -ComputerName (Get-ADComputer -Filter * | Select-Object -Expand Name)
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName = $env:COMPUTERNAME,
    [int]$MaxPatchAgeDays = 30
)

$Report = [System.Collections.Generic.List[PSObject]]::new()

foreach ($Computer in $ComputerName) {
    Write-Host "[*] Auditing patches on: $Computer" -ForegroundColor Cyan
    try {
        $session  = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session", $Computer))
        $searcher = $session.CreateUpdateSearcher()
        $results  = $searcher.Search("IsInstalled=0 and Type='Software'")

        $missing = $results.Updates | ForEach-Object {
            [PSCustomObject]@{
                Computer   = $Computer
                KBArticle  = ($_.KBArticleIDs -join ", ")
                Title      = $_.Title
                Severity   = $_.MsrcSeverity
                Categories = ($_.Categories | Select-Object -Expand Name) -join ", "
                Released   = $_.LastDeploymentChangeTime
            }
        }

        $lastPatch = (Get-HotFix -ComputerName $Computer | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
        $daysSince = ((Get-Date) - $lastPatch).Days

        $Report.Add([PSCustomObject]@{
            Computer         = $Computer
            MissingUpdates   = $missing.Count
            CriticalMissing  = ($missing | Where-Object Severity -eq "Critical").Count
            ImportantMissing = ($missing | Where-Object Severity -eq "Important").Count
            LastPatchDate    = $lastPatch
            DaysSincePatch   = $daysSince
            PatchCompliant   = ($daysSince -le $MaxPatchAgeDays -and $missing.Count -eq 0)
        })

        $missing | ForEach-Object { $Report.Add($_) }
    } catch {
        Write-Warning "Failed to query $Computer`: $_"
        $Report.Add([PSCustomObject]@{ Computer=$Computer; Error=$_.Exception.Message })
    }
}

$Report | Export-Csv "PatchAudit_$(Get-Date -Format yyyyMMdd).csv" -NoTypeInformation
$Report | Where-Object { $_.PSObject.Properties.Name -contains "PatchCompliant" } |
    Format-Table Computer, MissingUpdates, CriticalMissing, LastPatchDate, DaysSincePatch, PatchCompliant -AutoSize
