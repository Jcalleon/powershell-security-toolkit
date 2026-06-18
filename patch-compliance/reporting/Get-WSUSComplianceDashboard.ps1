<#
.SYNOPSIS
    Generates a WSUS patch compliance dashboard with approval status and SLA tracking.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$WSUSServer, [string]$OutputPath = $PWD)
[reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration") | Out-Null
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$wsus  = [Microsoft.UpdateServices.Administration.AdminProxy]::getUpdateServer($WSUSServer, $false, 8530)
$scope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
$scope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::NotApproved

$unapproved = $wsus.GetUpdates($scope) | Where-Object { -not $_.IsDeclined -and $_.MsrcSeverity -in "Critical","Important" }

$compScope  = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
$computers  = $wsus.GetComputerTargets($compScope)

$results = $computers | ForEach-Object {
    $pc = $_
    [PSCustomObject]@{
        Computer         = $pc.FullDomainName
        LastSyncTime     = $pc.LastSyncTime
        LastReportedTime = $pc.LastReportedStatusTime
        OS               = $pc.OSDescription
        NeedsUpdate      = ($pc.GetUpdateInstallationInfoPerUpdate() | Where-Object { $_.UpdateInstallationState -eq "NotInstalled" -and $_.Update.MsrcSeverity -in "Critical","Important" }).Count
    }
}

$results | Export-Csv (Join-Path $OutputPath "WSUSDashboard_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] WSUS computers: $($results.Count) | Unapproved critical/important updates: $($unapproved.Count)" -ForegroundColor Yellow
