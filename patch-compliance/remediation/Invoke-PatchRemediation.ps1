<#
.SYNOPSIS
    Triggers Windows Update installation on remote systems with pre/post validation.
.DESCRIPTION
    Connects to remote systems, triggers specific KB or all missing updates,
    monitors installation progress, validates completion, and reboots if required.
    Designed for bulk remediation of critical/zero-day patches at enterprise scale.
.PARAMETER ComputerName
    Target systems for patch deployment.
.PARAMETER KBArticleIDs
    Specific KB IDs to install. If omitted, installs all missing Critical/Important updates.
.PARAMETER Severity
    Minimum severity to install: Critical, Important, Moderate, Low. Default: Important.
.PARAMETER AllowReboot
    Automatically reboot systems if required to complete installation.
.PARAMETER MaintenanceWindowEnd
    DateTime by which patching must complete. Useful for change control compliance.
.EXAMPLE
    Invoke-PatchRemediation -ComputerName "SRV01","SRV02" -KBArticleIDs "KB5034441" -AllowReboot
    Invoke-PatchRemediation -ComputerName (Get-Content servers.txt) -Severity "Critical" -AllowReboot
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string[]]$ComputerName,
    [string[]]$KBArticleIDs,
    [ValidateSet("Critical","Important","Moderate","Low")][string]$Severity = "Important",
    [switch]$AllowReboot,
    [datetime]$MaintenanceWindowEnd = (Get-Date).AddHours(4)
)

$SeverityOrder = @{ Critical=4; Important=3; Moderate=2; Low=1 }
$MinSeverityNum = $SeverityOrder[$Severity]
$Results = [System.Collections.Generic.List[PSObject]]::new()

foreach ($Computer in $ComputerName) {
    if ((Get-Date) -gt $MaintenanceWindowEnd) {
        Write-Warning "Maintenance window exceeded. Stopping deployment."
        break
    }

    Write-Host "[*] Patching: $Computer" -ForegroundColor Cyan
    if ($PSCmdlet.ShouldProcess($Computer, "Install updates")) {
        try {
            $scriptBlock = {
                param($KBs, $MinSev, $SevOrder)
                $session  = New-Object -ComObject Microsoft.Update.Session
                $searcher = $session.CreateUpdateSearcher()
                $missing  = $searcher.Search("IsInstalled=0 and Type='Software'").Updates

                $toInstall = if ($KBs) {
                    $missing | Where-Object { ($_.KBArticleIDs | ForEach-Object { "KB$_" }) -in $KBs }
                } else {
                    $missing | Where-Object { $SevOrder[$_.MsrcSeverity] -ge $MinSev }
                }

                if ($toInstall.Count -eq 0) { return @{ Status="NoUpdates"; Count=0 } }

                $collection = New-Object -ComObject Microsoft.Update.UpdateColl
                $toInstall  | ForEach-Object { $collection.Add($_) | Out-Null }

                $downloader         = $session.CreateUpdateDownloader()
                $downloader.Updates = $collection
                $downloader.Download() | Out-Null

                $installer         = $session.CreateUpdateInstaller()
                $installer.Updates = $collection
                $result            = $installer.Install()

                return @{
                    Status         = if ($result.ResultCode -eq 2) { "Succeeded" } else { "Failed" }
                    Count          = $toInstall.Count
                    RebootRequired = $result.RebootRequired
                    ResultCode     = $result.ResultCode
                }
            }

            $r = Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock `
                -ArgumentList $KBArticleIDs, $MinSeverityNum, $SeverityOrder

            Write-Host "  [+] Status: $($r.Status) | Updates: $($r.Count) | Reboot needed: $($r.RebootRequired)" -ForegroundColor Green

            if ($r.RebootRequired -and $AllowReboot) {
                Write-Host "  [~] Scheduling reboot for $Computer in 60 seconds..." -ForegroundColor Yellow
                Invoke-Command -ComputerName $Computer -ScriptBlock { shutdown /r /t 60 /c "Patch remediation reboot - automated" }
            }

            $Results.Add([PSCustomObject]@{ Computer=$Computer; Status=$r.Status; UpdatesInstalled=$r.Count; RebootRequired=$r.RebootRequired })
        } catch {
            Write-Host "  [!] FAILED: $Computer - $_" -ForegroundColor Red
            $Results.Add([PSCustomObject]@{ Computer=$Computer; Status="Error"; Error=$_.Exception.Message })
        }
    }
}

$Results | Export-Csv "PatchRemediation_$(Get-Date -Format yyyyMMdd_HHmm).csv" -NoTypeInformation
Write-Host "`n[SUMMARY]" -ForegroundColor Cyan
$Results | Group-Object Status | Format-Table Name, Count -AutoSize
