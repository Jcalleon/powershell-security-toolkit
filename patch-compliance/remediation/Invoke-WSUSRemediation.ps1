<#
.SYNOPSIS
    Forces WSUS client synchronization and update installation on remote systems.
.DESCRIPTION
    Triggers wuauclt/UsoClient on target systems to check WSUS for updates,
    download, and install. Useful for forcing patch compliance after a WSUS
    approval cycle without waiting for scheduled scan windows.
.EXAMPLE
    Invoke-WSUSRemediation -ComputerName "SRV01","WS001" -AllowReboot
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string[]]$ComputerName,
    [switch]$AllowReboot,
    [int]$WaitMinutes = 30
)

$Results = [System.Collections.Generic.List[PSObject]]::new()
foreach ($comp in $ComputerName) {
    if ($PSCmdlet.ShouldProcess($comp, "Trigger WSUS update cycle")) {
        Write-Host "[*] Triggering WSUS update on: $comp" -ForegroundColor Cyan
        try {
            Invoke-Command -ComputerName $comp -ScriptBlock {
                param($reboot, $wait)
                # Force detection
                if (Get-Command UsoClient -ErrorAction SilentlyContinue) {
                    UsoClient ScanInstallWait
                } else {
                    wuauclt /detectnow /updatenow
                }
                # Wait for completion
                $deadline = (Get-Date).AddMinutes($wait)
                while ((Get-Date) -lt $deadline) {
                    $session  = New-Object -ComObject Microsoft.Update.Session
                    $searcher = $session.CreateUpdateSearcher()
                    $missing  = $searcher.Search("IsInstalled=0 and Type='Software'").Updates
                    if ($missing.Count -eq 0) { break }
                    Start-Sleep -Seconds 60
                }
                if ($reboot -and (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")) {
                    Restart-Computer -Force -Delay 60
                }
                return (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates.Count
            } -ArgumentList $AllowReboot, $WaitMinutes
            $Results.Add([PSCustomObject]@{ Computer=$comp; Status="Triggered"; Timestamp=(Get-Date) })
        } catch {
            $Results.Add([PSCustomObject]@{ Computer=$comp; Status="Failed"; Error=$_.Exception.Message })
            Write-Warning "Failed on $comp`: $_"
        }
    }
}
$Results | Export-Csv "WSUSRemediation_$(Get-Date -Format yyyyMMdd_HHmm).csv" -NoTypeInformation
Write-Host "[DONE] Triggered: $(($Results|Where-Object Status -eq 'Triggered').Count) | Failed: $(($Results|Where-Object Status -eq 'Failed').Count)" -ForegroundColor Green
