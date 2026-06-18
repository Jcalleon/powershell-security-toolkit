<#
.SYNOPSIS
    Audits installed software across fleet, flags risky/unauthorized applications.
#>
[CmdletBinding()]
param([string[]]$ComputerName = @($env:COMPUTERNAME), [string]$OutputPath = $PWD)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$RiskyKeywords = "TeamViewer|AnyDesk|LogMeIn|NetSupport|Radmin|RealVNC|UltraVNC|Wireshark|Nmap|Metasploit|ngrok"
$all = [System.Collections.Generic.List[PSObject]]::new()
foreach ($comp in $ComputerName) {
    try {
        $sw = Invoke-Command -ComputerName $comp -ScriptBlock {
            $keys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                      "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")
            $keys | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
                Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate
        } -ErrorAction Stop
        $sw | ForEach-Object {
            $_ | Add-Member -NotePropertyName Computer -NotePropertyValue $comp
            $_ | Add-Member -NotePropertyName Flagged  -NotePropertyValue ($_.DisplayName -match $using:RiskyKeywords)
            $all.Add($_)
        }
    } catch { Write-Warning "Failed: $comp" }
}
$all | Export-Csv (Join-Path $OutputPath "SoftwareAudit_$Timestamp.csv") -NoTypeInformation
$flagged = ($all | Where-Object Flagged).Count
Write-Host "[DONE] Total: $($all.Count) | Flagged: $flagged" -ForegroundColor $(if ($flagged -gt 0) { "Yellow" } else { "Green" })
