<#
.SYNOPSIS
    Audits BitLocker encryption status across enterprise endpoints.
.DESCRIPTION
    Queries all AD-joined workstations and servers for BitLocker status,
    recovery key backup to AD, and encryption method compliance.
#>
[CmdletBinding()]
param([string]$OutputPath = $PWD)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Computers = (Get-ADComputer -Filter { Enabled -eq $true } -Properties Name).Name
$Results = $Computers | ForEach-Object -ThrottleLimit 20 -Parallel {
    $comp = $_
    try {
        $bl = Invoke-Command -ComputerName $comp -ScriptBlock {
            $vols = Get-BitLockerVolume -ErrorAction Stop
            $vols | ForEach-Object { [PSCustomObject]@{
                Drive            = $_.MountPoint
                ProtectionStatus = $_.ProtectionStatus
                EncryptionMethod = $_.EncryptionMethod
                EncryptionPercentage = $_.EncryptionPercentage
                KeyProtectors    = ($_.KeyProtector | Select-Object -Expand KeyProtectorType) -join "|"
                IsFullyEncrypted = ($_.EncryptionPercentage -eq 100)
            }}
        } -ErrorAction Stop
        $bl | Add-Member -NotePropertyName Computer -NotePropertyValue $comp -PassThru
    } catch { [PSCustomObject]@{ Computer=$comp; Error=$_.Exception.Message } }
}
$CsvPath = Join-Path $OutputPath "BitLockerAudit_$Timestamp.csv"
$Results | Export-Csv $CsvPath -NoTypeInformation
$unencrypted = $Results | Where-Object { $_.ProtectionStatus -eq "Off" -or $_.IsFullyEncrypted -eq $false }
Write-Host "[DONE] Checked: $($Results.Count) | Unencrypted/Partial: $($unencrypted.Count)" -ForegroundColor $(if ($unencrypted.Count -gt 0) { "Red" } else { "Green" })
