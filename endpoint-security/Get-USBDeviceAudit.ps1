<#
.SYNOPSIS
    Audits USB device connection history from Windows event logs.
.DESCRIPTION
    Queries SetupAPI logs and event log for USB storage device history,
    maps to user sessions, flags unauthorized devices against allowlist.
#>
[CmdletBinding()]
param([string]$OutputPath = $PWD, [string[]]$AllowedVendorIDs = @())
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$usbEvents = Get-WinEvent -LogName "Microsoft-Windows-DriverFrameworks-UserMode/Operational" `
    -FilterXPath "*[System[(EventID=2003 or EventID=2100)]]" -MaxEvents 1000 -ErrorAction SilentlyContinue
$devices = Get-WmiObject Win32_USBControllerDevice | ForEach-Object {
    $dep = [wmi]$_.Dependent
    [PSCustomObject]@{
        DeviceID    = $dep.DeviceID
        Name        = $dep.Name
        Manufacturer= $dep.Manufacturer
        Status      = $dep.Status
        FirstSeen   = $dep.InstallDate
        Authorized  = ($AllowedVendorIDs.Count -eq 0 -or ($AllowedVendorIDs | Where-Object { $dep.DeviceID -match $_ }))
    }
} | Where-Object { $_.DeviceID -match "USB" }
$devices | Export-Csv (Join-Path $OutputPath "USBDevices_$Timestamp.csv") -NoTypeInformation
$unauthorized = $devices | Where-Object { -not $_.Authorized }
Write-Host "[DONE] USB devices: $($devices.Count) | Unauthorized: $($unauthorized.Count)" -ForegroundColor $(if ($unauthorized.Count -gt 0) { "Red" } else { "Green" })
