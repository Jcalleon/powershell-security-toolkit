<#
.SYNOPSIS
    Executes a scriptblock across hundreds of remote systems with throttling, logging, and retry logic.
.DESCRIPTION
    Enterprise-grade bulk remote execution wrapper with parallel execution,
    retry on failure, progress reporting, and comprehensive audit logging.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string[]]$ComputerNames,
    [Parameter(Mandatory)][scriptblock]$ScriptBlock,
    [hashtable]$ArgumentList   = @{},
    [int]$ThrottleLimit        = 50,
    [int]$RetryCount           = 2,
    [string]$OutputPath        = $PWD
)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Results   = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
Write-Host "[*] Executing on $($ComputerNames.Count) systems (throttle: $ThrottleLimit)..." -ForegroundColor Cyan
$ComputerNames | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
    $comp = $_; $sb = $using:ScriptBlock; $args = $using:ArgumentList; $retries = $using:RetryCount
    $attempt = 0; $success = $false
    while ($attempt -le $retries -and -not $success) {
        try {
            $out = Invoke-Command -ComputerName $comp -ScriptBlock $sb -ArgumentList $args -ErrorAction Stop
            ($using:Results).Add([PSCustomObject]@{ Computer=$comp; Status="SUCCESS"; Output=$out; Attempt=$attempt+1 })
            $success = $true
        } catch {
            $attempt++
            if ($attempt -gt $retries) { ($using:Results).Add([PSCustomObject]@{ Computer=$comp; Status="FAILED"; Error=$_.Exception.Message; Attempt=$attempt }) }
        }
    }
}
$Results | Export-Csv (Join-Path $OutputPath "BulkCommand_$Timestamp.csv") -NoTypeInformation
$ok   = ($Results | Where-Object Status -eq "SUCCESS").Count
$fail = ($Results | Where-Object Status -eq "FAILED").Count
Write-Host "[DONE] Success: $ok | Failed: $fail" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Yellow" })
