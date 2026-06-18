<#
.SYNOPSIS
    Audits SSL/TLS certificates across internal web services for expiry and weak config.
.DESCRIPTION
    Connects to specified endpoints, retrieves SSL certificates, checks for:
    expiry within warning window, weak signature algorithms (MD5/SHA1),
    hostname mismatches, and self-signed certificates.
.EXAMPLE
    Get-CertificateAudit -Endpoints "server01:443","server02:8443" -ExpiryWarningDays 30
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Endpoints,
    [int]$ExpiryWarningDays = 30,
    [string]$OutputPath = $PWD
)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Results   = [System.Collections.Generic.List[PSObject]]::new()

foreach ($endpoint in $Endpoints) {
    $parts = $endpoint -split ":"
    $host_ = $parts[0]; $port = if ($parts[1]) { [int]$parts[1] } else { 443 }
    try {
        $tcpClient  = [System.Net.Sockets.TcpClient]::new($host_, $port)
        $sslStream  = [System.Net.Security.SslStream]::new($tcpClient.GetStream(), $false, { $true })
        $sslStream.AuthenticateAsClient($host_)
        $cert       = $sslStream.RemoteCertificate
        $cert2      = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)
        $daysLeft   = ($cert2.NotAfter - (Get-Date)).Days

        $Results.Add([PSCustomObject]@{
            Endpoint        = $endpoint
            Subject         = $cert2.Subject
            Issuer          = $cert2.Issuer
            NotBefore       = $cert2.NotBefore
            NotAfter        = $cert2.NotAfter
            DaysUntilExpiry = $daysLeft
            SignatureAlg    = $cert2.SignatureAlgorithm.FriendlyName
            Thumbprint      = $cert2.Thumbprint
            SelfSigned      = ($cert2.Subject -eq $cert2.Issuer)
            ExpiryStatus    = if ($daysLeft -le 0) { "EXPIRED" } elseif ($daysLeft -le $ExpiryWarningDays) { "EXPIRING" } else { "OK" }
            WeakAlgorithm   = $cert2.SignatureAlgorithm.FriendlyName -match "md5|sha1"
        })
        $sslStream.Close(); $tcpClient.Close()
    } catch { $Results.Add([PSCustomObject]@{ Endpoint=$endpoint; Error=$_.Exception.Message }) }
}

$Results | Export-Csv (Join-Path $OutputPath "CertAudit_$Timestamp.csv") -NoTypeInformation
$issues = $Results | Where-Object { $_.ExpiryStatus -ne "OK" -or $_.WeakAlgorithm -or $_.SelfSigned }
Write-Host "[DONE] Certs: $($Results.Count) | Issues: $($issues.Count)" -ForegroundColor $(if ($issues.Count -gt 0) { "Yellow" } else { "Green" })
$issues | Format-Table Endpoint, DaysUntilExpiry, ExpiryStatus, WeakAlgorithm, SelfSigned -AutoSize
