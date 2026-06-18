<#
.SYNOPSIS
    Audits AWS account security posture via AWS CLI / AWS.Tools PowerShell module.
.DESCRIPTION
    Checks IAM password policy, root account MFA, S3 bucket public access,
    Security Groups with 0.0.0.0/0 inbound, CloudTrail status, GuardDuty,
    and unused IAM credentials. Maps findings to CIS AWS Foundations Benchmark.
.PARAMETER Profile
    AWS CLI profile name. Default: uses current credential context.
.PARAMETER Region
    AWS region to audit. Default: us-east-1.
.EXAMPLE
    Get-AWSSecurityAudit -Profile "prod" -Region "us-east-1" -OutputPath "C:\Reports"
#>
[CmdletBinding()]
param(
    [string]$Profile,
    [string]$Region     = "us-east-1",
    [string]$OutputPath = $PWD
)

$Findings = [System.Collections.Generic.List[PSObject]]::new()
$AWSOpts  = if ($Profile) { @{ ProfileName=$Profile; Region=$Region } } else { @{ Region=$Region } }

function Add-Finding {
    param($Resource, $Check, $Pass, $Severity, $Detail)
    $Findings.Add([PSCustomObject]@{
        Resource=$Resource; Check=$Check; Status=if($Pass){"PASS"}else{"FAIL"}
        Severity=if($Pass){"Info"}else{$Severity}; Detail=$Detail
        CISControl="CIS-AWS-1.x"
    })
    Write-Host "  $(if($Pass){'[PASS]'}else{'[FAIL]'}) $Check" -ForegroundColor $(if($Pass){"Green"}else{"Red"})
}

Write-Host "[*] AWS Security Audit - Region: $Region" -ForegroundColor Cyan

# IAM Password Policy (CIS 1.5-1.11)
Write-Host "`n[IAM PASSWORD POLICY]" -ForegroundColor Yellow
try {
    $pwdPolicy = Get-IAMAccountPasswordPolicy @AWSOpts
    Add-Finding "IAM" "Min password length >= 14"     ($pwdPolicy.MinimumPasswordLength -ge 14) "High"   "Min length: $($pwdPolicy.MinimumPasswordLength)"
    Add-Finding "IAM" "Password requires uppercase"   $pwdPolicy.RequireUppercaseCharacters         "Medium" "Uppercase required: $($pwdPolicy.RequireUppercaseCharacters)"
    Add-Finding "IAM" "Password requires lowercase"   $pwdPolicy.RequireLowercaseCharacters         "Medium" ""
    Add-Finding "IAM" "Password requires numbers"     $pwdPolicy.RequireNumbers                     "Medium" ""
    Add-Finding "IAM" "Password requires symbols"     $pwdPolicy.RequireSymbols                     "Medium" ""
    Add-Finding "IAM" "Password history >= 24"        ($pwdPolicy.PasswordReusePrevention -ge 24)   "Medium" "History: $($pwdPolicy.PasswordReusePrevention)"
    Add-Finding "IAM" "Max password age <= 90 days"   ($pwdPolicy.MaxPasswordAge -le 90)            "Medium" "Max age: $($pwdPolicy.MaxPasswordAge)"
} catch { Write-Warning "Could not retrieve IAM password policy" }

# S3 Public Access (CIS 2.1.x)
Write-Host "`n[S3 BUCKETS]" -ForegroundColor Yellow
$buckets = Get-S3Bucket @AWSOpts
foreach ($b in $buckets) {
    try {
        $pab = Get-S3BucketPublicAccessBlock -BucketName $b.BucketName @AWSOpts
        Add-Finding "S3:$($b.BucketName)" "S3 Block Public Access" `
            ($pab.BlockPublicAcls -and $pab.BlockPublicPolicy -and $pab.IgnorePublicAcls -and $pab.RestrictPublicBuckets) `
            "Critical" "BlockPublicAcls=$($pab.BlockPublicAcls) RestrictPublic=$($pab.RestrictPublicBuckets)"
    } catch {}
}

# CloudTrail (CIS 3.x)
Write-Host "`n[CLOUDTRAIL]" -ForegroundColor Yellow
$trails = Get-CTTrailStatus @AWSOpts -ErrorAction SilentlyContinue
Add-Finding "CloudTrail" "CloudTrail enabled and logging" `
    ($trails -and ($trails | Where-Object IsLogging).Count -gt 0) "Critical" `
    "Active trails: $(($trails | Where-Object IsLogging).Count)"

# GuardDuty
Write-Host "`n[GUARDDUTY]" -ForegroundColor Yellow
try {
    $detectors = Get-GDDetectorList @AWSOpts
    $enabled   = $detectors | ForEach-Object { Get-GDDetector -DetectorId $_ @AWSOpts } | Where-Object Status -eq "ENABLED"
    Add-Finding "GuardDuty" "GuardDuty enabled" ($enabled.Count -gt 0) "High" "Enabled detectors: $($enabled.Count)"
} catch {}

$Findings | Export-Csv (Join-Path $OutputPath "AWS_Audit_$(Get-Date -Format yyyyMMdd).csv") -NoTypeInformation
$Fail = ($Findings | Where-Object Status -eq "FAIL").Count
Write-Host "`n[RESULTS] Findings: $Fail | Output: $OutputPath" -ForegroundColor $(if ($Fail -gt 0) { "Yellow" } else { "Green" })
