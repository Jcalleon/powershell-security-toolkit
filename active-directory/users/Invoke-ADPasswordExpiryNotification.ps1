<#
.SYNOPSIS
    Sends password expiry notification emails to users before their passwords expire.
.DESCRIPTION
    Queries AD for users with passwords expiring within the warning window,
    sends personalized HTML email reminders with self-service reset instructions.
.PARAMETER DaysWarning
    Days before expiry to start sending notifications. Default: 14.
.EXAMPLE
    Invoke-ADPasswordExpiryNotification -SMTPServer "smtp.corp.local" -FromAddress "it@company.com" -DaysWarning 14
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SMTPServer,
    [Parameter(Mandatory)][string]$FromAddress,
    [int]$DaysWarning   = 14,
    [string]$SSOPortal  = "https://portal.company.com/password"
)
Import-Module ActiveDirectory
$MaxPwdAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
$Notified  = [System.Collections.Generic.List[PSObject]]::new()

$expiringUsers = Get-ADUser -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $false } `
    -Properties PasswordLastSet, EmailAddress, DisplayName, Manager |
    Where-Object {
        $_.PasswordLastSet -and $_.EmailAddress -and
        ($daysLeft = $MaxPwdAge - ((Get-Date) - $_.PasswordLastSet).Days) -gt 0 -and $daysLeft -le $DaysWarning
    }

foreach ($user in $expiringUsers) {
    $daysLeft = $MaxPwdAge - ((Get-Date) - $user.PasswordLastSet).Days
    $body = @"
<html><body style="font-family:Segoe UI,sans-serif;max-width:600px">
<div style="background:#1a252f;color:white;padding:16px 20px;border-radius:6px 6px 0 0">
  <h2 style="margin:0">&#x1F512; Password Expiry Reminder</h2>
</div>
<div style="padding:20px;border:1px solid #ddd;border-top:none">
  <p>Hi $($user.DisplayName),</p>
  <p>Your password will expire in <strong>$daysLeft day(s)</strong>.</p>
  <p><a href="$SSOPortal" style="background:#2980b9;color:white;padding:10px 18px;text-decoration:none;border-radius:4px">Change Password Now</a></p>
  <p style="color:#666;font-size:12px">This is an automated message. Contact IT helpdesk if you need assistance.</p>
</div></body></html>
"@
    if ($PSCmdlet.ShouldProcess($user.EmailAddress, "Send expiry notification")) {
        Send-MailMessage -To $user.EmailAddress -From $FromAddress `
            -Subject "Action Required: Your password expires in $daysLeft days" `
            -Body $body -BodyAsHtml -SmtpServer $SMTPServer
        $Notified.Add([PSCustomObject]@{ User=$user.SamAccountName; Email=$user.EmailAddress; DaysLeft=$daysLeft })
        Write-Host "  [+] Notified: $($user.DisplayName) ($daysLeft days)" -ForegroundColor Green
    }
}
Write-Host "[DONE] Notifications sent: $($Notified.Count)" -ForegroundColor Green
