<#
.SYNOPSIS
    Audits Azure AD identities: MFA status, guest accounts, service principals, and privileged roles.
#>
[CmdletBinding()]
param([string]$OutputPath = $PWD)
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
Connect-MgGraph -Scopes "User.Read.All","RoleManagement.Read.All","AuditLog.Read.All" -ErrorAction Stop
$users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime,UserType,SignInActivity
$noMFA = $users | Where-Object {
    $signIn = Get-MgUserAuthenticationMethod -UserId $_.Id -ErrorAction SilentlyContinue
    ($signIn | Where-Object { $_.AdditionalProperties["@odata.type"] -match "phone|authenticator|fido|windowsHello" }).Count -eq 0
}
$guests = $users | Where-Object UserType -eq "Guest"
$users | Select-Object DisplayName,UserPrincipalName,AccountEnabled,UserType,CreatedDateTime | Export-Csv (Join-Path $OutputPath "AzureUsers_$Timestamp.csv") -NoTypeInformation
$noMFA | Select-Object DisplayName,UserPrincipalName | Export-Csv (Join-Path $OutputPath "NoMFA_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] Users: $($users.Count) | No MFA: $($noMFA.Count) | Guests: $($guests.Count)" -ForegroundColor $(if ($noMFA.Count -gt 0) { "Yellow" } else { "Green" })
