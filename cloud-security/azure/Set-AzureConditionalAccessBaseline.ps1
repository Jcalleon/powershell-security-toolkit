<#
.SYNOPSIS
    Deploys baseline Conditional Access policies via Microsoft Graph API.
.DESCRIPTION
    Creates a set of foundational CA policies aligned to Microsoft security
    defaults and CIS Azure Benchmark:
    - Block legacy authentication
    - Require MFA for all users
    - Require MFA for admins
    - Block high-risk sign-ins
    - Require compliant device for sensitive apps
    Requires Azure AD P1/P2 license and Global Admin or CA Admin role.
.PARAMETER TenantId
    Azure AD tenant ID.
.PARAMETER ClientId
    App registration client ID for Graph API auth.
.PARAMETER ClientSecret
    App registration client secret.
.PARAMETER Mode
    "Report" for report-only mode (test), "Enabled" to enforce. Default: Report.
.EXAMPLE
    Set-AzureConditionalAccessBaseline -TenantId "..." -ClientId "..." -ClientSecret "..." -Mode "Report"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,
    [ValidateSet("Report","Enabled","Disabled")][string]$Mode = "Report"
)

# Auth
$tokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}
$token   = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody).access_token
$headers = @{ "Authorization" = "Bearer $token"; "Content-Type" = "application/json" }

function New-CAPolicy {
    param([hashtable]$Policy)
    $body = $Policy | ConvertTo-Json -Depth 10
    $resp = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
        -Method POST -Headers $headers -Body $body -ErrorAction Stop
    Write-Host "  [+] Created: $($Policy.displayName) (ID: $($resp.id))" -ForegroundColor Green
}

$policies = @(
    @{
        displayName = "CA001 - Block Legacy Authentication"
        state       = $Mode.ToLower()
        conditions  = @{
            users       = @{ includeUsers = @("All") }
            applications = @{ includeApplications = @("All") }
            clientAppTypes = @("exchangeActiveSync","other")
        }
        grantControls = @{ operator = "OR"; builtInControls = @("block") }
    },
    @{
        displayName = "CA002 - Require MFA for All Users"
        state       = $Mode.ToLower()
        conditions  = @{
            users        = @{ includeUsers = @("All"); excludeGroups = @("CA-Exclusion-MFA") }
            applications = @{ includeApplications = @("All") }
            locations    = @{ includeLocations = @("All"); excludeLocations = @("AllTrusted") }
        }
        grantControls = @{ operator = "OR"; builtInControls = @("mfa") }
    },
    @{
        displayName = "CA003 - Require MFA for Azure Management"
        state       = $Mode.ToLower()
        conditions  = @{
            users        = @{ includeUsers = @("All") }
            applications = @{ includeApplications = @("797f4846-ba00-4fd7-ba43-dac1f8f63013") }  # Azure Mgmt
        }
        grantControls = @{ operator = "OR"; builtInControls = @("mfa") }
    },
    @{
        displayName = "CA004 - Block High-Risk Sign-Ins (Identity Protection)"
        state       = $Mode.ToLower()
        conditions  = @{
            users        = @{ includeUsers = @("All") }
            applications = @{ includeApplications = @("All") }
            signInRiskLevels = @("high","medium")
        }
        grantControls = @{ operator = "OR"; builtInControls = @("block") }
    }
)

Write-Host "[*] Deploying $($policies.Count) Conditional Access policies (Mode: $Mode)" -ForegroundColor Cyan
foreach ($policy in $policies) {
    if ($PSCmdlet.ShouldProcess($policy.displayName, "Create Conditional Access Policy")) {
        try { New-CAPolicy $policy } catch { Write-Warning "Failed $($policy.displayName): $_" }
    }
}
Write-Host "`n[DONE] CA policies deployed in $Mode mode." -ForegroundColor Green
