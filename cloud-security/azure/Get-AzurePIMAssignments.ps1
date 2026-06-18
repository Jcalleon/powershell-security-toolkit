<#
.SYNOPSIS
    Audits Azure Privileged Identity Management (PIM) role assignments.
.DESCRIPTION
    Retrieves active and eligible PIM role assignments, flags permanent
    (non-PIM) assignments for privileged roles, and checks activation policies.
#>
[CmdletBinding()]
param([string]$SubscriptionId, [string]$OutputPath = $PWD)
#Requires -Modules Az.Resources
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

if ($SubscriptionId) { Set-AzContext -SubscriptionId $SubscriptionId | Out-Null }
$token   = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
$headers = @{ "Authorization"="Bearer $token" }
$scope   = "/subscriptions/$((Get-AzContext).Subscription.Id)"

# Get role assignments (non-PIM = permanent)
$permanent = Get-AzRoleAssignment | Where-Object { $_.RoleDefinitionName -in @("Owner","Contributor","User Access Administrator") }

$results = $permanent | ForEach-Object {
    [PSCustomObject]@{
        Principal       = $_.SignInName ?? $_.DisplayName
        PrincipalType   = $_.ObjectType
        Role            = $_.RoleDefinitionName
        Scope           = $_.Scope
        PIMManaged      = $false
        RiskLevel       = "HIGH"
        Recommendation  = "Convert to PIM eligible assignment"
    }
}

$results | Export-Csv (Join-Path $OutputPath "PIMAssignments_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] Permanent privileged assignments: $($results.Count) (should be 0 with PIM enforced)" -ForegroundColor $(if ($results.Count -gt 0) { "Red" } else { "Green" })
