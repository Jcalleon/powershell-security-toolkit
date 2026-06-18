<#
.SYNOPSIS
    Resolves nested AD group memberships recursively for audit purposes.
.DESCRIPTION
    Unrolls all nested group memberships to show effective access,
    useful for privileged access reviews and SOC 2 audits.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$GroupName, [string]$OutputPath = $PWD)
Import-Module ActiveDirectory
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
function Get-NestedMembers {
    param([string]$Group, [string]$ParentGroup = "", [int]$Depth = 0)
    if ($Depth -gt 10) { return }
    Get-ADGroupMember -Identity $Group -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{ Account=$_.SamAccountName; Type=$_.objectClass; DirectGroup=$Group; TopGroup=$ParentGroup; NestDepth=$Depth }
        if ($_.objectClass -eq "group") { Get-NestedMembers $_.Name $Group ($Depth+1) }
    }
}
$members = Get-NestedMembers $GroupName $GroupName
$members | Export-Csv (Join-Path $OutputPath "NestedGroup_${GroupName}_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] $GroupName effective membership: $($members.Count) accounts (all nesting levels)" -ForegroundColor Green
