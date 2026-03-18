<#PSScriptInfo
.VERSION        1.0.0
.AUTHOR         Codex
.GUID           8a5fdbe3-2f44-4c66-a2a1-111111111111
.COPYRIGHT      (c) 2026. MIT License.
.TAGS           Intune Graph ServicePrincipal Entra Azure MicrosoftGraph
.LICENSEURI     https://opensource.org/licenses/MIT
#>

<#
.SYNOPSIS
    Assign Microsoft Graph application permissions to a service principal.

.DESCRIPTION
    Looks up a target service principal, finds the Microsoft Graph app roles,
    and assigns the requested application permissions.

.EXAMPLE
    .\Set-EntraServicePrincipalPermissions.ps1 -TenantId "your-tenant-id" -ServicePrincipalAppId "your-app-client-id"
    Assigns the default Microsoft Graph application permissions required by Set-IntunePrimaryUsers.ps1.

.EXAMPLE
    .\Set-EntraServicePrincipalPermissions.ps1 -TenantId "your-tenant-id" -ServicePrincipalDisplayName "My Automation App" -WhatIf
    Shows what role assignments would be created for the target service principal.

.NOTES
    The signed-in admin needs enough Microsoft Graph rights to manage app role assignments.
    The script connects with delegated scopes:
    - Application.Read.All
    - AppRoleAssignment.ReadWrite.All
#>

#Requires -Modules Microsoft.Graph.Authentication
#Requires -Modules Microsoft.Graph.Applications
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Tenant ID")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(HelpMessage = "Service principal display name")]
    [string]$ServicePrincipalDisplayName,

    [Parameter(HelpMessage = "Service principal application (client) ID")]
    [string]$ServicePrincipalAppId,

    [Parameter(HelpMessage = "Service principal object ID")]
    [string]$ServicePrincipalObjectId,

    [Parameter(HelpMessage = "Microsoft Graph application permissions to assign")]
    [string[]]$Permissions = @(
        "DeviceManagementManagedDevices.ReadWrite.All",
        "AuditLog.Read.All",
        "User.Read.All"
    )
)

$ErrorActionPreference = "Stop"

$GraphAppId = "00000003-0000-0000-c000-000000000000"
$AdminScopes = @(
    "Application.Read.All",
    "AppRoleAssignment.ReadWrite.All"
)

function Get-TargetServicePrincipal {
    [CmdletBinding()]
    param(
        [string]$DisplayName,
        [string]$AppId,
        [string]$ObjectId
    )

    if (-not [string]::IsNullOrWhiteSpace($ObjectId)) {
        return Get-MgServicePrincipal -ServicePrincipalId $ObjectId -ErrorAction Stop
    }

    if (-not [string]::IsNullOrWhiteSpace($AppId)) {
        $Matches = @(Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction Stop)
        if ($Matches.Count -ne 1) {
            throw "Expected 1 service principal for AppId '$AppId', found $($Matches.Count)."
        }
        return $Matches[0]
    }

    if (-not [string]::IsNullOrWhiteSpace($DisplayName)) {
        $SafeName = $DisplayName.Replace("'", "''")
        $Matches = @(Get-MgServicePrincipal -Filter "displayName eq '$SafeName'" -ErrorAction Stop)
        if ($Matches.Count -ne 1) {
            throw "Expected 1 service principal for DisplayName '$DisplayName', found $($Matches.Count). Use -ServicePrincipalAppId or -ServicePrincipalObjectId instead."
        }
        return $Matches[0]
    }

    throw "Specify one of: -ServicePrincipalObjectId, -ServicePrincipalAppId, or -ServicePrincipalDisplayName."
}

try {
    Connect-MgGraph -TenantId $TenantId -Scopes $AdminScopes -NoWelcome -ErrorAction Stop | Out-Null

    $TargetSp = Get-TargetServicePrincipal `
        -DisplayName $ServicePrincipalDisplayName `
        -AppId $ServicePrincipalAppId `
        -ObjectId $ServicePrincipalObjectId

    Write-Host "Target service principal: $($TargetSp.DisplayName) [$($TargetSp.Id)]" -ForegroundColor Cyan

    $GraphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'" -ErrorAction Stop
    if (-not $GraphSp) {
        throw "Microsoft Graph service principal not found."
    }

    $DesiredRoles = @(
        $GraphSp.AppRoles |
        Where-Object {
            $_.Value -in $Permissions -and
            $_.AllowedMemberTypes -contains "Application"
        }
    )

    if (-not $DesiredRoles -or $DesiredRoles.Count -eq 0) {
        throw "None of the requested permissions were found as Microsoft Graph application roles."
    }

    $FoundValues = @($DesiredRoles.Value)
    $Missing = @($Permissions | Where-Object { $_ -notin $FoundValues })
    if ($Missing.Count -gt 0) {
        Write-Warning "Permissions not found: $($Missing -join ', ')"
    }

    $ExistingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $TargetSp.Id -All -ErrorAction Stop
    $ExistingRoleIds = @(
        $ExistingAssignments |
        Where-Object { $_.ResourceId -eq $GraphSp.Id } |
        Select-Object -ExpandProperty AppRoleId
    )

    foreach ($Role in $DesiredRoles) {
        if ($Role.Id -in $ExistingRoleIds) {
            Write-Host "SKIP  $($Role.Value) already assigned" -ForegroundColor Yellow
            continue
        }

        if ($PSCmdlet.ShouldProcess($TargetSp.DisplayName, "Assign Microsoft Graph application permission '$($Role.Value)'")) {
            $Body = @{
                principalId = $TargetSp.Id
                resourceId  = $GraphSp.Id
                appRoleId   = $Role.Id
            }

            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $TargetSp.Id `
                -BodyParameter $Body `
                -ErrorAction Stop | Out-Null

            Write-Host "OK    $($Role.Value)" -ForegroundColor Green
        }
    }
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
