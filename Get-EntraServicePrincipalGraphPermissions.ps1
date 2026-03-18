<#PSScriptInfo
.VERSION        1.0.0
.AUTHOR         Codex
.GUID           1e91e866-6a8a-4da4-8d9d-222222222222
.COPYRIGHT      (c) 2026. MIT License.
.TAGS           Intune Graph ServicePrincipal Entra Azure MicrosoftGraph KeyVault
.LICENSEURI     https://opensource.org/licenses/MIT
#>

<#
.SYNOPSIS
    Shows Microsoft Graph application permissions assigned to a service principal.

.DESCRIPTION
    Looks up a target service principal by object ID, app ID, or display name.
    Optionally resolves the app ID from Azure Key Vault, then lists the Graph
    app role assignments currently granted to that service principal.

.EXAMPLE
    .\Get-EntraServicePrincipalGraphPermissions.ps1 -TenantId "your-tenant-id" -ServicePrincipalAppId "your-app-client-id"

.EXAMPLE
    .\Get-EntraServicePrincipalGraphPermissions.ps1 -TenantId "your-tenant-id" -KeyVaultName "corp-automation-kv"
#>

#Requires -Modules Microsoft.Graph.Authentication
#Requires -Modules Microsoft.Graph.Applications
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter()]
    [string]$ServicePrincipalObjectId,

    [Parameter()]
    [string]$ServicePrincipalAppId,

    [Parameter()]
    [string]$ServicePrincipalDisplayName,

    [Parameter()]
    [string]$KeyVaultName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ClientIdSecretName = 'intune-client-id',

    [Parameter()]
    [switch]$SkipAzConnect
)

$ErrorActionPreference = 'Stop'
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$AdminScopes = @(
    'Application.Read.All',
    'AppRoleAssignment.Read.All'
)

function Assert-CommandAvailable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$InstallHint
    )

    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        throw $InstallHint
    }
}

function Ensure-AzConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter()]
        [switch]$SkipAzConnect
    )

    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if ($azContext) {
        return
    }

    if ($SkipAzConnect) {
        throw 'No active Az context is available. Remove -SkipAzConnect or establish an Az context before running the script.'
    }

    Connect-AzAccount -Tenant $TenantId -Identity -ErrorAction Stop | Out-Null
}

function Get-KeyVaultSecretPlainText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VaultName,

        [Parameter(Mandatory)]
        [string]$SecretName
    )

    $secret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -ErrorAction Stop
    if ($secret.PSObject.Properties.Name -contains 'SecretValueText' -and -not [string]::IsNullOrWhiteSpace([string]$secret.SecretValueText)) {
        return [string]$secret.SecretValueText
    }

    if ($secret.SecretValue) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret.SecretValue)
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            if ($bstr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }

    throw ("Secret '{0}' in Key Vault '{1}' did not contain a usable value." -f $SecretName, $VaultName)
}

function Resolve-ServicePrincipalAppId {
    [CmdletBinding()]
    param(
        [string]$ExplicitAppId,
        [string]$VaultName,
        [string]$SecretName,
        [string]$TenantId,
        [switch]$SkipAzConnect
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitAppId)) {
        return $ExplicitAppId
    }

    if ([string]::IsNullOrWhiteSpace($VaultName)) {
        return $null
    }

    Assert-CommandAvailable -Name 'Get-AzContext' -InstallHint 'Az.Accounts is not installed. Install-Module Az.Accounts -Scope CurrentUser'
    Assert-CommandAvailable -Name 'Connect-AzAccount' -InstallHint 'Az.Accounts is not installed. Install-Module Az.Accounts -Scope CurrentUser'
    Assert-CommandAvailable -Name 'Get-AzKeyVaultSecret' -InstallHint 'Az.KeyVault is not installed. Install-Module Az.KeyVault -Scope CurrentUser'

    Ensure-AzConnection -TenantId $TenantId -SkipAzConnect:$SkipAzConnect
    return Get-KeyVaultSecretPlainText -VaultName $VaultName -SecretName $SecretName
}

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
        $matches = @(Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction Stop)
        if ($matches.Count -ne 1) {
            throw "Expected 1 service principal for AppId '$AppId', found $($matches.Count)."
        }
        return $matches[0]
    }

    if (-not [string]::IsNullOrWhiteSpace($DisplayName)) {
        $safeName = $DisplayName.Replace("'", "''")
        $matches = @(Get-MgServicePrincipal -Filter "displayName eq '$safeName'" -ErrorAction Stop)
        if ($matches.Count -ne 1) {
            throw "Expected 1 service principal for DisplayName '$DisplayName', found $($matches.Count). Use -ServicePrincipalAppId or -ServicePrincipalObjectId instead."
        }
        return $matches[0]
    }

    throw 'Specify one of: -ServicePrincipalObjectId, -ServicePrincipalAppId, -ServicePrincipalDisplayName, or -KeyVaultName.'
}

try {
    $resolvedAppId = Resolve-ServicePrincipalAppId `
        -ExplicitAppId $ServicePrincipalAppId `
        -VaultName $KeyVaultName `
        -SecretName $ClientIdSecretName `
        -TenantId $TenantId `
        -SkipAzConnect:$SkipAzConnect

    Connect-MgGraph -TenantId $TenantId -Scopes $AdminScopes -NoWelcome -ErrorAction Stop | Out-Null

    $targetSp = Get-TargetServicePrincipal `
        -DisplayName $ServicePrincipalDisplayName `
        -AppId $resolvedAppId `
        -ObjectId $ServicePrincipalObjectId

    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'" -ErrorAction Stop
    if (-not $graphSp) {
        throw 'Microsoft Graph service principal not found.'
    }

    $roleMap = @{}
    foreach ($role in @($graphSp.AppRoles)) {
        $roleMap[[string]$role.Id] = [string]$role.Value
    }

    $assignments = @(
        Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $targetSp.Id -All -ErrorAction Stop |
        Where-Object { $_.ResourceId -eq $graphSp.Id }
    )

    Write-Host ("Target service principal: {0} [{1}]" -f $targetSp.DisplayName, $targetSp.Id) -ForegroundColor Cyan
    Write-Host ("AppId: {0}" -f $targetSp.AppId) -ForegroundColor Cyan
    Write-Host ''

    if ($assignments.Count -eq 0) {
        Write-Warning 'No Microsoft Graph app role assignments found on this service principal.'
        return
    }

    $rows = foreach ($assignment in $assignments) {
        [pscustomobject]@{
            Permission = $roleMap[[string]$assignment.AppRoleId]
            AppRoleId = [string]$assignment.AppRoleId
            Resource = [string]$assignment.ResourceDisplayName
        }
    }

    $rows |
        Sort-Object Permission |
        Format-Table -AutoSize
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
