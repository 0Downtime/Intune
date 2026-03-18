<#PSScriptInfo
.VERSION        1.0.0
.GUID           feedbeef-beef-4dad-beef-000000000002
.AUTHOR         Internal
.COPYRIGHT      (c) 2026
.TAGS           Intune Graph ManagedDevice Seed MicrosoftGraph Azure
.LICENSEURI     https://opensource.org/licenses/MIT
.PROJECTURI
.RELEASENOTES
    1.0.0 2026-03-18 Initial version to seed test Intune managedDevice objects using Key Vault-backed Graph app auth
#>

<#
.SYNOPSIS
    Seeds test Intune managedDevice objects for validation and troubleshooting.

.DESCRIPTION
    Creates managedDevice objects in Intune using Microsoft Graph app authentication resolved from Azure Key Vault.
    Optionally links a current primary user to each created device.

    This script does not create Entra sign-in logs. Scripts that depend on auditLogs/signIns, such as
    Set-IntunePrimaryUsers.ps1, will still need real sign-in activity to move beyond device discovery.

.EXAMPLE
    .\New-IntuneManagedDeviceSeed.ps1 -KeyVaultName 'kv-prod-intune' -DeviceCount 5 -DevicePrefix 'LAB-WIN'
    Creates five Windows managedDevice test objects in Intune.

.EXAMPLE
    .\New-IntuneManagedDeviceSeed.ps1 -KeyVaultName 'kv-prod-intune' -DeviceCount 3 -DevicePrefix 'LAB-WIN' -UserPrincipalName 'user@contoso.com'
    Creates three Windows managedDevice test objects and links the specified user as the current primary user.
#>

#Requires -Modules Microsoft.Graph.Authentication
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Azure Key Vault name used to retrieve Microsoft Graph app authentication secrets before connecting")]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultName,

    [Parameter(Mandatory = $false, HelpMessage = "Azure Key Vault secret name containing the Entra ID Tenant ID. Default is 'tenantid'")]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultTenantIdSecretName = 'tenantid',

    [Parameter(Mandatory = $false, HelpMessage = "Azure Key Vault secret name containing the Entra ID Application ID (Client ID). Default is 'clientid'")]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultClientIdSecretName = 'clientid',

    [Parameter(Mandatory = $false, HelpMessage = "Azure Key Vault secret name containing the Entra ID Application Secret. Default is 'secret'")]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultClientSecretSecretName = 'secret',

    [Parameter(Mandatory = $false, HelpMessage = "Number of test devices to create")]
    [ValidateRange(1,200)]
    [int]$DeviceCount = 5,

    [Parameter(Mandatory = $false, HelpMessage = "Device name prefix used for created test devices")]
    [ValidateNotNullOrEmpty()]
    [string]$DevicePrefix = 'LAB-INTUNE',

    [Parameter(Mandatory = $false, HelpMessage = "Starting index for generated device names")]
    [ValidateRange(1,99999)]
    [int]$StartIndex = 1,

    [Parameter(Mandatory = $false, HelpMessage = "Operating system for created devices")]
    [ValidateSet('Windows', 'Android', 'iOS', 'macOS')]
    [string]$OperatingSystem = 'Windows',

    [Parameter(Mandatory = $false, HelpMessage = "Optional user principal name to link as current primary user on created devices")]
    [string]$UserPrincipalName = '',

    [Parameter(Mandatory = $false, HelpMessage = "Ownership type for created devices")]
    [ValidateSet('company', 'personal')]
    [string]$ManagedDeviceOwnerType = 'company',

    [Parameter(Mandatory = $false, HelpMessage = "Last sync age in days to stamp on the created devices")]
    [ValidateRange(0,365)]
    [int]$LastSyncAgeDays = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-GetKeyVaultSecretValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$VaultName,
        [Parameter(Mandatory = $true)][string]$SecretName
    )

    process {
        try {
            if (Get-Command -Name Get-AzKeyVaultSecret -ErrorAction SilentlyContinue) {
                [bool]$UseAzKeyVault = $true
                if (-not (Get-Command -Name Get-AzContext -ErrorAction SilentlyContinue)) {
                    if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
                        $UseAzKeyVault = $false
                    }
                    else {
                        throw "Az.KeyVault is available, but Az.Accounts is missing."
                    }
                }

                if ($UseAzKeyVault) {
                    [object]$AzContext = Get-AzContext -ErrorAction SilentlyContinue
                    if (-not $AzContext) {
                        if (Get-Command -Name Connect-AzAccount -ErrorAction SilentlyContinue) {
                            if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
                                Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
                            }
                            else {
                                throw "No Azure context found for Key Vault access."
                            }
                        }
                        elseif ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
                            $UseAzKeyVault = $false
                        }
                        else {
                            throw "Az.Accounts cmdlets are not available."
                        }
                    }
                }

                if ($UseAzKeyVault) {
                    [object]$Secret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -ErrorAction Stop
                    if ($Secret.PSObject.Properties.Name -contains 'SecretValueText' -and -not [string]::IsNullOrWhiteSpace([string]$Secret.SecretValueText)) {
                        return [string]$Secret.SecretValueText
                    }
                    if ($Secret.SecretValue) {
                        $Bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret.SecretValue)
                        try {
                            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
                        }
                        finally {
                            if ($Bstr -ne [IntPtr]::Zero) {
                                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
                            }
                        }
                    }
                    throw "Secret '$SecretName' in Key Vault '$VaultName' is empty."
                }
            }

            if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
                [string]$VaultResource = "https://vault.azure.net"
                [hashtable]$Headers = @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER; 'Metadata' = 'True' }
                [object]$TokenResponse = Invoke-RestMethod -Uri "$($env:IDENTITY_ENDPOINT)?resource=$VaultResource" -Method GET -Headers $Headers -TimeoutSec 30 -ErrorAction Stop
                if (-not $TokenResponse -or [string]::IsNullOrWhiteSpace($TokenResponse.access_token)) {
                    throw "Failed to retrieve an Azure Key Vault access token from the managed identity endpoint."
                }
                [string]$SecretUri = "https://$VaultName.vault.azure.net/secrets/$SecretName?api-version=7.4"
                [object]$SecretResponse = Invoke-RestMethod -Uri $SecretUri -Method GET -Headers @{ Authorization = "Bearer $($TokenResponse.access_token)" } -TimeoutSec 30 -ErrorAction Stop
                if (-not $SecretResponse -or [string]::IsNullOrWhiteSpace($SecretResponse.value)) {
                    throw "Secret '$SecretName' in Key Vault '$VaultName' is empty."
                }
                return $SecretResponse.value
            }

            throw "Azure Key Vault retrieval requires either Az.KeyVault/Az.Accounts with a valid Azure context or execution with a managed identity."
        }
        catch {
            throw "Failed to retrieve secret '$SecretName' from Key Vault '$VaultName': $($_.Exception.Message)"
        }
    }
}

function Invoke-ConnectMgGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$AuthTenantId,
        [Parameter(Mandatory = $true)][string]$AuthClientId,
        [Parameter(Mandatory = $true)][Object]$AuthClientSecret
    )

    process {
        try {
            [SecureString]$SecureClientSecret = if ($AuthClientSecret -is [SecureString]) { $AuthClientSecret }
            elseif ($AuthClientSecret -is [string]) { ConvertTo-SecureString -String $AuthClientSecret -AsPlainText -Force }
            else { throw "AuthClientSecret must be either a string or SecureString" }

            [System.Management.Automation.PSCredential]$ClientCredential = [System.Management.Automation.PSCredential]::new($AuthClientId, $SecureClientSecret)

            Connect-MgGraph -NoWelcome -TenantId $AuthTenantId -ClientSecretCredential $ClientCredential -ErrorAction Stop | Out-Null
        }
        catch {
            throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        }
    }
}

function Invoke-MgGraphRequestSingle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST')][string]$GraphMethod,
        [Parameter(Mandatory = $true)][string]$GraphObject,
        [Parameter(Mandatory = $false)][string[]]$GraphProperties,
        [Parameter(Mandatory = $false)][string]$GraphFilters,
        [Parameter(Mandatory = $false)][string]$GraphBody
    )

    process {
        [string]$Uri = "https://graph.microsoft.com/beta/$GraphObject"
        [System.Collections.ArrayList]$QueryParts = [System.Collections.ArrayList]::new()
        if ($GraphProperties) { [void]$QueryParts.Add("`$select=$($GraphProperties -join ',')") }
        if ($GraphFilters) { [void]$QueryParts.Add("`$filter=$([System.Web.HttpUtility]::UrlEncode($GraphFilters))") }
        if ($QueryParts.Count -gt 0) { $Uri += '?' + ($QueryParts -join '&') }

        $Params = @{
            Method      = $GraphMethod
            Uri         = $Uri
            ErrorAction = 'Stop'
            OutputType  = 'PSObject'
            Verbose     = $false
        }
        if ($GraphMethod -eq 'POST') {
            $Params['Body'] = $GraphBody
            $Params['Headers'] = @{ 'Content-Type' = 'application/json' }
        }

        return Invoke-MgGraphRequest @Params
    }
}

function Get-OperatingSystemDefaults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OperatingSystem
    )

    process {
        switch ($OperatingSystem) {
            'Windows' {
                return [PSCustomObject]@{
                    DeviceEnrollmentType = 'windowsAzureADJoin'
                    OsVersion            = '11.0.22631.1'
                    Manufacturer         = 'Contoso'
                    Model                = 'VirtualTestPC'
                }
            }
            'Android' {
                return [PSCustomObject]@{
                    DeviceEnrollmentType = 'userEnrollment'
                    OsVersion            = '14'
                    Manufacturer         = 'Contoso Mobile'
                    Model                = 'VirtualAndroid'
                }
            }
            'iOS' {
                return [PSCustomObject]@{
                    DeviceEnrollmentType = 'userEnrollment'
                    OsVersion            = '17.0'
                    Manufacturer         = 'Apple'
                    Model                = 'iPhone Test'
                }
            }
            'macOS' {
                return [PSCustomObject]@{
                    DeviceEnrollmentType = 'appleUserEnrollment'
                    OsVersion            = '14.0'
                    Manufacturer         = 'Apple'
                    Model                = 'Mac Test'
                }
            }
        }
    }
}

[string]$ResolvedAuthTenantId = Invoke-GetKeyVaultSecretValue -VaultName $KeyVaultName -SecretName $KeyVaultTenantIdSecretName
[string]$ResolvedAuthClientId = Invoke-GetKeyVaultSecretValue -VaultName $KeyVaultName -SecretName $KeyVaultClientIdSecretName
[string]$ResolvedAuthClientSecret = Invoke-GetKeyVaultSecretValue -VaultName $KeyVaultName -SecretName $KeyVaultClientSecretSecretName

Invoke-ConnectMgGraph -AuthTenantId $ResolvedAuthTenantId -AuthClientId $ResolvedAuthClientId -AuthClientSecret $ResolvedAuthClientSecret

try {
    [object]$TargetUser = $null
    if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        $TargetUser = Invoke-MgGraphRequestSingle -GraphMethod 'GET' -GraphObject "users/$UserPrincipalName" -GraphProperties @('id', 'userPrincipalName', 'displayName')
        if (-not $TargetUser -or [string]::IsNullOrWhiteSpace($TargetUser.id)) {
            throw "Failed to resolve user '$UserPrincipalName'."
        }
    }

    [object]$OsDefaults = Get-OperatingSystemDefaults -OperatingSystem $OperatingSystem
    [datetime]$LastSyncDateTime = (Get-Date).AddDays(-$LastSyncAgeDays)
    [System.Collections.ArrayList]$CreatedDevices = [System.Collections.ArrayList]::new()

    for ($Index = $StartIndex; $Index -lt ($StartIndex + $DeviceCount); $Index++) {
        [string]$DeviceName = "{0}-{1:D3}" -f $DevicePrefix, $Index
        [string]$AzureAdDeviceId = ([guid]::NewGuid()).Guid
        [string]$SerialNumber = "SEED-{0:D6}" -f $Index

        [hashtable]$GraphBodyObject = @{
            '@odata.type'          = '#microsoft.graph.managedDevice'
            deviceName             = $DeviceName
            managedDeviceName      = $DeviceName
            managedDeviceOwnerType = $ManagedDeviceOwnerType
            operatingSystem        = $OperatingSystem
            managementAgent        = 'mdm'
            deviceEnrollmentType   = $OsDefaults.DeviceEnrollmentType
            osVersion              = $OsDefaults.OsVersion
            manufacturer           = $OsDefaults.Manufacturer
            model                  = $OsDefaults.Model
            serialNumber           = $SerialNumber
            azureADDeviceId        = $AzureAdDeviceId
            azureADRegistered      = $true
            lastSyncDateTime       = $LastSyncDateTime.ToString('o')
            enrolledDateTime       = (Get-Date).ToString('o')
        }

        if ($TargetUser) {
            $GraphBodyObject['userPrincipalName'] = $TargetUser.userPrincipalName
            $GraphBodyObject['userId'] = $TargetUser.id
            $GraphBodyObject['userDisplayName'] = $TargetUser.displayName
            $GraphBodyObject['emailAddress'] = $TargetUser.userPrincipalName
        }

        if ($PSCmdlet.ShouldProcess($DeviceName, "Create Intune managedDevice seed object")) {
            $CreatedDevice = Invoke-MgGraphRequestSingle -GraphMethod 'POST' -GraphObject 'deviceManagement/managedDevices' -GraphBody ($GraphBodyObject | ConvertTo-Json -Depth 10)

            if ($TargetUser -and $CreatedDevice.id) {
                $UserRefBody = @{ '@odata.id' = "https://graph.microsoft.com/beta/users/$($TargetUser.id)" } | ConvertTo-Json
                Invoke-MgGraphRequestSingle -GraphMethod 'POST' -GraphObject "deviceManagement/managedDevices/$($CreatedDevice.id)/users/`$ref" -GraphBody $UserRefBody | Out-Null
            }

            [void]$CreatedDevices.Add([PSCustomObject]@{
                DeviceId        = $CreatedDevice.id
                DeviceName      = $DeviceName
                OperatingSystem = $OperatingSystem
                AzureAdDeviceId = $AzureAdDeviceId
                PrimaryUser     = if ($TargetUser) { $TargetUser.userPrincipalName } else { $null }
            })
        }
    }

    if ($CreatedDevices.Count -gt 0) {
        Write-Output "Created $($CreatedDevices.Count) managedDevice seed object(s)."
        $CreatedDevices | Format-Table -AutoSize
        Write-Warning "These seeded devices do not generate auditLogs/signIns by themselves. Set-IntunePrimaryUsers.ps1 may still report Skipped-NoLogs until real sign-in activity exists."
    }
    else {
        Write-Warning "No devices were created."
    }
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue *>$null
}
