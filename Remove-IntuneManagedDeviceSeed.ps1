<#PSScriptInfo
.VERSION        1.0.0
.GUID           feedbeef-beef-4dad-beef-000000000003
.AUTHOR         Internal
.COPYRIGHT      (c) 2026
.TAGS           Intune Graph ManagedDevice Cleanup MicrosoftGraph Azure
.LICENSEURI     https://opensource.org/licenses/MIT
.PROJECTURI
.RELEASENOTES
    1.0.0 2026-03-18 Initial version to remove seeded Intune managedDevice objects using Key Vault-backed Graph app auth
#>

<#
.SYNOPSIS
    Removes seeded Intune managedDevice test objects.

.DESCRIPTION
    Deletes Intune managedDevice objects by device name prefix or explicit device names.
    Uses Microsoft Graph app authentication resolved from Azure Key Vault.

.EXAMPLE
    .\Remove-IntuneManagedDeviceSeed.ps1 -KeyVaultName 'kv-prod-intune' -DevicePrefix 'LAB-WIN'
    Deletes all managedDevice objects whose device names start with LAB-WIN.

.EXAMPLE
    .\Remove-IntuneManagedDeviceSeed.ps1 -KeyVaultName 'kv-prod-intune' -DeviceNames 'LAB-WIN-001','LAB-WIN-002'
    Deletes the specified managedDevice objects by exact device name.
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

    [Parameter(Mandatory = $false, HelpMessage = "Device name prefix used to find managedDevice objects for cleanup")]
    [string]$DevicePrefix = '',

    [Parameter(Mandatory = $false, HelpMessage = "Exact device names to delete")]
    [string[]]$DeviceNames = @()
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
        [Parameter(Mandatory = $true)][ValidateSet('GET', 'DELETE')][string]$GraphMethod,
        [Parameter(Mandatory = $true)][string]$GraphObject,
        [Parameter(Mandatory = $false)][string[]]$GraphProperties
    )

    process {
        [string]$Uri = "https://graph.microsoft.com/beta/$GraphObject"
        if ($GraphProperties -and $GraphMethod -eq 'GET') {
            $Uri += "?`$select=$($GraphProperties -join ',')"
        }

        return Invoke-MgGraphRequest -Method $GraphMethod -Uri $Uri -ErrorAction Stop -OutputType PSObject -Verbose:$false
    }
}

if ([string]::IsNullOrWhiteSpace($DevicePrefix) -and $DeviceNames.Count -eq 0) {
    throw "Provide either DevicePrefix or DeviceNames."
}

[string]$ResolvedAuthTenantId = Invoke-GetKeyVaultSecretValue -VaultName $KeyVaultName -SecretName $KeyVaultTenantIdSecretName
[string]$ResolvedAuthClientId = Invoke-GetKeyVaultSecretValue -VaultName $KeyVaultName -SecretName $KeyVaultClientIdSecretName
[string]$ResolvedAuthClientSecret = Invoke-GetKeyVaultSecretValue -VaultName $KeyVaultName -SecretName $KeyVaultClientSecretSecretName

Invoke-ConnectMgGraph -AuthTenantId $ResolvedAuthTenantId -AuthClientId $ResolvedAuthClientId -AuthClientSecret $ResolvedAuthClientSecret

try {
    [array]$AllDevices = @(
        Invoke-MgGraphRequestSingle -GraphMethod 'GET' -GraphObject 'deviceManagement/managedDevices' -GraphProperties @('id', 'deviceName', 'operatingSystem', 'azureADDeviceId')
    )

    [array]$TargetDevices = @($AllDevices | Where-Object {
        (
            -not [string]::IsNullOrWhiteSpace($DevicePrefix) -and
            $_.deviceName -like "$DevicePrefix*"
        ) -or (
            $DeviceNames.Count -gt 0 -and
            $_.deviceName -in $DeviceNames
        )
    })

    if ($TargetDevices.Count -eq 0) {
        Write-Warning "No managedDevice objects matched the supplied prefix or names."
        return
    }

    [System.Collections.ArrayList]$RemovedDevices = [System.Collections.ArrayList]::new()
    foreach ($Device in $TargetDevices) {
        if ($PSCmdlet.ShouldProcess($Device.deviceName, "Delete Intune managedDevice")) {
            Invoke-MgGraphRequestSingle -GraphMethod 'DELETE' -GraphObject "deviceManagement/managedDevices/$($Device.id)" | Out-Null
            [void]$RemovedDevices.Add([PSCustomObject]@{
                DeviceId        = $Device.id
                DeviceName      = $Device.deviceName
                OperatingSystem = $Device.operatingSystem
                AzureAdDeviceId = $Device.azureADDeviceId
            })
        }
    }

    if ($RemovedDevices.Count -gt 0) {
        Write-Output "Removed $($RemovedDevices.Count) managedDevice object(s)."
        $RemovedDevices | Format-Table -AutoSize
    }
    else {
        Write-Warning "No devices were removed."
    }
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue *>$null
}
