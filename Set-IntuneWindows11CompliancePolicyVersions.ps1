<#
.SYNOPSIS
    Keeps an Intune Windows 11 compliance policy aligned to supported Windows 11 release builds.

.DESCRIPTION
    This script retrieves the Microsoft Learn Windows 11 release information page in markdown format,
    discovers the currently supported Windows 11 mainstream release families, calculates an N-month lag
    minimum build per family, and updates an existing Intune Windows compliance policy by setting
    validOperatingSystemBuildRanges. When requested, it can create the compliance policy if it does
    not already exist.

    The script can also maintain a dynamic Entra ID device group for Windows 11 devices and ensure the
    compliance policy is assigned to that group.

.EXAMPLE
    .\Set-IntuneWindows11CompliancePolicyVersions.ps1 -Windows11PolicyName "Windows 11 Compliance"

.EXAMPLE
    .\Set-IntuneWindows11CompliancePolicyVersions.ps1 -Windows11PolicyId "00000000-0000-0000-0000-000000000000" -PatchLagMonths 1 -ManageAssignments $true

.EXAMPLE
    .\Set-IntuneWindows11CompliancePolicyVersions.ps1 -Windows11PolicyName "Windows 11 Compliance" -KeyVaultName "kv-prod-intune"

.EXAMPLE
    .\Set-IntuneWindows11CompliancePolicyVersions.ps1 -Windows11PolicyName "Windows 11 Compliance" -CreatePolicyIfMissing $true

.NOTES
    Please feel free to use this, but make sure to credit @MrTbone_se as the original author.
#>

#region ---------------------------------------------------[Set Script Requirements]-----------------------------------------------
#Requires -Modules Microsoft.Graph.Authentication
#Requires -Version 5.1
#endregion

#region ---------------------------------------------------[Modifiable Parameters and Defaults]------------------------------------
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Name of the script action for logging.")]
    [string]$ScriptActionName = "Set Intune Windows 11 Compliance Policy Versions",

    [Parameter(Mandatory = $false, HelpMessage = "Existing Intune compliance policy ID to update.")]
    [ValidateNotNullOrEmpty()]
    [string]$Windows11PolicyId,

    [Parameter(Mandatory = $false, HelpMessage = "Existing Intune compliance policy display name to update.")]
    [ValidateNotNullOrEmpty()]
    [string]$Windows11PolicyName = 'Windows 11 Compliance', 

    [Parameter(Mandatory = $false, HelpMessage = "Create the Windows 11 compliance policy when Windows11PolicyName does not already exist. Default is false.")]
    [bool]$CreatePolicyIfMissing = $false,

    [Parameter(Mandatory = $false, HelpMessage = "Description used when creating a new Windows 11 compliance policy.")]
    [string]$Windows11PolicyDescription = "Windows 11 compliance policy managed by Set-IntuneWindows11CompliancePolicyVersions.ps1",

    [Parameter(Mandatory = $false, HelpMessage = "Number of Patch Tuesday (B) releases to lag behind. Default is 1.")]
    [ValidateRange(0, 6)]
    [int]$PatchLagMonths = 1,

    [Parameter(Mandatory = $false, HelpMessage = "Manage Windows 11 assignment group and policy assignment. Default is true.")]
    [bool]$ManageAssignments = $true,

    [Parameter(Mandatory = $false, HelpMessage = "Display name of the Windows 11 dynamic device group.")]
    [ValidateNotNullOrEmpty()]
    [string]$Windows11GroupName = "Windows 11 Compliance",

    [Parameter(Mandatory = $false, HelpMessage = "Optional override for the Windows 11 dynamic membership rule. Leave blank to generate from supported Windows 11 build branches.")]
    [string]$Windows11GroupMembershipRule,

    [Parameter(Mandatory = $false, HelpMessage = "Microsoft Learn markdown source for Windows 11 release information.")]
    [ValidateNotNullOrEmpty()]
    [string]$ReleaseInfoUri = "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information?accept=text/markdown",

    [Parameter(Mandatory = $false, HelpMessage = "Testmode, same as -WhatIf. Default is false")]
    [bool]$Testmode = $false,
# ==========> Authentication (Invoke-ConnectMgGraph) Leave blank if use Interactive or Managed Identity <==============
    [Parameter(HelpMessage = "Entra ID Tenant ID (directory ID) (required for Client Secret or Certificate authentication)")]
    [ValidateNotNullOrEmpty()]
    [string]$AuthTenantId,

    [Parameter(HelpMessage = "Entra ID Application ID (ClientID) (required for Client Secret or Certificate authentication)")]
    [ValidateNotNullOrEmpty()]
    [string]$AuthClientId,

    [Parameter(HelpMessage = "Client Secret as SecureString or string for app-only authentication (require also ClientId and TenantId)")]
    [ValidateNotNull()]
    [object]$AuthClientSecret,

    [Parameter(HelpMessage = "Certificate thumbprint for certificate-based authentication (if certificate is stored in CurrentUser or LocalMachine store)")]
    [ValidateNotNullOrEmpty()]
    [string]$AuthCertThumbprint,

    [Parameter(HelpMessage = "Certificate subject name for certificate-based authentication (if certificate is stored in CurrentUser or LocalMachine store)")]
    [ValidateNotNullOrEmpty()]
    [string]$AuthCertName,

    [Parameter(HelpMessage = "File path to certificate (.pfx or .cer) for certificate-based authentication (if certificate is stored as a file)")]
    [ValidateNotNullOrEmpty()]
    [string]$AuthCertPath,

    [Parameter(HelpMessage = "Password for certificate file as SecureString (required if certificate is stored as a file and password-protected)")]
    [SecureString]$AuthCertPassword,

    [Parameter(HelpMessage = "Azure Key Vault name used to retrieve app authentication secrets before connecting to Microsoft Graph")]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultName = 'SharedAutomationKV',

    [Parameter(HelpMessage = "Azure Key Vault secret name containing the Entra ID Tenant ID. Default is 'tenantid'")]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultTenantIdSecretName = 'Intune-Automation-SP-tenantid',

    [Parameter(HelpMessage = "Azure Key Vault secret name containing the Entra ID Application ID (Client ID). Default is 'clientid'")]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultClientIdSecretName = 'Intune-Automation-SP-clientid',

    [Parameter(HelpMessage = "Azure Key Vault secret name containing the Entra ID Application Secret. Default is 'secret'")]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultClientSecretSecretName = 'Intune-Automation-SP-secret',
# ==========> Logging (Invoke-TboneLog) <==============================================================================
    [Parameter(Mandatory = $false, HelpMessage = 'Name of Log, to set name for Eventlog and Filelog')]
    [string]$LogName = "",

    [Parameter(Mandatory = $false, HelpMessage = 'Show output in console during execution')]
    [bool]$LogToGUI = $true,

    [Parameter(Mandatory = $false, HelpMessage = 'Write complete log array to Windows Event when script ends')]
    [bool]$LogToEventlog = $false,

    [Parameter(Mandatory = $false, HelpMessage = 'EventLog IDs as hashtable: @{Info=11001; Warn=11002; Error=11003}')]
    [hashtable]$LogEventIds = @{Info=11001; Warn=11002; Error=11003},

    [Parameter(Mandatory = $false, HelpMessage = 'Return complete log array as Host output when script ends (Good for Intune Remediations)')]
    [bool]$LogToHost = $false,

    [Parameter(Mandatory = $false, HelpMessage = 'Write complete log array to Disk when script ends')]
    [bool]$LogToDisk = $false,

    [Parameter(Mandatory = $false, HelpMessage = 'Path where Disk logs are saved (if LogToDisk is enabled)')]
    [string]$LogToDiskPath = "",

    [Parameter(Mandatory = $false, HelpMessage = "Enable verbose logging. Default is false")]
    [bool]$LogVerboseEnabled = $false,
# ==========> Reporting (Invoke-ScriptReport) <========================================================================
    [Parameter(Mandatory = $false, HelpMessage = "Title of the report")]
    [string]$ReportTitle = "",

    [Parameter(Mandatory = $false, HelpMessage = "Return report with statistics on how many changed objects. Default is true")]
    [bool]$ReportEnabled = $true,

    [Parameter(Mandatory = $false, HelpMessage = "Include detailed object changes in the report. Default is true")]
    [bool]$ReportDetailed = $true,

    [Parameter(Mandatory = $false, HelpMessage = "Save report to disk. Default is false")]
    [bool]$ReportToDisk = $false,

    [Parameter(Mandatory = $false, HelpMessage = "Path where to save the report when ReportToDisk is enabled")]
    [string]$ReportToDiskPath = "",
# ==========> Throttling and Retry (Invoke-MgGraphRequestSingle) <=====================================================
    [Parameter(Mandatory = $false, HelpMessage = "Wait time in milliseconds between throttled requests. Default is 1000")]
    [ValidateRange(100, 5000)]
    [int]$GraphWaitTime = 1000,

    [Parameter(Mandatory = $false, HelpMessage = "Maximum number of retry attempts for failed requests. Default is 3")]
    [ValidateRange(1, 10)]
    [int]$GraphMaxRetry = 3
)
#endregion

#region ---------------------------------------------------[Modifiable Variables and defaults]------------------------------------
[System.Collections.ArrayList]$RequiredScopes = @(
    "DeviceManagementConfiguration.ReadWrite.All",
    "Group.ReadWrite.All"
)
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
[bool]$HasExplicitGraphAuthInput = (
    -not [string]::IsNullOrWhiteSpace($AuthTenantId) -or
    -not [string]::IsNullOrWhiteSpace($AuthClientId) -or
    $null -ne $AuthClientSecret -or
    -not [string]::IsNullOrWhiteSpace($AuthCertThumbprint) -or
    -not [string]::IsNullOrWhiteSpace($AuthCertName) -or
    -not [string]::IsNullOrWhiteSpace($AuthCertPath)
)
[bool]$HasKeyVaultGraphAuthInput = -not [string]::IsNullOrWhiteSpace($KeyVaultName)
if (
    $env:IDENTITY_ENDPOINT -and
    $env:IDENTITY_HEADER -and
    $PSVersionTable.PSVersion -eq [version]"7.2.0" -and
    -not ($HasExplicitGraphAuthInput -or $HasKeyVaultGraphAuthInput)
) {
    Write-Error "This script cannot use Microsoft Graph managed identity authentication in PowerShell 7.2. Use a different PowerShell version or provide app or certificate authentication."
    exit 1
}

Set-StrictMode -Version Latest

[System.Management.Automation.ActionPreference]$script:OriginalErrorActionPreference = $ErrorActionPreference
[System.Management.Automation.ActionPreference]$script:OriginalVerbosePreference = $VerbosePreference
[bool]$script:OriginalWhatIfPreference = $WhatIfPreference

if ($LogVerboseEnabled) { $VerbosePreference = 'Continue' }
else { $VerbosePreference = 'SilentlyContinue' }
if ($Testmode) { $WhatIfPreference = 1 }
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
[string]$ModuleName = 'Microsoft.Graph.Authentication'
if (-not (Get-Module -Name $ModuleName)) {
    try {
        & { $VerbosePreference = 'SilentlyContinue'; Import-Module $ModuleName -ErrorAction Stop }
        Write-Verbose "Imported $ModuleName v$((Get-Module -Name $ModuleName).Version)"
    }
    catch {
        if ($_.Exception -is [System.TypeLoadException] -or $_.Exception.Message -match 'does not have an implementation') {
            Write-Warning "Module version conflict detected - cleaning up and retrying"
            & { $VerbosePreference = 'SilentlyContinue'; Get-Module Microsoft.Graph.* | Remove-Module -Force -ErrorAction SilentlyContinue }
            [version]$LatestVersion = (Get-Module -Name $ModuleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version
            & { $VerbosePreference = 'SilentlyContinue'; Import-Module $ModuleName -RequiredVersion $LatestVersion -Force -ErrorAction Stop }
            Write-Verbose "Resolved conflict - imported $ModuleName v$LatestVersion"
        }
        else { throw }
    }
}
else { Write-Verbose "Module '$ModuleName' already loaded v$((Get-Module -Name $ModuleName).Version)" }
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($LogName)) { [string]$LogName = $ScriptActionName }
if ([string]::IsNullOrWhiteSpace($ReportTitle)) { [string]$ReportTitle = $ScriptActionName }
[string]$DefaultTempPath = [System.IO.Path]::GetTempPath()
if ([string]::IsNullOrWhiteSpace($DefaultTempPath)) { $DefaultTempPath = '/tmp' }
if ($LogToDisk -and [string]::IsNullOrWhiteSpace($LogToDiskPath)) { $LogToDiskPath = $DefaultTempPath }
if ($ReportToDisk -and [string]::IsNullOrWhiteSpace($ReportToDiskPath)) { $ReportToDiskPath = $DefaultTempPath }
[datetime]$ReportStartTime = ([DateTime]::Now)
[hashtable]$ReportResults = @{}
[scriptblock]$AddReport = {
    param($Target, $OldValue, $NewValue, $Action, $Details)
    if (-not $ReportResults.ContainsKey($Action)) { $ReportResults[$Action] = [System.Collections.ArrayList]::new() }
    $null = $ReportResults[$Action].Add([PSCustomObject]@{Target = $Target; OldValue = $OldValue; NewValue = $NewValue; Action = $Action; Details = $Details })
}
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
function Invoke-ConnectMgGraph {
    [CmdletBinding()]
    param (
        [string[]]$RequiredScopes = @("User.Read.All"),
        [string]$AuthTenantId,
        [string]$AuthClientId,
        [object]$AuthClientSecret,
        [string]$AuthCertName,
        [string]$AuthCertThumbprint,
        [string]$AuthCertPath,
        [SecureString]$AuthCertPassword
    )

    begin {
        $ErrorActionPreference = 'Stop'
        [string]$ResourceURL = "https://graph.microsoft.com/"
        [bool]$HasClientId = -not [string]::IsNullOrWhiteSpace($AuthClientId)
        [bool]$HasTenantId = -not [string]::IsNullOrWhiteSpace($AuthTenantId)
        [bool]$HasClientSecret = $null -ne $AuthClientSecret
        [bool]$HasCertInput = -not [string]::IsNullOrWhiteSpace($AuthCertThumbprint) -or -not [string]::IsNullOrWhiteSpace($AuthCertName) -or -not [string]::IsNullOrWhiteSpace($AuthCertPath)

        [string]$AuthMethod = if ($HasClientSecret -and $HasClientId -and $HasTenantId) { 'ClientSecret' }
        elseif ($HasCertInput -and $HasClientId -and $HasTenantId) { 'Certificate' }
        elseif ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) { 'ManagedIdentity' }
        else { 'Interactive' }
        Write-Verbose "Using authentication method: $AuthMethod"
    }

    process {
        try {
            try {
                $Context = Get-MgContext -ErrorAction SilentlyContinue
                if ($Context) {
                    if ($AuthMethod -eq 'Interactive') {
                        [string[]]$MissingScopes = @($RequiredScopes | Where-Object { $_ -notin @($Context.Scopes) })
                        if ($MissingScopes.Count -eq 0) { return $Context.Account }
                        Disconnect-MgGraph -ErrorAction SilentlyContinue
                    }
                    else {
                        [string]$ContextTenantId = [string]$Context.TenantId
                        [string]$ContextClientId = [string]$Context.ClientId
                        [bool]$TenantMatches = ([string]::IsNullOrWhiteSpace($AuthTenantId) -or $ContextTenantId -eq $AuthTenantId)
                        [bool]$ClientMatches = ([string]::IsNullOrWhiteSpace($AuthClientId) -or $ContextClientId -eq $AuthClientId)
                        if ($TenantMatches -and $ClientMatches) {
                            return $Context.Account
                        }
                        Disconnect-MgGraph -ErrorAction SilentlyContinue
                    }
                }
            }
            catch { Write-Verbose "No reusable Graph context found" }

            $ConnectParams = @{ NoWelcome = $true }

            switch ($AuthMethod) {
                'ManagedIdentity' {
                    [version]$GraphVersion = (Get-Module -Name 'Microsoft.Graph.Authentication' -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version
                    if ($GraphVersion -ge [version]"2.0.0") {
                        $ConnectParams['Identity'] = $true
                    }
                    else {
                        [hashtable]$Headers = @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER; 'Metadata' = 'True' }
                        $Response = Invoke-RestMethod -Uri "$($env:IDENTITY_ENDPOINT)?resource=$ResourceURL" -Method GET -Headers $Headers -TimeoutSec 30 -ErrorAction Stop
                        if (-not $Response -or [string]::IsNullOrWhiteSpace($Response.access_token)) {
                            throw "Failed to retrieve access token from managed identity endpoint"
                        }
                        $ConnectParams['AccessToken'] = $Response.access_token
                    }
                }
                'ClientSecret' {
                    [SecureString]$SecureClientSecret = if ($AuthClientSecret -is [SecureString]) { $AuthClientSecret }
                    elseif ($AuthClientSecret -is [string]) { ConvertTo-SecureString -String $AuthClientSecret -AsPlainText -Force }
                    else { throw "AuthClientSecret must be either a string or SecureString" }
                    [System.Management.Automation.PSCredential]$ClientCredential = [System.Management.Automation.PSCredential]::new($AuthClientId, $SecureClientSecret)
                    $ConnectParams['TenantId'] = $AuthTenantId
                    $ConnectParams['ClientSecretCredential'] = $ClientCredential
                }
                'Certificate' {
                    $ConnectParams['ClientId'] = $AuthClientId
                    $ConnectParams['TenantId'] = $AuthTenantId
                    if ($AuthCertThumbprint) { $ConnectParams['CertificateThumbprint'] = $AuthCertThumbprint }
                    elseif ($AuthCertName) { $ConnectParams['CertificateName'] = $AuthCertName }
                    elseif ($AuthCertPath) {
                        if (-not (Test-Path $AuthCertPath)) { throw "Certificate file not found: $AuthCertPath" }
                        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert = $null
                        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]$KeyFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
                        if ($AuthCertPassword) {
                            $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($AuthCertPath, $AuthCertPassword, $KeyFlags)
                        }
                        else {
                            $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($AuthCertPath, [string]::Empty, $KeyFlags)
                        }
                        if (-not $Cert.HasPrivateKey) { throw "Certificate does not contain a private key" }
                        $ConnectParams['Certificate'] = $Cert
                    }
                }
                'Interactive' {
                    $ConnectParams['Scopes'] = @($RequiredScopes)
                }
            }

            Connect-MgGraph @ConnectParams -ErrorAction Stop
            if ($AuthMethod -eq 'Interactive' -and @($RequiredScopes).Count -gt 0) {
                [string[]]$MissingScopes = @($RequiredScopes | Where-Object { $_ -notin @(Get-MgContext).Scopes })
                if ($MissingScopes.Count -gt 0) { throw "Missing required scopes: $($MissingScopes -join ', ')" }
            }
            return (Get-MgContext).Account
        }
        catch {
            Write-Error "Connection failed: $($_.Exception.Message)"
            throw
        }
    }
}

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

function Invoke-TboneLog {
    [CmdletBinding()]
    param(
        [ValidateSet('Start', 'Stop')]
        [string]$LogMode,
        [string]$LogName = "PowerShellScript",
        [bool]$LogToGUI = $true,
        [bool]$LogToEventlog = $true,
        [hashtable]$LogEventIds = @{Info = 11001; Warn = 11002; Error = 11003},
        [bool]$LogToHost = $true,
        [bool]$LogToDisk = $false,
        [string]$LogPath = ""
    )

    if (!$LogMode) { $LogMode = if (Get-Variable -Name _l -Scope Global -EA 0) { 'Stop' } else { 'Start' } }
    if ($LogToDisk -and !$LogPath) {
        $ExistingLogPath = Get-Variable -Name _p -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        $LogPath = if ($ExistingLogPath) { $ExistingLogPath } elseif ($env:TEMP) { $env:TEMP } else { '/tmp' }
    }

    if ($LogMode -eq 'Stop') {
        if ((Get-Variable -Name _l -Scope Global -EA 0) -and (Test-Path function:\global:_Save)) {
            _Save
            $ReturnLogsToHost = Get-Variable -Name _r -Scope Global -ValueOnly -ErrorAction SilentlyContinue
            if ($ReturnLogsToHost) { , $global:_l.ToArray() }
        }
        Unregister-Event -SourceIdentifier PowerShell.Exiting -ea 0 -WhatIf:$false
        if (Test-Path function:\global:_Clean) { _Clean }
        return
    }

    if ($LogMode -eq 'Start') {
        $global:_az = $env:AZUREPS_HOST_ENVIRONMENT -or $env:AUTOMATION_ASSET_ACCOUNTID
        $global:_l = [Collections.Generic.List[string]]::new()
        $global:_g = $LogToGUI
        $global:_s = $Logname
        $global:_n = "{0}-{1:yyyyMMdd-HHmmss}" -f $Logname, (Get-Date)
        $global:_p = $LogPath
        $global:_d = $LogToDisk
        $global:_e = $LogToEventlog
        $global:_i = $LogEventIds
        $global:_r = $LogToHost
        $global:_w = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
        if (!(Test-Path function:\global:_Time)) { function global:_Time { Get-Date -f 'yyyy-MM-dd,HH:mm:ss' } }
        if (!(Test-Path function:\global:_ID)) { function global:_ID { $c = (Get-PSCallStack)[2]; $n = if ($c.Command -and $c.Command -ne '<ScriptBlock>') { $c.Command } elseif ($c.FunctionName -and $c.FunctionName -ne '<ScriptBlock>') { $c.FunctionName } else { 'Main-Script' }; if ($n -like '*.ps1') { 'Main-Script' } else { $n } } }
        if (!(Test-Path function:\global:_Save)) { function global:_Save { try { if ($global:_d -and -not [string]::IsNullOrWhiteSpace($global:_p)) { [IO.Directory]::CreateDirectory($global:_p) | Out-Null; [IO.File]::WriteAllLines((Join-Path $global:_p "$($global:_n).log"), $global:_l.ToArray()) }; if ($global:_e -and $global:_w) { $isAdmin = $false; try { $id = [Security.Principal.WindowsIdentity]::GetCurrent(); $isAdmin = ([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) } catch { }; $la = $global:_l -join "`n"; $h = $la -match ',ERROR,'; $et = if ($h) { 'Error' } elseif ($la -match ',WARN,') { 'Warning' } else { 'Information' }; $eid = if ($h) { $global:_i.Error } elseif ($la -match ',WARN,') { $global:_i.Warn } else { $global:_i.Info }; $ok = $false; try { Write-EventLog -LogName Application -Source $global:_s -EventId $eid -EntryType $et -Message $la -EA Stop; $ok = $true } catch { }; if (-not $ok -and $isAdmin) { try { [Diagnostics.EventLog]::CreateEventSource($global:_s, 'Application') } catch { }; try { Write-EventLog -LogName Application -Source $global:_s -EventId $eid -EntryType $et -Message $la } catch { } } } } catch { } } }
        if (!(Test-Path function:\global:_Clean)) { function global:_Clean { $WhatIfPreference = $false; Remove-Item -Path function:\Write-Host, function:\Write-Output, function:\Write-Warning, function:\Write-Error, function:\Write-Verbose, function:\_Save, function:\_Clean, function:\_ID, function:\_Time -ea 0 -Force; Remove-Variable -Name _l, _g, _s, _n, _p, _d, _e, _i, _r, _w, _az -Scope Global -ea 0 } }
        $null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { if ($global:_l) { try { _Save } catch { } }; if (Test-Path function:\_Clean) { _Clean } } -MaxTriggerCount 1
        function Script:Write-Host { $m = "$args"; $c = (Get-PSCallStack)[1]; $r = "Row$($c.ScriptLineNumber)"; $e = "$(_Time),INFO,$r,$(_ID),$m"; $global:_l.Add($e); if ($global:_g) { if ($global:_az) { Microsoft.PowerShell.Utility\Write-Output $m } else { Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Green } } }
        function Script:Write-Output { $m = "$args"; $c = (Get-PSCallStack)[1]; $r = "Row$($c.ScriptLineNumber)"; $e = "$(_Time),OUTPUT,$r,$(_ID),$m"; $global:_l.Add($e); if ($global:_g) { if ($global:_az) { Microsoft.PowerShell.Utility\Write-Output $m } else { Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Green } } }
        function Script:Write-Verbose { $m = "$args"; $c = (Get-PSCallStack)[1]; $r = "Row$($c.ScriptLineNumber)"; $e = "$(_Time),VERBOSE,$r,$(_ID),$m"; $global:_l.Add($e); if ($global:_g -and $VerbosePreference -ne 'SilentlyContinue') { if ($global:_az) { Microsoft.PowerShell.Utility\Write-Verbose $m } else { Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Cyan } } }
        function Script:Write-Warning { $m = "$args"; $c = (Get-PSCallStack)[1]; $r = "Row$($c.ScriptLineNumber)"; $e = "$(_Time),WARN,$r,$(_ID),$m"; $global:_l.Add($e); if ($global:_g) { if ($global:_az) { Microsoft.PowerShell.Utility\Write-Warning $m } else { Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Yellow } }; if ($WarningPreference -eq 'Stop') { _Save; _Clean; exit } }
        function Script:Write-Error { $m = "$args"; $c = (Get-PSCallStack)[1]; $r = "Row$($c.ScriptLineNumber)"; $e = "$(_Time),ERROR,$r,$(_ID),$m"; $global:_l.Add($e); if ($global:_g) { if ($global:_az) { Microsoft.PowerShell.Utility\Write-Error $m } else { Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Red } }; if ($ErrorActionPreference -eq 'Stop') { _Save; _Clean; exit } }
    }
}

function Invoke-MgGraphRequestSingle {
    [CmdletBinding()]
    param(
        [ValidateSet('beta', 'v1.0')]
        [string]$GraphRunProfile = "v1.0",

        [ValidateSet('GET', 'PATCH', 'POST', 'DELETE')]
        [string]$GraphMethod = "GET",

        [Parameter(Mandatory = $true)]
        [string]$GraphObject,

        [string]$GraphBody,
        [string[]]$GraphProperties,
        [string]$GraphFilters,
        [int]$GraphPageSize = 999,
        [bool]$GraphSkipPagination = $false,
        [bool]$GraphCount = $false,
        [ValidateRange(100, 5000)]
        [int]$GraphWaitTime = 1000,
        [ValidateRange(1, 10)]
        [int]$GraphMaxRetry = 3
    )

    begin { $ErrorActionPreference = 'Stop' }

    process {
        $BaseUri = "https://graph.microsoft.com/$GraphRunProfile/$GraphObject"
        [System.Collections.ArrayList]$Results = [System.Collections.ArrayList]::new()
        [string]$NextUri = $BaseUri
        [int]$Attempt = 0

        if ($GraphMethod -eq 'GET') {
            [System.Collections.ArrayList]$QueryParts = [System.Collections.ArrayList]::new()
            if ($GraphProperties -and $GraphProperties.Count -gt 0) { [void]$QueryParts.Add("`$select=$([uri]::EscapeDataString(($GraphProperties -join ',')))") }
            if (-not [string]::IsNullOrWhiteSpace($GraphFilters)) { [void]$QueryParts.Add("`$filter=$([uri]::EscapeDataString($GraphFilters))") }
            if ($GraphCount) { [void]$QueryParts.Add("`$count=true") }
            if ($GraphPageSize -gt 0) { [void]$QueryParts.Add("`$top=$GraphPageSize") }
            if ($QueryParts.Count -gt 0) {
                $NextUri = "${BaseUri}?$(($QueryParts -join '&'))"
            }
        }

        do {
            try {
                $Params = @{
                    Method      = $GraphMethod
                    Uri         = $NextUri
                    OutputType  = 'PSObject'
                    ErrorAction = 'Stop'
                }
                if ($GraphMethod -ne 'GET' -and -not [string]::IsNullOrWhiteSpace($GraphBody)) {
                    $Params['Body'] = $GraphBody
                    $Params['ContentType'] = 'application/json'
                }
                if ($GraphMethod -eq 'GET' -and $GraphCount) {
                    $Params['Headers'] = @{ ConsistencyLevel = 'eventual' }
                }

                $Response = Invoke-MgGraphRequest @Params
                $Attempt = 0

                if ($GraphMethod -ne 'GET') { return $Response }
                if ($null -eq $Response) { return $null }
                if ($GraphSkipPagination) {
                    if ($Response.PSObject.Properties.Name -contains 'value') { return $Response.value }
                    return $Response
                }

                if ($Response.PSObject.Properties.Name -contains 'value') {
                    [void]$Results.AddRange(@($Response.value))
                    if ($Response.PSObject.Properties.Name -contains '@odata.nextLink') {
                        $NextUri = $Response.'@odata.nextLink'
                    }
                    else {
                        $NextUri = $null
                    }
                }
                else {
                    [void]$Results.Add($Response)
                    $NextUri = $null
                }
            }
            catch {
                $Attempt++
                if ($Attempt -gt $GraphMaxRetry) { throw }
                [int]$StatusCode = 0
                if ($null -ne $_.Exception -and $null -ne $_.Exception.PSObject.Properties['Response'] -and $null -ne $_.Exception.Response) {
                    $StatusCode = $_.Exception.Response.StatusCode.value__
                }
                $ShouldRetry = ($StatusCode -eq 429 -or $StatusCode -eq 503 -or $StatusCode -eq 504 -or $_.Exception.Message -match 'too many requests')
                if (-not $ShouldRetry) { throw }
                Start-Sleep -Milliseconds ($GraphWaitTime * [math]::Pow(2, $Attempt - 1))
            }
        } while ($NextUri)

        return @($Results)
    }
}

function Invoke-ScriptReport {
    [CmdletBinding()]
    param(
        [string]$ReportTitle = "Script Execution Report",
        [hashtable]$ReportResults,
        [datetime]$ReportStartTime,
        [bool]$ReportDetailed = $false,
        [bool]$ReportToDisk = $false,
        [string]$ReportToDiskPath = "",
        [ValidateSet('JSON', 'CSV')]
        [string]$ReportFormat = 'CSV'
    )

    process {
        [datetime]$ReportEndTime = [DateTime]::Now
        [timespan]$Duration = $ReportEndTime - $ReportStartTime
        [string]$DurationFormatted = $Duration.ToString("hh\:mm\:ss")
        [array]$SortedActions = @($ReportResults.Keys | Sort-Object)
        [int]$TotalObjects = 0
        [System.Collections.Specialized.OrderedDictionary]$ActionSummary = [ordered]@{}
        foreach ($Action in $SortedActions) {
            [int]$Count = $ReportResults[$Action].Count
            $ActionSummary[$Action] = $Count
            $TotalObjects += $Count
        }

        if ($ReportDetailed -and $TotalObjects -gt 0) {
            [System.Collections.ArrayList]$AllEntries = [System.Collections.ArrayList]::new($TotalObjects)
            foreach ($Action in $SortedActions) { [void]$AllEntries.AddRange(@($ReportResults[$Action])) }
            [array]$SortedEntries = @($AllEntries | Sort-Object -Property Action, Target)
            [object]$TableOutput = $SortedEntries | Format-Table -Property `
                @{Name = 'Target'; Expression = { $_.Target }; Alignment = 'Left' },
                @{Name = 'OldValue'; Expression = { $_.OldValue }; Alignment = 'Left' },
                @{Name = 'NewValue'; Expression = { $_.NewValue }; Alignment = 'Left' },
                @{Name = 'Action'; Expression = { $_.Action }; Alignment = 'Left' },
                @{Name = 'Details'; Expression = { $_.Details }; Alignment = 'Left' } -AutoSize -Wrap
            $TableOutput | Out-String -Stream -Width 250 | ForEach-Object { Write-Output $_ }
        }

        Write-Output "═══════════════════════════════════════════════════════════"
        Write-Output "  $ReportTitle"
        Write-Output "═══════════════════════════════════════════════════════════"
        Write-Output "  Start:    $($ReportStartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        Write-Output "  End:      $($ReportEndTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        Write-Output "  Duration: $DurationFormatted"
        Write-Output "───────────────────────────────────────────────────────────"
        Write-Output "  Summary"
        foreach ($Action in $ActionSummary.Keys) {
            [int]$Count = $ActionSummary[$Action]
            [double]$Percentage = if ($TotalObjects -gt 0) { [math]::Round(($Count / $TotalObjects) * 100, 1) } else { 0 }
            Write-Output (("    {0,-30}: {1,6} ({2,5}" -f $Action, $Count, $Percentage) + '%)')
        }
        Write-Output ("    {0,-30}: {1,6}" -f "Total Objects", $TotalObjects)
        Write-Output "═══════════════════════════════════════════════════════════"

        if ($ReportToDisk) {
            if ([string]::IsNullOrWhiteSpace($ReportToDiskPath)) {
                [string]$BaseReportPath = if ($env:TEMP) { $env:TEMP } else { '/tmp' }
                $ReportToDiskPath = Join-Path $BaseReportPath 'Reports'
            }
            if (-not (Test-Path $ReportToDiskPath)) { New-Item -ItemType Directory -Path $ReportToDiskPath -Force -ErrorAction Stop | Out-Null }
            [string]$Timestamp = $ReportEndTime.ToString('yyyyMMdd_HHmmss')
            [string]$CleanAction = $ReportTitle -replace '[^\w\-]', '_'
            [string]$BaseFileName = "Report_$($CleanAction)_$Timestamp"

            [System.Collections.ArrayList]$AllResults = [System.Collections.ArrayList]::new()
            foreach ($List in $ReportResults.Values) { [void]$AllResults.AddRange($List) }

            if ($ReportFormat -eq 'JSON') {
                $ReportData = [PSCustomObject]@{
                    ReportTitle    = $ReportTitle
                    StartTime      = $ReportStartTime.ToString('yyyy-MM-dd HH:mm:ss')
                    EndTime        = $ReportEndTime.ToString('yyyy-MM-dd HH:mm:ss')
                    Duration       = $DurationFormatted
                    TotalProcessed = $TotalObjects
                    ActionSummary  = $ActionSummary
                    DetailedResults = $AllResults
                }
                $OutPath = Join-Path $ReportToDiskPath "$BaseFileName.json"
                $ReportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutPath -Force -Encoding utf8
                Write-Output "Report saved: $OutPath"
            }
            else {
                $OutPath = Join-Path $ReportToDiskPath "$BaseFileName.csv"
                $AllResults | Export-Csv -Path $OutPath -NoTypeInformation -Force -Encoding UTF8
                Write-Output "Report saved: $OutPath"
            }
        }
    }
}

function ConvertTo-EscapedODataString {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Value)
    return $Value.Replace("'", "''")
}

function Invoke-GetWebContent {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Uri)

    process {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
        catch { }

        try {
            $Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -Headers @{ 'User-Agent' = 'PowerShell Intune Windows 11 Compliance Policy Updater' } -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($Response.Content)) { throw "Response body was empty." }
            return $Response.Content
        }
        catch {
            throw "Failed to download '$Uri': $($_.Exception.Message)"
        }
    }
}

function Get-Windows11SupportedReleaseMatrix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$MarkdownContent,
        [ValidateRange(0, 6)][int]$PatchLagMonths = 1
    )

    process {
        [regex]$ServicingBlockRegex = [regex]'(?ms)#### Servicing channels\s+(?<Block>\|.*?)(?=^#### Enterprise and IoT Enterprise LTSC editions)'
        $ServicingBlockMatch = $ServicingBlockRegex.Match($MarkdownContent)
        if (-not $ServicingBlockMatch.Success) {
            throw "Failed to locate the 'Servicing channels' table in the Windows 11 release information source."
        }

        [System.Collections.ArrayList]$SupportedVersions = [System.Collections.ArrayList]::new()
        foreach ($Line in ($ServicingBlockMatch.Groups['Block'].Value -split "`r?`n")) {
            if ($Line -notmatch '^\|') { continue }
            if ($Line -match '^\|\s*---') { continue }
            [string[]]$Columns = @($Line.Trim('|').Split('|') | ForEach-Object { $_.Trim() })
            if ($Columns.Count -lt 8 -or $Columns[0] -eq 'Version') { continue }
            if ($Columns[1] -notmatch 'General Availability Channel') { continue }
            if ($Columns[3] -eq 'End of updates' -and $Columns[4] -eq 'End of updates') { continue }
            [void]$SupportedVersions.Add([PSCustomObject]@{
                Version = $Columns[0]
                LatestBuild = $Columns[7]
                LatestRevisionDate = $Columns[6]
            })
        }

        if ($SupportedVersions.Count -eq 0) {
            throw "No supported Windows 11 mainstream versions were found in the servicing table."
        }

        [regex]$HistoryRegex = [regex]'(?ms)^\*\*Version (?<Version>[0-9A-Za-z]+) \(OS build (?<BaseBuild>\d+)\)\*\*(?<Body>.*?)(?=^\*\*Version |\z)'
        [System.Collections.ArrayList]$ReleaseMatrix = [System.Collections.ArrayList]::new()

        foreach ($SupportedVersion in $SupportedVersions) {
            $VersionMatch = $HistoryRegex.Matches($MarkdownContent) | Where-Object { $_.Groups['Version'].Value -eq $SupportedVersion.Version } | Select-Object -First 1
            if (-not $VersionMatch) {
                throw "Failed to locate the release history section for Windows 11 version $($SupportedVersion.Version)."
            }

            [string]$SectionBody = $VersionMatch.Groups['Body'].Value
            [string]$BaseBuild = $VersionMatch.Groups['BaseBuild'].Value
            [System.Collections.ArrayList]$AllBuildRows = [System.Collections.ArrayList]::new()
            [System.Collections.ArrayList]$BReleaseRows = [System.Collections.ArrayList]::new()

            foreach ($Line in ($SectionBody -split "`r?`n")) {
                if ($Line -notmatch '^\|') { continue }
                if ($Line -match '^\|\s*---') { continue }
                [string[]]$Columns = @($Line.Trim('|').Split('|') | ForEach-Object { $_.Trim() })
                if ($Columns.Count -lt 5 -or $Columns[0] -eq 'Servicing option') { continue }
                if ($Columns[3] -notmatch '^\d+\.\d+$') { continue }
                [datetime]$AvailabilityDate = [datetime]::Parse($Columns[2], [System.Globalization.CultureInfo]::InvariantCulture)
                [PSCustomObject]$Row = [PSCustomObject]@{
                    UpdateType = $Columns[1]
                    AvailabilityDate = $AvailabilityDate
                    Build = $Columns[3]
                }
                [void]$AllBuildRows.Add($Row)
                if ($Columns[1] -match '^\d{4}-\d{2} B$') { [void]$BReleaseRows.Add($Row) }
            }

            if ($AllBuildRows.Count -eq 0) {
                throw "No build history rows were found for Windows 11 version $($SupportedVersion.Version)."
            }

            [array]$SortedAllBuildRows = @($AllBuildRows | Sort-Object AvailabilityDate, Build)
            [array]$SortedBReleaseRows = @($BReleaseRows | Sort-Object -Property `
                @{ Expression = 'AvailabilityDate'; Descending = $true },
                @{ Expression = 'Build'; Descending = $true })
            [object]$SelectedBaseline = $null
            [string]$SelectionReason = ""

            if ($SortedBReleaseRows.Count -gt $PatchLagMonths) {
                $SelectedBaseline = $SortedBReleaseRows[$PatchLagMonths]
                $SelectionReason = "LaggedBRelease"
            }
            else {
                $SelectedBaseline = $SortedAllBuildRows[0]
                $SelectionReason = "FallbackEarliestAvailable"
            }

            [void]$ReleaseMatrix.Add([PSCustomObject]@{
                Version = $SupportedVersion.Version
                BaseBuild = $BaseBuild
                LatestBuild = $SupportedVersion.LatestBuild
                LowestVersion = "10.0.$($SelectedBaseline.Build)"
                HighestVersion = "10.0.$BaseBuild.65535"
                LowestBuild = $SelectedBaseline.Build
                LowestBuildDate = $SelectedBaseline.AvailabilityDate.ToString('yyyy-MM-dd')
                SelectionReason = $SelectionReason
                Description = "Windows 11 $($SupportedVersion.Version)"
            })
        }

        return @($ReleaseMatrix | Sort-Object {[int]$_.BaseBuild})
    }
}

function Get-Windows11GroupMembershipRuleFromReleaseMatrix {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$ReleaseMatrix)

    process {
        [array]$BranchRules = @($ReleaseMatrix | ForEach-Object { '(device.deviceOSVersion -startsWith "10.0.{0}")' -f $_.BaseBuild } | Select-Object -Unique)
        if ($BranchRules.Count -eq 0) { throw "No Windows 11 build branches were available to generate a membership rule." }
        return '(device.deviceOSType -eq "Windows") and ({0})' -f ($BranchRules -join ' or ')
    }
}

function Get-NormalizedVersionRangeJson {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$Ranges)

    process {
        [array]$Normalized = @($Ranges | ForEach-Object {
            [PSCustomObject]@{
                description = [string]$_.description
                lowestVersion = [string]$_.lowestVersion
                highestVersion = [string]$_.highestVersion
            }
        } | Sort-Object lowestVersion, highestVersion, description)
        return ($Normalized | ConvertTo-Json -Depth 5 -Compress)
    }
}

function New-Windows11CompliancePolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)][string]$PolicyName,
        [Parameter(Mandatory = $true)][object[]]$DesiredRanges,
        [string]$PolicyDescription,
        [int]$GraphMaxRetry = 3,
        [int]$GraphWaitTime = 1000
    )

    process {
        [string]$Body = @{
            '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'
            displayName = $PolicyName
            description = $PolicyDescription
            validOperatingSystemBuildRanges = $DesiredRanges
            osMinimumVersion = $null
            osMaximumVersion = $null
            scheduledActionsForRule = @(
                @{
                    ruleName = 'PasswordRequired'
                    scheduledActionConfigurations = @(
                        @{
                            actionType = 'block'
                            gracePeriodHours = 0
                            notificationTemplateId = ''
                            notificationMessageCCList = @()
                        }
                    )
                }
            )
        } | ConvertTo-Json -Depth 10

        if ($PSCmdlet.ShouldProcess($PolicyName, "Create Windows 11 compliance policy")) {
            $CreatedPolicy = Invoke-MgGraphRequestSingle -GraphRunProfile 'beta' -GraphMethod 'POST' -GraphObject 'deviceManagement/deviceCompliancePolicies' -GraphBody $Body -GraphMaxRetry $GraphMaxRetry -GraphWaitTime $GraphWaitTime
            & $AddReport -Target $PolicyName -OldValue 'Missing' -NewValue 'Created' -Action 'Success-PolicyCreated' -Details 'Created Windows 11 compliance policy'
            return $CreatedPolicy
        }

        & $AddReport -Target $PolicyName -OldValue 'Missing' -NewValue 'WouldCreate' -Action 'WhatIf-PolicyCreate' -Details 'Would create Windows 11 compliance policy'
        return [PSCustomObject]@{
            id = 'WhatIf'
            displayName = $PolicyName
            description = $PolicyDescription
            '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'
            validOperatingSystemBuildRanges = $DesiredRanges
            osMinimumVersion = $null
            osMaximumVersion = $null
        }
    }
}

function Resolve-Windows11CompliancePolicy {
    [CmdletBinding()]
    param(
        [string]$PolicyId,
        [string]$PolicyName,
        [bool]$CreateIfMissing = $false,
        [object[]]$DesiredRanges,
        [string]$PolicyDescription,
        [int]$GraphMaxRetry = 3,
        [int]$GraphWaitTime = 1000
    )

    process {
        if ([string]::IsNullOrWhiteSpace($PolicyId) -and [string]::IsNullOrWhiteSpace($PolicyName)) {
            throw "Specify either Windows11PolicyId or Windows11PolicyName."
        }

        [object[]]$Policies = @()
        if (-not [string]::IsNullOrWhiteSpace($PolicyId)) {
            $Policy = Invoke-MgGraphRequestSingle -GraphRunProfile 'beta' -GraphMethod 'GET' -GraphObject "deviceManagement/deviceCompliancePolicies/$PolicyId" -GraphMaxRetry $GraphMaxRetry -GraphWaitTime $GraphWaitTime
            if ($Policy) { $Policies = @($Policy) }
        }
        else {
            [string]$Filter = "displayName eq '$(ConvertTo-EscapedODataString -Value $PolicyName)'"
            $Policies = @(Invoke-MgGraphRequestSingle -GraphRunProfile 'beta' -GraphMethod 'GET' -GraphObject 'deviceManagement/deviceCompliancePolicies' -GraphFilters $Filter -GraphMaxRetry $GraphMaxRetry -GraphWaitTime $GraphWaitTime)
        }

        if ($Policies.Count -eq 0) {
            if ($CreateIfMissing) {
                if ([string]::IsNullOrWhiteSpace($PolicyName)) {
                    throw "Windows11PolicyName is required when CreatePolicyIfMissing is enabled."
                }
                if (-not $DesiredRanges -or @($DesiredRanges).Count -eq 0) {
                    throw "DesiredRanges are required to create a new Windows 11 compliance policy."
                }
                return (New-Windows11CompliancePolicy -PolicyName $PolicyName -DesiredRanges $DesiredRanges -PolicyDescription $PolicyDescription -GraphMaxRetry $GraphMaxRetry -GraphWaitTime $GraphWaitTime -WhatIf:$WhatIfPreference)
            }
            throw "No compliance policy matched the provided Windows 11 policy identifier."
        }
        if ($Policies.Count -gt 1) {
            throw "Multiple compliance policies matched the provided Windows 11 policy name. Use Windows11PolicyId instead."
        }

        $ResolvedPolicy = $Policies[0]
        if ($ResolvedPolicy.'@odata.type' -notmatch 'windows10CompliancePolicy$') {
            throw "The target policy '$($ResolvedPolicy.displayName)' is '$($ResolvedPolicy.'@odata.type')'. Windows 11 compliance policies must be the windows10CompliancePolicy type in Microsoft Graph."
        }

        return $ResolvedPolicy
    }
}

function Resolve-EntraGroupByName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$GroupName,
        [int]$GraphMaxRetry = 3,
        [int]$GraphWaitTime = 1000
    )

    process {
        [string]$Filter = "displayName eq '$(ConvertTo-EscapedODataString -Value $GroupName)'"
        [object[]]$Groups = @(Invoke-MgGraphRequestSingle -GraphRunProfile 'v1.0' -GraphMethod 'GET' -GraphObject 'groups' -GraphFilters $Filter -GraphProperties @('id', 'displayName', 'groupTypes', 'membershipRule', 'membershipRuleProcessingState') -GraphMaxRetry $GraphMaxRetry -GraphWaitTime $GraphWaitTime)
        if ($Groups.Count -gt 1) {
            throw "Multiple groups matched '$GroupName'. Use a unique group name."
        }
        if ($Groups.Count -eq 0) { return $null }
        return $Groups[0]
    }
}

function New-SafeMailNickname {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DisplayName)

    process {
        [string]$Nickname = ($DisplayName -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($Nickname)) { $Nickname = 'intunewindows11devices' }
        if ($Nickname.Length -gt 48) { $Nickname = $Nickname.Substring(0, 48) }
        return "$Nickname$(Get-Random -Minimum 1000 -Maximum 9999)"
    }
}

function Ensure-Windows11DynamicGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)][string]$GroupName,
        [Parameter(Mandatory = $true)][string]$MembershipRule,
        [int]$GraphMaxRetry = 3,
        [int]$GraphWaitTime = 1000
    )

    process {
        $ExistingGroup = Resolve-EntraGroupByName -GroupName $GroupName -GraphMaxRetry $GraphMaxRetry -GraphWaitTime $GraphWaitTime
        if (-not $ExistingGroup) {
            if ($PSCmdlet.ShouldProcess($GroupName, "Create Windows 11 dynamic group")) {
                [string]$Body = @{
                    displayName = $GroupName
                    description = "Dynamic device group for supported Windows 11 devices managed by $ScriptActionName"
                    mailEnabled = $false
                    mailNickname = (New-SafeMailNickname -DisplayName $GroupName)
                    securityEnabled = $true
                    groupTypes = @('DynamicMembership')
                    membershipRule = $MembershipRule
                    membershipRuleProcessingState = 'On'
                } | ConvertTo-Json -Depth 5
                $ExistingGroup = Invoke-MgGraphRequestSingle -GraphRunProfile 'v1.0' -GraphMethod 'POST' -GraphObject 'groups' -GraphBody $Body -GraphMaxRetry $GraphMaxRetry -GraphWaitTime $GraphWaitTime
                & $AddReport -Target $GroupName -OldValue 'Missing' -NewValue 'Created' -Action 'Success-GroupCreated' -Details 'Created Windows 11 dynamic group'
            }
            else {
                & $AddReport -Target $GroupName -OldValue 'Missing' -NewValue 'WouldCreate' -Action 'WhatIf-GroupCreate' -Details 'Would create Windows 11 dynamic group'
                return [PSCustomObject]@{ id = 'WhatIf'; displayName = $GroupName; membershipRule = $MembershipRule; membershipRuleProcessingState = 'On'; groupTypes = @('DynamicMembership') }
            }
        }
        else {
            if ('DynamicMembership' -notin @($ExistingGroup.groupTypes)) {
                throw "Existing group '$GroupName' is not a dynamic group. Convert it manually or specify another group name."
            }

            [hashtable]$PatchBody = @{}
            if ($ExistingGroup.membershipRule -ne $MembershipRule) { $PatchBody['membershipRule'] = $MembershipRule }
            if ($ExistingGroup.membershipRuleProcessingState -ne 'On') { $PatchBody['membershipRuleProcessingState'] = 'On' }

            if ($PatchBody.Count -gt 0) {
                if ($PSCmdlet.ShouldProcess($GroupName, "Update Windows 11 dynamic membership rule")) {
                    Invoke-MgGraphRequestSingle -GraphRunProfile 'v1.0' -GraphMethod 'PATCH' -GraphObject "groups/$($ExistingGroup.id)" -GraphBody ($PatchBody | ConvertTo-Json -Depth 5) -GraphMaxRetry $GraphMaxRetry -GraphWaitTime $GraphWaitTime | Out-Null
                    & $AddReport -Target $GroupName -OldValue $ExistingGroup.membershipRule -NewValue $MembershipRule -Action 'Success-GroupUpdated' -Details 'Updated Windows 11 dynamic group rule'
                    $ExistingGroup.membershipRule = $MembershipRule
                    $ExistingGroup.membershipRuleProcessingState = 'On'
                }
                else {
                    & $AddReport -Target $GroupName -OldValue $ExistingGroup.membershipRule -NewValue $MembershipRule -Action 'WhatIf-GroupUpdate' -Details 'Would update Windows 11 dynamic group rule'
                }
            }
            else {
                & $AddReport -Target $GroupName -OldValue $ExistingGroup.membershipRule -NewValue $MembershipRule -Action 'Correct-Group' -Details 'Windows 11 dynamic group already up to date'
            }
        }

        return $ExistingGroup
    }
}

function Ensure-CompliancePolicyAssignment {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)][string]$PolicyId,
        [Parameter(Mandatory = $true)][string]$PolicyName,
        [Parameter(Mandatory = $true)][string]$GroupId,
        [Parameter(Mandatory = $true)][string]$GroupName,
        [int]$GraphMaxRetry = 3,
        [int]$GraphWaitTime = 1000
    )

    process {
        [object[]]$Assignments = @(Invoke-MgGraphRequestSingle -GraphRunProfile 'beta' -GraphMethod 'GET' -GraphObject "deviceManagement/deviceCompliancePolicies/$PolicyId/assignments" -GraphMaxRetry $GraphMaxRetry -GraphWaitTime $GraphWaitTime)
        [object]$ExistingAssignment = $Assignments | Where-Object { $_.target.groupId -eq $GroupId } | Select-Object -First 1

        if ($ExistingAssignment) {
            & $AddReport -Target $PolicyName -OldValue $GroupName -NewValue $GroupName -Action 'Correct-Assignment' -Details 'Policy already assigned to Windows 11 group'
            return
        }

        if ($PSCmdlet.ShouldProcess($PolicyName, "Assign compliance policy to group $GroupName")) {
            [string]$Body = @{
                '@odata.type' = '#microsoft.graph.deviceCompliancePolicyAssignment'
                target = @{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId = $GroupId
                }
            } | ConvertTo-Json -Depth 5
            Invoke-MgGraphRequestSingle -GraphRunProfile 'beta' -GraphMethod 'POST' -GraphObject "deviceManagement/deviceCompliancePolicies/$PolicyId/assignments" -GraphBody $Body -GraphMaxRetry $GraphMaxRetry -GraphWaitTime $GraphWaitTime | Out-Null
            & $AddReport -Target $PolicyName -OldValue 'MissingAssignment' -NewValue $GroupName -Action 'Success-AssignmentCreated' -Details 'Assigned Windows 11 compliance policy to group'
        }
        else {
            & $AddReport -Target $PolicyName -OldValue 'MissingAssignment' -NewValue $GroupName -Action 'WhatIf-AssignmentCreate' -Details 'Would assign Windows 11 compliance policy to group'
        }
    }
}
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
Invoke-TboneLog -LogMode Start -Logname $LogName -LogToGUI $LogToGUI -LogToEventlog $LogToEventlog -LogEventIds $LogEventIds -LogToDisk $LogToDisk -LogPath $LogToDiskPath -LogToHost $LogToHost

try {
    if (-not [string]::IsNullOrWhiteSpace($KeyVaultName)) {
        Write-Verbose "Key Vault integration enabled with vault '$KeyVaultName'"
        if ([string]::IsNullOrWhiteSpace($AuthTenantId)) {
            $AuthTenantId = Invoke-GetKeyVaultSecretValue -VaultName $KeyVaultName -SecretName $KeyVaultTenantIdSecretName
        }
        if ([string]::IsNullOrWhiteSpace($AuthClientId)) {
            $AuthClientId = Invoke-GetKeyVaultSecretValue -VaultName $KeyVaultName -SecretName $KeyVaultClientIdSecretName
        }
        if ($null -eq $AuthClientSecret) {
            $AuthClientSecret = Invoke-GetKeyVaultSecretValue -VaultName $KeyVaultName -SecretName $KeyVaultClientSecretSecretName
        }
    }

    [hashtable]$AuthParams = @{}
    @{AuthTenantId = $AuthTenantId; AuthClientId = $AuthClientId; AuthCertThumbprint = $AuthCertThumbprint; AuthCertName = $AuthCertName; AuthCertPath = $AuthCertPath }.GetEnumerator() |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.Value) } |
        ForEach-Object { $AuthParams[$_.Key] = $_.Value }
    if ($null -ne $AuthClientSecret) { $AuthParams['AuthClientSecret'] = $AuthClientSecret }
    if ($AuthCertPassword -and $AuthCertPassword.Length -gt 0) { $AuthParams['AuthCertPassword'] = $AuthCertPassword }
    Invoke-ConnectMgGraph @AuthParams -RequiredScopes $RequiredScopes | Out-Null

    [string]$ReleaseMarkdown = Invoke-GetWebContent -Uri $ReleaseInfoUri
    [object[]]$ReleaseMatrix = @(Get-Windows11SupportedReleaseMatrix -MarkdownContent $ReleaseMarkdown -PatchLagMonths $PatchLagMonths)
    if ($ReleaseMatrix.Count -eq 0) { throw "No Windows 11 release ranges were generated from the release information source." }

    foreach ($Release in $ReleaseMatrix) {
        [string]$Details = "LatestBuild=$($Release.LatestBuild); MinimumBuild=$($Release.LowestBuild); Reason=$($Release.SelectionReason)"
        & $AddReport -Target $Release.Version -OldValue $Release.LatestBuild -NewValue $Release.LowestBuild -Action 'Detected-ReleaseRange' -Details $Details
        if ($Release.SelectionReason -eq 'FallbackEarliestAvailable') {
            Write-Warning "Version $($Release.Version) does not yet have enough B releases to honor PatchLagMonths=$PatchLagMonths. Using earliest available build $($Release.LowestBuild)."
        }
    }

    [string]$GeneratedMembershipRule = if ([string]::IsNullOrWhiteSpace($Windows11GroupMembershipRule)) {
        Get-Windows11GroupMembershipRuleFromReleaseMatrix -ReleaseMatrix $ReleaseMatrix
    }
    else {
        $Windows11GroupMembershipRule
    }

    [array]$DesiredRanges = @($ReleaseMatrix | ForEach-Object {
        [ordered]@{
            '@odata.type' = '#microsoft.graph.operatingSystemVersionRange'
            description = $_.Description
            lowestVersion = $_.LowestVersion
            highestVersion = $_.HighestVersion
        }
    })

    [object]$Policy = Resolve-Windows11CompliancePolicy -PolicyId $Windows11PolicyId -PolicyName $Windows11PolicyName -CreateIfMissing $CreatePolicyIfMissing -DesiredRanges $DesiredRanges -PolicyDescription $Windows11PolicyDescription -GraphMaxRetry $GraphMaxRetry -GraphWaitTime $GraphWaitTime
    [string]$PolicyId = $Policy.id
    [string]$PolicyName = $Policy.displayName

    [string]$CurrentRangesJson = Get-NormalizedVersionRangeJson -Ranges @($Policy.validOperatingSystemBuildRanges)
    [string]$DesiredRangesJson = Get-NormalizedVersionRangeJson -Ranges $DesiredRanges
    [bool]$PolicyNeedsUpdate = ($CurrentRangesJson -ne $DesiredRangesJson -or -not [string]::IsNullOrWhiteSpace($Policy.osMinimumVersion) -or -not [string]::IsNullOrWhiteSpace($Policy.osMaximumVersion))

    if ($PolicyNeedsUpdate) {
        [string]$PatchBody = @{
            validOperatingSystemBuildRanges = $DesiredRanges
            osMinimumVersion = $null
            osMaximumVersion = $null
        } | ConvertTo-Json -Depth 10

        if ($PSCmdlet.ShouldProcess($PolicyName, "Update Windows 11 validOperatingSystemBuildRanges")) {
            Invoke-MgGraphRequestSingle -GraphRunProfile 'beta' -GraphMethod 'PATCH' -GraphObject "deviceManagement/deviceCompliancePolicies/$PolicyId" -GraphBody $PatchBody -GraphMaxRetry $GraphMaxRetry -GraphWaitTime $GraphWaitTime | Out-Null
            & $AddReport -Target $PolicyName -OldValue $CurrentRangesJson -NewValue $DesiredRangesJson -Action 'Success-PolicyUpdated' -Details 'Updated validOperatingSystemBuildRanges and cleared osMinimumVersion/osMaximumVersion'
        }
        else {
            & $AddReport -Target $PolicyName -OldValue $CurrentRangesJson -NewValue $DesiredRangesJson -Action 'WhatIf-PolicyUpdate' -Details 'Would update validOperatingSystemBuildRanges'
        }
    }
    else {
        & $AddReport -Target $PolicyName -OldValue $CurrentRangesJson -NewValue $DesiredRangesJson -Action 'Correct-Policy' -Details 'Policy already aligned to supported Windows 11 release ranges'
    }

    if ($ManageAssignments) {
        [object]$Group = Ensure-Windows11DynamicGroup -GroupName $Windows11GroupName -MembershipRule $GeneratedMembershipRule -GraphMaxRetry $GraphMaxRetry -GraphWaitTime $GraphWaitTime
        if ($PolicyId -and $PolicyId -ne 'WhatIf' -and $Group.id -and $Group.id -ne 'WhatIf') {
            Ensure-CompliancePolicyAssignment -PolicyId $PolicyId -PolicyName $PolicyName -GroupId $Group.id -GroupName $Windows11GroupName -GraphMaxRetry $GraphMaxRetry -GraphWaitTime $GraphWaitTime
        }
    }
    else {
        & $AddReport -Target $PolicyName -OldValue 'AssignmentsSkipped' -NewValue 'AssignmentsSkipped' -Action 'Skipped-Assignments' -Details 'ManageAssignments was disabled'
    }
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    throw
}
finally {
    try {
        Disconnect-MgGraph -ErrorAction Stop *>$null
        Write-Verbose "Disconnected from Graph"
    }
    catch { Write-Warning "Failed to disconnect from Graph: $($_.Exception.Message)" }

    $ErrorActionPreference = $script:OriginalErrorActionPreference
    $VerbosePreference = $script:OriginalVerbosePreference
    $WhatIfPreference = $script:OriginalWhatIfPreference

    Invoke-TboneLog -LogMode Stop
    if ($ReportEnabled) {
        Invoke-ScriptReport -ReportTitle $ReportTitle -ReportResults $ReportResults -ReportStartTime $ReportStartTime -ReportDetailed $ReportDetailed -ReportToDisk $ReportToDisk -ReportToDiskPath $ReportToDiskPath
    }
}
#endregion
