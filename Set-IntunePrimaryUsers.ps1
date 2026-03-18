<#PSScriptInfo
.VERSION        7.5.1
.GUID           feedbeef-beef-4dad-beef-000000000001
.AUTHOR         Internal
.COPYRIGHT      (c) 2026
.TAGS           Intune Graph PrimaryUser DeviceManagement MicrosoftGraph Azure
.LICENSEURI     https://opensource.org/licenses/MIT
.PROJECTURI
.RELEASENOTES
    1.0.2202.1 - Initial Version
    2.0.2312.1 - Large update to use Graph batching and reduce runtime
    3.0.2407.1 - Added support for Group filtering
    3.0.2407.2 - Added a verification of required permissions
    4.0.2503.1 - Added new functions and new structure for the script
    5.0.2504.1 - Changed all requests to use invoke-mggraphrequets
    5.0.2504.2 - Bug fixing and error and throttling handling
    5.1.2504.3 - Changed sorting and selecting from the sign-in logs and overall performance improvements
    6.0.2510.1 - A complete rewrite of the processes due to changes in Microsoft Graph, now 10x faster and more reliable 
    6.0.2510.2 - Added T-Bone logging function throughout the script to better track execution and errors
    6.0.2510.3 - Improved logic and performance of the user sign-in data processing
    6.0.2510.4 - Added a fallback for windows devices with no Windows sign-in logs, to use application sign-in logs instead
    6.0.2510.5 - New parameters for keep and replace accounts
    6.0.2511.1 - New parameters for Intune only or both Intune and Co-managed 
    6.1.2511.2 - Bug fixes with DeviceTimeSpan and changed the name of the script to Set-IntunePrimaryUsers.ps1
    6.1.2512.1 - Added Certificate based auth and app based auth support in Invoke-ConnectMgGraph function
    6.2 2512.1 - Added versions on functions to keep track of changes, aslo worked through declarations, comments and fixed minor bugs
    6.1.1 2025-12-22 Fixed a better connect with parameter check
    7.0.0 2025-12-23 Major update to allign all primary user scripts. Many small changes to improve performance and reliability.
    7.0.1 2026-01-07 Fixed missing variable
    7.0.2 2026-01-09 Fixed header to comply with best practice
    7.0.3 2026-01-19 Fixed small bugs and syntax errors
    7.1.0 2026-01-21 Minor update to logging module and a lot of variable naming changes
    7.1.1 2026-01-30 Fixed missing $SignInsStartTime
    7.2.0 2026-02-06 Fixed skip token expiration issue with automatic query restart and deduplication
    7.3.0 2026-02-06 Minor update to support skip token that break graph requests early
    7.4.0 2026-02-17 Minor change to avoid mismatch  in microsoft.graph modules
    7.4.1 2026-02-17 Fix a bug in reporting function with formating issues on some regional languages
    7.4.2 2026-02-24 Fixed ClientSecret authentication PSCredential creation
    7.4.3 2026-02-24 Fixed clientsecret
    7.4.4 2026-02-24 Fix AuthClientSecret
    7.4.5 2026-02-24 Fixed ClientSecret authentication without exposing secrets
    7.4.6 2026-03-02 Fix to support both secure and non secure secret string using object type
    7.4.7 2026-03-12 Added optional Azure Key Vault secret retrieval for app authentication
    7.4.8 2026-03-13 Added default Azure Key Vault secret names for tenantid, clientid and secret authentication values
    7.5.0 2026-03-18 Added optional unauthenticated SMTP relay email reporting with summary body and CSV report attachment
    7.5.1 2026-03-18 Simplified authentication inputs to Key Vault-backed app auth only for secret-based configuration
#>

<#
.SYNOPSIS
    Script for Intune to set Primary User on Device

.DESCRIPTION
    This script gets Entra Sign-in logs for Windows and application sign-ins,
    determines the most frequent user in the last 30 days, and sets them as Primary User.
    Uses Microsoft Graph and requires only the Microsoft.Graph.Authentication module.

.EXAMPLE
    .\Set-IntunePrimaryUsers.ps1
    Sets primary user for all Intune devices with default settings.

.EXAMPLE
    .\Set-IntunePrimaryUsers.ps1 -OperatingSystems All -ReportDetailed $true -ReportToDisk $true
    Sets primary user for all Intune devices and saves detailed report to disk.

.EXAMPLE
    .\Set-IntunePrimaryUsers.ps1 -OperatingSystems Windows -SignInsTimeSpan 7 -DeviceTimeSpan 7
    Sets primary user for Windows devices based on sign-ins and device activity in the last 7 days.

.EXAMPLE
    .\Set-IntunePrimaryUsers.ps1 -KeyVaultName 'kv-prod-intune'
    Retrieves app authentication values from Azure Key Vault secret names 'tenantid', 'clientid' and 'secret' before connecting to Microsoft Graph.

.EXAMPLE
    .\Set-IntunePrimaryUsers.ps1 -KeyVaultName 'kv-prod-intune' -KeyVaultClientIdSecretName 'GraphClientId' -KeyVaultClientSecretSecretName 'GraphClientSecret' -KeyVaultTenantIdSecretName 'GraphTenantId'
    Retrieves app authentication values from Azure Key Vault using custom secret names before connecting to Microsoft Graph.

.EXAMPLE
    .\Set-IntunePrimaryUsers.ps1 -EmailReportEnabled $true -EmailRelayServer 'mailrelay.contoso.com' -EmailRelayPort 25 -EmailFrom 'intune-report@contoso.com' -EmailTo 'helpdesk@contoso.com;endpoint-team@contoso.com'
    Sends the report summary in the email body and attaches the full CSV report through an unauthenticated SMTP relay when the run finishes.
 
.NOTES
    Internal team script
#>

#region ---------------------------------------------------[Set Script Requirements]-----------------------------------------------
#Requires -Modules Microsoft.Graph.Authentication
#Requires -Version 5.1
#endregion

#region ---------------------------------------------------[Modifiable Parameters and Defaults]------------------------------------
# Customizations
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false,          HelpMessage = "Name of the script action for logging.")]
    [string]$ScriptActionName       = "Set Intune Primary User",

    [Parameter(Mandatory = $false,          HelpMessage = "Device operatingsystems to process ('All', 'Windows', 'Android', 'iOS', 'macOS'). Default is 'Windows'")]
    [ValidateSet('All', 'Windows', 'Android', 'iOS', 'macOS')]
    [string[]]$OperatingSystems     = @('Windows'),
        
    [Parameter(Mandatory = $false,          HelpMessage = "Filter Intune only managed devices (true) or also include Co-managed devices (false). Default is true")]
    [bool]$IntuneOnly               = $false,

    [Parameter(Mandatory = $false,          HelpMessage = "Filter to only include devicenames that starts with specific strings like ('Tbone', 'Desktop'). Default is blank")]
    [string[]]$IncludedDeviceNames  = @(),

    [Parameter(Mandatory = $false,          HelpMessage = "Filter to exclude devicenames that starts with specific strings like ('Tbone', 'Desktop'). Default is blank")]
    [string[]]$ExcludedDeviceNames  = @(),

    [Parameter(Mandatory = $false,          HelpMessage = "Filter to exclude specific accounts as primary owners for example enrollment accounts ('setup@example.com','install@example.com'). Default is blank")]
    [string[]]$ReplaceUserAccounts  = @(),

    [Parameter(Mandatory = $false,          HelpMessage = "Filter to keep specific accounts that always should be keept as primary owners ('monitoring@example.com'). Default is blank")]
    [string[]]$KeepUserAccounts     = @(),

    [Parameter(Mandatory = $false,          HelpMessage = "Time period in days to retrieve user sign-in activity logs. Default is 30 days")]
    [ValidateRange(1,90)]
    [int]$SignInsTimeSpan           = 30,

    [Parameter(Mandatory = $false,          HelpMessage = "Time period in days to retrieve active devices. Default is 30 days")]
    [ValidateRange(1,365)]
    [int]$DeviceTimeSpan            = 30,

    [Parameter(Mandatory = $false,          HelpMessage = "Testmode, same as -WhatIf. Default is false")]
    [bool]$Testmode                 = $false,
# ==========> Authentication (Invoke-ConnectMgGraph) <============================================================================
    [Parameter(                             HelpMessage = "Azure Key Vault name used to retrieve Microsoft Graph app authentication secrets before connecting")]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultName = 'SharedAutomationKV',

    [Parameter(                             HelpMessage = "Azure Key Vault secret name containing the Entra ID Tenant ID. Default is 'tenantid'")]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultTenantIdSecretName = 'Intune-Automation-SP-tenantid',

    [Parameter(                             HelpMessage = "Azure Key Vault secret name containing the Entra ID Application ID (Client ID). Default is 'clientid'")]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultClientIdSecretName = 'Intune-Automation-SP-clientid',

    [Parameter(                             HelpMessage = "Azure Key Vault secret name containing the Entra ID Application Secret. Default is 'secret'")]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultClientSecretSecretName = 'Intune-Automation-SP-secret',
# ==========> Logging (Invoke-TboneLog) <==============================================================================
    [Parameter(Mandatory = $false,          HelpMessage='Name of Log, to set name for Eventlog and Filelog')]
    [string]$LogName                = "",

    [Parameter(Mandatory = $false,          HelpMessage='Show output in console during execution')]
    [bool]$LogToGUI                 = $true,

    [Parameter(Mandatory = $false,          HelpMessage='Write complete log array to Windows Event when script ends')]
    [bool]$LogToEventlog            = $false,

    [Parameter(Mandatory = $false,          HelpMessage='EventLog IDs as hashtable: @{Info=11001; Warn=11002; Error=11003}')]
    [hashtable]$LogEventIds         = @{Info=11001; Warn=11002; Error=11003},

    [Parameter(Mandatory = $false,          HelpMessage='Return complete log array as Host output when script ends (Good for Intune Remediations)')]
    [bool]$LogToHost                = $false,

    [Parameter(Mandatory = $false,          HelpMessage='Write complete log array to Disk when script ends')]
    [bool]$LogToDisk                = $false,

    [Parameter(Mandatory = $false,          HelpMessage='Path where Disk logs are saved (if LogToDisk is enabled)')]
    [string]$LogToDiskPath          = "$env:TEMP",

    [Parameter(Mandatory = $false,          HelpMessage = "Enable verbose logging. Default is false")]
    [bool]$LogVerboseEnabled        = $false,
# ==========> Reporting (Invoke-ScriptReport) <========================================================================
    [Parameter(Mandatory = $false,          HelpMessage = "Title of the report")]
    [string]$ReportTitle            = "",

    [Parameter(Mandatory = $false,          HelpMessage = "Return report with statistics on how many changed objects. Default is true")]
    [bool]$ReportEnabled            = $true,

    [Parameter(Mandatory = $false,          HelpMessage = "Include detailed device changes in the report. Default is true")]
    [bool]$ReportDetailed           = $true,

    [Parameter(Mandatory = $false,          HelpMessage = "Save report to disk. Default is false")]
    [bool]$ReportToDisk             = $false,    

    [Parameter(Mandatory = $false,          HelpMessage = "Path where to save the report. Default is TEMP directory for Azure Automation compatibility")]
    [string]$ReportToDiskPath       = "$env:TEMP",

    [Parameter(Mandatory = $false,          HelpMessage = "Send the report summary and CSV attachment by unauthenticated SMTP relay. Default is false")]
    [bool]$EmailReportEnabled       = $false,

    [Parameter(Mandatory = $false,          HelpMessage = "SMTP relay server used for unauthenticated report delivery")]
    [string]$EmailRelayServer       = "emailserver.lac1.biz",

    [Parameter(Mandatory = $false,          HelpMessage = "SMTP relay port used for unauthenticated report delivery. Default is 25")]
    [ValidateRange(1,65535)]
    [int]$EmailRelayPort            = 25,

    [Parameter(Mandatory = $false,          HelpMessage = "Email sender address used for report delivery")]
    [string]$EmailFrom              = "intunereports@spireenergy.com",

    [Parameter(Mandatory = $false,          HelpMessage = "Recipient addresses used for report delivery. Separate multiple addresses with commas or semicolons")]
    [string]$EmailTo                = "intunereports@spireenergy.com",

    [Parameter(Mandatory = $false,          HelpMessage = "Optional email subject override. Defaults to report title with timestamp")]
    [string]$EmailSubject           = "Intune Primary User Script Report",
# ==========> Throttling and Retry (Invoke-MgGraphRequestSingle and Invoke-MgGraphRequestBatch) <======================
    [Parameter(Mandatory = $false,          HelpMessage = "Wait time in milliseconds between throttled requests. Default is 1000")]
    [ValidateRange(100,5000)]
    [int]$GraphWaitTime              = 1000,

    [Parameter(Mandatory = $false,          HelpMessage = "Maximum number of retry attempts for failed requests. Default is 3")]
    [ValidateRange(1,10)]
    [int]$GraphMaxRetry              = 3
    )
#endregion

#region ---------------------------------------------------[Modifiable Variables and defaults]------------------------------------
# Application IDs for the search of sign-in logs on different OS
[string]$AppId_Android           = '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'  # Microsoft Intune Company Portal
[string]$AppId_iOS               = 'e8be65d6-d430-4289-a665-51bf2a194bda'  # Microsoft 365 App Catalog Services
[string]$AppId_macOS             = '29d9ed98-a469-4536-ade2-f981bc1d605e'  # Microsoft Authentication Broker
[string]$AppId_Windows           = '38aa3b87-a06d-4817-b275-7a316988d93b'  # Windows Sign In
[string]$AppId_Windows_Fallback  = 'fc0f3af4-6835-4174-b806-f7db311fd2f3'  # Microsoft Intune Windows Agent. Fallback if no Windows Sign In logs are found

# ==========> Authentication (Invoke-ConnectMgGraph) <=================================================================
[System.Collections.ArrayList]$RequiredScopes = @(  # Required Graph API permission scopes used in function Invoke-ConnectMgGraph
    "DeviceManagementManagedDevices.ReadWrite.All", # Read/write Intune device to set Primary Users
    "AuditLog.Read.All",                            # Read sign-in logs
    "User.Read.All"                                 # Read users
)
#endregion

#region ---------------------------------------------------[Set global script settings]--------------------------------------------
# Exit if running as a managed identity in PowerShell 7.2 due to bugs connecting to MgGraph https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3151
# Allow execution to continue only when Key Vault-backed app authentication is configured.
[bool]$HasKeyVaultGraphAuthInput = -not [string]::IsNullOrWhiteSpace($KeyVaultName)
if (
    $env:IDENTITY_ENDPOINT -and
    $env:IDENTITY_HEADER -and
    $PSVersionTable.PSVersion -eq [version]"7.2.0" -and
    -not $HasKeyVaultGraphAuthInput
) {
    Write-Error "This script cannot use Microsoft Graph managed identity authentication in PowerShell 7.2. Use a different PowerShell version or configure Key Vault-backed app authentication."
    exit 1
}
# set strict mode to latest version
Set-StrictMode -Version Latest

# Save original preference states at script scope for restoration in finally block
[System.Management.Automation.ActionPreference]$script:OriginalErrorActionPreference    = $ErrorActionPreference
[System.Management.Automation.ActionPreference]$script:OriginalVerbosePreference        = $VerbosePreference
[bool]$script:OriginalWhatIfPreference                                                  = $WhatIfPreference

# Set verbose- and whatif- preference based on parameter instead of hardcoded values
if ($LogVerboseEnabled)     {$VerbosePreference = 'Continue'}                   # Set verbose logging based on the parameter $LogVerboseEnabled
else                        {$VerbosePreference = 'SilentlyContinue'}
if($Testmode)               {$WhatIfPreference = 1}                             # Manually enable whatif mode with parameter $Testmode for testing
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
# Import Microsoft.Graph.Authentication with automatic version conflict resolution
[string]$ModuleName = 'Microsoft.Graph.Authentication'
if (-not (Get-Module -Name $ModuleName)) {
    try { # Try normal import first
        & {$VerbosePreference = 'SilentlyContinue'; Import-Module $ModuleName -ErrorAction Stop}
        Write-Verbose "Imported $ModuleName v$((Get-Module -Name $ModuleName).Version)"
    }
    catch { # Reported bug with missmatch version. This will catch the error and try to clean up and retry the import
        if ($_.Exception -is [System.TypeLoadException] -or $_.Exception.Message -match 'does not have an implementation') {
            Write-Warning "Module version conflict detected - cleaning up and retrying"
            & {$VerbosePreference = 'SilentlyContinue'; Get-Module Microsoft.Graph.* | Remove-Module -Force -ErrorAction SilentlyContinue}
            [version]$LatestVersion = (Get-Module -Name $ModuleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version
            & {$VerbosePreference = 'SilentlyContinue'; Import-Module $ModuleName -RequiredVersion $LatestVersion -Force -ErrorAction Stop}
            Write-Verbose "Resolved conflict - imported $ModuleName v$LatestVersion"
        } else {throw}
    }
} else {Write-Verbose "Module '$ModuleName' already loaded v$((Get-Module -Name $ModuleName).Version)"}
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
# ==========> Logging (Invoke-TboneLog) <==============================================================================
if([string]::IsNullOrWhiteSpace($LogName)) {[string]$LogName = $ScriptActionName}           # Logname defaults to script action name
# ==========> Reporting (Invoke-ScriptReport) <========================================================================
if([string]::IsNullOrWhiteSpace($ReportTitle)) {[string]$ReportTitle = $ScriptActionName}   # Report title defaults to script action name
[datetime]$ReportStartTime = ([DateTime]::Now)                                              # Script start time for reporting
[hashtable]$ReportResults = @{}                                                             # Initialize empty hashtable for report results
[object]$script:LastScriptReport = $null                                                   # Stores the latest structured report without changing normal stdout behavior
[scriptblock]$AddReport = {param($Target,$OldValue,$NewValue,$Action,$Details)              # Small inline function to add report entries
    if(-not $ReportResults.ContainsKey($Action)){$ReportResults[$Action]=[System.Collections.ArrayList]::new()}
    $null=$ReportResults[$Action].Add([PSCustomObject]@{Target=$Target;OldValue=$OldValue;NewValue=$NewValue;Action=$Action;Details=$Details})}
# Data collection variables - initialized dynamically during script execution
[datetime]$SignInsStartTime = (Get-Date).AddDays(-$SigninsTimeSpan) # Sign-in logs start time    
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
function Invoke-ConnectMgGraph {
<#
.SYNOPSIS
    Connects to Microsoft Graph API with multiple authentication methods.
.DESCRIPTION
    Supports Managed Identity, Interactive, and Client Secret authentication.
.NOTES
    Version: 2.0
    
    Version History:
    1.0 - Initial version
    2.0 - 2026-01-09 - Changed parameter names and fixed minor bugs on authentication
    2.1 - 2026-02-24 - Fixed ClientSecret authentication PSCredential creation
    2.2 - 2026-03-01 - Fix to support both secure and non secure secret string using object type
    2.3 - 2026-03-18 - Simplified to client secret, managed identity, and interactive authentication
#>
    [CmdletBinding()]
    param (
        [Parameter(             HelpMessage = "Array of required Microsoft Graph API permission scopes example:('User.Read.All','DeviceManagementManagedDevices.ReadWrite.All') ")]
        [string[]]$RequiredScopes = @("User.Read.All"),

        [Parameter(             HelpMessage = "Entra ID Tenant ID (directory ID) required for Client Secret authentication")]
        [ValidateNotNullOrEmpty()]
        [string]$AuthTenantId,
        
        [Parameter(             HelpMessage = "Entra ID Application ID (ClientID) required for Client Secret authentication")]
        [ValidateNotNullOrEmpty()]
        [string]$AuthClientId, 

        [Parameter(             HelpMessage = "Client Secret as SecureString or stringfor app-only authentication (require also ClientId and TenantId)")]
        [ValidateNotNull()]
        [Object]$AuthClientSecret
    )

    Begin {
        $ErrorActionPreference = 'Stop'
        [string]$ResourceURL = "https://graph.microsoft.com/"
        
        # Detect authentication method based on parameters and environment (priority: ClientSecret > ManagedIdentity > Interactive)
        [bool]$HasClientId     = -not [string]::IsNullOrWhiteSpace($AuthClientId)
        [bool]$HasTenantId     = -not [string]::IsNullOrWhiteSpace($AuthTenantId)
        [bool]$HasClientSecret = $null -ne $AuthClientSecret

        [string]$AuthMethod = if ($HasClientSecret -and $HasClientId -and $HasTenantId) {'ClientSecret'}
        elseif ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER)                    {'ManagedIdentity'}
        else                                                                         {'Interactive'}
        Write-Verbose "Using authentication method: $AuthMethod"
    }

    Process {
        try {
            # Check for existing valid connection and required scopes
            try {
                $Context = Get-MgContext -ErrorAction SilentlyContinue
                if ($Context) {
                    Write-Verbose "Existing connection found for: $($Context.Account)"
                    # Validate scopes only for Interactive auth (Managed Identity/app-only doesn't use delegated scopes)
                    if ($AuthMethod -eq 'Interactive') {
                        [string[]]$CurrentScopes = @($Context.Scopes)
                        [string[]]$MissingScopes = @($RequiredScopes | Where-Object { $_ -notin $CurrentScopes })
                        
                        if ($MissingScopes.Count -eq 0) {
                            Write-Verbose "Reusing existing connection with valid scopes"
                            return $Context.Account
                        }
                        Write-Verbose "Existing connection missing scopes: $($MissingScopes -join ', ')"
                        Disconnect-MgGraph -ErrorAction SilentlyContinue
                    } else {
                        # For app-only auth, reuse existing connection
                        return $Context.Account
                    }
                }
            }
            catch {
                Write-Verbose "No existing connection found"
            }
            
            # Build connection parameters
            $ConnectParams = @{ NoWelcome = $true }
            
            switch ($AuthMethod) {
                'ManagedIdentity' {
                    Write-Verbose "Connecting with Managed Identity"
                    
                    # Validate environment variables
                    if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
                        throw "Managed Identity environment variables not set"
                    }
                    
                    # Get Graph SDK version for compatibility
                    [version]$GraphVersion = (Get-Module -Name 'Microsoft.Graph.Authentication' -ListAvailable | 
                        Sort-Object Version -Descending | Select-Object -First 1).Version
                    Write-Verbose "Graph SDK version: $GraphVersion"
                    
                    if ($GraphVersion -ge [version]"2.0.0") {
                        $ConnectParams['Identity'] = $true
                    } else {
                        # For older SDK versions, get token manually from managed identity endpoint
                        [hashtable]$Headers = @{
                            'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER
                            'Metadata' = 'True'
                        }
                        $Response = Invoke-RestMethod -Uri "$($env:IDENTITY_ENDPOINT)?resource=$ResourceURL" -Method GET -Headers $Headers -TimeoutSec 30 -ErrorAction Stop
                        if (-not $Response -or [string]::IsNullOrWhiteSpace($Response.access_token)) {
                            throw "Failed to retrieve access token from managed identity endpoint"
                        }
                        $ConnectParams['AccessToken'] = $Response.access_token
                        Write-Verbose "Retrieved managed identity token"
                    }
                }
                
                'ClientSecret' {
                    Write-Verbose "Connecting with Client Secret"
                    # Validate required inputs
                    if (-not $HasClientId -or -not $HasTenantId) {
                        throw "ClientSecret authentication requires both ClientId and TenantId."
                    }
                    # Convert to SecureString if it's a plain string
                    [SecureString]$SecureClientSecret = if ($AuthClientSecret -is [SecureString]) {$AuthClientSecret}
                        elseif ($AuthClientSecret -is [string]) {ConvertTo-SecureString -String $AuthClientSecret -AsPlainText -Force}
                        else {throw "AuthClientSecret must be either a string or SecureString"}
                    # Now lets use the secure string to build credentials    
                    [System.Management.Automation.PSCredential]$ClientCredential = [System.Management.Automation.PSCredential]::new($AuthClientId, $SecureClientSecret)
                    $ConnectParams['TenantId']               = $AuthTenantId
                    $ConnectParams['ClientSecretCredential'] = $ClientCredential
                    Write-Verbose "Using ClientId: $AuthClientId, TenantId: $AuthTenantId"
                }
                
                'Interactive' {
                    Write-Verbose "Connecting interactively"
                    # Ensure scopes are a string array
                    $ConnectParams['Scopes'] = @($RequiredScopes)
                }
            }
            
            # Connect to Microsoft Graph
            try {
                Connect-MgGraph @ConnectParams -ErrorAction Stop
                Write-Verbose "Successfully connected to Microsoft Graph"
            }
            catch {
                throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
            }
            finally {
                # Clear sensitive credentials if used (PSCredential object)
                if ($ConnectParams.ContainsKey('ClientSecretCredential')) { 
                    $ConnectParams['ClientSecretCredential'] = $null 
                }
            }
            
            # Validate permissions for delegated auth (Interactive only)
            if ($AuthMethod -eq 'Interactive' -and @($RequiredScopes).Count -gt 0) {
                try {
                    $Context = Get-MgContext
                    $CurrentScopes = @($Context.Scopes)
                    $ReqScopes = @($RequiredScopes)
                    $MissingScopes = @($ReqScopes | Where-Object { $_ -notin $CurrentScopes })
                    if (@($MissingScopes).Count -gt 0) {
                        throw "Missing required scopes: $($MissingScopes -join ', ')"
                    }
                    
                    Write-Verbose "Validated all required scopes: $($RequiredScopes -join ', ')"
                }
                catch {
                    throw "Failed to validate permissions: $($_.Exception.Message)"
                }
            }
            
            # Return account context
            $Context = Get-MgContext
            $Account = $Context.Account
            Write-Verbose "Connected as: $Account"
            return $Account
        }
        catch {
            Write-Error "Connection failed: $($_.Exception.Message)"
            throw
        }
    }

    End {
        # End function and report memory usage 
        [double]$MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
        Write-Verbose "Function finished. Memory usage: $MemoryUsage MB"
    }
}
function Invoke-GetKeyVaultSecretValue {
<#
.SYNOPSIS
    Retrieves a plain text secret value from Azure Key Vault.
.DESCRIPTION
    Uses Az.KeyVault when available. If Az modules are not available, it falls back to the managed identity endpoint
    when the script is running with a managed identity in Azure.
.NOTES
    Version: 1.0
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Azure Key Vault name")]
        [ValidateNotNullOrEmpty()]
        [string]$VaultName,

        [Parameter(Mandatory = $true, HelpMessage = "Azure Key Vault secret name")]
        [ValidateNotNullOrEmpty()]
        [string]$SecretName
    )

    begin {
        $ErrorActionPreference = 'Stop'
    }

    process {
        try {
            if (Get-Command -Name Get-AzKeyVaultSecret -ErrorAction SilentlyContinue) {
                [bool]$UseAzKeyVault = $true
                Write-Verbose "Retrieving secret '$SecretName' from Key Vault '$VaultName' using Az.KeyVault when available"

                if (-not (Get-Command -Name Get-AzContext -ErrorAction SilentlyContinue)) {
                    if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
                        Write-Verbose "Az.Accounts is missing. Falling back to managed identity REST for Key Vault access."
                        $UseAzKeyVault = $false
                    }
                    else {
                        throw "Az.KeyVault is available, but Az.Accounts is missing. Install Az.Accounts or run with managed identity fallback."
                    }
                }

                if ($UseAzKeyVault) {
                    [object]$AzContext = Get-AzContext -ErrorAction SilentlyContinue
                    if (-not $AzContext) {
                        if (Get-Command -Name Connect-AzAccount -ErrorAction SilentlyContinue) {
                            if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
                                Write-Verbose "No Azure context found. Connecting to Azure with managed identity for Key Vault access."
                                Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
                            }
                            else {
                                throw "No Azure context found for Key Vault access. Run Connect-AzAccount first or execute the script with a managed identity."
                            }
                        }
                        elseif ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
                            Write-Verbose "Connect-AzAccount is unavailable. Falling back to managed identity REST for Key Vault access."
                            $UseAzKeyVault = $false
                        }
                        else {
                            throw "Az.Accounts cmdlets are not available. Install Az.Accounts or use managed identity fallback."
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
                Write-Verbose "Retrieving secret '$SecretName' from Key Vault '$VaultName' using managed identity REST fallback"
                [string]$VaultResource = "https://vault.azure.net"
                [hashtable]$Headers = @{
                    'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER
                    'Metadata'          = 'True'
                }
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
function Invoke-TboneLog { 
<#
.SYNOPSIS
    Unified tiny logger for PowerShell 5.1–7.5 and Azure Automation; overrides Write-* cmdlets and stores all messages in-memory
.DESCRIPTION
    A lightweight, cross-platform logging solution that intercepts all Write-Host, Write-Output, Write-Verbose, 
    Write-Warning, and Write-Error calls. Stores messages in memory with timestamps and can optionally output to:
    -LogToGUI - Console (real-time during execution) -LogToDisk - Disk (log file at script completion) -LogToEventlog - Windows Event Log (Application log)
.NOTES
    Version: 1.1.0
    
    Version History:
    1.0 - Initial version
    1.0.1 - Fixed event log source creation for first-time runs
    1.1.0 - Added parameter logName and logEventIds to customize event log source and file log name
#>
    [CmdletBinding()]
    param(
        [Parameter(                     HelpMessage='Start=Begin logging, Stop=End and output log array')]
        [ValidateSet('Start','Stop')]
        [string]$LogMode,
        [Parameter(                     HelpMessage='Name of Log, to set name for Eventlog and Filelog')]
        [string]$LogName        = "PowerShellScript",
        [Parameter(                     HelpMessage='Show output in console during execution')]
        [bool]$LogToGUI         = $true,
        [Parameter(                     HelpMessage='Write complete log array to Windows Eventlog when script ends')]
        [bool]$LogToEventlog    = $true,
        [Parameter(                     HelpMessage='EventLog IDs as hashtable: @{Info=11001; Warn=11002; Error=11003}')]
        [hashtable]$LogEventIds = @{Info=11001; Warn=11002; Error=11003},
        [Parameter(                     HelpMessage='Return complete log array as Host output when script ends (Good for Intune Remediations)')]
        [bool]$LogToHost        = $True,
        [Parameter(                     HelpMessage='Write complete log array to filelog on disk when script ends')]
        [bool]$LogToDisk        = $true,
        [Parameter(                     HelpMessage='Path where Disk logs are saved (if LogToDisk is enabled)')]
        [string]$LogPath        = "$env:TEMP"
    )
    # Auto-detect mode: if logger functions is already loaded in memory and no mode specified, assume Stop
    if(!$LogMode){$LogMode=if(Get-Variable -Name _l -Scope Global -EA 0){'Stop'}else{'Start'}}
    if(!$LogPath){
        $ExistingLogPath = Get-Variable -Name _p -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        $LogPath = if($ExistingLogPath){$ExistingLogPath}elseif($env:TEMP){$env:TEMP}else{'/tmp'}
    }
    # Stop mode: Save logs and cleanup
    if ($LogMode -eq 'Stop') {
        if((Get-Variable -Name _l -Scope Global -EA 0) -and (Test-Path function:\global:_Save)){
            _Save
            $ReturnLogsToHost = Get-Variable -Name _r -Scope Global -ValueOnly -ErrorAction SilentlyContinue
            if($ReturnLogsToHost){,$global:_l.ToArray()}
        }
        Unregister-Event -SourceIdentifier PowerShell.Exiting -ea 0 -WhatIf:$false
        if(Test-Path function:\global:_Clean){_Clean}
        return
    }
    # Start mode: Initialize logging and proxy all Write-* functions
    if ($LogMode -eq 'Start') {
        # Create helper functions and variables
        $global:_az=$env:AZUREPS_HOST_ENVIRONMENT -or $env:AUTOMATION_ASSET_ACCOUNTID # Detect Azure Automation environment
        $global:_l=[Collections.Generic.List[string]]::new();$global:_g=$LogToGUI;$global:_s=$Logname;$global:_n="{0}-{1:yyyyMMdd-HHmmss}"-f$Logname,(Get-Date);$global:_p=$LogPath;$global:_d=$LogToDisk;$global:_e=$LogToEventlog;$global:_i=$LogEventIds;$global:_r=$LogToHost;$global:_w=([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
        if(!(Test-Path function:\global:_Time)){function global:_Time{Get-Date -f 'yyyy-MM-dd,HH:mm:ss'}}
        if(!(Test-Path function:\global:_ID)){function global:_ID{$c=(Get-PSCallStack)[2];$n=if($c.Command -and $c.Command -ne '<ScriptBlock>'){$c.Command}elseif($c.FunctionName -and $c.FunctionName -ne '<ScriptBlock>'){$c.FunctionName}else{'Main-Script'};if($n -like '*.ps1'){'Main-Script'}else{$n}}}
        if(!(Test-Path function:\global:_Save)){function global:_Save{try{if($global:_d){[IO.Directory]::CreateDirectory($global:_p)|Out-Null;[IO.File]::WriteAllLines((Join-Path $global:_p "$($global:_n).log"),$global:_l.ToArray())};if($global:_e -and $global:_w){$isAdmin=$false;try{$id=[Security.Principal.WindowsIdentity]::GetCurrent();$isAdmin=([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)}catch{};$la=$global:_l -join"`n";$h=$la -match ',ERROR,';$et=if($h){'Error'}elseif($la -match ',WARN,'){'Warning'}else{'Information'};$eid=if($h){$global:_i.Error}elseif($la -match ',WARN,'){$global:_i.Warn}else{$global:_i.Info};$ok=$false;try{Write-EventLog -LogName Application -Source $global:_s -EventId $eid -EntryType $et -Message $la -EA Stop;$ok=$true}catch{};if(-not $ok -and $isAdmin){try{[Diagnostics.EventLog]::CreateEventSource($global:_s,'Application')}catch{};try{Write-EventLog -LogName Application -Source $global:_s -EventId $eid -EntryType $et -Message $la}catch{}}}}catch{}}}
        if(!(Test-Path function:\global:_Clean)){function global:_Clean{$WhatIfPreference=$false;Remove-Item -Path function:\Write-Host,function:\Write-Output,function:\Write-Warning,function:\Write-Error,function:\Write-Verbose,function:\_Save,function:\_Clean,function:\_ID,function:\_Time -ea 0 -Force;Remove-Variable -Name _l,_g,_s,_n,_p,_d,_e,_i,_r,_w,_az -Scope Global -ea 0}}
        # Register exit handler FIRST (before Write-* overrides)
        $null=Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action{if($global:_l){try{_Save}catch{}};if(Test-Path function:\_Clean){_Clean}} -MaxTriggerCount 1
        # Create Write-* proxy functions (skip in Azure Automation)
        function Script:Write-Host{$m="$args";$c=(Get-PSCallStack)[1];$r="Row$($c.ScriptLineNumber)";$e="$(_Time),INFO,$r,$(_ID),$m";$global:_l.Add($e);if($global:_g){if($global:_az){Microsoft.PowerShell.Utility\Write-Output $m}else{Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Green}}}
        function Script:Write-Output{$m="$args";$c=(Get-PSCallStack)[1];$r="Row$($c.ScriptLineNumber)";$e="$(_Time),OUTPUT,$r,$(_ID),$m";$global:_l.Add($e);if($global:_g){if($global:_az){Microsoft.PowerShell.Utility\Write-Output $m}else{Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Green}}}
        function Script:Write-Verbose{$m="$args";$c=(Get-PSCallStack)[1];$r="Row$($c.ScriptLineNumber)";$e="$(_Time),VERBOSE,$r,$(_ID),$m";$global:_l.Add($e);if($global:_g -and $VerbosePreference -ne 'SilentlyContinue'){if($global:_az){Microsoft.PowerShell.Utility\Write-Verbose $m}else{Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor cyan}}}
        function Script:Write-Warning{$m="$args";$c=(Get-PSCallStack)[1];$r="Row$($c.ScriptLineNumber)";$e="$(_Time),WARN,$r,$(_ID),$m";$global:_l.Add($e);if($global:_g){if($global:_az){Microsoft.PowerShell.Utility\Write-Warning $m}else{Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Yellow}};if($WarningPreference -eq 'Stop'){_Save;_Clean;exit}}
        function Script:Write-Error{$m="$args";$c=(Get-PSCallStack)[1];$r="Row$($c.ScriptLineNumber)";$e="$(_Time),ERROR,$r,$(_ID),$m";$global:_l.Add($e);if($global:_g){if($global:_az){Microsoft.PowerShell.Utility\Write-Error $m}else{Microsoft.PowerShell.Utility\Write-Host $e -ForegroundColor Red}};if($ErrorActionPreference -eq 'Stop'){_Save;_Clean;exit}}
    }
}
function Invoke-MgGraphRequestSingle {
<#
.SYNOPSIS
    Makes a single Graph API call with Invoke-MgGraphRequest and support for filtering, property selection, and count queries.
.DESCRIPTION
    Makes Graph API calls using Invoke-MgGraphRequest but add automatic pagination, throttling handling, and exponential backoff retry logic.
    Supports filtering, property selection, and count queries. Returns all pages of results automatically.
    Handles skip token expiration by restarting query with smaller page size and deduplication.
.NOTES
    Version: 2.2
    
    Version History:
    1.0 - Initial version
    2.0 - Fixed some small bugs with throttling handling
    2.1 - Added more error handling for Post/Patch methods
    2.2 - Added skip token expiration recovery with automatic restart and deduplication
#>
[CmdletBinding()]
    Param(
        [Parameter(                 HelpMessage = "The Graph API version ('beta' or 'v1.0')")]
        [ValidateSet('beta', 'v1.0')]
        [string]$GraphRunProfile     = "v1.0",
    
        [Parameter(                 HelpMessage = "The HTTP method for the request(e.g., 'GET', 'PATCH', 'POST', 'DELETE')")]
        [ValidateSet('GET', 'PATCH', 'POST', 'DELETE')]
        [String]$GraphMethod         = "GET",
        
        [Parameter(Mandatory=$true, HelpMessage = "The Graph API endpoint path to target (e.g., 'me', 'users', 'groups')")]
        [ValidateNotNullOrEmpty()]
        [string]$GraphObject,

        [Parameter(                 HelpMessage = "Request body for POST/PATCH operations")]
        [string[]]$GraphBody,
        
        [Parameter(                 HelpMessage = "Graph API properties to include")]
        [string[]]$GraphProperties,
    
        [Parameter(                 HelpMessage = "Graph API filters to apply")]
        [string]$GraphFilters,
    
        [Parameter(                 HelpMessage = "Page size (Default is 500 for better stability)")]
        [ValidateRange(1,1000)]
        [int]$GraphPageSize          = 500,

        [Parameter(                 HelpMessage = "Skip pagination and only get the first page. (Default is false)")]
        [bool]$GraphSkipPagination   = $false,

        [Parameter(                 HelpMessage = "Include count of total items. Adds ConsistencyLevel header. (Default is false)")]
        [bool]$GraphCount            = $false,

        [Parameter(                 HelpMessage = "Delay in milliseconds between requests if throttled")]
        [ValidateRange(100,5000)]
        [int]$GraphWaitTime         = 1000,

        [Parameter(                 HelpMessage = "Maximum retry attempts for failed requests when throttled")]
        [ValidateRange(1,10)]
        [int]$GraphMaxRetry         = 3
    )

    Begin {
        # Initialize variables
        [nullable[int]]$TotalCount = $null
        [System.Collections.ArrayList]$PsobjectResults = [System.Collections.ArrayList]::new()
        [int]$RetryCount = 0
        [string]$Uri = "https://graph.microsoft.com/$GraphRunProfile/$GraphObject"
        [System.Collections.ArrayList]$GraphQueryParams = [System.Collections.ArrayList]::new()
        
        # Skip token recovery variables (only used if needed)
        [string]$BaseUri = $Uri
        [System.Collections.Generic.HashSet[string]]$SeenIds = $null

        # Add Count parameter to Query if requested
        if ($GraphCount) {[void]$GraphQueryParams.Add("`$count=true")}

        # Add page size parameter to Query if specified
        if ($GraphMethod -eq 'GET') {[void]$GraphQueryParams.Add("`$top=$GraphPageSize")}

        # Add properties to Query if specified
        if ($GraphProperties) {
            [string]$Select = $GraphProperties -join ','
            [void]$GraphQueryParams.Add("`$select=$Select")
        }

        # Add filters to Query if specified
        if ($GraphFilters) {
            [void]$GraphQueryParams.Add("`$filter=$([System.Web.HttpUtility]::UrlEncode($GraphFilters))")
        }

        # Combine query parameters into URI
        if ($GraphQueryParams.Count -gt 0) {$Uri += "?" + ($GraphQueryParams -join '&')}
    }

    Process {
        do {
            try {
                Write-Verbose "Making request to: $Uri"
                $I = 1
                do {
                    $Response = $null
                    Write-Verbose "Requesting page $I with $GraphPageSize items"
                    # Set default parameters for Invoke-MgGraphRequest
                    $Params = @{
                        Method      = $GraphMethod
                        Uri         = $Uri
                        ErrorAction = 'Stop'
                        OutputType  = 'PSObject'
                        Verbose     = $false
                    }
                    # Add ConsistencyLevel header if Count is requested
                    if ($GraphCount) { $Params['Headers'] = @{ 'ConsistencyLevel' = 'eventual' } }

                    # Add additional parameters based on method
                    if ($GraphMethod -in 'POST', 'PATCH') {
                        $Params['Body'] = $GraphBody
                        if (-not $Params.ContainsKey('Headers')) {
                            $Params['Headers'] = @{}
                        }
                        $Params['Headers']['Content-Type'] = 'application/json'
                        Write-Verbose "Request body: $($GraphBody | ConvertTo-Json -Depth 10)"
                    }
                    # Send request to Graph API
                    try {
                        $Response = Invoke-MgGraphRequest @Params
                        Write-Verbose "Request successful"
                    }
                    catch {
                        # Check if this is an expired skip token error
                        if ($_.Exception.Message -match "Skip token.*expired|Skip token is null") {
                            Write-Warning "Skip token expired at page $I after $($PsobjectResults.Count) items. Restarting..."
                            
                            # Initialize deduplication on first skip token failure
                            if ($null -eq $SeenIds) {
                                $SeenIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                                $PsobjectResults | Where-Object {$_.id} | ForEach-Object {[void]$SeenIds.Add($_.id)}
                            }
                            
                            # Reduce page size and rebuild URI
                            $GraphPageSize = [Math]::Max([int]($GraphPageSize / 2), 100)
                            $GraphQueryParams.Clear()
                            if ($GraphCount) {[void]$GraphQueryParams.Add("`$count=true")}
                            if ($GraphMethod -eq 'GET') {[void]$GraphQueryParams.Add("`$top=$GraphPageSize")}
                            if ($GraphProperties) {[void]$GraphQueryParams.Add("`$select=$($GraphProperties -join ',')")}
                            if ($GraphFilters) {[void]$GraphQueryParams.Add("`$filter=$([System.Web.HttpUtility]::UrlEncode($GraphFilters))")}
                            $Uri = $BaseUri + "?" + ($GraphQueryParams -join '&')
                            break
                        }
                        Write-Verbose "Request failed with error: $($_.Exception.Message)"
                        throw
                    }
                    if ($GraphMethod -in 'POST', 'PATCH', 'DELETE') {return $Response}
                    
                    # Add items (with deduplication if skip token recovery active)
                    if ($Response.value) {
                        if ($SeenIds) {
                            foreach ($item in $Response.value) {
                                if ($item.id -and -not $SeenIds.Contains($item.id)) {
                                    [void]$PsobjectResults.Add($item)
                                    [void]$SeenIds.Add($item.id)
                                }
                            }
                        } else {
                            [void]$PsobjectResults.AddRange($Response.value)
                        }
                    }
                    
                    # Capture count from first response if requested
                    if ($GraphCount -and $null -eq $TotalCount -and $Response.'@odata.count') {
                        $TotalCount = $Response.'@odata.count'
                        Write-Verbose "Total count available: $TotalCount items"
                    }
                    Write-Verbose "Retrieved page $I, Now total: $($PsobjectResults.Count) items"

                    # Check for next page
                    if ($GraphSkipPagination) {
                        Write-Verbose "SkipPagination enabled, stopping after first page"
                        $Uri = $null
                    }
                    elseif ($Response.PSObject.Properties.Name -contains '@odata.nextLink') {
                        if ($Response.'@odata.nextLink') {
                            $Uri = $Response.'@odata.nextLink'
                            Write-Verbose "Next page found: $Uri"
                        }
                        else {
                            Write-Verbose "No @odata.nextLink value, stopping pagination"
                            $Uri = $null
                        }
                    }
                    else {
                        Write-Verbose "No more pages found"
                        $Uri = $null
                    }

                    $I++
                } while ($Uri)
                Write-Verbose "Completed pagination. Returning array with $($PsobjectResults.Count) items"
                
                # Return results with count if requested
                if ($GraphCount -and $null -ne $TotalCount) {
                    return [PSCustomObject]@{
                        Items = $PsobjectResults
                        Count = $TotalCount
                    }
                }
                return $PsobjectResults # Success, return results and exit retry loop
            }
            catch {
                [string]$ErrorMessage = $_.Exception.Message
                # Get full error string including nested JSON messages for better pattern matching
                [string]$FullErrorString = $_ | Out-String
                Write-Warning "Request failed (Retry attempt $($RetryCount + 1)/$GraphMaxRetry): $ErrorMessage"

                # First check for throttling in error message (Invoke-MgGraphRequest may internally retry and throw with embedded 429 info)
                if ($ErrorMessage -match "TooManyRequests|Too Many Requests|429" -or $FullErrorString -match "TooManyRequests|Too Many Requests|429") {
                    # Throttling detected from error message - use exponential backoff
                    [int]$Delay = [math]::Min(($GraphWaitTime * ([math]::Pow(2, $RetryCount + 1))), 60000)
                    Write-Warning "Throttling detected from error message. Waiting $Delay milliseconds before retrying."
                    Start-Sleep -Milliseconds $Delay
                }
                # Check if the exception has response details (standard HTTP errors)
                elseif ($_.Exception.PSObject.Properties.Name -contains 'Response' -and $_.Exception.Response) {
                    [object]$StatusCode = $_.Exception.Response.StatusCode

                    # Use switch to handle specific status codes (handle both enum names and numeric values)
                    switch ($StatusCode) {
                        {$_ -eq 429 -or $_ -eq 'TooManyRequests'} { # Throttling
                            $RetryAfter = $_.Exception.Response.Headers["Retry-After"]
                            if ($RetryAfter) {
                                Write-Warning "Throttling detected (429). Waiting $($RetryAfter * 1000) milliseconds before retrying."
                                Start-Sleep -Milliseconds ($RetryAfter * 1000)
                            } else {
                                [int]$Delay = [math]::Min(($GraphWaitTime * ([math]::Pow(2, $RetryCount))), 60000)
                                Write-Warning "Throttling detected (429). No Retry-After header found. Waiting $Delay milliseconds before retrying."
                                Start-Sleep -Milliseconds $Delay
                            }
                            # Break not needed, will fall through to retry logic below
                        }
                        {$_ -eq 404 -or $_ -eq 'NotFound'} { # Not Found
                            # For DELETE operations, 404 means already deleted - treat as success
                            if ($GraphMethod -eq 'DELETE') {
                                Write-Verbose "Resource not found (404) - treating as already deleted"
                                return [PSCustomObject]@{ id = $GraphObject; status = 204; note = 'Already deleted' }
                            }
                            Write-Warning "Resource not found (404). Error: $ErrorMessage"
                            throw "$ErrorMessage (Object Deleted/No User License)"
                        }
                        {$_ -eq 400 -or $_ -eq 'BadRequest'} { # Bad Request                            
                            if ($ErrorMessage -match "Skip token.*expired|Skip token is null" -or $FullErrorString -match "Skip token.*expired|Skip token is null") {
                                # Fallback - should normally be handled in inner try-catch
                                Write-Warning "Skip token expired (outer catch fallback). Returning $($PsobjectResults.Count) items."
                                return $PsobjectResults
                            }
                            if ($ErrorMessage -match "does not have intune license or is deleted" -or $FullErrorString -match "does not have intune license or is deleted") { # Check if no license, common for Intune queries
                                Write-Warning "Object Deleted or User has no Intune license"
                                return "$ErrorMessage (Object Deleted/No User License)"
                            }
                            # For DELETE operations, "not found" patterns mean already removed - treat as success
                            if ($GraphMethod -eq 'DELETE' -and ($ErrorMessage -imatch 'does not exist|not found|cannot be found|no longer exists|was not found|resource .+ not found' -or $FullErrorString -imatch 'does not exist|not found|cannot be found|no longer exists')) {
                                Write-Verbose "Object already removed or not found (400) - treating as success"
                                return [PSCustomObject]@{ id = $GraphObject; status = 204; note = 'Already removed' }
                            }
                            # For POST operations, "already exists" patterns mean already created - treat as success
                            if ($GraphMethod -eq 'POST' -and ($ErrorMessage -imatch 'already exist|duplicate|conflict|references already exist|object reference already exist' -or $FullErrorString -imatch 'already exist|duplicate|conflict')) {
                                Write-Verbose "Object already exists (400) - treating as success"
                                return [PSCustomObject]@{ id = $GraphObject; status = 200; note = 'Already exists' }
                            }
                            Write-Error "Bad request (400). Error: $ErrorMessage"
                            throw $_
                        }
                        {$_ -eq 403 -or $_ -eq 'Forbidden'} { # Forbidden / Access Denied
                             Write-Error "Access denied (403). Error: $ErrorMessage"
                             throw $_
                        }
                        default { # Other HTTP errors - Use generic retry
                            [int]$Delay = [math]::Min(($GraphWaitTime * ([math]::Pow(2, $RetryCount))), 60000)
                            Write-Warning "HTTP error $StatusCode. Waiting $Delay milliseconds before retrying."
                            Start-Sleep -Milliseconds $Delay
                            # Break not needed, will fall through to retry logic below
                        }
                    }
                } else {
                    # Non-HTTP errors (e.g., network issues, DNS resolution) - Use generic retry
                    [int]$Delay = [math]::Min(($GraphWaitTime * ([math]::Pow(2, $RetryCount))), 60000)
                    Write-Warning "Non-HTTP error. Waiting $Delay milliseconds before retrying. Error: $ErrorMessage"
                    Start-Sleep -Milliseconds $Delay
                }

                # Increment retry count and check if max retries exceeded ONLY if not already thrown
                $RetryCount++
                if ($RetryCount -gt $GraphMaxRetry) {
                     Write-Error "Request failed after $($GraphMaxRetry) retries. Aborting."
                     throw "Request failed after $($GraphMaxRetry) retries. Last error: $ErrorMessage"
                }
                # If retries not exceeded and error was potentially retryable (e.g., 429, other HTTP, non-HTTP), the loop will continue
            }
        } while ($RetryCount -le $GraphMaxRetry)

        Write-Error "Request failed after $($GraphMaxRetry) retries. Aborting."
        throw "Request failed after $($GraphMaxRetry) retries." # Re-throw the exception after max retries
    }

    End {
        # End function and report memory usage 
        [double]$MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
        Write-Verbose "Function finished. Memory usage: $MemoryUsage MB"
    }
}
function Invoke-MgGraphRequestBatch {
<#
.SYNOPSIS
    Processes multiple Graph API requests in batches for improved performance.
.DESCRIPTION
    Sends Graph API requests in batches (up to 20 per batch) to efficiently process large numbers of objects.
    Handles throttling, retries, and provides progress tracking. Supports GET, PATCH, POST, and DELETE operations.
.NOTES
    Version: 1.3
    
    Version History:
    1.0 - Initial version
    1.1 - Added version on function to keep track of changes, minor bug fixes
    1.2 - Added more error handling for Post/Patch methods
    1.3 - Added a new parameter GraphNoObjectIdInUrl to allow requests where objectId should not be appended to the URL
#>
    [CmdletBinding()]
    Param(
        [Parameter(
            HelpMessage = "The Graph API version ('beta' or 'v1.0')")]
        [ValidateSet('beta', 'v1.0')]
        [string]$GraphRunProfile = "v1.0",
    
        [Parameter(
            HelpMessage = "The HTTP method for the request(e.g., 'GET', 'PATCH', 'POST', 'DELETE')")]
        [ValidateSet('GET', 'PATCH', 'POST', 'DELETE')]
        [String]$GraphMethod = "GET",
        
        [Parameter(
            HelpMessage = "The Graph API endpoint path to target (e.g., 'me', 'users', 'groups')")]
        [string]$GraphObject,
    
        [Parameter(
            HelpMessage = "Array of objects to process in batches")]
        [System.Object[]]$GraphObjects,

        [Parameter(HelpMessage = "Do not append objectId to the request URL (useful for endpoints like POST groups/id/members)")]
        [bool]$GraphNoObjectIdInUrl = $false,
    
        [Parameter(
            HelpMessage = "The Graph API query on the objects")]
        [string]$GraphQuery,
    
        [Parameter(HelpMessage = "Request body for POST/PATCH operations")]
        [object]$GraphBody,
        
        [Parameter(HelpMessage = "Graph API properties to include")]
        [string[]]$GraphProperties,
    
        [Parameter(HelpMessage = "Graph API filters to apply")]
        [string]$GraphFilters,
    
        [Parameter(HelpMessage = "Batch size (max 20 objects per batch)")]
        [ValidateRange(1,20)]
        [int]$GraphBatchSize = 20,
    
        [Parameter(HelpMessage = "Delay between batches in milliseconds")]
        [ValidateRange(100,5000)]
        [int]$GraphWaitTime = 1000,
    
        [Parameter(HelpMessage = "Maximum retry attempts for failed requests")]
        [ValidateRange(1,10)]
        [int]$GraphMaxRetry = 3
    )
    
    Begin {
        $ErrorActionPreference = 'Stop'
        [scriptblock]$script:GetTimestamp = { ([DateTime]::Now).ToString('yyyy-MM-dd HH:mm:ss') }
        [datetime]$StartTime = Get-Date
        [int]$RetryCount = 0
        [int]$TotalObjects = $GraphObjects.Count
        
        # Pre-allocate collections with capacity for better performance
        [System.Collections.Generic.List[PSObject]]$CollectedObjects = [System.Collections.Generic.List[PSObject]]::new($TotalObjects)
        [System.Collections.Generic.List[PSObject]]$RetryObjects = [System.Collections.Generic.List[PSObject]]::new()
        
        # Check execution context once
        [bool]$ManagedIdentity = [bool]$env:AUTOMATION_ASSET_ACCOUNTID
        Write-Verbose "Running in $(if ($ManagedIdentity) { 'Azure Automation' } else { 'interactive PowerShell' }) context"
        
        # Pre-calculate common values to avoid repeated work
        [string]$BatchUri = "https://graph.microsoft.com/$GraphRunProfile/`$batch"
        [hashtable]$BatchHeaders = @{'Content-Type' = 'application/json'}
        
        # Build URL query parameters once (they're the same for all requests)
        [string]$UrlQueryString = $null
        if ($GraphProperties -or $GraphFilters) {
            [System.Collections.Generic.List[string]]$UrlParams = [System.Collections.Generic.List[string]]::new()
            if ($GraphProperties) {
                $UrlParams.Add("`$select=$($GraphProperties -join ',')")
            }
            if ($GraphFilters) {
                $UrlParams.Add("`$filter=$([System.Web.HttpUtility]::UrlEncode($GraphFilters))")
            }
            $UrlQueryString = "?" + ($UrlParams -join '&')
        }
        
        # Pre-determine if method needs body/headers (avoid repeated checks)
        [bool]$NeedsBody = $GraphMethod -in 'PATCH','POST'
        [string]$ContentTypeHeader = if ($NeedsBody) { 'application/json' } else { $null }
        
        Write-Verbose "Graph batch processing initialized for $TotalObjects objects"
    }
    
    Process {
        try {
            do {
                [int]$CurrentObject = 0
                $RetryObjects.Clear()
                
                # Process objects in batches
                for($i = 0; $i -lt $GraphObjects.Count; $i += $GraphBatchSize) {
                    # Calculate batch boundaries
                    [int]$BatchEnd = [Math]::Min($i + $GraphBatchSize, $GraphObjects.Count)
                    [int]$BatchCount = $BatchEnd - $i
                    
                    # Pre-allocate request array with exact size
                    [System.Collections.ArrayList]$Req = [System.Collections.ArrayList]::new($BatchCount)
                    
                    # Build batch requests (optimized loop)
                    for ($j = $i; $j -lt $BatchEnd; $j++) {
                        [object]$Obj = $GraphObjects[$j]
                        [string]$Url = if ($GraphNoObjectIdInUrl) { "/$GraphObject$GraphQuery" } else { "/$GraphObject/$($Obj.id)$GraphQuery" }
                        if ($UrlQueryString) { $Url += $UrlQueryString }
                        
                        # Use object's body if available, otherwise use the global Body parameter
                        [object]$RequestBody = if ($Obj.PSObject.Properties.Name -contains 'body' -and $Obj.body) {
                            $Obj.body
                        } elseif ($NeedsBody) {
                            $GraphBody
                        } else {
                            $null
                        }
                        
                        [void]$Req.Add(@{
                            'id' = $Obj.id
                            'method' = $GraphMethod
                            'url' = $Url
                            'body' = $RequestBody
                            'headers' = @{ 'Content-Type' = $ContentTypeHeader }
                        })
                    }
                    
                    Write-Verbose "Sending batch $([Math]::Floor($i/$GraphBatchSize) + 1): items $($i+1) to $BatchEnd of $($GraphObjects.Count)"
                    
                    # Send batch request
                    try {
                        [string]$BatchBody = @{'requests' = $Req} | ConvertTo-Json -Depth 10 -Compress
                        [object]$Responses = Invoke-MgGraphRequest -Method POST -Uri $BatchUri -Body $BatchBody -Headers $BatchHeaders -Verbose:$false
                        Write-Verbose "Batch request successful with $($Req.Count) requests"
                    }
                    catch {
                        Write-Error "Failed to send batch request: $($_.Exception.Message)"
                        throw
                    }
                    
                    # Process responses (optimized with direct property access)
                    [int]$ThrottledCount = 0
                    foreach ($Response in $Responses.responses) {
                        $CurrentObject++
                        
                        # Handle response by status code
                        switch ($Response.status) {
                            {$_ -in 200,201,204} { # Success cases
                                # Extract the actual device object from response.body
                                if ($Response.body) {
                                    # Convert hashtable to PSCustomObject if needed
                                    [object]$GraphBodyObject = if ($Response.body -is [hashtable]) {
                                        [PSCustomObject]$Response.body
                                    } else {
                                        $Response.body
                                    }
                                    [void]$CollectedObjects.Add($GraphBodyObject)
                                    Write-Verbose "Success ($($Response.status)) for request $($Response.id) with body"
                                } else {
                                    # For 204 No Content (PATCH/DELETE), return a success indicator with the request ID
                                    [PSCustomObject]$SuccessObject = [PSCustomObject]@{
                                        id = $Response.id
                                        status = $Response.status
                                    }
                                    [void]$CollectedObjects.Add($SuccessObject)
                                    Write-Verbose "Success ($($Response.status)) for request $($Response.id) - no body returned"
                                }
                            }
                            400 { # Bad request - check error details for expected failures
                                # Extract error message from response body
                                [string]$ErrorCode = $null
                                [string]$ErrorMsg = $null
                                if ($Response.body -and $Response.body.error) {
                                    $ErrorCode = $Response.body.error.code
                                    $ErrorMsg = $Response.body.error.message
                                }
                                
                                # For DELETE operations, common "not found" patterns mean already removed - treat as success
                                if ($GraphMethod -eq 'DELETE' -and ($ErrorMsg -imatch 'does not exist|not found|cannot be found|no longer exists|was not found|resource .+ not found')) {
                                    Write-Verbose "Object $($Response.id) already removed or not found (400: $ErrorCode)"
                                    [PSCustomObject]$SuccessObject = [PSCustomObject]@{
                                        id = $Response.id
                                        status = 204  # Treat as successful removal
                                        note = 'Already removed'
                                    }
                                    [void]$CollectedObjects.Add($SuccessObject)
                                }
                                # For POST operations, "already exists" patterns mean already created - treat as success
                                elseif ($GraphMethod -eq 'POST' -and ($ErrorMsg -imatch 'already exist|duplicate|conflict|references already exist|object reference already exist')) {
                                    Write-Verbose "Object $($Response.id) already exists (400: $ErrorCode)"
                                    [PSCustomObject]$SuccessObject = [PSCustomObject]@{
                                        id = $Response.id
                                        status = 200  # Treat as successful (already exists)
                                        note = 'Already exists'
                                    }
                                    [void]$CollectedObjects.Add($SuccessObject)
                                }
                                else {
                                    # Unexpected 400 error - log and add to retry
                                    Write-Error "Bad request (400) for object $($Response.id): $ErrorCode - $ErrorMsg"
                                    [void]$RetryObjects.Add($Response)
                                }
                            }
                            403 { # Access denied - don't retry
                                Write-Error "Access denied (403) for object $($Response.id) - Check permissions"
                            }
                            404 { # Not found - for DELETE treat as success, for others log warning
                                if ($GraphMethod -eq 'DELETE') {
                                    Write-Verbose "Object $($Response.id) not found (404) - treating as already removed"
                                    [PSCustomObject]$SuccessObject = [PSCustomObject]@{
                                        id = $Response.id
                                        status = 204
                                        note = 'Not found - already removed'
                                    }
                                    [void]$CollectedObjects.Add($SuccessObject)
                                } else {
                                    Write-Warning "Resource not found (404) for object $($Response.id)"
                                }
                            }
                            429 { # Throttling - retry with backoff
                                Write-Warning "Throttling (429) for object $($Response.id)"
                                [void]$RetryObjects.Add($Response)
                                $ThrottledCount++
                            }
                            default { # Other errors - retry
                                Write-Error "Unexpected status ($($Response.status)) for object $($Response.id)"
                                [void]$RetryObjects.Add($Response)
                            }
                        }
                    }
                    
                    # Show progress (only in interactive mode)
                    if (-not $ManagedIdentity) {
                        [double]$PercentComplete = ($CurrentObject / $TotalObjects) * 100
                        [timespan]$Elapsed = (Get-Date) - $StartTime
                        [timespan]$TimeLeft = if ($CurrentObject -gt 0) {
                            [TimeSpan]::FromMilliseconds(($Elapsed.TotalMilliseconds / $CurrentObject) * ($TotalObjects - $CurrentObject))
                        } else { [TimeSpan]::Zero }
                        
                        Write-Progress -Activity "Processing Graph Batch Requests" `
                            -Status "Progress: $CurrentObject/$TotalObjects | Estimated Time Left: $($TimeLeft.ToString('hh\:mm\:ss')) | Throttled: $ThrottledCount | Retry: $RetryCount/$GraphMaxRetry" `
                            -PercentComplete $PercentComplete
                    }
                    
                    # Handle throttling with exponential backoff (only if throttled responses exist)
                    if ($ThrottledCount -gt 0) {
                        # Extract retry-after values efficiently
                        [array]$RetryAfterValues = @($RetryObjects | 
                            Where-Object { $_.status -eq 429 -and $_.headers.'retry-after' } | 
                            Select-Object -ExpandProperty headers | 
                            Select-Object -ExpandProperty 'retry-after')
                        
                        [int]$WaitSeconds = if ($RetryAfterValues -and $RetryAfterValues.Count -gt 0) {
                            [Math]::Min(($RetryAfterValues | Measure-Object -Maximum).Maximum + ($RetryCount * 2), 30)
                        } else {
                            [Math]::Min(1 + ($RetryCount * 2), 30)
                        }
                        
                        Write-Warning "Throttling detected, waiting $WaitSeconds seconds (Retry: $RetryCount)"
                        Start-Sleep -Seconds $WaitSeconds
                    }
                }
                
                # Prepare for retry if needed
                if ($RetryObjects.Count -gt 0 -and $RetryCount -lt $GraphMaxRetry) {
                    $RetryCount++
                    Write-Verbose "Starting retry $RetryCount with $($RetryObjects.Count) objects"
                    
                    # Create lookup hashtable for faster filtering
                    [hashtable]$RetryIdHash = @{}
                    foreach ($R in $RetryObjects) { $RetryIdHash[$R.id] = $true }
                    
                    # Filter objects to retry
                    $Objects = $Objects | Where-Object { $RetryIdHash.ContainsKey($_.id) }
                }
                
            } while ($RetryObjects.Count -gt 0 -and $RetryCount -lt $GraphMaxRetry)
            
            # Clear progress bar if used
            if (-not $ManagedIdentity) {
                Write-Progress -Activity "Processing Graph Batch Requests" -Completed
            }
            
            Write-Verbose "Successfully processed $($CollectedObjects.Count) of $TotalObjects objects"
            return $CollectedObjects
        }
        catch {
            Write-Error "Function failed in main process block: $($_.Exception.Message)"
            throw
        }
    }
    
    End {
        # Report memory usage
        [double]$MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
        [timespan]$Duration = (Get-Date) - $StartTime
        Write-Verbose "Function $($MyInvocation.MyCommand.Name) finished in $($Duration.ToString('mm\:ss')) | Memory: $MemoryUsage MB"
    }
}
function Convert-PSObjectArrayToHashTables {
<#
.SYNOPSIS
    Converts PSObject arrays to optimized hashtables for fast O(1) lookups.
.DESCRIPTION
    Creates Generic.Dictionary hashtables from PSObject arrays using specified properties as keys.
    Returns single or multiple hashtables indexed by property values for efficient data retrieval.
.NOTES
    Version: 1.2
    
    Version History:
    1.0 - Initial version
    1.1 - Removed pipeline support, optimized property checks, added capacity pre-allocation
    1.2 - Added StringComparer.OrdinalIgnoreCase for correct UPN/ID lookups and improved error handling
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,  HelpMessage = "Array of PSObjects to convert to hashtables")]
        [PSObject[]]$PSObjectArray,

        [Parameter(Mandatory = $true,  HelpMessage = "Property names to use as keys for hashtables")]
        [string[]]$IdProperties
    )

    Begin {
        $ErrorActionPreference = 'Stop'
        Write-Verbose "Starting conversion of $($PSObjectArray.Count) objects using $($IdProperties.Count) index propert$(if($IdProperties.Count -eq 1){'y'}else{'ies'})"
        
        # Validate inputs
        try {
            if ($null -eq $PSObjectArray -or $PSObjectArray.Count -eq 0) {
                throw "PSObjectArray is null or empty"
            }
            if ($null -eq $IdProperties -or $IdProperties.Count -eq 0) {
                throw "IdProperties is null or empty"
            }
        }
        catch {
            Write-Error "Input validation failed: $($_.Exception.Message)"
            throw
        }
    }

    Process {
        try {
            # Pre-calculate capacity for better memory allocation
            [int]$capacity = $PSObjectArray.Count

            # Single index requested (most common)
            if ($IdProperties.Count -eq 1) {
                try {
                    [string]$IdProperty = $IdProperties[0]
                    [System.Collections.Generic.Dictionary[string,object]]$HashTable = [System.Collections.Generic.Dictionary[string,object]]::new($capacity, [System.StringComparer]::OrdinalIgnoreCase)

                    foreach ($PSObject in $PSObjectArray) {
                        try {
                            [object]$IdValue = $PSObject.$IdProperty
                            if ($null -eq $IdValue) { continue }

                            # Convert to string for dictionary key (handles int/guid IDs etc)
                            [string]$key = $IdValue.ToString()
                            if ($key.Length -eq 0) { continue }

                            # Add to hashtable (overwrite if duplicate key exists)
                            $HashTable[$key] = $PSObject
                        }
                        catch {
                            Write-Warning "Failed to process object for property '$IdProperty': $($_.Exception.Message)"
                            continue
                        }
                    }

                    Write-Verbose "Converted $($HashTable.Count) objects to hashtable using property '$IdProperty'"
                    return $HashTable
                }
                catch {
                    Write-Error "Failed to create single-index hashtable for property '$IdProperty': $($_.Exception.Message)"
                    throw
                }
            }

            # Create hashtable collections for multiple indexes
            try {
                [hashtable]$HashTables = [hashtable]::new($IdProperties.Count)
                foreach ($prop in $IdProperties) {
                    try {
                        $HashTables[$prop] = [System.Collections.Generic.Dictionary[string,object]]::new($capacity, [System.StringComparer]::OrdinalIgnoreCase)
                    }
                    catch {
                        Write-Error "Failed to create dictionary for property '$prop': $($_.Exception.Message)"
                        throw
                    }
                }
            }
            catch {
                Write-Error "Failed to initialize hashtable collection: $($_.Exception.Message)"
                throw
            }

            # Process all objects and populate hashtables
            foreach ($PSObject in $PSObjectArray) {
                foreach ($IdProperty in $IdProperties) {
                    try {
                        $IdValue = $PSObject.$IdProperty
                        if ($null -eq $IdValue) { continue }

                        $key = $IdValue.ToString()
                        if ($key.Length -eq 0) { continue }

                        $HashTables[$IdProperty][$key] = $PSObject
                    }
                    catch {
                        Write-Warning "Failed to process object for property '$IdProperty': $($_.Exception.Message)"
                        continue
                    }
                }
            }
            # Log conversion summary
            foreach ($prop in $IdProperties) {
                Write-Verbose "Converted $($HashTables[$prop].Count) objects to hashtable using property '$prop'"
            }
            return $HashTables
        }
        catch {
            Write-Error "Failed to convert objects to hashtables: $($_.Exception.Message)"
            throw
        }
    }

    End {
        # End function and report memory usage 
        [double]$MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
        Write-Verbose "Function finished. Memory usage: $MemoryUsage MB"
    }
}
function Invoke-ScriptReport {
<#
.SYNOPSIS
    Generates a report summary, detailed data, and optional exports for script execution.
.DESCRIPTION
    Builds a reusable report object from the collected action results. The function can emit the report to the
    console/log stream, export it to disk, and return a structured object for downstream handling such as email.
.NOTES
    Version: 3.0
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = "Description of the action performed by the script")]
        [string]$ReportTitle = "Script Execution Report",

        [Parameter(Mandatory = $true, HelpMessage = "Hashtable of ArrayLists grouped by Action containing report entries")]
        [hashtable]$ReportResults,

        [Parameter(Mandatory = $true, HelpMessage = "Start time of the report execution")]
        [datetime]$ReportStartTime,

        [Parameter(Mandatory = $false, HelpMessage = "Include detailed per-object results in console output")]
        [bool]$ReportDetailed = $false,

        [Parameter(Mandatory = $false, HelpMessage = "Save report to disk in JSON/CSV format")]
        [bool]$ReportToDisk = $false,

        [Parameter(Mandatory = $false, HelpMessage = "Directory path where report files will be saved")]
        [ValidateScript({Test-Path $_ -IsValid})]
        [string]$ReportToDiskPath = "$env:TEMP\Reports",

        [Parameter(Mandatory = $false, HelpMessage = "Format for report export (JSON or CSV)")]
        [ValidateSet('JSON', 'CSV')]
        [string]$ReportFormat = 'CSV',

        [Parameter(Mandatory = $false, HelpMessage = "Emit report output to the console/log stream")]
        [bool]$ReportEmitOutput = $true
    )

    Begin {
        Write-Verbose "Starting report generation"
        [datetime]$ReportEndTime = [DateTime]::Now
    }

    Process {
        try {
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

            [System.Collections.ArrayList]$AllEntries = [System.Collections.ArrayList]::new()
            foreach ($Action in $SortedActions) {
                [void]$AllEntries.AddRange(@($ReportResults[$Action]))
            }
            [array]$SortedEntries = @($AllEntries | Sort-Object -Property Action, Target)

            [System.Collections.Generic.List[string]]$SummaryLines = [System.Collections.Generic.List[string]]::new()
            $SummaryLines.Add("Report: $ReportTitle")
            $SummaryLines.Add("Start: $($ReportStartTime.ToString('yyyy-MM-dd HH:mm:ss'))")
            $SummaryLines.Add("End: $($ReportEndTime.ToString('yyyy-MM-dd HH:mm:ss'))")
            $SummaryLines.Add("Duration: $DurationFormatted")
            $SummaryLines.Add("Summary:")
            if ($ActionSummary.Count -gt 0) {
                foreach ($Action in $ActionSummary.Keys) {
                    [int]$Count = $ActionSummary[$Action]
                    [double]$Percentage = if ($TotalObjects -gt 0) { [math]::Round(($Count / $TotalObjects) * 100, 1) } else { 0 }
                    $SummaryLines.Add("  ${Action}: $Count ($Percentage%)")
                }
            }
            else {
                $SummaryLines.Add("  No actions recorded")
            }
            $SummaryLines.Add("Total Objects: $TotalObjects")

            if ($ReportEmitOutput -and $ReportDetailed -and $TotalObjects -gt 0) {
                [object]$TableOutput = $SortedEntries | Format-Table -Property `
                    @{Name='Target';Expression={$_.Target};Alignment='Left'},
                    @{Name='OldValue';Expression={$_.OldValue};Alignment='Left'},
                    @{Name='NewValue';Expression={$_.NewValue};Alignment='Left'},
                    @{Name='Action';Expression={$_.Action};Alignment='Left'},
                    @{Name='Details';Expression={$_.Details};Alignment='Left'} -AutoSize -Wrap
                $TableOutput | Out-String -Stream -Width 250 | ForEach-Object { Write-Output $_ }
            }

            if ($ReportEmitOutput) {
                Write-Output "═══════════════════════════════════════════════════════════"
                Write-Output "  $ReportTitle"
                Write-Output "═══════════════════════════════════════════════════════════"
                Write-Output "  Start:    $($ReportStartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                Write-Output "  End:      $($ReportEndTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                Write-Output "  Duration: $DurationFormatted"
                Write-Output "───────────────────────────────────────────────────────────"
                Write-Output "  Summary"
                if ($ActionSummary.Count -gt 0) {
                    foreach ($Action in $ActionSummary.Keys) {
                        [int]$Count = $ActionSummary[$Action]
                        [double]$Percentage = if ($TotalObjects -gt 0) { [math]::Round(($Count / $TotalObjects) * 100, 1) } else { 0 }
                        Write-Output (("    {0,-30}: {1,6} ({2,5}" -f $Action, $Count, $Percentage) + '%)')
                    }
                }
                Write-Output ("    {0,-30}: {1,6}" -f "Total Objects", $TotalObjects)
                Write-Output "═══════════════════════════════════════════════════════════"
            }

            [string]$SavedReportPath = $null
            if ($ReportToDisk) {
                if (-not (Test-Path $ReportToDiskPath)) {
                    try { New-Item -ItemType Directory -Path $ReportToDiskPath -Force -ErrorAction Stop | Out-Null }
                    catch {
                        Write-Warning "Failed to create report directory '$ReportToDiskPath': $($_.Exception.Message)"
                        Write-Warning "Report will not be saved to disk."
                    }
                }

                if (Test-Path $ReportToDiskPath) {
                    [string]$Timestamp = $ReportEndTime.ToString('yyyyMMdd_HHmmss')
                    [string]$CleanAction = $ReportTitle -replace '[^\w\-]', '_'
                    [string]$BaseFileName = "Report_$($CleanAction)_$Timestamp"

                    if ($ReportFormat -eq 'JSON') {
                        [PSCustomObject]$ReportData = [PSCustomObject]@{
                            ReportTitle     = $ReportTitle
                            StartTime       = $ReportStartTime.ToString('yyyy-MM-dd HH:mm:ss')
                            EndTime         = $ReportEndTime.ToString('yyyy-MM-dd HH:mm:ss')
                            Duration        = $DurationFormatted
                            TotalProcessed  = $TotalObjects
                            ActionSummary   = $ActionSummary
                            DetailedResults = $SortedEntries
                        }

                        try {
                            $SavedReportPath = Join-Path $ReportToDiskPath "$BaseFileName.json"
                            $ReportData | ConvertTo-Json -Depth 10 -Compress:$false | Out-File -FilePath $SavedReportPath -Force -Encoding utf8 -ErrorAction Stop
                            if ($ReportEmitOutput) { Write-Output "Report saved: $SavedReportPath" }
                        }
                        catch {
                            Write-Warning "Failed to save JSON report: $($_.Exception.Message)"
                            $SavedReportPath = $null
                        }
                    }
                    else {
                        try {
                            $SavedReportPath = Join-Path $ReportToDiskPath "$BaseFileName.csv"
                            if ($SortedEntries.Count -gt 0) {
                                $SortedEntries | Export-Csv -Path $SavedReportPath -NoTypeInformation -Force -Encoding UTF8 -ErrorAction Stop
                            }
                            else {
                                [System.IO.File]::WriteAllText($SavedReportPath, "Target,OldValue,NewValue,Action,Details`r`n", [System.Text.Encoding]::UTF8)
                            }
                            if ($ReportEmitOutput) { Write-Output "Report saved: $SavedReportPath" }
                        }
                        catch {
                            Write-Warning "Failed to save CSV report: $($_.Exception.Message)"
                            $SavedReportPath = $null
                        }
                    }
                }
            }

            [PSCustomObject]$ReportObject = [PSCustomObject]@{
                ReportTitle     = $ReportTitle
                StartTime       = $ReportStartTime
                EndTime         = $ReportEndTime
                Duration        = $DurationFormatted
                TotalProcessed  = $TotalObjects
                ActionSummary   = $ActionSummary
                DetailedResults = $SortedEntries
                SummaryLines    = $SummaryLines.ToArray()
                SummaryText     = ($SummaryLines.ToArray() -join [Environment]::NewLine)
                SavedReportPath = $SavedReportPath
            }

            $script:LastScriptReport = $ReportObject
            Write-Verbose "Report completed successfully"
        }
        catch {
            Write-Error "Failed to generate report: $($_.Exception.Message)"
            throw
        }
    }

    End {
        [double]$MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
        Write-Verbose "Function finished. Memory usage: $MemoryUsage MB"
    }
}
function Invoke-SendSmtpReport {
<#
.SYNOPSIS
    Sends a report summary and attachment through an unauthenticated SMTP relay.
.DESCRIPTION
    Builds a plain text email message and sends it without SMTP authentication.
.NOTES
    Version: 1.0
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "SMTP relay host")]
        [ValidateNotNullOrEmpty()]
        [string]$SmtpServer,

        [Parameter(Mandatory = $false, HelpMessage = "SMTP relay port")]
        [ValidateRange(1,65535)]
        [int]$SmtpPort = 25,

        [Parameter(Mandatory = $true, HelpMessage = "Sender email address")]
        [ValidateNotNullOrEmpty()]
        [string]$From,

        [Parameter(Mandatory = $true, HelpMessage = "Recipient email addresses")]
        [ValidateNotNullOrEmpty()]
        [string[]]$To,

        [Parameter(Mandatory = $true, HelpMessage = "Email subject")]
        [ValidateNotNullOrEmpty()]
        [string]$Subject,

        [Parameter(Mandatory = $true, HelpMessage = "Plain text email body")]
        [string]$Body,

        [Parameter(Mandatory = $true, HelpMessage = "Path to the report attachment")]
        [ValidateNotNullOrEmpty()]
        [string]$AttachmentPath
    )

    begin {
        $ErrorActionPreference = 'Stop'
        [System.Net.Mail.MailMessage]$MailMessage = $null
        [System.Net.Mail.SmtpClient]$SmtpClient = $null
        [System.Net.Mail.Attachment]$Attachment = $null
    }

    process {
        try {
            if (-not (Test-Path -LiteralPath $AttachmentPath -PathType Leaf)) {
                throw "Attachment file not found: $AttachmentPath"
            }

            $MailMessage = [System.Net.Mail.MailMessage]::new()
            $MailMessage.From = [System.Net.Mail.MailAddress]::new($From)
            foreach ($Recipient in $To) {
                if (-not [string]::IsNullOrWhiteSpace($Recipient)) {
                    [void]$MailMessage.To.Add($Recipient)
                }
            }

            if ($MailMessage.To.Count -eq 0) {
                throw "At least one recipient address is required."
            }

            $MailMessage.Subject = $Subject
            $MailMessage.Body = $Body
            $MailMessage.IsBodyHtml = $false

            $Attachment = [System.Net.Mail.Attachment]::new($AttachmentPath)
            [void]$MailMessage.Attachments.Add($Attachment)

            $SmtpClient = [System.Net.Mail.SmtpClient]::new($SmtpServer, $SmtpPort)
            $SmtpClient.EnableSsl = $false
            $SmtpClient.UseDefaultCredentials = $false
            $SmtpClient.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network
            $SmtpClient.Timeout = 30000

            $SmtpClient.Send($MailMessage)
            Write-Verbose "Sent report email via SMTP relay '${SmtpServer}:$SmtpPort' to $($MailMessage.To -join ', ')"
        }
        catch {
            throw "Failed to send SMTP report email: $($_.Exception.Message)"
        }
        finally {
            if ($Attachment) { $Attachment.Dispose() }
            if ($MailMessage) { $MailMessage.Dispose() }
            if ($SmtpClient) { $SmtpClient.Dispose() }
        }
    }
}
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
# Start T-Bone custom logging (can be removed if you don't want to use T-Bone logging)
Invoke-TboneLog -LogMode Start -Logname $LogName -LogToGUI $LogToGUI -LogToEventlog $LogToEventlog -LogEventIds $LogEventIds -LogToDisk $LogToDisk -LogPath $LogToDiskPath -LogToHost $LogToHost

try {
    #Sign in to Graph
    try {
        [string]$ResolvedAuthTenantId = $null
        [string]$ResolvedAuthClientId = $null
        [string]$ResolvedAuthClientSecret = $null

        if (-not [string]::IsNullOrWhiteSpace($KeyVaultName)) {
            Write-Verbose "Key Vault integration enabled with vault '$KeyVaultName'"

            if (-not [string]::IsNullOrWhiteSpace($KeyVaultTenantIdSecretName)) {
                $ResolvedAuthTenantId = Invoke-GetKeyVaultSecretValue -VaultName $KeyVaultName -SecretName $KeyVaultTenantIdSecretName
                Write-Verbose "Resolved AuthTenantId from Azure Key Vault"
            }
            if (-not [string]::IsNullOrWhiteSpace($KeyVaultClientIdSecretName)) {
                $ResolvedAuthClientId = Invoke-GetKeyVaultSecretValue -VaultName $KeyVaultName -SecretName $KeyVaultClientIdSecretName
                Write-Verbose "Resolved AuthClientId from Azure Key Vault"
            }
            if (-not [string]::IsNullOrWhiteSpace($KeyVaultClientSecretSecretName)) {
                $ResolvedAuthClientSecret = Invoke-GetKeyVaultSecretValue -VaultName $KeyVaultName -SecretName $KeyVaultClientSecretSecretName
                Write-Verbose "Resolved AuthClientSecret from Azure Key Vault"
            }

            if (
                [string]::IsNullOrWhiteSpace($ResolvedAuthTenantId) -or
                [string]::IsNullOrWhiteSpace($ResolvedAuthClientId) -or
                [string]::IsNullOrWhiteSpace($ResolvedAuthClientSecret)
            ) {
                throw "Key Vault authentication requires tenant ID, client ID, and client secret values."
            }
        }

        # Build authentication parameters to pass only non-empty values. If no values are provided, default interactive auth or managed identity auth will be used.
        [hashtable]$AuthParams = @{}
        @{AuthTenantId = $ResolvedAuthTenantId; AuthClientId = $ResolvedAuthClientId}.GetEnumerator() `
            | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Value) } `
            | ForEach-Object { $AuthParams[$_.Key] = $_.Value }
        if (-not [string]::IsNullOrWhiteSpace($ResolvedAuthClientSecret)) { $AuthParams['AuthClientSecret'] = $ResolvedAuthClientSecret }
        # Invoke connection to Microsoft Graph with specified authentication parameters
        Invoke-ConnectMgGraph @AuthParams -RequiredScopes $RequiredScopes
        Write-Verbose "Success to get Access Token to Graph"
    }
    catch {
        Write-Error "Failed to get Access Token to Graph: $($_.Exception.Message)"
        throw
    }

    # Get all devices
    try {
        # List properties to retrieve
        [string]$GraphProperties = 'id,deviceName,operatingSystem,AzureAdDeviceId,userId'
        # Prepare filters
        [string]$GraphFilterString = $null
        # Add filter for Operating Systems
        if ($OperatingSystems -notcontains 'All' -and $OperatingSystems.Count -gt 0) {
            [array]$OsFilterParts = @($OperatingSystems | ForEach-Object { "operatingSystem eq '$_'" })
            $GraphFilterString = "($($OsFilterParts -join ' or '))"
            Write-Verbose "Using OS filter: $GraphFilterString"
        }
        else {Write-Verbose "No OS filter applied (retrieving all operating systems)"}
        # Add filter for device last sync time
        if ($DeviceTimeSpan -gt 0) { 
            [string]$timeThreshold = (Get-Date).AddDays(-$DeviceTimeSpan).ToString('yyyy-MM-ddTHH:mm:ssZ')
            if ($GraphFilterString) {$GraphFilterString = "lastSyncDateTime ge $timeThreshold and " + $GraphFilterString
            } else {$GraphFilterString = "lastSyncDateTime ge $timeThreshold"}
            Write-Verbose "Using device last sync time filter: lastSyncDateTime ge $timeThreshold"
        }
        else {Write-Verbose "No device last sync time filter applied"}
        # Add filter for Intune managed devices or also include co-managed devices
        if ($IntuneOnly) {
            if ($GraphFilterString) {$GraphFilterString = "managementAgent eq 'mdm' and " + $GraphFilterString}
            else {$GraphFilterString = "managementAgent eq 'mdm' "}
        }
        else {Write-Verbose "No management agent filter applied"}
        # Get graph objects with single call
        $AllDevices = Invoke-MgGraphRequestSingle `
            -GraphRunProfile 'beta' `
            -GraphMethod 'GET' `
            -GraphObject 'deviceManagement/managedDevices' `
            -GraphProperties $GraphProperties `
            -GraphFilters $GraphFilterString `
            -GraphMaxRetry $GraphMaxRetry `
            -GraphWaitTime $GraphWaitTime
        # Initialize hashtables
        $AllDevicesByIdHash = [System.Collections.Generic.Dictionary[string,object]]::new(0, [System.StringComparer]::OrdinalIgnoreCase)
        # Verify if objects were found   
        if ($AllDevices -and $AllDevices.Count -gt 0) {
            Write-Verbose "Retrieved $($AllDevices.Count) devices from Graph API"
            
            # Apply client-side name filters
            if (($IncludedDeviceNames -and $IncludedDeviceNames.Count -gt 0) -or ($ExcludedDeviceNames -and $ExcludedDeviceNames.Count -gt 0)) {
                [string]$IncludePattern = if ($IncludedDeviceNames -and $IncludedDeviceNames.Count -gt 0) {
                    '^(' + (($IncludedDeviceNames | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
                } else { $null }
                [string]$ExcludePattern = if ($ExcludedDeviceNames -and $ExcludedDeviceNames.Count -gt 0) {
                    '^(' + (($ExcludedDeviceNames | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
                } else { $null }
                $AllDevices = $AllDevices | Where-Object {
                    $IncludeMatch = if ($IncludePattern) { $_.deviceName -imatch $IncludePattern } else { $true }
                    $ExcludeMatch = if ($ExcludePattern) { $_.deviceName -notmatch $ExcludePattern } else { $true }
                    $IncludeMatch -and $ExcludeMatch
                }
                if ($IncludePattern) { Write-Verbose "Applied inclusion filter for $($IncludedDeviceNames.Count) patterns" }
                if ($ExcludePattern) { Write-Verbose "Applied exclusion filter for $($ExcludedDeviceNames.Count) patterns" }
                Write-Verbose "Remaining after filters: $($AllDevices.Count) devices"
            }
            # Create hashtable for fast lookups
            $AllDevicesByIdHash = Convert-PSObjectArrayToHashTables -PSObjectArray $AllDevices -IdProperties @('id')
            Write-Verbose "Created device lookup hashtable with $($AllDevicesByIdHash.Count) entries"
        }
        else {Write-Warning "No devices found in tenant"}
    }
    catch {
        Write-Error "Failed to get devices: $($_.Exception.Message)"
        throw
    }

    # Get all users from Graph
    try {
        # List properties to retrieve
        [string]$GraphProperties = 'id,userPrincipalName'
        # Prepare filters
        [string]$GraphFilterString = $null
        # Get graph objects with single call
        $AllUsers = Invoke-MgGraphRequestSingle `
            -GraphRunProfile 'v1.0' `
            -GraphMethod 'GET' `
            -GraphObject 'users' `
            -GraphProperties $GraphProperties `
            -GraphFilters $GraphFilterString `
            -GraphMaxRetry $GraphMaxRetry `
            -GraphWaitTime $GraphWaitTime

        # Initialize hashtables
        $AllUsersByIdHash = [System.Collections.Generic.Dictionary[string,object]]::new(0, [System.StringComparer]::OrdinalIgnoreCase)
        $AllUsersByUPNHash = [System.Collections.Generic.Dictionary[string,object]]::new(0, [System.StringComparer]::OrdinalIgnoreCase)
        # Verify if objects were found
        if ($AllUsers -and $AllUsers.Count -gt 0) {
            Write-Verbose "Successfully retrieved $($AllUsers.Count) users from Graph API"
            # Create hashtable for fast lookups
            $AllUserHashTables = Convert-PSObjectArrayToHashTables -PSObjectArray $AllUsers -IdProperties @('id', 'userPrincipalName')
            $AllUsersByIdHash = $AllUserHashTables['id']
            $AllUsersByUPNHash = $AllUserHashTables['userPrincipalName']
            Write-Verbose "Created user lookup hashtables: ID=$($AllUsersByIdHash.Count) entries, UPN=$($AllUsersByUPNHash.Count) entries"
        }
        else {Write-Warning "No users found in tenant"}
    }
    catch {
        Write-Error "Failed to get users: $($_.Exception.Message)"
        throw
    }

    # Get all sign-in logs from Graph in chunks per OS type
    try {
        # List properties to retrieve
        [string]$GraphProperties = 'deviceDetail,userPrincipalName,userId'
        # Prepare filters
        [string]$GraphFilterString = "status/errorCode eq 0 and deviceDetail/isManaged eq true"
        # Add filter for OS specific queries
        [hashtable]$OsQueryConfigs = @{
            'Android' = @{ AppId = $AppId_Android; EventType = "signInEventTypes/any(t: t eq 'nonInteractiveUser')"; OSFilter = "startsWith(deviceDetail/operatingSystem,'Android')" }
            'iOS' = @{ AppId = $AppId_iOS; EventType = "signInEventTypes/any(t: t eq 'nonInteractiveUser')"; OSFilter = "startsWith(deviceDetail/operatingSystem,'iOS')" }
            'macOS' = @{ AppId = $AppId_macOS; EventType = "signInEventTypes/any(t: t eq 'nonInteractiveUser')"; OSFilter = "startsWith(deviceDetail/operatingSystem,'MacOs')" }
            'Windows' = @{ AppId = $AppId_Windows; EventType = "isInteractive eq true"; OSFilter = "startsWith(deviceDetail/operatingSystem,'Windows')" }
            'Windows Fallback' = @{ AppId = $AppId_Windows_Fallback; EventType = "signInEventTypes/any(t: t eq 'nonInteractiveUser')"; OSFilter = "startsWith(deviceDetail/operatingSystem,'Windows')" }
        }
        # Build OS query list to process one operating system at a time
        [System.Collections.ArrayList]$OsQueries = [System.Collections.ArrayList]::new()
        [bool]$IsAll = $OperatingSystems -contains 'All'
        [array]$OsNamesToProcess = if ($IsAll) { @('Android', 'iOS', 'macOS', 'Windows', 'Windows Fallback') } else { $OperatingSystems }
        [System.Collections.Generic.HashSet[string]]$AddedOSes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($OsName in $OsNamesToProcess) {
            if ($OsQueryConfigs.ContainsKey($OsName) -and -not $AddedOSes.Contains($OsName)) {
                [hashtable]$Cfg = $OsQueryConfigs[$OsName]
                [void]$OsQueries.Add([PSCustomObject]@{
                    Name = $OsName
                    BaseFilter = "appId eq '$($Cfg.AppId)' and $GraphFilterString and $($Cfg.EventType) and $($Cfg.OSFilter)"
                })
                [void]$AddedOSes.Add($OsName)
            }
        }
        # Initialize variables used
        [System.Collections.ArrayList]$AllSignInLogs = [System.Collections.ArrayList]::new()
        [hashtable]$SignInsByDeviceHash = @{}
        [bool]$WindowsSucceeded = $false
        # Pre-calculate timestamps for test
        [string]$TestTimeStr = (Get-Date).AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        # Get graph objects per OS type
        foreach ($OsQuery in $OsQueries) {
            if ($OsQuery.Name -eq 'Windows Fallback' -and $WindowsSucceeded) {
                Write-Verbose "Windows logs already retrieved, skipping fallback"
                continue
            }
            Write-Verbose "Querying $($OsQuery.Name) sign-in logs"
            try {
                # Quick existence check with 1-day window to speed up no-data scenarios
                [string]$TestFilter = "createdDateTime gt $TestTimeStr and $($OsQuery.BaseFilter)"
                try {
                    $QuickCheck = Invoke-MgGraphRequestSingle `
                        -GraphRunProfile 'beta' `
                        -GraphMethod 'GET' `
                        -GraphObject 'auditLogs/signIns' `
                        -GraphProperties $GraphProperties `
                        -GraphFilters $TestFilter `
                        -GraphPageSize 1 `
                        -GraphCount $false `
                        -GraphSkipPagination $true `
                        -GraphMaxRetry 1 `
                        -GraphWaitTime $GraphWaitTime

                    # Check if results exist
                    [bool]$HasResults = $false
                    if ($QuickCheck) {
                        if ($QuickCheck -is [System.Collections.ICollection] -and $QuickCheck.Count -gt 0) {
                            $HasResults = $true
                        } elseif ($QuickCheck -is [PSCustomObject]) {
                            $HasResults = $true
                        }
                    }
                }
                catch {
                    Write-Verbose "Quick check failed for $($OsQuery.Name): $($_.Exception.Message)"
                    $HasResults = $false  
                }
                
                if ($HasResults) {
                    Write-Verbose "Found $($OsQuery.Name) logs, fetching full dataset using optimized batch approach..."
                    # Build time chunks for more stable retrieval (7-day chunks)
                    [int]$ChunkDays = 7
                    [datetime]$CurrentStart = $SignInsStartTime
                    [datetime]$EndTime = [DateTime]::Now
                    [System.Collections.ArrayList]$TimeChunks = [System.Collections.ArrayList]::new()
                    while ($CurrentStart -lt $EndTime) {
                        [datetime]$CurrentEnd = if ($CurrentStart.AddDays($ChunkDays) -gt $EndTime) { $EndTime } else { $CurrentStart.AddDays($ChunkDays) }
                        [void]$TimeChunks.Add([PSCustomObject]@{
                            id = "$($OsQuery.Name)_$($CurrentStart.ToString('yyyyMMdd'))_$($CurrentEnd.ToString('yyyyMMdd'))"
                            StartTime = $CurrentStart
                            EndTime = $CurrentEnd
                        })
                        $CurrentStart = $CurrentEnd
                    }
                    Write-Verbose "Created $($TimeChunks.Count) time chunks for $($OsQuery.Name)"
                    [System.Collections.ArrayList]$ChunkResults = [System.Collections.ArrayList]::new()
                    foreach ($Chunk in $TimeChunks) {
                        [string]$ChunkFilter = "createdDateTime gt $($Chunk.StartTime.ToString('yyyy-MM-ddTHH:mm:ssZ')) and createdDateTime lt $($Chunk.EndTime.ToString('yyyy-MM-ddTHH:mm:ssZ')) and $($OsQuery.BaseFilter)"
                        Write-Verbose "Fetching chunk: $($Chunk.id)"
                        try {
                            $ChunkLogs = Invoke-MgGraphRequestSingle `
                                -GraphRunProfile 'beta' `
                                -GraphMethod 'GET' `
                                -GraphObject 'auditLogs/signIns' `
                                -GraphProperties $GraphProperties `
                                -GraphFilters $ChunkFilter `
                                -GraphPageSize 999 `
                                -GraphMaxRetry $GraphMaxRetry `
                                -GraphWaitTime $GraphWaitTime
                            
                            if ($ChunkLogs) {
                                # Force array to handle single-object returns from Graph API
                                [array]$ChunkLogsArray = @($ChunkLogs)
                                Write-Verbose "Chunk $($Chunk.id): Retrieved $($ChunkLogsArray.Count) logs"
                                [void]$ChunkResults.AddRange($ChunkLogsArray)
                            }
                        }
                        catch {
                            Write-Warning "Chunk $($Chunk.id) failed: $($_.Exception.Message)"
                        }
                    }
                    
                    # Process all results for this OS type
                    if ($ChunkResults.Count -gt 0) {
                        Write-Verbose "Processing $($ChunkResults.Count) logs for $($OsQuery.Name)"
                        # Apply ReplaceUserAccounts filtering if specified
                        [array]$FilteredLogs = if ($ReplaceUserAccounts -and $ReplaceUserAccounts.Count -gt 0) {
                            [int]$PreCount = $ChunkResults.Count
                            [array]$Filtered = @($ChunkResults | Where-Object {
                                [string]$Upn = $_.userPrincipalName
                                [bool]$ShouldExclude = $false
                                foreach ($pattern in $ReplaceUserAccounts) {
                                    if ($Upn -like $pattern) {
                                        $ShouldExclude = $true
                                        break
                                    }
                                }
                                -not $ShouldExclude
                            })
                            Write-Verbose "Pre-filtered replace accounts for $($OsQuery.Name): $PreCount → $($Filtered.Count)"
                            $Filtered
                        } 
                        else {$ChunkResults}
                        
                        # Group sign-ins by device ID efficiently
                        foreach ($SignIn in $FilteredLogs) {
                            [string]$DeviceId = $SignIn.deviceDetail.deviceId
                            if ($DeviceId) {
                                if (-not $SignInsByDeviceHash.ContainsKey($DeviceId)) {
                                    $SignInsByDeviceHash[$DeviceId] = [System.Collections.ArrayList]::new()
                                }
                                [void]$SignInsByDeviceHash[$DeviceId].Add($SignIn)
                            }
                        }
                        [void]$AllSignInLogs.AddRange($FilteredLogs)
                        if ($OsQuery.Name -eq 'Windows') { $WindowsSucceeded = $true }
                        Write-Verbose "Completed $($OsQuery.Name) - Total logs: $($AllSignInLogs.Count), Unique devices: $($SignInsByDeviceHash.Count)"
                    }
                }
            }
            catch {
                Write-Warning "Failed to retrieve $($OsQuery.Name) sign-in logs: $($_.Exception.Message)"
            }
        }
        if ($AllSignInLogs -and $AllSignInLogs.Count -gt 0) {
            Write-Verbose "Successfully retrieved $($AllSignInLogs.Count) total sign-in logs from $($SignInsByDeviceHash.Count) unique devices"
        }
        else {
            Write-Warning "No sign-in logs found for selected operating systems"
        }
    }
    catch {
        Write-Error "Failed to get sign-in logs: $($_.Exception.Message)"
        throw
    }

    # Process all devices and set the primary user to the most frequent user
    foreach ($Device in $AllDevices) {
        # Cache device properties for faster access
        [string]$DeviceName = $Device.DeviceName
        [string]$DeviceId = $Device.id
        [string]$DeviceAzureAdId = $Device.AzureAdDeviceId

        # Get current Primary User
        [object]$CurrentPrimaryUser = $null
        [string]$CurrentPrimaryUserUPN = if ($Device.userId -and $AllUsersByIdHash.TryGetValue($Device.userId, [ref]$CurrentPrimaryUser)) {
            Write-Verbose "Current primary user: $($CurrentPrimaryUser.userPrincipalName) for device $DeviceName"
            $CurrentPrimaryUser.userPrincipalName
        } else {
            Write-Warning "Current primary user for device $DeviceName is missing or invalid"
            "No.CurrentPrimaryUser"
        }
        
        # Early exit: Check if current primary user matches KeepUserAccounts pattern
        if ($KeepUserAccounts -and $KeepUserAccounts.Count -gt 0 -and $CurrentPrimaryUserUPN -ne 'No.CurrentPrimaryUser') {
            [bool]$IsProtected = $false
            foreach ($KeepPattern in $KeepUserAccounts) {
                if ($CurrentPrimaryUserUPN -like $KeepPattern) {
                    & $AddReport -Target $DeviceName -OldValue $CurrentPrimaryUserUPN -NewValue "N/A" -Action "Skipped-Protected" -Details "Primary User Protected By KeepUserAccounts"
                    Write-Verbose "Current primary user $CurrentPrimaryUserUPN matches keep account '$KeepPattern' - will not replace"
                    $IsProtected = $true
                    break
                }
            }
            if ($IsProtected) { continue }
        }
        
        try {
            # Early exit: Check if device has sign-in logs
            [System.Collections.ArrayList]$SignInLogsOnDevice = $SignInsByDeviceHash[$DeviceAzureAdId]
            if (-not $SignInLogsOnDevice) {
                & $AddReport -Target $DeviceName -OldValue $CurrentPrimaryUserUPN -NewValue "No.SignInLogs" -Action "Skipped-NoLogs" -Details "Missing SignIn Logs For The Device"
                Write-Warning "No SignIn logs found for device $DeviceName"
                continue
            }
            
            # Find most frequent user
            [array]$GroupedUsers = @($SignInLogsOnDevice | Group-Object -Property userPrincipalName | Sort-Object -Property Count -Descending)
            [string]$MostFrequentUserUPN = ($GroupedUsers | Select-Object -First 1).Name
            
            # Early exit: No valid frequent user found
            if (-not $MostFrequentUserUPN) {
                & $AddReport -Target $DeviceName -OldValue $CurrentPrimaryUserUPN -NewValue "No.MostFrequentUser" -Action "Skipped-NoUser" -Details "Missing Most Frequent User in Sign-In Logs"
                Write-Warning "No valid Most Frequent User found in sign-in logs for device $DeviceName"
                continue
            }
            
            # Trim whitespace and normalize the UPN (sign-in logs might have extra spaces)
            $MostFrequentUserUPN = $MostFrequentUserUPN.Trim()
            
            # Lookup user ID with case-insensitive matching
            [string]$MostFrequentUserID = $null
            [object]$FoundUser = $null
            
            if ($AllUsersByUPNHash.TryGetValue($MostFrequentUserUPN, [ref]$FoundUser)) {
                $MostFrequentUserID = $FoundUser.id
            }
            
            [int]$SignInCount = ($GroupedUsers | Select-Object -First 1).Count
            Write-Verbose "Selected primary user candidate: $MostFrequentUserUPN (Sign-ins: $SignInCount)"
            
            # Early exit: Check if MostFrequentUserID is missing
            if (-not $MostFrequentUserID) {
                & $AddReport -Target $DeviceName -OldValue $CurrentPrimaryUserUPN -NewValue $MostFrequentUserUPN -Action "Failed" -Details "Most Frequent User $MostFrequentUserUPN Not Found"
                Write-Warning "Most frequent user '$MostFrequentUserUPN' not found in user hashtable for device $DeviceName (hashtable has $($AllUsersByUPNHash.Count) entries)"
                continue
            }
            
            # Early exit: Check if primary user already correct
            if ($CurrentPrimaryUserUPN -ne 'No.CurrentPrimaryUser' -and $MostFrequentUserUPN.Equals($CurrentPrimaryUserUPN, [StringComparison]::OrdinalIgnoreCase)) {
                & $AddReport -Target $DeviceName -OldValue $CurrentPrimaryUserUPN -NewValue $MostFrequentUserUPN -Action "Correct" -Details "Correct Primary User"
                Write-Verbose "Device $DeviceName already has the correct Primary User $CurrentPrimaryUserUPN"
                continue
            }
            
            # Change of primary user is needed
            Write-Verbose "Determined change needed on Device $DeviceName primary user from $CurrentPrimaryUserUPN to $MostFrequentUserUPN"

            if ($PSCmdlet.ShouldProcess("Device $DeviceName", "Set Primary User To $MostFrequentUserUPN")) {
                try {
                    # Attempt to set the primary user
                    [string]$GraphBody = @{ "@odata.id" = "https://graph.microsoft.com/beta/users/$MostFrequentUserID" } | ConvertTo-Json
                    
                    Invoke-MgGraphRequestSingle `
                        -GraphRunProfile 'beta' `
                        -GraphMethod 'POST' `
                        -GraphBody $GraphBody `
                        -GraphObject "deviceManagement/managedDevices/$DeviceId/users/`$ref" `
                        -GraphMaxRetry $GraphMaxRetry `
                        -GraphWaitTime $GraphWaitTime

                    
                    & $AddReport -Target $DeviceName -OldValue $CurrentPrimaryUserUPN -NewValue $MostFrequentUserUPN -Action "Success-Updated" -Details "Primary User Set To $MostFrequentUserUPN"
                    Write-Verbose "Successfully set Primary User $MostFrequentUserUPN for device $DeviceName"
                }
                catch {
                    & $AddReport -Target $DeviceName -OldValue $CurrentPrimaryUserUPN -NewValue $MostFrequentUserUPN -Action "Failed" -Details "$($_.Exception.Message)"
                    Write-Warning "Failed to set Primary User $MostFrequentUserUPN for device $DeviceName with error: $($_.Exception.Message)"
                }
            } else {
                & $AddReport -Target $DeviceName -OldValue $CurrentPrimaryUserUPN -NewValue $MostFrequentUserUPN -Action "WhatIf" -Details "Would set primary User $MostFrequentUserUPN"
                Write-Verbose "WhatIf: Would set Primary User $MostFrequentUserUPN for device $DeviceName"
            }
        }
        catch {
            & $AddReport -Target $DeviceName -OldValue $CurrentPrimaryUserUPN -NewValue 'FailedDuringProcessing' -Action "Failed" -Details "$($_.Exception.Message)"
            Write-Error "Failed to process device $DeviceName`: $($_.Exception.Message)"
        }
    }
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
}
finally { #End Script and restore preferences
    # Disconnect from Graph
    try {
        Disconnect-MgGraph -ErrorAction Stop *>$null
        Write-Verbose "Disconnected from Graph"
    } 
    catch {Write-Warning "Failed to disconnect from Graph: $($_.Exception.Message)"}
    # Restore original preference settings to user's console
    $ErrorActionPreference  = $script:OriginalErrorActionPreference
    $VerbosePreference      = $script:OriginalVerbosePreference
    $WhatIfPreference       = $script:OriginalWhatIfPreference
    # End T-Bone custom logging before report generation so report output reaches the caller's normal stdout stream
    Invoke-TboneLog -LogMode Stop
    [object]$GeneratedReport = $null
    [string[]]$EmailRecipients = @()
    if (-not [string]::IsNullOrWhiteSpace($EmailTo)) {
        $EmailRecipients = @(
            $EmailTo -split '[,;`r`n]+'
            | ForEach-Object { $_.Trim() }
            | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
    }
    $script:LastScriptReport = $null
    if ($ReportEnabled -or $EmailReportEnabled) {
        [bool]$PersistReportToDisk = $ReportToDisk -or $EmailReportEnabled
        [string]$EffectiveReportToDiskPath = if ($PersistReportToDisk -and -not [string]::IsNullOrWhiteSpace($ReportToDiskPath)) {
            $ReportToDiskPath
        }
        elseif ($env:TEMP) {
            $env:TEMP
        }
        else {
            '/tmp'
        }

        Invoke-ScriptReport `
            -ReportTitle $ReportTitle `
            -ReportResults $ReportResults `
            -ReportStartTime $ReportStartTime `
            -ReportDetailed $ReportDetailed `
            -ReportToDisk $PersistReportToDisk `
            -ReportToDiskPath $EffectiveReportToDiskPath `
            -ReportFormat 'CSV' `
            -ReportEmitOutput $ReportEnabled
        $GeneratedReport = $script:LastScriptReport
    }
    else {
        Write-Verbose "Report generation not requested"
    }

    if ($EmailReportEnabled) {
        [string[]]$MissingEmailSettings = @()
        if ([string]::IsNullOrWhiteSpace($EmailRelayServer)) { $MissingEmailSettings += 'EmailRelayServer' }
        if ([string]::IsNullOrWhiteSpace($EmailFrom)) { $MissingEmailSettings += 'EmailFrom' }
        if ($EmailRecipients.Count -eq 0) { $MissingEmailSettings += 'EmailTo' }
        if ($null -eq $GeneratedReport) { $MissingEmailSettings += 'GeneratedReport' }
        if ($null -eq $GeneratedReport.SavedReportPath -or -not (Test-Path -LiteralPath $GeneratedReport.SavedReportPath -PathType Leaf)) { $MissingEmailSettings += 'SavedReportPath' }

        if ($MissingEmailSettings.Count -gt 0) {
            Write-Warning "Email report enabled but missing required values: $($MissingEmailSettings -join ', '). Skipping email delivery."
        }
        else {
            [string]$ResolvedEmailSubject = if ([string]::IsNullOrWhiteSpace($EmailSubject)) {
                "$ReportTitle - $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
            }
            else {
                $EmailSubject
            }
            [string]$EmailBody = @(
                $GeneratedReport.SummaryText
                ""
                "Full report attached: $(Split-Path -Path $GeneratedReport.SavedReportPath -Leaf)"
            ) -join [Environment]::NewLine

            try {
                Invoke-SendSmtpReport `
                    -SmtpServer $EmailRelayServer `
                    -SmtpPort $EmailRelayPort `
                    -From $EmailFrom `
                    -To $EmailRecipients `
                    -Subject $ResolvedEmailSubject `
                    -Body $EmailBody `
                    -AttachmentPath $GeneratedReport.SavedReportPath
                Write-Output "Report email sent: $($EmailRecipients -join ', ')"
            }
            catch {
                Write-Warning $_.Exception.Message
            }
        }
    }
    # End script and report memory usage 
    [double]$MemoryUsage = [Math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 2)
    Write-Verbose "Script finished. Memory usage: $MemoryUsage MB"
}
#endregion




