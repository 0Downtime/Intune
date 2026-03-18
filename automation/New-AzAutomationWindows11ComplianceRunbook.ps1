<#
.SYNOPSIS
    Provisions an Azure Automation Account runbook for Set-IntuneWindows11CompliancePolicyVersions.ps1 using system-assigned managed identity.

.DESCRIPTION
    This script creates or updates the Azure resources needed to run the Windows 11 compliance policy
    updater as an Azure Automation runbook without hardcoded secrets. It enables a system-assigned
    managed identity, uploads the local runbook script to a private blob with a short-lived SAS for
    import, creates a PowerShell 7.4 Runtime Environment, imports Microsoft.Graph.Authentication into
    that Runtime Environment, creates a schedule, grants the Automation identity the required Microsoft
    Graph application permissions, and links the schedule to the runbook.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Location,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AutomationAccountName,

    [ValidateNotNullOrEmpty()]
    [string]$RunbookName = 'Set-IntuneWindows11CompliancePolicyVersions',

    [ValidateNotNullOrEmpty()]
    [string]$RuntimeEnvironmentName = 'PowerShell74Graph',

    [ValidateNotNullOrEmpty()]
    [string]$RunbookPath = (Join-Path $PSScriptRoot '..' 'Set-IntuneWindows11CompliancePolicyVersions.ps1'),

    [ValidateNotNullOrEmpty()]
    [string]$ScheduleName = 'Daily-0200-UTC',

    [datetime]$ScheduleStartTime = ([DateTime]::UtcNow.Date.AddDays(1).AddHours(2)),

    [ValidateSet('Day', 'Hour', 'Minute', 'Month', 'OneTime', 'Week')]
    [string]$ScheduleFrequency = 'Day',

    [ValidateRange(1, 365)]
    [int]$ScheduleInterval = 1,

    [ValidateNotNullOrEmpty()]
    [string]$ScheduleTimeZone = 'UTC',

    [string]$Windows11PolicyId,

    [string]$Windows11PolicyName = 'Windows 11 Compliance',

    [bool]$CreatePolicyIfMissing = $false,

    [ValidateRange(0, 6)]
    [int]$PatchLagMonths = 1,

    [bool]$ManageAssignments = $true,

    [string]$Windows11GroupName = 'Intune Windows 11 Devices',

    [string]$Windows11GroupMembershipRule,

    [bool]$LogVerboseEnabled = $false,

    [bool]$LogToHost = $true,

    [ValidateNotNullOrEmpty()]
    [string]$MicrosoftGraphAuthenticationVersion = '2.35.1',

    [ValidateNotNullOrEmpty()]
    [string]$AzDefaultPackageVersion = '12.3.0',

    [string]$SubscriptionId,

    [string]$StorageAccountName,

    [ValidateNotNullOrEmpty()]
    [string]$ArtifactContainerName = 'automation-artifacts',

    [switch]$SkipManagedIdentityPermissionAssignment,

    [switch]$SkipScheduleAssociation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-CommandAvailable {
    param([Parameter(Mandatory = $true)][string]$Name)

    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found in PATH."
    }
}

function Invoke-AzCli {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [switch]$ExpectJson
    )

    $output = & az @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "az $($Arguments -join ' ') failed.`n$($output -join [Environment]::NewLine)"
    }

    $text = ($output -join [Environment]::NewLine).Trim()
    if (-not $ExpectJson) {
        return $text
    }
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }
    return $text | ConvertFrom-Json -Depth 100
}

function ConvertTo-ODataStringLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)

    return $Value.Replace("'", "''")
}

function Get-DeterministicStorageAccountName {
    param([Parameter(Mandatory = $true)][string]$Seed)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Seed.ToLowerInvariant())
        $hash = $sha256.ComputeHash($bytes)
    }
    finally {
        $sha256.Dispose()
    }

    $hex = ([System.BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    return ('st' + $hex).Substring(0, 24)
}

function Get-DeterministicGuid {
    param([Parameter(Mandatory = $true)][string]$Seed)

    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Seed)
        $hash = $md5.ComputeHash($bytes)
    }
    finally {
        $md5.Dispose()
    }

    return [guid]::new($hash)
}

function Wait-AutomationProvisioningState {
    param(
        [Parameter(Mandatory = $true)][string]$ResourceId,
        [int]$TimeoutSeconds = 1800
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $state = Invoke-AzCli -Arguments @(
            'resource', 'show',
            '--ids', $ResourceId,
            '--api-version', '2024-10-23',
            '--query', 'properties.provisioningState',
            '-o', 'tsv'
        )

        if ($state -eq 'Succeeded') {
            return
        }
        if ($state -eq 'Failed') {
            throw "Provisioning failed for resource '$ResourceId'."
        }

        Start-Sleep -Seconds 15
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "Timed out waiting for provisioning to complete for '$ResourceId'."
}

function Wait-AutomationResourceExists {
    param(
        [Parameter(Mandatory = $true)][string]$ResourceId,
        [int]$TimeoutSeconds = 600
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            Invoke-AzCli -Arguments @(
                'resource', 'show',
                '--ids', $ResourceId,
                '--api-version', '2024-10-23',
                '--output', 'none'
            ) | Out-Null
            return
        }
        catch {
            Start-Sleep -Seconds 10
        }
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "Timed out waiting for resource '$ResourceId' to exist."
}

function Invoke-AzRestJson {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST')][string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [string]$Body
    )

    $arguments = @('rest', '--method', $Method, '--url', $Uri, '--output', 'json')
    if (-not [string]::IsNullOrWhiteSpace($Body)) {
        $arguments += @('--headers', 'Content-Type=application/json', '--body', $Body)
    }

    return Invoke-AzCli -Arguments $arguments -ExpectJson
}

function Resolve-ServicePrincipalByFilter {
    param([Parameter(Mandatory = $true)][string]$Filter)

    $encodedFilter = [uri]::EscapeDataString($Filter)
    $response = Invoke-AzRestJson -Method 'GET' -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$encodedFilter"
    $items = @($response.value)
    if ($items.Count -eq 0) {
        throw "No service principal matched filter: $Filter"
    }
    if ($items.Count -gt 1) {
        throw "Multiple service principals matched filter: $Filter"
    }
    return $items[0]
}

function Ensure-GraphAppRoleAssignments {
    param(
        [Parameter(Mandatory = $true)][string]$ManagedIdentityDisplayName,
        [Parameter(Mandatory = $true)][string[]]$Permissions
    )

    $managedIdentity = Resolve-ServicePrincipalByFilter -Filter "displayName eq '$(ConvertTo-ODataStringLiteral -Value $ManagedIdentityDisplayName)'"
    $graphServicePrincipal = Resolve-ServicePrincipalByFilter -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
    $existingAssignments = Invoke-AzRestJson -Method 'GET' -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($managedIdentity.id)/appRoleAssignments"

    foreach ($permission in $Permissions) {
        $appRole = @($graphServicePrincipal.appRoles | Where-Object {
            $_.value -eq $permission -and $_.allowedMemberTypes -contains 'Application'
        }) | Select-Object -First 1

        if (-not $appRole) {
            throw "Could not resolve Microsoft Graph app role '$permission'."
        }

        $alreadyAssigned = @($existingAssignments.value | Where-Object {
            $_.resourceId -eq $graphServicePrincipal.id -and $_.appRoleId -eq $appRole.id
        }).Count -gt 0

        if ($alreadyAssigned) {
            continue
        }

        $body = @{
            principalId = $managedIdentity.id
            resourceId = $graphServicePrincipal.id
            appRoleId = $appRole.id
        } | ConvertTo-Json -Compress

        Invoke-AzRestJson -Method 'POST' -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($managedIdentity.id)/appRoleAssignments" -Body $body | Out-Null
    }
}

Assert-CommandAvailable -Name 'az'

if (-not (Test-Path -LiteralPath $RunbookPath)) {
    throw "Runbook script not found at '$RunbookPath'."
}

$templatePath = Join-Path $PSScriptRoot 'windows11-compliance-runbook.bicep'

if (-not (Test-Path -LiteralPath $templatePath)) {
    throw "Bicep template not found at '$templatePath'."
}

$account = Invoke-AzCli -Arguments @('account', 'show', '--output', 'json') -ExpectJson
if ($SubscriptionId) {
    Invoke-AzCli -Arguments @('account', 'set', '--subscription', $SubscriptionId) | Out-Null
    $account = Invoke-AzCli -Arguments @('account', 'show', '--output', 'json') -ExpectJson
}

$activeSubscriptionId = [string]$account.id
$tenantId = [string]$account.tenantId

if ([string]::IsNullOrWhiteSpace($activeSubscriptionId) -or [string]::IsNullOrWhiteSpace($tenantId)) {
    throw "Unable to resolve the active Azure subscription or tenant. Run 'az login' first."
}

if ([string]::IsNullOrWhiteSpace($StorageAccountName)) {
    $StorageAccountName = Get-DeterministicStorageAccountName -Seed "$activeSubscriptionId|$ResourceGroupName|$AutomationAccountName"
}

$runbookFileName = Split-Path -Leaf $RunbookPath
$artifactBlobName = "$RunbookName/$runbookFileName"
$moduleUri = "https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Authentication/$MicrosoftGraphAuthenticationVersion"
$jobScheduleGuid = (Get-DeterministicGuid -Seed "$activeSubscriptionId|$ResourceGroupName|$AutomationAccountName|$RunbookName|$ScheduleName").Guid
$runtimeEnvironmentResourceId = "/subscriptions/$activeSubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runtimeEnvironments/$RuntimeEnvironmentName"
$packageResourceId = "$runtimeEnvironmentResourceId/packages/Microsoft.Graph.Authentication"
$jobScheduleResourceId = "/subscriptions/$activeSubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobSchedules/$jobScheduleGuid"

if ($PSCmdlet.ShouldProcess($ResourceGroupName, "Create or update Azure resources for the Windows 11 compliance Automation runbook")) {
    Invoke-AzCli -Arguments @('provider', 'register', '--namespace', 'Microsoft.Automation', '--wait') | Out-Null
    Invoke-AzCli -Arguments @('provider', 'register', '--namespace', 'Microsoft.Storage', '--wait') | Out-Null

    Invoke-AzCli -Arguments @('group', 'create', '--name', $ResourceGroupName, '--location', $Location, '--output', 'none') | Out-Null

    Invoke-AzCli -Arguments @(
        'storage', 'account', 'create',
        '--name', $StorageAccountName,
        '--resource-group', $ResourceGroupName,
        '--location', $Location,
        '--sku', 'Standard_LRS',
        '--kind', 'StorageV2',
        '--allow-blob-public-access', 'false',
        '--https-only', 'true',
        '--min-tls-version', 'TLS1_2',
        '--output', 'none'
    ) | Out-Null

    $storageKey = Invoke-AzCli -Arguments @(
        'storage', 'account', 'keys', 'list',
        '--resource-group', $ResourceGroupName,
        '--account-name', $StorageAccountName,
        '--query', '[0].value',
        '-o', 'tsv'
    )

    Invoke-AzCli -Arguments @(
        'storage', 'container', 'create',
        '--name', $ArtifactContainerName,
        '--account-name', $StorageAccountName,
        '--account-key', $storageKey,
        '--public-access', 'off',
        '--output', 'none'
    ) | Out-Null

    Invoke-AzCli -Arguments @(
        'storage', 'blob', 'upload',
        '--container-name', $ArtifactContainerName,
        '--name', $artifactBlobName,
        '--file', $RunbookPath,
        '--overwrite', 'true',
        '--account-name', $StorageAccountName,
        '--account-key', $storageKey,
        '--output', 'none'
    ) | Out-Null

    $sasExpiry = [DateTime]::UtcNow.AddHours(24).ToString("yyyy-MM-ddTHH:mmZ")
    $runbookContentUri = Invoke-AzCli -Arguments @(
        'storage', 'blob', 'generate-sas',
        '--account-name', $StorageAccountName,
        '--account-key', $storageKey,
        '--container-name', $ArtifactContainerName,
        '--name', $artifactBlobName,
        '--permissions', 'r',
        '--expiry', $sasExpiry,
        '--https-only',
        '--full-uri',
        '-o', 'tsv'
    )

    $deployment = Invoke-AzCli -Arguments @(
        'deployment', 'group', 'create',
        '--resource-group', $ResourceGroupName,
        '--name', "windows11-compliance-runbook-$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))",
        '--template-file', $templatePath,
        '--parameters',
        "automationAccountName=$AutomationAccountName",
        "location=$Location",
        "runbookName=$RunbookName",
        "runtimeEnvironmentName=$RuntimeEnvironmentName",
        "runbookContentUri=$runbookContentUri",
        "moduleContentUri=$moduleUri",
        "azDefaultPackageVersion=$AzDefaultPackageVersion",
        "scheduleName=$ScheduleName",
        "scheduleStartTime=$($ScheduleStartTime.ToString('o'))",
        "scheduleFrequency=$ScheduleFrequency",
        "scheduleInterval=$ScheduleInterval",
        "timeZone=$ScheduleTimeZone",
        '--output', 'json'
    ) -ExpectJson

    Wait-AutomationResourceExists -ResourceId $runtimeEnvironmentResourceId
    Wait-AutomationProvisioningState -ResourceId $packageResourceId

    if (-not $SkipManagedIdentityPermissionAssignment) {
        Ensure-GraphAppRoleAssignments `
            -ManagedIdentityDisplayName $AutomationAccountName `
            -Permissions @('DeviceManagementConfiguration.ReadWrite.All', 'Group.ReadWrite.All')
    }

    if (-not $SkipScheduleAssociation) {
        $jobParameters = [ordered]@{
            CreatePolicyIfMissing = $CreatePolicyIfMissing
            PatchLagMonths = $PatchLagMonths
            ManageAssignments = $ManageAssignments
            LogVerboseEnabled = $LogVerboseEnabled
            LogToHost = $LogToHost
        }

        if (-not [string]::IsNullOrWhiteSpace($Windows11PolicyId)) {
            $jobParameters['Windows11PolicyId'] = $Windows11PolicyId
        }
        if (-not [string]::IsNullOrWhiteSpace($Windows11PolicyName)) {
            $jobParameters['Windows11PolicyName'] = $Windows11PolicyName
        }
        if (-not [string]::IsNullOrWhiteSpace($Windows11GroupName)) {
            $jobParameters['Windows11GroupName'] = $Windows11GroupName
        }
        if (-not [string]::IsNullOrWhiteSpace($Windows11GroupMembershipRule)) {
            $jobParameters['Windows11GroupMembershipRule'] = $Windows11GroupMembershipRule
        }

        $jobScheduleBody = @{
            properties = @{
                runbook = @{
                    name = $RunbookName
                }
                schedule = @{
                    name = $ScheduleName
                }
                parameters = $jobParameters
            }
        } | ConvertTo-Json -Depth 10 -Compress

        Invoke-AzCli -Arguments @(
            'rest',
            '--method', 'put',
            '--uri', "https://management.azure.com$jobScheduleResourceId?api-version=2024-10-23",
            '--body', $jobScheduleBody,
            '--headers', 'Content-Type=application/json',
            '--output', 'none'
        ) | Out-Null
    }

    [PSCustomObject]@{
        SubscriptionId = $activeSubscriptionId
        TenantId = $tenantId
        ResourceGroupName = $ResourceGroupName
        AutomationAccountName = $AutomationAccountName
        RuntimeEnvironmentName = $RuntimeEnvironmentName
        StorageAccountName = $StorageAccountName
        RunbookName = $RunbookName
        ScheduleName = $ScheduleName
        PackageName = 'Microsoft.Graph.Authentication'
        PackageUri = $moduleUri
        JobScheduleId = $jobScheduleGuid
        DeploymentName = $deployment.name
    }
}
