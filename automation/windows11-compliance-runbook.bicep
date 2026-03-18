@description('Name of the Azure Automation account.')
param automationAccountName string

@description('Azure region for the Automation account resources.')
param location string

@description('Runbook name to create or update.')
param runbookName string = 'Set-IntuneWindows11CompliancePolicyVersions'

@description('Runtime Environment name to create or update.')
param runtimeEnvironmentName string = 'PowerShell74Graph'

@description('Description for the Runtime Environment.')
param runtimeEnvironmentDescription string = 'PowerShell 7.4 Runtime Environment for Windows 11 compliance automation.'

@description('Az module bundle version to include as a default package in the Runtime Environment.')
param azDefaultPackageVersion string = '12.3.0'

@description('Description for the runbook.')
param runbookDescription string = 'Keeps an Intune Windows 11 compliance policy aligned to supported releases.'

@description('HTTPS URI to the published PowerShell runbook content.')
param runbookContentUri string

@description('Automation module name required by the runbook.')
param moduleName string = 'Microsoft.Graph.Authentication'

@description('HTTPS URI to the PowerShell module package (.nupkg).')
param moduleContentUri string

@description('Name of the Automation schedule to create or update.')
param scheduleName string = 'Daily-0200-UTC'

@description('Description for the Automation schedule.')
param scheduleDescription string = 'Runs the Windows 11 compliance policy version updater.'

@description('UTC or timezone-aware start time for the schedule.')
param scheduleStartTime string

@allowed([
  'Day'
  'Hour'
  'Minute'
  'Month'
  'OneTime'
  'Week'
])
@description('Automation schedule frequency.')
param scheduleFrequency string = 'Day'

@minValue(1)
@description('Automation schedule interval.')
param scheduleInterval int = 1

@description('Windows timezone name for the schedule.')
param timeZone string = 'UTC'

@description('Enable public network access for the Automation account.')
param publicNetworkAccess bool = true

resource automationAccount 'Microsoft.Automation/automationAccounts@2024-10-23' = {
  name: automationAccountName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    publicNetworkAccess: publicNetworkAccess
    sku: {
      name: 'Basic'
    }
  }
}

resource runtimeEnvironment 'Microsoft.Automation/automationAccounts/runtimeEnvironments@2024-10-23' = {
  parent: automationAccount
  name: runtimeEnvironmentName
  location: location
  properties: {
    defaultPackages: {
      Az: azDefaultPackageVersion
    }
    description: runtimeEnvironmentDescription
    runtime: {
      language: 'PowerShell'
      version: '7.4'
    }
  }
}

resource graphAuthenticationPackage 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2024-10-23' = {
  parent: runtimeEnvironment
  name: moduleName
  properties: {
    contentLink: {
      uri: moduleContentUri
    }
  }
}

resource runbook 'Microsoft.Automation/automationAccounts/runbooks@2024-10-23' = {
  parent: automationAccount
  name: runbookName
  location: location
  properties: {
    description: runbookDescription
    logProgress: true
    logVerbose: true
    publishContentLink: {
      uri: runbookContentUri
    }
    runbookType: 'PowerShell'
    runtimeEnvironment: runtimeEnvironmentName
  }
}

resource schedule 'Microsoft.Automation/automationAccounts/schedules@2024-10-23' = {
  parent: automationAccount
  name: scheduleName
  properties: {
    description: scheduleDescription
    frequency: scheduleFrequency
    interval: scheduleInterval
    startTime: scheduleStartTime
    timeZone: timeZone
  }
}

output automationAccountResourceId string = automationAccount.id
output automationPrincipalId string = automationAccount.identity.principalId
output runtimeEnvironmentResourceId string = runtimeEnvironment.id
output runbookResourceId string = runbook.id
output scheduleResourceId string = schedule.id
output packageResourceId string = graphAuthenticationPackage.id
