---
layout: post
title:  "How to create an Azure Function that queries Microsoft Entra ID Roles to send metrics to Azure Log Analytics Workspace"
date:   2023-07-31 11:21:00 +0200
categories: Azure
---

# Goals
Create an Azure Function App that can authenticate to Microsoft Entra ID (formerly Azure Active Directory) to query role memberships (eg. Global Administrator), then send them to log analytics, to then be displayed in Azure Monitor or Azure Dashboards.

This can be used to create charts or metrics on the number of holders of specific roles.

For this POC we will develop the Function app on the Azure Portal. For a production environment I recommend using Infrastructure as Code deployment through a CI/CD pipeline.

# Prerequisites
- Azure Tenant with an administrative account with permissions to
    - create resources,
    - manage App registrations,
    - manage admin consent for the application,
    - read Azure roles,
    - create secrets in Key Vault (eg. Key Vault Administrator role)
- Azure subscription

# Azure resources used
- Function App
- Log Analytics workspace
- Monitor/Azure Dashboards
- Key Vault

# Deployment

## Create the Azure Function App
1. On the [Azure Portal](https://portal.azure.com) search for [Function App](https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites/kind/functionapp)
2. Click `Create`
3. On Basics
    - Select a Subscription and Resource group
    - Give the app a descriptive name that will also be the URL of the app. This has to be globally unique
    - Select `Code`
    - Select `PowerShell Core` as the Runtime Stack
    - Select the latest available version
    - Select your region
    - Select `Windows` as your OS
    - Select `Consumption (Serverless)` as the hosting option
4. On Storage
    - Create a new or select an existing Storage Account to store the Function App data
5. Click `Review + create`. Wait for the validation to complete and click create.

## Create the Log Analytics Workspace
This Log Analytics workspace will be used to host the data in a table that will be used to visualize the number of role holders on a Dashboard.

1. On the [Azure Portal](https://portal.azure.com) search for [Log Analytics workspaces](https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.OperationalInsights%2Fworkspaces)
2. Click `Create`
3. On Basics
    - Select a Subscription and Resource group
    - Select a descriptive name
    - Select your region
4. Click `Review + create`. Wait for the validation to complete and click create.

### Create a Data Collection Endpoint

1. On the [Azure Portal](https://portal.azure.com) search for [Data Collection Endpoints](https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/microsoft.insights%2Fdatacollectionendpoints)
    - Click `Create`
    - Add a descriptive name eg. `EntraIDMonitorDCE`, select the Resource Group and Region
    - Click `Review + create`, wait for the validation to complete and click `Create`
2. Navigate to the Data Collection Endpoint
    - On the overview pane copy and save the Log ingestion URI in the form of `https://DCEId.regionId.ingest.monitor.azure.com`. It will be used by the Function App to send the data.

### Configure the Log Analytics Workspace to use the DCE to accept custom logs
[Reference](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-portal)

1. On the [Azure Portal](https://portal.azure.com) search for [Log Analytics workspaces](https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.OperationalInsights%2Fworkspaces)
2. Select the Log Analytics Workspace created before and go to `Settings/Tables`
3. Click `Create/New custom log (DCR-based)`
    - Add a descriptive name for the table eg. EntraIDRoleCount. Azure automatically appends `_CL` to the name of every custom table, so the final name will be `EntraIDRoleCount_CL`
    - For the Data collection rule click `Create new data collection rule`, add a descriptive name to the new DCR eg. EntraIDRoleCountDCR and click `Done`
    - For the Data collection endpoint select the previously created DCE and click `Next`
    - On `Schema and transformation` upload a sample `.json` file eg.:
      ```
      [
          {
              "TimeGenerated": "2023-08-02T07:01:23.4567891Z",
              "RoleId": "00000000-0000-0000-0000-000000000000",
              "RoleHolderCount": 9999
          },
          {
              "TimeGenerated": "2023-08-02T07:01:23.4567892Z",
              "RoleId": "00000000-0000-0000-0000-000000000000",
              "RoleHolderCount": 9998
          },
          {
              "TimeGenerated": "2023-08-02T07:01:23.4567893Z",
              "RoleId": "00000000-0000-0000-0000-000000000000",
              "RoleHolderCount": 9997
          },
          {
              "TimeGenerated": "2023-08-02T07:01:23.4567894Z",
              "RoleId": "00000000-0000-0000-0000-000000000000",
              "RoleHolderCount": 9996
          },
          {
              "TimeGenerated": "2023-08-02T07:01:23.4567895Z",
              "RoleId": "00000000-0000-0000-0000-000000000000",
              "RoleHolderCount": 9995
          },
          {
              "TimeGenerated": "2023-08-02T07:01:23.4567896Z",
              "RoleId": "00000000-0000-0000-0000-000000000000",
              "RoleHolderCount": 9994
          },
          {
              "TimeGenerated": "2023-08-02T07:01:23.4567897Z",
              "RoleId": "00000000-0000-0000-0000-000000000000",
              "RoleHolderCount": 9993
          },
          {
              "TimeGenerated": "2023-08-02T07:01:23.4567898Z",
              "RoleId": "00000000-0000-0000-0000-000000000000",
              "RoleHolderCount": 9992
          },
          {
              "TimeGenerated": "2023-08-02T07:01:23.4567899Z",
              "RoleId": "00000000-0000-0000-0000-000000000000",
              "RoleHolderCount": 9991
          },
          {
              "TimeGenerated": "2023-08-02T07:01:23.4567810Z",
              "RoleId": "00000000-0000-0000-0000-000000000000",
              "RoleHolderCount": 9990
          },
          {
              "TimeGenerated": "2023-08-02T07:01:23.4567811Z",
              "RoleId": "00000000-0000-0000-0000-000000000000",
              "RoleHolderCount": 9989
          },
          {
              "TimeGenerated": "2023-08-02T07:01:23.4567812Z",
              "RoleId": "00000000-0000-0000-0000-000000000000",
              "RoleHolderCount": 9988
          }
      ]
      ```
    - Alternatively use [this tool](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-portal#generate-sample-data) to generate the sample data file. The tool can also be used to upload the sample data to the Log Analytics Workspace Table.
    - Click `Next` and then `Create`
    - Find the `immutableId` of the DCR according to [this reference](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-portal#collect-information-from-the-dcr) and save it. It will be used by the Function App to send the data.

## Configure the Azure Function App
1. After the Azure Function App is deployed, navigate to the resource.
2. Under `Settings/Authentication` configure Microsoft as an Identity Provider to create an App registration in your Tenant.
    - Click `Add identity provider`
    - For the identity provider select `Microsoft`
    - For the Tenant type select `Workforce`
    - For the App registration type select `Create new app registration`
    - Create a descriptive name for your App registration
    - For the Supported account types select `Current tenant - Single tenant`
    - On the bottom of the page click `Add`
3. To configure the required permissions:
    - Navigate to [App registrations](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps) in your Tenant
    - Select `All applications` and search for your App registration
    - Navigate to `Manage/API permissions`
    - Under Configured permissions you should see `User.Read.All` permission already added with a `Delegated` permission type. We will not use this, you can remove it using the ellipsis (...) at the end of the row.
    - Click `Add a permission`, select `Microsoft Graph`, select `Application permissions`
    - Search for the permission `User.Read.All`, select it, then search for `RoleManagement.Read.All`, select it, then click `Add permissions`
    - Click `Grant admin consent for <YourTenantName>`
4. To configure the authentication of the application we will use Client secrets
    - Still on the `App registration` of our Function App navigate to `Manage/Certificates & Secrets`
    - Click on `Client secrets`
    - Click `New client secret`
    - Add a description and select an expiration, then click `Add`
    - Save the `Value` of the Client Secret safely. This is a high value credential that is only displayed once.
5. Navigate to `Settings/Identity` and switch the status from `Off` to `On` to configure the Managed Identity of the Function App.

### Configure prerequisites
1. Navigate to `Functions/App files` in your Function App.
2. On the file navigation row select the `host.json` configuration file and make sure that the `managedDependency` setting is set to `true`.
3. On the file navigation row select the `requirements.psd1` configuration file. Replace the contents with the below code:

   ```
   @{
       'Az' = '10.*'
       'Microsoft.Graph.Identity.DirectoryManagement' = '2.2.0'
       'Microsoft.Graph.Authentication' = '2.2.0'
   }
   ```
4. On the file navigation row select the `profile.ps1` configuration file and add the below rows:

   ```
   Import-Module Az
   Import-Module Microsoft.Graph.Identity.DirectoryManagement
   Import-Module Microsoft.Graph.Authentication
   ```
5. Navigate to the Overview pane of the Function App and click `Restart` and `Yes` to confirm, in order for prerequisites defined in the App Files to take effect.
6. Wait for the restart to complete and navigate to `Functions/Functions`
7. Click `Create`, Select `Timer trigger`, add a descriptive name to the Function e.g. `EntraIDRoleQuery`, set the schedule to how often you would like the data to be refreshed.

### Create KeyVault Secret with Client Secret Value

1. On the [Azure Portal](https://portal.azure.com) search for [Key Vaults](https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2Fvaults)
2. Click `New` and create a dedicated Key Vault for your Entra ID secret management
3. Navigate to `Access control (IAM)`
    - Click `Add/Add role assignment`
    - Select `Key Vault Secrets User`
    - Click `Next`
    - Under Members for Assign access to select `Managed identity`
    - For members select the Managed identity of the Function App and click `Select`, then `Review + Assign` twice.
4. Navigate to `Objects/Secrets`
    - Click `Generate/Import`
    - For Upload options leave the default `Manual` setting
    - Add a descriptive name (eg. EntraIDMonitorClientSecret) and the Client Secret Value saved earlier in the App registration
    - Optionally set an expiration date, then click `Create`

### Grant the Function App access to the Data Collection Rule
The Function App will send the data to the Data Collection Endpoint, which forwards it according to the Data Collection Rule. To authorize the Function App:

1. On the [Azure Portal](https://portal.azure.com) search for [Data Collection Rules](https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/microsoft.insights%2Fdatacollectionrules)
2. Select the Data Collection Rule created earlier (eg. EntraIDRoleCountDCR)
3. Navigate to `Access control (IAM)`
    - Click `Add/Add role assignment`
    - Select `Monitoring Metrics Publisher`
    - Click `Next`
    - Under Members for Assign access to select `Managed identity`
    - For members select the Managed identity of the Function App and click `Select`, then `Review + Assign` twice.

### Create the script
1. Once the Function is created, navigate to the `Code + Test` pane of the Function and replace the contents of `run.ps1` with the below script. Replace the placeholder values with the ones saved in the previous steps.

```
# Input bindings are passed in via param block.
param($Timer)

# Replace the placeholders with your values
$ClientId = "<Insert App Registration Application (Client) Id Here>"
$VaultName = "<Insert Key Vault Name Here>"
$SecretName = "<Insert Key Vault Secret Name Here>"
# The Log ingestion URI of the DCE eg. https://DCEId.regionId.ingest.monitor.azure.com
$DceIngestionUri = "<Insert Data Collection Endpoint Log Ingestion URI Here>"
# The immutableId of the DCR eg. dcr-00000000000000000000000000000000
$DcrImmutableId = "<Insert DCR immutableId Here>"
# The name of the custom table including the _CL suffix eg. EntraIDRoleCount_CL
$TableName = "<Insert Log Analytics Workspace Table Name Here>"

# Authenticate with the Managed Identity of the Function App
Connect-AzAccount -Identity
Connect-MgGraph -Identity
$TenantId = (Get-MgContext).TenantId

# Query the Key Vault for the Client Secret of the App registration
$Secret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName

# Authenticate to Microsoft Graph with the App registration
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientId, $Secret.SecretValue
Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential

# Query Entra ID
$RoleId = (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'").Id
$RoleHolders = Get-MgDirectoryRoleMemberAsUser -DirectoryRoleId $RoleId
$RoleCount = $RoleHolders.Count

# Create the record to send
$TimeGenerated = Get-Date ([datetime]::UtcNow) -Format O
$Json = @"
[
    {
        "TimeGenerated": "$TimeGenerated",
        "RoleId": "$RoleId",
        "RoleHolderCount": $RoleCount
    }
]
"@

# Send the data to the Log Analytics Workspace table through the Data Collection Endpoint
$Token = (Get-AzAccessToken -ResourceUrl "https://monitor.azure.com").Token
$Headers = @{
    "Authorization" = "Bearer $Token"
    "Content-Type"  = "application/json"
}
$Uri = "$DceIngestionUri/dataCollectionRules/$DcrImmutableId/streams/Custom-$TableName" + "?api-version=2023-01-01"
Invoke-RestMethod -Uri $Uri -Method Post -Headers $Headers -Body $Json
```

2. Click `Save`, then use `Test/Run` to verify that the Function runs successfully.

## Configure the Dashboard

You can find [Azure Dashboards](https://portal.azure.com/#dashboard) above the Favorites bar on the Azure Portal.

You will be able to find the data within the created Log Analytics Workspace under `Settings/Tables`. It is going to be of type `Custom table`.
