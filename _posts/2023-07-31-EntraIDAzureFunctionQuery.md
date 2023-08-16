---
layout: post
title:  "How to create an Azure Function that queries Microsft Entra ID Roles to send metrics to Azure Log Analytics Workspace"
date:   2023-07-31 11:21:00 +0200
categories: Azure
---

# Goals
Create an Azure Function App that can authenticate to Microsft Entra ID (formerly Azure Active Directory) to query role memberships (eg. Global Administrator), then send them to log analytics, to then be displayed in Azure Monitor or Azure Dashboards.

This can be used to create charts or metrics on the number of holders of specific roles.

For this POC we will develop the Function app on the Azure Portal. For a production environment I recommend to use Infrastructure as a Code deployment through a CICD pipeline.

# Prerequisites
- Azure Tenant with an administrative with permission to
    - create resources, 
    - managing App registrations, 
    - managing admin consent for the application, 
    - read azure roles
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
    - Create a new or select an exsisting Storage Account to store the Function App data
5. Click `Review + create`. Wait for the validation to complete and click create.

## Create the Log Analytics Workspace
This Log Analytics worksspace will be used to host the data in a table that will be used to visualize the number of role holders on a Dashboard.

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
- Add a descriptive name eg. `EntraIDMonitorDCE`, select the REsource Group and Region
- Click `Review + create`, wait for the validation to complete and click `Create`
2. Navigate to the Data Collection Endpoint
- On the overview pane copy and save the Log ingestion URI in the form of `https://DCEId.regionId.ingest.monitor.azure.com`

### Configure the Log Analytics Workspace to use the DCE to accept custom logs
(Reference)[https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-portal]

1. On the [Azure Portal](https://portal.azure.com) search for [Log Analytics workspaces](https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.OperationalInsights%2Fworkspaces)
2. Select the Log Analytics Workspace created before and go to `Settings/Tables`
3. Click `Create/New custom log (DCR-based)`
    - Add a descriptive name for the table eg. EntraIDRoleCount
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
    - Find the `immutableId` of the DCR according to [this reference](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-portal#collect-information-from-the-dcr).

## Configure the Azure Function App
1. After the Azure Function App to deployed, navigate to the resource.
2. Under `Settings/Authentication` configure Microsoft as an Identity Provider to create an Application Registartion in your Tenant.
    - Click `Add identity provider`
    - For the identity provider select `Microsoft`
    - For the Tenant type select `Workforce`
    - For the App registration type select `Create new app registration`
    - Create a descriptive name for your App registration
    - For the Supported account types select `Current tenant - Single tenant`
    - On the bottom of the page click `Add`
3. To configure the required permissions:
    - Navigate to [App registrations](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps) in your Tennant
    - Select `All applications` and search for your Application registration
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
2. On the file navigation row select the `host.json` configuration file and make sure that `managedDependency` setting is set to `true`.
3. On the file navigation row select the `requirements.psd1` configuration file. Replace the contents with the below code:
```
@{
    'Az' = '10.*'
    'Microsoft.Graph.Identity.DirectoryManagement' = '2.2.0'
    'Microsoft.Graph.Authentication' = '2.2.0'
}
```
- On the file navgiation row select the `profile.ps1` configuration file and add the below rows:
```
Import-Module Az
Import-Module Microsoft.Graph.Identity.DirectoryManagement
Import-Module Microsoft.Graph.Authentication
```
4. Navigate to the Overview pane of the Function App and click `Restart` and `Yes` to confirm, in order for prerequisites defined in the App Files to take effect.
5. Wait for the restart to complete and navigate to `Functions/Functions`
6. Click `Create`, Select `Timer trigger`, add a descriptive name to the Function e.g. `EntraIDRoleQuery`, set the schedule to how often you would like the data to be refreshed.

### Create KeyVault Secret with Client Secret Value

1. On the [Azure Portal](https://portal.azure.com) search for [Key Vaults](https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2Fvaults)
2. Click `New` and create a dedicated Key Vault for your Entra ID secret management
3. Navigate to `Access control (IAM)`
    - Click `Add/Add role assignment`
    - Select `Key Vault Secrets User`
    - Click `Next`
    - Under Members for Assign access to select `Managed identity`
    - For members select the Managed identity of the Function App and click `Select`, then `Review + Assign` twice.
3. Navigate to `Objects/Secrets`
    - Click `Generate/Import`
    - For Upload options leave the default `Manual` setting
    - Add a descriptive name (eg. EntraIDMonitorClientSecret) and the Client Secret Value saved earlier in the App registration
    - Optionally set an expiration date, then click `Create`

### Create the script
1. Once the Function is created, navigate to 

```
$ClientId = "<Insert Client Id Here>"
$ResourceGroup = "<Insert Resource Group Name Here>"
$LogAnalyticsWorkspaceName = "AADLogAnalyticsTest"
# Replace with your Workspace ID
$CustomerId = "<Insert Log Analytics Workspace Id Here>"  

# Replace with your Primary Key
$SharedKey = (Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $ResourceGroup -Name $LogAnalyticsWorkspaceName).PrimarySharedKey

# Specify the name of the record type that you'll be creating
$LogType = "<Insert Log Analytics Workspace Table Name Here>"

# Authenticate
Connect-MgGrap -Identity
$TenantId = (Get-MgContext).TenantId

# Query the Key Vault for the secret
Connect-AzAccount -Identity
$Secret = Get-AzKeyVaultSecret -VaultName "<Insert Vault Name Here>" -Name "<Insert Key Vault Secret Name here>"

$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientId, $Secret.SecretValue
Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential

# Query Entra ID
$RoleId = (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'").Id
$RoleHolders = Get-MgDirectoryRoleMemberAsUser -DirectoryRoleId $RoleId
$RoleCount = $RoleHolders.Count

# Send data to Log Analytics Workspace

# Optional name of a field that includes the timestamp for the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
$TimeStampField = "TimeGenerated"


# Create two records with the same set of properties to create
$json = @"
    {
        "TimeGenerated": Get-Date ([datetime]::UtcNow) -Format O,
        "RoleId": $RoleId,
        "RoleHolderCount": $RoleCount
    }
"@

# Create the function to create the authorization signature
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response

}

# Submit the data to the API endpoint
Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType
```

## Configure the Dashboard

You can find [Azure Dasboards](https://portal.azure.com/#dashboard) above the Favorites bar on the Azure Portal.

You will be able to find the data within the created Log Analytics Workspace under `Settings/Tables`. It is going to be of type `Custom table`.