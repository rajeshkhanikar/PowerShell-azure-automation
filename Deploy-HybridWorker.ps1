<#

.AUTHOR Rajesh Khanikar 
.VERSION 1.0 (21-AUG-2024)

#>

<#
.SYNOPSIS
    This PowerShell script automates the deployment of the Azure Automation Windows Hybrid Worker 
    on an Arc-enabled on-premises server.

.DESCRIPTION
    This script is designed to be executed in stages to ensure the smooth installation and 
    configuration of the Azure Automation Windows Hybrid Worker Extension on an 
    Azure Arc-enabled machine. The script performs the following major operations:

1. **Environment and Pre-requisite Checks:**
   - Validates that the script is running with administrative privileges.
   - Confirms the execution policy is set to 'RemoteSigned'.
   - Verifies the presence of the agent configuration file required for an 
     Azure Arc-connected machine.
   - Checks the status of the `himds` service (Azure Hybrid Instance Metadata Service) 
     and prompts the user to resolve issues if it is not running.

2. **Azure Authentication and Role Verification:**
   - Uses device code authentication to sign in to Azure.
   - Retrieves an Azure access token for the signed-in user.
   - Checks if the signed-in user has 'Owner' role on the specified resource group.

3. **Automation Account Discovery:**
   - Attempts to discover the Automation Account within the resource group.
   - Handles scenarios with no Automation Account, multiple accounts, or 
     missing account information and prompts the user accordingly.

4. **Hybrid Worker Group and Worker Creation:**
   - Creates a Hybrid Worker Group named after the machine name (1 machine/hybrid worker group), 
     creates the group it does not already exist.
   - Checks for existing Hybrid Workers within the group to avoid duplication and conflicts.
   - Creates a new Hybrid Worker linked to the Arc-enabled machine if one does not already exist.

5. **Azure Automation Windows Hybrid Worker Extension Deployment:**
   - Checks if the Hybrid Worker Extension is already deployed on the Arc-enabled machine.
   - If the extension is not present, it retrieves the Automation Account Hybrid Service URL and
     installs the extension.
   - Handles error conditions, such as unsupported API versions or existing extensions.

6. **Verbose Logging and Diagnostic Information:**
   - Detailed logging for every operation, including requests, responses, variable values, and 
     diagnostic information.
   - Logs are stored in a file named `log-add-hybridext.txt` in the current directory, which is 
     overwritten each time the script is run.
   - The script provides clear messaging for both successful operations and failures, making 
     troubleshooting easier.

.PARAMETERS
    The script does not take external parameters; it reads required values 
    (like subscription ID, resource group, and machine name) from the Arc configuration file.

.NOTES
    - The script requires the following PowerShell modules: 
      `Az.Accounts`, `Az.Resources`, and `Az.Automation`.
    - The script is designed to be idempotent—if resources or extensions are already 
      configured, the script will safely skip their reconfiguration.
    - The API version `2022-11-10` is used for stability when interacting with Azure resources.

.EXAMPLE
    ```powershell
    .\Deploy-HybridWorker.ps1

#>



function Write-VerboseLog {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$true)]
        [string]$LogType, # INFO, WARNING, ERROR, etc.

        [string]$Command = $null,

        [object]$Output = $null
    )

    # Log file name
    $logFileName = "log-add-hybridext.txt"
    $logFilePath = Join-Path -Path (Get-Location) -ChildPath $logFileName

    # Timestamp format
    $timestamp = Get-Date -Format "dd-MM-yyyy, HH:mm:ss"

    # Prepare the log entry with the appropriate format
    $logEntry = "[$timestamp] [$LogType] - $Message"

    # If a command was executed, log the command and its output
    if ($Command) {
        $logEntry += "`n    [Command] - $Command"
    }

    # If the command had any output, log the output details
    if ($Output) {
        $logEntry += "`n    [Output] - $(ConvertTo-Json -InputObject $Output -Depth 3)"
    }

    # Write the log entry to the file
    Add-Content -Path $logFilePath -Value $logEntry

    # Also output the log entry for the console in verbose mode
    Write-Verbose -Message $logEntry
}

# Initialize the log file (clear previous content)
$logFileName = "log-add-hybridext.txt"
$logFilePath = Join-Path -Path (Get-Location) -ChildPath $logFileName
Set-Content -Path $logFilePath -Value ""  # This clears the log file content at the start

function Check-PreRequisites {
    # Function to check if the script is running with administrator privileges
    function Is-Administrator {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Check if the script is running as an administrator
    if (-not (Is-Administrator)) {
        Write-Host "ERROR: The script must be run as an administrator. Please restart PowerShell with 'Run as Administrator' and try again." -ForegroundColor Red
        Write-VerboseLog -Message "Script not running with administrator privileges. Exiting." -LogType "ERROR"
        Exit 1
    } else {
        Write-VerboseLog -Message "Script is running with administrator privileges." -LogType "INFO"
    }

    # Check the current execution policy
    $currentExecutionPolicy = Get-ExecutionPolicy
    if ($currentExecutionPolicy -ne 'RemoteSigned') {
        Write-VerboseLog -Message "Current execution policy is '$currentExecutionPolicy'. Attempting to set it to 'RemoteSigned'." -LogType "WARNING"

        try {
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
            Write-VerboseLog -Message "Execution policy successfully set to 'RemoteSigned'." -LogType "INFO"
        }
        catch {
            Write-Host "ERROR: Failed to set execution policy to 'RemoteSigned'. Please set it manually and rerun the script." -ForegroundColor Red
            Write-VerboseLog -Message "Failed to set execution policy. Error: $($_.Exception.Message)" -LogType "ERROR"
            Exit 1
        }
    } else {
        Write-VerboseLog -Message "Execution policy is already set to 'RemoteSigned'." -LogType "INFO"
    }
}

# Call the Check-PreRequisites function at the start of your script
Check-PreRequisites

function Check-AzureArcAgent {
    # Path to the agent configuration file
    $agentConfigPath = Join-Path -Path $env:PROGRAMDATA -ChildPath "AzureConnectedMachineAgent\Config\agentconfig.json"

    # Check if the agentconfig.json file exists
    if (-not (Test-Path -Path $agentConfigPath)) {
        Write-VerboseLog -Message "The file '$agentConfigPath' does not exist." -LogType "ERROR"
        Write-Host "ERROR: The required file '$agentConfigPath' does not exist. This script requires the machine to be connected using Azure Arc." -ForegroundColor Red
        Exit 1
    } else {
        Write-VerboseLog -Message "The file '$agentConfigPath' was found." -LogType "INFO"
    }

    # Check if the himds service exists
    $serviceName = "himds"
    $serviceDisplayName = "Azure Hybrid Instance Metadata Service"
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

    if ($null -eq $service) {
        Write-VerboseLog -Message "The service '$serviceDisplayName' ($serviceName) is not found on this system. The machine may not be properly connected via Azure Arc." -LogType "ERROR"
        Write-Host "ERROR: The service '$serviceDisplayName' ($serviceName) is not found on this system. Please ensure the machine is connected using Azure Arc." -ForegroundColor Red
        Exit 1
    }

    # Check if the himds service is running
    if ($service.Status -ne 'Running') {
        Write-VerboseLog -Message "The service '$serviceDisplayName' ($serviceName) exists but is not running. Current status: $($service.Status)" -LogType "ERROR"
        Write-Host "ERROR: The service '$serviceDisplayName' ($serviceName) is not running. Please ensure the service is started before running this script." -ForegroundColor Red
        Exit 1
    } else {
        Write-VerboseLog -Message "The service '$serviceDisplayName' ($serviceName) is running." -LogType "INFO"
    }
}

# Call the Check-AzureArcAgent function at the appropriate place in your script
Check-AzureArcAgent

# Function to read and parse the agentconfig.json file
function Read-AgentConfig {
    param (
        [string]$configFilePath
    )

    # Read the JSON content from the agentconfig.json file
    try {
        $jsonContent = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json
        Write-VerboseLog -Message "Successfully read and parsed the agentconfig.json file." -LogType "INFO"
    }
    catch {
        Write-VerboseLog -Message "Failed to read or parse the agentconfig.json file. Error: $($_.Exception.Message)" -LogType "ERROR"
        Write-Host "ERROR: Unable to read or parse the agentconfig.json file. Please check the file and try again." -ForegroundColor Red
        Exit 1
    }

    # Store the values in globally available variables
    $global:SubscriptionId = $jsonContent.subscriptionId
    $global:ResourceGroup = $jsonContent.resourceGroup
    $global:ResourceName = $jsonContent.resourceName
    $global:TenantId = $jsonContent.tenantId
    $global:Location = $jsonContent.location
    $global:VmId = $jsonContent.vmId
    $global:VmUuid = $jsonContent.vmUuid
    $global:CertificateThumbprint = $jsonContent.certificateThumbprint
    $global:ClientId = $jsonContent.clientId
    $global:Cloud = $jsonContent.cloud
    $global:PrivateLinkScope = $jsonContent.privateLinkScope
    $global:Namespace = $jsonContent.Namespace
    $global:CorrelationId = $jsonContent.correlationId
    $global:ArmEndpoint = $jsonContent.armendpoint

    # Log and display the retrieved values
    Write-VerboseLog -Message "SubscriptionId: $SubscriptionId" -LogType "INFO"
    Write-VerboseLog -Message "ResourceGroup: $ResourceGroup" -LogType "INFO"
    Write-VerboseLog -Message "ResourceName: $ResourceName" -LogType "INFO"
    Write-VerboseLog -Message "TenantId: $TenantId" -LogType "INFO"
    Write-VerboseLog -Message "Location: $Location" -LogType "INFO"
    Write-VerboseLog -Message "VmId: $VmId" -LogType "INFO"
    Write-VerboseLog -Message "VmUuid: $VmUuid" -LogType "INFO"
    Write-VerboseLog -Message "CertificateThumbprint: $CertificateThumbprint" -LogType "INFO"
    Write-VerboseLog -Message "ClientId: $ClientId" -LogType "INFO"
    Write-VerboseLog -Message "Cloud: $Cloud" -LogType "INFO"
    Write-VerboseLog -Message "PrivateLinkScope: $PrivateLinkScope" -LogType "INFO"
    Write-VerboseLog -Message "Namespace: $Namespace" -LogType "INFO"
    Write-VerboseLog -Message "CorrelationId: $CorrelationId" -LogType "INFO"
    Write-VerboseLog -Message "ArmEndpoint: $ArmEndpoint" -LogType "INFO"

    Write-Host "The following configuration was retrieved from the agentconfig.json file:" -ForegroundColor Green
    Write-Host "SubscriptionId: $SubscriptionId"
    Write-Host "ResourceGroup: $ResourceGroup"
    Write-Host "ResourceName: $ResourceName"
    Write-Host "TenantId: $TenantId"
    Write-Host "Location: $Location"
    Write-Host "VmId: $VmId"
    Write-Host "VmUuid: $VmUuid"
    Write-Host "CertificateThumbprint: $CertificateThumbprint"
    Write-Host "ClientId: $ClientId"
    Write-Host "Cloud: $Cloud"
    Write-Host "PrivateLinkScope: $PrivateLinkScope"
    Write-Host "Namespace: $Namespace"
    Write-Host "CorrelationId: $CorrelationId"
    Write-Host "ArmEndpoint: $ArmEndpoint"

    # Prompt the user to continue
    $userResponse = Read-Host "Do you want to continue? This script will attempt to add Azure Automation Windows Hybrid Worker to this machine. (yes/no)"
    if ($userResponse -notin @("yes", "y")) {
        Write-VerboseLog -Message "User chose not to continue with the script." -LogType "INFO"
        Write-Host "Operation canceled by user." -ForegroundColor Yellow
        Exit 0
    }
    Write-VerboseLog -Message "User chose to continue with the script." -LogType "INFO"
}

# Call the Read-AgentConfig function with the path to the agentconfig.json file
$agentConfigPath = Join-Path -Path $env:PROGRAMDATA -ChildPath "AzureConnectedMachineAgent\Config\agentconfig.json"
Read-AgentConfig -configFilePath $agentConfigPath


function Check-RequiredModules {
    # List of required modules
    $requiredModules = @("Az.Accounts", "Az.Resources")

    foreach ($module in $requiredModules) {
        # Check if the module is installed for all users
        $moduleInstalled = Get-Module -ListAvailable -Name $module -ErrorAction SilentlyContinue

        if (-not $moduleInstalled) {
            Write-VerboseLog -Message "The required module '$module' is not installed. Attempting to install..." -LogType "WARNING"
            Write-Host "The required module '$module' is not installed. Attempting to install..." -ForegroundColor Yellow

            try {
                # Install the module for all users
                Install-Module -Name $module -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
                Write-VerboseLog -Message "Successfully installed the module '$module'." -LogType "INFO"
            }
            catch {
                Write-VerboseLog -Message "Failed to install the module '$module'. Error: $($_.Exception.Message)" -LogType "ERROR"
                Write-Host "ERROR: Failed to install the module '$module'. Please ensure you have the necessary permissions and internet access." -ForegroundColor Red
                Exit 1
            }
        } else {
            Write-VerboseLog -Message "The module '$module' is already installed." -LogType "INFO"
        }
    }

    # Ensure that the 'Az.Resources' module contains 'Get-AzRoleAssignment'
    if (-not (Get-Command -Name "Get-AzRoleAssignment" -Module "Az.Resources" -ErrorAction SilentlyContinue)) {
        Write-VerboseLog -Message "The 'Az.Resources' module is installed but does not contain the 'Get-AzRoleAssignment' command. Attempting to update..." -LogType "WARNING"
        Write-Host "The 'Az.Resources' module is installed but does not contain the 'Get-AzRoleAssignment' command. Attempting to update..." -ForegroundColor Yellow

        try {
            # Update the Az.Resources module to the latest version for all users
            Install-Module -Name "Az.Resources" -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
            Write-VerboseLog -Message "Successfully updated the 'Az.Resources' module." -LogType "INFO"
        }
        catch {
            Write-VerboseLog -Message "Failed to update the 'Az.Resources' module. Error: $($_.Exception.Message)" -LogType "ERROR"
            Write-Host "ERROR: Failed to update the 'Az.Resources' module. Please ensure you have the necessary permissions and internet access." -ForegroundColor Red
            Exit 1
        }
    } else {
        Write-VerboseLog -Message "The 'Get-AzRoleAssignment' command is available." -LogType "INFO"
    }
}

# Call the Check-RequiredModules function at the start of your script
Check-RequiredModules


function Authenticate-ToAzure {
    Write-VerboseLog -Message "Authenticating to Azure using device code..." -LogType "INFO"

    # Check if there is an existing Azure session context
    if (-not (Get-AzContext)) {
        Connect-AzAccount -DeviceCode
    }

    # Get the UPN (User Principal Name) of the signed-in user
    $currentContext = Get-AzContext
    $global:UserUPN = $currentContext.Account.Id

    # Log the UPN of the signed-in user
    Write-VerboseLog -Message "Signed in as user: $global:UserUPN" -LogType "INFO"
    
    # Get the access token and convert it to a plain string (handling both current and future versions)
    $secureToken = (Get-AzAccessToken -AsSecureString).Token
    $global:token = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken))

    # Verify if the token was successfully obtained
    if (-not $global:token) {
        Write-VerboseLog -Message "Failed to obtain the Azure access token." -LogType "ERROR"
        Write-Host "ERROR: Failed to obtain the Azure access token. Please check your authentication and try again." -ForegroundColor Red
        Exit 1
    } else {
        Write-VerboseLog -Message "Successfully obtained Azure access token." -LogType "INFO"
    }
}


function Check-UserRole {
    # Get the ResourceGroup from the previously read config
    $resourceGroup = $global:ResourceGroup
    $subscriptionId = $global:SubscriptionId

    Write-VerboseLog -Message "Checking if the signed-in user ($global:UserUPN) has 'Owner' role on resource group: $resourceGroup." -LogType "INFO"

    # Define the scope to the resource group
    $scope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup"

    # Get the role assignments for the current user in the specified scope
    try {
        $roleAssignments = Get-AzRoleAssignment -Scope $scope -ErrorAction Stop
    }
    catch {
        Write-VerboseLog -Message "Failed to retrieve role assignments for resource group: $resourceGroup. Error: $($_.Exception.Message)" -LogType "ERROR"
        Write-Host "ERROR: Unable to retrieve role assignments for the resource group '$resourceGroup'. Ensure you have the correct permissions." -ForegroundColor Red
        Exit 1
    }

    # Check if the current user has the 'Owner' role
    $isOwner = $roleAssignments | Where-Object { $_.RoleDefinitionName -eq "Owner" }

    if (-not $isOwner) {
        Write-VerboseLog -Message "The signed-in user ($global:UserUPN) does not have the 'Owner' role on the resource group: $resourceGroup." -LogType "ERROR"
        Write-Host "ERROR: The signed-in user ($global:UserUPN) does not have the 'Owner' role on the resource group '$resourceGroup'. Please use an account with the 'Owner' role and rerun the script." -ForegroundColor Red
        Exit 1
    } else {
        Write-VerboseLog -Message "The signed-in user ($global:UserUPN) has the 'Owner' role on the resource group: $resourceGroup." -LogType "INFO"
    }
}

# Call the functions in the appropriate order
Authenticate-ToAzure
Check-UserRole

# Function to Get the Automation Account Name
function Get-AutomationAccountName {
    Write-VerboseLog -Message "Attempting to retrieve automation account name from the resource group: $global:ResourceGroup..." -LogType "INFO"

    try {
        # Retrieve automation account(s) in the specified resource group
        $automationAccounts = Get-AzAutomationAccount -ResourceGroupName $global:ResourceGroup -ErrorAction Stop
        Write-VerboseLog -Message "Raw output of Get-AzAutomationAccount: $(ConvertTo-Json $automationAccounts -Depth 3)" -LogType "INFO"

        if ($automationAccounts.Count -eq 1) {
            # If there is only one automation account, select it and extract the name
            $global:automationAccountName = $automationAccounts.AutomationAccountName
            Write-VerboseLog -Message "Automation account '$global:automationAccountName' found." -LogType "INFO"
        } elseif ($automationAccounts.Count -gt 1) {
            # If multiple automation accounts are found, prompt the user to choose one
            Write-VerboseLog -Message "Multiple automation accounts found in the resource group." -LogType "INFO"
            Write-Host "Multiple automation accounts found in the resource group. Please choose one from the list below:" -ForegroundColor Yellow

            # Display the list of automation accounts
            $automationAccounts | ForEach-Object { Write-Host " - $($_.AutomationAccountName)" }

            # Prompt the user to input the desired automation account name
            $userInput = Read-Host "Please enter the name of the automation account you wish to use"

            # Validate the user's input
            if ($automationAccounts.AutomationAccountName -contains $userInput) {
                $global:automationAccountName = $userInput
                Write-VerboseLog -Message "User selected automation account '$global:automationAccountName'." -LogType "INFO"
            } else {
                Write-VerboseLog -Message "User input '$userInput' does not match any of the available automation accounts." -LogType "ERROR"
                Write-Host "ERROR: The specified automation account name does not match any of the available accounts. Exiting script." -ForegroundColor Red
                Exit 1
            }
        } else {
            Write-VerboseLog -Message "No automation accounts found in the resource group." -LogType "ERROR"
            Write-Host "ERROR: No automation accounts found in the resource group. Please ensure the correct resource group is being used." -ForegroundColor Red
            Exit 1
        }
    } catch {
        Write-VerboseLog -Message "Failed to retrieve automation account name. Error Details: $_" -LogType "ERROR"
        Write-Host "ERROR: Unable to retrieve automation account name. Please check the log for details." -ForegroundColor Red
        Exit 1
    }

    # Validate that the automation account name is not empty
    if (-not $global:automationAccountName) {
        Write-VerboseLog -Message "Automation account name is empty or not set. Stopping the script." -LogType "ERROR"
        Write-Host "ERROR: Automation account name is empty or not set. Please check the resource group and try again." -ForegroundColor Red
        Exit 1
    }
}

# Function to Create the Hybrid Worker Group
function Create-HybridWorkerGroup {
    $headers = @{ Authorization = "Bearer $global:token" }
    
    # Ensure this variable is correctly populated
    $hybridRunbookWorkerGroupName = $env:COMPUTERNAME  # Using uppercase for environment variable

    Write-VerboseLog -Message "HybridWorker Group Name: $hybridRunbookWorkerGroupName" -LogType "INFO"

    if (-not $hybridRunbookWorkerGroupName) {
        Write-VerboseLog -Message "Hybrid Worker Group Name is empty or not set. Stopping the script." -LogType "ERROR"
        Write-Host "ERROR: Hybrid Worker Group Name is empty or not set. Please check the script." -ForegroundColor Red
        Exit 1
    }

    # Check if the Hybrid Worker Group already exists
    $checkHRWGroupUri = "https://management.azure.com/subscriptions/$($global:SubscriptionId)/resourceGroups/$($global:ResourceGroup)/providers/Microsoft.Automation/automationAccounts/$($global:automationAccountName)/hybridRunbookWorkerGroups/$($hybridRunbookWorkerGroupName)?api-version=2023-11-01"
    Write-VerboseLog -Message "Checking if Hybrid Worker Group exists. Request URI: $checkHRWGroupUri" -LogType "INFO"

    try {
        $existingGroup = Invoke-RestMethod -Uri $checkHRWGroupUri -Method GET -Headers $headers -ErrorAction Stop
        if ($existingGroup) {
            Write-VerboseLog -Message "Hybrid Worker Group '$hybridRunbookWorkerGroupName' already exists. Skipping creation." -LogType "INFO"
            Write-Host "INFO: Hybrid Worker Group '$hybridRunbookWorkerGroupName' already exists. Skipping creation." -ForegroundColor Yellow
            return
        }
    } catch {
        Write-VerboseLog -Message "Hybrid Worker Group does not exist. Proceeding with creation." -LogType "INFO"
    }

    # Create Hybrid Worker Group
    Write-VerboseLog -Message "Creating Hybrid Worker Group..." -LogType "INFO"
    $createHRWGroupUri = "https://management.azure.com/subscriptions/$($global:SubscriptionId)/resourceGroups/$($global:ResourceGroup)/providers/Microsoft.Automation/automationAccounts/$($global:automationAccountName)/hybridRunbookWorkerGroups/$($hybridRunbookWorkerGroupName)?api-version=2023-11-01"
    Write-VerboseLog -Message "Request URI: $createHRWGroupUri" -LogType "INFO"

    try {
        $body = @{
            properties = @{
                # Add additional properties here if required by the API
            }
        } | ConvertTo-Json

        Write-VerboseLog -Message "Request Body: $body" -LogType "INFO" # Log the body for diagnostics

        $response = Invoke-RestMethod -Uri $createHRWGroupUri -Method PUT -Headers $headers -Body $body -ContentType "application/json" -ErrorAction Stop
        Write-VerboseLog -Message "Hybrid Worker Group Created Successfully." -LogType "INFO"
    } catch {
        Write-VerboseLog -Message "Failed to create Hybrid Worker Group. Error Details: $_" -LogType "ERROR"
        Write-Host "ERROR: Failed to create Hybrid Worker Group. Please check the log for details." -ForegroundColor Red

        # Log more diagnostic information
        if ($_.Exception.Response -ne $null) {
            $errorResponse = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $responseBody = $reader.ReadToEnd()
            Write-VerboseLog -Message "API Error Response: $responseBody" -LogType "ERROR"
        }
        Exit 1
    }
}

# Function to Create the Hybrid Worker
function Create-HybridWorker {
    $headers = @{ Authorization = "Bearer $global:token" }
    
    # Ensure this variable is correctly populated
    $hybridRunbookWorkerGroupName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { "DefaultHybridWorkerGroup" }

    if (-not $hybridRunbookWorkerGroupName) {
        Write-VerboseLog -Message "Hybrid Runbook Worker Group Name is empty or not set. Stopping the script." -LogType "ERROR"
        Write-Host "ERROR: Hybrid Runbook Worker Group Name is empty or not set. Please check the script." -ForegroundColor Red
        Exit 1
    }

    $ARCServerResourceId = "/subscriptions/$global:SubscriptionId/resourceGroups/$global:ResourceGroup/providers/Microsoft.HybridCompute/machines/$global:ResourceName"

    # Check if the Hybrid Worker already exists
    $listHRWUri = "https://management.azure.com/subscriptions/$global:SubscriptionId/resourceGroups/$global:ResourceGroup/providers/Microsoft.Automation/automationAccounts/$global:automationAccountName/hybridRunbookWorkerGroups/$hybridRunbookWorkerGroupName/hybridRunbookWorkers?api-version=2023-11-01"
    Write-VerboseLog -Message "Checking if Hybrid Workers already exist. Request URI: $listHRWUri" -LogType "INFO"

    try {
        $existingWorkers = Invoke-RestMethod -Uri $listHRWUri -Method GET -Headers $headers -ErrorAction Stop
        foreach ($worker in $existingWorkers.value) {
            if ($worker.properties.vmResourceId -eq $ARCServerResourceId) {
                Write-VerboseLog -Message "Hybrid Worker with the same AzureResourceId already exists in Group '$hybridRunbookWorkerGroupName'. Skipping creation." -LogType "INFO"
                Write-Host "INFO: Hybrid Worker with the same AzureResourceId already exists in Group '$hybridRunbookWorkerGroupName'. Skipping creation." -ForegroundColor Yellow
                return
            }
        }
    } catch {
        Write-VerboseLog -Message "Failed to retrieve existing Hybrid Workers. Proceeding with creation if it does not already exist." -LogType "INFO"
    }

    # Proceed to create the Hybrid Worker if it doesn't already exist
    $hrwId = [guid]::NewGuid().ToString()
    $createHRWUri = "https://management.azure.com/subscriptions/$global:SubscriptionId/resourceGroups/$global:ResourceGroup/providers/Microsoft.Automation/automationAccounts/$global:automationAccountName/hybridRunbookWorkerGroups/$hybridRunbookWorkerGroupName/hybridRunbookWorkers/$($hrwId)?api-version=2023-11-01"
    Write-VerboseLog -Message "Request URI: $createHRWUri" -LogType "INFO"

    $body = @{
        properties = @{
            vmResourceId = $ARCServerResourceId
        }
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri $createHRWUri -Method PUT -Headers $headers -Body $body -ContentType "application/json" -ErrorAction Stop
        Write-VerboseLog -Message "Hybrid Worker Created Successfully." -LogType "INFO"
    } catch {
        Write-VerboseLog -Message "Failed to create Hybrid Worker. Error Details: $_" -LogType "ERROR"
        Write-Host "ERROR: Failed to create Hybrid Worker. Please check the log for details." -ForegroundColor Red
        Exit 1
    }
}

# Function to Add the Azure Automation Windows Hybrid Worker Extension to Arc Machine
function Add-ARCExtension {
    $headers = @{ Authorization = "Bearer $global:token" }
    $extensionName = "HybridWorkerExtension"
    $checkExtensionUri = "https://management.azure.com/subscriptions/$global:SubscriptionId/resourceGroups/$global:ResourceGroup/providers/Microsoft.HybridCompute/machines/$global:ResourceName/extensions/$($extensionName)?api-version=2022-11-10"
    
    Write-VerboseLog -Message "Checking if the Azure Automation Windows Hybrid Worker Extension is already added. Request URI: $checkExtensionUri" -LogType "INFO"

    try {
        # Check if the extension is already added
        $existingExtension = Invoke-RestMethod -Uri $checkExtensionUri -Method GET -Headers $headers -ErrorAction Stop
        if ($existingExtension) {
            Write-VerboseLog -Message "The Azure Automation Windows Hybrid Worker Extension is already added to this machine. Skipping extension addition." -LogType "INFO"
            Write-Host "INFO: The Azure Automation Windows Hybrid Worker Extension is already added to this machine. Skipping extension addition." -ForegroundColor Yellow
            return
        }
    } catch {
        # If the extension is not found, proceed with adding it
        if ($_.Exception.Response.StatusCode -eq 404) {
            Write-VerboseLog -Message "The Azure Automation Windows Hybrid Worker Extension is not found. Proceeding to add the extension." -LogType "INFO"
        } else {
            Write-VerboseLog -Message "Failed to check for existing extension. Error Details: $_" -LogType "ERROR"
            Write-Host "ERROR: Unable to check for existing extension. Please check the log for details." -ForegroundColor Red
            Exit 1
        }
    }

    # Retrieve Automation Hybrid Service URL
    Write-VerboseLog -Message "Retrieving Automation Account Hybrid Service URL..." -LogType "INFO"
    $automationAccountInfoUri = "https://management.azure.com/subscriptions/$global:SubscriptionId/resourceGroups/$global:ResourceGroup/providers/Microsoft.Automation/automationAccounts/$($global:automationAccountName)?api-version=2023-11-01"
    try {
        $automationHybridServiceUrl = (Invoke-RestMethod -Uri $automationAccountInfoUri -Method GET -Headers $headers -ErrorAction Stop).properties.automationHybridServiceUrl
        Write-VerboseLog -Message "Automation Account Hybrid Service URL: $automationHybridServiceUrl" -LogType "INFO"
    } catch {
        Write-VerboseLog -Message "Failed to retrieve Automation Account Hybrid Service URL: $_" -LogType "ERROR"
        Write-Host "ERROR: Unable to retrieve Automation Account Hybrid Service URL. Please check the log for details." -ForegroundColor Red
        Exit 1
    }

    # Create the extension only if it's not already added
    $createARCExtensionUri = "https://management.azure.com/subscriptions/$global:SubscriptionId/resourceGroups/$global:ResourceGroup/providers/Microsoft.HybridCompute/machines/$global:ResourceName/extensions/$($extensionName)?api-version=2022-11-10"
    Write-VerboseLog -Message "Request URI: $createARCExtensionUri" -LogType "INFO"

    $createARCExtensionBody = @{
        location   = $global:Location
        properties = @{
            publisher               = 'Microsoft.Azure.Automation.HybridWorker'
            type                    = 'HybridWorkerForWindows'
            typeHandlerVersion      = '1.1.13'
            autoUpgradeMinorVersion = $false
            enableAutomaticUpgrade  = $true
            settings                = @{
                AutomationAccountURL = $automationHybridServiceUrl
            }
        }
    } | ConvertTo-Json -Depth 2

    try {
        $response = Invoke-RestMethod -Uri $createARCExtensionUri -Method PUT -Headers $headers -Body $createARCExtensionBody -ContentType "application/json" -ErrorAction Stop
        Write-VerboseLog -Message "Azure Automation Windows Hybrid Worker Extension added successfully." -LogType "INFO"
    } catch {
        Write-VerboseLog -Message "Failed to add the extension. Error Details: $_" -LogType "ERROR"
        Write-Host "ERROR: Failed to add the Azure Automation Windows Hybrid Worker Extension. Please check the log for details." -ForegroundColor Red

        # Log more diagnostic information
        if ($_.Exception.Response -ne $null) {
            $errorResponse = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $responseBody = $reader.ReadToEnd()
            Write-VerboseLog -Message "API Error Response: $responseBody" -LogType "ERROR"
        }
        Exit 1
    }
}


# Main Script Execution
# Call functions in sequence
Get-AutomationAccountName
Create-HybridWorkerGroup
Create-HybridWorker
Add-ARCExtension
