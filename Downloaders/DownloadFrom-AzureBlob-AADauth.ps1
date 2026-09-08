<#

As of 11/6/25 this script is interactive. Non-interactive functions still under contsruction.
TODO: Logging is also not yet as inclusive as I would like to make it. This script also doesn't have a pre-check yet.

.SYNOPSIS
    Downloads secure file from Azure Blob Storage using Azure AD authentication
.DESCRIPTION
    This script automatically uses the logged-in user's Azure AD credentials
    to download a sensitive file from Azure Blob Storage

    Example blob locations:
    $ContainerName/$BlobDirectoryPath/$BlobName
    $ContainerName/$BlobName
    
#>

[CmdletBinding()]
param(

    [string]$StorageAccountName,
    
    [string]$ContainerName,
    
    [string]$BlobDirectoryPath, # Can be empty if the blob lives at the root of the container. Don't include leading or trailing slashes!

    [string]$BlobName,
    
    [string]$TenantId,

    [string]$WorkingDirectory

)


##########
## Vars ##
##########

#$WorkingDirectory = 'C:\ProgramData\TEST'
$TargetDirectory = "$WorkingDirectory\TEMP"
$LocalDestinationPath = "$TargetDirectory\$BlobName"

$ThisFileName = $MyInvocation.MyCommand.Name
$LogRoot = "$WorkingDirectory\Logs\Download_Logs"
$LogPath = "$LogRoot\$ThisFileName._$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

###############
## Functions ##
###############

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "DRYRUN"  { Write-Host $logEntry -ForegroundColor Cyan }
        default   { Write-Host $logEntry }
    }
    
    # Ensure log directory exists
    $logDir = Split-Path $LogPath -Parent
    if (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    # Resilient log write: retry an atomic append so a transient AV/EDR file lock
    # (Defender, CrowdStrike, etc.) cannot throw "Stream was not readable" and spam the
    # console. Encoding::Default (system ANSI) matches the prior Add-Content behavior.
    for ($logAttempt = 1; $logAttempt -le 5; $logAttempt++) {
        try {
            [System.IO.File]::AppendAllText($LogPath, $logEntry + [Environment]::NewLine, [System.Text.Encoding]::Default)
            break
        } catch {
            if ($logAttempt -eq 5) { break }   # give up quietly after ~160ms of retries
            Start-Sleep -Milliseconds 40
        }
    }
}

# NOTE: This method is still under development
# Silent authentication using Azure CLI's cached token
function Get-AzureTokenSilently-Old {
    # Check if Azure CLI is installed
    Write-Log "Checking if Azure CLI is installed..."
    $azCmd = Get-Command az -ErrorAction SilentlyContinue
    if (!$azCmd) {
        Write-Log "Azure CLI not installed, attempting to install"
        Try{

            # Install AzureCLI
            winget install -e --id Microsoft.AzureCLI

            # Refresh env vars
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

            # test to make sure it works
            if ($azCmd){

                Write-Log "Install Success!"

            } else {

                Throw "Test after download failed"

            }
        } Catch {

            Write-Log "Install failed: $_"
            Throw $_
        }

    } else {

        Write-log "Azure CLI installed and working!"

    }
    
    Try{

        Write-Log "Attempting to retrieve token..."
        # Use Azure CLI to get token silently (uses Windows credentials)
        $token = az account get-access-token --resource https://storage.azure.com/ --query accessToken -o tsv 2>$null
        
        if (!$token) {
            # Try to login silently first
            Write-Log "Couldn't obtain token initially... attempting to do silent login." "WARNING"
            az login --identity 2>$null
            if ($LASTEXITCODE -ne 0) {
                # Use device authentication as fallback
                Write-Log "Silent login failed. Attempting to use device authentication." "WARNING"
                az login --use-device-code
            }

            Write-Log "Attempting one final time to retrieve token..."
            $token = az account get-access-token --resource https://storage.azure.com/ --query accessToken -o tsv
        }

    } Catch {

        Write-Log "Token retrieval failed: $_"
        Exit 1

    }

    
    return $token
}

# NOTE: This method is still under development
function Get-AzureTokenSilently {
    # Check if Azure CLI is installed
    Write-Log "Checking if Azure CLI is installed..."
    $azCmd = Get-Command az -ErrorAction SilentlyContinue
    if (!$azCmd) {
        Write-Log "Azure CLI not installed, attempting to install"
        Try{
            # Install AzureCLI
            winget install -e --id Microsoft.AzureCLI

            # Refresh env vars
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

            # test to make sure it works
            if ($azCmd){
                Write-Log "Install Success!"
            } else {
                Throw "Test after download failed"
            }
        } Catch {
            Write-Log "Install failed: $_"
            Throw $_
        }
    } else {
        Write-log "Azure CLI installed and working!"
    }
    
    Try{
        Write-Log "Attempting to retrieve token..."
        
        # Save current location
        $originalLocation = Get-Location
        
        # Change to a local directory (use TEMP or Windows directory)
        Push-Location $env:TEMP
        
        try {
            # Use Azure CLI to get token silently (uses Windows credentials)
            $token = az account get-access-token --resource https://storage.azure.com/ --query accessToken -o tsv 2>$null
            
            if (!$token) {
                # Try to login silently first
                Write-Log "Couldn't obtain token initially... attempting to do silent login." "WARNING"
                az login --identity 2>$null
                if ($LASTEXITCODE -ne 0) {
                    # Use device authentication as fallback
                    Write-Log "Silent login failed. Attempting to use device authentication." "WARNING"
                    az login --use-device-code
                }

                Write-Log "Attempting one final time to retrieve token..."
                $token = az account get-access-token --resource https://storage.azure.com/ --query accessToken -o tsv
            }
        }
        finally {
            # Always return to original location
            Pop-Location
        }

    } Catch {
        Write-Log "Token retrieval failed: $_"
        Exit 1
    }
    
    return $token
}

#############
## TESTING ##
#############

        # winget uninstall Microsoft.AzureCLI


        #$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

        #cmd.exe az --version

        # $token = Get-AzureTokenSilently

        # $token
        # pause

        ##

        <#
        # Use the token directly with REST API
            Try{
                
                Write-Log "Installing Azure CLI"
                #$ProgressPreference = 'SilentlyContinue'; 
                #Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; Remove-Item .\AzureCLI.msi

                winget uninstall Microsoft.AzureCLI

                winget install -e --id Microsoft.AzureCLI

                Write-Log "Getting token"
                $token = Get-AzureTokenSilently
                $headers = @{
                    'Authorization' = "Bearer $token"
                    'x-ms-version' = '2020-04-08'
                }

                # Download blob using REST API
                $uri = 'https://genericdeploy.blob.core.windows.net/applications/Escape/Escape_Online_5_Client_SC_PROD.msi?sp=r&st=2025-11-04T18:35:35Z&se=2025-11-05T02:50:35Z&spr=https&sv=2024-11-04&sr=b&sig=DqJPQYPyAtZQ%2Fres5KohGX56Bdhs1ZoHB7%2BY0xpMnJ8%3D'
                Invoke-RestMethod -Uri $uri -Headers $headers -OutFile "C:\ProgramData\TEST\Temp\zz.msi"
            } Catch {

                "duhhhh: $_"
            }
            Pause
        #>
        ##


##########
## Main ##
##########



# Main script
try {

    Write-Log "Starting secure file download process"
    Write-Log ""

    
    # Check if running as SYSTEM (we need user context)
        Write-Log "Checking the current user..."
        $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $currentUser = $currentIdentity.Name
        
        if ($currentUser -eq "NT AUTHORITY\SYSTEM") {
            throw "Script must run in user context, not SYSTEM context"
        }
    
    Write-Log "Running as user: $currentUser"
    
    # Ensure Az modules are installed
        Write-Log "Checking the required modules..."
        $requiredModules = @('Az.Accounts', 'Az.Storage')
        foreach ($module in $requiredModules) {
            if (!(Get-Module -ListAvailable -Name $module)) {
                Write-Log "Installing module: $module"
                Install-Module -Name $module -Force -Scope CurrentUser -AllowClobber
            }
            Import-Module $module -Force
        }
        Write-Log "Modules completed import."

##
    
    # Get the user's UPN for authentication
        $userUpn = whoami /upn
        Write-Log "Authenticating as: $userUpn"
    
    # Connect to Azure using the user's credentials
        # This will use Windows Integrated Authentication
        $connected = $false
        $maxRetries = 3
        $retryCount = 0
        
        while (!$connected -and $retryCount -lt $maxRetries) {
            try {
                # First, try silent authentication
                $account = Connect-AzAccount `
                    -AccountId $userUpn `
                    -TenantId $TenantId `
                    -ErrorAction Stop
                
                $connected = $true
                Write-Log "Successfully authenticated to Azure AD"
            }
            catch {
                $retryCount++
                Write-Log "Authentication attempt $retryCount failed: $_" -EntryType Warning
                
                if ($retryCount -lt $maxRetries) {
                    Start-Sleep -Seconds 5
                }
            }
        }
        
        if (!$connected) {
            throw "Failed to authenticate to Azure AD after $maxRetries attempts"
        }
    
    # Create storage context using Azure AD auth
        Write-Log "Creating storage context for account: $StorageAccountName"
        $storageContext = New-AzStorageContext `
            -StorageAccountName $StorageAccountName `
            -UseConnectedAccount `
            -ErrorAction Stop
    
    # Ensure destination directory exists
        if (!(Test-Path $TargetDirectory)) {
            New-Item -ItemType Directory -Path $TargetDirectory -Force | Out-Null
            Write-Log "Created destination directory: $LocalDestinationPath"
        }
        
    # Download the blob
        
        Write-Log "Downloading blob to: $LocalDestinationPath"
    
        $Blobber = "$BlobDirectoryPath/$BlobName"

        Write-Log "Downloading from this path: $Blobber"

        $blob = Get-AzStorageBlobContent `
            -Container $ContainerName `
            -Blob $Blobber `
            -Destination $LocalDestinationPath `
            -Context $storageContext `
            -Force `
            -ErrorAction Stop
        
    # Verify download
        if (Test-Path $LocalDestinationPath) {
            $fileInfo = Get-Item $LocalDestinationPath
            Write-Log "File downloaded successfully. Size: $($fileInfo.Length) bytes"
            
            # Set appropriate permissions on the file
            # $acl = Get-Acl $destinationFile
            # $acl.SetAccessRuleProtection($true, $false)
            
            # Only allow SYSTEM and Administrators
            # $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
            # $adminsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
            
            # $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            #     $systemSid, "FullControl", "Allow"
            # )
            # $adminsRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            #     $adminsSid, "FullControl", "Allow"
            # )
            
            # $acl.SetAccessRule($systemRule)
            # $acl.SetAccessRule($adminsRule)
            # Set-Acl -Path $destinationFile -AclObject $acl
            
            # Write-Log "File permissions configured successfully"
            Write-Log "File downloaded successfully to: $LocalDestinationPath" "SUCCESS"
            Disconnect-AzAccount -ErrorAction SilentlyContinue

            exit 0
        }
        else {
            throw "File download verification failed"
        }
}
catch {
    $errorMessage = "Failed to download secure file: $_"
    Write-Log $errorMessage -EntryType Error -EventId 1001
    Write-Error $errorMessage
    Disconnect-AzAccount -ErrorAction SilentlyContinue
    exit 1
}