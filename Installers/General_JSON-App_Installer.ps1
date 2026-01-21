# Install app from JSON

Param(

    #[Parameter(Mandatory=$true)]
    [string]$TargetAppName

)

##########
## VARS ##
##########

if($TargetAppName -eq "" -or $TargetAppName -eq $null){
    Write-Log "No TargetAppName specified. Exiting." -ForegroundColor Red
    Exit 1
}


$RepoRoot = (Split-Path -Path $PSScriptRoot -Parent)

$WorkingDirectory = Split-Path -Path $RepoRoot -Parent

#$LocalJSONpath = "$WorkingDirectory\TEMP\Downloads\ApplicationData.json"

$PublicJSONpath = "$RepoRoot\Templates\ApplicationData_TEMPLATE.json"

$ThisFileName = $MyInvocation.MyCommand.Name

$LogRoot = "$WorkingDirectory\Logs\Installer_Logs"

$LogPath = "$LogRoot\$ThisFileName.$TargetAppName._Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"


$OrgRegReader_ScriptPath = "$RepoRoot\Templates\OrganizationCustomRegistryValues-Reader_TEMPLATE.ps1"

$General_WinGet_Installer_ScriptPath = "$RepoRoot\Installers\General_WinGet_Installer.ps1"

$DownloadAzureBlobSAS_ScriptPath = "$RepoRoot\Downloaders\DownloadFrom-AzureBlob-SAS.ps1"

$MSIinstallScriptPath = "$RepoRoot\Installers\General_MSI_Installer.ps1"

$EXEInstallScriptPath = "$RepoRoot\Installers\General_EXE_Installer.ps1"

###############
## FUNCTIONS ##
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
    
    Add-Content -Path $LogPath -Value $logEntry
}

Function InstallApp-via-WinGet {

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START | Calling General_WinGet_Installer script to install $TargetAppName via WinGet..."
    
    Try {

        if ($Version){

            & $General_WinGet_Installer_ScriptPath -AppName $TargetAppName -AppID $WinGetID -WorkingDirectory $WorkingDirectory -Version $Version

        } else {

            & $General_WinGet_Installer_ScriptPath -AppName $TargetAppName -AppID $WinGetID -WorkingDirectory $WorkingDirectory

        }

    } Catch {

        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END |WinGet installation failed: $_" "ERROR"
        Exit 1

    }


    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"
}

Function InstallApp-via-MSI-Private-AzureBlob {

    # Works

    # Download the custom MSI from Azure Blob Storage
    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START | Downloading MSI from Private Azure Blob Storage..."


    $MSIPathFromContainerRoot

    $MSIname = Split-Path $MSIPathFromContainerRoot -Leaf

    # Grab organization custom registry values
    Try{
    # Grab organization custom registry values
        Write-Log "Retrieving organization custom registry values..." 
        $ReturnHash = & $OrgRegReader_ScriptPath #| Out-Null

        # Check the returned hashtable
        if(($ReturnHash -eq $null) -or ($ReturnHash.Count -eq 0)){
            Write-Log "No data returned from Organization Registry Reader script!" "ERROR"
            Exit 1
        }
        #Write-Log "Organization custom registry values retrieved:"
        foreach ($key in $ReturnHash.Keys) {
            $value = $ReturnHash[$key]
            Write-Log "   $key : $value" 
        }    

        # Turn the returned hashtable into variables
        Write-Log "Setting organization custom registry values as local variables..." 
        foreach ($key in $ReturnHash.Keys) {
            Set-Variable -Name $key -Value $ReturnHash[$key] -Scope Local
            Write-Log "Should be: $key = $($ReturnHash[$key])" 
            $targetValue = Get-Variable -Name $key -Scope Local
            Write-Log "Ended up as: $key = $($targetValue.Value)" 

        }
    } Catch {
        Write-Log "Error retrieving organization custom registry values: $_" "ERROR"
        Exit 1
    }

    # Construct blob URI

    $parts = $ApplicationDataJSONpath -split '/', 2

    $ApplicationData_JSON_ContainerName = $parts[0]      
    $ApplicationData_JSON_BlobName = $parts[1]

    $SasToken = $ApplicationContainerSASkey

    Write-Log "Final values to be used to build $MSIname URI:" 
    Write-Log "StorageAccountName: $StorageAccountName"
    Write-Log "SasToken: $SasToken"
    Write-Log "ApplicationData_JSON_ContainerName: $ApplicationData_JSON_ContainerName"
    Write-Log "ApplicationData_JSON_BlobName: $ApplicationData_JSON_BlobName"

    $applicationJSONUri = "https://$StorageAccountName.blob.core.windows.net/$ApplicationData_JSON_ContainerName/$MSIPathFromContainerRoot"+"?"+"$SasToken"

    Write-Log "Attempting to access ApplicationData.json with this URI: $applicationJSONUri"

    Try{


        Write-Log "Beginning download..."
        & $DownloadAzureBlobSAS_ScriptPath -WorkingDirectory $WorkingDirectory -BlobName $MSIPathFromContainerRoot -StorageAccountName $StorageAccountName -ContainerName $ApplicationData_JSON_ContainerName -SasToken $SasToken
        if($LASTEXITCODE -ne 0){Throw $LASTEXITCODE }


    }catch{

        Write-Log "Download MSI failed. Exit code returned: $_"
        Exit 1
        
    }

    # Install the MSI

    Write-Log "Calling General_MSI_Installer script to install $MSIname..."

    $MSIPath2 = $MSIPathFromContainerRoot.Replace('/', '\')

    Try {
        if ($InstallArgs) {
            Write-Log "Using custom install arguments: $InstallArgs"
            & $MSIinstallScriptPath -MSIPath "$WorkingDirectory\TEMP\Downloads\$MSIPath2" -InstallArgs $InstallArgs -WorkingDirectory $WorkingDirectory -AppName $TargetAppName -DisplayName $DisplayName

        } else {
            & $MSIinstallScriptPath -MSIPath "$WorkingDirectory\TEMP\Downloads\$MSIPath2" -WorkingDirectory $WorkingDirectory -AppName $TargetAppName -DisplayName $DisplayName

        }
    } Catch {

        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END | MSI installation failed: $_" "ERROR"
        Exit 1

    }

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"

}

Function InstallApp-via-EXE-Private-AzureBlob {

    # Works

    # Download the custom MSI from Azure Blob Storage
    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START | Downloading MSI from Private Azure Blob Storage..."


    $EXEPathFromContainerRoot

    $EXEname = Split-Path $EXEPathFromContainerRoot -Leaf

    # Grab organization custom registry values
    Try{
    # Grab organization custom registry values
        Write-Log "Retrieving organization custom registry values..." 
        $ReturnHash = & $OrgRegReader_ScriptPath #| Out-Null

        # Check the returned hashtable
        if(($ReturnHash -eq $null) -or ($ReturnHash.Count -eq 0)){
            Write-Log "No data returned from Organization Registry Reader script!" "ERROR"
            Exit 1
        }
        #Write-Log "Organization custom registry values retrieved:"
        foreach ($key in $ReturnHash.Keys) {
            $value = $ReturnHash[$key]
            Write-Log "   $key : $value" 
        }    

        # Turn the returned hashtable into variables
        Write-Log "Setting organization custom registry values as local variables..." 
        foreach ($key in $ReturnHash.Keys) {
            Set-Variable -Name $key -Value $ReturnHash[$key] -Scope Local
            Write-Log "Should be: $key = $($ReturnHash[$key])" 
            $targetValue = Get-Variable -Name $key -Scope Local
            Write-Log "Ended up as: $key = $($targetValue.Value)" 

        }
    } Catch {
        Write-Log "Error retrieving organization custom registry values: $_" "ERROR"
        Exit 1
    }

    # Construct blob URI

    $parts = $ApplicationDataJSONpath -split '/', 2

    $ApplicationData_JSON_ContainerName = $parts[0]      
    $ApplicationData_JSON_BlobName = $parts[1]

    $SasToken = $ApplicationContainerSASkey

    Write-Log "Final values to be used to build $MSIname URI:" 
    Write-Log "StorageAccountName: $StorageAccountName"
    Write-Log "SasToken: $SasToken"
    Write-Log "ApplicationData_JSON_ContainerName: $ApplicationData_JSON_ContainerName"
    Write-Log "ApplicationData_JSON_BlobName: $ApplicationData_JSON_BlobName"

    $applicationJSONUri = "https://$StorageAccountName.blob.core.windows.net/$ApplicationData_JSON_ContainerName/$EXEPathFromContainerRoot"+"?"+"$SasToken"

    Write-Log "Attempting to access ApplicationData.json with this URI: $applicationJSONUri"

    Try{


        Write-Log "Beginning download..."
        & $DownloadAzureBlobSAS_ScriptPath -WorkingDirectory $WorkingDirectory -BlobName $EXEPathFromContainerRoot -StorageAccountName $StorageAccountName -ContainerName $ApplicationData_JSON_ContainerName -SasToken $SasToken
        if($LASTEXITCODE -ne 0){Throw $LASTEXITCODE }


    }catch{

        Write-Log "Download MSI failed. Exit code returned: $_"
        Exit 1
        
    }
    
    # Install the MSI

    Write-Log "Calling General_EXE_Installer script to install $EXEname..."

    $EXEPath2 = $EXEPathFromContainerRoot.Replace('/', '\')

    Try {

        & $EXEinstallScriptPath -EXEPath "$WorkingDirectory\TEMP\Downloads\$EXEPath2" -ArgumentList $InstallArgs -WorkingDirectory $WorkingDirectory -AppName $TargetAppName -DisplayName $DisplayName -ExpectedExitCodes $ExpectedExitCodes

        if($LASTEXITCODE -ne 0){Throw $LASTEXITCODE }

    } Catch {

        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END | EXE installation failed: $_" "ERROR"
        Exit 1

    }


    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"

}

Function InstallApp-via-CustomScript-AzureBlob {

}

Function InstallApp-via-MSI-Online {

}

Function InstallApp-via-CustomScript {

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START |Calling custom installation script: $ScriptPathFromRepoRoot"

    $CustomScriptPath = "$RepoRoot\$ScriptPathFromRepoRoot"

    if ($CustomScriptArgs)
    {
        Write-Log "Passing script arguments: $CustomScriptArgs"
        #"$CustomScriptPath -WorkingDirectory ""$WorkingDirectory"" $CustomScriptArgsList"
        #& $CustomScriptPath -WorkingDirectory "$WorkingDirectory" $ParsedArgs


            
            # Construct the full command string
            # We use single quotes around the path to handle spaces safely
            $Command = "& '$CustomScriptPath' -WorkingDirectory '$WorkingDirectory' $CustomScriptArgs"
            
            Write-Log "Constructed command: $Command"

            # Execute the string as code
            Invoke-Expression $Command


    } else {

        & $CustomScriptPath -WorkingDirectory $WorkingDirectory

    }

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"

}

Function ParseJSON {

    param(
        [string]$JSONpath
    )

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START"
    
    if (Test-Path $JSONpath) {Write-Log "Local JSON found. Attempting to get content."} else { Write-Log "Local JSON not found" "ERROR"; throw "Local JSON not found" }

    try {
        $jsonText = Get-Content -LiteralPath $JSONpath -Raw -Encoding UTF8
        $jsonData = $jsonText | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Log "ConvertFrom-Json failed: $($_.Exception.Message)" "ERROR"
        Throw $_
    }


    Write-Log ""

    # Can comment out
    # Write-Log "Here are all the applications we found from the JSON:"
    # Write-Log ""
    # $list = $jsonData.applications.ApplicationName 
    # Foreach ($item in $list) {
    #     Write-Log "$item"
    # }
    # Write-Log "" 

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"
    return $jsonData

}

Function InstallSomethingMain{

    Param(

        $AppNameToFind,

        $InstallIt = $true
    )

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START | Searching for application: $AppNameToFind"
    Write-Log "Parsing Public JSON"

    $PublicJSONdata = ParseJSON -JSONpath $PublicJSONpath
    $list = $PublicJSONdata.applications.ApplicationName


    if ($list -contains $AppNameToFind) {

        Write-Log "Found $AppNameToFind in public JSON data."
        $AppData = $PublicJSONdata.applications | Where-Object { $_.ApplicationName -eq $AppNameToFind }

        Write-log "Application data for $AppNameToFind retrieved from JSON:"
        Write-Log ($AppData | ConvertTo-Json -Depth 10)

    } else {

        ### If nothing found, attempt to search the  JSON...

        Write-Log "Application $AppNameToFind not found in public JSON data." "WARNING"

        ### Download the private JSON file from Azure Blob Storage

        Write-Log "Now constructing URI for accessing private json..." 
        

        $parts = $ApplicationDataJSONpath -split '/', 2

        $ApplicationData_JSON_ContainerName = $parts[0]      
        $ApplicationData_JSON_BlobName = $parts[1]

        #$ApplicationContainerSASkey
        $SasToken = $ApplicationContainerSASkey
        #$SasToken

        #pause

        Write-Log "Final values to be used to build ApplicationData.json URI:"
        Write-Log "StorageAccountName: $StorageAccountName"
        Write-Log "SasToken: $SasToken"
        Write-Log "ApplicationData_JSON_ContainerName: $ApplicationData_JSON_ContainerName" 
        Write-Log "ApplicationData_JSON_BlobName: $ApplicationData_JSON_BlobName" 
        $applicationJSONUri = "https://$StorageAccountName.blob.core.windows.net/$ApplicationData_JSON_ContainerName/$ApplicationData_JSON_BlobName"+"?"+"$SasToken"


        Write-Log "Attempting to access ApplicationData.json with this URI: $applicationJSONUri"

        Try{


            Write-Log "Beginning download..."
            & $DownloadAzureBlobSAS_ScriptPath -WorkingDirectory $WorkingDirectory -BlobName $ApplicationData_JSON_BlobName -StorageAccountName $StorageAccountName -ContainerName $ApplicationData_JSON_ContainerName -SasToken $SasToken
            if($LASTEXITCODE -ne 0){Throw $LASTEXITCODE }

            ### Ingest the private JSON data

            Write-Log "Parsing Private JSON"
            $PrivateJSONpath = "$WorkingDirectory\TEMP\Downloads\$ApplicationData_JSON_BlobName"
            $JSONpath = $PrivateJSONpath

            $PrivateJSONdata = ParseJSON -JSONpath $JSONpath
            $list = $PrivateJSONdata.applications.ApplicationName 

        }catch{

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END | Accessing JSON from private share failed. Exit code returned: $_" "ERROR"
            Exit 1
            
        }
        
        ### Search for the target application in the private JSON data

        if ($list -contains $AppNameToFind) {
            Write-Log "Found $AppNameToFind in private JSON data."
            $AppData = $PrivateJSONdata.applications | Where-Object { $_.ApplicationName -eq $AppNameToFind }

            Write-log "Application data for $AppNameToFind retrieved from private JSON:"
            Write-Log ($AppData | ConvertTo-Json -Depth 10)
        } else {
            Write-Log "Application $AppNameToFind not found in either public or private JSON data." "ERROR"
            Exit 1
        }

    }


    # Convert the JSON values into local variables for access later
    Write-Log "Setting application data values as local variables..."
    foreach ($property in $AppData.PSObject.Properties) {

        $propName = $property.Name
        $propValue = $property.Value
        Set-Variable -Name $propName -Value $propValue -Scope Local
        Write-Log "Should be: $propName = $propValue"
        $targetValue = Get-Variable -Name $propName -Scope Local
        Write-Log "Ended up as: $propName = $($targetValue.Value)"

    }

    if ($Prerequisites){
        # Set the Prerequisites variable to global scope so it can be accessed later
        Set-Variable -Name "Prerequisites" -Value $Prerequisites -Scope Global
    } else {
        # Ensure Prerequisites variable is empty if not set in JSON
        Set-Variable -Name "Prerequisites" -Value $null -Scope Global
    }

    if ($InstallIt) {
        InstallRunner -AppToInstall $AppNameToFind
    } else {
        Write-Log "InstallIt parameter set to false. Skipping installation for $AppNameToFind."# "DRYRUN"
    }

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"
}

Function InstallRunner {

    Param (

        $AppToInstall

    )

    ### Determine installation method
    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START | Requested installation method: $InstallMethod"

    if($InstallMethod -eq "WinGet"){

        Write-Log "Beginning installation via WinGet..."
        InstallApp-via-WinGet

    } elseif ($InstallMethod -eq "MSI-Private-AzureBlob") {

        Write-Log "Beginning installation via MSI from Private Azure Blob..."
        InstallApp-via-MSI-Private-AzureBlob

    } elseif ($InstallMethod -eq "EXE-Private-AzureBlob") {

        Write-Log "Beginning installation via EXE from Private Azure Blob..."
        InstallApp-via-EXE-Private-AzureBlob

    } elseif ($InstallMethod -eq "MSI-Online") {

        Write-Log "Beginning installation via MSI from Online source..."
        InstallApp-via-MSI-Online

    } elseif ($InstallMethod -eq "Custom_Script") {

        Write-Log "Beginning installation via Custom Script..."
        InstallApp-via-CustomScript

    } else { # TODO: Make this "$InstallMethod" able to be the direct name of the function to call

        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Unknown installation method specified: $InstallMethod" "ERROR"
        Exit 1

    }

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"

}

##########
## MAIN ##
##########

# Ingest the registry data

Write-Log "SCRIPT: $ThisFileName | START"
Write-Log ""

if($TargetAppName -eq "" -or $TargetAppName -eq $null){
    Write-Log "No TargetAppName specified. Exiting." "ERROR"
    Exit 1
}

Write-Log "Target Application to install: $TargetAppName"

Write-Log "================================="



Try{
# Grab organization custom registry values
    Write-Log "Retrieving organization custom registry values..."
    $ReturnHash = & $OrgRegReader_ScriptPath #| Out-Null

    # Check the returned hashtable
    if(($ReturnHash -eq $null) -or ($ReturnHash.Count -eq 0)){
        Write-Log "No data returned from Organization Registry Reader script!" "ERROR"
        Exit 1
    }
    #Write-Log "Organization custom registry values retrieved:"
    foreach ($key in $ReturnHash.Keys) {
        $value = $ReturnHash[$key]
        Write-Log "   $key : $value"
    }    

    # Turn the returned hashtable into variables
    Write-Log "Setting organization custom registry values as local variables..."
    foreach ($key in $ReturnHash.Keys) {
        Set-Variable -Name $key -Value $ReturnHash[$key] -Scope Local
        Write-Log "Should be: $key = $($ReturnHash[$key])"
        $targetValue = Get-Variable -Name $key -Scope Local
        Write-Log "Ended up as: $key = $($targetValue.Value)"

    }
} Catch {
    Write-Log "Error retrieving organization custom registry values: $_" "ERROR"
    Exit 1
}


Write-Log ""
Write-Log "================================="


# Check if the target application exists in either JSON and if it has prerequisites
Write-Log "Checking for application $TargetAppName and its prerequisites..."
InstallSomethingMain -AppNameToFind $TargetAppName -InstallIt $false

Write-Log "================================="

## If there are prerequisites, install them first
if ($Prerequisites) {  

    Write-Log "SCRIPT: $ThisFileName | Beginning installation of prerequisite applications: $Prerequisites"
    # Take the prerequisites string and split into an array
    $PrereqList = $Prerequisites -split ','

    Foreach ($Prereq in $PrereqList) {

        Write-Log "SCRIPT: $ThisFileName | Beginning installation of prerequisite application: $Prereq"

        # Call the InstallRunner function for each prerequisite
        $PreReqAppName = $Prereq.Trim()

        InstallSomethingMain -AppNameToFind $PreReqAppName -InstallIt $true

        # Check for success/fail
        if($LASTEXITCODE -ne 0){
            Write-Log "SCRIPT: $ThisFileName | END | Prerequisite installation for $Prereq failed with exit code $LASTEXITCODE" "ERROR"
            Exit $LASTEXITCODE
        } else {
            Write-Log "SCRIPT: $ThisFileName | Prerequisite installation for $Prereq completed successfully." "SUCCESS"
        }

   } 

    Write-Log "SCRIPT: $ThisFileName | All prerequisites installed successfully." "SUCCESS"

} Else {

    Write-Log "SCRIPT: $ThisFileName | No prerequisites specified for $TargetAppName. Proceeding to main installation."
}

Write-Log "================================="

## Install main requested application

Write-Log "SCRIPT: $ThisFileName | Beginning installation of main application: $TargetAppName"

InstallSomethingMain -AppNameToFind $TargetAppName -InstallIt $true

Write-Log "================================="

# Check for success/fail
if($LASTEXITCODE -ne 0){
    Write-Log "SCRIPT: $ThisFileName | END | Installation script failed with exit code $LASTEXITCODE" "ERROR"
    Exit $LASTEXITCODE
} else {
    Write-Log "SCRIPT: $ThisFileName | END | Installation script completed successfully." "SUCCESS"
    Exit 0
}

### Determine install variables from JSON data

