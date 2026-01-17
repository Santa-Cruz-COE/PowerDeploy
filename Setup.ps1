<#

.SYNOPSIS
    Setup script for Admin Script Suite. 

.DESCRIPTION
    This script is the main point of contact for the technician users of PowerDeploy. 
    Uses Azure Blob Storage based JSON files to set up printer and application deployments via Intune.
    It can:
    - Set up printer/app deployments via Intune (from Azure Blob Storage JSON)
    - Install a local printer/app (from Azure Blob Storage JSON)
    - Add printers and applications to the Azure Blob Storage JSON files

    PRE-REQUISITES:
    - Ensure you have the required Azure Blob Storage infrastructure set up:
        Documentation URL: will add soon
    - Ensure you have the required registry values set up for accessing the Azure Blob Storage. Recommend using Remediation Scripts for this.
        Documentation URL: will add soon
    
    DIRECTIONS FOR USE:
    - Run this script in an elevated PowerShell session (Run as Administrator) or run Setup_RUNNER.bat as admin
    - Follow the on-screen prompts to perform the desired setup tasks.


.NOTES


    TODO: Add a warning if script user != logged in user and script/user is not elevated (WinGet does not like this scenario)

    TODO: If app to add to InTune is a winget install, attempt to pull the desc from the ms store and dump into a txt for the user to copy and paste

    TODO: add this functionality:

      {
            "ApplicationName": "7zip.MSI",
            "InstallMethod": "MSI-Online",
            "URL":"https://www.7-zip.org/a/7z2201-x64.msi",
            "MSI_name":"7z2201-x64.msi"
        },

    TODO: Add ability to switch current branch of this script?

    TODO: Redo the update local git repo functionality


#>



$LocalFileName = $MyInvocation.MyCommand.Name


$WorkingDirectory = (Split-Path $PSScriptRoot -Parent)
$RepoRoot = $PSScriptRoot
$LocalRepoPath = $RepoRoot
$ThisRepoNickName = (Split-Path $PSScriptRoot -leaf)

$LogRoot = "$WorkingDirectory\Logs\Setup_Logs"
$LogPath = "$LogRoot\$LocalFileName._Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# path of WinGet installer
$WinGetInstallerScript = "$RepoRoot\Installers\General_WinGet_Installer.ps1"
# path of General uninstaller
$UninstallerScript = "$RepoRoot\Uninstallers\General_Uninstaller.ps1"
# path of the DotNet installer
$DotNetInstallerScript = "$RepoRoot\Installers\Install-DotNET.ps1"
# path to Git Runner
$GitRunnerScript = "$RepoRoot\Templates\Git-Runner_TEMPLATE.ps1"
# path of General_RemediationScriptSuite-Registry-Detection_TEMPLATE
$General_RemediationScript_Registry_TEMPLATE = "$RepoRoot\Templates\General_RemediationScript-Registry_TEMPLATE.ps1"
# path of Organization_CustomRegistryValues-Reader_TEMPLATE
$OrgRegReader_ScriptPath = "$RepoRoot\Templates\OrganizationCustomRegistryValues-Reader_TEMPLATE.ps1"
# path of Generate_Install-Command script
$GenerateInstallCommand_ScriptPath = "$RepoRoot\Other_Tools\Generate_Install-Command.ps1"
# path of the Azure Blob SAS downloader script
$DownloadAzureBlobSAS_ScriptPath = "$RepoRoot\Downloaders\DownloadFrom-AzureBlob-SAS.ps1"
# Path to the printer install script
$InstallPrinterIP_ScriptPath = "$RepoRoot\Installers\General_IP-Printer_Installer.ps1"
# Path to JSON app install script
$JSONAppInstaller_ScriptPath = "$RepoRoot\Installers\General_JSON-App_Installer.ps1"
# Path to printer uninstall script
$UninstallPrinter_ScriptPath = "$RepoRoot\Uninstallers\Uninstall-Printer.ps1"
# Path to app uninstall script
$UninstallApp_ScriptPath = "$RepoRoot\Uninstallers\General_Uninstaller.ps1"
# Path to install WinGet script
$InstallWinGet_ScriptPath = "$RepoRoot\Installers\Install-WinGet.ps1"
# Path to app detect script
$AppDetect_ScriptPath = "$RepoRoot\Templates\Detection-Script-Application_TEMPLATE.ps1"
# Path to Git Runner template
$GitRunnerTemplate_ScriptPath = "$RepoRoot\Templates\Git-Runner_TEMPLATE.ps1"

$PublicJSONpath = "$RepoRoot\Templates\ApplicationData_TEMPLATE.json"

$MyCompanyRepoURL = ""
$MyCompanyRepoURLTOKEN = ""
$OfficialPublicRepoURL = "https://github.com/Santa-Cruz-COE/PowerDeploy"
$Global:TargetRepoNickName = ""
$Global:TargetWorkingDirectory = ""
$Global:DeployMode = "" 

$ExamplePrinterJSON = @"
{
  "printers": [
    {
      "PrinterName": "OLD_Printer",
      "PortName": "010.020.030.040",
      "PrinterIP":"10.20.30.40",
      "DriverName":"HP Universal Printing PCL 6",
      "INFFile":"hpcu270u.inf",
      "DriverZip":"printers/Drivers/HP/testDrivers.zip"
    },
	{
      "PrinterName": "NEW_Printer",
      "PortName": "010.020.030.041",
      "PrinterIP":"10.20.30.41",
      "DriverName":"HP Universal Printing PCL 6",
      "INFFile":"hpcu345u.inf",
      "DriverZip":"printers/Drivers/HP/HP_Universal_Printing_PCL_6/upd-pcl6-x64-7.9.0.26347.zip"
    }
}
"@

$ExampleAppJSON = @"
{
  "Applications": [
  {
    "ApplicationName": "Visual_Studio_Code",
    "InstallMethod": "WinGet",
    "WinGetID":"Microsoft.VisualStudioCode"
  },
  {
    "ApplicationName": ".NET_3.5",
    "InstallMethod": "Custom_Script",
    "ScriptPathFromRepoRoot":"Installers\\Install-DotNET.ps1",
    "CustomScriptArgs":"-Version \"3.5\""
  },
  {
    "ApplicationName": "MSI-Private-AzureBlob_Example",
    "InstallMethod": "MSI-Private-AzureBlob",
    "MSIPathFromContainerRoot":"Adobe_Creative_Cloud/install.msi",
    "DisplayName":"Adobe Creative Cloud",
    "PreRequisites":".NET_3.5,Visual_Studio_Code"
  },
  ]
}
"@

#################
### Functions ###
#################

# NOTE: This function will not use write-log.
function Test-PathSyntaxValidity {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Paths,
        [switch]$ExitOnError
    )
    
    # Windows illegal path characters (excluding : for drive letters and \ for path separators)
    $illegalChars = '[<>"|?*]'
    
    # Reserved Windows filenames
    $reservedNames = @(
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    )
    
    $allValid = $true
    $issues = @()
    
    foreach ($paramName in $Paths.Keys) {
        $path = $Paths[$paramName]
        
        # Skip if null or empty
        if ([string]::IsNullOrWhiteSpace($path)) {
            $issues += "Parameter '$paramName' is null or empty"
            $allValid = $false
            continue
        }
        
        # Check for trailing backslash before closing quote pattern (common BAT file issue)
        if ($path -match '\\["\' + "']$") {
            $issues += "Parameter '$paramName' has trailing backslash before quote: '$path' - This will cause escape character issues"
            $allValid = $false
        }
        
        # Check for illegal characters
        if ($path -match $illegalChars) {
            $matches = [regex]::Matches($path, $illegalChars)
            $foundChars = ($matches | ForEach-Object { $_.Value }) -join ', '
            $issues += "Parameter '$paramName' contains illegal characters ($foundChars): '$path'"
            $allValid = $false
        }
        
        # Check for invalid double backslashes (except at start for UNC paths)
        if ($path -match '(?<!^)\\\\') {
            $issues += "Parameter '$paramName' contains double backslashes (not a UNC path): '$path'"
            $allValid = $false
        }
        
        # Check for reserved Windows names in path components
        $pathComponents = $path -split '[\\/]'
        foreach ($component in $pathComponents) {
            $nameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($component)
            if ($nameWithoutExt -in $reservedNames) {
                $issues += "Parameter '$paramName' contains reserved Windows name '$nameWithoutExt': '$path'"
                $allValid = $false
            }
        }
        
        # Check for paths that are too long (MAX_PATH = 260 characters in Windows)
        if ($path.Length -gt 260) {
            $issues += "Parameter '$paramName' exceeds maximum path length (260 characters): '$path' (Length: $($path.Length))"
            $allValid = $false
        }
        
        # Check for invalid drive letter format
        if ($path -match '^[a-zA-Z]:' -and $path -notmatch '^[a-zA-Z]:\\') {
            $issues += "Parameter '$paramName' has invalid drive format (missing backslash after colon): '$path'"
            $allValid = $false
        }
        
        # Check for spaces at beginning or end of path (common copy-paste issue)
        if ($path -ne $path.Trim()) {
            $issues += "Parameter '$paramName' has leading or trailing whitespace: '$path'"
            $allValid = $false
        }
    }
    
    # Report results
    if (-not $allValid) {
        Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX PATH VALIDATION FAILED - Issues detected:"
        foreach ($issue in $issues) {
            Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX - $issue"
        }
        
        if ($ExitOnError) {
            Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Exiting script due to path validation errors"
            Exit 1
        }
    } else {
        Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Path validation successful - all parameters valid"
    }
    
    #return $allValid

}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    if ($Level -eq "INFO2") {
        $logEntry = "[$timestamp] [INFO] $Message"
    } else {
        $logEntry = "[$timestamp] [$Level] $Message"
    }

    
    
    switch ($Level) {
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "DRYRUN"  { Write-Host $logEntry -ForegroundColor Cyan }
        "INFO"    { Write-Host $logEntry -ForegroundColor Cyan }
        "INFO2"    { Write-Host $logEntry }

        default   { Write-Host $logEntry }
    }
    
    # Ensure log directory exists
    $logDir = Split-Path $LogPath -Parent
    if (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    Add-Content -Path $LogPath -Value $logEntry
}

Function Set-URL {

    Write-Log "Before we begin, please confirm the deployment mode."
    Write-Log ""
    Write-Log "WHAT IS THIS?"
    Write-Log " - Determines which repo/branch the custom script/command will pull from during use"
    Write-Log ""
    Write-Log "WHICH ONE SHOULD I CHOOSE?"
    Write-Log " - To simply get a new asset in to production quickly, choose PRODUCTION"
    Write-Log " - If you are doing any form of dev/testing, do testing in order of 1-4 as appropriate"
    Write-Log ""

    #Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START"
    #Write-Log ""
    Write-Log "Deployment Mode Options:"
    # Write-Log "1 - TEST MODE: The resulting InTune application will utilize the official public repository for PowerDeploy. This is good for testing the latest code before merging it into your own code. Target URL: $OfficialPublicRepoURL"
    # Write-Log "2 - PRODUCTION MODE: The resulting InTune application will utilize your organization's custom repository for PowerDeploy. Target URL: $CustomRepoURL"
    Write-Log ""
    Write-Log "1 - [PUBLIC-DEVELOPMENT]:" 
    Write-Log "     - For TESTING purposes."
    Write-Log "     - Uses official public PowerDeploy repo (DEV branch)" 
    Write-Log "     - For testing public dev code if you are a public developer"
    Write-Log ""

    Write-Log "2 - [PUBLIC-TESTING]:"
    Write-Log "     - For TESTING purposes."
    Write-Log "     - Uses official public PowerDeploy repo (MAIN branch)"
    Write-Log "     - For testing the latest code before merging it into your own repo."
    Write-Log ""

    Write-Log "3 - [PRIVATE-DEVELOPMENT]:"
    Write-Log "     - For TESTING purposes."
    Write-Log "     - Uses your organization's custom PowerDeploy repository (DEV branch)"
    Write-Log "     - For testing YOUR dev code if you are a developer of your org repo."

    Write-Log ""

    Write-Log "4 - [PRODUCTION]:"
    Write-Log "     - For PRODUCTION deployments."
    Write-Log "     - Uses your organization's custom PowerDeploy repository (MAIN branch)"
    Write-Log "     - For deploying your latest stable code from your org repo."
    Write-Log "     - If the InTune asset is intended for production use, this is the mode to choose."
    Write-Log ""

    $modeSelected = $false
    $modeSelected1 = $false

    while (-not $modeSelected) {
        $userInput = Read-Host "Please enter a number (1-4) to select the deployment mode"
        Write-Log ""

        
         switch ($userInput) {
            '1' {
                $Global:DeployMode = "PUBLIC-DEVELOPMENT"
                $RepoUrl = $OfficialPublicRepoURL
                $Global:RepoBranch = "dev"
                
                $modeSelected1 = $true
            }
            '2' {
                $Global:DeployMode = "PUBLIC-TESTING"
                $RepoUrl = $OfficialPublicRepoURL
                $Global:RepoBranch = "main"
                $modeSelected1 = $true
            }
            '3' {
                $Global:DeployMode = "PRIVATE-DEVELOPMENT"

                    if ($CustomRepoToken -ne "" -and $CustomRepoToken -ne $null) {
                        # Insert token into URL for authentication
                        $RepoUrl = $CustomRepoURL -replace 'https://', "https://oauth2:$CustomRepoToken@"
                    } else {
                        $RepoUrl = $CustomRepoURL
                    }
                $Global:RepoBranch = "dev"
                $modeSelected1 = $true
            }
            '4' {
                $Global:DeployMode = "PRODUCTION"

                    if ($CustomRepoToken -ne "" -and $CustomRepoToken -ne $null) {
                        # Insert token into URL for authentication
                        $RepoUrl = $CustomRepoURL -replace 'https://', "https://oauth2:$CustomRepoToken@"
                    } else {
                        $RepoUrl = $CustomRepoURL
                    }
                $Global:RepoBranch = "main"
                $modeSelected1 = $true
            }
            default {
                Write-Log "Invalid input. Please enter a number between '1' and '4'." "WARNING"

            }

        }

        if ($modeSelected1) {

            if ($userinput -eq "3" -or $userinput -eq "4") {
                # Verify that CustomRepoURL is set
                if ([string]::IsNullOrWhiteSpace($CustomRepoURL)) {
                    Write-Log "ERROR: Organization CustomRepoURL is not set in registry. Cannot proceed with PRIVATE-DEVELOPMENT or PRODUCTION mode. Please set your custom org repo by forking the public repo and then set the registry appropriately with your custom URL/token using the following function from this script: Setup--Azure-PowerDeploy_Registry_Remediations_For_Organization" "ERROR"
                    $modeSelected1 = $False
                }
            }
        }

        if ($modeSelected1) {

            $Global:ProgamDataFolderName = "PowerDeploy--$Global:DeployMode"
            #$Global:TargetRepoNickName = "PowerDeploy-Repo--$Global:DeployMode"
            $Global:TargetRepoNickName = "PowerDeploy-Repo"
            $Global:TargetWorkingDirectory = "C:\ProgramData\$Global:ProgamDataFolderName"

            Write-Log "You have selected the following:"
            Write-Log ""
            Write-Log " Target Deployment mode:                 $Global:DeployMode"
            Write-Log " Target Repo URL set to:                 $RepoUrl"
            Write-Log " Target Repo branch:                     $Global:RepoBranch"
            Write-Log " Target Local Repo Nickname set to:      $Global:TargetRepoNickName"
            Write-Log " Target Local Working Directory set to:  $Global:TargetWorkingDirectory"
            Write-Log ""
            Write-Log "Is this acceptable? (y/n)" "WARNING"
            $confirmation = Read-Host "(y/n)"
            if ($confirmation -eq "y") {
                $modeSelected = $true
            } else {
                Write-Log "Let's try again to select the deployment mode."
            }

        }

        Write-Log ""




    }

    Write-Log "Deployment mode set to $Global:DeployMode" "WARNING"
    Write-Log ""
    Write-Log "The end product you create will use the above repository for its scripts."
    Write-Log ""
    Write-Log ""
    #Pause
    Clear
    Return $RepoUrl

    
}

# DONE (still need testing) 1/14/26
function Setup--Azure-Printer{

    # Determine if this is a test or production deployment
    $RepoUrl = Set-URL

    Write-Log "==========================================================================================="
    Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START"
    Write-Log "==========================================================================================="

    Write-Log ""

    # vars

    $parts = $PrinterDataJSONpath -split '/', 2

    $PrinterData_JSON_ContainerName = $parts[0]      
    $PrinterData_JSON_BlobName = $parts[1]

    # main 




    # User needs:
        # - Printer Name
        # - Printer IP and Port
        # - Printer Driver INF file
        # - Printer Driver Name
        # - Printer Driver Zip Location in Azure Blob

    Write-Log "Have you already set up the printer configuration for your desired printer in the PrinterData.json file in Azure Blob Storage?" "WARNING"
    $Answer = Read-Host "(y/n)"
    While ($Answer -ne "y" -and $Answer -ne "n") {
        Write-Log "Invalid input. Please enter 'y' for yes or 'n' for no." "ERROR"
        $Answer = Read-Host "(y/n)"
    }

    if ($Answer -eq "y" ){

        Write-Log "Please select the printer from the PrinterData.json:"

        $PrinterName = Select-PrinterFromJSON -DialogueSelection "B"

        Clear 

        if ($PrinterName -eq $null -or $PrinterName -eq "") {
            Write-Log "No printer selected. Proceeding with guided setup." "WARNING"
            $Answer = "n"
        } else {
            Write-Log "You have selected printer: $PrinterName"
        }
    } 

    Write-Log ""

    if ($Answer -eq "n") {

        Write-Log "==========================================================================================="
        Write-Log "PRE-REQUISITES FOR PRINTER SETUP"
        Write-Log "==========================================================================================="
        Write-Log ""

    
        Write-Log "Before proceeding, you need these 6 items figured out:"
        Write-Log ""
        Write-Log "     1 - Printer Name"
        Write-Log "     2 - Printer IP"
        Write-Log "     3 - Printer Port - (Could be same as IP but formatted as full length eg 000.000.000.000)"
        Write-Log ""
        Write-Log "     > You may need to do research to find the correct driver for your printer model. Make sure to do testing:"
        Write-Log "     4 - Printer Driver INF file"
        Write-Log "     5 - Printer Driver Name"
        Write-Log ""
        Write-Log "     > Finally, you will need to upload the printer driver files to Azure Blob Storage if the required driver is not there already. This script will assist with this part if you don't have it yet."
        Write-Log "     6 - Printer Driver Zip Location in Azure Blob"
        Write-Log ""
        Write-Log "Save these details, as you will need them shortly."
        Write-Log ""
        Pause
        Write-Log ""
        Write-Log "Please enter the name of your printer:" "WARNING"
        $PrinterName = Read-Host "Printer Name"
        While ([string]::IsNullOrWhiteSpace($PrinterName)) {
            Write-Log "No printer name provided. Please enter a printer name." "ERROR"
            $PrinterName = Read-Host "Printer Name"
        }
        Write-Log "Printer Name set to: $PrinterName"




        Write-Log ""

        Write-Log "==========================================================================================="
        Write-Log "NAVIGATE TO AZURE BLOB STORAGE"
        Write-Log "==========================================================================================="
        Write-Log ""
        # Determine the location of the azure blob based off of registry values:
            # Go to "https://portal.azure.com/#view/Microsoft_Azure_StorageHub/StorageHub.MenuView/~/StorageAccountsBrowse"
            # Select this storage account: $AzureStorageAccountName
            # Select "Containers" from the left menu
            # Select this container: $AzureBlobContainerName
        Write-Log "Next we will navigate to your Azure Blob Storage container to create the required resources"
        Write-Log ""
        Write-Log "Instructions for navigating to your Azure Blob Storage container as follows:"
        Write-Log ""
        Write-Log " 1 - Go to https://portal.azure.com/#view/Microsoft_Azure_StorageHub/StorageHub.MenuView/~/StorageAccountsBrowse"
        Write-Log ""
        Write-Log " 2 - Select this storage account: $StorageAccountName"
        Write-Log ""
        Write-Log " 3 - Select 'Data Storage' > 'Containers' from the left menu"
        Write-Log ""
        Write-Log " 4 - Select this container: $PrinterData_JSON_ContainerName"
        # Write-Log ""
        # Pause
        Write-Log ""

    } 


    # Write-Log ""

    Write-Log "Have you uploaded the required printer driver ZIP file to Azure Blob Storage?" "WARNING"
    $Answer2 = Read-Host "(y/n)"

    if ($Answer2 -ne "y" -and $Answer2 -ne "n") {
        Write-Log "Invalid input. Please enter 'y' for yes or 'n' for no." "ERROR"
        $Answer2 = Read-Host "(y/n)"
    }

    Write-Log ""

    If ($Answer2 -eq "n") {

        Write-Log "==========================================================================================="
        Write-Log "UPLOAD PRINTER DRIVER TO AZURE BLOB STORAGE"
        Write-Log "==========================================================================================="
        Write-Log ""

        # Tell the user of the location to place the print drivers in Azure Blob
        Write-Log "Next we need to ensure the correct printer drivers are in our Azure Blob Storage."
        Write-Log ""
        Write-Log "The location of your printer driver ZIP files in your Azure Blob Storage is: $PrinterData_JSON_ContainerName\Drivers"
        Write-Log ""
        Write-Log "Please note the following"
        Write-Log "     - Use the Drivers folder to keep a neat structure of general driver packs from the manufacturers." 
        Write-Log "     - Example: $PrinterData_JSON_ContainerName\Drivers\HP\HP_Universal_Printing_PCL_6\[latestVersion].zip" 
        Write-Log "     - These driver packs carry the INF file needed for installation for most of the specific manufacturer's printers."
        Write-Log "     - Most of the time you WILL NOT need to upload a new driver if you have pre-existing manufacturer driver packs (PCL/PostScript) here."
        Write-Log "     - How do you determine the appropriate INF?"
        Write-Log "       - EXAMPLE: After looking up your specific Printer's driver for Windows Server..."
        Write-Log "       - If HP says an appropriate driver is ""HP Universal Print Driver for Windows PCL6 (64-bit)"", then the INF file that should end up being targetted is always hpcu***u.inf (the only INF in that pack with those drivers)"
        Write-Log "     - If you end up needing to download the driver, when you are looking for the driver online you may need to change the target OS to Windows Server in order to find the PCL/PostScript drivers."
        Write-Log ""    
        Write-Log "If your required printer driver is not already in Azure Blob, please upload it now. Record the path you upload it to for later use."
        Write-Log ""    
        Pause
    
    }   

    Write-Log ""


    if ($Answer -eq "n") {

        Write-Log "==========================================================================================="
        Write-Log "EDIT PRINTER DATA JSON"
        Write-Log "==========================================================================================="
        Write-Log ""
        # Tell the user what the possible location of the printerJSON is in Azure Blob
        # From within the container, the path to the printer JSON should be: $AzureBlobContainerPath\$PrinterJSONFileName
        # Click on the JSON and navigate to edit
        Write-Log "Next we need to edit the Printer Data JSON file that contains the details of all printers available for deployment."
        Write-Log ""    
        Write-Log "From within the container, the path to the printer JSON should be: $PrinterDataJSONpath"
        Write-Log ""
        Write-Log "Click on the JSON and select to ""edit"""
        Write-Log ""
        Write-Log "Here is an example of what the JSON should look like:"
        Write-Log ""
        Write-Host $ExamplePrinterJSON
        Write-Log ""
        Write-Log "Add your new printer details to the JSON now, following the existing format within. Save when you are finished." "WARNING"


        Pause

    }

    Write-Log ""

    Write-Log "==========================================================================================="
    Write-Log "TEST PRINTER INSTALLATION FROM JSON"
    Write-Log "==========================================================================================="
    Write-Log ""




    # Suggest testing the JSON with the local install script
    Write-Log "After completing the Printer Data JSON, it is highly recommended to test the installation of the new printer on a local machine before proceeding with Intune deployment."
    Write-Log ""
    Write-Log "This will help ensure that all details are correct and the installation process works as expected."
    Write-Log ""
    Write-Log "Would you like to test by installing this printer from the JSON on this local machine?" "WARNING"
    $Answer = Read-Host "(y/n)"
    Write-Log ""


        if ($answer -eq "y"){

            Write-Log "Before proceeding, please make sure this printer is not already installed locally on this machine. If it is, please uninstall it first." "WARNING"
            Pause
            Write-Log ""

            Write-Log "Proceeding with local installation test..."

            Write-Log ""


            & Install--Local-Printer -PrinterName $PrinterName

            Write-Log ""

            if($LASTEXITCODE -ne 0){
                Write-Log "Local printer installation test failed with exit code: $LASTEXITCODE" "ERROR"
                Write-Log "Please resolve any issues before proceeding with Intune deployment."
                Exit $LASTEXITCODE
            } else {
                Write-Log "Local printer installation test succeeded! This configuration for the JSON works!" "SUCCESS"
                Pause
            }   

        } else {

            Write-Log "Skipping local installation test. Proceeding with Intune deployment setup."

        }

    Write-Log "==========================================================================================="
    Write-Log "AUTOMATIC CREATION OF:"
    Write-Log " - INTUNE WIN32 APP PACKAGE"
    Write-Log " - INSTALL/UNINSTALL COMMANDS/SCRIPTS"
    Write-Log "==========================================================================================="


    Write-Log ""
    Write-Log "Next we will automatically create the Intune Win32 app package for deploying the printer."
    Write-Log ""
    # Pause
    Write-Log ""

    # Add the printer to InTune
        # Create the win32app
        # Tell the user where it is and how to import it into InTune
        # Create the detection script
        # Tell the user where it is and how to import it into InTune
    Make-InTuneWin -SourceFile "$GitRunnerScript" 
    $PrinterIntuneWinPath = $Global:intunewinpath
    Write-Log ""    
    Write-Log "The Intune Win32 app package has been created at: $PrinterIntuneWinPath"
    Write-Log ""    
    Write-Log "Next we will automatically create the install/uninstall commands/scripts and the detection script required for the Intune Win32 app."

    Write-Log "" "INFO2"

        # Create install command    

        [hashtable]$FunctionParams = @{
            PrinterName = $PrinterName
        }

        $ReturnHash2 = & $GenerateInstallCommand_ScriptPath -DesiredFunction "InstallPrinterByIP" -RepoURL $RepoURL -RepoNickName $Global:TargetRepoNickName -RepoBranch $Global:RepoBranch -TargetWorkingDirectory $Global:TargetWorkingDirectory-FunctionParams $FunctionParams

        # Check the returned hashtable
        if(($ReturnHash2 -eq $null) -or ($ReturnHash2.Count -eq 0)){
            Write-Log "No data returned!" "ERROR"
            Exit 1
        }

        Write-Log "Values retrieved:" "INFO2"

        foreach ($key in $ReturnHash2.Keys) {

            $value = $ReturnHash2[$key]
            Write-Log "   $key : $value" "INFO2"

        }    

        # $result = $ReturnHash2
        # foreach ($key in $result.Keys) {

        #     Write-Host "   $key : $($result[$key])"

        # }


        # Turn the returned hashtable into variables
        Write-Log "Setting values as local variables..." "INFO2"
        foreach ($key in $ReturnHash2.Keys) {
            Set-Variable -Name $key -Value $ReturnHash2[$key] -Scope Local
            # Write-Log "Should be: $key = $($ReturnHash[$key])"
            $targetValue = Get-Variable -Name $key -Scope Local
            Write-Log "Ended up as: $key = $($targetValue.Value)" "INFO2"


        }

        # Create uninstall command    

        [hashtable]$FunctionParams = @{
            PrinterName = $PrinterName
        }

        $ReturnHash3 = & $GenerateInstallCommand_ScriptPath -DesiredFunction "UninstallPrinterByName" -RepoURL $RepoURL -RepoNickName $Global:TargetRepoNickName -RepoBranch $Global:RepoBranch -TargetWorkingDirectory $Global:TargetWorkingDirectory -FunctionParams $FunctionParams

        # Check the returned hashtable
        if(($ReturnHash3 -eq $null) -or ($ReturnHash3.Count -eq 0)){
            Write-Log "No data returned!" "ERROR"
            Exit 1
        }

        Write-Log "Values retrieved:" "INFO2"

        foreach ($key in $ReturnHash3.Keys) {

            $value = $ReturnHash3[$key]
            Write-Log "   $key : $value" "INFO2"

        }    

        # $result = $ReturnHash2
        # foreach ($key in $result.Keys) {

        #     Write-Host "   $key : $($result[$key])"

        # }


        # Turn the returned hashtable into variables
        Write-Log "Setting values as local variables..." "INFO2"
        foreach ($key in $ReturnHash3.Keys) {
            Set-Variable -Name $key -Value $ReturnHash3[$key] -Scope Local
            # Write-Log "Should be: $key = $($ReturnHash[$key])"
            $targetValue = Get-Variable -Name $key -Scope Local
            Write-Log "Ended up as: $key = $($targetValue.Value)" "INFO2"


        }

    if ($Global:DeployMode -eq "Production"){

            $PotentialPrinterInTuneName = "PRINTER: $PrinterName"

    } else {
            $PotentialPrinterInTuneName = "PRINTER: $PrinterName [$Global:DeployMode]"
    }
        
    Clear
    Write-Log ""
    Write-Log "Install command, uninstall command, and detection script created!" "SUCCESS"
    Write-Log ""
    # Write-Log "When you are ready we can move on to the final step of uploading and creating the Intune Win32 application."
    # Write-Log ""
    # Pause
    # Write-Log ""
    Clear
    Write-Log "==========================================================================================="
    Write-Log "UPLOAD AND CREATE INTUNE WIN32 APPLICATION"
    Write-Log "==========================================================================================="
    Write-Log ""
    Write-Log "Next we will manually create a Win32 application in InTune for this printer using the new intunewin file, script, and install command."
    Write-Log ""
    Write-Log "InTune Win32 Application creation instructions:"
    Write-Log ""           
    Write-Log ""    
    Write-Log " 1 - Navigate to Microsoft Endpoint Manager admin center > Devices > Windows > Windows apps"
    Write-Log "     - Alt url: https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/AppsWindowsMenu/~/windowsApps"
    Write-Log "     - + Create > App type: Windows app (Win32)"
    Write-Log ""   
    Pause
    Write-Log ""  
    Write-Log " 2 - Upload the .intunewin file located here: $PrinterIntuneWinPath"
    Write-Log ""   
    Pause
    Write-Log ""  
    Write-Log " 3 - APP INFORMATION:"
    write-log "     - Name: follow your org naming conventions."
    Write-Log "         - What I recommend: ""$PotentialPrinterInTuneName"""
    Write-Log "     - Description: Include printer name, IP, driver version, location, etc following a common naming convention for you organization."
    Write-Log "     - Publisher: Your organization name"
    Write-Log "     - Logo: Optional - You could create something with Canva using your organization logo, but standardize it"
    Write-Log ""   
    Pause
    Write-Log ""   
    Write-Log " 4 - PROGRAM:"
    Write-Log "     - Install command:" 
    Write-Log "         - Use the install command found inside this file: $MainInstallCommandTXT" # I don't remember why I named this "main"
    Write-Log "     - Uninstall command:" 
    Write-Log "         - Use the uninstall command found inside this file: $UninstallCommandTXT"
    Write-Log "     - Install time: 15 minutes"
    Write-Log "     - Allow available uninstall: Yes"
    Write-Log "     - Install behavior: System"
    Write-Log "     - Device restart behavior: No specific action"
    Write-Log ""   
    Pause
    Write-Log ""    
    Write-Log " 5 - REQUIREMENTS:"
    Write-Log "     - Check operating system architecture if needed (most printers will work on both x86 and x64 but not ARM64). You can skip if desired."
    Write-Log "     - Minimum operating system: Doesn't matter."
    Write-Log ""   
    Pause
    Write-Log ""  
    Write-Log " 6 - DETECTION:"
    Write-Log "     - Rules format: Use a custom detection script"
    Write-Log "     - Script File: Upload this script: $DetectPrinterScript"
    Write-Log "     - Run script as 32-bit process on 64-bit clients: No"
    Write-Log "     - Enforce script signature check: No"
    Write-Log ""   
    Pause
    Write-Log ""  
    Write-Log " 7 - DEPENDENCIES: None"
    Write-Log ""   
    Pause
    Write-Log ""  
    Write-Log " 8 - SUPERSEDENCE: None"
    Write-Log ""   
    Pause
    Write-Log ""  
    Write-Log " 9 - ASSIGNMENTS: Assign to the required groups/devices for your organization."
    Write-Log ""
    Pause
    Write-Log ""
    Write-Log "Printer deployment setup is complete! Please verify functionality on a test device. The printer will both be available from the Company Portal for the assigned devices AND from the local Printer Installer function in this script." "SUCCESS"
    Write-Log ""    
    Pause


}

# DONE (still need testing) 1/14/26
Function Setup--Azure-WindowsApp{

    # Determine if this is a test or production deployment
    $RepoUrl = Set-URL
    Write-Log "==========================================================================================="
    Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START"
    Write-Log "==========================================================================================="
    Write-Log ""



    # vars

    $parts = $ApplicationDataJSONpath -split '/', 2

    $ApplicationData_JSON_ContainerName = $parts[0]      
    $ApplicationData_JSON_BlobName = $parts[1]



    # main 

    Write-Log "Is your app already in either the public or private JSON files?" "WARNING"
    Write-Log ""

    Write-Log "NOTE: If you are unsure, select 'n' to proceed with guided setup." "WARNING"
    Write-Log ""

    $Answer = Read-Host "(y/n)"
    While ($Answer -ne "y" -and $Answer -ne "n") {
        Write-Log "Invalid input. Please enter 'y' for yes or 'n' for no." "ERROR"
        $Answer = Read-Host "(y/n)"
    }

    Write-Log ""


    If ($Answer -eq "n"){




        Write-Log "==========================================================================================="
        Write-Log "PRE-REQUISITES FOR APPLICATION SETUP"
        Write-Log "==========================================================================================="
        Write-Log ""
        

        Write-Log "To begin, we will prepare the data required to set up an app deployment via Intune."
        Write-Log ""
        Write-Log "App data is stored in one of two JSON files:"
        Write-Log ""
        Write-Log " - Public JSON: "
        Write-Log "     - Location:GitHub repository where this script is hosted."
        Write-Log "     - Updates: Maintained by the community and updated periodically."
        Write-Log " - Private JSON: "
        Write-Log "     - Location: Your organization's Azure Blob Storage."
        Write-Log "     - Updates: Managed by your organization for custom or proprietary apps."

        # User needs:
            # If application IS in the public or private JSON...
                # - Application Name (that's it!!)
            # If application IS NOT in the public or private JSON...
                # - Application Name
                # - Install Method
                    # if Winget:
                        # - Winget ID
                    # if MSI-Online
                        # - URL
                        # - MSI name
                    # if Custom_Script
                        # - Script Path from Repo Root
                        # - Custom Script Args (if any)
                # - PreRequisites (if any)


        Write-Log ""
        # Write-Log "REQUIRED RESOURCES:"
        # Write-Log ""
        # Write-Log "If application IS ALREADY in the public or private JSON..."
        # Write-Log "    1 - Application Name (that's it!!)"
        # Write-Log ""
        # Write-Log "If application IS NOT in the public or private JSON..."
        # Write-Log "    1 - Application Name"
        # Write-Log "    2 - Install Method"
        # Write-Log "        if Winget:"
        # Write-Log "            - Winget ID"
        # Write-Log "        if MSI-Online"
        # Write-Log "            - URL"
        # Write-Log "            - MSI name"
        # Write-Log "        if Custom_Script"
        # Write-Log "            - Script Path from Repo Root"
        # Write-Log "            - Custom Script Args (if any)"
        # Write-Log "    3 - PreRequisites (if any)"
        # Write-Log ""
        # Write-Log "Save these details, as you will need them shortly."
        # Write-Log ""

        # Pause
        Write-Log ""
        # Write-Log "Next we will see what applications are already available for us to put into InTune." 
        Write-Log "We can first see what apps are already available in the public and private JSON files." 
        Write-Log ""
        Write-Log "Choose an app from the selection or you can add your own!"
        Write-Log ""
        Write-Log "We will then make the InTune entry based off of the selected data in the JSON."
        Write-Log ""
        Write-Log "Would you like to select an existing application from the JSON files? (y/n)" "WARNING"
        $Answer = Read-Host "y/n"
        Write-Log ""

    }


    $TargetApp = $null
    if ($Answer -ne "n") {


        $DialogueSelection = "B"
        $TargetApp = Select-ApplicationFromJSON -DialogueSelection "$DialogueSelection"
        $DialogueSelection = "A" # reset for next use

        if ($TargetApp -eq $null) {

            $LoopIt = $true

            While ($LoopIt -eq $true) {

                Write-Log "No application selected from the JSON files. Do you want to try again? (y/n)" "WARNING"
                $Answer = Read-Host "y/n"
                Write-Log ""

                if ($Answer -eq "y"){

                    $TargetApp = Select-ApplicationFromJSON

                    if ($TargetApp -ne $null) {
                        $LoopIt = $false
                    }

                } else {
                    $LoopIt = $false
                }

            }

        }

        Write-Log "" 

        # If ($AppNameToFind -eq "" -or $AppNameToFind -eq $null) {
        #     Write-Log "Please enter the name of the application (as you want it to appear in the JSON) to set up for Intune deployment:" "WARNING"
        #     $AppNameToFind = Read-Host "Application Name"

        #     While ([string]::IsNullOrWhiteSpace($AppNameToFind) -or $AppNameToFind -eq "exit") {
        #         Write-Log "No application name provided. Please enter an application name." "ERROR"
        #         $AppNameToFind = Read-Host "Application Name"
        #     }
        # }


    }
    # Write-Log "If you see the app you want already there we will make the InTune entry based off of the data in the JSON." 
    # Write-Log ""
    # Write-Log "Otherwise if you do not see the app you want in the selection for the JSONs, you can exit the provided the selection to add it yourself."
    # Write-Log ""
    # Pause


    #     $TargetApp = Select-ApplicationFromJSON -AppNameToFind $AppNameToFind
    #     Write-Log ""

    #     #Write-Log "Application Name set to: $AppNameToFind"
    # } else {
    #     Write-Log "Using provided application name: $AppNameToFind"
    # }

    # Write-Log "" 


    if ($TargetApp -eq $null) {
        
        Write-Log "==========================================================================================="
        Write-Log "GUIDED SETUP FOR NEW APPLICATION ENTRY IN PRIVATE JSON"
        Write-Log "==========================================================================================="
        Write-Log ""

        
        # Write-Log "No pre-existing application entry for $AppNameToFind was selected from the JSON files. We will move forward with doing a new custom application entry in the private JSON."
        
        Write-Log "No pre-existing app selected."
        Write-Log ""
        Write-Log "We will now set up a new custom application entry in the private JSON."
        Write-Log ""
        Write-Log "Please enter the name of the application (as it will appear in the JSON):" "WARNING"
        $AppNameToFind = Read-Host "Application Name"

        While ([string]::IsNullOrWhiteSpace($AppNameToFind) -or $AppNameToFind -eq "exit") {
            Write-Log "No application name provided. Please enter an application name." "ERROR"
            $AppNameToFind = Read-Host "Application Name"
        }

        Write-Log "Application Name set to: $AppNameToFind"
        Write-Log ""

        # TODO: Add a function that searches WinGet for the app name and suggests the correct ID.

        Write-Log "Would you like assistance in finding the Winget ID for this application? (y/n)" "WARNING"
        $Answer = Read-Host "y/n"
        Write-Log ""
        
        if ($answer -eq "y"){

            Write-Log "Launching Winget search for application name: $AppNameToFind" "INFO2"
            Write-Log "" "INFO2"
            try{

                # NOTE: Write-Host used here to preserve formatting of winget output. It doesn't get logged tho.
                Write-Host ""
                Write-Host "================ Winget Search Results ===================="
                Write-Host ""
                winget search $AppNameToFind | Format-Table -AutoSize | Out-Host
                Write-Host ""
                Write-Host "==========================================================="
                Write-Host ""
                Write-Host "Winget search complete."
                Write-Host ""
                Write-Log "==========================================================================================="
                Write-Log "SELECT A WINGET ID FROM THE SEARCH RESULTS ABOVE"
                Write-Log "==========================================================================================="
                Write-Host ""
                Write-Log "1 - Review the above search results to find the appropriate Winget ID for your application."
                Write-Log ""
                Write-Log "2 - Test out the Winget ID locally first to ensure it installs the correct application before adding it to the JSON." #"WARNING"
                Write-Log "     - Example command to test locally: winget install <WingetID>"
                Write-Log ""
                Write-Log "3 - If you do not see a suitable match, you may need to research further to find the correct Winget ID or consider alternative installation methods."
                Write-Log ""
                Write-Log "Enter your selected Winget ID or leave blank to skip:" "WARNING"
                $SelectedWingetID = Read-Host "Winget ID"
                Write-Log ""
                # Write-Log "When you are ready we will update the private JSON with your new application/ID."


            } catch {
                Write-Log "An error occurred while attempting to search Winget. Please ensure Winget is installed and accessible from this script. Error: $_" "ERROR"
            }

            # Pause


        } else {

            Write-Log "Skipping Winget search assistance."

        }
        # Pause

        Write-Log ""
        Write-Log "==========================================================================================="
        Write-Log "NAVIGATE TO AZURE BLOB STORAGE"
        Write-Log "==========================================================================================="
        Write-Log ""

        Write-Log "Next we will navigate to our Azure Blob Storage container to edit the private JSON to add your new application."
        Write-Log ""
        Write-Log "Instructions for navigating to your Azure Blob Storage container as follows:"
        Write-Log ""
        Write-Log " 1 - Go to https://portal.azure.com/#view/Microsoft_Azure_StorageHub/StorageHub.MenuView/~/StorageAccountsBrowse"
        Write-Log ""
        Write-Log " 2 - Select this storage account: $StorageAccountName"
        Write-Log ""
        Write-Log " 3 - Select 'Data Storage' > 'Containers' from the left menu"
        Write-Log ""
        Write-Log " 4 - Select this container: $ApplicationData_JSON_ContainerName"
        Write-Log ""
        Pause
        Write-Log ""
        Write-Log "==========================================================================================="
        Write-Log "EDIT PRIVATE APPLICATION DATA JSON"
        Write-Log "==========================================================================================="

        Write-Log ""    
        Write-Log "Next we need to edit the private JSON file (ApplicationData.json) which contains the details of all custom applications available for deployment."
        Write-Log ""    
        Write-Log "From within the container, the path to the application JSON should be: $ApplicationDataJSONpath"
        Write-Log ""
        Write-Log "Click on the JSON and select to ""edit"""
        Write-Log ""

        Write-Log "REQUIRED RESOURCES:"

        Write-Log "    1 - Application Name"
        Write-Log "    2 - Install Method"
        Write-Log "        if Winget:"
        Write-Log "            - Winget ID ($SelectedWingetID)"
        Write-Log "        if MSI-Online"
        Write-Log "            - URL"
        Write-Log "            - MSI name"
        Write-Log "        if Custom_Script"
        Write-Log "            - Script Path from Repo Root"
        Write-Log "            - Custom Script Args (if any)"
        Write-Log "    3 - PreRequisites (if any)"
        Write-Log ""
        Write-Log "Here is an example of what the format of the JSON:"
        Write-Log ""
        Write-Host $ExampleAppJSON
        Write-Log ""
        Write-Log "Add your new application details to the JSON now, following the above format. Save when you are finished." "WARNING"
        Write-Log ""
        Write-Log "When you are ready we will check if you updated either JSON with the new application..."
        Write-Log ""
        Pause
        Write-Log "" "INFO2"

        $TargetApp = Select-ApplicationFromJSON -AppNameToFind $AppNameToFind

        if ($TargetApp -eq $null){

            Write-Log "The application '$AppNameToFind' was still not found in either JSON. Please ensure you have added it correctly and re-run this setup process." "ERROR"
            Exit 1

        } else {
            Write-Log "The application '$AppNameToFind' was successfully found in the JSON after your update!" "SUCCESS"
        }

        Write-Log ""

        # Suggest testing the JSON with the local install script
        Write-Log "After updating the Application Data JSON, it is highly recommended to test the installation of the new application on a local machine before proceeding with Intune deployment."
        Write-Log ""
        Write-Log "This will help ensure that all details are correct and the installation process works as expected."
        Write-Log ""

        #Pause


    }

    Write-Log "Application confirmed: $ApplicationName"
    Write-Log ""



    Write-Log "Would you like to test by having this script install the app based on the JSON configuration? (y/n)" "WARNING"
    $Answer = Read-Host "y/n"
    Write-Log ""


        if ($answer -eq "y"){

            Write-Log "Before proceeding, please make sure this application is not already installed locally on this machine. If it is, please uninstall it first." "WARNING"
            Pause
            Write-Log "Proceeding with local installation test for $AppNameToFind..."

            & Install--Local-Application -ApplicationName $AppNameToFind

            if($LASTEXITCODE -ne 0){
                Write-Log "Local application installation test failed with exit code: $LASTEXITCODE" "ERROR"
                Write-Log "Please resolve any issues before proceeding with Intune deployment."
                Exit $LASTEXITCODE
            } else {
                Write-Log "Local application installation test succeeded! This configuration for the JSON works!" "SUCCESS"
            }   

        } else {

            Write-Log "Skipping local installation test. Proceeding with Intune deployment setup."

        }

    Write-Log "==========================================================================================="
    Write-Log "AUTOMATIC CREATION OF:"
    Write-Log " - INTUNE WIN32 APP PACKAGE"
    Write-Log " - INSTALL/UNINSTALL COMMANDS/SCRIPTS"
    Write-Log "==========================================================================================="

    Write-Log ""
    Write-Log "Next we will automatically create the Win32 package for deploying the app from InTune."
    Write-Log ""

    # Pause

    Make-InTuneWin -SourceFile "$GitRunnerScript" 
    $ApplicationIntuneWinPath = $Global:intunewinpath
    Write-Log ""    
    Write-Log "The Intune Win32 app package has been created at: $ApplicationIntuneWinPath"
    Write-Log ""    

    Write-Log "Next we will automatically create the install/uninstall commands/scripts."

    Write-Log ""    
    Pause
    Write-Log ""   



    # If sufficient info is present from the JSON, we can generate the install command and detection script. Otherwise user needs to enter it manually and update their JSON.

    # Needed info:
            # - Install Method
                # if Winget:
                    # - Winget ID
                # if MSI-Online
                    # - URL
                    # - MSI name
                # if Custom_Script
                    # - Script Path from Repo Root
                    # - Custom Script Args (if any)
            # - PreRequisites (if any)


    While ($InstallMethod -eq $null -or ($InstallMethod -eq "")) {

        Write-Log "The application '$ApplicationName' does not have sufficient information for the InstallMethod var in the JSON to auto-generate install command and detection script." "WARNING"
        Write-Log "Please update your JSON and then continue this script." "WARNING"
        Pause   
        Select-ApplicationFromJSON -AppNameToFind $AppNameToFind

    }

    if ($InstallMethod -eq "WinGet" -or $DetectMethod -eq "WinGet") {

        if($WinGetID -eq $null -or $WinGetID -eq ""){
            Write-Log "The application '$ApplicationName' does not have a WinGet ID specified in the JSON. Please update your JSON with the required fields and re-run this setup process for automatic generation." "ERROR"
            Exit 1
        }

        [hashtable]$FunctionParams = @{
            ApplicationName = $ApplicationName
            AppID = $WinGetID
            DetectMethod = "WinGet"
        }

        Write-log "Detect method set as WinGet" "INFO2"

    } elseif ($InstallMethod -eq "MSI-Private-AzureBlob" -or $DetectMethod -eq "MSI_Registry") {

        if ($DisplayName -eq $null -or $DisplayName -eq "") {
            Write-Log "The application '$ApplicationName' does not have a Display Name specified in the JSON. Please update your JSON with the required fields and re-run this setup process for automatic generation." "ERROR"
            Exit 1
        }

        [hashtable]$FunctionParams = @{
            ApplicationName = $ApplicationName
            DisplayName = $DisplayName
            DetectMethod = "MSI_Registry"
        }

        Write-Log "Detect method set as MSI_Registry" "INFO2"

    } else {

        Write-Log "Unknown Install Method or missing Detect Method. Please correct this in the JSON and re-run this setup process." "ERROR"
        Write-Log "Install Method: $InstallMethod" 
        Write-Log "Detect Method: $DetectMethod" 

        Exit 1

    }




    Write-Log "" "INFO2"
    Write-Log "Generating install command..." "INFO2"
    Write-Log "" "INFO2"

    <#
    # Run the automation script to generate the install command and detection script
    $ReturnHash2 = & $GenerateInstallCommand_ScriptPath -DesiredFunction "InstallAppWithJSON" -FunctionParams $FunctionParams
    #$ReturnHash2 = & $GenerateInstallCommand_ScriptPath -DesiredFunction "InstallPrinterByIP" -FunctionParams $FunctionParams

    # Check the returned hashtable
    if(($ReturnHash2 -eq $null) -or ($ReturnHash2.Count -eq 0)){
        Write-Log "No data returned!" "ERROR"
        Exit 1
    }
    
    Write-Log "Values retrieved:" "INFO2"

    #$ReturnHash2
    foreach ($key in $ReturnHash2.Keys) {
        $value = $ReturnHash2[$key]
        Write-Log "   $key : $value" "INFO2"
    }    

    # Turn the returned hashtable into variables
    Write-Log "Setting values as local variables..." "INFO2"
    foreach ($key in $ReturnHash2.Keys) {

        $value = $ReturnHash2[$key]
        Write-Log "   $key : $value" "INFO2"


        Set-Variable -Name $key -Value $value -Scope Local

        # Write-Log "Should be: $key = $($ReturnHash[$key])"
        $targetValue = Get-Variable -Name $key -Scope Local
        Write-Log "Ended up as: $key = $($targetValue.Value)" "INFO2"

    }
    #>

    # Call the generator; this now returns the hashtable we want
    $installResult = @{}
    $installResult = & $GenerateInstallCommand_ScriptPath `
        -DesiredFunction "InstallAppWithJSON" `
        -RepoURL $RepoURL `
        -RepoNickName $Global:TargetRepoNickName `
        -RepoBranch $Global:RepoBranch `
        -TargetWorkingDirectory $Global:TargetWorkingDirectory `
        -FunctionParams $FunctionParams

    # Sanity check
    if (($installResult -eq $null) -or ($installResult.Count -eq 0)) {
        Write-Log "No data returned from Generate_Install-Command.ps1!" "ERROR"
        exit 1
    }

    Write-Log "Values retrieved:" "INFO2"
    foreach ($key in $installResult.Keys) {
        Write-Log "   $key : $($installResult[$key])" "INFO2"
    }

    Write-Log "Setting values as local variables..." "INFO2"
    foreach ($key in $installResult.Keys) {
        $value = $installResult[$key]
        Write-Log "   $key : $value" "INFO2"

        Set-Variable -Name $key -Value $value -Scope Local

        $targetValue = Get-Variable -Name $key -Scope Local
        Write-Log "Ended up as: $key = $($targetValue.Value)" "INFO2"
    }


    ##  Create uninstall command ##
    Write-Log "" "INFO2"
    Write-Log "Generating uninstall command..." "INFO2"
    Write-Log "" "INFO2"

    ## Prereqs

        # Declare these variables if they do not yet exist to avoid errors
        if(!($Version)){ $Version = $null }
        if(!($WinGetID)){ $WinGetID = $null }
        if(!($DisplayName)){ $DisplayName = $null }

        # If InstallMethod is WinGet and UninstallType is not set, set UninstallType to WinGet by default
        if($InstallMethod -eq "WinGet" -and ($UninstallType -eq "" -or $UninstallType -eq $null)){
            $UninstallType = "WinGet"
        }

        # Exit out if UninstallType is still not set
        # TODO: Swap out for a loop that asks the user to input the uninstall type instead of exiting?
        If ($UninstallType -eq "" -or $UninstallType -eq $null) {

            Write-Log "The application '$ApplicationName' does not have sufficient information for the UninstallType var in the JSON to auto-generate uninstall command." "WARNING"
            Write-Log "Please update your JSON with uninstall data and then run this script again" "WARNING"
            
            Exit 1

        }

    [hashtable]$FunctionParams = @{
        ApplicationName = $ApplicationName
        UninstallType = $UninstallType
        Version = $Version
        WinGetID = $WinGetID
        UninstallString_DisplayName = $DisplayName
    }

    $FunctionParams

    $ReturnHash3 = @{}
    $ReturnHash3 = & $GenerateInstallCommand_ScriptPath `
        -DesiredFunction "UninstallApp" `
        -RepoURL $RepoURL `
        -RepoNickName $Global:TargetRepoNickName `
        -RepoBranch $Global:RepoBranch `
        -TargetWorkingDirectory $Global:TargetWorkingDirectory `
        -FunctionParams $FunctionParams

    # Check the returned hashtable
    if(($ReturnHash3 -eq $null) -or ($ReturnHash3.Count -eq 0)){
        Write-Log "No data returned!" "ERROR"
        Exit 1
    }

    Write-Log "Values retrieved:" "INFO2"

    foreach ($key in $ReturnHash3.Keys) {

        $value = $ReturnHash3[$key]
        Write-Log "   $key : $value" "INFO2"

    }    

    Write-Log "Setting values as local variables..." "INFO2"
    foreach ($key in $ReturnHash3.Keys) {
        Set-Variable -Name $key -Value $ReturnHash3[$key] -Scope Local
        # Write-Log "Should be: $key = $($ReturnHash[$key])"
        $targetValue = Get-Variable -Name $key -Scope Local
        Write-Log "Ended up as: $key = $($targetValue.Value)" "INFO2"


    }
    

    Write-Log ""
    Write-Log "Install/Uninstall command and detection script created!"
    Write-Log ""
    Write-Log "Next, we will manually create a Win32 app in InTune using the new .intunewin file, command, and script."
    Write-Log ""

    # Pause

    Clear
    Write-Log "==========================================================================================="
    Write-Log "UPLOAD AND CREATE INTUNE WIN32 APPLICATION"
    Write-Log "==========================================================================================="
    Write-Log ""
    Write-Log "All prep complete!"
    Write-Log ""
    Write-Log "Next we will manually create a Win32 application in InTune for this app using the new intunewin file, script, and install command."
    Write-Log ""

    if ($Global:DeployMode -eq "Production"){

            $PotentialAppInTuneName = "APP: $ApplicationName"

    } else {
            $PotentialAppInTuneName = "APP: $ApplicationName [$Global:DeployMode]"
    }

    Write-Log ""
    Write-Log "InTune Win32 Application creation instructions:" "WARNING"
    Write-Log ""           
    Write-Log ""    
    Write-Log " 1 - Navigate to Microsoft Endpoint Manager admin center > Devices > Windows > Windows apps"
    Write-Log "     - Direct url: https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/AppsWindowsMenu/~/windowsApps"
    Write-Log "     - + Create > App type: Windows app (Win32)"
    Write-Log ""
    Pause   
    Write-Log ""
    Write-Log " 2 - Upload the .intunewin file located here: $ApplicationIntuneWinPath"
    Write-Log ""
    Pause   
    Write-Log "" 
    Write-Log " 3 - APP INFORMATION:"
    write-log "     - Name: follow your org naming conventions"
    Write-Log "         - What I recommend: ""$PotentialAppInTuneName"""

    Write-Log "     - Description: Up to your descretion. Copying the description from Windows Store, App website, etc could be beneficial.,"
    Write-Log "     - Publisher: Look up the publisher if you are not sure. You can check the Windows Store, app website, etc."
    Write-Log "     - Version: Recommend to leave blank unless you are using a static MSI installer with a set version.."
    Write-Log "     - Logo: Optional - You could create something with Canva using your organization logo, but standardize it"
    Write-Log "     - Everything else on this page is up to your discretion."
    Write-Log ""
    Pause   
    Write-Log "" 
    Write-Log " 4 - PROGRAM:"
    Write-Log "     - Install command:"
    Write-Log "         - Use the install command found inside this file: $MainInstallCommandTXT"
    Write-Log "     - Uninstall command:"
    Write-Log "         - Use the install command found inside this file: $UninstallCommandTXT"
    Write-Log "     - Install time: 15 minutes"
    Write-Log "     - Allow available uninstall: No"
    Write-Log "     - Install behavior: System"
    Write-Log "     - Device restart behavior: No specific action"
    Write-Log ""
    Pause   
    Write-Log ""  
    Write-Log " 5 - REQUIREMENTS:"
    Write-Log "     - Architecture: Unnecessary unless you know the app is specific to x86 or x64. WinGet apps will handle this automatically."
    Write-Log "     - Minimum operating system: Minimum available version unless you know otherwise."
    Write-Log ""
    Pause   
    Write-Log ""
    Write-Log " 6 - DETECTION:"
    Write-Log "     - Rules format: Use a custom detection script"
    Write-Log "     - Script File: Upload this script: $DetectAppScript"
    Write-Log "     - Run script as 32-bit process on 64-bit clients: No"
    Write-Log "     - Enforce script signature check: No"
    Write-Log ""
    Pause   
    Write-Log ""
    Write-Log " 7 - DEPENDENCIES: None"
    Write-Log ""
    Pause   
    Write-Log ""
    Write-Log " 8 - SUPERSEDENCE: None"
    Write-Log ""
    Pause   
    Write-Log ""
    Write-Log " 9 - ASSIGNMENTS: Assign to the required groups/devices for your organization."
    Write-Log ""
    Pause
    Write-Log ""
    Write-Log "Application deployment setup is complete! Please verify functionality on a test device. The application will both be available from the Company Portal for the assigned devices AND from the local Application Installer function in this script." "SUCCESS"
    Write-Log ""    
    Pause


}

Function Make-InTuneWin {

    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceFile,   # Path to your installer/script (exe, msi, ps1, etc.)

        [string]$IntuneToolsDir = "$WorkingDirectory\Temp\Tools",
        [string]$TempRoot       = "$WorkingDirectory\Temp\IntuneWin_Source\$(Get-Date -Format 'yyyyMMdd_HHmmss')",
        [string]$OutputFolder   = "$WorkingDirectory\Temp\IntuneWin_Output\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )

    $ErrorActionPreference = 'Stop'

    # Ensure the existence of the Intune Win32 Content Prep Tool

        # Where we'll store IntuneWinAppUtil.exe
        $IntuneWinAppUtil = Join-Path $IntuneToolsDir "IntuneWinAppUtil.exe"

        # URL for the Intune Win32 Content Prep Tool (from Microsoft download center)
        $IntuneWinAppUtilUrl = "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe"

        # Ensure tools directory exists
        if (-not (Test-Path $IntuneToolsDir)) {
            New-Item -Path $IntuneToolsDir -ItemType Directory -Force | Out-Null
        }

        # Download IntuneWinAppUtil.exe if missing
        if (-not (Test-Path $IntuneWinAppUtil)) {
            Write-Log "Downloading IntuneWinAppUtil.exe..." "INFO2"
            Invoke-WebRequest -Uri $IntuneWinAppUtilUrl -OutFile $IntuneWinAppUtil
            Write-Log "Downloaded IntuneWinAppUtil.exe to $IntuneWinAppUtil" "INFO2"
        }

        # Resolve and split the source file
        $sourceFileFull = (Resolve-Path $SourceFile).Path
        $sourceFileName = Split-Path $sourceFileFull -Leaf
        $packageName    = [IO.Path]::GetFileNameWithoutExtension($sourceFileName)

        # Create unique temp source dir
        $timeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $workingDir = Join-Path $TempRoot "${packageName}_$timeStamp"

        New-Item -Path $workingDir -ItemType Directory -Force | Out-Null
        New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null

        # Copy target file into temp dir
        Copy-Item -Path $sourceFileFull -Destination $workingDir -Force
        #Write-Log "Source copied to: $workingDir"

        # Run Intune Win32 Content Prep Tool
        & $IntuneWinAppUtil `
            -c $workingDir `
            -s $sourceFileName `
            -o $OutputFolder `
            -q | Out-Null

        # Show the resulting .intunewin file
        # $intuneWin = Get-ChildItem -Path $OutputFolder -Filter '*.intunewin' -Recurse |
        #             Sort-Object LastWriteTime -Descending |
        #             Select-Object -First 1
        
        $intunewin = Get-ChildItem -path $outputfolder | Where-Object { $_.Extension -eq ".intunewin" }
        #$intunewin = Get-ChildItem -path $outputfolder | Where-Object { $_ -like "*.intunewin" }

        $Global:intunewin = $intunewin.name
        $Global:intunewinpath = "$outputfolder\$intunewin"
        # "intunewin file name: "

        # $intunewin


        if ($intuneWin) {
            #Write-Log "Created Intune package: $intuneWin"
            #return $intuneWin.FullName
        } else {
            Write-Log "No .intunewin file found in $OutputFolder." "ERROR"
            Throw "Intune package creation failed."
        }



    #Return $intuneWin

}

# DONE AND TESTED 1/14/26
Function Install--Local-Printer{
    Param(

        $PrinterName=$null

    )

    Write-Log "To begin we will access the PrinterData.json file stored in Azure Blob Storage to show you the available printers."
    Write-Log ""

    $PrinterName = Select-PrinterFromJSON -PrinterName $PrinterName -DialogueSelection "A"

    # Pause

    # Call the Install-Printer-IP script with the obtained values
    Write-Log "" "INFO2"
    Write-Log "Next we will attempt to install the selected printer ($GLobal:PrinterName) using the install script."
    Write-Log ""
    # Pause

    & $InstallPrinterIP_ScriptPath -PrinterName $Global:PrinterName -WorkingDirectory $WorkingDirectory
    
    
    Write-Log "" 
    if($LASTEXITCODE -ne 0){
        Write-Log "Install-Printer-IP script failed with exit code: $LASTEXITCODE" "ERROR"
        Exit $LASTEXITCODE
    } else {
        Write-Log "Printer '$Global:PrinterName' installed successfully!" "SUCCESS"
    }   

}   

# DONE AND TESTED 1/14/26
Function Uninstall--Local-Printer{

    # Write-Log "Uninstalling a local printer function is still being developed." "ERROR"
    # Exit 1

    # List the installed printers
    $PrinterList = Get-Printer | Select-Object -ExpandProperty Name
    $Counter = 1
    $HashTable = @{}

    Write-Log "Here are the installed printers on this machine:"
    Write-Log ""

    foreach ($printer in $PrinterList) {

            Write-Log "$Counter - $printer"

            $HashTable.Add($Counter,$printer)

            $Counter++

    }
    Write-Log ""
    $Exit = "n"
    While ($Exit -ne "y") {

            
        Write-Log "Please enter the number of the printer you wish to uninstall from the above list:" "WARNING"

        [int]$PrinterNumToFind = Read-Host "Please enter a number between 1 and $($COUNTER - 1)"


        While ( [int]$PrinterNumToFind -lt 1 -or [int]$PrinterNumToFind -ge $COUNTER ) {

                    Write-Log "Invalid choice. Please select a valid number from the list above." "WARNING"
                    $PrinterNumToFind = Read-Host "Please enter a number between 1 and $($COUNTER - 1)"
        }

        # $PrinterName = $HashTable[$PrinterNumToFind]

        [string]$PrinterNameToFind = $HashTable[[int]$PrinterNumToFind]

        $PrinterName = $PrinterNameToFind
        Write-Log ""
        Write-Log "You have selected to uninstall the printer: $PrinterName"
        Write-Log ""
        Write-Log "Is this acceptable?" "WARNING"
        $Exit = Read-Host "y/n"
        Write-Log ""

    }


    # Select a printer to uninstall
    # Write-Log "Please enter the name of the printer you wish to uninstall from the above list:" "WARNING"
    # $PrinterName = Read-Host "Printer Name"
    # While ([string]::IsNullOrWhiteSpace($PrinterName)) {
    #     Write-Log "No printer name provided. Please enter a printer name from the list above:" "ERROR"
    #     $PrinterName = Read-Host "Printer Name"
    # }

    # Call the uninstall script with the selected printer
    Try{
        & $UninstallPrinter_ScriptPath -PrinterName $PrinterName -WorkingDirectory $WorkingDirectory
    } catch {
        Write-Log "An error occurred while attempting to uninstall the printer: $_" "ERROR"
        Exit 1
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Log "Uninstall-Printer script failed with exit code: $LASTEXITCODE" "ERROR"
        Exit $LASTEXITCODE
    } else {
        Write-Log "Printer '$PrinterName' uninstalled successfully!" "SUCCESS"
    }

    Pause
}

# DONE AND TESTED 1/14/26
Function Uninstall--Local-Application{

    # UNFINISHED
    Function JSON-zz-search-and-uninstall{

        Write-Log "To begin we will access the ApplicationData.json files, both public (local repo) and private (Azure Blob) to show you the available documented applications."
        Write-Log ""

        $TargetApp = Select-ApplicationFromJSON -DialogueSelection "C"

        if ($TargetApp -eq $null) {
            Write-Log "No application selected. Exiting." "ERROR"
            Exit 1
        } else {
            Write-Log "Valid application selected for uninstallation: $TargetApp"
        }

        # Determine if sufficient info is present from the JSON to generate uninstall command
        if ($UninstallType -eq "" -or $UninstallType -eq $null) {

            if ($installMethod -eq "WinGet") {

                $UninstallType = "WinGet"

            } else {

                Write-Log "The application '$TargetApp' does not have sufficient information for the UninstallType var in the JSON to auto-generate uninstall command." "WARNING"
                Write-Log "Please update your JSON with uninstall data and then run this script again" "WARNING"
                
                Exit 1
            }

        }

        # Format optional params to avoid issues with empty strings
        if ($Version -eq "" -or $Version -eq $null) {
            $Version = $null
        }

        if ($WinGetID -eq "" -or $WinGetID -eq $null) {
            $WinGetID = $null
        }

        if ($DisplayName -eq "" -or $DisplayName -eq $null) {
            $DisplayName = $null
        }
    
        & $UninstallApp_ScriptPath -AppName $TargetApp -UninstallType $UninstallType -WorkingDirectory $WorkingDirectory -Version $Version -WinGetID $WinGetID -UninstallString_DisplayName $DisplayName

        if ($LASTEXITCODE -ne 0) {
            Write-Log "Uninstall app script failed with exit code: $LASTEXITCODE" "ERROR"
            Exit 1
        } else {
            Write-Log "Application '$TargetApp' uninstalled successfully!" "SUCCESS"
            Exit 0
        }

    }

    # UNFINISHED
    Function Winget-zz-search-and-uninstall{

        # Install winget if not present

        $WinGet = & $InstallWinGet_ScriptPath
        
        # Winget Search

        $outFile = Join-Path $env:TEMP 'winget-export.json'

        & $winget export -o $outFile --include-versions *> $null

        $data = Get-Content $outFile -Raw | ConvertFrom-Json

        $result =$data.Sources | `
        ForEach-Object { $_.Packages } | `
        Select-Object PackageIdentifier, Version | `
        Sort-Object PackageIdentifier | `
        Format-Table -AutoSize

        $Result = $result | Out-String
        Write-Log "Local applications found with winget:"
        # ForEach ($line in $Result) {

        #     Write-Log $line

        # }

        $Counter = 1
        $HashTable = @{}

        ForEach ($app in $Result) {
            
            Write-Log "$Counter - $($result.PackageIdentifier.packages.packageidentifier)"

            $HashTable.Add($Counter, $($result.PackageIdentifier.packages.packageidentifier))

            $Counter++

        }

        # Ask for user input of EXACT winget ID

        # $WingetID = Read-Host "Enter the exact Winget Package Identifier of the application you wish to uninstall:"

        # # Search again to confirm presence with exact ID

        # if ( -not ($data.Sources.Packages | Where-Object { $_.PackageIdentifier -eq $WingetID }) ) {

        #     Write-Log "The specified Winget Package Identifier '$WingetID' was not found among the installed applications." "ERROR"
        #     Exit 1

        # } else {

        #     Write-Log "The specified Winget Package Identifier '$WingetID' was confirmed to be valid. Proceeding with uninstallation."

        # }



        $Exit = "n"

        While ($Exit -ne "y") {

            Write-Log ""
            $TargetAppNum = Read-Host "Please enter the # of the application you wish to uninstall from the above list:"

            While ($TargetAppNum -lt 1 -or $TargetAppNum -ge $COUNTER) {

                Write-Log "Invalid choice. Please select a valid number from the list above." "WARNING"
                $TargetAppNum = Read-Host "Enter the number of the app you wish to uninstall"

            }

            $TargetApp = $HashTable[[int]$TargetAppNum]

            Write-log "You selected to uninstall app: $TargetApp using method: CIM Win32_Product"
            Read-Host "Is this acceptable? (y/n)"
            if ($exit -eq "y") { break }
            

        }


        # Uninstall with winget uninstall

        & $UninstallApp_ScriptPath -AppName $TargetApp -UninstallType "WinGet" -WorkingDirectory $WorkingDirectory -WinGetID $TargetApp


        if ($LASTEXITCODE -ne 0) {
            Write-Log "Uninstall app script failed with exit code: $LASTEXITCODE" "ERROR"
            Exit 1
        } else {
            Write-Log "Application '$WingetID' uninstalled successfully!" "SUCCESS"
            Exit 0  
        }

    }

    # TESTED AND WORKING!
    Function CIM--search-and-uninstall{

        $Result = Get-CimInstance -ClassName Win32_Product | Select-Object Name

        Write-Log ""
        Write-Log "Local applications found via CIM Win32_Product:"
        Write-Log ""

        $HashTable = @{}
        $Counter = 1
        ForEach ($app in $Result) {
            #Write-Log "$($app.Name)"
            Write-Log "$Counter - $($App.name)"

            $HashTable.Add($Counter, $($App.name))

            $Counter++
        }

        $Exit = "n"

        While ($Exit -ne "y") {

            Write-Log ""
            Write-Log "Please enter the # of the application you wish to uninstall from the above list:" "WARNING"
            $numTodisplay = $COUNTER - 1
            [int]$TargetAppNum = Read-Host "Please enter a # between 1 and $numTodisplay "

            While ($TargetAppNum -lt 1 -or $TargetAppNum -ge $COUNTER) {

                Write-Log "Invalid choice. Please select a valid number from the list above." "WARNING"
                [int]$TargetAppNum = Read-Host "Please enter a # between 1 and $numTodisplay "

            }

            $TargetApp = $HashTable.$TargetAppNum

            Write-Log "You selected to uninstall app: $TargetApp using method: CIM Win32_Product | Is this acceptable?" "WARNING"
            $exit = Read-Host "(y/n)" 

            if ($exit -eq "y") { break }
            
        }


        
        Write-Log ""
        Write-Log "You selected to uninstall app: $TargetApp using method: $UninstallMethod"
        Write-Log ""



        Write-Log "Final selected app to uninstall: $TargetApp"

        & $UninstallApp_ScriptPath -AppName $TargetApp -UninstallType "Remove-App-CIM" -WorkingDirectory $WorkingDirectory

        if ($LASTEXITCODE -ne 0) {
            Write-Log "Uninstall app script failed with exit code: $LASTEXITCODE" "ERROR"
            Exit 1
        } else {
            Write-Log "Application '$TargetApp' uninstalled successfully!" "SUCCESS"
            Exit 0  
        }

    }

    # TESTED AND WORKING!
    Function Registry--search-and-uninstall{

        $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )

        $Result0 = Get-ItemProperty $paths |`
        Where-Object DisplayName |`
        Select-Object DisplayName, DisplayVersion, PSChildName |`
        Sort-Object DisplayName



        Write-Log "Please select an app to uninstall based on the above list:"
        Write-Log ""
        $Counter = 1
        $HashTable = @{}

        ForEach ($app in $Result0) {
            
            Write-Log "$Counter - $($app.DisplayName)"

            $HashTable.Add($Counter, $app.DisplayName)

            $Counter++

        }


        # Write-Log ""
        # [int]$Selection = Read-Host "Enter the # of the app you wish to uninstall"

        # $HashTable

        # While ($Selection -lt 1 -or $Selection -ge $COUNTER) {

        # #$HashTable.$Selection

        #     Write-Log "Invalid choice. Please select a valid number from the list above." "WARNING"
        #     $Selection = Read-Host "Enter the number of the app you wish to uninstall"

        # }




        $Exit = "n"

        

        While ($Exit -ne "y") {

            [int]$TargetAppNum = 0
            Write-Log ""
            [int]$TargetAppNum = Read-Host "Please enter the # of the application you wish to uninstall from the above list"

            While ($TargetAppNum -lt 1 -or $TargetAppNum -ge $COUNTER) {

                Write-Log "Invalid choice. Please select a valid number from the list above." "WARNING"
                [int]$TargetAppNum = Read-Host "Enter the number of the app you wish to uninstall"

            }

            $TargetApp = $HashTable[[int]$TargetAppNum]

            Write-log "You selected to uninstall app: $TargetApp. We will attempt to hit it with every uninstall method available." "WARNING"
            $exit =Read-Host "Is this acceptable? (y/n)"
            if ($exit -eq "y") { break }
            

        }




        Write-Log ""
        Write-log "You selected to uninstall app: $TargetApp. "

        # NOTE/TODO: there is a flaw here; sometimes there are duplicate DisplayNames. In the future we may want to list the found apps with indexes or other identifiers and have the user select one.
        <#

            Example of duplicates from my test machine:

            DisplayName                                                     DisplayVersion   PSChildName                           
            -----------                                                     --------------   -----------                           
            Flameshot                                                       13.3.0           {8FA03992-037E-4A23-B8A8-AF2768116FBC}
            Git                                                             2.51.2           Git_is1                               
            Google Chrome                                                   143.0.7499.41    {AFEF3E4D-0F28-305F-94EA-B5F732F974C2}
            Microsoft .NET Host - 8.0.15 (arm64)                            64.60.31149      {45BFB9A6-1426-467E-9F8E-93D5E9E63883}
            Microsoft .NET Host FX Resolver - 8.0.15 (arm64)                64.60.31149      {1658430D-653D-43AF-8FD2-5C283EEDF162}
            Microsoft .NET Runtime - 8.0.15 (arm64)                         64.60.31149      {77ACC55A-6671-48E3-9A3D-21E79B6627EF}
            Microsoft 365 Apps for enterprise - en-us                       16.0.19328.20266 O365ProPlusRetail - en-us             
            Microsoft Edge                                                  143.0.3650.96    Microsoft Edge                        
            Microsoft Edge WebView2 Runtime                                 143.0.3650.96    Microsoft EdgeWebView                 
            Microsoft Visual C++ 2022 Arm64 Runtime - 14.44.35211           14.44.35211      {88A3EF6C-D7E4-4707-B3F5-E530B3AD6081}
            Microsoft Visual C++ 2022 Redistributable (Arm64) - 14.44.35211 14.44.35211.0    {a87e42cd-475d-4f15-8848-e0d60c63c02f}
            Microsoft Windows Desktop Runtime - 8.0.15 (arm64)              8.0.15.34718     {754291a4-39ad-4334-b288-97b2515eca65}
            Microsoft Windows Desktop Runtime - 8.0.15 (arm64)              64.60.31203      {CD4994D0-62B1-46E9-BC33-61FAD70FFA57}
            Office 16 Click-to-Run Extensibility Component                  16.0.19328.20106 {90160000-008C-0000-1000-0000000FF1CE}
            Office 16 Click-to-Run Licensing Component                      16.0.19029.20244 {90160000-007E-0000-1000-0000000FF1CE}
            OpenSSL 3.5.1 for ARM (64-bit)                                  3.5.1            {44B11A22-49CB-4C70-9350-DAA6181BC86A}
            Parallels Tools                                                 26.1.2.57293     {4254F5B9-8150-4F44-AD56-A356893E9C80}
        
        #>

        & $UninstallApp_ScriptPath -AppName $TargetApp -UninstallType "All" -WorkingDirectory $WorkingDirectory -UninstallString_DisplayName $DisplayName
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Uninstall app script failed with exit code: $LASTEXITCODE" "ERROR"
            Exit 1
        } else {
            Write-Log "Application '$TargetApp' uninstalled successfully!" "SUCCESS"
            Exit 0  
        }

    }

    # UNFINISHED
    Function Adobe-zz-search-and-uninstall{

        Write-Log "Adobe application uninstallation is not yet implemented." "ERROR"
        Exit 1

    }

    # TESTED AND WORKING!
    Function AppPackage--search-and-uninstall{

        $Result1 = Get-AppxPackage -AllUsers | Select-Object Name, PackageFullName
        # $Result2 = Get-AppPackage -AllUsers | Select-Object Name, PackageFullName
        $Result3 = Get-AppxProvisionedPackage -Online | Select-Object DisplayName, PackageName
        # $Result4 = Get-AppProvisionedPackage -Online | Select-Object PackageName, PackageFullName

        Write-Log ""
        Write-Log "AppxPackage: Local App Packages found via Get-AppxPackage (all users):"
        Write-Log ""

        ForEach ($app in $Result1) {
            Write-Log "Name: $($app.Name) | PackageFullName: $($app.PackageFullName)" "INFO2"
        }

        # Write-Log ""
        # Write-Log "AppPackage: Local App Packages found via Get-AppPackage (all users):"
        # Write-Log ""

        # ForEach ($app in $Result2) {
        #     Write-Log "Name: $($app.Name) | PackageFullName: $($app.PackageFullName)" "INFO2"
        # }
        

        Write-Log ""
        Write-Log "AppxProvisionedPackage: Local App Packages found via Get-AppxProvisionedPackage (online):"
        Write-Log ""

        ForEach ($app in $Result3) {
            Write-Log "DisplayName: $($app.DisplayName) | PackageName: $($app.PackageName)" "INFO2"
        }
        

        # Write-Log ""
        # Write-Log "AppProvisionedPackage: Local App Packages found via Get-AppProvisionedPackage (online):"
        # Write-Log ""

        # ForEach ($app in $Result4) {
        #     Write-Log "PackageName: $($app.PackageName) | PackageFullName: $($app.PackageFullName)" "INFO2"
        # }
        

        Write-Log ""
        Clear
        Write-Log "Available AppPackage uninstall methods:"

        Write-Log " 1 - AppxPackage - Apps CURRENTLY INSTALLED on this machine (regardless of user)"

        Write-Log " 2 - AppxProvisionedPackage - Apps that WILL BE INSTALLED for new users"


        Write-Log ""

        Write-Log "Enter the uninstall method number of your choice:" "WARNING"

        $Method = Read-Host "Enter a #"

        Write-Log ""

        While( $Method -lt 1 -or $Method -gt 2){

            Write-Log "Invalid choice. Please select a valid method." "WARNING"
            $Method = Read-Host "Enter the uninstall method number of your choice from the options above"

        }
        Write-Log ""

        Write-Log "Please select an app to uninstall based on this list:" 
        Write-Log ""



        if( $Method -eq 1){

            Write-Log "AppxPackage has been selected."
            $UninstallMethod = "Remove-AppxPackage"
            Write-Log ""
            Write-Log "Here are the available AppxPackages to uninstall:"
            Write-Log ""

            $Counter = 1
            $HashTable = @{}
            ForEach ($app in $Result1) {
                
                #Write-host "$Counter | $($app.DisplayName)"

                Write-Log "$Counter - $($app.Name)"

                $HashTable.Add($Counter, $app.Name)

                $Counter++
            }

        } elseif( $Method -eq 2 ){

            Write-Log "AppxProvisionedPackage has been selected."
            $UninstallMethod = "Remove-AppxPackage"
            Write-Log ""
            Write-Log "Here are the available AppxProvisionedPackages to uninstall:"
            Write-Log ""

            $Counter = 1
            $HashTable = @{}
            ForEach ($app in $Result3) {
                
                #Write-host "$Counter | $($app.DisplayName)"

                Write-Log "$Counter - $($app.DisplayName)"

                $HashTable.Add($Counter, $app.DisplayName)

                $Counter++

            }

        }

        
        # if( $Method -eq 1){

        #     $UninstallMethod = "Remove-AppxPackage"

        #     $Result0 = $Result1

        # } elseif( $Method -eq 2 ){

        #     $UninstallMethod = "Remove-AppPackage"

        #     $Result0 = $Result2

        # } elseif( $Method -eq 3 ){

        #     $UninstallMethod = "Remove-AppxPackage"

        #     $Result0 = $Result3

        # } elseif( $Method -eq 4 ){

        #     $UninstallMethod = "Remove-AppPackage"

        #     $Result0 = $Result4

        # }


        # $Counter = 1
        # $HashTable = @{}
        # ForEach ($app in $Result0) {
            
        #     #Write-host "$Counter | $($app.DisplayName)"

        #     Write-Log "$Counter - $($app.Name)"

        #     $HashTable.Add($Counter, $app.Name)

        #     $Counter++
        # }

        # $HashTable = $HashTable.GetEnumerator() | Sort-Object -Property:Name

        # ForEach ($item in $HashTable) {

        #     Write-Log "$($item.Name) | $($item.Value)"

        # }




        # Write-Log ""
        # $Selection = Read-Host "Enter the number of the app you wish to uninstall"

        # While( -not $HashTable.ContainsKey([int]$Selection) ){

        #     Write-Log "Invalid choice. Please select a valid number from the list above." "WARNING"
        #     $Selection = Read-Host "Enter the number of the app you wish to uninstall"

        # }

        # Write-Host "HERE IS THE HASH TABLE:"
        # $HashTable


        $Exit = "n"

        While ($Exit -ne "y") {

            Write-Log ""
            Write-Log "Please enter the # of the application you wish to uninstall from the above list:" "WARNING"
            $numTodisplay = $COUNTER - 1
            [int]$TargetAppNum = Read-Host "Please enter a # between 1 and $numTodisplay "

            While ($TargetAppNum -lt 1 -or $TargetAppNum -ge $COUNTER) {

                Write-Log "Invalid choice. Please select a valid number from the list above." "WARNING"
                [int]$TargetAppNum = Read-Host "Please enter a # between 1 and $numTodisplay "

            }

            $TargetApp = $HashTable.$TargetAppNum

            Write-Log "You selected to uninstall app: $TargetApp using method: $UninstallMethod | Is this acceptable?" "WARNING"
            $exit = Read-Host "(y/n)" 

            if ($exit -eq "y") { break }
            
        }




        
        Write-Log ""
        Write-Log "You selected to uninstall app: $TargetApp using method: $UninstallMethod"
        Write-Log ""

        & $UninstallApp_ScriptPath -AppName $TargetApp -UninstallType $UninstallMethod -WorkingDirectory $WorkingDirectory

        if ($LASTEXITCODE -ne 0) {
            Write-Log "Uninstall app script failed with exit code: $LASTEXITCODE" "ERROR"
            Exit 1
        } else {
            Write-Log "Application '$TargetApp' uninstalled successfully!" "SUCCESS"
            Exit 0  
        }

    }



    # Suggest using Control panel of open it for them?

    # NOTE: This is actually pretty complex and needs to be thought through well. Perhaps we should develop this out after re-architecting the Uninstall infrastructure.

    # Do you want to uninstall an application from the JSON, winget search -> uninstall, or CIM search -> uninstall?

    Write-Log "These are the uninstall functions currently available through this script:"
    Write-Log ""

    $methods = Get-Command -CommandType Function -Name "*--search-and-uninstall" | Select-Object -ExpandProperty Name

    $AvailableFunctions = @{}

    #Write-Log "Available Functions:" "INFO"
    $COUNTER = 1
    $methods | ForEach-Object { 
        
        Write-Log "$Counter - $_" "INFO"
        $AvailableFunctions.add($Counter,$_)
        $Counter++ 

    }

    Write-Log "================================="
    Write-Log ""

    
    # Write-Log "NOTE: If you are not sure where to begin, start with JSON--search-and-uninstall." "WARNING"
    # Write-Log "NOTE: For All Adobe CC apps, please use Adobe--search-and-uninstall." "WARNING"
    Write-Log "NOTE THE FOLLOWING:"
    Write-Log " - Each of these may offer exclusive applications not found in the others."
    Write-Log " - For most general use cases, try Registry--search-and-uninstall."
    Write-Log " - For the largest selection of apps, try AppPackage--search-and-uninstall."
    Write-Log ""
    Write-Log "Enter the # of your desired uninstall function:" "WARNING"
    [int]$SelectedFunctionNumber = Read-Host "Please enter a #"


    While ($SelectedFunctionNumber -lt 1 -or $SelectedFunctionNumber -ge $COUNTER) {
        Write-Log "No function selected. Please enter a function number from the list above:" "ERROR"
        [int]$SelectedFunctionNumber = Read-Host "Please enter a #"
    }


    $SelectedFunction2 = $AvailableFunctions[$SelectedFunctionNumber]
    Write-Log ""
    Write-Log "You have selected: $SelectedFunction2"
    Write-Log ""
    Write-Log "================================="
    Write-Log ""
    & $SelectedFunction2
    Write-Log "================================="
    Write-Log ""
    Write-Log "SCRIPT: $LocalFileName | END | Function $SelectedFunction2 complete" "SUCCESS"


}

# DONE AND TESTED 1/14/26
Function Install--Local-Application{

    param(

        $ApplicationName=$null

    )


    if ($ApplicationName -ne $null -or $ApplicationName -ne ""){

        Write-Log "Application name provided as parameter: $ApplicationName" "INFO2"

        $TargetApp = Select-ApplicationFromJSON -AppNameToFind $ApplicationName


    }else{

        Write-Log "To begin we will access the ApplicationData.json files, both public (local repo) and private (Azure Blob) to show you the available applications."
        Write-Log ""

        Pause


        $TargetApp = Select-ApplicationFromJSON
    }

    if ($TargetApp -eq $null) {
        Write-Log "No application selected. Exiting." "ERROR"
        Exit 1
    } else {
        $AppNameToFind = $TargetApp
        Write-Log "Valid application selected for installation: $AppNameToFind"
    }
    
    Write-Log "Installation of requested application will now commence..."
    Write-Log "" 

    #Pause

    & $JSONAppInstaller_ScriptPath -TargetAppName $AppNameToFind

    Write-Log "" 

    if($LASTEXITCODE -ne 0){
        Write-Log "Install app script failed with exit code: $LASTEXITCODE" "ERROR"
        Exit $LASTEXITCODE
    } else {
        Write-Log "Application '$AppNameToFind' installed successfully!" "SUCCESS"
    }   




}

Function SearchJSONForApp {

        param(
            [string]$AppNameToSearch
        )

        if ($list1 -contains $AppNameToSearch) {

            Write-Log "Confirmed valid application name: $AppNameToSearch" "INFO2"


            Write-Log "Found $AppNameToSearch in public JSON data." "INFO2"
            $AppData = $PublicJSONdata.applications | Where-Object { $_.ApplicationName -eq $AppNameToSearch }
            Write-log "Application data for $AppNameToSearch retrieved from public JSON:" "INFO2"
            $Output = ($AppData | ConvertTo-Json -Depth 10)
            
            Write-Log $Output "INFO2"

            # Record the needed data as variables for use in other functions
            # Convert the JSON values into local variables for access later
            Write-Log "Setting application data values as local variables..." "INFO2"
            foreach ($property in $AppData.PSObject.Properties) {

                $propName = $property.Name
                $propValue = $property.Value
                Set-Variable -Name $propName -Value $propValue -Scope Global
                Write-Log "Should be: $propName = $propValue" "INFO2"
                $targetValue = Get-Variable -Name $propName -Scope Global
                Write-Log "Ended up as: $propName = $($targetValue.Value)" "INFO2"

            }

            # Return $AppNameToSearch


        } elseif($list2 -contains $AppNameToSearch){

            Write-Log "Confirmed valid application name: $AppNameToSearch"


            Write-Log "Found $AppNameToSearch in private JSON data."
            $AppData = $PrivateJSONdata.applications | Where-Object { $_.ApplicationName -eq $AppNameToSearch }

            Write-log "Application data for $AppNameToSearch retrieved from private JSON:" "INFO2"
            Write-Log ($AppData | ConvertTo-Json -Depth 10)

            # Record the needed data as variables for use in other functions
            # Convert the JSON values into local variables for access later
            Write-Log "Setting application data values as local variables..." "INFO2"
            foreach ($property in $AppData.PSObject.Properties) {

                $propName = $property.Name
                $propValue = $property.Value
                Set-Variable -Name $propName -Value $propValue -Scope Global
                Write-Log "Should be: $propName = $propValue" "INFO2"
                $targetValue = Get-Variable -Name $propName -Scope Global
                Write-Log "Ended up as: $propName = $($targetValue.Value)" "INFO2"

            }

            # Return $AppNameToSearch


        } else {

            Write-Log "Application $AppNameToSearch not found in either public or private JSON data." "ERROR"
            # Return $null
            Throw

        }

        # Exit without a return cuz it is too messy

}

function Select-ApplicationFromJSON {

    Param (

        $AppNameToFind=$null,
        $DialogueSelection="A"
    )

    # main 

    Write-Log "Parsing Public JSON" "INFO2"

    $PublicJSONdata = ParseJSON -JSONpath $PublicJSONpath
    $list1 = $PublicJSONdata.applications.ApplicationName


    # if ($list -contains $AppNameToFind) {

    #     Write-Log "Found $AppNameToFind in public JSON data." "INFO2"
    #     $AppData = $PublicJSONdata.applications | Where-Object { $_.ApplicationName -eq $AppNameToFind }

    #     Write-log "Application data for $AppNameToFind retrieved from JSON:" "INFO2"
    #     Write-Log ($AppData | ConvertTo-Json -Depth 10) "INFO2"

    # } else {

        ### If nothing found, attempt to search the  JSON...

        #Write-Log "Application $AppNameToFind not found in public JSON data." "INFO2"

        ### Download the private JSON file from Azure Blob Storage

        Write-Log "Now constructing URI for accessing private json..." "INFO2"
        

        $parts = $ApplicationDataJSONpath -split '/', 2

        $ApplicationData_JSON_ContainerName = $parts[0]      
        $ApplicationData_JSON_BlobName = $parts[1]

        #$ApplicationContainerSASkey
        $SasToken = $ApplicationContainerSASkey
        #$SasToken

        #pause

        Write-Log "Final values to be used to build ApplicationData.json URI:" "INFO2"
        Write-Log "StorageAccountName: $StorageAccountName" "INFO2"
        Write-Log "SasToken: $SasToken" "INFO2"
        Write-Log "ApplicationData_JSON_ContainerName: $ApplicationData_JSON_ContainerName" "INFO2"
        Write-Log "ApplicationData_JSON_BlobName: $ApplicationData_JSON_BlobName" "INFO2"
        $applicationJSONUri = "https://$StorageAccountName.blob.core.windows.net/$ApplicationData_JSON_ContainerName/$ApplicationData_JSON_BlobName"+"?"+"$SasToken"


        Write-Log "Attempting to access ApplicationData.json with this URI: $applicationJSONUri" "INFO2"

        Try{


            Write-Log "Beginning download..." "INFO2"
            & $DownloadAzureBlobSAS_ScriptPath -WorkingDirectory $WorkingDirectory -BlobName $ApplicationData_JSON_BlobName -StorageAccountName $StorageAccountName -ContainerName $ApplicationData_JSON_ContainerName -SasToken $SasToken
            if($LASTEXITCODE -ne 0){Throw $LASTEXITCODE }

            ### Ingest the private JSON data

            Write-Log "Parsing Private JSON" "INFO2"
            $PrivateJSONpath = "$WorkingDirectory\TEMP\Downloads\$ApplicationData_JSON_BlobName"
            $JSONpath = $PrivateJSONpath

            $PrivateJSONdata = ParseJSON -JSONpath $JSONpath
            $list2 = $PrivateJSONdata.applications.ApplicationName 

        }catch{

            Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END | Accessing JSON from private share failed. Exit code returned: $_" "ERROR"
            Exit 1
            
        }

        Clear 
        
        ### Show everything that was found
        Write-Log ""
        Write-Log "----------------------------------------------------------------"
        Write-Log "" 
        Write-Log "Applications found from the public JSON:"
        Write-Log ""
        #$list = $jsonData.applications.ApplicationName 
        $Counter = 1
        $HashTable = @{}
        Foreach ($item in $list1) {
            Write-Log "$Counter - $item"

            $HashTable.Add($Counter,$item)

            $Counter++

            #$HashTable

        }
        Write-Log "" 
        Write-Log "----------------------------------------------------------------"
        Write-Log "" 
        Write-Log "Applications found from the private JSON:"
        Write-Log ""
        #$list = $jsonData.applications.ApplicationName 
        Foreach ($item in $list2) {
            Write-Log "$Counter - $item"

            $HashTable.Add($Counter,$item)

            $Counter++

            #$HashTable
        }
        Write-Log "" 
        Write-Log "----------------------------------------------------------------"
        Write-Log ""

        if ($AppNameToFind -ne $null) {

            Write-Log "Application name provided as parameter: $AppNameToFind"
            $exit = "y"

        } else {

            $exit = "n"

        }

        # Write-Log "Looking through:"
        # $HashTable[1]
        # Write-Log "But just:"
        # $HashTable.Values


        if ($DialogueSelection -eq "C") {

            # Loop through each application in the JSON and check if it is installed

            Write-Log "Checking installation status of applications listed in JSON..."

            $HashTable2 = @{}
            $HashTable3 = @{}
            $COUNTER=1

            # Write-Log "Looking through:"
            # $HashTable[1]
            # Write-Log "But just:"
            # $HashTable.Values

            ForEach ($appName in $HashTable.Values) {

                Write-Log "" 

                Write-Log "SCRIPT: $LocalFileName | Checking installation status for application in JSON: $appName"
                Write-Log "" 


                $WinGetID = $Null
                $DisplayName = $Null

                $InstallMethod = $null
                $DetectMethod = $null


                SearchJSONForApp -AppNameToSearch $appName


                
                Write-Log "WinGetID: $WinGetID"

                # Check if the application is installed using the values from the JSON

                # Determine the detect method by the install method
                if($InstallMethod -match "MSI") {
                    $detectMethod = "MSI_Registry"
                } elseif ($InstallMethod -match "WinGet") {
                    $detectMethod = "WinGet"
                } else {
                    $detectMethod = "All"
                }

                # if ($WinGetID -eq $null -or $WinGetID -eq "") {
                #     $WinGetID = $Null
                # }

                # if ($DisplayName -eq $null -or $DisplayName -eq "") {
                #     $DisplayName = $Null
                # }
                Write-Log "WinGetID: $WinGetID"

                Write-Log "" 
                Write-Log "Using detect method: $detectMethod"
                Write-Log "" 
                Write-Log "Running command: $AppDetect_ScriptPath -AppToDetect $appName -DetectMethod $detectMethod -WorkingDirectory $WorkingDirectory -AppID $WinGetID -DisplayName $DisplayName"
                Write-Log "" 

                # Call the detect script
                & $AppDetect_ScriptPath -AppToDetect $appName -DetectMethod $detectMethod -WorkingDirectory $WorkingDirectory -AppID $WinGetID -DisplayName $DisplayName


                if ( $LASTEXITCODE -eq 0 ) {

                    Write-Log "" 

                    #Write-Log "$Counter - INSTALLED: $appName"
                    Write-Log "Application '$appName' is already installed on this system." "INFO"
                    $HashTable2.Add($COUNTER, "YES: $appName")
                    $HashTable3.Add($COUNTER, $appName)

                    $Counter++

                } else {

                    Write-Log "" 


                    #Write-Log "N/A - NOT INSTALLED: $appName" "INFO2"

                    Write-Log "Application '$appName' is NOT installed on this system." "INFO"
                    $HashTable2.Add($COUNTER, "NO: $appName")
                    $HashTable3.Add($COUNTER, $appName)

                    $Counter++

                }

                Write-Log "" 


                
            }

            #$HashTable2

            Write-Log ""
            Write-Log "Now showing installed applications from the JSON data for uninstallation selection (marked as YES):"
            Write-Log ""

            $HashTable4 = $HashTable2

            ForEach ($Item in ($HashTable4.GetEnumerator() | Sort-Object -Property:Name)) {

                Write-Log "$($Item.Name) - $($Item.Value)"

            }


            $HashTable = $HashTable3

        }
        Write-Log ""

        While($exit -ne "y") {

            if ($DialogueSelection -eq "B"){

                Write-Log "Enter the # of an app from the above list to add to InTune." "WARNING"
                Write-Log " - NOTE: If you DO NOT SEE the app you want, type 'exit' and you can add your own." "WARNING"
            
            } elseif ($DialogueSelection -eq "A"){

                Write-Log "Enter the # of an app from the list above for installation." "WARNING"

            } elseif ($DialogueSelection -eq "C"){

                Write-Log "Enter the # of an app from the list above for uninstallation." "WARNING"

            } else {

                Write-Log "Enter the # of an app from the list above." "WARNING"

            }
            
            
            $AppNumToFind = Read-Host "Please enter a number between 1 and $($COUNTER - 1)"

            if ($AppNumToFind -eq 'exit') {

                Return $null

            }

            While ( [int]$AppNumToFind -lt 1 -or [int]$AppNumToFind -ge $COUNTER ) {

                Write-Log "Invalid choice. Please select a valid number from the list above." "WARNING"
                $AppNumToFind = Read-Host "Please enter a number between 1 and $($COUNTER - 1)"

                if ($AppNumToFind -eq 'exit') {

                    Return $null

                }

            }

            While ([string]::IsNullOrWhiteSpace($AppNumToFind)) {
            Write-Log "No application name provided. Please enter a # from the list above. If you wish to exit this selection, type 'exit'." "ERROR"
            $AppNumToFind = Read-Host "Please enter a number between 1 and $($COUNTER - 1)"

            if ($AppNumToFind -eq 'exit') {
                Return $null
            }

            }

            [string]$AppNameToFind = $HashTable[[int]$AppNumToFind]

            Write-Log "Application requested: $AppNameToFind | Is this correct?" "WARNING"
            $exit = Read-Host "(y/n)"

        }

        

        #Set $AppNameToFind to global variable for use in other functions
        $Global:AppNameToFind = $AppNameToFind

        ### Search for the target application in the private JSON data
        Write-Log "" "INFO2"

        Try {
            
            SearchJSONForApp -AppNameToSearch $AppNameToFind

            Return $AppNameToFind

        } Catch {

            Return $null

        }

        

        

}

Function Select-PrinterFromJSON {

    Param (

        $PrinterName=$null,
        $DialogueSelection="A"

    )

    Write-Log "Now constructing URI for accessing PrinterData.json..." "INFO2"
    
    ## Show available printers from JSON ##

    # This snippet was taken from the Install-Printer-IP script

    $parts = $PrinterDataJSONpath -split '/', 2

    $PrinterData_JSON_ContainerName = $parts[0]      
    $PrinterData_JSON_BlobName = $parts[1]

    # $parts = $ApplicationDataJSONpath -split '\\', 2
    # $ApplicationData_JSON_ContainerName = $parts[0]      
    # $ApplicationData_JSON_BlobName = $parts[1]

    $SasToken = $PrinterContainerSASkey

    # Write-Log "Insufficient params. Each of these cannot be empty:" "ERROR"
    # Write-Log "StorageAccountName: $StorageAccountName"
    # Write-Log "SasToken: $SasToken"
    # Write-Log "PrinterData_JSON_ContainerName: $PrinterData_JSON_ContainerName"
    # Write-Log "PrinterData_JSON_BlobName: $PrinterData_JSON_BlobName"
    # Exit 1

    Write-Log "Final values to be used to build PrinterData.json URI:" "INFO2"
    Write-Log "StorageAccountName: $StorageAccountName" "INFO2"
    Write-Log "SasToken: $SasToken" "INFO2"
    Write-Log "PrinterData_JSON_ContainerName: $PrinterData_JSON_ContainerName" "INFO2"
    Write-Log "PrinterData_JSON_BlobName: $PrinterData_JSON_BlobName" "INFO2"

    $printerJSONUri = "https://$StorageAccountName.blob.core.windows.net/$PrinterData_JSON_ContainerName/$PrinterData_JSON_BlobName"+"?"+"$SasToken"


    Write-Log "Attempting to access PrinterData.json with this URI: $printerJSONUri" "INFO2"

    Try{

        # TODO: Try and create a snippet that can directly parse JSOn from web
        #$data = Invoke-RestMethod "$printerJSONUri"

        #$Result =Invoke-WebRequest -Uri $printerJSONUri -OutFile "$WorkingDirectory\temp\PrinterData.json" -UseBasicParsing

        Write-Log "Beginning download..." "INFO2"
        & $DownloadAzureBlobSAS_ScriptPath -WorkingDirectory $WorkingDirectory -BlobName $PrinterData_JSON_BlobName -StorageAccountName $StorageAccountName -ContainerName $PrinterData_JSON_ContainerName -SasToken $SasToken
        if($LASTEXITCODE -ne 0){Throw $LASTEXITCODE }

        Write-Log "Parsing JSON" "INFO2"
        $LocalJSONpath = "$WorkingDirectory\TEMP\Downloads\$PrinterData_JSON_BlobName"
        if (Test-Path $LocalJSONpath) {Write-Log "Local JSON found. Attempting to get content." "INFO2"} else { Write-Log "Local JSON not found" "ERROR"; throw "Local JSON not found" }
        #$jsonData = Get-Content -Raw $LocalJSONpath | ConvertFrom-Json
        try {
            $jsonText = Get-Content -LiteralPath $LocalJSONpath -Raw -Encoding UTF8
            $jsonData = $jsonText | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Write-Log "ConvertFrom-Json failed: $($_.Exception.Message)" "ERROR"
            throw $_
        }

        # "Printers count: {0}" -f ($jsonData.printers.Count)
        # $jsonData.printers[0] | Format-List *
        Write-Log "" "INFO2"

        Clear 

        # Can comment out
        Write-Log "Here are all the printers we found from the JSON:"
        Write-Log ""
        $list = $jsonData.printers.PrinterName 
 

        $Counter = 1
        $HashTable = @{}
        Foreach ($item in $list) {
            Write-Log "$Counter - $item"

            $HashTable.Add($Counter,$item)

            $Counter++

            #$HashTable

        }


    }catch{

        Write-Log "Accessing JSON failed. Exit code returned: $_"
        Exit 1
        
    }

    Write-Log ""

    ## Prompt user to select printer IF one was not provided ##
    # if ($PrinterName -ne $null) {

    #     Write-Log "Printer name provided as parameter: $PrinterName"


    # } else {

    #     Write-Log "Please enter the name of the printer you wish to install from the above list:" "WARNING"
    #     $PrinterName = Read-Host "Printer Name"
    #     While ([string]::IsNullOrWhiteSpace($PrinterName)) {
    #         Write-Log "No printer name provided. Please enter a printer name from the list above:" "ERROR"
    #         $PrinterName = Read-Host "Printer Name"
    #     }

    # }

    if ($PrinterName -ne $null) {

        Write-Log "Printer name provided as parameter: $PrinterName"

    } else {

        While($exit -ne "y") {

            if ($DialogueSelection -eq "B"){

                Write-Log "Enter the # of an printer from the above list to add to InTune." "WARNING"
                Write-Log " - NOTE: If you DO NOT SEE the printer you want, type 'exit' and you can add your own." "WARNING"
            
            } elseif ($DialogueSelection -eq "A"){

                Write-Log "Enter the # of an printer from the list above for installation." "WARNING"

            } elseif ($DialogueSelection -eq "C"){

                Write-Log "Enter the # of an printer from the list above for uninstallation." "WARNING"

            } else {

                Write-Log "Enter the # of an Printer from the list above." "WARNING"

            }
            
            
            $PrinterNumToFind = Read-Host "Please enter a number between 1 and $($COUNTER - 1)"

            if ($PrinterNumToFind -eq 'exit') {

                Return $null

            }

            While ( [int]$PrinterNumToFind -lt 1 -or [int]$PrinterNumToFind -ge $COUNTER ) {

                Write-Log "Invalid choice. Please select a valid number from the list above." "WARNING"
                $PrinterNumToFind = Read-Host "Please enter a number between 1 and $($COUNTER - 1)"

                if ($PrinterNumToFind -eq 'exit') {

                    Return $null

                }

            }

            While ([string]::IsNullOrWhiteSpace($PrinterNumToFind)) {

                Write-Log "No printer name provided. Please enter a # from the list above. If you wish to exit this selection, type 'exit'." "ERROR"
                $PrinterNumToFind = Read-Host "Please enter a number between 1 and $($COUNTER - 1)"

                if ($PrinterNumToFind -eq 'exit') {
                    Return $null
                }

            }

            [string]$PrinterNameToFind = $HashTable[[int]$PrinterNumToFind]


            $PrinterName = $PrinterNameToFind
            Write-Log "" "INFO2"


            #Write-Log "Here is all the data on Printer ($PrinterName):" "INFO2"
            Write-Log "PRINTER INFO:" "INFO2"
            $printer = $jsonData.printers | Where-Object { $_.PrinterName -eq $PrinterName }
            Write-Log "" "INFO2"

            if ($printer) {
                
                # Write-Log "Formatted list:"
                # $printer | Format-List *

                # Write-Log "This is the IP address"
                # $printer.PrinterIP


                # Write-Log "Attempting to digest data into PowerShell objects..." "INFO2"
                Set-VariablesFromObject -InputObject $printer -Scope Script
                # Write-Log "" "INFO2"
                # Write-Log "These are the obtained values that are now PowerShell objects:" "INFO2"
                Write-Log "Printer Name: $PrinterName" "INFO2"
                Write-Log "Port Name: $PortName" "INFO2"
                Write-Log "Printer IP: $PrinterIP" "INFO2"
                Write-Log "Driver Name: $DriverName" "INFO2"
                Write-Log "INF File: $INFFile" "INFO2"
                Write-Log "DriverZip: $DriverZip" "INFO2"
                # Write-Log "" "INFO2"

            } else {

                Write-Log "Printer '$PrinterName' not found. Your spelling may be incorrect." "ERROR"
                Exit 1

            }

            Write-Log "" "INFO2"

            Write-Log "Printer requested: $PrinterNameToFind | Is this correct?" "WARNING"

            $exit = Read-Host "(y/n)"

        }

        Write-Log ""

    }



    ## Install selected printer ##

        

        # Set all vars as global for use in other functions
        $Global:PortName = $PortName
        $Global:PrinterIP = $PrinterIP
        $Global:PrinterName = $PrinterName
        $Global:DriverName = $DriverName
        $Global:INFFile = $INFFile
        $Global:DriverZip = $DriverZip

        Return $PrinterName

}

function Set-VariablesFromObject {
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $InputObject,
        #[string]$Prefix = 'Printer_',
        [ValidateSet('Local','Script','Global')] [string]$Scope = 'Local'
    )
    process {
        foreach ($p in $InputObject.PSObject.Properties) {
            # sanitize to a valid PowerShell variable name
            $name = $p.Name -replace '[^A-Za-z0-9_]', '_'
            if ($name -notmatch '^[A-Za-z_]') { $name = "_$name" }

            #$varName = "$Prefix$name"
            $VarName= $Name
            Set-Variable -Name $varName -Value $p.Value -Scope $Scope -Force
        }
    }
}

Function ParseJSON {

    param(
        [string]$JSONpath
    )

    Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START" "INFO2"
    
    if (Test-Path $JSONpath) {
        Write-Log "Local JSON found. Attempting to get content." "INFO2"
    } else { 
        Write-Log "Local JSON not found" "ERROR" "INFO2"; throw "Local JSON not found" 
    }

    try {
        $jsonText = Get-Content -LiteralPath $JSONpath -Raw -Encoding UTF8
        $jsonData = $jsonText | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Log "ConvertFrom-Json failed: $($_.Exception.Message)" "ERROR"
        Throw $_
    }


    Write-Log "" "INFO2"

    # Can comment out
    # Write-Log "Here are all the applications we found from the JSON:"
    # Write-Log ""
    # $list = $jsonData.applications.ApplicationName 
    # Foreach ($item in $list) {
    #     Write-Log "$item"
    # }
    # Write-Log "" 

    Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END" "INFO2"
    return $jsonData

}

# DONE (still need testing) 1/14/26
Function Setup--Azure-Registry_Remediations_For_Org{

    # Determine if this is a test or production deployment
    $RepoUrl = Set-URL
    Write-Log "==========================================================================================="
    Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START"
    Write-Log "==========================================================================================="

    Write-Log ""

    Write-Log "Do you need instructions on generating SAS keys for your Azure Blob Storage containers?" "WARNING"
    $NeedInstructions = Read-Host "(y/n)"
    While ($NeedInstructions -ne "y" -and $NeedInstructions -ne "n") {
        Write-Log "Invalid choice. Please enter 'y' or 'n'." "ERROR"
        $NeedInstructions = Read-Host "(y/n)"
    }
    Write-Log ""
    if ($NeedInstructions -eq "y") {

        Write-Log "Instructions for navigating to your Azure Blob Storage container as follows:"
        Write-Log ""
        Write-Log " 1 - Go to https://portal.azure.com/#view/Microsoft_Azure_StorageHub/StorageHub.MenuView/~/StorageAccountsBrowse"
        Write-Log ""
        Write-Log " 2 - Select this storage account: $StorageAccountName"
        Write-Log ""
        Write-Log " 3 - Select 'Data Storage' > 'Containers' from the left menu"
        Write-Log ""
        Write-Log "For each containiner that you need a SAS key for, follow these steps:"
        Write-Log ""
        Write-Log " 4 - Select the container from the list (e.g., applications, printers, etc.)"
        Write-Log ""
        Write-Log " 5 - Click the three dots (...) next to the far right of the container name and select 'Generate SAS...'"
        Write-Log ""
        Write-Log " 6 - In the 'Generate SAS' pane, set the appropriate date range for the key to be valid. No other default options need to be changed."
        Write-Log ""
        Write-Log " 7 - Click the 'Generate SAS token and URL' button at the bottom of the pane."
        Write-Log ""
        Write-Log " 8 - Copy the 'SAS token' value (not the full URL). You will need paste it into the appropriate prompt in the next steps of this script. You can store the SAS keys in a text document if needed."
        Write-Log ""
        Pause

    }

    # Collect input data


    # Write-Log "Currently this function only supports updating SAS keys for Azure Blob, custom Git URL, no custom variables. Will add option for other values in the future." "WARNING"

    # Write-Log ""
    Write-Log ""


    # [hashtable]$HashTable = @{}

    Write-Log "==========================================================================================="
    Write-Log "GIT REPO URL"
    Write-Log "==========================================================================================="
    Write-Log ""

    $OldCustomRepoURL = $CustomRepoURL
    $exit = "n"

    While ($exit -eq "n"){

        $CustomRepoURL = $OldCustomRepoURL
        Write-Log "Your current custom organization Git Repo URL is:"
        Write-Log "$CustomRepoURL"
        Write-Log ""
        # Write-Log "If this is acceptable, press Enter to continue or enter the new key now:" "WARNING"
        Write-Log "Options:"
        Write-Log " - Input a new value"
        Write-Log " - Leave blank to keep existing"
        Write-Log " - Type 'CLEAR' to remove existing key"
        Write-Log ""
        $TempRepoURL = Read-Host "Enter your selection"
        Write-Log ""

        if ($TempRepoURL -eq "") {
            $RepoURLtoUse = $CustomRepoURL

            Write-Log "Using existing Repo URL: $RepoURLtoUse"
        } elseif ($TempRepoURL -eq "CLEAR") {

            $RepoURLtoUse = ""
            Write-Log "Clearing Repo URL, setting to blank."
        } else {

            Write-Log "Using new Repo URL: $TempRepoURL"
            $RepoURLtoUse = $TempRepoURL
        }
        Write-Log ""
        Write-Log "Is this acceptable?" "WARNING"
        $exit = Read-Host "(y/n)"


        Write-Log ""
    }
    # if ($RepoURLtoUse -ne "" -or $null -ne $RepoURLtoUse) {

    #     $HashTable.Add("CustomRepoURL", $RepoURLtoUse)

    # }
    

    Write-Log "==========================================================================================="
    Write-Log "GIT REPO TOKEN"
    Write-Log "==========================================================================================="
    Write-Log ""

    $OldCustomRepoToken = $CustomRepoToken
    $exit = "n"
    While ($exit -eq "n"){

        $CustomRepoToken = $OldCustomRepoToken
        Write-Log "Your current custom organization Git Repo Token is:"
        Write-Log "$CustomRepoToken"
        Write-Log ""
        # Write-Log "If this is acceptable, press Enter to continue or enter the new key now:" "WARNING"
        Write-Log "Options:"
        Write-Log " - Input a new value"
        Write-Log " - Leave blank to keep existing"
        Write-Log " - Type 'CLEAR' to remove existing key"
        Write-Log ""
        $TempRepoToken = Read-Host "Enter your selection"
        Write-Log ""
        if ($TempRepoToken -eq "") {

            $CustomRepoTokenToUse = $CustomRepoToken
            Write-Log "Using existing Repo Token: $CustomRepoTokenToUse"
        } elseif ($TempRepoToken -eq "CLEAR") {

            $CustomRepoTokenToUse = ""
            Write-Log "Clearing Repo Token, setting to blank."
        } else {

            Write-Log "Using new Repo Token: $TempRepoToken"
            $CustomRepoTokenToUse = $TempRepoToken
        } 

        Write-Log ""
        Write-Log "Is this acceptable?" "WARNING"
        $exit = Read-Host "(y/n)"   

        Write-Log ""

    }
    # if ($CustomRepoTokenToUse -ne "" -or $null -ne $CustomRepoTokenToUse) {

    #     $HashTable.Add("CustomRepoToken", $CustomRepoTokenToUse)
    # }
    

    # Write-Log "Enter your custom PRINTER share SAS key:" "WARNING"

    # $PrinterContainerSASkey = Read-Host "SAS KEY"

    Write-Log "==========================================================================================="
    Write-Log "PRINTER SHARE SAS KEY"
    Write-Log "==========================================================================================="

    Write-Log ""

    $OldPrinterContainerSASkey = $PrinterContainerSASkey
    $exit = "n"
    While ($exit -eq "n"){

        $PrinterContainerSASkey = $OldPrinterContainerSASkey
        Write-Log "Your current custom organization PRINTER share SAS key is:"
        Write-Log "$PrinterContainerSASkey"
        Write-Log ""
        # Write-Log "If this is acceptable, press Enter to continue or enter the new key now:" "WARNING"
        Write-Log "Options:"
        Write-Log " - Input a new value"
        Write-Log " - Leave blank to keep existing"
        Write-Log " - Type 'CLEAR' to remove existing key"
        Write-Log ""
        $TempKey = Read-Host "Enter your selection"
        Write-Log ""

        if ($TempKey -eq "") {

            $PrintSASKeytoUse = $PrinterContainerSASkey
            Write-Log "Using existing Printer SAS key: $PrintSASKeytoUse"

        } elseif ($TempKey -eq "CLEAR") {
            $PrintSASKeytoUse = ""
            Write-Log "Clearing Printer SAS key, setting to blank."
        } else {
            Write-Log "Using new Printer SAS key: $TempKey"
            $PrintSASKeytoUse = $TempKey
        }

        Write-Log ""
        Write-Log "Is this acceptable?" "WARNING"
        $exit = Read-Host "(y/n)"

    }
    # if ($PrintSASKeytoUse -ne "" -or $null -ne $PrintSASKeytoUse) {

    #     $HashTable.Add("PrinterContainerSASkey", $PrintSASKeytoUse)
    # }


    # Write-Log "Enter your custom APPLICATION share SAS key:" "WARNING"  

    # $ApplicationContainerSASkey = Read-Host "SAS KEY"
    Write-Log "==========================================================================================="
    Write-Log "APPLICATION SHARE SAS KEY"
    Write-Log "==========================================================================================="
    Write-Log ""  

    $OldApplicationContainerSASkey = $ApplicationContainerSASkey
    $exit = "n"
    While ($exit -eq "n"){

        $ApplicationContainerSASkey = $OldApplicationContainerSASkey
        Write-Log "Your current custom organization APP share SAS key is: "
        Write-Log "$ApplicationContainerSASkey"
        Write-Log ""
        # Write-Log "If this is acceptable, press Enter to continue or enter the new key now:" "WARNING"
        Write-Log "Options:"
        Write-Log " - Input a new value"
        Write-Log " - Leave blank to keep existing"
        Write-Log " - Type 'CLEAR' to remove existing key"
        Write-Log ""
        $TempKey = Read-Host "Enter your selection"
        Write-Log ""

        if ($TempKey -eq "") {

            $ApplicationSASKeytoUse = $ApplicationContainerSASkey
            Write-Log "Using existing Application SAS key: $ApplicationSASKeytoUse"

        } elseif ($TempKey -eq "CLEAR") {
            $ApplicationSASKeytoUse = ""
            Write-Log "Clearing Application SAS key, setting to blank."
        } else {
            Write-Log "Using new Application SAS key: $TempKey"
            $ApplicationSASKeytoUse = $TempKey
        } 

        Write-Log ""
        Write-Log "Is this acceptable?" "WARNING"
        $exit = Read-Host "(y/n)"
        Write-Log ""


    }



    
    # if ($ApplicationSASKeytoUse -ne "" -or $null -ne $ApplicationSASKeytoUse) {

    #     $HashTable.Add("ApplicationContainerSASkey", $ApplicationSASKeytoUse)
    # }

    Write-Log ""

    Write-Log ""

    [hashtable]$FunctionParams = $HashTable

    
        [hashtable]$FunctionParams = @{
            PrinterContainerSASkey = $PrintSASKeytoUse
            ApplicationContainerSASkey = $ApplicationSASKeytoUse
            CustomRepoToken = $CustomRepoTokenToUse
            CustomRepoURL = $RepoURLtoUse
        }

        Write-Log "Attempting to generate the registry remediation scripts..."
        Write-Log ""


        [hashtable]$ReturnHash = @{}

        $ReturnHash = & $GenerateInstallCommand_ScriptPath `
        -DesiredFunction "RegRemediationScript" `
        -RepoURL $RepoURL `
        -RepoNickName $Global:TargetRepoNickName `
        -RepoBranch $Global:RepoBranch `
        -TargetWorkingDirectory $Global:TargetWorkingDirectory `
        -FunctionParams $FunctionParams

        # Check the returned hashtable
        if(($ReturnHash -eq $null) -or ($ReturnHash.Count -eq 0)){
            Write-Log "No data returned!" "ERROR"
            Exit 1
        }

        Write-Log "Values retrieved:" "INFO2"

        foreach ($key in $ReturnHash.Keys) {

            $value = $ReturnHash[$key]
            Write-Log "   $key : $value" "INFO2"

        }    

        Write-Log "Setting values as local variables..." "INFO2"
        foreach ($key in $ReturnHash.Keys) {
            Set-Variable -Name $key -Value $ReturnHash[$key] -Scope Local
            # Write-Log "Should be: $key = $($ReturnHash[$key])"
            $targetValue = Get-Variable -Name $key -Scope Local
            Write-Log "Ended up as: $key = $($targetValue.Value)" "INFO2"

        }

    Clear
    Write-Log ""
    Write-Log "==========================================================================================="
    Write-Log "UPLOAD REGISTRY REMEDIATION SCRIPTS TO INTUNE"
    Write-Log "==========================================================================================="
    Write-Log ""

    Write-Log "Next we are going to upload the detect and remediation script to InTune."
    Write-Log ""

    Write-Log "1. In InTune, navigate to: Device > Windows > Scripts and remediations"
    Write-Log " - Direct link: https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesWindowsMenu/~/powershell"
    Write-Log ""
    Write-Log "2. Navigate to your PowerDeploy Registry Update remediation script package. If you for sure do not have one, we will walk through creating one."
    Write-Log ""
    Write-Log "NOTE: Make sure that you do not leave behind old remediation scripts in production once replace them." "WARNING"
    Write-Log ""
    Write-Log "Do you need to create a new package?" "WARNING"
    $Answer = Read-Host "(y/n)"

    if ($Answer -eq "y"){

        Write-Log "  To create a new package..."
            Write-Log ""

        write-Log "   1. Click ""Create"""
            Write-Log ""

        write-log "   2. Suggested name: ""PowerDeploy Registry Update"""
            Write-Log ""

        Write-Log "   3. Suggested description: ""Used to update company registry values for use with PowerDeploy. For more information see the official repo: https://github.com/Santa-Cruz-COE/PowerDeploy"""
            Write-Log ""

        Write-Log "   4. Click Next to go to the Script settings page."
            Write-Log ""

        Write-Log "   5. For ""Detection script file"", select the script located at: $DetectScript"
            Write-Log ""

        Write-Log "   6. For ""Remediation script file"", select the script located at: $RemediationScript"
            Write-Log ""

        Write-Log "   7. For ""Run script in 64-bit PowerShell"" select: Yes"
            Write-Log ""

        Write-Log "   8. Click Next to go to the Scope tags page."
            Write-Log ""

        Write-Log "   9. Add any scope tags you wish to use. I don't use any personally."
            Write-Log ""

        Write-Log "  10. Click Next to go to the Assignments page and assign to your desired groups. I recommend starting with a small test group first, then expanding to the whole org (if appropriate) once confirmed working."
            Write-Log ""
        
        Write-Log "  11. Click ""Create"" to finish creating the remediation package."


    } else {

        Write-Log "  Update your existing package as follows..."
            Write-Log ""

        Write-Log "   For ""Detection script file"", select the script located at: $DetectScript"
            Write-Log ""

        Write-Log "   For ""Remediation script file"", select the script located at: $RemediationScript"
            Write-Log ""

        Write-Log "   Make sure ""Run script in 64-bit PowerShell"" is set to: Yes"
            Write-Log ""

        Write-Log "   Save your changes."
            Write-Log ""


    }

    Pause
    Write-Log ""
    Write-Log "That's all! Now give your target machines some time and monitor progress." "SUCCESS"



}


##########
## MAIN ##
########## 

# Setup 
# Write-Log "SCRIPT: $LocalFileName | START" "INFO2"
# Write-Log "NOTE: Progess feed and non required info will be in white. Feel free to ignore these lines." "INFO2"
# Write-Log "NOTE: Instructions and required info will be in Cyan. Please note these lines."
# Write-Log ""
Write-Log ""
Write-Log "=================================="
Write-Log "========== Set Up Asset =========="
Write-Log "=================================="
Write-Log ""
Write-Log "Welcome! This script can be used to:"
Write-Log " - Install a printer/app on your local machine"
Write-Log " - Make a printer/app available for deployment via Azure/Intune."
Write-Log ""
Write-Log ""
Write-Log "When you are ready we will begin by checking pre-requisites..."
Write-Log ""
# Write-Log "NOTE: Instructions and required info will be in Cyan. Please note these lines."
# Write-Log "NOTE: Progess feed and non required info will be in white. Feel free to ignore these lines." "INFO2"

# Pause

# Warnings
Write-Log ""
# If this script is not being ran against C:ProgramData\PowerDeploy, it is going to lock down files in the root of the repo parent folder. Give a big fat warning. 
if ($WorkingDirectory -ne "C:\ProgramData\PowerDeploy") {
    Write-Log "You are running this script from a non-standard location: $WorkingDirectory" "WARNING"
    Write-Log "This may cause permission issues with files created in the this folder. It is recommended to run this script from C:\ProgramData\PowerDeploy" "WARNING"
    Write-Log "" "WARNING"
    Write-Log "ATTENTION: The following folders will be locked down:" "WARNING"
    Write-Log " - $WorkingDirectory\Temp" "WARNING"
    Write-Log " - $WorkingDirectory\Logs" "WARNING"
    Write-Log " - $RepoRoot" "WARNING"
    Write-Log "" "WARNING"
    Write-Log "If that is acceptable, press enter to continue." "WARNING"
    Pause
    Write-Log ""

}

# If this script is not being ran as an admin that is also the logged in user, OR SYSTEM, then WinGet will not work properly. You must be running as the logged in user and also be admin. Otherwise set up the app in compay portal using this script. 
If( (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or `
    -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::User))`
    -and !(([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18'))){ # skip block if user is System

    Write-Log "You are either not running this script as an administrator or as the logged in user." "ERROR"
    Write-Log "" "WARNING"
    Write-Log "WinGet WILL NOT WORK PROPERLY." "WARNING"
    Write-Log "" "WARNING"
    Write-Log "WinGet requires you to be running as the logged in user who is also an administrator." "WARNING"
    Write-Log "" "WARNING"
    Write-Log "If this is not possible, you can still use this script to set up applications for deployment via InTune." "WARNING"
    Write-Log "" "WARNING"
    Write-Log "App installs from InTune/CompanyPortal do not require the user to be an admin." "WARNING"
    Write-Log "" "WARNING"
    Pause
    Write-Log ""

} 

# Grab organization custom registry values and set as local variables
Try{

# Grab organization custom registry values
    Write-Log "Retrieving organization custom registry values..." "INFO2"
    $ReturnHash = & $OrgRegReader_ScriptPath #| Out-Null

    # Check the returned hashtable
    if(($ReturnHash -eq $null) -or ($ReturnHash.Count -eq 0)){
        Write-Log "No data returned from Organization Registry Reader script!" "ERROR"
        Exit 1
    }
    #Write-Log "Organization custom registry values retrieved:"
    foreach ($key in $ReturnHash.Keys) {
        $value = $ReturnHash[$key]
        Write-Log "   $key : $value" "INFO2"
    }    

    # Turn the returned hashtable into variables
    Write-Log "Setting organization custom registry values as local variables..." "INFO2"
    foreach ($key in $ReturnHash.Keys) {
        Set-Variable -Name $key -Value $ReturnHash[$key] -Scope Local
        Write-Log "Should be: $key = $($ReturnHash[$key])" "INFO2"
        $targetValue = Get-Variable -Name $key -Scope Local
        Write-Log "Ended up as: $key = $($targetValue.Value)" "INFO2"

    }
} Catch {
    Write-Log "Error retrieving organization custom registry values: $_" "ERROR"
    Exit 1
}

# Update this repo
# TODO: This isn't working quite yet. Need to add auth too.

Push-Location $RepoRoot

    Write-Log "Dot sourcing Git Runner template script located at: $GitRunnerTemplate_ScriptPath" "INFO2"

    & { # Run in a script block to avoid scope issues
        . $GitRunnerTemplate_ScriptPath -RepoURL "ZZ" -RepoNickName $ThisRepoNickName -WorkingDirectory $WorkingDirectory -UpdateLocalRepoOnly $true

        CheckAndInstall-Git
        Set-GitSafeDirectory
    }

    Write-Log "Running Git pre-reqs" "INFO2"
    Write-Log "" "INFO2"


    $gitOutput = git fetch 2>&1
    ForEach ($line in $gitOutput) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $LocalFileName | END | Failed" "ERROR"; Exit 1 }

    $gitBranch = git rev-parse --abbrev-ref HEAD 2>&1
    ForEach ($line in $gitBranch) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $LocalFileName | END | Failed" "ERROR"; Exit 1 }

    $gitCommit = git rev-parse HEAD 2>&1
    ForEach ($line in $gitCommit) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $LocalFileName | END | Failed" "ERROR"; Exit 1 }

    $gitURL = git remote get-url origin 2>&1
    ForEach ($line in $gitURL) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $LocalFileName | END | Failed" "ERROR"; Exit 1 }

    $gitCommitRemote = git ls-remote origin $gitBranch | ForEach-Object { $_.Split("`t")[0] } 2>&1
    ForEach ($line in $gitCommitRemote) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $LocalFileName | END | Failed" "ERROR"; Exit 1 }
    



    Write-Log "" "INFO2"


Clear

# Determine the deploy mode

# if $gitURL contains the CustomRepoURL, then this is a custom org deployment
if ($gitURL -match [regex]::Escape($CustomRepoURL) -and $CustomRepoURL -ne "" -and $CustomRepoURL -ne $null) {

    if ($gitBranch -eq "Dev"){

        $PerceivedMode = "PRIVATE-DEVELOPMENT"
    } elseif ($gitBranch -eq "Main" -or $gitBranch -eq "Master") {
        $PerceivedMode = "PRODUCTION"
    } else {
        $PerceivedMode = "???"
    }

} elseif ($gitURL -match "$OfficialPublicRepoURL") {

    if ($gitBranch -eq "Dev"){

        $PerceivedMode = "PUBLIC-DEVELOPMENT"
    } elseif ($gitBranch -eq "Main" -or $gitBranch -eq "Master") {
        $PerceivedMode = "PUBLIC-TESTING"
    } else {
        $PerceivedMode = "???"
    }

} else {

    $PerceivedMode = "???"

}


Write-Log "=================================="
Write-Log "============ UPDATES ============="
Write-Log "=================================="
Write-Log ""
Write-Log "Current Git Repo info:"
Write-Log ""
Write-Log "Operational Mode:                 $PerceivedMode"
Write-Log "Details:"
Write-Log "     URL:                         $gitURL"
Write-Log "     Branch:                      $gitBranch"
Write-Log "     Latest Commit on Remote:     $($gitCommitRemote)"
Write-Log "     Local Commit:                $gitCommit"
Write-Log "=================================="


if ($gitCommit -eq $gitCommitRemote) {

    Write-Log ""
    Write-Log "Your local repo is already up to date with the latest version." "SUCCESS"
    Write-Log ""
} else {

    Write-Log ""
    Write-Log "A newer version of this repo is available." "WARNING"


    # Write-Log "NOTE: Operational mode indicates which version of the code this currently repo is using."
    Write-Log ""
    Write-Log "Would you like to update the repo to the latest version?" "WARNING"
    $Answer = Read-Host "y/n"
    if ($Answer -ne "y" -and $Answer -ne "n") {
        Write-Log "Invalid input. Please type 'y' to update or 'n' to skip." "ERROR"
        $Answer = Read-Host "y/n"
    }

    If ($Answer -eq "y"){

        

        Write-Log "Updating local repo located at: $RepoRoot" "INFO2"

        Write-Log "" "INFO2"


        # Write-Log "Running Git Pull to update the repo..." "INFO2"

        $gitOutput = git pull 2>&1
        ForEach ($line in $gitOutput) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $LocalFileName | END | Failed" "ERROR"; Exit 1 }
        
        Write-Log "" "INFO2"
    
        Write-Log "Repo updated to the latest version."
        Pause
        
    } 

}

Pop-Location 

Write-Log ""
Write-Log "Pre-reqs check complete."
Write-Log ""

clear
Write-Log "==============================================="
Write-Log "============== PowerDeploy Setup =============="
Write-Log "==============================================="
Write-Log ""
Write-Log "Info:"
Write-Log ""
Write-Log " - Operational Mode: $PerceivedMode"
Write-Log " - Commit Version: $gitCommit"
Write-Log ""
Write-Log "==============================================="
Write-Log ""
#Write-Log "These are the functions currently available through this script:"
Write-Log "Available Functions:"
Write-Log ""

$methods = Get-Command -CommandType Function -Name "*--*" | Select-Object -ExpandProperty Name

$AvailableFunctions = @{}

#Write-Log "Available Functions:" "INFO"
$COUNTER = 1
$methods | ForEach-Object { 
    
    Write-Log "$Counter - $_" "INFO"
    $AvailableFunctions.add($Counter,$_)
    $Counter++ 

}
Write-Log ""
Write-Log "==============================================="
Write-Log ""

Write-Log "Enter the # of your desired function:" "WARNING"
[int]$SelectedFunctionNumber = Read-Host "Please enter a #"


While ($SelectedFunctionNumber -lt 1 -or $SelectedFunctionNumber -ge $COUNTER) {
    Write-Log "No function selected. Please enter a function number from the list above:" "ERROR"
    [int]$SelectedFunctionNumber = Read-Host "Please enter a #"
}

Clear

$SelectedFunction = $AvailableFunctions[$SelectedFunctionNumber]
Write-Log ""
Write-Log "You have selected: $SelectedFunction"
Write-Log ""
Write-Log "==============================================="
Write-Log ""
& $SelectedFunction
Write-Log "==============================================="
Write-Log ""
Write-Log "SCRIPT: $LocalFileName | END | Function $SelectedFunction complete" "SUCCESS"
Exit 0