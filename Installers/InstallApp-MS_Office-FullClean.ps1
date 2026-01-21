# Microsoft Office - Full Clean Install

Param(

    [Parameter(Mandatory=$true)]
    [String]$WorkingDirectory,

    $CustomSetupZipBlobPath, # if this is not supplied the WinGet will be used

    $ConfigFileName = "configuration.xml",
    
    #[String]$VerboseLogs = $True,
    [int]$timeoutSeconds = 900 # Timeout in seconds (300 sec = 5 minutes)

)

### Other Vars ###

$ThisFileName = $MyInvocation.MyCommand.Name

#$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$RepoRoot = Split-Path -Path $PSScriptRoot -Parent
#$WorkingDirector = (Resolve-Path "$PSScriptRoot\..\..").Path
$WorkingDirectory = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent


$LogRoot = "$WorkingDirectory\Logs\Installer_Logs"

# path of WinGet installer
$WinGetInstallerScript = "$RepoRoot\Installers\General_WinGet_Installer.ps1"

# path of General uninstaller
$UninstallerScript = "$RepoRoot\Uninstallers\General_Uninstaller.ps1"

# path of the DotNet installer
$DotNetInstallerScript = "$RepoRoot\Installers\Install-DotNET.ps1"

# path of the Azure Blob SAS downloader script
$DownloadAzureBlobSAS_ScriptPath = "$RepoRoot\Downloaders\DownloadFrom-AzureBlob-SAS.ps1"

# path of Organization_CustomRegistryValues-Reader_TEMPLATE
$OrgRegReader_ScriptPath = "$RepoRoot\Templates\OrganizationCustomRegistryValues-Reader_TEMPLATE.ps1"

# path to application detection script
$AppDetectionScriptPath = "$RepoRoot\Templates\Detection-Script-Application_TEMPLATE.ps1"

$LogPath = "$LogRoot\$ThisFileName.Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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

##########
## Main ##
##########

## Pre-Check

Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX PRE-CHECK for SCRIPT: $ThisFileName"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX NOTE: PRE-CHECK is not logged"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Checking if supplied paths have valid syntax"

# Test the paths syntax
$pathsToValidate = @{
    'WorkingDirectory' = $WorkingDirectory
    'RepoRoot' = $RepoRoot
    'LogRoot' = $LogRoot
    'LogPath' = $LogPath
    'WinGetInstallerScript' = $WinGetInstallerScript
    'UninstallerScript' = $UninstallerScript
}
Test-PathSyntaxValidity -Paths $pathsToValidate -ExitOnError

# Test the paths existance
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Checking if supplied paths exist"
$pathsToTest = @{
    'WorkingDirectory' = $WorkingDirectory
    'WinGetInstallerScript' = $WinGetInstallerScript
    'UninstallerScript' = $UninstallerScript
}
Foreach ($pathToTest in $pathsToTest.keys){ 

    $TargetPath = $pathsToTest[$pathToTest]

    if((test-path $TargetPath) -eq $false){
        Write-Log "Required path $pathToTest does not exist at $TargetPath" "ERROR"
        Exit 1
    }

}
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Path validation successful - all exist"

Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

If($CustomSetupZipBlobPath -ne $null -and $CustomSetupZipBlobPath -ne "") {

    $InstallMode = "CustomAzureBlobSetup"

} else {

    $InstallMode = "WinGet"

}


Write-Log "===== Preconfigured App Installer  ====="

Write-Log "Install App: MS Office"
Write-Log "Install Method: Full Clean (Multiple steps)"
Write-Log "Steps:"
Write-Log "  Attempt clean uninstall of pre-existing installations of MS Office"
Write-Log "  Install Office using $InstallMode"

Write-Log "LOG PATH: $LogPath"


Write-Log "========================================"
Write-Log "SCRIPT: $ThisFileName | 1. Attempt clean uninstall of pre-existing installations of Office"
Write-Log "========================================"

Try{ 

    Write-Log "SCRIPT: $ThisFileName | Attempting to uninstall Microsoft Office"
    # & $UninstallerScript -AppName "Microsoft_Office" -UninstallType "All" -UninstallString_DisplayName "Microsoft 365 Apps for enterprise - en-us" -WinGetID "Microsoft.Office" -WorkingDirectory $WorkingDirectory
    # if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }
    # & $UninstallerScript -AppName "Microsoft_Office" -UninstallType "All" -UninstallString_DisplayName "Microsoft 365 Apps for enterprise - en-us" -WinGetID "Microsoft.Office" -WorkingDirectory $WorkingDirectory
    # if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

    # I will expand these over time as I find more items to clean

    # NOTE: Removed this section because WinGet uninstall of Office cannot be done silently this way
    # Winget IDs to uninstall
    # $WinGetIDToUninstall = @(

    #     "Microsoft.Office"

    # )

    # foreach ($WinGetApp in $WinGetIDToUninstall) {

    #     & $UninstallerScript -AppName "$WinGetApp" -UninstallType "Remove-App-WinGet" -WorkingDirectory $WorkingDirectory
    #     if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

    # }










    # TODO: The items below will fail because these methods so far are not able to uninstall Office products. Need to investigate why. Then I can implement this: https://learn.microsoft.com/en-us/troubleshoot/microsoft-365/admin/miscellaneous/assistant-office-uninstall

    # apppackage cleanup
    $AppPackagesToRemove = @(

        "Microsoft.OfficePushNotificationUtility",
        "Microsoft.Office.ActionsServer",
        "Microsoft.MicrosoftOfficeHub"

    )

    Foreach ($AppPackage in $AppPackagesToRemove) {

        $packages = Get-AppxPackage -Name $AppPackage -AllUsers -ErrorAction SilentlyContinue

        foreach ($package in $packages) {

            & $UninstallerScript -AppName "$AppPackage" -UninstallType "Remove-AppxPackage" -WorkingDirectory $WorkingDirectory
            if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

        }
    }

    # CIM instance uninstall
    $CIMtoUninstall = @(

        "Office 16 Click-to-Run Extensibility Component"

    )

    foreach ($CIMApp in $CIMtoUninstall) {

        & $UninstallerScript -AppName "$CIMApp" -UninstallType "Remove-App-CIM" -WorkingDirectory $WorkingDirectory
        if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

    }

    # Regitry items to uninstall 
    $RegistryItemsToUninstall = @(

        "Office 16 Click-to-Run Extensibility Component",
        "Aplicaciones de Microsoft 365 para empresas - es-mx",
        "Microsoft 365 Apps for enterprise - en-us"

    )

    foreach ($RegApp in $RegistryItemsToUninstall) {

        & $UninstallerScript -AppName "$RegApp" -UninstallType "All" -WorkingDirectory $WorkingDirectory
        if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

    }

    Pause


    Write-Log "SCRIPT: $ThisFileName | Pre-existing Office uninstall completed successfully." "SUCCESS"

} Catch {

    Write-Log "SCRIPT: $ThisFileName | END | Office Uninstall failed. Code: $_" "ERROR"
    Exit 1

}

Write-Log "========================================"
Write-Log "SCRIPT: $ThisFileName | 2. Download and extract Custom Setup Zip"
Write-Log "========================================"

Try {


    ###

    # Grab organization custom registry values and set as local variables
    Try{

    # Grab organization custom registry values
        Write-Log "Retrieving organization custom registry values..." "INFO"
        $ReturnHash = & $OrgRegReader_ScriptPath #| Out-Null

        # Check the returned hashtable
        if(($ReturnHash -eq $null) -or ($ReturnHash.Count -eq 0)){
            Write-Log "No data returned from Organization Registry Reader script!" "ERROR"
            Exit 1
        }
        #Write-Log "Organization custom registry values retrieved:"
        foreach ($key in $ReturnHash.Keys) {
            $value = $ReturnHash[$key]
            Write-Log "   $key : $value" "INFO"
        }    

        # Turn the returned hashtable into variables
        Write-Log "Setting organization custom registry values as local variables..." "INFO"
        foreach ($key in $ReturnHash.Keys) {
            Set-Variable -Name $key -Value $ReturnHash[$key] -Scope Local
            Write-Log "Should be: $key = $($ReturnHash[$key])" "INFO"
            $targetValue = Get-Variable -Name $key -Scope Local
            Write-Log "Ended up as: $key = $($targetValue.Value)" "INFO"

        }
    } Catch {
        Write-Log "Error retrieving organization custom registry values: $_" "ERROR"
        Exit 1
    }

    ###


    Write-Log "Now constructing URI for accessing private json..." "INFO"

    $parts = $CustomSetupZipBlobPath -split '/', 2

    $CustomSetupZip_ContainerName = $parts[0]      
    $CustomSetupZip_BlobName = $parts[1]

    #$ApplicationContainerSASkey
    $SasToken = $ApplicationContainerSASkey
    #$SasToken

    #pause

    Write-Log "Final values to be used to build ApplicationData.json URI:" "INFO"
    Write-Log "StorageAccountName: $StorageAccountName" "INFO"
    Write-Log "SasToken: $SasToken" "INFO"
    Write-Log "CustomSetupZip_ContainerName: $CustomSetupZip_ContainerName" "INFO"
    Write-Log "CustomSetupZip_BlobName: $CustomSetupZip_BlobName" "INFO"
    $CustomSetupZip_Uri = "https://$StorageAccountName.blob.core.windows.net/applications/$CustomSetupZip_ContainerName/$CustomSetupZip_BlobName"+"?"+"$SasToken"

    Try{


        Write-Log "Beginning download..." "INFO"
        & $DownloadAzureBlobSAS_ScriptPath -WorkingDirectory $WorkingDirectory -BlobName $CustomSetupZip_BlobName -BlobSASurl $CustomSetupZip_Uri
        if($LASTEXITCODE -ne 0){Throw $LASTEXITCODE }

        ### Ingest the private JSON data

        # Write-Log "Parsing Private JSON" "INFO"
        # $PrivateJSONpath = "$WorkingDirectory\TEMP\Downloads\$CustomSetupZip_BlobName"
        # $JSONpath = $PrivateJSONpath

        # $PrivateJSONdata = ParseJSON -JSONpath $JSONpath
        # $list2 = $PrivateJSONdata.applications.ApplicationName 

        # Extract the zip to working directory
        $DownloadedZipPath = "$WorkingDirectory\TEMP\Downloads\$CustomSetupZip_BlobName"
        $ExtractedFolderPath = "$WorkingDirectory\TEMP\Downloads\CustomSetupZip_BlobName_EXTRACTED"

        if (Test-Path $ExtractedFolderPath) {
            Write-Log "Extracting downloaded Office setup zip to $ExtractedFolderPath"
            Expand-Archive -Path $DownloadedZipPath -DestinationPath $ExtractedFolderPath -Force
        } else {
            Write-Log "Creating extraction folder at $ExtractedFolderPath"
            New-Item -ItemType Directory -Path $ExtractedFolderPath -Force | Out-Null
            Write-Log "Extracting downloaded Office setup zip to $ExtractedFolderPath"
            Expand-Archive -Path $DownloadedZipPath -DestinationPath $ExtractedFolderPath -Force
        }


    }catch{

        Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END | Accessing custom Office zip from private share failed. Exit code returned: $_" "ERROR"
        Exit 1
        
    }



} Catch {

    Write-Log "SCRIPT: $ThisFileName | END | .NET install failed. There may be another version of .NET 8 Desktop Runtime already installed preventing rollback to 8.0.15. Code: $_" "ERROR"
    Exit 1

}

if ($InstallMode -eq "WinGet") {

    Write-Log "========================================"
    Write-Log "SCRIPT: $ThisFileName | 3. Install Office using WinGet"
    Write-Log "========================================"

    Try {

        Write-Log "SCRIPT: $ThisFileName | Attempting to install DCU"
        #Powershell.exe -executionpolicy remotesigned -File $WinGetInstallerScript -AppName "DellCommandUpdate" -AppID "Dell.CommandUpdate" -WorkingDirectory $WorkingDirectory
        & $WinGetInstallerScript -AppName "Microsoft_Office" -AppID "Microsoft.Office" -WorkingDirectory $WorkingDirectory
        if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

    } Catch {

        Write-Log "SCRIPT: $ThisFileName | END | Failed to install DCU. Code: $_" "ERROR"
        Exit 1


    }

} else {

    Write-Log "========================================"
    Write-Log "SCRIPT: $ThisFileName | 3. Install Office using Custom Setup Zip"
    Write-Log "========================================"

    Try {

        Write-Log "SCRIPT: $ThisFileName | Attempting to install Office using Custom Setup Zip"
        # Powershell.exe -executionpolicy remotesigned -File $WinGetInstallerScript -AppName "Microsoft_Office" -AppID "Microsoft.Office" -WorkingDirectory $WorkingDirectory -CustomSetupZipBlobPath $CustomSetupZipBlobPath
        
        Push-Location

        Set-Location -Path $ExtractedFolderPath

        # Run the setup.exe with appropriate arguments
        $SetupExePath = Join-Path -Path $ExtractedFolderPath -ChildPath "setup.exe"

        # $SetupArguments = "/download $ConfigFileName"
        Write-Log "SCRIPT: $ThisFileName | Running setup.exe with arguments: /download $ConfigFileName"
        $output = & $SetupExePath /download $ConfigFileName
        foreach ($line in $output) {Write-Log "OFFICE_SETUP: $line"}
        if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }
        Write-Log ""
        # $SetupArguments = "/configure $ConfigFileName"
        Write-Log "SCRIPT: $ThisFileName | Running setup.exe with arguments: /configure $ConfigFileName"
        $output = & $SetupExePath /configure $ConfigFileName
        foreach ($line in $output) {Write-Log "OFFICE_SETUP: $line"}
        if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }
        Write-Log ""

        Pop-Location

        # Test the installation

        & $AppDetectionScriptPath -AppToDetect "Microsoft_Office" -DisplayName "Microsoft 365 Apps for enterprise - en-us" -WorkingDirectory $WorkingDirectory -DetectMethod "MSI_Registry"
        if ($LASTEXITCODE -ne 0) { throw "Application detection failed" } else {

            Write-Log "SCRIPT: $ThisFileName | Office installation verified successfully." "SUCCESS"

        }

    } Catch {

        Write-Log "SCRIPT: $ThisFileName | END | Failed to install Office using Custom Setup Zip. Code: $_" "ERROR"
        Exit 1
    }

}

Write-Log "========================================"

Write-Log "SCRIPT: $ThisFileName | END " "SUCCESS"
Exit 0