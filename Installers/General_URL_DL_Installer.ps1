Param(

    [string]$TargetAppName,
    [string]$DisplayName,
    [string]$DownloadURL,
    [string]$DownloadType, # e.g. "EXE", "ZIP", etc.
    [string]$InstallType, # e.g. "MSI", "EXE", etc.
    [string]$ExtractedPathFromDownloadRoot, # Only needed if DownloadType is ZIP - this is the relative path from the root of the extracted ZIP to the installer file (e.g. "Adobe Acrobat/AcroPro.msi")
    [string]$InstallArgs, # Optional custom install arguments to pass to the installer
    [int[]]$ExpectedExitCodes = @(0) # Optional array of expected exit codes for EXE installers (default is 0 for success) # NOTE: UNTESTED

)


##########
## VARS ##
##########

if($TargetAppName -eq "" -or $TargetAppName -eq $null){
    Write-Log "No TargetAppName specified. Exiting." -ForegroundColor Red
    Exit 1
}

$ProgressPreference = 'SilentlyContinue' # for faster web invoke downloads without progress bars

$RepoRoot = (Split-Path -Path $PSScriptRoot -Parent)

$WorkingDirectory = Split-Path -Path $RepoRoot -Parent

#$LocalJSONpath = "$WorkingDirectory\TEMP\Downloads\ApplicationData.json"

$PublicJSONpath = "$RepoRoot\Templates\ApplicationData_TEMPLATE.json"

$ThisFileName = $MyInvocation.MyCommand.Name

$LogRoot = "$WorkingDirectory\Logs\Installer_Logs"

$TimeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'

$LogPath = "$LogRoot\$ThisFileName.$TargetAppName._Log_$TimeStamp.log"

$OrgRegReader_ScriptPath = "$RepoRoot\Templates\OrganizationCustomRegistryValues-Reader_TEMPLATE.ps1"

$General_WinGet_Installer_ScriptPath = "$RepoRoot\Installers\General_WinGet_Installer.ps1"

$DownloadAzureBlobSAS_ScriptPath = "$RepoRoot\Downloaders\DownloadFrom-AzureBlob-SAS.ps1"

$MSIinstallScriptPath = "$RepoRoot\Installers\General_MSI_Installer.ps1"

$EXEInstallScriptPath = "$RepoRoot\Installers\General_EXE_Installer.ps1"

$AppDetect_ScriptPath = "$RepoRoot\Templates\Detection-Script-Application_TEMPLATE.ps1"

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


##########
## MAIN ##
##########


Write-Log "SCRIPT: $ThisFileName | START"
Write-Log ""
Write-Log "Received parameters:"
Write-Log "TargetAppName: $TargetAppName"
Write-Log "DownloadURL: $DownloadURL"
Write-Log "DownloadType: $DownloadType"
Write-Log "InstallType: $InstallType"
Write-Log "ExtractedPathFromDownloadRoot: $ExtractedPathFromDownloadRoot"
Write-Log "InstallArgs: $InstallArgs"
Write-Log "ExpectedExitCodes: $($ExpectedExitCodes -join ', ')"
Write-Log "WorkingDirectory: $WorkingDirectory"
Write-Log ""

Write-Log "SCRIPT: $ThisFileName | Checking if app is already installed..."
& $AppDetect_ScriptPath -AppToDetect $TargetAppName -WorkingDirectory $WorkingDirectory -DisplayName $DisplayName -SkipWinGet $SkipWinGet -DetectMethod "MSI_Registry"
if($LASTEXITCODE -eq 0){
    Write-Log "SCRIPT: $ThisFileName | END | App is already installed. Exiting with code 0." "SUCCESS"
    Exit 0
} else {
    Write-Log "SCRIPT: $ThisFileName | App is not installed. Proceeding with installation..." "WARNING"
}

# Download the application from a URL
#$DownloadURL = $AppData.DownloadURL # Shouldn't be needed


# $DownloadURL = "https://prod-rel-ffc-ccm.oobesaas.adobe.com/adobe-ffc-external/core/v1/wam/download?sapCode=KCCC&wamFeature=nuj-live"

$Response = Invoke-WebRequest -Uri $DownloadURL -Method Head -UseBasicParsing
$ContentDisposition = $Response.Headers['Content-Disposition']

# Content-Disposition looks like: attachment; filename="CreativeCloudSetup.exe"
if ($ContentDisposition -match 'filename="?([^"]+)"?') {
    $FileName = $Matches[1]
} else {
    # Fallback to using the last segment of the URL if Content-Disposition header is not present or doesn't contain a filename
    $FileName = Split-Path $DownloadURL -Leaf
}

Write-Log "Detected Filename: $FileName"


# $FileNameFromURL = Split-Path $DownloadURL -Leaf

if (!(Test-Path "$WorkingDirectory\TEMP\Downloads\")){

    Write-Log "SCRIPT: $ThisFileName | Creating download directory at: $WorkingDirectory\TEMP\Downloads\"

    New-Item -ItemType Directory -Path "$WorkingDirectory\TEMP\Downloads\" -Force | Out-Null
}

$DownloadPath = "$WorkingDirectory\TEMP\Downloads\$TimeStamp.$fileName"

Write-Log "SCRIPT: $ThisFileName | Attempting to download application from URL: $DownloadURL"

Try {
    Invoke-WebRequest -Uri $DownloadURL -OutFile $DownloadPath -UseBasicParsing
    Write-Log "SCRIPT: $ThisFileName | Successfully downloaded application to: $DownloadPath"
} catch {
    Write-Log "SCRIPT: $ThisFileName | END | Failed to download application from URL: $_" "ERROR"
    Exit 1
}

# Determine if file downloaded successfully
if (Test-Path $DownloadPath) {
    Write-Log "SCRIPT: $ThisFileName | Download verified. File exists at: $DownloadPath"
} else {
    Write-Log "SCRIPT: $ThisFileName | END | Download failed. File does not exist at: $DownloadPath" "ERROR"
    Exit 1
}

If ($DownloadType -eq "ZIP"){

    # $tempname = $($FileNameFromURL -replace '.zip$', '')
    # if ($tempname -eq $null -or $tempname -eq ""){

    #     $ExtractedPath = "$WorkingDirectory\TEMP\Extracted\$TimeStamp.$tempname"

    # } else {

    #     $ExtractedPath = "$WorkingDirectory\TEMP\Extracted\$TimeStamp.$TargetAppName"

    # }

    
    $ExtractedPath = "$WorkingDirectory\TEMP\Extracted\$TimeStamp.$fileName"

    # Extract the ZIP file to a temporary location
    Write-Log "SCRIPT: $ThisFileName | Extracting to path: $ExtractedPath"

    # Create the extracted path directory if it doesn't exist
    if (!(Test-Path $ExtractedPath)) {
        New-Item -ItemType Directory -Path $ExtractedPath
    }

    # Extract the ZIP file using PowerShell's built-in functionality
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($DownloadPath, $ExtractedPath)

    Write-Log "SCRIPT: $ThisFileName | Successfully extracted ZIP file to: $ExtractedPath"

    $InstallerPath = "$ExtractedPath\$ExtractedPathFromDownloadRoot"

    $InstallerPath = $InstallerPath.Replace('/', '\')

    if (Test-Path $InstallerPath) {
        Write-Log "SCRIPT: $ThisFileName | Installer found at expected path: $InstallerPath"

    } else {
        Write-Log "SCRIPT: $ThisFileName | END | Installer not found at expected path: $InstallerPath" "ERROR"
        Exit 1  
    }

} else {

    $InstallerPath = $DownloadPath

}

# Install the application using the appropriate method based on the file type (e.g., MSI, EXE)
if ($InstallType -eq "MSI"){


    # Install the MSI

    Write-Log "SCRIPT: $ThisFileName | Calling General_MSI_Installer script to install $FileNameFromURL..."

    # $MSIPath2 = $MSIPathFromContainerRoot.Replace('/', '\')

    Try {
        if ($InstallArgs) {
            Write-Log "SCRIPT: $ThisFileName | Using custom install arguments: $InstallArgs"
            & $MSIinstallScriptPath -MSIPath "$InstallerPath" -InstallArgs $InstallArgs -WorkingDirectory $WorkingDirectory -AppName $TargetAppName -DisplayName $DisplayName

        } else {
            & $MSIinstallScriptPath -MSIPath "$InstallerPath" -WorkingDirectory $WorkingDirectory -AppName $TargetAppName -DisplayName $DisplayName

        }
    } Catch {

        Write-Log "SCRIPT: $ThisFileName | END | MSI installation failed: $_" "ERROR"
        Exit 1

    }

    Write-Log "SCRIPT: $ThisFileName | END"



} elseif ($InstallType -eq "EXE"){

        
    # Install the EXE

    Write-Log "Calling General_EXE_Installer script to install $FileNameFromURL..."

    # $EXEPath2 = $EXEPathFromContainerRoot.Replace('/', '\')

    Try {

        # & $EXEinstallScriptPath -EXEPath "$InstallerPath" -ArgumentList $InstallArgs -WorkingDirectory $WorkingDirectory -AppName $TargetAppName -DisplayName $DisplayName -ExpectedExitCodes $ExpectedExitCodes


        if ($InstallArgs) {
            Write-Log "SCRIPT: $ThisFileName | Using custom install arguments: $InstallArgs"
            & $EXEinstallScriptPath -EXEPath "$InstallerPath" -InstallArgs $InstallArgs -WorkingDirectory $WorkingDirectory -AppName $TargetAppName -DisplayName $DisplayName -ExpectedExitCodes $ExpectedExitCodes

        } else {
            & $EXEinstallScriptPath -EXEPath "$InstallerPath" -WorkingDirectory $WorkingDirectory -AppName $TargetAppName -DisplayName $DisplayName -ExpectedExitCodes $ExpectedExitCodes


        }

        if($LASTEXITCODE -ne 0){Throw $LASTEXITCODE }

    } Catch {

        Write-Log "SCRIPT: $ThisFileName | END | EXE installation failed: $_" "ERROR"
        Exit 1

    }


    # Write-Log "SCRIPT: $ThisFileName | END"


} else {
    Write-Log "Unknown InstallType specified in JSON: $InstallType" "ERROR"
    Exit 1
}

if($LASTEXITCODE -ne 0){

    Write-Log "SCRIPT: $ThisFileName | END | Installation completed with unexpected exit code: $LASTEXITCODE" "ERROR"
    
    Throw $LASTEXITCODE 

} else {
    Write-Log "SCRIPT: $ThisFileName | END | Installation completed successfully with exit code: $LASTEXITCODE" "SUCCESS"
}