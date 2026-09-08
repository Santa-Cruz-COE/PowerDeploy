# Microsoft Office - Full Clean Install

Param(

    [Parameter(Mandatory=$true)]
    [String]$WorkingDirectory,

    #$CustomSetupZipBlobPath, # if this is not supplied the WinGet will be used

    # $ConfigFileName = "configuration.xml",

    [String]$IncludedApps = "Excel,Word,PowerPoint", # Can be 'All', "Excel,Word,PowerPoint", etc
    $LanguageCode = "en-us", # takes whatever real language code for office you supply
    
    #[String]$VerboseLogs = $True,
    [int]$timeoutSeconds = 900 # Timeout in seconds (300 sec = 5 minutes)

)

### Other Vars ###

$ThisFileName = $MyInvocation.MyCommand.Name

#$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$RepoRoot = Split-Path -Path $PSScriptRoot -Parent
#$WorkingDirector = (Resolve-Path "$PSScriptRoot\..\..").Path

# $WorkingDirectory = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent


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

# Process the excluded apps
[Array]$TotalPossibleApps='Excel', 'Word', 'PowerPoint', 'Access', 'Groove', 'Lync', 'OneDrive', 'OneNote', 'Outlook', 'Publisher', 'Teams', 'Bing'
[Array]$ExcludedApps
[Array]$IncludedAppsArray = $IncludedApps -Split ',\s?'


if ($IncludedAppsArray -eq 'All') {

    $ExcludedApps = $null

} else {

    ForEach ($PossibleApp in $TotalPossibleApps){

        $Match = $False

        ForEach ($IncludedApp in $IncludedAppsArray){

            Write-Host "Checking if $PossibleApp matches $IncludedApp..."

            if ($PossibleApp -Match $IncludedApp){

                $Match = $True

                Write-Host "Match!"

            }

        }

        if ($Match -eq $False){

            Write-Host "Adding $PossibleApp to exlcusion list"
            [Array]$ExcludedApps += $PossibleApp

        }

    }

}

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

function InstallCheck {


    # $AppPackagesToRemove = @(

    #     "Microsoft.OfficePushNotificationUtility",
    #     "Microsoft.Office.ActionsServer",
    #     "Microsoft.MicrosoftOfficeHub"

    # )

    # $CIMtoUninstall = @(

    #     "Office 16 Click-to-Run Extensibility Component"

    # )

    $RegistryItems = @(

        "Office 16 Click-to-Run Extensibility Component",
        "Aplicaciones de Microsoft 365 para empresas - es-mx",
        "Microsoft 365 Apps for enterprise - en-us"

    )


    $Found = $False

    ForEach ($DisplayName in $RegistryItems){

        Try {
            & $AppDetectionScriptPath -AppToDetect "$DisplayName" -WorkingDirectory $WorkingDirectory -DisplayName $DisplayName -DetectMethod "MSI_Registry"
            $Result = $LASTEXITCODE
        } Catch {
            $Found = "Error: $_"
        }

        if ($Result -eq 0) {
            $Found = $True
        } elseif ($Result -eq 1) {
            $Found = $False
        } else {$Found = "Error"}

    }

    Return $Found

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

# If($CustomSetupZipBlobPath -ne $null -and $CustomSetupZipBlobPath -ne "") {

#     $InstallMode = "CustomAzureBlobSetup"

# } else {

#     $InstallMode = "WinGet"

# }


Write-Log "===== Preconfigured App Installer  ====="

Write-Log "Install App: MS Office"
Write-Log "Install Method: Full Clean (Multiple steps)"
Write-Log ""
Write-Log "Apps to include:"
ForEach ($app in $IncludedAppsArray){Write-Log " - $App"}
Write-Log ""
Write-Log "Apps to exlude:"
ForEach ($App in $ExcludedApps){Write-Log " - $App"}
Write-Log ""
# Write-Log "Steps:"
# Write-Log "  Attempt clean uninstall of pre-existing installations of MS Office"
# Write-Log "  Install Office using $InstallMode"

Write-Log "LOG PATH: $LogPath"

###

# Define a temporary working directory
$workDir = "$WorkingDirectory\TEMP\Downloads\Office\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
if (!(Test-Path $workDir)) { New-Item -ItemType Directory -Path $workDir -Force | Out-Null }
$setupExe = "$workDir\setup.exe"


$odtExe = "$workDir\odt_installer.exe"

Write-Log "Downloading the Office Deployment Tool..."
Try {

    $Success = $False

    # Force TLS 1.2 to ensure the connection to Microsoft isn't rejected
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Write-Log "Will attempt to locate the latest Office Deployment Tool URL..."

    # 1. Hit the main Details page instead of the dead Confirmation page
    Write-Log "Downloading the download page..."
    $downloadPage = "https://www.microsoft.com/en-us/download/details.aspx?id=49117"
    $webResponse = Invoke-WebRequest -Uri $downloadPage -UseBasicParsing

    # 2. Extract the direct .exe link using Regex on the raw HTML
    # This avoids the .Links property issue and grabs the CDN link directly
    $pattern = '(https://[^"''\s>]+officedeploymenttool_[^"''\s>]+\.exe)'
    
    if ($webResponse.Content -match $pattern) {
        $directLink = $Matches[1]
        Write-Log "Found direct link: $directLink"
    } else {
        Throw "Could not scrape the direct download link from the download page. No link present."
    }

    # 3. Download the actual executable
    Write-Log "Downloading actual ODT executable from Microsoft CDN..."
    # Ensure $workDir is defined earlier in your script, or replace it with a hardcoded path
    $odtExe = "$workDir\odt_installer.exe" 
    Invoke-WebRequest -Uri $directLink -OutFile $odtExe -UseBasicParsing

    $Counter = 3
    While ($Counter -ne 0){

        $Counter--

        Write-Log "Waiting for system to refresh..."
        Start-Sleep -Seconds 3
        if (!(Test-Path $odtExe)){
            Write-Log "odt_installer.exe not found..." "ERROR"
        } else {

            Write-Log "Downloaded installer confirmed to exist!"
            $Success = $True
            $Counter = 0
        }

    }

    If ($Success -eq $False){
        Throw "odt_installer.exe not found at $odtExe!"
    }


} Catch {

    Write-Log "Download of Office Deployment Tool failed: $_" "ERROR"
    Exit 1

}



# 3. Extract the tool silently to get setup.exe
Write-Log "Extracting setup.exe..." 
Start-Process -FilePath $odtExe -ArgumentList "/quiet /extract:`"$workDir`"" -Wait -NoNewWindow
Start-Sleep -Seconds 3
if (Test-Path $setupExe) { 

    Write-Log "Setup.exe confirmed to exist. Extraction successful."

} else {

    Write-Log "Setup.exe not confirmed to exist at expected location: $setupExe" "ERROR"

    Exit 1

}

# Check if Office apps are installed
Write-Log "Checking if Office apps are already installed to determine if uninstall is necessary..."
$Check = InstallCheck

if ($Check -eq $True){

    Write-Log "Previous Office installation found. Will move forward with uninstallation."

} elseif ($Check -eq $False) {

    Write-Log "No previous Office installation found. Will skip uninstallation."

} else {

    Write-Log "Error encountered while checking: $Check" "ERROR"

    Exit 1

}

# TODO: Kill all Office/ Office install processes

### Uninstall Office
if ($Check -eq $True){


    # Create the uninstall.xml configuration file
    $xmlPath = "$workDir\uninstall.xml"

$xmlContent = @"
<Configuration>
  <Remove All="TRUE" />
  <RemoveMSI />
  <Display Level="None" AcceptEULA="TRUE" />
</Configuration>
"@

    Write-Log "Creating uninstall.xml..."
    Set-Content -Path $xmlPath -Value $xmlContent

    # Execute the uninstallation

    Write-Log "Uninstalling Microsoft Office silently. This may take a few minutes..." "WARNING"

    # TODO: introduce a timer

    # Run setup.exe with the uninstall config and wait for it to finish
    Try {

        Start-Process -FilePath $setupExe -ArgumentList "/configure `"$xmlPath`"" -Wait -NoNewWindow

    } Catch {

        Write-Log "Error encountered during uninstallation: $_"

    }

    Write-Log "Uninstallation successfully triggered and completed!" "SUCCESSS"

    Write-Log "Now checking for if uninstall was successful..."

    $Check = InstallCheck

    if ($Check -eq $True){

        Write-Log "Previous Office installation found. Uninstallation failed." "ERROR"
        Exit 1

    } elseif ($Check -eq $False) {

        Write-Log "No Office installation found. Uninstall success." "SUCCESS"

    } else {

        Write-Log "Error encountered while checking: $Check" "ERROR"

        Exit 1

    }

}

# TODO: Run another check
# TODO: If check is positive, run another install method

### Install Office

Write-Log "Now moving on to install office"
## Installer XML
$xmlPath = "$workDir\install.xml"

# Initialize an empty array
$xmlLines = @()

# Start building the XML line by line
$xmlLines += '<Configuration>'
$xmlLines += '  <Add OfficeClientEdition="64" Channel="Current">'

# Teams Logic
if ($IncludedApps -notcontains "Teams" -or $IncludedApps -ne "All"){
    $xmlLines += '    <Product ID="O365ProPlusEEANoTeamsRetail">'
} else {
    $xmlLines += '    <Product ID="O365ProPlusRetail">'
}

# Language
$LanguageLine = '      <Language ID="'+$LanguageCode+'" />'
$xmlLines += $LanguageLine

# Add exclusions to XML
if ($ExcludedApps -ne $null){
    foreach ($ExcludedApp in $ExcludedApps){
        # Notice we use double quotes here so the $ExcludedApp variable expands properly
        $xmlLines += "      <ExcludeApp ID=`"$ExcludedApp`" />" 
    }
}

# Finish XML
$xmlLines += '    </Product>'
$xmlLines += '  </Add>'
$xmlLines += '  <Display Level="None" AcceptEULA="TRUE" />'
$xmlLines += '</Configuration>'

Write-Log "Creating install.xml..."

# Set-Content automatically handles putting each array item on a new line!
$xmlLines | Set-Content -Path $xmlPath -Encoding UTF8
Write-Log "Installing Microsoft Office silently. This may take a few minutes..." "WARNING"
# TODO: introduce a timer?

# Run setup.exe with the uninstall config and wait for it to finish
Try {

    # TODO: Introduce a timer

    Start-Process -FilePath $setupExe -ArgumentList "/configure `"$xmlPath`"" -Wait -NoNewWindow

    # Hunt down the generated logs and move them to your custom folder
    # ODT names logs starting with the machine name (e.g., MACHINENAME-20260318-1200.log)
    $tempPaths = @($env:TEMP, "$env:windir\Temp")
    $LogFolder = "$LogRoot\Installer_Logs"
    Get-ChildItem -Path $tempPaths -Filter "$env:COMPUTERNAME*.log" -ErrorAction SilentlyContinue | `
        Where-Object { $_.LastWriteTime -ge (Get-Date).AddMinutes(-60) } | `
        Copy-Item -Destination $LogFolder -Force

    Write-Log "Installation complete. Logs moved to $LogFolder"

} Catch {

    Write-Log "Error encountered during installation: $_"

}

Write-Log "Installation successfully triggered and completed!" "SUCCESSS"

# Check for installation

Write-Log "Checking if install was successful..."

$Check = InstallCheck

    if ($Check -eq $True){

        Write-Log " Office installation found. Install success!" "SUCCESS"


    } elseif ($Check -eq $False) {

        Write-Log "No Office installation found. Install success." "ERROR"
        Exit 1

    } else {

        Write-Log "Error encountered while checking: $Check" "ERROR"

        Exit 1

    }

# 6. (Optional) Clean up the working directory after we are done
# Write-Host "Cleaning up temporary files..." -ForegroundColor Cyan
# Remove-Item -Path $workDir -Recurse -Force
# Write-Host "Done." -ForegroundColor Green

Write-Log "========================================"

Write-Log "SCRIPT: $ThisFileName | END " "SUCCESS"
Exit 0