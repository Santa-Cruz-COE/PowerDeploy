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
# Path to Adobe Uninstall Cleanup script
$AdobeUninstallCleanup_ScriptPath = "$RepoRoot\Uninstallers\Adobe_Uninstaller_Suite\Uninstall-AllAdobeProducts-FullClean.ps1"
# Path to Convert-VendorPack-ToDriverZip.ps1
$ConvertVendorPackToDriverZip_ScriptPath = "$RepoRoot\Other_Tools\Convert-VendorPack-ToDriverZip.ps1"
# Path to the Intune Graph helper library (dot-sourced below: functions only, no side effects)
$InTuneGraphHelperScriptPath = "$RepoRoot\Other_Tools\InTune-GraphAPI_Helpers.ps1"
# Path to the Intune uploader (dot-sourced below: its script body is skipped when dot-sourced)
$IntuneUploadScriptPath = "$RepoRoot\Other_Tools\Upload-InTuneWin32App.ps1"
# Path to the WinGet description lookup used for app Descriptions (dot-sourced below: functions only)
$WinGetDescriptionScriptPath = "$RepoRoot\Other_Tools\Get-WinGetAppDescription.ps1"
# Standard icon for every printer published to Intune (plain on purpose: users see "a printer")
$PrinterIconPath = "$RepoRoot\Templates\Printer-Icon.png"
# SVG-to-PNG converter for app icons: resvg v0.47.0 (MIT/Apache-2.0, github.com/linebender/resvg, the last
# release with a Windows build). Pinned by hash: a different file is never run. Update both lines together.
$SvgConverterExePath = "$RepoRoot\Other_Tools\resvg\resvg.exe"
$SvgConverterExeSha256 = '433A7C744CFF561ED64FCF73C7C04E239D7A07AE5F0AADBF1BA8471D63707402'
# Path to the shared printer/Intune builders (dot-sourced below: functions only)
$PrinterIntuneHelpersScriptPath = "$RepoRoot\Other_Tools\Printer-Intune_Helpers.ps1"
# Path to the bulk printer tools: bulk create from PrinterData.json, bulk delete (dot-sourced below: functions only)
$PrinterIntuneBulkScriptPath = "$RepoRoot\Other_Tools\Printer-IntuneBulk.ps1"
# Path to the built-in sheet editor the bulk tools use when no program opens .csv files (dot-sourced below: functions only)
$CsvGridEditorScriptPath = "$RepoRoot\Other_Tools\CsvGrid-Editor_Helpers.ps1"

# ---------------------------------------------------------------------------
# Optional Intune upload feature (spec 3): loaded at SCRIPT scope, functions only
# ---------------------------------------------------------------------------
# Two reasons this lives here rather than inside a function:
#
#   1. Dot-sourcing inside a function defines those functions in that function's local scope, and
#      they vanish when it returns. That fails in the strangest possible way: a caller that already
#      loaded the library works, while a plain "run Setup.ps1" cannot see a single helper.
#   2. Both files are safe to dot-source. The library is functions only, and the uploader's script
#      body is guarded by $script:PDUploaderDotSourced, so importing it never runs an upload,
#      never prints anything, and never writes a log file. Neither file declares a top-level
#      param() block, because dot-sourcing a script that does writes every one of its parameters
#      into THIS scope as $null - which would silently erase live wizard state.
#
# A failure here is recorded, not fatal: guided manual publishing must keep working when the
# feature files are missing or the helper library cannot be read, and the menu says why.

$GraphUploadAvailable  = $false
$GraphUploadLoadError  = $null

try {

    if (-not (Test-Path -LiteralPath $InTuneGraphHelperScriptPath)) {
        throw "The Graph helper library was not found at $InTuneGraphHelperScriptPath"
    }
    . $InTuneGraphHelperScriptPath

    if (-not (Test-Path -LiteralPath $IntuneUploadScriptPath)) {
        throw "The Intune uploader was not found at $IntuneUploadScriptPath"
    }
    . $IntuneUploadScriptPath

    if (-not (Get-Command -Name 'Invoke-PDIntuneUpload' -CommandType Function -ErrorAction SilentlyContinue)) {
        throw "Upload-InTuneWin32App.ps1 loaded without defining Invoke-PDIntuneUpload; it may be from a different version."
    }
    if (-not (Get-Command -Name 'Get-PDGraphCredential' -CommandType Function -ErrorAction SilentlyContinue)) {
        throw "InTune-GraphAPI_Helpers.ps1 loaded without defining its credential functions; it may be from a different version."
    }

    # Give the uploader its own detailed log (same folder and name as a command-line run). Nothing
    # is written until an upload actually runs, so importing still never creates a log file.
    $script:PDUploadLogPath = "$WorkingDirectory\Logs\Other_Logs\Upload-InTuneWin32App.ps1._Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

    $GraphUploadAvailable = $true

} Catch {

    $GraphUploadLoadError = $_.Exception.Message

}

# Optional WinGet description lookup (spec 6), loaded the same way and kept separate so a problem
# here only costs the description (it falls back to N/A), never the upload or the manual path.
$WinGetDescriptionLoadError = $null

try {

    if (-not (Test-Path -LiteralPath $WinGetDescriptionScriptPath)) {
        throw "The WinGet description lookup was not found at $WinGetDescriptionScriptPath"
    }
    . $WinGetDescriptionScriptPath

    if (-not (Get-Command -Name 'Get-WinGetAppDescription' -CommandType Function -ErrorAction SilentlyContinue)) {
        throw "Get-WinGetAppDescription.ps1 loaded without defining Get-WinGetAppDescription."
    }

} Catch {

    $WinGetDescriptionLoadError = $_.Exception.Message

}

# Shared printer/Intune builders, loaded the same way. Both Intune wizards (printer and app) build
# their Description/Notes with these, so a load failure is shown straight away instead of surfacing
# later as "command not found" halfway through a wizard.
$PrinterIntuneHelpersLoadError = $null

try {

    if (-not (Test-Path -LiteralPath $PrinterIntuneHelpersScriptPath)) {
        throw "The shared printer builders were not found at $PrinterIntuneHelpersScriptPath"
    }
    . $PrinterIntuneHelpersScriptPath

    if (-not (Get-Command -Name 'New-PDPrinterIntuneMetadata' -CommandType Function -ErrorAction SilentlyContinue)) {
        throw "Printer-Intune_Helpers.ps1 loaded without defining New-PDPrinterIntuneMetadata; it may be from a different version."
    }

} Catch {

    $PrinterIntuneHelpersLoadError = $_.Exception.Message
    Write-Host "WARNING: $PrinterIntuneHelpersLoadError" -ForegroundColor Yellow
    Write-Host "WARNING: The Intune setup wizards for printers and apps will not work until this is fixed." -ForegroundColor Yellow

}

# Bulk printer tools (bulk create / bulk delete). Optional like the uploader: a problem here only
# disables the two bulk menu entries, which say why.
$PrinterIntuneBulkLoadError = $null

try {

    if (-not (Test-Path -LiteralPath $PrinterIntuneBulkScriptPath)) {
        throw "The bulk printer tools were not found at $PrinterIntuneBulkScriptPath"
    }
    . $PrinterIntuneBulkScriptPath

    if (-not (Get-Command -Name 'Invoke-PDPrinterBulkCreate' -CommandType Function -ErrorAction SilentlyContinue)) {
        throw "Printer-IntuneBulk.ps1 loaded without defining Invoke-PDPrinterBulkCreate; it may be from a different version."
    }

} Catch {

    $PrinterIntuneBulkLoadError = $_.Exception.Message

}

# Built-in sheet editor (optional): without it the bulk tools fall back to Notepad when this PC has
# no program for .csv files.
$CsvGridEditorLoadError = $null

try {

    if (-not (Test-Path -LiteralPath $CsvGridEditorScriptPath)) {
        throw "The built-in sheet editor was not found at $CsvGridEditorScriptPath"
    }
    . $CsvGridEditorScriptPath

    if (-not (Get-Command -Name 'Show-PDCsvGridEditor' -CommandType Function -ErrorAction SilentlyContinue)) {
        throw "CsvGrid-Editor_Helpers.ps1 loaded without defining Show-PDCsvGridEditor; it may be from a different version."
    }

} Catch {

    $CsvGridEditorLoadError = $_.Exception.Message

}

$PublicJSONpath = "$RepoRoot\Templates\ApplicationData_TEMPLATE.json"

$MyCompanyRepoURL = ""
$MyCompanyRepoURLTOKEN = ""
$OfficialPublicRepoURL = "github.com/Santa-Cruz-COE/PowerDeploy"
$Global:TargetRepoNickName = ""
$Global:TargetWorkingDirectory = ""
$Global:DeployMode = "" 

$ExamplePrinterJSON = get-content "$RepoRoot\Templates\PrinterData_TEMPLATE.json" | Out-String

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
        [string]$Level = "INFO",
        # Write to the log file only. Used by Write-LogBlock, which shows the text on screen itself.
        [switch]$LogOnly
    )

    # Ensure log directory exists
    $logDir = Split-Path $LogPath -Parent
    if (!(Test-Path $logDir)) {
       #Write-Host "Creating log directory at $logDir" -ForegroundColor Green
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    


    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    if ($Level -eq "INFO2") {
        $logEntry = "[$timestamp] [INFO] $Message"
    } else {
        $logEntry = "[$timestamp] [$Level] $Message"
    }
    
    
    if (-not $LogOnly) { switch ($Level) {
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "DRYRUN"  { Write-Host $logEntry -ForegroundColor Cyan }
        "INFO"    { Write-Host $logEntry -ForegroundColor Cyan }
        "INFO2"    { Write-Host $logEntry }

        default   { Write-Host $logEntry }
    } }
    

    # Resilient log write. A real-time AV/EDR filter driver (Defender, CrowdStrike, etc.)
    # can briefly grab a freshly-created log file mid-burst to scan it. The old bare
    # Add-Content had no retry, so a single locked moment threw "Stream was not readable"
    # and spammed the console for the rest of the (sub-second) run. Retry a few times
    # against an atomic append, and never let a logging failure surface as an error.
    # Encoding::Default (system ANSI) matches the prior Add-Content behavior so existing
    # log tooling sees no change other than resilience.
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

function Write-LogBlock {
    param([AllowNull()][object]$Text)

    # Shows a block exactly as-is (no timestamp prefix, so it can be copied straight into the Intune
    # portal) and records the same text in the log, one line at a time. Never pass command text or
    # anything else that can carry a repository token - that stays on screen only.
    $Block = [string]$Text
    Write-Host $Block
    foreach ($Line in ($Block -split "`r?`n")) {
        if (-not [string]::IsNullOrWhiteSpace($Line)) { Write-Log "    | $Line" "INFO2" -LogOnly }
    }
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
    Write-Log "     - PUB/DEV"
    Write-Log "     - For TESTING purposes."
    Write-Log "     - Uses official public PowerDeploy repo (DEV branch)" 
    Write-Log "     - For testing public dev code if you are a public developer"
    Write-Log ""

    Write-Log "2 - [PUBLIC-TESTING]:"
    Write-Log "     - PUB/MAIN"
    Write-Log "     - For TESTING purposes."
    Write-Log "     - Uses official public PowerDeploy repo (MAIN branch)"
    Write-Log "     - For testing the latest code before merging it into your own repo."
    Write-Log ""

    Write-Log "3 - [PRIVATE-DEVELOPMENT]:"
    Write-Log "     - PRVT/DEV"
    Write-Log "     - For TESTING purposes."
    Write-Log "     - Uses your organization's custom PowerDeploy repository (DEV branch)"
    Write-Log "     - For testing YOUR dev code if you are a developer of your org repo."

    Write-Log ""

    Write-Log "4 - [PRODUCTION]:"
    Write-Log "     - PRVT/MAIN"
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
                    Write-Log "ERROR: Organization CustomRepoURL is not set in registry. Cannot proceed with PRIVATE-DEVELOPMENT or PRODUCTION mode. Please set your custom org repo by forking the public repo and then set the registry appropriately with your custom URL/token using one of these Setup options: OrganizationRegistryEntries--InTune-Setup (for your fleet) or OrganizationRegistryEntries--Local-Setup (for this PC only)" "ERROR"
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
                Write-Log "Let's try again to select the deployment mode." "WARNING"
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

Function Printer--Convert-Vendor-DriverPack {

    Clear

    Write-Log "==========================================================================================="
    Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START"
    Write-Log "==========================================================================================="

    Write-Log ""

    Write-Log "Enter the path of your manufacturer driver pack. ZIP or EXE accepted."

    $PackPath = Read-Host "PATH"

    Write-Host ""
    Try{

        & $ConvertVendorPackToDriverZip_ScriptPath -PackPath $PackPath

    } Catch {

        Throw $_

    }

}

# DONE (still need testing) 1/14/26
function Printer--InTune-Setup{

    # Determine if this is a test or production deployment
    $RepoUrl = Set-URL

    # Select-PrinterFromJSON copies the chosen record's properties into script scope and never
    # clears the ones a record does not have, so a printer without a Location would inherit the
    # previous selection's Location. Clear the optional Intune metadata fields first (spec I04).
    foreach ($StaleField in @('Department', 'Location', 'Model', 'Asset', 'Verified', 'Publisher')) {
        Remove-Variable -Name $StaleField -Scope Script -ErrorAction SilentlyContinue
    }

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

        $script:PrinterSelectionError = $null
        $PrinterName = Select-PrinterFromJSON -DialogueSelection "B"

        # A duplicate PrinterName stops this printer's setup before anything is packaged (spec 12.2);
        # the screen is left as-is so the error stays readable. Setup itself keeps running.
        if ($script:PrinterSelectionError) {
            Write-Log ""
            Write-Log "Printer setup stopped: $($script:PrinterSelectionError)" "ERROR"
            Write-Log "Fix PrinterData.json so each PrinterName appears once, then run this setup again." "WARNING"
            $script:PrinterSelectionError = $null
            Pause
            return
        }

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

    
        Write-Log "These 7 items are required to set up a printer:"
        Write-Log ""
        Write-Log "     1 - Printer Name"
        Write-Log "     2 - Printer IP"
        Write-Log "     3 - Printer Port (Could be same as IP but formatted as full length eg 000.000.000.000)"
        Write-Log "     4 - Printer Driver (Select from list of PresetDrivers in your private JSON or enter a new one)"
        Write-Log ""
        Write-Log "     > Each print driver entry requires the following. If you need to enter a new Printer Driver, the script will help guide you."
        Write-Log "     5 - Printer Driver INF file"
        Write-Log "     6 - Printer Driver Name"
        Write-Log "     7 - Printer Driver Zip Location in Azure Blob (after you upload the driver)"
        Write-Log ""
        # Write-Log "Save these details, as you will need them shortly."
        # Write-Log ""
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
        Write-Log "Next we will navigate to your Azure Blob Storage container to create the required resources (Driver and PrinterData)"
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

    Write-Log "Have you uploaded the required printer driver ZIP file to Azure Blob Storage? If not you will be guided in the next step." "WARNING"
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

    # Write-Log "Have you updated your PrinterData.json file to include your new printer? If not you will be guided in the next step." "WARNING"
    # $Answer2 = Read-Host "(y/n)"

    # if ($Answer2 -ne "y" -and $Answer2 -ne "n") {
    #     Write-Log "Invalid input. Please enter 'y' for yes or 'n' for no." "ERROR"
    #     $Answer2 = Read-Host "(y/n)"
    # }

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
    Write-Log "Would you like to TEST by installing this printer from the JSON on this local machine?" "WARNING"
    $Answer = Read-Host "(y/n)"
    Write-Log ""


        if ($answer -eq "y"){

            Write-Log "Before proceeding, please make sure this printer is not already installed locally on this machine. If it is, please uninstall it first." "WARNING"
            Pause
            Write-Log ""

            Write-Log "Proceeding with local installation test..."

            Write-Log ""


            & Printer--Install-Local -PrinterName $PrinterName

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

        # Install/uninstall commands, detection script, display name, Description, Notes and the upload
        # metadata come from the shared printer builder (Other_Tools\Printer-Intune_Helpers.ps1), the
        # same code the bulk printer tools use, so a printer looks the same however it was published.
        try {
            $PrinterBuild = New-PDPrinterIntuneMetadata -PrinterName $PrinterName `
                -Department $Department -Location $Location -Model $Model -Asset $Asset -PrinterIP $PrinterIP `
                -Verified $Verified -Publisher $publisher `
                -IntuneWinPath $PrinterIntuneWinPath `
                -RepoUrl $RepoURL -RepoNickName $Global:TargetRepoNickName -RepoBranch $Global:RepoBranch `
                -TargetWorkingDirectory $Global:TargetWorkingDirectory -DeployMode $Global:DeployMode `
                -RepoRoot $RepoRoot -IconPath $PrinterIconPath `
                -GenerateInstallCommandPath $GenerateInstallCommand_ScriptPath `
                -Log { param($Message, $Level) Write-Log $Message $Level }
        } Catch {
            # 'No data returned!' was already logged by the builder, exactly as before it moved out.
            if ($_.Exception.Message -ne 'No data returned!') { Write-Log "$($_.Exception.Message)" "ERROR" }
            Exit 1
        }

        # The same local variables this wizard had when the builder was inline (the guided walkthrough
        # below prints several of them).
        foreach ($BuildValues in @($PrinterBuild.InstallValues, $PrinterBuild.UninstallValues)) {
            foreach ($key in $BuildValues.Keys) {
                Set-Variable -Name $key -Value $BuildValues[$key] -Scope Local
            }
        }
        $CurrentGitVer              = $PrinterBuild.SourceCommit
        $PotentialPrinterInTuneName = $PrinterBuild.DisplayName
        $PrinterDescriptionText     = $PrinterBuild.Description
        $PrinterTechnicalNotes      = $PrinterBuild.TechnicalNotes
        $PrinterIntuneMetadata      = $PrinterBuild.Metadata

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

    if ((Read-IntunePublishChoice) -eq '2') {
        if (Invoke-InTuneAutoUpload -Metadata $PrinterIntuneMetadata) { return }
        Clear
        Write-Log "==========================================================================================="
        Write-Log "UPLOAD AND CREATE INTUNE WIN32 APPLICATION (GUIDED)"
        Write-Log "==========================================================================================="
        Write-Log ""
    }

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
    Write-Log " 2 - Upload the .intunewin file located here:"
    Write-LogBlock "`n$PrinterIntuneWinPath`n"
    Write-Log ""   
    Pause
    Write-Log ""  
    Write-Log " 3 - APP INFORMATION:"
    write-log "     - NAME (Pre-made default):"
Write-LogBlock "`n$PotentialPrinterInTuneName`n"
    Write-Log "     - DESCRIPTION (Pre-made default, shown to users in the Company Portal):"

    Write-Host ""
    Write-LogBlock $PrinterDescriptionText
    Write-Host ""

    # Stamped once here, kept in its own variable so the technical block is never stamped twice
    $PrinterManualNotes = Complete-IntuneManualNotes -Notes $PrinterTechnicalNotes

    Write-Log "     - NOTES (Pre-made default, admins only - near the bottom of the App information page):"
    Write-Host ""
    Write-LogBlock $PrinterManualNotes
    Write-Host ""

    Write-Log "     - PUBLISHER: Your organization name (default is PowerDeploy)"
    Write-Log "     - VERSION: "
    
    Write-LogBlock "`n$CurrentGitVer`n"
    
    Write-Log "     - Category: Printers (Create this category if you do not already have, it will take some time to show up: https://learn.microsoft.com/en-us/intune/intune-service/apps/apps-add#create-and-edit-categories-for-apps)"
    if (Test-Path -LiteralPath $PrinterIconPath) {
        Write-Log "     - LOGO: Select image and upload the standard printer icon:"
        Write-LogBlock "`n$PrinterIconPath`n"
    } else {
        Write-Log "     - Logo: Optional - You could create something with Canva using your organization logo, but standardize it"
    }
    Write-Log ""   
    Pause
    Write-Log ""   
    Write-Log " 4 - PROGRAM:"
    Write-Log "     - Install command:" 
    Write-Log "         - Use the install command found inside this file: $MainInstallCommandTXT" # I don't remember why I named this "main"
    Write-Host ""
    Write-Host "Install Command:"
    Write-Host ""
    Write-Host ((Get-Content -LiteralPath $MainInstallCommandTXT -Raw).TrimEnd())
    Write-Host ""
    Write-Log "     - Uninstall command:" 
    Write-Log "         - Use the uninstall command found inside this file: $UninstallCommandTXT"
    Write-Host ""
    Write-Host "Uninstall Command:"
    Write-Host ""
    Write-Host ((Get-Content -LiteralPath $UninstallCommandTXT -Raw).TrimEnd())
    Write-Host ""
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
    Write-Log "     - Script File: Upload this script:"
    Write-LogBlock "`n$DetectPrinterScript`n"
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
# ---------------------------------------------------------------------------
# Bulk printer tools (logic: Other_Tools\Printer-IntuneBulk.ps1; plan: printer-bulk-tools.buildplan.md)
# ---------------------------------------------------------------------------
# The two menu entries below own every prompt; the library does the work. Neither ever calls exit:
# every failure returns to the main menu.

Function Test-PrinterBulkReady {

    # Shared preconditions for both bulk tools. Returns $true when the tool can run.
    if ($PrinterIntuneHelpersLoadError) {
        Write-Log "The bulk printer tools cannot run: $PrinterIntuneHelpersLoadError" 'ERROR'
        return $false
    }
    if ($PrinterIntuneBulkLoadError) {
        Write-Log "The bulk printer tools cannot run: $PrinterIntuneBulkLoadError" 'ERROR'
        return $false
    }
    if (-not $GraphUploadAvailable) {
        Write-Log "The bulk printer tools use the Intune API, which is not available on this workstation: $GraphUploadLoadError" 'ERROR'
        return $false
    }

    try {
        $Credential = Get-PDGraphCredential
        foreach ($Warning in @($Credential.Warnings)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$Warning)) { Write-Log $Warning 'WARNING' }
        }
    } Catch {
        Show-GraphUploadError -Failure $_
        Write-Log ""
        Write-Log "The upload credential is set up from the main menu with InTuneAPI--Setup-and-Manage." 'WARNING'
        return $false
    }

    return $true
}

Function Open-PrinterBulkSheet {
    param([Parameter(Mandatory = $true)][string]$Path)

    Write-Log "The sheet is here:"
    Write-LogBlock "`n$Path`n"
    try {
        Start-Process -FilePath $Path -ErrorAction Stop
        Write-Log "It has been opened for you (usually in Excel)." "INFO2"
    } Catch {
        Write-Log "It could not be opened automatically. Open it from the path above." 'WARNING'
    }
}

Function Wait-PrinterBulkSheet {

    # $true when the operator says the sheet is saved, $false when they cancel.
    Write-Log ""
    Write-Log "Edit the sheet, SAVE it (keep the CSV format), and close it." 'WARNING'
    $Answer = ([string](Read-Host "Press Enter when it is saved, or type exit to cancel")).Trim()
    return ($Answer -ine 'exit')
}

Function Edit-PrinterBulkSheet {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('Create', 'Delete')][string]$Kind,
        [AllowEmptyCollection()][string[]]$Problems = @()
    )

    # Opens the sheet for editing and waits. $true when it is saved and ready to check, $false when
    # the operator cancels. In order: the PC's own program for .csv files (usually Excel); LibreOffice
    # Calc if it is installed, or offered for install (never installed without a yes); PowerDeploy's
    # built-in editor window; Notepad.
    $Program = $null
    if (Get-Command -Name 'Get-PDCsvAssociatedProgram' -CommandType Function -ErrorAction SilentlyContinue) { $Program = Get-PDCsvAssociatedProgram }

    if ($Program) {
        Open-PrinterBulkSheet -Path $Path
        return (Wait-PrinterBulkSheet)
    }

    $LibreOffice = $null
    if (-not $CsvGridEditorLoadError) {
        $LibreOffice = Find-PDLibreOffice

        # Asked once per Setup session: a "no" is not repeated every time the sheet is re-checked.
        if (-not $LibreOffice -and -not $script:PrinterBulkLibreOfficeDeclined) {
            Write-Log ""
            Write-Log "No program is set up to open .csv files on this PC." 'WARNING'
            Write-Log "PowerDeploy can install LibreOffice (free, open source spreadsheet; about 360 MB download) from its app catalog, and open the sheet in it."
            if (Read-GraphUploadYesNo -Question 'Install LibreOffice now?' -Default $false -Note "Answer n to use PowerDeploy's basic built-in editor instead (you will not be asked again until Setup restarts).") {
                # Installed like any catalog app: the 'LibreOffice' entry in the public catalog
                # (Templates\ApplicationData_TEMPLATE.json, InstallMethod WinGet) through the JSON app
                # installer, exactly what WindowsApp--Install-Local runs for it.
                Write-Log "Installing LibreOffice from the PowerDeploy app catalog (WinGet). This can take several minutes..."
                & $JSONAppInstaller_ScriptPath -TargetAppName 'LibreOffice'
                $InstallExit = $LASTEXITCODE
                $LibreOffice = Find-PDLibreOffice
                if ($LibreOffice) {
                    Write-Log "LibreOffice is installed." 'SUCCESS'
                } else {
                    Write-Log "LibreOffice could not be installed (exit code $InstallExit). The installer logs under Logs\Installer_Logs have the details. Using the built-in editor instead." 'ERROR'
                    $script:PrinterBulkLibreOfficeDeclined = $true
                }
            } else {
                $script:PrinterBulkLibreOfficeDeclined = $true
            }
        }
    }

    if ($LibreOffice) {
        Write-Log ""
        Write-Log "Opening the sheet in LibreOffice Calc:"
        Write-LogBlock "`n$Path`n"
        Write-Log "When you save (Ctrl+S), LibreOffice asks which format to keep: choose 'Use Text CSV Format!'." 'WARNING'
        Write-Log "Then close LibreOffice (or at least this sheet) before pressing Enter here."
        try {
            Start-Process -FilePath $LibreOffice -ArgumentList (Get-PDLibreOfficeCsvArguments -Path $Path) -ErrorAction Stop
            return (Wait-PrinterBulkSheet)
        } Catch {
            Write-Log "LibreOffice could not be started: $($_.Exception.Message). Using the built-in editor instead." 'WARNING'
        }
    }

    if ($CsvGridEditorLoadError) {
        Write-Log "The built-in sheet editor is not available: $CsvGridEditorLoadError" 'WARNING'
    } else {
        if ($Kind -eq 'Create') {
            $Instructions = "Tick Include for every printer to create; untick the ones to leave out.`r`n" +
                            "RequiredGroups: groups the printer is installed on automatically. AvailableGroups: groups that can install it from the Company Portal.`r`n" +
                            "Separate several groups with ';'. Use exact group names or object IDs, or /AllDevices or /AllUsers.`r`n" +
                            "Grey columns are for reference only. To fill many rows at once: select the cells, type the groups in 'Set selected cells to', and press Apply."
            $Editable = @('RequiredGroups', 'AvailableGroups')
            $Flags    = @('Include')
            $Title    = 'PowerDeploy - Bulk create printers'
        } else {
            $Instructions = "Tick Delete for every printer app to delete from Intune. Grey columns are for reference only.`r`n" +
                            "Devices that already have a printer keep it; this only cleans up Intune."
            $Editable = @()
            $Flags    = @('Delete')
            $Title    = 'PowerDeploy - Bulk delete printer apps'
        }

        Write-Log ""
        Write-Log "The sheet opens in PowerDeploy's own editor window." 'WARNING'
        Write-Log "Edit it there and press 'Save and continue'. (If you don't see it, check the taskbar.)"
        $Edited = Show-PDCsvGridEditor -Path $Path -Title $Title -Instructions $Instructions -EditableColumns $Editable -FlagColumns $Flags -Messages $Problems
        if ($Edited.Result -eq 'Saved') { Write-Log "Sheet saved." 'SUCCESS'; return $true }
        if ($Edited.Result -eq 'Cancelled') { return $false }
        Write-Log "The built-in editor could not open: $($Edited.Reason)" 'WARNING'
    }

    Write-Log "Opening the sheet in Notepad instead. Keep the commas and quotes exactly as they are; only change values." 'WARNING'
    Write-LogBlock "`n$Path`n"
    try { Start-Process -FilePath 'notepad.exe' -ArgumentList ('"{0}"' -f $Path) -ErrorAction Stop } Catch { Write-Log "Notepad could not be started. Open the file from the path above." 'WARNING' }
    return (Wait-PrinterBulkSheet)
}

Function Get-PrinterBulkJsonPath {
    param([Parameter(Mandatory = $true)][ValidateSet('Blob', 'Local')][string]$Source)

    # Returns a local PrinterData.json path, or $null when the operator cancels. A failed download
    # offers a local file instead of ending the run.
    if ($Source -eq 'Blob') {

        $DownloadProblem = $null
        if ([string]::IsNullOrWhiteSpace($PrinterDataJSONpath) -or [string]::IsNullOrWhiteSpace($StorageAccountName) -or [string]::IsNullOrWhiteSpace($PrinterContainerSASkey)) {
            $DownloadProblem = "This PC does not have the organization's printer storage settings (PrinterDataJSONpath, StorageAccountName, PrinterContainerSASkey), so PrinterData.json cannot be downloaded."
        } else {
            $parts = $PrinterDataJSONpath -split '/', 2
            $PrinterData_JSON_ContainerName = $parts[0]
            $PrinterData_JSON_BlobName = $parts[1]

            Write-Log "Downloading the current PrinterData.json..."
            & $DownloadAzureBlobSAS_ScriptPath -WorkingDirectory $WorkingDirectory -BlobName $PrinterData_JSON_BlobName -StorageAccountName $StorageAccountName -ContainerName $PrinterData_JSON_ContainerName -SasToken $PrinterContainerSASkey
            $LocalJSONpath = "$WorkingDirectory\TEMP\Downloads\$PrinterData_JSON_BlobName"
            if ($LASTEXITCODE -ne 0) {
                $DownloadProblem = "Downloading PrinterData.json failed (exit code $LASTEXITCODE). The Azure Blob downloader logs have the details."
            } elseif (-not (Test-Path -LiteralPath $LocalJSONpath)) {
                $DownloadProblem = "The download reported success, but the file is not at $LocalJSONpath."
            } else {
                return $LocalJSONpath
            }
        }

        Write-Log $DownloadProblem 'ERROR'
        if (-not (Read-GraphUploadYesNo -Question 'Use a PrinterData.json file on this PC instead?' -Default $false)) { return $null }
    }

    While ($true) {
        $Typed = ([string](Read-Host "Full path to the PrinterData.json file (or exit)")).Trim().Trim('"').Trim("'")
        if ($Typed -ieq 'exit') { return $null }
        if (-not [string]::IsNullOrWhiteSpace($Typed) -and (Test-Path -LiteralPath $Typed -PathType Leaf)) { return $Typed }
        Write-Log "No file was found at '$Typed'." 'ERROR'
    }
}

Function Printer--InTune-BulkCreate {

    Write-Log "==========================================================================================="
    Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START"
    Write-Log "==========================================================================================="
    Write-Log ""
    Write-Log "BULK CREATE PRINTERS IN INTUNE"
    Write-Log ""
    Write-Log "Creates Intune apps for many printers from PrinterData.json in one go:"
    Write-Log "  1 - You get a sheet (CSV) with every printer. Set Include to N (or delete the row) for printers you don't want, and fill in the groups."
    Write-Log "  2 - The sheet is checked: every group must exist, and printers already in Intune (same name, same deployment mode) are found."
    Write-Log "  3 - For printers that already exist you choose: override (the new app is created, then the old one is backed up and deleted) or skip."
    Write-Log "  4 - Nothing is created until you confirm the summary."
    Write-Log ""

    if (-not (Test-PrinterBulkReady)) { Pause; return }

    $RepoUrl = Set-URL

    # --- One question: how to start --------------------------------------------------------------
    # Printer details (IP, driver, department) always come from PrinterData.json; a sheet only holds
    # the operator's choices (which printers, which groups). So a pre-existing sheet still needs the
    # JSON, and gets the current one from blob.
    Write-Log "How do you want to start?" 'WARNING'
    Write-Log ""
    Write-Log "     1 - Start a fresh spreadsheet export from PrinterData.json in Azure Blob (normal)"
    Write-Log "     2 - Start a fresh spreadsheet export from a PrinterData.json file on this PC"
    Write-Log "     3 - Use a pre-existing sheet (you can resume previous runs with this)"
    Write-Log ""
    While ($true) {
        $StartChoice = ([string](Read-Host "1/2/3 (or exit)")).Trim()
        if ($StartChoice -ieq 'exit') { Write-Log "Cancelled. Nothing was created." 'WARNING'; Pause; return }
        if (@('1', '2', '3') -contains $StartChoice) { break }
        Write-Log "Invalid input. Please enter 1, 2 or 3." 'ERROR'
    }

    $Earlier = $null
    if ($StartChoice -eq '3') {
        # Offer the most recent earlier runs by number. A run's results.csv marks only the printers
        # that did not finish as Include = Y; a run that never got that far offers its draft.csv.
        $RecentSheets = @()
        $BulkRoot = Join-Path $WorkingDirectory 'TEMP\PrinterBulk'
        if (Test-Path -LiteralPath $BulkRoot) {
            foreach ($RunDir in @(Get-ChildItem -LiteralPath $BulkRoot -Directory -Filter 'Create_*' | Sort-Object Name -Descending)) {
                foreach ($Candidate in @('results.csv', 'draft.csv')) {
                    $CandidatePath = Join-Path $RunDir.FullName $Candidate
                    if (Test-Path -LiteralPath $CandidatePath) { $RecentSheets += $CandidatePath; break }
                }
                if ($RecentSheets.Count -ge 5) { break }
            }
        }

        if ($RecentSheets.Count -gt 0) {
            Write-Log ""
            Write-Log "Recent sheets from earlier runs (newest first):"
            for ($i = 0; $i -lt $RecentSheets.Count; $i++) {
                $Marked = '?'
                try { $Marked = @(Read-PDBulkCsv -Path $RecentSheets[$i] -RequiredColumns @('Include') | Where-Object { Test-PDBulkYes -Value $_.Include }).Count } Catch { }
                Write-Log ("     {0} - {1}\{2}  ({3} printer(s) marked Include = Y)" -f ($i + 1), (Split-Path (Split-Path $RecentSheets[$i] -Parent) -Leaf), (Split-Path $RecentSheets[$i] -Leaf), $Marked)
            }
            Write-Log ""
        }

        While ($true) {
            $Earlier = ([string](Read-Host "Enter a number from the list, or the full path to a sheet (or exit)")).Trim().Trim('"').Trim("'")
            if ($Earlier -ieq 'exit') { Write-Log "Cancelled. Nothing was created." 'WARNING'; Pause; return }
            $Picked = 0
            if ([int]::TryParse($Earlier, [ref]$Picked) -and $Picked -ge 1 -and $Picked -le $RecentSheets.Count) { $Earlier = $RecentSheets[$Picked - 1] }
            if (-not [string]::IsNullOrWhiteSpace($Earlier) -and (Test-Path -LiteralPath $Earlier -PathType Leaf)) { break }
            Write-Log "No file was found at '$Earlier'." 'ERROR'
        }
        Write-Log "Using: $Earlier"
        Write-Log ""
        Write-Log "The printer details for that sheet come from the current PrinterData.json." 'INFO2'
    }

    # --- PrinterData.json --------------------------------------------------------------------------
    $JsonSource = 'Blob'
    if ($StartChoice -eq '2') { $JsonSource = 'Local' }
    $JsonPath = Get-PrinterBulkJsonPath -Source $JsonSource
    if (-not $JsonPath) { Write-Log "Cancelled. Nothing was created." 'WARNING'; Pause; return }

    $Catalog = Get-PDPrinterJsonCatalog -Path $JsonPath
    if (@($Catalog.Errors).Count -gt 0) {
        Write-Log ""
        Write-Log "PrinterData.json has problems that must be fixed first:" 'ERROR'
        foreach ($Problem in @($Catalog.Errors)) { Write-Log "     - $Problem" 'ERROR' }
        Pause
        return
    }

    Write-Log ""
    Write-Log ("Found {0} printer(s) in PrinterData.json." -f @($Catalog.Printers).Count) 'SUCCESS'
    if ($Catalog.Problems.Count -gt 0) {
        Write-Log ("{0} of them would fail to install as written; they start with Include = N and the reason in the Problem column." -f $Catalog.Problems.Count) 'WARNING'
    }
    Write-Log ""

    $SourceCommit = Get-PDPrinterSourceCommit -RepoRoot $RepoRoot
    $RunFolder    = Join-Path $WorkingDirectory ("TEMP\PrinterBulk\Create_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $SheetPath    = Join-Path $RunFolder 'draft.csv'

    # --- The sheet ---------------------------------------------------------------------------------
    if ($StartChoice -eq '3') {
        New-Item -ItemType Directory -Path $RunFolder -Force | Out-Null
        Copy-Item -LiteralPath $Earlier -Destination $SheetPath -Force
    } else {
        # Default groups (decision D4): pre-filled into every row; blank skips it.
        Write-Log ""
        Write-Log "DEFAULT GROUPS: pre-filled into every row of the sheet, and you can still change any row." 'WARNING'
        Write-Log "Leave both blank to skip this and start with empty group columns."
        Write-Log ""
        [string[]]$DefaultRequired  = @(Read-IntuneGroupList -Intent 'Required')
        Write-Log ""
        [string[]]$DefaultAvailable = @(Read-IntuneGroupList -Intent 'Available')
        Write-Log ""

        # Picking a handful out of many is easier from an all-unticked sheet.
        $IncludeAll = Read-GraphUploadYesNo -Question 'Start with every printer ticked (Include = Y)?' -Default $true `
                                            -Note 'Answer n to start with none ticked, then tick only the printers you want.'
        Write-Log ""

        $Draft = New-PDPrinterBulkDraft -Catalog $Catalog -DeployMode $Global:DeployMode -SourceCommit $SourceCommit `
                                        -DefaultRequiredGroups $DefaultRequired -DefaultAvailableGroups $DefaultAvailable `
                                        -IncludeByDefault $IncludeAll
        Write-PDBulkCsv -Rows $Draft -Columns (Get-PDPrinterBulkDraftColumns -Catalog $Catalog) -Path $SheetPath
    }

    Write-Log ""
    Write-Log "HOW TO EDIT THE SHEET:" 'WARNING'
    Write-Log "     - Include:          Y to create the printer, N (or delete the row) to leave it out."
    Write-Log "     - RequiredGroups:   groups the printer is installed on automatically. Separate several with ';'."
    Write-Log "     - AvailableGroups:  groups that can install it from the Company Portal. Separate several with ';'."
    Write-Log "       Use exact group names or object IDs, or /AllDevices or /AllUsers."
    Write-Log "     - Every other column is for reference only, straight from PrinterData.json, and edits to it are ignored."
    Write-Log "       Change printer details in PrinterData.json itself. PrinterName must not be changed."
    Write-Log ""

    $AuthContext = @{ Credential = (Get-PDGraphCredential) }

    # --- Stage: check the sheet until it is clean ------------------------------------------------
    # The problems from the last check go back into the editor window, so they can be fixed in place.
    $LastProblems = @()
    While ($true) {

        if (-not (Edit-PrinterBulkSheet -Path $SheetPath -Kind 'Create' -Problems $LastProblems)) { Write-Log "Cancelled. Nothing was created." 'WARNING'; Pause; return }
        $LastProblems = @()

        try {
            $Rows = @(Read-PDBulkCsv -Path $SheetPath -RequiredColumns @('Include', 'PrinterName', 'RequiredGroups', 'AvailableGroups'))
        } Catch {
            Write-Log $_.Exception.Message 'ERROR'
            $LastProblems = @($_.Exception.Message)
            continue
        }

        Write-Log ""
        Write-Log "Checking the sheet against Intune (reads only, nothing is created)..."

        try {
            $Included = @($Rows | Where-Object { Test-PDBulkYes -Value (Get-PDBulkCell -Row $_ -Name 'Include') })
            $Groups   = Resolve-PDBulkGroups -Rows $Included -AuthContext $AuthContext
            $Existing = @(Get-PDIntunePrinterApps -AuthContext $AuthContext)
            $Stage    = Resolve-PDPrinterBulkStage -Rows $Rows -Catalog $Catalog -ExistingApps $Existing -GroupMap $Groups.Map `
                                                   -DeployMode $Global:DeployMode -SourceCommit $SourceCommit
            $CategoryCheck = Find-PDIntuneCategory -Category $script:PDBulk.Category -AuthContext $AuthContext
        } Catch {
            Show-GraphUploadError -Failure $_
            if (Read-GraphUploadYesNo -Question 'Check the sheet again?' -Default $true -Note 'Answer n to cancel. Nothing has been created.') { continue }
            Pause
            return
        }

        $SheetProblems = @(@($Groups.Errors) + @($Stage.Errors))
        if ($SheetProblems.Count -gt 0) {
            Write-Log ""
            Write-Log ("The sheet has {0} problem(s). Nothing has been created:" -f $SheetProblems.Count) 'ERROR'
            foreach ($Problem in $SheetProblems) { Write-Log "     - $Problem" 'ERROR' }
            Write-Log ""
            Write-Log "Fix them in the sheet, save it, and it will be checked again."
            $LastProblems = $SheetProblems
            continue
        }

        if (@($Stage.Rows).Count -eq 0) {
            Write-Log "No printers are marked Include = Y." 'WARNING'
            $LastProblems = @('No printers are marked Include = Y.')
            continue
        }

        break
    }

    # --- Printers that already exist (decision D3) ----------------------------------------------
    $Conflicts = @($Stage.Rows | Where-Object { $_.Action -eq 'Conflict' })
    if ($Conflicts.Count -gt 0) {
        Write-Log ""
        Write-Log ("{0} printer(s) already exist in Intune in {1} mode:" -f $Conflicts.Count, $Global:DeployMode) 'WARNING'
        foreach ($Row in $Conflicts) {
            foreach ($Old in @($Row.Matches)) { Write-Log ("     {0}  ->  existing: {1} ({2})" -f $Row.PrinterName, $Old.DisplayName, $Old.AppId) }
        }
        Write-Log ""
        Write-Log "Override = create the new app, then back up and delete the existing one (its install history in Intune is lost)."
        Write-Log "Skip     = leave the existing app alone and do not create this printer."
        Write-Log ""
        Write-Log "     1 - Override all"
        Write-Log "     2 - Skip all"
        Write-Log "     3 - Decide each"
        Write-Log ""
        While ($true) {
            $ConflictChoice = ([string](Read-Host "1/2/3")).Trim()
            if (@('1', '2', '3') -contains $ConflictChoice) { break }
            Write-Log "Invalid input. Please enter 1, 2 or 3." 'ERROR'
        }

        foreach ($Row in $Conflicts) {
            switch ($ConflictChoice) {
                '1' { $Row.Action = 'Override' }
                '2' { $Row.Action = 'Skip' }
                '3' {
                    $ExistingNames = (@($Row.Matches) | ForEach-Object { $_.DisplayName }) -join '; '
                    if (Read-GraphUploadYesNo -Question ("Override '{0}' (existing: {1})?" -f $Row.PrinterName, $ExistingNames) -Default $false) {
                        $Row.Action = 'Override'
                    } else {
                        $Row.Action = 'Skip'
                    }
                }
            }
        }
    }

    $StagedPath = Join-Path $RunFolder 'staged.csv'
    Write-PDBulkCsv -Rows $Stage.Rows -Columns $script:PDBulk.StagedColumns -Path $StagedPath

    $Creates   = @($Stage.Rows | Where-Object { $_.Action -eq 'Create' })
    $Overrides = @($Stage.Rows | Where-Object { $_.Action -eq 'Override' })
    $Skips     = @($Stage.Rows | Where-Object { $_.Action -eq 'Skip' })
    $OldApps   = 0
    foreach ($Row in $Overrides) { $OldApps += @($Row.Matches).Count }
    $OtherMode = @($Stage.Rows | Where-Object { @($_.OtherModeMatches).Count -gt 0 })

    # --- Summary and confirmation -------------------------------------------------------------
    Clear
    Write-Log "==========================================================================================="
    Write-Log "SUMMARY - nothing has been created in Intune yet"
    Write-Log "==========================================================================================="
    Write-Log ""
    Write-Log " Deployment mode:  $Global:DeployMode"
    Write-Log (" Repo / branch:    {0} ({1})" -f (Get-IntuneDisplayUrl -Url $RepoUrl), $Global:RepoBranch)
    Write-Log ""
    Write-Log (" Create:    {0}" -f $Creates.Count)
    Write-Log (" Override:  {0}  (then {1} existing app(s) backed up and deleted)" -f $Overrides.Count, $OldApps)
    Write-Log (" Skip:      {0}" -f $Skips.Count)
    Write-Log (" Left out:  {0}  (Include = N)" -f $Stage.Excluded)
    Write-Log ""
    if ($null -ne $CategoryCheck -and [string]$CategoryCheck.Status -ne 'Resolved') {
        Write-Log ("The '{0}' app category was not found in Intune, so the apps will be created without a category." -f $script:PDBulk.Category) 'WARNING'
        Write-Log ""
    }
    $EditedCells = @($Stage.Warnings)
    if ($EditedCells.Count -gt 0) {
        Write-Log ("{0} reference cell(s) in the sheet differ from PrinterData.json. They are IGNORED: printers are built from PrinterData.json." -f $EditedCells.Count) 'WARNING'
        foreach ($Edited in @($EditedCells | Select-Object -First 10)) { Write-Log "     $Edited" 'WARNING' }
        if ($EditedCells.Count -gt 10) { Write-Log ("     ...and {0} more." -f ($EditedCells.Count - 10)) 'WARNING' }
        Write-Log "To change printer details, edit PrinterData.json and start a fresh export." 'WARNING'
        Write-Log ""
    }
    if ($OtherMode.Count -gt 0) {
        Write-Log ("For information: {0} printer(s) also exist in another deployment mode. Those apps are never touched:" -f $OtherMode.Count) 'INFO2'
        foreach ($Row in $OtherMode) {
            foreach ($Other in @($Row.OtherModeMatches)) { Write-Log ("     {0} ({1})" -f $Other.DisplayName, $Other.AppId) 'INFO2' }
        }
        Write-Log ""
    }
    Write-Log "The full plan, row by row, is in:"
    Write-LogBlock "`n$StagedPath`n"

    if (($Creates.Count + $Overrides.Count) -eq 0) {
        Write-Log "Nothing to create. Nothing was changed in Intune." 'WARNING'
        Pause
        return
    }

    $Confirm = ([string](Read-Host "Type yes to create these printers in Intune")).Trim()
    if ($Confirm -ine 'yes') { Write-Log "Cancelled. Nothing was created." 'WARNING'; Pause; return }

    # --- Run --------------------------------------------------------------------------------------
    # Every printer uses the same package (the Git-Runner template), so it is built once.
    Write-Log ""
    Write-Log "Building the Intune package (shared by every printer)..."
    try {
        Make-InTuneWin -SourceFile "$GitRunnerScript"
    } Catch {
        Write-Log "The Intune package could not be built: $($_.Exception.Message)" 'ERROR'
        Write-Log "Nothing was created in Intune." 'WARNING'
        Pause
        return
    }
    $BulkIntuneWinPath = $Global:intunewinpath

    $Context = @{
        RepoUrl                    = $RepoUrl
        RepoNickName               = $Global:TargetRepoNickName
        RepoBranch                 = $Global:RepoBranch
        TargetWorkingDirectory     = $Global:TargetWorkingDirectory
        DeployMode                 = $Global:DeployMode
        RepoRoot                   = $RepoRoot
        IconPath                   = $PrinterIconPath
        GenerateInstallCommandPath = $GenerateInstallCommand_ScriptPath
        IntuneWinPath              = $BulkIntuneWinPath
        BackupFolder               = (Join-Path $RunFolder 'backups')
        CredentialPath             = ''
    }

    Write-Log ""
    Write-Log ("Creating {0} printer(s). Each one takes a little while..." -f ($Creates.Count + $Overrides.Count))
    Write-Log ""

    $Results = @(Invoke-PDPrinterBulkCreate -StagedRows $Stage.Rows -Catalog $Catalog -Context $Context -AuthContext $AuthContext `
        -OnProgress {
            param($Index, $Total, $Row, $Result)
            $Level = 'SUCCESS'
            if ($Result.Result -eq 'Failed') { $Level = 'ERROR' } elseif ($Result.Result -eq 'CreatedOldNotDeleted') { $Level = 'WARNING' }
            $Detail = ''
            if ($Result.NewAppId) { $Detail = " (new app $($Result.NewAppId)" + $(if ($Result.DeletedAppIds) { ", replaced $($Result.DeletedAppIds))" } else { ')' }) }
            if ([int]("0" + $Result.Attempts) -gt 1) { $Detail += " [attempt $($Result.Attempts)]" }
            if (([int]("0" + $Result.StorageRenewals) -gt 0) -or ([int]("0" + $Result.StorageWaits) -gt 0)) { $Detail += " [storage: $($Result.StorageRenewals) renewal(s), $($Result.StorageWaits) wait(s)]" }
            if ($Result.Result -ne 'Created' -and $Result.Result -ne 'Overridden' -and $Result.Error) { $Detail += ": $($Result.Error)" }
            Write-Log ("[{0}/{1}] {2} ... {3}{4}" -f $Index, $Total, $Result.IntuneDisplayName, $Result.Result, $Detail) $Level
        } `
        -Log { param($Message, $Level) Write-Log $Message $Level -LogOnly })

    $ResultsPath = Join-Path $RunFolder 'results.csv'
    Write-PDBulkCsv -Rows $Results -Columns $script:PDBulk.ResultColumns -Path $ResultsPath

    # --- Report -----------------------------------------------------------------------------------
    Write-Log ""
    Write-Log "==========================================================================================="
    Write-Log "BULK CREATE FINISHED"
    Write-Log "==========================================================================================="
    foreach ($Outcome in @('Created', 'Overridden', 'CreatedOldNotDeleted', 'Failed', 'Skipped')) {
        $Count = @($Results | Where-Object { $_.Result -eq $Outcome }).Count
        if ($Count -gt 0) { Write-Log (" {0,-22} {1}" -f $Outcome, $Count) }
    }
    $NeedsAttention = @($Results | Where-Object { $_.Result -eq 'Failed' -or $_.Result -eq 'CreatedOldNotDeleted' })
    if ($NeedsAttention.Count -gt 0) {
        Write-Log ""
        Write-Log "Needs attention:" 'WARNING'
        foreach ($Row in $NeedsAttention) { Write-Log ("     {0}: {1}" -f $Row.PrinterName, $Row.Error) 'WARNING' }
        Write-Log ""
        Write-Log "To retry the failed printers, run this again and choose 'Use a pre-existing sheet'; this run is offered at the top of the list."
        Write-Log "An old app that could not be removed can be deleted with Printer--InTune-BulkDelete."
    }
    Write-Log ""
    Write-Log "Results (one row per printer):"
    Write-LogBlock "`n$ResultsPath`n"
    if (Test-Path -LiteralPath $Context.BackupFolder) {
        Write-Log "Backups of the apps that were replaced:"
        Write-LogBlock "`n$($Context.BackupFolder)`n"
    }
    Write-Log "Please verify a few of the new printers on a test device." 'WARNING'
    Pause
}

Function Printer--InTune-BulkDelete {

    Write-Log "==========================================================================================="
    Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START"
    Write-Log "==========================================================================================="
    Write-Log ""
    Write-Log "BULK DELETE PRINTER APPS FROM INTUNE"
    Write-Log ""
    Write-Log "Lists every PowerDeploy printer app in Intune (all deployment modes) in a sheet. You mark the"
    Write-Log "ones to delete; each one is backed up to a file and then deleted."
    Write-Log ""
    Write-Log "This only cleans up Intune. Devices that already have a printer KEEP it." 'WARNING'
    Write-Log ""

    if (-not (Test-PrinterBulkReady)) { Pause; return }

    $AuthContext = @{ Credential = (Get-PDGraphCredential) }

    Write-Log "Reading the printer apps from Intune..."
    try {
        $Apps = @(Get-PDIntunePrinterApps -AuthContext $AuthContext)
    } Catch {
        Show-GraphUploadError -Failure $_
        Pause
        return
    }

    if ($Apps.Count -eq 0) {
        Write-Log "No PowerDeploy printer apps were found in Intune." 'WARNING'
        Pause
        return
    }

    Write-Log ("Found {0} printer app(s):" -f $Apps.Count) 'SUCCESS'
    foreach ($Group in @($Apps | Group-Object DeployMode | Sort-Object Name)) { Write-Log ("     {0,-22} {1}" -f $Group.Name, $Group.Count) }
    Write-Log ""

    $RunFolder = Join-Path $WorkingDirectory ("TEMP\PrinterBulk\Delete_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $SheetPath = Join-Path $RunFolder 'delete.csv'
    Write-PDBulkCsv -Rows (New-PDPrinterDeleteSheet -Apps $Apps) -Columns $script:PDBulk.DeleteColumns -Path $SheetPath

    Write-Log "HOW TO EDIT THE SHEET:" 'WARNING'
    Write-Log "     - Put Y in the Delete column of every app to delete. Leave it blank to keep the app."
    Write-Log "     - Rows are matched by AppId only; the other columns are for reference."
    Write-Log ""
    $LastProblems = @()

    While ($true) {

        if (-not (Edit-PrinterBulkSheet -Path $SheetPath -Kind 'Delete' -Problems $LastProblems)) { Write-Log "Cancelled. Nothing was deleted." 'WARNING'; Pause; return }
        $LastProblems = @()

        try {
            $Rows = @(Read-PDBulkCsv -Path $SheetPath -RequiredColumns @('Delete', 'AppId'))
        } Catch {
            Write-Log $_.Exception.Message 'ERROR'
            $LastProblems = @($_.Exception.Message)
            continue
        }

        # A fresh list, so an app deleted or renamed since the sheet was written is caught here.
        try {
            $Current = @(Get-PDIntunePrinterApps -AuthContext $AuthContext)
        } Catch {
            Show-GraphUploadError -Failure $_
            if (Read-GraphUploadYesNo -Question 'Try again?' -Default $true -Note 'Answer n to cancel. Nothing has been deleted.') { continue }
            Pause
            return
        }

        $Selection = Resolve-PDPrinterDeleteSelection -Rows $Rows -CurrentApps $Current

        if (@($Selection.Errors).Count -gt 0) {
            Write-Log "The sheet has problems. Nothing has been deleted:" 'ERROR'
            foreach ($Problem in @($Selection.Errors)) { Write-Log "     - $Problem" 'ERROR' }
            $LastProblems = @($Selection.Errors)
            continue
        }

        if (@($Selection.Gone).Count -gt 0) {
            Write-Log "These marked apps are no longer in Intune and will be skipped:" 'WARNING'
            foreach ($Gone in @($Selection.Gone)) { Write-Log ("     {0} ({1})" -f $Gone.DisplayName, $Gone.AppId) 'WARNING' }
            Write-Log ""
        }

        if (@($Selection.Selected).Count -eq 0) {
            Write-Log "No apps are marked for deletion." 'WARNING'
            $LastProblems = @('No apps are marked for deletion. Tick Delete on the apps to remove, or press Cancel.')
            continue
        }

        break
    }

    $ToDelete = @($Selection.Selected)

    Clear
    Write-Log "==========================================================================================="
    Write-Log "CONFIRM - nothing has been deleted yet"
    Write-Log "==========================================================================================="
    Write-Log ""
    foreach ($App in $ToDelete) { Write-Log ("     {0}  ({1})" -f $App.DisplayName, $App.AppId) }
    Write-Log ""
    Write-Log ("{0} app(s) will be backed up and then DELETED from Intune. Devices keep their printers." -f $ToDelete.Count) 'WARNING'
    Write-Log ""

    $Typed = ([string](Read-Host ("Type {0} (the number of apps) to delete them, or anything else to cancel" -f $ToDelete.Count))).Trim()
    if ($Typed -ne [string]$ToDelete.Count) { Write-Log "Cancelled. Nothing was deleted." 'WARNING'; Pause; return }

    $BackupFolder = Join-Path $RunFolder 'backups'
    Write-Log ""

    $Results = @(Invoke-PDPrinterBulkDelete -Apps $ToDelete -BackupFolder $BackupFolder -AuthContext $AuthContext `
        -OnProgress {
            param($Index, $Total, $Row)
            $Level = 'SUCCESS'
            if (@('Deleted', 'AlreadyGone') -notcontains $Row.Result) { $Level = 'ERROR' }
            Write-Log ("[{0}/{1}] {2} ... {3}" -f $Index, $Total, $Row.DisplayName, $Row.Result) $Level
        })

    $ResultsPath = Join-Path $RunFolder 'delete-results.csv'
    Write-PDBulkCsv -Rows $Results -Columns $script:PDBulk.DeleteResultColumns -Path $ResultsPath

    Write-Log ""
    Write-Log "==========================================================================================="
    Write-Log "BULK DELETE FINISHED"
    Write-Log "==========================================================================================="
    foreach ($Outcome in @('Deleted', 'AlreadyGone', 'BackupFailed', 'DeleteFailed')) {
        $Count = @($Results | Where-Object { $_.Result -eq $Outcome }).Count
        if ($Count -gt 0) { Write-Log (" {0,-14} {1}" -f $Outcome, $Count) }
    }
    $Failed = @($Results | Where-Object { @('Deleted', 'AlreadyGone') -notcontains $_.Result })
    if ($Failed.Count -gt 0) {
        Write-Log ""
        foreach ($Row in $Failed) { Write-Log ("     {0}: {1}" -f $Row.DisplayName, $Row.Error) 'ERROR' }
    }
    Write-Log ""
    Write-Log "Results:"
    Write-LogBlock "`n$ResultsPath`n"
    Write-Log "Backups (one JSON file per app, including its group assignments):"
    Write-LogBlock "`n$BackupFolder`n"
    Pause
}


# DONE (still need testing) 1/14/26
Function WindowsApp--InTune-Setup{

    # Determine if this is a test or production deployment
    $RepoUrl = Set-URL

    # SearchJSONForApp copies the chosen entry's properties into global scope and never clears
    # the ones an entry does not have, so an app without an AppDescription would inherit the
    # previous selection's. Clear the optional fields first (spec I04).
    foreach ($StaleField in @('AppDescription', 'Category', 'Verified', 'Publisher', 'PackagedVersion', 'Version', 'PreRequisites', 'DisplayName', 'WinGetID', 'InformationUrl', 'PrivacyUrl', 'IconUrl', 'IconFile', 'PDAppCatalogSource', 'PDAppPrereqCatalogInfo')) {
        Remove-Variable -Name $StaleField -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name $StaleField -Scope Script -ErrorAction SilentlyContinue
    }
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
        Write-Log "Look here is an example of JSON format: \Templates\ApplicationData_TEMPLATE.json"
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



    Write-Log "Would you like to TEST by having this script install the app based on the JSON configuration? (y/n)" "WARNING"
    $Answer = Read-Host "y/n"
    Write-Log ""


        if ($answer -eq "y"){

            Write-Log "Before proceeding, please make sure this application is not already installed locally on this machine. If it is, please uninstall it first." "WARNING"
            Pause
            Write-Log "Proceeding with local installation test for $AppNameToFind..."

            & WindowsApp--Install-Local -ApplicationName $AppNameToFind

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

    # If ($DetectMethod -eq $null -or ($DetectMethod -eq "")) {

        # Write-Log "The application '$ApplicationName' does not have information for the DetectMethod var in the JSON to auto-generate install command and detection script. This script will automatically choose a detect method based on the install method." "WARNING"

        # Write-Log ""

        if ($InstallMethod -eq "WinGet") {

            if($WinGetID -eq $null -or $WinGetID -eq ""){
                Write-Log "The application '$ApplicationName' does not have a WinGet ID specified in the JSON. Please update your JSON with the required fields and re-run this setup process for automatic generation." "ERROR"
                Exit 1
            }

            [hashtable]$FunctionParams = @{
                ApplicationName = $ApplicationName
                AppID = $WinGetID

            }

            if ($DetectMethod -eq $null -or $DetectMethod -eq "") {

                Write-Log "No DetectMethod specified in JSON, but sufficient info to auto-set it based on InstallMethod." "WARNING"

                Write-Log "Detect method set as WinGet" "WARNING"

                $DetectMethod = "WinGet"

                $FunctionParams.Add("DetectMethod", $DetectMethod)

            } else {

                Write-Log "DetectMethod specified in JSON, using that for generation: $DetectMethod" "INFO2"
                $FunctionParams.Add("DetectMethod", $DetectMethod)
            }


        } elseif ($InstallMethod -eq "MSI-Private-AzureBlob") {

            if ($DisplayName -eq $null -or $DisplayName -eq "") {
                Write-Log "The application '$ApplicationName' does not have a Display Name specified in the JSON. Please update your JSON with the required fields and re-run this setup process for automatic generation." "ERROR"
                Exit 1
            }

            [hashtable]$FunctionParams = @{
                ApplicationName = $ApplicationName
                DisplayName = $DisplayName
            }

            if ($DetectMethod -eq $null -or $DetectMethod -eq "") {

                Write-Log "No DetectMethod specified in JSON, but sufficient info to auto-set it based on InstallMethod." "WARNING"

                Write-Log "Detect method set as MSI_Registry" "WARNING"

                $DetectMethod = "MSI_Registry"

                $FunctionParams.Add("DetectMethod", $DetectMethod)
                
            } else {

                Write-Log "DetectMethod specified in JSON, using that for generation: $DetectMethod" "INFO2"
                $FunctionParams.Add("DetectMethod", $DetectMethod)
            }

        } elseif ($InstallMethod -eq "EXE-Private-AzureBlob") {

            if ($DisplayName -eq $null -or $DisplayName -eq "") {
                Write-Log "The application '$ApplicationName' does not have a Display Name specified in the JSON. Please update your JSON with the required fields and re-run this setup process for automatic generation." "ERROR"
                Exit 1
            }

            [hashtable]$FunctionParams = @{
                ApplicationName = $ApplicationName
                DisplayName = $DisplayName
            }

            if ($DetectMethod -eq $null -or $DetectMethod -eq "") {

                Write-Log "No DetectMethod specified in JSON, but sufficient info to auto-set it based on InstallMethod." "WARNING"

                Write-Log "Detect method set as MSI_Registry" "WARNING"

                $DetectMethod = "MSI_Registry"

                $FunctionParams.Add("DetectMethod", $DetectMethod)
                
            } else {

                Write-Log "DetectMethod specified in JSON, using that for generation: $DetectMethod" "INFO2"
                $FunctionParams.Add("DetectMethod", $DetectMethod)
            }


        } elseif ($InstallMethod -eq "URL_Download") {

            if ($DisplayName -eq $null -or $DisplayName -eq "") {
                Write-Log "The application '$ApplicationName' does not have a Display Name specified in the JSON. Please update your JSON with the required fields and re-run this setup process for automatic generation." "ERROR"
                Exit 1
            }

            [hashtable]$FunctionParams = @{
                ApplicationName = $ApplicationName
                DisplayName = $DisplayName
            }

            if ($DetectMethod -eq $null -or $DetectMethod -eq "") {

                Write-Log "No DetectMethod specified in JSON, but sufficient info to auto-set it based on InstallMethod." "WARNING"

                Write-Log "Detect method set as MSI_Registry" "WARNING"

                $DetectMethod = "MSI_Registry"

                $FunctionParams.Add("DetectMethod", $DetectMethod)
                
            } else {

                Write-Log "DetectMethod specified in JSON, using that for generation: $DetectMethod" "INFO2"
                $FunctionParams.Add("DetectMethod", $DetectMethod)
            }
            
        } else {

            Write-Log "Unknown Install Method or Detect Method. Please correct this in the JSON and re-run this setup process." "ERROR"
            Write-Log "Install Method: $InstallMethod" 
            Write-Log "Detect Method: $DetectMethod" 

            Exit 1

        }
    
    # }


    # Org registry values: decided here, when the command is generated - Git-Runner never guesses.
    # Yes = the install command gets -RequireOrgKeys 'Applications', so Git-Runner exits 1618 (Intune retry)
    # until the org registry values exist on the device.
    $AppOrgKeysDecision = Get-PDAppOrgKeysDecision -CatalogSource $Global:PDAppCatalogSource -InstallMethod $InstallMethod -PrereqCatalogInfo $Global:PDAppPrereqCatalogInfo
    if ($AppOrgKeysDecision.Required) {
        $FunctionParams.Add("RequireOrgKeys", "Applications")
        $AppWaitsForOrgKeys = "Yes"
    } else {
        $AppWaitsForOrgKeys = "No"
    }
    Write-Log "" "INFO2"
    Write-Log "Waits for organization registry keys: $AppWaitsForOrgKeys ($($AppOrgKeysDecision.Reason))" "INFO2"


    Write-Log "" "INFO2"
    Write-Log "Final method results:" "INFO2"
    Write-Log "   Install Method: $InstallMethod" "INFO2"
    Write-Log "Function Paramters:" "INFO2"
    # Write-Log "Detect Method: $DetectMethod" "INFO2"
    Foreach ($key in $FunctionParams.Keys) {
        Write-Log "   $key : $($FunctionParams[$key])" "INFO2"
    }
    Write-Log "" "INFO2"



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

            Write-Log "UninstallType not provided for application '$ApplicationName' in the JSON file." "WARNING"

            Write-Log "Since the InstallMethod is WinGet, we will set the UninstallType to WinGet by default for uninstall command generation." "WARNING"

            $UninstallType = "WinGet"
        }

        # Exit out if UninstallType is still not set
        # TODO: Swap out for a loop that asks the user to input the uninstall type instead of exiting?
        If ($UninstallType -eq "" -or $UninstallType -eq $null) {

            Write-Log "UninstallType not provided for application '$ApplicationName' in the JSON file." "WARNING"

            # Write-Log "The application '$ApplicationName' does not have sufficient information for the UninstallType var in the JSON to auto-generate uninstall command." "WARNING"
            # Write-Log "Please update your JSON with uninstall data and then run this script again" "WARNING"
            Write-Log "" "WARNING"
            Write-Log "We will set uninstall type to 'All' to attempt to generate an uninstall command, but please note this may not work correctly." "WARNING" 
            Write-Log "" "WARNING"
            Write-Log "It is highly recommended to update the JSON with the correct uninstall information and re-run this setup process for proper uninstall command generation." "WARNING"
            
            $UninstallType = "All"
            Pause
            # Exit 1

        } 

    [hashtable]$FunctionParams2 = @{
        ApplicationName = $ApplicationName
        UninstallType = $UninstallType
        Version = $Version
        WinGetID = $WinGetID
        UninstallString_DisplayName = $DisplayName
    }

    if($UninstallArgs -ne $null -and $UninstallArgs -ne ""){
        $FunctionParams2.Add("UninstallArgs", $UninstallArgs)
    }

    if($UninstallCustomString -ne $null -and $UninstallCustomString -ne ""){
        $FunctionParams2.Add("UninstallCustomString", $UninstallCustomString)
    }

    Write-Log "" "INFO2"
    Write-Log "Uninstall Command Function Paramters:" "INFO2"
    # Write-Log "Detect Method: $DetectMethod" "INFO2"
    Foreach ($key in $FunctionParams2.Keys) {
        Write-Log "   $key : $($FunctionParams2[$key])" "INFO2"
    }
    Write-Log "" "INFO2"
    Write-Log "Calling uninstall command generator function..." "INFO2"
    Write-Log "" "INFO2"

    $ReturnHash3 = @{}
    $ReturnHash3 = & $GenerateInstallCommand_ScriptPath `
        -DesiredFunction "UninstallApp" `
        -RepoURL $RepoURL `
        -RepoNickName $Global:TargetRepoNickName `
        -RepoBranch $Global:RepoBranch `
        -TargetWorkingDirectory $Global:TargetWorkingDirectory `
        -FunctionParams $FunctionParams2

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
    Write-Log "Next we will create a Win32 application in InTune for this app using the new intunewin file, script, and install command."
    Write-Log ""




    # Specs of endpoint target repo
        # $Global:DeployMode
        # $RepoUrl
        # $Global:RepoBranch

    # Specs of working repo
        # Commit of the local repo, plus a marker if the packaged Git-Runner has uncommitted edits
        $CurrentGitVer = git -C $RepoRoot rev-parse --short HEAD 2>$null
        if (-not $CurrentGitVer) { $CurrentGitVer = "unknown" }
        $RunnerChanges = git -C $RepoRoot status --porcelain -- "Templates/Git-Runner_TEMPLATE.ps1"
        if ($RunnerChanges) { $CurrentGitVer = "$CurrentGitVer.UnstagedChanges" }


    # Get the potential name sorted out
    # Always based on ApplicationName (the admin-chosen label). DisplayName is the vendor's registry string used for detection/uninstall matching, so it is never used here.
    $PotentialAppInTuneName = "APP: $ApplicationName"

    if ($Global:DeployMode -ne "Production"){

            $PotentialAppInTuneName = "$PotentialAppInTuneName [MODE: $Global:DeployMode] [VER: $CurrentGitVer]"

    }



    $CatalogPublisher = $publisher
    if($publisher -eq "" -or $null -eq $publisher){$publisher = "PowerDeploy"}
    if($AppDescription -eq "" -or $null -eq $AppDescription){$AppDescription = "N/A"}
    if($PreRequisites -eq "" -or $null -eq $PreRequisites){$PreRequisites = "N/A"}
    if($Version -eq "" -or $null -eq $Version){$Version = "N/A"}
    if($PackagedVersion -eq "" -or $null -eq $PackagedVersion){$PackagedVersion = "N/A"}
    #if($PackagedVersion -eq "" -or $null -eq $PackagedVersion){$PackagedVersion = "N/A"}

    # Intune text, built once before any publishing choice (spec 5.1 step 2). $AppDescription stays
    # the JSON value; $TheAppDescription is the final Company Portal text (spec 4.3).
    # One WinGet lookup serves both the description and the publisher, and only runs when either
    # is missing from the catalog.
    $WinGetLookup = $null
    if (([string]$InstallMethod -eq 'WinGet') -and -not (Test-IntuneFieldMissing -Value $WinGetID) -and
        ((Test-IntuneFieldMissing -Value $AppDescription) -or (Test-IntuneFieldMissing -Value $CatalogPublisher) -or
         (Test-IntuneFieldMissing -Value $InformationUrl) -or (Test-IntuneFieldMissing -Value $PrivacyUrl))) {
        $WinGetLookup = Invoke-IntuneWinGetLookup -WinGetID $WinGetID
    }

    $AppDescriptionResult = Get-IntuneAppDescriptionText -AppDescription $AppDescription -InstallMethod $InstallMethod -WinGetID $WinGetID -Lookup $WinGetLookup
    $TheAppDescription = [string]$AppDescriptionResult.Text
    if ($AppDescriptionResult.Warning) { Write-Log $AppDescriptionResult.Warning "WARNING" }
    Write-Log "Description source: $($AppDescriptionResult.Source)" "INFO2"

    $AppPublisherResult = Get-IntuneAppPublisherText -CatalogPublisher $CatalogPublisher -InstallMethod $InstallMethod -Lookup $WinGetLookup
    $publisher = [string]$AppPublisherResult.Text
    Write-Log "Publisher: $publisher (source: $($AppPublisherResult.Source))" "INFO2"

    # Company Portal links: catalog InformationUrl / PrivacyUrl, else what WinGet reports.
    $AppLinks = Get-IntuneAppLinks -CatalogInformationUrl $InformationUrl -CatalogPrivacyUrl $PrivacyUrl -InstallMethod $InstallMethod -Lookup $WinGetLookup
    if ($AppLinks.InformationUrl) { Write-Log "Information URL: $($AppLinks.InformationUrl) (source: $($AppLinks.InformationSource))" "INFO2" }
    if ($AppLinks.PrivacyUrl)     { Write-Log "Privacy URL: $($AppLinks.PrivacyUrl) (source: $($AppLinks.PrivacySource))" "INFO2" }

    # App icon: a repo file (IconFile, relative to the repo root) wins over a download link (IconUrl).
    $AppIconFile = ""
    if (-not (Test-IntuneFieldMissing -Value $IconFile)) {
        $AppIconFile = [string]$IconFile
        if (-not [System.IO.Path]::IsPathRooted($AppIconFile)) { $AppIconFile = Join-Path $RepoRoot $AppIconFile }
        if (-not (Test-Path -LiteralPath $AppIconFile)) {
            Write-Log "The catalog IconFile '$IconFile' was not found at $AppIconFile; no icon will be used." "WARNING"
            $AppIconFile = ""
        }
    }
    $AppIconUrl = ""
    if ([string]::IsNullOrWhiteSpace($AppIconFile) -and -not (Test-IntuneFieldMissing -Value $IconUrl)) { $AppIconUrl = [string]$IconUrl }

    $AppNotesFields = [ordered]@{
        'InstallMethod'    = $InstallMethod
        'Target Version'   = $Version
        'Packaged Version' = $PackagedVersion
        'PreRequisites'    = $PreRequisites
    }
    $AppTechnicalNotes = New-IntuneTechnicalNotes -AppFields $AppNotesFields -TargetRepo $RepoUrl -TargetBranch $Global:RepoBranch -SourceCommit $CurrentGitVer -Verified $Verified -SourceRepoRoot $RepoRoot -WaitsForOrgKeys $AppWaitsForOrgKeys

    # AppVersion: PackagedVersion, else Version, else the PowerDeploy commit - like printers, and
    # never WinGet's version, because WinGet installs whatever is latest on each device.
    $AppIntuneVersion = [string]$CurrentGitVer
    if (-not (Test-IntuneFieldMissing -Value $PackagedVersion)) { $AppIntuneVersion = [string]$PackagedVersion }
    elseif (-not (Test-IntuneFieldMissing -Value $Version)) { $AppIntuneVersion = [string]$Version }

    $AppIntuneMetadata = @{
        IntuneWinPath           = $ApplicationIntuneWinPath
        DisplayName             = $PotentialAppInTuneName
        Description             = $TheAppDescription
        Publisher               = $publisher
        AppVersion              = $AppIntuneVersion
        Category                = $(if (Test-IntuneFieldMissing -Value $Category) { "" } else { [string]$Category })
        Notes                   = $AppTechnicalNotes
        InstallCommandFile      = $MainInstallCommandTXT
        UninstallCommandFile    = $UninstallCommandTXT
        DetectionScriptFile     = $DetectAppScript
        AllowAvailableUninstall = $false
        InformationUrl          = [string]$AppLinks.InformationUrl
        PrivacyUrl              = [string]$AppLinks.PrivacyUrl
        IconFile                = $AppIconFile
        IconUrl                 = $AppIconUrl
    }

    Write-Log ""
    if ((Read-IntunePublishChoice) -eq '2') {
        if (Invoke-InTuneAutoUpload -Metadata $AppIntuneMetadata) { return }
        Clear
        Write-Log "==========================================================================================="
        Write-Log "UPLOAD AND CREATE INTUNE WIN32 APPLICATION (GUIDED)"
        Write-Log "==========================================================================================="
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
    Write-Log " 2 - Upload the .intunewin file located here:"
    Write-LogBlock "`n$ApplicationIntuneWinPath`n"
    Write-Log ""
    Pause   
    Write-Log "" 
    Write-Log " 3 - APP INFORMATION:"
    write-log "     - NAME (Pre-made default):"
    Write-LogBlock "`n$PotentialAppInTuneName`n"
    #Write-Log "         - What I recommend: ""$PotentialAppInTuneName"""

    # $Global:DeployMode = "PUBLIC-DEVELOPMENT"
    # $RepoUrl = $OfficialPublicRepoURL
    # $Global:RepoBranch = "dev"

    # Write-Log "     - Description: Up to your descretion. You could use the current repo commit number. Copying the description from Windows Store, App website, etc could be beneficial."
    # Write-Log "         - Sample Description with your commit #: `n`nPowered by PowerDeploy `n`nInstallMethod: $InstallMethod `nEndPoint Deployment Mode:$Global:DeployMode `nEndpoint Deployment Environment:`n   Git URL: $RepoUrl `n   Git Branch: $Global:RepoBranch `nThis Win32App Development Environment:`n   Git URL: $CurrentGitURL `n   Git Branch: $CurrentGitBranch `n   Git Commit Ver: $CurrentGitVer`n"
    
    Write-Log "     - DESCRIPTION (Pre-made default, shown to users in the Company Portal):"

    Write-Host ""
    Write-LogBlock $TheAppDescription
    Write-Host ""

    # Stamped once here, kept in its own variable so the technical block is never stamped twice
    $AppManualNotes = Complete-IntuneManualNotes -Notes $AppTechnicalNotes

    Write-Log "     - NOTES (Pre-made default, admins only - near the bottom of the App information page):"
    Write-Host ""
    Write-LogBlock $AppManualNotes
    Write-Host ""
    
    
    #Write-Log "     - Publisher: Look up the publisher if you are not sure. You can check the Windows Store, app website, etc."
    Write-Log "     - PUBLISHER: "
    Write-Host "`n"
    If ($publisher -eq "N/A"){Write-LogBlock "Currently empty. Look up the publisher if you are not sure. You can check the Windows Store, app website, etc."} else {Write-LogBlock "$Publisher"}
    Write-Host "`n"
    #Write-Log "     - Version: Recommend to leave blank unless you are using a static MSI installer with a set version."
    Write-Log "     - VERSION:"
    Write-Host "`n"
    #If ($VERSION -eq "N/A"){Write-Host "Currently empty."} else {Write-Host "$Publisher"}
    Write-LogBlock "$AppIntuneVersion"
    Write-Host "`n"
    #Write-Log "     - Category: Choose an existing category or create a new one here: https://learn.microsoft.com/en-us/intune/intune-service/apps/apps-add#create-and-edit-categories-for-apps"
    Write-Log "     - CATEGORY:"
    Write-Host "`n"
    If($Category -ne "" -and $Category -ne $null) {Write-LogBlock "$Category"} else {Write-LogBlock "Currently empty. Choose an existing category or create a new one here: https://learn.microsoft.com/en-us/intune/intune-service/apps/apps-add#create-and-edit-categories-for-apps"}
    Write-Host "`n"
    if ($AppLinks.InformationUrl) { Write-Log "     - INFORMATION URL:"; Write-LogBlock "`n$($AppLinks.InformationUrl)`n" }
    if ($AppLinks.PrivacyUrl)     { Write-Log "     - PRIVACY URL:";     Write-LogBlock "`n$($AppLinks.PrivacyUrl)`n" }
    if ($AppIconFile) {
        # An SVG is converted to a PNG for the operator, into Setup's Temp folder like a download.
        $GuidedIconFile = Resolve-IntuneSvgIconFile -Path $AppIconFile -Directory "$WorkingDirectory\Temp\Intune_Icons"
        if ($GuidedIconFile.Warning) {
            Write-Log "     $($GuidedIconFile.Warning)" "WARNING"
            Write-Log "     - LOGO: Convert this SVG to PNG yourself and upload it:"
            Write-LogBlock "`n$AppIconFile`n"
        } elseif ($GuidedIconFile.Converted) {
            Write-Log "     - LOGO: Select image and upload (converted to PNG from the catalog's SVG IconFile):"
            Write-LogBlock "`n$($GuidedIconFile.Path)`n"
        } else {
            Write-Log "     - LOGO: Select image and upload:"
            Write-LogBlock "`n$AppIconFile`n"
        }
    } elseif ($AppIconUrl) {
        # Download it for the operator, into Setup's Temp folder (beside the repo, never inside it).
        $GuidedIcon = Save-IntuneIconFromUrl -Url $AppIconUrl -Directory "$WorkingDirectory\Temp\Intune_Icons"
        if ($GuidedIcon.Path) {
            Write-Log "     - LOGO: Select image and upload (downloaded from the catalog's IconUrl):"
            Write-LogBlock "`n$($GuidedIcon.Path)`n"
        } else {
            Write-Log "     $($GuidedIcon.Warning)" "WARNING"
            Write-Log "     - LOGO: Download this image yourself and upload it:"
            Write-LogBlock "`n$AppIconUrl`n"
        }
    } else {
        Write-Log "     - LOGO: Optional - You could create something with Canva using your organization logo, but standardize it"
    }
    Write-Log "     - Everything else on this page is up to your discretion."
    Write-Log ""
    Pause   
    Write-Log "" 
    Write-Log " 4 - PROGRAM:"
    Write-Log "     - Install command:"
    Write-Log "         - Use the install command found inside this file: $MainInstallCommandTXT"
    # Shown on screen only, like the printer walkthrough: never logged, because the command can
    # carry the repository token.
    Write-Host ""
    Write-Host "Install Command:"
    Write-Host ""
    Write-Host ((Get-Content -LiteralPath $MainInstallCommandTXT -Raw).TrimEnd())
    Write-Host ""
    Write-Log "     - Uninstall command:"
    Write-Log "         - Use the uninstall command found inside this file: $UninstallCommandTXT"
    Write-Host ""
    Write-Host "Uninstall Command:"
    Write-Host ""
    Write-Host ((Get-Content -LiteralPath $UninstallCommandTXT -Raw).TrimEnd())
    Write-Host ""
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
    Write-Log "     - Script File: Upload this script:"
    Write-LogBlock "`n$DetectAppScript`n"
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
Function Printer--Install-Local{
    Param(

        $PrinterName=$null

    )

    Write-Log "To begin we will access the PrinterData.json file stored in Azure Blob Storage to show you the available printers."
    Write-Log ""

    $PrinterName = Select-PrinterFromJSON -PrinterName $PrinterName -DialogueSelection "A"

    if ($PrinterName -eq $null -or $PrinterName -eq "") {
        Write-Log "No printer selected. Printer will not be installed." "WARNING"
        Return
    }

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
Function Printer--Uninstall-Local{

    # Write-Log "Uninstalling a local printer function is still being developed." "ERROR"
    # Exit 1

    # List the installed printers
    $PrinterList = Get-Printer | Select-Object -ExpandProperty Name | Sort-Object
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
Function WindowsApp--Uninstall-Local{

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

        $UninstallMethod = "Remove-App-CIM"
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

        & $UninstallApp_ScriptPath -AppName $TargetApp -UninstallType "Remove-App-CIM" -WorkingDirectory $WorkingDirectory -SkipWinGet $True

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

        & $UninstallApp_ScriptPath -AppName $TargetApp -UninstallType "All" -WorkingDirectory $WorkingDirectory -UninstallString_DisplayName $DisplayName -SkipWinGet $True
        
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

        & $UninstallApp_ScriptPath -AppName $TargetApp -UninstallType $UninstallMethod -WorkingDirectory $WorkingDirectory -SkipWinGet $True

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
Function WindowsApp--Install-Local{

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

# Org registry keys decision for the Intune app wizard (build plan org-keys-retry section 4.5).
# Neither name contains "--", so neither becomes a menu item.
Function Get-PDAppPrereqCatalogInfo {
    param(
        [AllowNull()][object]$PreRequisites,
        [AllowNull()][object[]]$PublicApps,
        [AllowNull()][object[]]$PrivateApps
    )

    # One entry per prerequisite: Name, Source (Public / Private / NotFound), InstallMethod.
    # Public first, then private: the installer's own lookup order (a public entry shadows a private one).
    # Split on ',' and trimmed, one level deep, exactly like General_JSON-App_Installer.ps1.
    $Info = @()
    foreach ($RawPrereqs in @($PreRequisites)) {
        foreach ($Part in ([string]$RawPrereqs -split ',')) {
            $Name = $Part.Trim()
            if ([string]::IsNullOrWhiteSpace($Name) -or $Name -eq 'N/A') { continue }

            $Source = 'Public'
            $Entry = @($PublicApps | Where-Object { $null -ne $_ -and $_.ApplicationName -eq $Name }) | Select-Object -First 1
            if ($null -eq $Entry) {
                $Source = 'Private'
                $Entry = @($PrivateApps | Where-Object { $null -ne $_ -and $_.ApplicationName -eq $Name }) | Select-Object -First 1
            }
            if ($null -eq $Entry) { $Source = 'NotFound' }

            $Info += [pscustomobject]@{
                Name          = $Name
                Source        = $Source
                InstallMethod = $(if ($null -ne $Entry) { [string]$Entry.InstallMethod } else { '' })
            }
        }
    }

    return $Info
}

Function Get-PDAppOrgKeysDecision {
    param(
        [AllowNull()][string]$CatalogSource,
        [AllowNull()][string]$InstallMethod,
        [AllowNull()][object[]]$PrereqCatalogInfo
    )

    # Required when ANY is true: the app is in the private catalog; it uses a Blob install method; a
    # prerequisite is in the private catalog (or not in the public one, which sends the installer to the
    # private catalog) or uses a Blob install method. Anything unknown counts as required.
    $BlobMethods = @('MSI-Private-AzureBlob', 'EXE-Private-AzureBlob')
    $Reasons = @()

    if ($CatalogSource -eq 'Private') {
        $Reasons += 'app is in the private catalog'
    } elseif ($CatalogSource -ne 'Public') {
        $Reasons += 'app catalog source unknown'
    }

    if ($BlobMethods -contains $InstallMethod) {
        $Reasons += "InstallMethod is $InstallMethod"
    }

    foreach ($Prereq in @($PrereqCatalogInfo)) {
        if ($null -eq $Prereq) { continue }
        if ($Prereq.Source -eq 'Private') {
            $Reasons += "prerequisite '$($Prereq.Name)' is in the private catalog"
        } elseif ($Prereq.Source -ne 'Public') {
            $Reasons += "prerequisite '$($Prereq.Name)' is not in the public catalog"
        } elseif ($BlobMethods -contains [string]$Prereq.InstallMethod) {
            $Reasons += "prerequisite '$($Prereq.Name)' uses $($Prereq.InstallMethod)"
        }
    }

    if ($Reasons.Count -gt 0) {
        return [pscustomobject]@{ Required = $true; Reason = ($Reasons -join '; ') }
    }

    return [pscustomobject]@{ Required = $false; Reason = 'public catalog app, no Blob install method, public prerequisites only' }
}

Function SearchJSONForApp {

        param(
            [string]$AppNameToSearch
        )

        if ($list1 -contains $AppNameToSearch) {

            Write-Log "Confirmed valid application name: $AppNameToSearch" "INFO2"


            Write-Log "Found $AppNameToSearch in public JSON data." "INFO2"
            $AppData = $PublicJSONdata.applications | Where-Object { $_.ApplicationName -eq $AppNameToSearch }
            $Global:PDAppCatalogSource = 'Public'

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

            Write-Log "Confirmed valid application name: $AppNameToSearch" "INFO2"


            Write-Log "Found $AppNameToSearch in private JSON data." "INFO2"
            $AppData = $PrivateJSONdata.applications | Where-Object { $_.ApplicationName -eq $AppNameToSearch }
            $Global:PDAppCatalogSource = 'Private'

            Write-log "Application data for $AppNameToSearch retrieved from private JSON:" "INFO2"
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


        } else {

            Write-Log "Application $AppNameToSearch not found in either public or private JSON data." "ERROR"
            # Return $null
            Throw

        }

        # Where each prerequisite resolves, captured now because both catalogs only exist inside
        # Select-ApplicationFromJSON. Read by the Intune app wizard's org registry keys decision.
        # A failure here must never look like "app not found" to the caller, so it is caught.
        try {
            $Global:PDAppPrereqCatalogInfo = Get-PDAppPrereqCatalogInfo -PreRequisites $AppData.PreRequisites -PublicApps $PublicJSONdata.applications -PrivateApps $PrivateJSONdata.Applications
        } catch {
            $Global:PDAppPrereqCatalogInfo = @([pscustomobject]@{ Name = '(prerequisites could not be checked)'; Source = 'Unknown'; InstallMethod = '' })
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

    # $PublicJSONdata = ParseJSON -JSONpath $PublicJSONpath


        Write-Log "Parsing JSON" "INFO2"

        # $LocalJSONpath = "$WorkingDirectory\TEMP\Downloads\$PrinterData_JSON_BlobName"

        if (Test-Path $PublicJSONpath) {Write-Log "Local JSON found. Attempting to get content." "INFO2"} else { Write-Log "Local JSON not found" "ERROR"; throw "Local JSON not found" }
        
        
        
        
        #$jsonData = Get-Content -Raw $LocalJSONpath | ConvertFrom-Json
        try {
            $jsonText = Get-Content -LiteralPath $PublicJSONpath -Raw -Encoding UTF8
            $PublicJSONdata = $jsonText | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Write-Log "ConvertFrom-Json failed: $($_.Exception.Message)" "ERROR"
            throw $_
        }




    $list1 = $PublicJSONdata.applications.ApplicationName | Sort-Object


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
            
            
            # $JSONpath = $PrivateJSONpath

            # $PrivateJSONdata = ParseJSON -JSONpath $JSONpath

            if (Test-Path $PrivateJSONpath) {Write-Log "Local JSON found. Attempting to get content." "INFO2"} else { Write-Log "Local JSON not found" "ERROR"; throw "Local JSON not found" }
            
            
            #$jsonData = Get-Content -Raw $LocalJSONpath | ConvertFrom-Json
            try {
                $jsonText = Get-Content -LiteralPath $PrivateJSONpath -Raw -Encoding UTF8
                Write-Log "Json text; $jsonText" "INFO2"
                $PrivateJSONdata = $jsonText | ConvertFrom-Json -ErrorAction Stop
            } catch {
                Write-Log "ConvertFrom-Json failed: $($_.Exception.Message)" "ERROR"
                throw $_
            }

            # Write-Log "Applications count: $($PrivateJSONdata.Applications.Count)" "INFO2"
            # Write-Log "First app name: $($PrivateJSONdata.Applications[0].ApplicationName)" "INFO2"

            $list2 = $PrivateJSONdata.Applications.ApplicationName | Sort-Object

            # Write-Log "Application name count: $($list2.Count)" "INFO2"
            # Write-Log "First app name: $($list2[0])" "INFO2"

            # Pause


        }catch{

            Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END | Accessing JSON from private share failed. Exit code returned: $_" "ERROR"
            #Exit 1

            Write-Log "Proceeding with only public JSON data." "WARNING"
            
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
        if ($list2 -eq $null -or $list2 -eq "") {

            Write-Log "COULD NOT ACCESS"

        } else {

            Foreach ($item in $list2) {
                Write-Log "$Counter - $item"

                $HashTable.Add($Counter,$item)

                $Counter++

                #$HashTable
            }

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
        $list = $jsonData.printers.PrinterName | Sort-Object
 

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

                Write-Log "Enter the # of a printer from the above list to add to InTune." "WARNING"
                Write-Log " - NOTE: If you DO NOT SEE the printer you want, type 'exit' and you can add your own." "WARNING"
            
            } elseif ($DialogueSelection -eq "A"){

                Write-Log "Enter the # of a printer from the list above for installation." "WARNING"

            } elseif ($DialogueSelection -eq "C"){

                Write-Log "Enter the # of a printer from the list above for uninstallation." "WARNING"

            } else {

                Write-Log "Enter the # of a Printer from the list above." "WARNING"

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
            $printer = @($jsonData.printers | Where-Object { $_.PrinterName -eq $PrinterName })
            Write-Log "" "INFO2"

            # Duplicate names would copy an array into every field and blank them; stop this workflow (caller sees $null)
            if ($printer.Count -gt 1) {
                Write-Log "'$PrinterName' appears $($printer.Count) times in PrinterData.json; printer names must be unique." "ERROR"
                # Lets Printer--InTune-Setup tell a duplicate (stop) apart from a cancel (guided setup)
                $script:PrinterSelectionError = "'$PrinterName' appears $($printer.Count) times in PrinterData.json; printer names must be unique."
                Return $null
            }

            if ($printer.Count -eq 1) {
                $printer = $printer[0]
                
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
                Write-Log "PresetDriver: $PresetDriver" "INFO2"
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

# DEPRECATED 2/19/26 - imbedded the same logic into the main functions during troubleshooting.
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

        Write-Log "Successfully parsed JSON data from $JSONpath" "INFO2"

        Write-Log "Perceived JSON data: $jsonData" "INFO2"
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

# One organization registry value: show this PC's current value, then keep / replace / CLEAR it.
# Shared by OrganizationRegistryEntries--InTune-Setup and OrganizationRegistryEntries--Local-Setup.
Function Read-OrgRegistryEntryValue {

    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Label,
        [AllowNull()][AllowEmptyString()][string]$Current
    )

    Write-Log "==========================================================================================="
    Write-Log $Title
    Write-Log "==========================================================================================="
    Write-Log ""

    $ValueToUse = $Current
    $exit = "n"

    While ($exit -eq "n"){

        Write-Log "Your current organization $Label (read from this PC) is:"
        if ([string]::IsNullOrEmpty($Current)) { Write-Log "(not set)" } else { Write-Log "$Current" }
        Write-Log ""
        # Write-Log "If this is acceptable, press Enter to continue or enter the new key now:" "WARNING"
        Write-Log "Options:"
        Write-Log " - Input a new value"
        Write-Log " - Leave blank to keep existing"
        Write-Log " - Type 'CLEAR' to remove existing value"
        Write-Log ""
        $TempValue = Read-Host "Enter your selection"
        Write-Log ""

        if ($TempValue -eq "") {
            $ValueToUse = $Current
            Write-Log "Using existing $($Label): $ValueToUse"
        } elseif ($TempValue -eq "CLEAR") {
            $ValueToUse = ""
            Write-Log "Clearing $Label, setting to blank."
        } else {
            $ValueToUse = $TempValue
            Write-Log "Using new $($Label): $ValueToUse"
        }

        Write-Log ""
        Write-Log "Is this acceptable?" "WARNING"
        $exit = Read-Host "(y/n)"
        Write-Log ""
    }

    return $ValueToUse
}

# Collects the four organization values an admin enters by hand (the other three are the defaults in
# Generate_Install-Command.ps1 -> OrgRegistryChangesString). -Target only changes the wording: the
# values either go into Intune remediation scripts or straight into this PC's registry.
Function Read-OrgRegistryEntryValues {

    param(
        [ValidateSet('Intune', 'Local')][string]$Target = 'Intune'
    )

    Write-Log ""
    if ($Target -eq 'Local') {
        Write-Log "The values you enter below will be written to THIS PC's registry only (HKLM\SOFTWARE\PowerDeploy)." "WARNING"
    } else {
        Write-Log "The values you enter below will be built into Intune remediation scripts that write them to every device you assign them to." "WARNING"
    }
    Write-Log ""

    Write-Log "Do you need instructions on generating SAS keys for your Azure Blob Storage containers?" "WARNING"
    $NeedInstructions = Read-Host "(y/n)"
    While ($NeedInstructions -ne "y" -and $NeedInstructions -ne "n") {
        Write-Log "Invalid choice. Please enter 'y' or 'n'." "ERROR"
        $NeedInstructions = Read-Host "(y/n)"
    }
    Write-Log ""
    if ($NeedInstructions -eq "y") {

        $StorageAccountToShow = $StorageAccountName
        if ([string]::IsNullOrWhiteSpace($StorageAccountToShow)) { $StorageAccountToShow = "(your PowerDeploy storage account)" }

        Write-Log "Instructions for navigating to your Azure Blob Storage container as follows:"
        Write-Log ""
        Write-Log " 1 - Go to https://portal.azure.com/#view/Microsoft_Azure_StorageHub/StorageHub.MenuView/~/StorageAccountsBrowse"
        Write-Log ""
        Write-Log " 2 - Select this storage account: $StorageAccountToShow"
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

    [hashtable]$Values = @{
        CustomRepoURL              = Read-OrgRegistryEntryValue -Title "GIT REPO URL"              -Label "Git Repo URL"            -Current $CustomRepoURL

    # if ($RepoURLtoUse -ne "" -or $null -ne $RepoURLtoUse) {

    #     $HashTable.Add("CustomRepoURL", $RepoURLtoUse)

    # }

        CustomRepoToken            = Read-OrgRegistryEntryValue -Title "GIT REPO TOKEN"            -Label "Git Repo Token"          -Current $CustomRepoToken

    # if ($CustomRepoTokenToUse -ne "" -or $null -ne $CustomRepoTokenToUse) {

    #     $HashTable.Add("CustomRepoToken", $CustomRepoTokenToUse)
    # }


    # Write-Log "Enter your custom PRINTER share SAS key:" "WARNING"

    # $PrinterContainerSASkey = Read-Host "SAS KEY"

        PrinterContainerSASkey     = Read-OrgRegistryEntryValue -Title "PRINTER SHARE SAS KEY"     -Label "PRINTER share SAS key"   -Current $PrinterContainerSASkey

    # if ($PrintSASKeytoUse -ne "" -or $null -ne $PrintSASKeytoUse) {

    #     $HashTable.Add("PrinterContainerSASkey", $PrintSASKeytoUse)
    # }


    # Write-Log "Enter your custom APPLICATION share SAS key:" "WARNING"  

    # $ApplicationContainerSASkey = Read-Host "SAS KEY"

        ApplicationContainerSASkey = Read-OrgRegistryEntryValue -Title "APPLICATION SHARE SAS KEY" -Label "APP share SAS key"       -Current $ApplicationContainerSASkey

    # if ($ApplicationSASKeytoUse -ne "" -or $null -ne $ApplicationSASKeytoUse) {

    #     $HashTable.Add("ApplicationContainerSASkey", $ApplicationSASKeytoUse)
    # }
    }

    Write-Log ""

    return $Values
}

# DONE 1/14/26 - Thoroughly tested
Function OrganizationRegistryEntries--InTune-Setup{

    # Determine if this is a test or production deployment
    $RepoUrl = Set-URL
    Write-Log "==========================================================================================="
    Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START"
    Write-Log "==========================================================================================="

    Write-Log ""
    Write-Log "ORGANIZATION REGISTRY ENTRIES - INTUNE SETUP"
    Write-Log ""

    # NOTE: Not currently used - kept for the planned "only pass non-blank values" feature (see the commented
    # $HashTable lines in Read-OrgRegistryEntryValues). $HashTable is never set today, so this would only assign
    # $null before the real assignment below. When enabling it, have Read-OrgRegistryEntryValues return the
    # filtered table (its $HashTable is local to that function), and keep this ABOVE the real assignment.
    # [hashtable]$FunctionParams = $HashTable

    [hashtable]$FunctionParams = Read-OrgRegistryEntryValues -Target 'Intune'

    Write-Log ""
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
    Write-Log "The scripts have been created!" "SUCCESS"
    Write-Log ""
    Write-Log "Next we are going to upload the detect and remediation script to InTune."
    Write-Log "Detect Script location: $DetectScript"
    Write-Log "Remediate Script location: $RemediationScript"
    Write-Log ""

    Write-Log "1. In InTune, navigate to: Device > Windows > Scripts and remediations"
    Write-Log " - Direct link: https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesWindowsMenu/~/powershell"
    Write-Log ""
    Write-Log "2. Navigate to your PowerDeploy Registry Update remediation script package. If you for sure do not have one, we will walk through creating one."
    Write-Log ""
    Write-Log "NOTE: Make sure that you do not leave behind old remediation scripts in production once replace them." "WARNING"
    Write-Log ""
    Write-Log "Do you need to create a new Remediation Script package entry in InTune?" "WARNING"
    $Answer = Read-Host "(y/n)"

    if ($Answer -eq "y"){

        Write-Log "  To create a new entry..."
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

    Write-Log ""

    Write-Log "Do you need to create a new InTuneWin package entry in InTune?" "WARNING"
    $Answer = Read-Host "(y/n)"
    if ($Answer -eq "y"){

        Write-Log "Now packaging InTuneWin stuff..."

        Make-InTuneWin -SourceFile $RemediationScript
        $RemediationIntuneWinPath = $Global:intunewinpath

        Write-Log ""    
        Write-Log "The Intune Win32 app package has been created at: $RemediationIntuneWinPath"
        # Write-Log ""    

        # Write-Log "Next we will automatically create the install/uninstall commands. Keep in mind the uninstall command is dummy, it won't do anything by design in this scenario."


        Write-Log ""   

        $RemediationScriptName = Split-Path -Path $RemediationScript -Leaf

        $InstallCommand = '%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& ''.\'+"$RemediationScriptName"+'''"'
    
        Write-Log "InstallCommand: $InstallCommand"
        Write-Log ""   

        Write-Log "UninstallCommand (dummy): $InstallCommand"

        Write-Log ""   

        Write-Log "Detection Script: $DetectScript"

        Write-Log ""  


    }

    Pause
    Write-Log ""
    Write-Log "That's all! After deploying to endpoints give your target machines some time and monitor progress." "SUCCESS"



}

# Writes the organization registry values straight to THIS PC, for a machine that no PowerDeploy
# registry remediation targets yet. Same prompts as OrganizationRegistryEntries--InTune-Setup, the same
# value layout and defaults (Generate_Install-Command.ps1 -> OrgRegistryChangesString), and the same
# write / lock down / read back script the Intune remediation runs on endpoints.
Function OrganizationRegistryEntries--Local-Setup {

    Write-Log "==========================================================================================="
    Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START"
    Write-Log "==========================================================================================="
    Write-Log ""
    Write-Log "ORGANIZATION REGISTRY ENTRIES - LOCAL SETUP"
    Write-Log ""
    Write-Log "This function is used to set up the custom Organization Registry Entries manually."
    Write-log "This is useful on a fresh PC or when no PowerDeploy registry remediation from Intune targets this PC yet." "INFO2"
    Write-Log "In the future if an automated remediation does target this PC, the remediation's values will replace the local values you have set up manually." "INFO2"

    [hashtable]$FunctionParams = Read-OrgRegistryEntryValues -Target 'Local'

    Write-Log "Building the registry values..." "INFO2"
    Write-Log ""

    $RegistryChanges = [string](@(& $GenerateInstallCommand_ScriptPath `
        -DesiredFunction "OrgRegistryChangesString" `
        -TargetWorkingDirectory $WorkingDirectory `
        -FunctionParams $FunctionParams) | Select-Object -Last 1)

    $Entries = @([regex]::Matches($RegistryChanges, '-KeyPath "(?<k>(?:[^"]|"")*)" -ValueName "(?<n>(?:[^"]|"")*)" -ValueType "(?:[^"]|"")*" -Value "(?<v>(?:[^"]|"")*)"'))

    if ($Entries.Count -eq 0) {
        Write-Log "Could not build the registry values; nothing was written. See the Generator_Logs folder for details." "ERROR"
        return
    }

    Write-Log ""
    Write-Log "==========================================================================================="
    Write-Log "REVIEW"
    Write-Log "==========================================================================================="
    Write-Log ""
    Write-Log "These values will be written to this PC's registry:"
    Write-Log ""
    foreach ($Entry in $Entries) {
        $ShownValue = $Entry.Groups['v'].Value -replace '""', '"'
        if ([string]::IsNullOrEmpty($ShownValue)) { $ShownValue = "(blank)" }
        Write-Log ("   {0}\{1} = {2}" -f $Entry.Groups['k'].Value, $Entry.Groups['n'].Value, $ShownValue) "INFO2"
    }
    Write-Log ""
    Write-Log "StorageAccountName and the two JSON paths are the defaults in Other_Tools\Generate_Install-Command.ps1 (OrgRegistryChangesString)." "INFO2"
    Write-Log ""

    Write-Log "Write these values to this PC's registry now?" "WARNING"
    $Answer = Read-Host "(y/n)"
    While ($Answer -ne "y" -and $Answer -ne "n") {
        Write-Log "Invalid choice. Please enter 'y' or 'n'." "ERROR"
        $Answer = Read-Host "(y/n)"
    }
    Write-Log ""

    if ($Answer -ne "y") {
        Write-Log "Cancelled; nothing was written." "WARNING"
        return
    }

    Write-Log "Writing the values, locking down the key, and reading them back..." "INFO2"
    Write-Log ""

    # Guarded like Git-Runner guards the same call: a terminating error inside the template must not
    # escape into the menu, and a stale exit code from earlier must not read as success.
    $global:LASTEXITCODE = 1
    try {
        & $General_RemediationScript_Registry_TEMPLATE `
            -RegistryChanges $RegistryChanges `
            -WorkingDirectory $WorkingDirectory `
            -RepoNickName $ThisRepoNickName `
            -function 'Remediate' `
            -AlsoLockDown $True
        $ExitCode = $global:LASTEXITCODE
    } catch {
        Write-Log "The registry write stopped with an error: $_" "ERROR"
        $ExitCode = 1
    }

    Write-Log ""

    if ($ExitCode -ne 0) {
        Write-Log "The registry values could not all be written and confirmed (exit code $ExitCode). See the output above and the Detection_Logs folder." "ERROR"
        return
    }

    # On endpoints, Git-Runner's Security_Manager.ps1 also locks the parent key (the template only
    # locks keys it creates). Same call, so this PC ends up with the same ACLs as a managed endpoint.
    $global:LASTEXITCODE = 1
    try {
        & "$RepoRoot\Configurators\Configure-Registry.ps1" -KeyOnly $true -KeyPath 'HKLM:\SOFTWARE\PowerDeploy' -Function "Lockdown" -WorkingDirectory $WorkingDirectory
        $LockExitCode = $global:LASTEXITCODE
    } catch {
        Write-Log "Locking down HKLM\SOFTWARE\PowerDeploy stopped with an error: $_" "ERROR"
        $LockExitCode = 1
    }

    Write-Log ""

    if ($LockExitCode -ne 0) {
        Write-Log "The values were written and confirmed, but HKLM\SOFTWARE\PowerDeploy could not be locked down to SYSTEM and Administrators (exit code $LockExitCode). See the Config_Logs folder." "ERROR"
        return
    }

    Write-Log "All values were written to this PC's registry and confirmed." "SUCCESS"
    Write-Log "Close and reopen Setup so it picks up the new values." "WARNING"
    Write-Log ""

}

# DONE 2/19/26 - Keeping simple for now
Function Adobe-Apps-FullCleanup--Uninstall-Local{

    Clear 

    & $AdobeUninstallCleanup_ScriptPath -WorkingDirectory $WorkingDirectory


}


#region Intune API upload (Graph) - menu, its helpers, and the wizards' publishing helpers

# ---------------------------------------------------------------------------
# Intune upload: credential provisioning menu (spec 7.2)
#
# Only InTuneAPI--Setup-and-Manage has '--' in its name, because the reflection menu at the end
# of this script lists every function whose name contains '--'. Everything else here is a helper it
# calls. None of these functions prompt for metadata or publish anything: they create, test, rotate
# and remove ONE thing, the credential the uploader uses. Publishing stays with the upload entry
# point, and the guided walkthrough is always still available.
#
# No function here calls exit, and every failure is reported and returns to this menu, because an
# error in this menu must never close Setup for the technician.
# ---------------------------------------------------------------------------

Function Show-GraphUploadMenu {

    Clear

    Write-Log "==========================================================================================="
    Write-Log "============== Intune API upload: setup ==================================================================="
    Write-Log "==========================================================================================="
    Write-Log ""
    Write-Log "This menu manages the credential that PowerDeploy uses to publish apps through Microsoft Graph."
    Write-Log "It is stored only on this Windows account, protected by Windows DPAPI. It is never stored in the fleet registry, in this repo, or in any log."
    Write-Log ""
    Write-Log "1 - Azure App Registration - Setup/Config (prerequisite for API uploads)"
    Write-Log "2 - Azure App Registration - Test config"
    Write-Log "3 - Azure App Registration - Rotate local PC secret"
    Write-Log "4 - Azure App Registration - Remove local PC secret"
    Write-Log "5 - MAA Exclusions - Setup/Config manually (not prerequisite, useful if your tenant has MAA enabled)"
    Write-Log "0 - Return"
    Write-Log ""

}

Function Show-GraphUploadError {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Failure
    )

    # Errors from the Graph helper library arrive already sanitized. Anything else (a .NET fault,
    # an unexpected cmdlet error) is shown through Remove-UrlCredential as well, so a URL carrying
    # credentials can never reach the console or the log from here (spec 11.1).
    $message = 'Unknown error.'

    try {
        if ($null -ne $Failure.Exception -and -not [string]::IsNullOrWhiteSpace($Failure.Exception.Message)) {
            $message = [string]$Failure.Exception.Message
        } elseif ($null -ne $Failure) {
            $message = [string]($Failure | Out-String).Trim()
        }
    } Catch {
        $message = 'Unknown error.'
    }

    if (Get-Command -Name 'Remove-UrlCredential' -CommandType Function -ErrorAction SilentlyContinue) {
        $message = Remove-UrlCredential -Url $message
    }

    foreach ($line in ($message -split "`r?`n")) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { Write-Log $line.Trim() 'ERROR' }
    }
}

Function Read-GraphUploadYesNo {
    param(
        [Parameter(Mandatory = $true)][string]$Question,
        [bool]$Default = $true,
        [string]$Note = ''
    )

    Write-Log $Question 'WARNING'

    if (-not [string]::IsNullOrWhiteSpace($Note)) {
        foreach ($line in ($Note -split "`r?`n")) {
            if (-not [string]::IsNullOrWhiteSpace($line)) { Write-Log ("     " + $line.Trim()) 'INFO2' }
        }
    }

    $hint = '(y/n) [n]'
    if ($Default) { $hint = '(y/n) [y]' }

    While ($true) {

        $Answer = ([string](Read-Host $hint)).Trim().ToLowerInvariant()

        if ([string]::IsNullOrWhiteSpace($Answer)) { return $Default }
        if ($Answer -eq 'y') { return $true }
        if ($Answer -eq 'n') { return $false }

        Write-Log "Invalid input. Please enter 'y' for yes or 'n' for no." 'ERROR'

    }
}

Function Read-GraphUploadTenantId {

    # Spec 7.2 step 1: collect the tenant ID, then sign in. A value that is not a GUID is refused
    # rather than sent to the sign-in, and Enter is allowed to mean "accept whichever tenant the
    # account signs in to" - the session is still verified before anything is written.
    While ($true) {

        Write-Log "Enter your Tenant ID (Entra admin center > Overview > Tenant ID)." 'WARNING'
        Write-Log "     Or press Enter to use the tenant of the account you sign in with." 'INFO2'

        $Answer = ([string](Read-Host "Tenant ID")).Trim()

        if ([string]::IsNullOrWhiteSpace($Answer)) {
            if (-not (Read-GraphUploadYesNo -Question "Continue without naming the tenant?" -Default $false)) { return $null }
            return ''
        }

        $Parsed = [guid]::Empty
        if ([guid]::TryParse($Answer, [ref]$Parsed)) { return $Parsed.ToString() }

        Write-Log "That is not a Tenant ID GUID, so it was not used." 'ERROR'

    }
}

Function Read-GraphUploadSecretLifetime {

    param([int]$Default = 180)

    # Spec 7.2 step 7: six months by default, but a different lifetime consistent with tenant
    # policy is accepted. The service still decides what the tenant really allows.
    While ($true) {

        Write-Log "How many days should this PC's secret last before it has to be rotated?" 'WARNING'
        Write-Log "     Press Enter for $Default days (about six months)." 'INFO2'

        $Answer = ([string](Read-Host "Days")).Trim()

        if ([string]::IsNullOrWhiteSpace($Answer)) { return $Default }

        $Days = 0
        if (-not [int]::TryParse($Answer, [ref]$Days)) {
            Write-Log "Please enter a whole number of days." 'ERROR'
            continue
        }

        if ($Days -lt 1 -or $Days -gt ([int]$PDGraph.MaxSecretLifetimeDays)) {
            Write-Log "Please enter between 1 and $([int]$PDGraph.MaxSecretLifetimeDays) days." 'ERROR'
            continue
        }

        return $Days

    }
}

Function Confirm-GraphUploadAdminModule {

    param([string]$Purpose = 'automatic API setup')

    # The administrator sign-in needs Microsoft.Graph.Authentication. The library only reports it
    # missing (it must never install anything as a side effect of loading - spec 7.1), so the offer
    # to install it lives here, behind an explicit yes. Returns $true when the module is usable.
    $Prerequisite = Get-PDGraphProvisioningPrerequisite

    if ($Prerequisite.Available) { return $true }

    Write-Log "The administrator sign-in function (which is required for $Purpose) needs the Microsoft Graph PowerShell module ($([string]$PDGraph.MgModuleName)), which is not installed for this Windows account." 'WARNING'
    Write-Log ""
    Write-Log "Installation can take place automatically right now, or you can manually install with this command: $([string]$PDGraph.MgModuleInstallHint)"
    Write-Log ""

    $Install = Read-GraphUploadYesNo -Question "Would you like this script to automatically install the Microsoft Graph PowerShell module right now?" -Default $true

    if (-not $Install) {
        Write-Log "Not installed; nothing was changed. Uploads, the Manual setup choice and guided publishing work without it." 'WARNING'
        return $false
    }

    Write-Log ""
    Write-Log "Installing $([string]$PDGraph.MgModuleName) for this Windows account. This can take a minute..." 'INFO2'

    try {

        # Older .NET defaults can refuse the Gallery's TLS 1.2. Only this process is affected.
        $Protocol = [Net.ServicePointManager]::SecurityProtocol
        if ($Protocol -ne [Net.SecurityProtocolType]::SystemDefault -and -not ($Protocol -band [Net.SecurityProtocolType]::Tls12)) {
            [Net.ServicePointManager]::SecurityProtocol = $Protocol -bor [Net.SecurityProtocolType]::Tls12
        }

        # Stock Windows PowerShell 5.1 has no NuGet provider, and Install-Module would otherwise stop
        # to ask for it. -Force on both calls also skips the "untrusted repository" prompt for this
        # one install, without marking PSGallery as trusted.
        $NuGet = Get-PackageProvider -ListAvailable -Name 'NuGet' -ErrorAction SilentlyContinue |
                 Where-Object { $_.Version -ge [version]'2.8.5.201' } | Select-Object -First 1
        if ($null -eq $NuGet) {
            Write-Log "     Installing the NuGet package provider (needed by Install-Module)..." 'INFO2'
            Install-PackageProvider -Name 'NuGet' -MinimumVersion '2.8.5.201' -Scope CurrentUser -Force -ErrorAction Stop | Out-Null
        }

        Install-Module -Name ([string]$PDGraph.MgModuleName) -Repository 'PSGallery' -Scope CurrentUser -Force -ErrorAction Stop

    } Catch {

        Write-Log "The install did not complete:" 'ERROR'
        Show-GraphUploadError $_
        Write-Log "You can retry, or install it yourself with: $([string]$PDGraph.MgModuleInstallHint)" 'WARNING'
        return $false

    }

    $Prerequisite = Get-PDGraphProvisioningPrerequisite

    if (-not $Prerequisite.Available) {
        Write-Log "The install reported no error, but the module still cannot be found. Close and reopen Setup, then try again." 'ERROR'
        return $false
    }

    Write-Log "Installed $([string]$PDGraph.MgModuleName) $($Prerequisite.Version)." 'SUCCESS'
    Write-Log ""
    return $true
}

Function Connect-GraphUploadAdminSession {

    param(
        [switch]$IncludeConsent,
        [string]$Purpose = 'make this change'
    )

    # The upload identity is never allowed to manage applications (spec 7.1), so anything here that
    # touches Entra is done by a temporary sign-in as an administrator. This function owns the
    # prompts; the library owns the connection and its verification.
    if (-not (Confirm-GraphUploadAdminModule)) { return $null }

    $TenantId = Read-GraphUploadTenantId
    if ($null -eq $TenantId) {
        Write-Log "Cancelled; no sign-in was attempted." 'WARNING'
        return $null
    }

    Write-Log ""
    Write-Log "Opening sign in window to $Purpose." 'WARNING'
    Write-Log ""
    Write-Log "About the permissions requested:"
    Write-Log "  - Read and write applications: finds or creates the PowerDeploy Azure App Registration and adds or removes its secrets."
    if ($IncludeConsent) {
        Write-Log "  - Manage app permission grants and app role assignments: gives that application its two permissions (manage Intune apps, read groups)."
    }
    Write-Log "  - View users' basic profile: tells Setup which account signed in, so it can check you are in the right tenant."
    Write-Log "  - Maintain access to data you have given it access to: lets the sign-in renew itself so you are not asked again every hour."
    Write-Log "The Microsoft screen may also list permissions your organization approved earlier for Microsoft Graph PowerShell. PowerDeploy only requests the ones above."
    Write-Log "Leave 'Consent on behalf of your organization' unchecked." 'WARNING'
    Write-Log ""

    $Connect = Connect-PDGraphInteractive -TenantId $TenantId -IncludeConsent:$IncludeConsent

    if ($Connect.Reason -eq 'ExistingContext') {

        Write-Log $Connect.Message 'WARNING'
        Write-Log "     r - reuse that sign-in" 'INFO2'
        Write-Log "     s - sign in again instead" 'INFO2'
        Write-Log "     anything else - go back" 'INFO2'

        $Answer = ([string](Read-Host "r/s")).Trim().ToLowerInvariant()

        if ($Answer -eq 'r') {
            $Connect = Connect-PDGraphInteractive -TenantId $TenantId -ReuseExistingContext
        } elseif ($Answer -eq 's') {
            $Connect = Connect-PDGraphInteractive -TenantId $TenantId -IncludeConsent:$IncludeConsent -ReplaceExistingContext
        } else {
            Write-Log "Cancelled; the existing sign-in was left as it was." 'WARNING'
            return $null
        }

    }

    if (-not $Connect.Success) {
        Write-Log $Connect.Message 'ERROR'
        return $null
    }

    Write-Log $Connect.Message 'SUCCESS'
    return $Connect.Session
}

Function Show-GraphUploadSteps {

    param([AllowNull()][object]$Steps)

    foreach ($step in @(Get-PDGraphItems -Payload $Steps)) {
        if ($null -eq $step) { continue }

        $name    = [string](Get-PDGraphPropertyValue -Object $step -Name 'Step')
        $ok      = [bool](Get-PDGraphPropertyValue -Object $step -Name 'Success')
        $message = [string](Get-PDGraphPropertyValue -Object $step -Name 'Message')
        $status  = 'OK   '
        if (-not $ok) { $status = 'FAILED' }

        Write-Log ("     {0} {1,-22} {2}" -f $status, $name, $message) 'INFO2'
    }
}

Function Show-GraphUploadCredentialState {

    $summary = Get-PDGraphCredentialSummary

    Write-Log ""

    if (-not $summary.Stored) {
        Write-Log "No credential is stored for this Windows account yet." 'WARNING'
        Write-Log "     Expected at: $($summary.Path)" 'INFO2'
        return $summary
    }

    Write-Log "Stored credential for this Windows account:" 'WARNING'
    Write-Log ("     Application: {0}" -f [string]$summary.AppDisplayName) 'INFO2'
    Write-Log ("     Tenant ID:   {0}" -f [string]$summary.TenantId) 'INFO2'
    Write-Log ("     Client ID:   {0}" -f [string]$summary.ClientId) 'INFO2'

    if ($summary.Usable) {
        Write-Log ("     Secret expires: {0} ({1} day(s))" -f $summary.SecretExpiresOn.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture), $summary.DaysUntilExpiry) 'INFO2'
        Write-Log ("     Secret key id:  {0}" -f $(if ([string]::IsNullOrWhiteSpace($summary.SecretKeyId)) { 'not recorded (rotation will report the old key for manual cleanup)' } else { [string]$summary.SecretKeyId })) 'INFO2'
    } else {
        Write-Log "     The file exists but is not usable: $($summary.Message)" 'ERROR'
    }

    foreach ($warning in @($summary.Warnings)) {
        if (-not [string]::IsNullOrWhiteSpace($warning)) { Write-Log "     WARNING: $warning" 'WARNING' }
    }

    Write-Log "     (The secret value itself is never shown.)" 'INFO2'

    return $summary
}

Function Invoke-GraphUploadProvisionApplication {

    # Spec 7.2 "Create/configure". The prompts and the confirmation are here; every tenant write is
    # done by Start-PDGraphUploadProvisioning, which is where the step-by-step behaviour lives and is
    # tested. An existing sign-in is never reused without asking, and one opened here is closed here.

    Write-Log ""
    Write-Log "-------------------------------------------------------------------------------------------"
    Write-Log "AZURE APP REGISTRATION - SETUP/CONFIG (AUTOMATIC)"
    Write-Log "-------------------------------------------------------------------------------------------"
    Write-Log ""

    if (-not (Confirm-GraphUploadAdminModule)) { return }

    $LifetimeDays = Read-GraphUploadSecretLifetime -Default ([int]$PDGraph.DefaultSecretLifetimeDays)

    $Session = Connect-GraphUploadAdminSession -IncludeConsent -Purpose 'automatically create or configure the Azure App Registration'
    if ($null -eq $Session) { return }

    try {

        Write-Log ""
        Write-Log "Checking whether the PowerDeploy Azure App Registration already exists in your tenant..." 'INFO2'

        $Found         = Find-PDEntraUploadApp
        $ApplicationId = ''
        $AppName       = [string]$PDGraph.AppDisplayName

        # Say what was found before saying what happens next.
        if (-not $Found.Found) {
            Write-Log "     Not found: no Azure App Registration named '$AppName' exists yet." 'INFO2'
        } elseif (-not $Found.Multiple) {
            $Existing = @($Found.Apps)[0]
            Write-Log "     Found: '$AppName' already exists (id $($Existing.ApplicationId), created $($Existing.Created))." 'INFO2'
        }

        if ($Found.Multiple) {

            Write-Log ""
            Write-Log "More than one Azure App Registration is named '$AppName'. Pick the one PowerDeploy should use:" 'WARNING'

            foreach ($Candidate in @($Found.Apps)) {
                Write-Log ("     {0}   (created {1})" -f [string]$Candidate.ApplicationId, [string]$Candidate.Created) 'INFO2'
            }

            While ($true) {

                $Answer = ([string](Read-Host "Paste the id to use, or press Enter to go back")).Trim()

                if ([string]::IsNullOrWhiteSpace($Answer)) {
                    Write-Log "Cancelled; nothing was changed." 'WARNING'
                    return
                }

                foreach ($Candidate in @($Found.Apps)) {
                    if (([string]$Candidate.ApplicationId) -ieq $Answer) { $ApplicationId = $Answer; break }
                }

                if (-not [string]::IsNullOrWhiteSpace($ApplicationId)) { break }

                Write-Log "That id is not one of the ones listed above." 'ERROR'

            }

        }

        # One plain list of what is about to happen, then one question.
        Write-Log ""
        Write-Log "PowerDeploy will now:" 'WARNING'
        if ($Found.Found) {
            Write-Log "     1 - Use the existing Azure App Registration '$AppName'"
        } else {
            Write-Log "     1 - Create an Azure App Registration named '$AppName' (none exists yet)"
        }
        Write-Log "     2 - Make sure it has its two permissions: manage Intune apps, and read groups"
        Write-Log "     3 - Create a secret for this PC (valid $LifetimeDays days), test it, and save it encrypted for your Windows account"
        Write-Log ""

        if (-not (Read-GraphUploadYesNo -Question "Go ahead?" -Default $true)) {
            Write-Log "Cancelled; nothing was changed." 'WARNING'
            return
        }

        Write-Log ""
        Write-Log "Setting up the Azure App Registration. A brand-new secret can take a few minutes to start working; Setup waits for it (up to 5 minutes)..." 'INFO2'

        $Result = Start-PDGraphUploadProvisioning -Session $Session -ApplicationId $ApplicationId -SecretLifetimeDays $LifetimeDays

        Show-GraphUploadSteps -Steps $Result.Steps

        foreach ($Warning in @($Result.Warnings)) {
            if (-not [string]::IsNullOrWhiteSpace($Warning)) { Write-Log "     $Warning" 'WARNING' }
        }

        Write-Log ""

        if ($Result.Success) {

            Write-Log $Result.Message 'SUCCESS'
            Write-Log "     Automatic publishing is now offered in the printer and app wizards." 'INFO2'

        } else {

            Write-Log $Result.Message 'ERROR'
            Write-Log ""

            if ($Result.Reason -eq 'NeedsSelection') {
                Write-Log "Run this option again and choose one of the application ids it listed." 'WARNING'
            }

            Write-Log "Nothing was saved to this machine unless the steps above say it was. Guided manual publishing is still available from the printer and app wizards." 'WARNING'

        }

    } Catch {

        Show-GraphUploadError $_
        Write-Log "Guided manual publishing is still available from the printer and app wizards." 'WARNING'

    } Finally {

        $Closed = Disconnect-PDGraphInteractive -Session $Session
        Write-Log "     $($Closed.Message)" 'INFO2'

    }

}

Function Invoke-GraphUploadEnterCredential {

    # Spec 7.2 "Manual entry": TenantId, ClientId, expiry and secret (Read-Host -AsSecureString),
    # tested against the tenant BEFORE the local configuration is replaced. AppObjectId and
    # SecretKeyId may be absent and are never invented; without a key id, rotation reports the old
    # secret for manual revocation instead of guessing at it.

    Write-Log ""
    Write-Log "-------------------------------------------------------------------------------------------"
    Write-Log "AZURE APP REGISTRATION - SETUP/CONFIG (MANUAL)"
    Write-Log "-------------------------------------------------------------------------------------------"
    Write-Log ""
    Write-Log "Use this when the application already exists in your tenant and its secret was created somewhere"
    Write-Log "else. No browser sign-in is needed: the secret is tested with the same client-credentials call the"
    Write-Log "upload itself uses. Nothing is saved unless that test passes." 'WARNING'
    Write-Log ""

    Show-GraphUploadCredentialState | Out-Null
    Write-Log ""

    While ($true) {

        $Answer = ([string](Read-Host "Tenant ID (GUID)")).Trim()
        $Parsed = [guid]::Empty
        if ([guid]::TryParse($Answer, [ref]$Parsed)) { $TenantId = $Parsed.ToString(); break }
        Write-Log "A tenant ID GUID is required, because it is stored with the credential." 'ERROR'

    }

    While ($true) {

        $Answer = ([string](Read-Host "Client ID / application ID (GUID)")).Trim()
        $Parsed = [guid]::Empty
        if ([guid]::TryParse($Answer, [ref]$Parsed)) { $ClientId = $Parsed.ToString(); break }
        Write-Log "A client ID GUID is required." 'ERROR'

    }

    Write-Log ""
    Write-Log "Type the secret below. It is not echoed, it is not written to the log, and it is stored only as a"
    Write-Log "DPAPI-protected value for this Windows account." 'WARNING'

    try {
        $ClientSecret = Read-Host "Secret value" -AsSecureString
    } Catch {
        Write-Log "The secret could not be entered, so nothing was changed." 'ERROR'
        return
    }

    $DefaultExpiry = [System.DateTimeOffset]::UtcNow.AddDays([double]$PDGraph.DefaultSecretLifetimeDays)
    $DefaultText   = $DefaultExpiry.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)

    While ($true) {

        Write-Log "When does this secret expire? Enter a date, or press Enter for $DefaultText (today + $([int]$PDGraph.DefaultSecretLifetimeDays) days)." 'WARNING'
        $Answer = ([string](Read-Host "Secret expiry")).Trim()

        if ([string]::IsNullOrWhiteSpace($Answer)) { $ExpiresOn = $DefaultExpiry; break }

        $Parsed = [System.DateTimeOffset]::UtcNow
        if ([System.DateTimeOffset]::TryParse($Answer, [System.Globalization.DateTimeFormatInfo]::InvariantInfo, [System.Globalization.DateTimeStyles]::None, [ref]$Parsed)) {
            $ExpiresOn = $Parsed
            break
        }

        Write-Log "That date could not be read. Try a date like 2026-04-09." 'ERROR'

    }

    Write-Log ""
    Write-Log "The secret's key ID lets rotation revoke THIS secret once a new one works. Leave it blank if you do not"
    Write-Log "know it: the credential still works, and rotation will report the old key for you to revoke by hand." 'WARNING'

    $SecretKeyId = ''
    $KeyAnswer   = ([string](Read-Host "Secret key ID (GUID, or Enter for unknown)")).Trim()

    if (-not [string]::IsNullOrWhiteSpace($KeyAnswer)) {
        $ParsedKey = [guid]::Empty
        if ([guid]::TryParse($KeyAnswer, [ref]$ParsedKey)) {
            $SecretKeyId = $ParsedKey.ToString()
        } else {
            Write-Log "That is not a GUID, so it was left out. The credential will work; rotation will report the old key for manual cleanup." 'WARNING'
            $SecretKeyId = ''
        }
    }

    $DisplayName = ([string](Read-Host "Application display name (Enter for $($PDGraph.AppDisplayName))")).Trim()
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = [string]$PDGraph.AppDisplayName }

    Write-Log ""
    Write-Log "Testing those credentials against your tenant (nothing is saved yet)..." 'INFO2'

    try {

        $Check = Test-PDGraphUploadCandidateCredential -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret `
                        -SecretExpiresOn $ExpiresOn -SecretKeyId $SecretKeyId -AppDisplayName $DisplayName

        foreach ($Warning in @($Check.Warnings)) {
            if (-not [string]::IsNullOrWhiteSpace($Warning)) { Write-Log "     $Warning" 'WARNING' }
        }

        if (-not $Check.Valid) {
            Write-Log ""
            Write-Log $Check.Message 'ERROR'
            Write-Log "Your stored credential was not changed." 'WARNING'
            return
        }

        Write-Log "     $($Check.Message)" 'SUCCESS'

        $Saved = Save-PDGraphCredential -Credential $Check.Credential

        Write-Log ""
        Write-Log "Saved for this Windows account: $($Saved.Path)" 'SUCCESS'
        Write-Log "     Expires: $($Saved.SecretExpiresOn.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture))" 'INFO2'
        Write-Log "     Azure App Registration - Test config re-tests this at any time; Rotate local PC secret replaces it." 'WARNING'

    } Catch {

        Show-GraphUploadError $_

    }

}

Function Invoke-GraphUploadTestConnection {

    # Spec 7.2 "Test": token, the two roles, one small Intune read. It reports permissions and expiry,
    # and says plainly that a read cannot prove the Multi-Admin Approval exclusion exists.

    Write-Log ""
    Write-Log "-------------------------------------------------------------------------------------------"
    Write-Log "AZURE APP REGISTRATION - TEST CONFIG"
    Write-Log "-------------------------------------------------------------------------------------------"
    Write-Log ""

    try {

        $Result = Test-PDGraphUploadConnection

        Write-Log ("     Roles in the token: {0}" -f (@($Result.Roles) -join ', ')) 'INFO2'

        if (@($Result.MissingRoles).Count -gt 0) {
            Write-Log "     Missing roles: $((@($Result.MissingRoles)) -join ', ')" 'ERROR'
        }

        if ($null -ne $Result.TokenExpiresOn) {
            Write-Log "     Token expires: $($Result.TokenExpiresOn)" 'INFO2'
        }

        Write-Log ""

        if ($Result.Success) {
            Write-Log $Result.Message 'SUCCESS'
        } else {
            Write-Log $Result.Message 'ERROR'
        }

        foreach ($Warning in @($Result.Warnings)) {
            if (-not [string]::IsNullOrWhiteSpace($Warning)) { Write-Log "     $Warning" 'WARNING' }
        }

    } Catch {

        Show-GraphUploadError $_
        Write-Log "If no credential is stored yet, use Azure App Registration - Setup/Config first." 'WARNING'

    }

}

Function Invoke-GraphUploadRotateSecret {

    # Spec 7.4, in order: add the replacement while the old one still works, test it, save it, and
    # only then revoke the OLD secret by its recorded key id. If the test or the save fails the old
    # credential is still in place; if only the revocation fails, the new secret stays working and the
    # surviving old key is reported. Nothing is ever revoked by display name.

    Write-Log ""
    Write-Log "-------------------------------------------------------------------------------------------"
    Write-Log "AZURE APP REGISTRATION - ROTATE LOCAL PC SECRET"
    Write-Log "-------------------------------------------------------------------------------------------"
    Write-Log ""

    if (-not (Confirm-GraphUploadAdminModule -Purpose "rotating this PC's secret")) { return }

    $Summary = Show-GraphUploadCredentialState

    if (-not $Summary.Stored) {
        Write-Log "There is nothing to rotate yet. Use Azure App Registration - Setup/Config first." 'WARNING'
        return
    }

    $LifetimeDays = Read-GraphUploadSecretLifetime -Default ([int]$PDGraph.DefaultSecretLifetimeDays)

    $Session = Connect-GraphUploadAdminSession -Purpose 'add a new secret for this PC and remove the old one'
    if ($null -eq $Session) { return }

    try {

        Write-Log ""
        Write-Log "Adding a new secret for this PC, testing it, then removing the old one. A brand-new secret can take a few minutes to start working; Setup waits for it (up to 5 minutes)..." 'INFO2'

        $Result = Start-PDGraphSecretRotation -Session $Session -SecretLifetimeDays $LifetimeDays

        Write-Log ""

        if ($Result.Success) {
            Write-Log $Result.Message 'SUCCESS'
        } else {
            Write-Log $Result.Message 'ERROR'
            Write-Log "Your previous credential is still in place, so uploads keep working as they did before." 'WARNING'
        }

        foreach ($Warning in @($Result.Warnings)) {
            if (-not [string]::IsNullOrWhiteSpace($Warning)) { Write-Log "     $Warning" 'WARNING' }
        }

    } Catch {

        Show-GraphUploadError $_

    } Finally {

        $Closed = Disconnect-PDGraphInteractive -Session $Session
        Write-Log "     $($Closed.Message)" 'INFO2'

    }

}

Function Show-GraphUploadMaaInstructions {

    # Spec 7.5: displays the configured name and client ID plus the portal path, and performs no
    # Graph reads or writes about MAA - this has to work when the connection is the broken part.

    Write-Log ""
    Write-Log "-------------------------------------------------------------------------------------------"
    Write-Log "MAA EXCLUSIONS - SETUP/CONFIG MANUALLY"
    Write-Log "-------------------------------------------------------------------------------------------"
    Write-Log ""

    $Guidance = Get-PDGraphUploadMaaGuidance

    Write-Log $Guidance.Message 'WARNING'
    Write-Log "     Client ID: $($Guidance.ClientId)" 'INFO2'
    Write-Log ""
    Write-Log "Do this in the Intune admin center (Setup cannot do it for you):" 'WARNING'

    foreach ($Step in @($Guidance.Steps)) {
        Write-Log "     $Step" 'INFO2'
    }

    Write-Log ""

    foreach ($Note in @($Guidance.Notes)) {
        Write-Log "     - $Note" 'INFO2'
    }

    Write-Log ""

}

Function Invoke-GraphUploadRemoveCredential {

    # Spec 7.4 "Removal": the local file, and optionally its own Entra key. Never the shared
    # application, never its service principal, and never another administrator's secret.

    Write-Log ""
    Write-Log "-------------------------------------------------------------------------------------------"
    Write-Log "AZURE APP REGISTRATION - REMOVE LOCAL PC SECRET"
    Write-Log "-------------------------------------------------------------------------------------------"
    Write-Log ""

    $Summary = Show-GraphUploadCredentialState

    if (-not $Summary.Stored) {
        Write-Log "There is no stored credential to remove." 'WARNING'
        return
    }

    Write-Log ""
    Write-Log "Removal only affects this workstation's stored credential. It never deletes the shared application,"
    Write-Log "never removes its service principal, and never touches another administrator's secret. The Entra secret"
    Write-Log "itself stays active unless you also revoke it below." 'WARNING'
    Write-Log ""

    $Revoke = Read-GraphUploadYesNo -Question "Also revoke this credential's own secret in Entra?" -Default $false `
                                        -Note "Revoking needs a temporary administrator sign-in, and only revokes the secret whose key id is recorded here ($($(if ([string]::IsNullOrWhiteSpace($Summary.SecretKeyId)) { 'none recorded - it cannot be revoked from here' } else { [string]$Summary.SecretKeyId }))). Choosing no leaves that secret active until someone revokes it in Entra."

    $Session = $null

    if ($Revoke) {

        if (-not (Confirm-GraphUploadAdminModule -Purpose "revoking this PC's secret in Entra")) { return }

        $Session = Connect-GraphUploadAdminSession -Purpose "remove this PC's secret from the Azure App Registration"
        if ($null -eq $Session) { return }

    }

    try {

        $Result = Remove-PDGraphUploadCredential -RevokeEntraKey:$Revoke -Session $Session

        Write-Log ""

        if ($Result.Success) {
            Write-Log $Result.Message 'SUCCESS'
        } else {
            Write-Log $Result.Message 'ERROR'
        }

        foreach ($Warning in @($Result.Warnings)) {
            if (-not [string]::IsNullOrWhiteSpace($Warning)) { Write-Log "     $Warning" 'WARNING' }
        }

        if ($Result.Removed) {
            Write-Log ""
            Write-Log "Publishing through the API is unavailable again until a credential exists; the wizards fall back to guided manual publishing." 'WARNING'
        }

    } Catch {

        Show-GraphUploadError $_

    } Finally {

        if ($null -ne $Session) {
            $Closed = Disconnect-PDGraphInteractive -Session $Session
            Write-Log "     $($Closed.Message)" 'INFO2'
        }

    }

}

# ---------------------------------------------------------------------------
# Intune publishing from the printer and app wizards (spec 4 and 5.1)
# ---------------------------------------------------------------------------
# The wizards build one metadata hashtable and hand it to Invoke-InTuneAutoUpload. Everything these
# functions use arrives as a parameter (no wizard variables are read), none of them calls exit, and
# every failure returns $false so the caller falls through to the guided walkthrough.

# Test-IntuneFieldMissing, ConvertTo-IntuneFieldText, Get-IntuneDisplayUrl, New-IntunePrinterDescription
# and New-IntuneTechnicalNotes live in Other_Tools\Printer-Intune_Helpers.ps1 (dot-sourced above), shared
# with the bulk printer tools.

Function Complete-IntuneManualNotes {
    param([AllowNull()][string]$Notes)

    # Manual mode stamps the technical block once, the same way the uploader does (spec 4.4).
    $Now = [System.DateTimeOffset]::Now

    if (Get-Command -Name 'Complete-PDIntuneNotes' -CommandType Function -ErrorAction SilentlyContinue) {
        return (Complete-PDIntuneNotes -Notes $Notes -CreatedAt $Now)
    }

    return (([string]$Notes).TrimEnd() + "`r`n" + 'Created: ' + $Now.ToString('yyyy-MM-ddTHH:mm:sszzz', [System.Globalization.CultureInfo]::InvariantCulture))
}

Function Invoke-IntuneWinGetLookup {
    param([AllowNull()][string]$WinGetID)

    # One read-only 'winget show' per app selection, shared by the description and the publisher.
    # Always returns an object with Found / Description / Publisher / Status / Message.
    $Failed = { param($Status, $Message) [pscustomobject]@{ Found = $false; Description = $null; Publisher = $null; Source = $null; Status = $Status; Message = $Message } }

    if (-not (Get-Command -Name 'Get-WinGetAppDescription' -CommandType Function -ErrorAction SilentlyContinue)) {
        return (& $Failed 'Unavailable' "The WinGet lookup is not available ($WinGetDescriptionLoadError).")
    }

    Write-Log "Looking up '$WinGetID' with WinGet for its description and publisher (read-only, up to a minute)..." 'INFO2'

    try {
        $Lookup = @(Get-WinGetAppDescription -WinGetId $WinGetID) | Select-Object -Last 1
        if ($null -eq $Lookup) { return (& $Failed 'Unavailable' 'The WinGet lookup returned nothing.') }
        return $Lookup
    } Catch {
        return (& $Failed 'Unavailable' "The WinGet lookup failed: $($_.Exception.Message)")
    }
}

Function Get-IntuneAppDescriptionText {
    param(
        [AllowNull()][string]$AppDescription,
        [AllowNull()][string]$InstallMethod,
        [AllowNull()][string]$WinGetID,
        # A lookup already made for this selection; when absent and needed, one is made here.
        [AllowNull()][object]$Lookup
    )

    # Spec 4.3 decision sequence. The JSON is never written back and the app name is never used
    # as a fallback. A failed lookup is a warning plus N/A, never a reason to stop publishing.
    if (-not (Test-IntuneFieldMissing -Value $AppDescription)) {
        return @{ Text = $AppDescription; Source = 'JSON AppDescription'; Warning = $null }
    }

    if ([string]$InstallMethod -ne 'WinGet') {
        return @{ Text = 'N/A'; Source = 'none'; Warning = $null }
    }

    if (Test-IntuneFieldMissing -Value $WinGetID) {
        return @{ Text = 'N/A'; Source = 'none'; Warning = 'The app installs with WinGet but has no WinGetID, so no description could be looked up. Using N/A.' }
    }

    if ($null -eq $Lookup) { $Lookup = Invoke-IntuneWinGetLookup -WinGetID $WinGetID }

    if ($Lookup.Found -and -not (Test-IntuneFieldMissing -Value $Lookup.Description)) {
        return @{ Text = [string]$Lookup.Description; Source = "WinGet ($($Lookup.Source))"; Warning = $null }
    }

    return @{ Text = 'N/A'; Source = 'none'; Warning = ("No WinGet description was found for '{0}' ({1}: {2}). Using N/A." -f $WinGetID, [string]$Lookup.Status, [string]$Lookup.Message) }
}

Function Get-IntuneAppLinks {
    param(
        [AllowNull()][string]$CatalogInformationUrl,
        [AllowNull()][string]$CatalogPrivacyUrl,
        [AllowNull()][string]$InstallMethod,
        [AllowNull()][object]$Lookup
    )

    # Catalog values win; for WinGet apps the gaps are filled from the same winget show lookup.
    $Result = @{ InformationUrl = ''; InformationSource = 'none'; PrivacyUrl = ''; PrivacySource = 'none' }
    $FromWinGet = ([string]$InstallMethod -eq 'WinGet') -and ($null -ne $Lookup)

    if (-not (Test-IntuneFieldMissing -Value $CatalogInformationUrl)) { $Result.InformationUrl = $CatalogInformationUrl; $Result.InformationSource = 'JSON InformationUrl' }
    elseif ($FromWinGet -and -not (Test-IntuneFieldMissing -Value $Lookup.Homepage)) { $Result.InformationUrl = [string]$Lookup.Homepage; $Result.InformationSource = 'WinGet' }

    if (-not (Test-IntuneFieldMissing -Value $CatalogPrivacyUrl)) { $Result.PrivacyUrl = $CatalogPrivacyUrl; $Result.PrivacySource = 'JSON PrivacyUrl' }
    elseif ($FromWinGet -and -not (Test-IntuneFieldMissing -Value $Lookup.PrivacyUrl)) { $Result.PrivacyUrl = [string]$Lookup.PrivacyUrl; $Result.PrivacySource = 'WinGet' }

    return $Result
}

Function Test-IntuneIconBytes {
    param([AllowNull()][byte[]]$Bytes)

    # 'png' | 'jpeg' | $null, from the file's own signature (never from its name or the server).
    if ($null -eq $Bytes -or $Bytes.Length -lt 8) { return $null }
    if (($Bytes[0] -eq 0x89) -and ($Bytes[1] -eq 0x50) -and ($Bytes[2] -eq 0x4E) -and ($Bytes[3] -eq 0x47) -and
        ($Bytes[4] -eq 0x0D) -and ($Bytes[5] -eq 0x0A) -and ($Bytes[6] -eq 0x1A) -and ($Bytes[7] -eq 0x0A)) { return 'png' }
    if (($Bytes[0] -eq 0xFF) -and ($Bytes[1] -eq 0xD8) -and ($Bytes[2] -eq 0xFF)) { return 'jpeg' }
    return $null
}

Function Test-IntuneIconIsSvg {
    param([AllowNull()][byte[]]$Bytes)

    # $true when the content is SVG text: markup from the first character (after an optional UTF-8
    # BOM and whitespace) with an <svg element near the top. resvg makes the final call.
    if ($null -eq $Bytes -or $Bytes.Length -lt 5) { return $false }
    $Text = [System.Text.Encoding]::UTF8.GetString($Bytes, 0, [Math]::Min($Bytes.Length, 4096)).TrimStart([char]0xFEFF).TrimStart()
    return ($Text.StartsWith('<') -and ($Text -match '<svg[\s>]'))
}

Function Get-IntuneSvgConverterStartFailure {
    param([AllowNull()][System.Exception]$Exception)

    # Why Windows would not start resvg.exe, in words that say what to fix. Application control
    # and antivirus are named outright: resvg.exe is not code-signed, so policies that only allow
    # signed programs block it.
    $Native = $null
    $Current = $Exception
    while ($null -ne $Current) {
        if ($Current -is [System.ComponentModel.Win32Exception]) { $Native = $Current.NativeErrorCode; break }
        $Current = $Current.InnerException
    }

    switch ($Native) {
        1260 { return "Windows blocked the SVG icon converter (Other_Tools\resvg\resvg.exe) from running: an AppLocker or software restriction policy on this PC does not allow it (resvg.exe is not code-signed)." }
        4551 { return "Windows blocked the SVG icon converter (Other_Tools\resvg\resvg.exe) from running: an App Control (WDAC) policy on this PC does not allow it (resvg.exe is not code-signed)." }
        225  { return "Antivirus blocked the SVG icon converter (Other_Tools\resvg\resvg.exe) from running." }
    }
    $Reason = if ($null -ne $Exception) { $Exception.Message } else { 'unknown error' }
    return "The SVG icon converter (Other_Tools\resvg\resvg.exe) could not be started: $Reason"
}

Function ConvertTo-IntuneIconPng {
    param(
        [Parameter(Mandatory = $true)][string]$SvgPath,
        # Where icon.png is written; created when missing, and removed again on failure if it was.
        [Parameter(Mandatory = $true)][string]$Directory,
        # How the icon is named in warnings (the catalog's IconUrl or IconFile); default: the file name.
        [string]$Label,
        [int]$Size = 512,
        [int]$TimeoutSec = 30,
        [int]$MaxBytes = 1048576,
        [string]$ExePath = $SvgConverterExePath,
        [string]$ExpectedSha256 = $SvgConverterExeSha256
    )

    # SVG -> PNG with the pinned resvg build, fitted inside Size x Size with its shape kept.
    # Returns @{ Path; Warning } like Save-IntuneIconFromUrl: Path is empty on any failure and
    # Warning says exactly why, because an icon must never stop an app being published.
    if ([string]::IsNullOrWhiteSpace($Label)) { $Label = Split-Path -Leaf $SvgPath }
    $NoIcon = "The SVG icon '$Label' was not converted, so no icon will be used. To use this logo, convert it to PNG yourself and set IconFile."

    if ([string]::IsNullOrWhiteSpace($ExePath) -or -not (Test-Path -LiteralPath $ExePath -PathType Leaf)) {
        return @{ Path = ''; Warning = "The SVG icon converter is missing (expected at $ExePath). $NoIcon" }
    }
    $ActualSha256 = (Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash
    if ($ActualSha256 -ne $ExpectedSha256) {
        return @{ Path = ''; Warning = "The SVG icon converter $ExePath is not the pinned resvg build (SHA256 $ActualSha256, expected $ExpectedSha256), so it was not run. Restore it from the repository. $NoIcon" }
    }

    $CreatedDirectory = -not (Test-Path -LiteralPath $Directory)
    # The SVG is rendered from a folder of its own, which is also where its relative links resolve.
    $Work = Join-Path $Directory ('svg_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $Png = Join-Path $Directory 'icon.png'
    $Warning = $null
    try {
        New-Item -ItemType Directory -Path $Work -Force | Out-Null
        $Source = Join-Path $Work 'source.svg'
        Copy-Item -LiteralPath $SvgPath -Destination $Source -Force

        $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $StartInfo.FileName = $ExePath
        $StartInfo.Arguments = ('-w {0} -h {0} --resources-dir "{1}" "{2}" "{3}"' -f $Size, $Work, $Source, $Png)
        $StartInfo.UseShellExecute = $false
        $StartInfo.CreateNoWindow = $true
        $StartInfo.RedirectStandardOutput = $true
        $StartInfo.RedirectStandardError = $true

        $Process = $null
        try { $Process = [System.Diagnostics.Process]::Start($StartInfo) } Catch { $Warning = (Get-IntuneSvgConverterStartFailure -Exception $_.Exception) + " $NoIcon" }

        if ($null -ne $Process) {
            $ErrorText = $Process.StandardError.ReadToEndAsync()
            $null = $Process.StandardOutput.ReadToEndAsync()
            if (-not $Process.WaitForExit($TimeoutSec * 1000)) {
                try { $Process.Kill() } Catch { }
                $Warning = "The SVG icon converter did not finish within $TimeoutSec seconds. $NoIcon"
            } elseif (($Process.ExitCode -ne 0) -or -not (Test-Path -LiteralPath $Png)) {
                $Detail = @(([string]$ErrorText.Result) -split "`r?`n" | Where-Object { $_.Trim() }) | Select-Object -First 1
                if ([string]::IsNullOrWhiteSpace($Detail)) { $Detail = "exit code $($Process.ExitCode)" }
                $Warning = "The SVG icon converter could not read the SVG ($($Detail.Trim())). $NoIcon"
            } elseif ((Get-Item -LiteralPath $Png).Length -gt $MaxBytes) {
                $Warning = ("The PNG converted from the SVG icon is {0:N0} KB, larger than the {1:N0} KB limit. {2}" -f ((Get-Item -LiteralPath $Png).Length / 1KB), ($MaxBytes / 1KB), $NoIcon)
            } elseif ((Test-IntuneIconBytes -Bytes ([System.IO.File]::ReadAllBytes($Png))) -ne 'png') {
                $Warning = "The SVG icon converter did not produce a PNG. $NoIcon"
            }
            $Process.Dispose()
        }
    } Catch {
        $Warning = "The SVG icon could not be converted ($($_.Exception.Message)). $NoIcon"
    } finally {
        Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
    }

    if ($Warning) {
        Remove-Item -LiteralPath $Png -Force -ErrorAction SilentlyContinue
        if ($CreatedDirectory) { Remove-Item -LiteralPath $Directory -Recurse -Force -ErrorAction SilentlyContinue }
        return @{ Path = ''; Warning = $Warning }
    }
    return @{ Path = $Png; Warning = $null }
}

Function Resolve-IntuneSvgIconFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        # Same meaning as Save-IntuneIconFromUrl's -Directory.
        [string]$Directory
    )

    # A catalog IconFile that is SVG becomes a PNG copy; any other file comes back as it is (the
    # uploader and the operator check PNG/JPEG themselves). Returns @{ Path; Warning; Converted }.
    $Bytes = $null
    try { $Bytes = [System.IO.File]::ReadAllBytes($Path) } Catch { }
    if ((Test-IntuneIconBytes -Bytes $Bytes) -or -not (Test-IntuneIconIsSvg -Bytes $Bytes)) {
        return @{ Path = $Path; Warning = $null; Converted = $false }
    }

    $Folder = Join-Path ([System.IO.Path]::GetTempPath()) ('PowerDeploy-Icon-' + [guid]::NewGuid().ToString('N'))
    if (-not [string]::IsNullOrWhiteSpace($Directory)) { $Folder = Join-Path $Directory ((Get-Date -Format 'yyyyMMdd_HHmmss') + '_' + [guid]::NewGuid().ToString('N').Substring(0, 8)) }
    $Result = ConvertTo-IntuneIconPng -SvgPath $Path -Directory $Folder -Label $Path
    return @{ Path = [string]$Result.Path; Warning = $Result.Warning; Converted = [bool]$Result.Path }
}

Function Save-IntuneIconFromUrl {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [int]$MaxBytes = 1048576,
        [int]$TimeoutSec = 30,
        # Where to keep the download. Default: a throwaway folder in the system temp (automatic
        # mode deletes it). Guided mode passes Setup's own Temp folder, beside - never inside - the repo.
        [string]$Directory
    )

    # HTTPS only, bounded, no credentials sent, and the content must really be a PNG or JPEG
    # (an SVG is converted to a PNG).
    # Returns @{ Path; Warning } - Path is empty when no usable icon was downloaded.
    $Parsed = $null
    if (-not ([System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$Parsed)) -or ($Parsed.Scheme -ne 'https')) {
        return @{ Path = ''; Warning = "The catalog IconUrl '$Url' is not an https link, so no icon will be used." }
    }

    $Folder = Join-Path ([System.IO.Path]::GetTempPath()) ('PowerDeploy-Icon-' + [guid]::NewGuid().ToString('N'))
    if (-not [string]::IsNullOrWhiteSpace($Directory)) { $Folder = Join-Path $Directory ((Get-Date -Format 'yyyyMMdd_HHmmss') + '_' + [guid]::NewGuid().ToString('N').Substring(0, 8)) }
    try {
        New-Item -ItemType Directory -Path $Folder -Force | Out-Null
        $Download = Join-Path $Folder 'download.bin'
        $ProgressPreference = 'SilentlyContinue'
        # A named User-Agent: some logo hosts (Wikimedia) answer PowerShell's default one with 429.
        $UserAgent = 'PowerDeploy/1.0 (Intune app icon download; +https://github.com/Santa-Cruz-COE/PowerDeploy)'
        Invoke-WebRequest -Uri $Url -OutFile $Download -UseBasicParsing -TimeoutSec $TimeoutSec -MaximumRedirection 5 -UserAgent $UserAgent -ErrorAction Stop

        $Length = (Get-Item -LiteralPath $Download).Length
        if ($Length -gt $MaxBytes) {
            Remove-Item -LiteralPath $Folder -Recurse -Force -ErrorAction SilentlyContinue
            return @{ Path = ''; Warning = ("The icon at '{0}' is {1:N0} KB, larger than the {2:N0} KB limit, so no icon will be used." -f $Url, ($Length / 1KB), ($MaxBytes / 1KB)) }
        }

        $Bytes = [System.IO.File]::ReadAllBytes($Download)
        $Kind = Test-IntuneIconBytes -Bytes $Bytes
        if (-not $Kind -and (Test-IntuneIconIsSvg -Bytes $Bytes)) {
            # Many official logos are only published as SVG; Intune takes PNG/JPEG, so convert it.
            $Converted = ConvertTo-IntuneIconPng -SvgPath $Download -Directory $Folder -Label $Url
            if (-not $Converted.Path) { Remove-Item -LiteralPath $Folder -Recurse -Force -ErrorAction SilentlyContinue; return $Converted }
            Remove-Item -LiteralPath $Download -Force -ErrorAction SilentlyContinue
            return $Converted
        }
        if (-not $Kind) {
            Remove-Item -LiteralPath $Folder -Recurse -Force -ErrorAction SilentlyContinue
            return @{ Path = ''; Warning = "The file at '$Url' is not a PNG, JPEG or SVG image, so no icon will be used." }
        }

        $Final = Join-Path $Folder ('icon.' + $Kind)
        Move-Item -LiteralPath $Download -Destination $Final -Force
        return @{ Path = $Final; Warning = $null }
    } Catch {
        Remove-Item -LiteralPath $Folder -Recurse -Force -ErrorAction SilentlyContinue
        return @{ Path = ''; Warning = "The icon could not be downloaded from '$Url' ($($_.Exception.Message)), so no icon will be used." }
    }
}

Function Get-IntuneAppPublisherText {
    param(
        [AllowNull()][string]$CatalogPublisher,
        [AllowNull()][string]$InstallMethod,
        [AllowNull()][object]$Lookup
    )

    # Catalog Publisher, else the publisher WinGet reports (WinGet apps only), else PowerDeploy.
    if (-not (Test-IntuneFieldMissing -Value $CatalogPublisher)) {
        return @{ Text = $CatalogPublisher; Source = 'JSON Publisher' }
    }

    if (([string]$InstallMethod -eq 'WinGet') -and ($null -ne $Lookup) -and -not (Test-IntuneFieldMissing -Value $Lookup.Publisher)) {
        return @{ Text = [string]$Lookup.Publisher; Source = 'WinGet' }
    }

    return @{ Text = 'PowerDeploy'; Source = 'default' }
}

Function Read-IntunePublishChoice {

    Write-Log "How would you like to create this app in Intune?" 'WARNING'
    Write-Log ""
    Write-Log "     1 - Guided manual setup (step-by-step walkthrough of the Intune portal)"
    Write-Log "     2 - Automatic setup via the API (creates, uploads, and assigns the app for you)"
    Write-Log ""

    While ($true) {
        $Choice = ([string](Read-Host "1/2")).Trim()
        if ($Choice -eq '1' -or $Choice -eq '2') { return $Choice }
        Write-Log "Invalid input. Please enter 1 or 2." 'ERROR'
    }
}

Function Read-IntuneGroupList {
    param([Parameter(Mandatory = $true)][string]$Intent)

    Write-Log ("Enter the {0} assignment groups, separated by ';' (e.g. IT PCs; Techs). Use exact group names or object IDs, or /AllDevices or /AllUsers for Intune's built-in targets. Leave blank for none." -f $Intent.ToUpperInvariant()) 'WARNING'
    $Raw = [string](Read-Host $Intent)

    # Spec 5.2: split on semicolons, trim, discard empty pieces. Returned as plain pipeline items:
    # wrapping the array (return ,$x) and then @() at the caller made a one-item list holding the
    # whole array, which [string[]] turned into "IT PCs Techs" - the separator vanished.
    return @($Raw -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
}

Function Get-IntuneUploadFileHashes {
    param([string[]]$Paths)

    # Fingerprint of everything the review covered, so a file that changes between review and
    # submission forces a fresh review (spec 5.1).
    $Parts = foreach ($Path in $Paths) {
        try { (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } Catch { 'missing' }
    }
    return ($Parts -join '|')
}

Function Show-IntuneUploadReview {
    param([Parameter(Mandatory = $true)][object]$Review)

    $Meta = $Review.ReviewMetadata

    Write-Log "==========================================================================================="
    Write-Log "REVIEW - nothing has been created in Intune yet"
    Write-Log "==========================================================================================="
    Write-Log ""

    if ($null -ne $Meta) {
        $Version = [string]$Meta.AppVersion
        if ([string]::IsNullOrWhiteSpace($Version)) { $Version = '(none)' }

        Write-Log "NAME:      $($Meta.DisplayName)"
        Write-Log "PUBLISHER: $($Meta.Publisher)"
        Write-Log "VERSION:   $Version"
        Write-Log "PACKAGE:   $($Meta.PackageFileName) (setup file: $($Meta.SetupFilePath))"
        Write-Log "ALLOW AVAILABLE UNINSTALL: $($Meta.AllowAvailableUninstall)"
        if (-not [string]::IsNullOrWhiteSpace([string]$Meta.IconFile)) { Write-Log "ICON:      $($Meta.IconFile)" }
        if (-not [string]::IsNullOrWhiteSpace([string]$Meta.InformationUrl)) { Write-Log "INFO URL:  $($Meta.InformationUrl)" }
        if (-not [string]::IsNullOrWhiteSpace([string]$Meta.PrivacyUrl)) { Write-Log "PRIVACY:   $($Meta.PrivacyUrl)" }
        Write-Log ""
        Write-Log "DESCRIPTION (shown to users in the Company Portal):"
        Write-Host ""
        Write-LogBlock $Meta.Description
        Write-Host ""
        Write-Log "NOTES (admins only):"
        Write-Host ""
        Write-LogBlock $Meta.Notes
        # The Created line is added by the uploader at creation time; show where it will go
        # instead of a separate explanation line.
        if (-not [string]::IsNullOrWhiteSpace([string]$Meta.NotesTimestampNote)) { Write-LogBlock "Created: (added automatically when the app is created)" }
        Write-Host ""
        Write-Log ""
    }

    $CategoryResult = $Review.CategoryResult
    if ($null -ne $CategoryResult) {
        switch ([string]$CategoryResult.Status) {
            'Resolved'    { Write-Log "CATEGORY:  $($CategoryResult.RequestedName) ($($CategoryResult.Id))" }
            'Missing'     { Write-Log "CATEGORY:  '$($CategoryResult.RequestedName)' does not exist in Intune - the app will be created without a category." 'WARNING' }
            'Ambiguous'   { Write-Log "CATEGORY:  '$($CategoryResult.RequestedName)' matches more than one Intune category - the app will be created without a category." 'WARNING' }
            default       { Write-Log "CATEGORY:  (none requested)" }
        }
    }

    $Groups = @($Review.ResolvedGroups)
    if ($Groups.Count -eq 0) {
        Write-Log "ASSIGNMENTS: No assignments"
    } else {
        Write-Log "ASSIGNMENTS:"
        foreach ($Group in $Groups) {
            if (([string]$Group.Id).StartsWith('/')) {
                Write-Log ("     [{0}] {1}" -f $Group.Intent, $Group.DisplayName)
            } else {
                Write-Log ("     [{0}] {1} ({2})" -f $Group.Intent, $Group.DisplayName, $Group.Id)
            }
        }
    }

    $Duplicates = @($Review.DuplicateApps)
    if ($Duplicates.Count -gt 0) {
        Write-Log ""
        Write-Log "AN APP WITH THIS NAME ALREADY EXISTS IN INTUNE:" 'WARNING'
        foreach ($Duplicate in $Duplicates) {
            Write-Log ("     {0} ({1})" -f $Duplicate.DisplayName, $Duplicate.Id) 'WARNING'
        }
    }

    if ($null -ne $Review.CommandLengths) {
        Write-Log ""
        Write-Log ("Command lengths: install {0}, uninstall {1} characters" -f $Review.CommandLengths.Install, $Review.CommandLengths.Uninstall) 'INFO2'
    }

    if ($null -ne $Review.SecretExpiresOn) {
        Write-Log ("Upload credential expires: {0}" -f ([System.DateTimeOffset]$Review.SecretExpiresOn).ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)) 'INFO2'
    }

    foreach ($Warning in @($Review.Warnings)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Warning)) { Write-Log $Warning 'WARNING' }
    }

    Write-Log ""
}

Function Invoke-InTuneAutoUpload {
    <#
        Spec 5.1 steps 5-13. Returns $true only when the app was published and verified; any other
        outcome (no credential, failed check, declined duplicate or confirmation, failed upload)
        returns $false and the calling wizard continues with the guided walkthrough.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Metadata
    )

    $DownloadedIconPath = $null

    try {

        Clear
        Write-Log "==========================================================================================="
        Write-Log "AUTOMATIC SETUP VIA THE API"
        Write-Log "==========================================================================================="
        Write-Log ""

        if (-not $GraphUploadAvailable) {
            Write-Log "Automatic setup is not available on this workstation: $GraphUploadLoadError" 'WARNING'
            Write-Log "Continuing with the guided manual setup." 'WARNING'
            Pause
            return $false
        }

        # Step 5: is there a usable credential? Loaded only to check it; the uploader loads its own.
        try {
            $Credential = Get-PDGraphCredential
            foreach ($Warning in @($Credential.Warnings)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$Warning)) { Write-Log $Warning 'WARNING' }
            }
            $Credential = $null
        } Catch {
            Show-GraphUploadError -Failure $_
            Write-Log ""
            Write-Log "The upload credential is set up from the main menu with InTuneAPI--Setup-and-Manage." 'WARNING'
            Write-Log "Continuing with the guided manual setup." 'WARNING'
            Pause
            return $false
        }

        $Common = @{
            IntuneWinPath           = [string]$Metadata.IntuneWinPath
            DisplayName             = [string]$Metadata.DisplayName
            Description             = [string]$Metadata.Description
            Publisher               = [string]$Metadata.Publisher
            InstallCommandFile      = [string]$Metadata.InstallCommandFile
            UninstallCommandFile    = [string]$Metadata.UninstallCommandFile
            DetectionScriptFile     = [string]$Metadata.DetectionScriptFile
            AppVersion              = [string]$Metadata.AppVersion
            Category                = [string]$Metadata.Category
            Notes                   = [string]$Metadata.Notes
            AllowAvailableUninstall = [bool]$Metadata.AllowAvailableUninstall
            IconFile                = [string]$Metadata.IconFile
            InformationUrl          = [string]$Metadata.InformationUrl
            PrivacyUrl              = [string]$Metadata.PrivacyUrl
        }

        # A catalog IconFile that is SVG is converted to a PNG copy here, deleted when this function
        # finishes like a downloaded icon. A failed conversion just means no icon.
        if (-not [string]::IsNullOrWhiteSpace($Common.IconFile)) {
            $ResolvedIcon = Resolve-IntuneSvgIconFile -Path $Common.IconFile
            if ($ResolvedIcon.Warning) {
                Write-Log $ResolvedIcon.Warning "WARNING"
                $Common.IconFile = ''
            } elseif ($ResolvedIcon.Converted) {
                $Common.IconFile = $ResolvedIcon.Path
                $DownloadedIconPath = $ResolvedIcon.Path
                Write-Log "Converted the SVG app icon $($Metadata.IconFile) to PNG" "INFO2"
            }
        }

        # An icon given as a link is downloaded here, on this PC, only for automatic mode, and the
        # copy is deleted when this function finishes. A failed download just means no icon.
        if ([string]::IsNullOrWhiteSpace($Common.IconFile) -and -not [string]::IsNullOrWhiteSpace([string]$Metadata.IconUrl)) {
            $Downloaded = Save-IntuneIconFromUrl -Url ([string]$Metadata.IconUrl)
            if ($Downloaded.Path) {
                $Common.IconFile = $Downloaded.Path
                $DownloadedIconPath = $Downloaded.Path
                Write-Log "Downloaded the app icon from $($Metadata.IconUrl)" "INFO2"
            } else {
                Write-Log $Downloaded.Warning "WARNING"
            }
        }

        $HashedFiles = @($Common.IntuneWinPath, $Common.InstallCommandFile, $Common.UninstallCommandFile, $Common.DetectionScriptFile)

        $AllowDuplicate = $false

        $AskGroups = $true

        While ($true) {

            # Step 6: groups, Required first. Asked again after a failed check, so a mistyped group
            # name means retyping the list, not starting over or falling back to manual setup.
            if ($AskGroups) {
                Write-Log ""
                [string[]]$RequiredGroups  = @(Read-IntuneGroupList -Intent 'Required')
                Write-Log ""
                [string[]]$AvailableGroups = @(Read-IntuneGroupList -Intent 'Available')
                Write-Log ""
                $AskGroups = $false
            }

            # Step 7: dry run - reads only, zero writes.
            Write-Log "Checking the package, credential, groups, and category against the tenant (dry run, nothing is created)..."
            Write-Log ""

            $ReviewedHashes = Get-IntuneUploadFileHashes -Paths $HashedFiles
            $Review = Invoke-PDIntuneUpload @Common -RequiredGroups $RequiredGroups -AvailableGroups $AvailableGroups -DryRun

            if ($null -eq $Review) {
                Write-Log "The uploader returned nothing. Nothing was created. Continuing with the guided manual setup." 'ERROR'
                Pause
                return $false
            }

            # Step 8. A failed check shows only the problem: a half-filled review ("No assignments")
            # would describe something that is not going to happen.
            if (-not $Review.Success) {
                Write-Log "The check failed, so nothing was created in Intune:" 'ERROR'
                Show-GraphUploadError -Failure $Review.Message
                Write-Log ""
                if (Read-GraphUploadYesNo -Question 'Re-enter the assignment groups and check again?' -Default $true -Note 'Answer n to continue with the guided manual setup instead.') {
                    $AskGroups = $true
                    continue
                }
                Write-Log "Continuing with the guided manual setup." 'WARNING'
                Pause
                return $false
            }

            Show-IntuneUploadReview -Review $Review

            # Step 9: a duplicate name needs its own explicit yes.
            $AllowDuplicate = $false
            if (@($Review.DuplicateApps).Count -gt 0) {
                $AllowDuplicate = Read-GraphUploadYesNo -Question 'Create ANOTHER app with the same name anyway?' -Default $false
                if (-not $AllowDuplicate) {
                    Write-Log "Not creating a duplicate. Continuing with the guided manual setup." 'WARNING'
                    Pause
                    return $false
                }
            }

            # Step 10.
            $Confirmed = Read-GraphUploadYesNo -Question 'Create this app in Intune now?' -Default $false
            if (-not $Confirmed) {
                Write-Log "Cancelled. Nothing was created. Continuing with the guided manual setup." 'WARNING'
                Pause
                return $false
            }

            if ((Get-IntuneUploadFileHashes -Paths $HashedFiles) -eq $ReviewedHashes) { break }

            Write-Log "The package, a command file, or the detection script changed after the review. Reviewing again..." 'WARNING'
            Write-Log ""
        }

        # Step 11: submit the RESOLVED ids, so a renamed or newly ambiguous group can't swap in.
        $ResolvedRequired  = [string[]]@(@($Review.ResolvedGroups) | Where-Object { [string]$_.Intent -eq 'required' }  | ForEach-Object { [string]$_.Id })
        $ResolvedAvailable = [string[]]@(@($Review.ResolvedGroups) | Where-Object { [string]$_.Intent -eq 'available' } | ForEach-Object { [string]$_.Id })

        Write-Log ""
        Write-Log "Creating the app, uploading the package, and assigning it. Large packages can take several minutes..."
        Write-Log ""

        $Result = Invoke-PDIntuneUpload @Common -RequiredGroups $ResolvedRequired -AvailableGroups $ResolvedAvailable -AllowDuplicateName:$AllowDuplicate

        # The downloaded icon has done its job; remove it now rather than after the final prompt,
        # so closing the window at that prompt cannot leave it behind (Finally stays as a backstop).
        if ($DownloadedIconPath -and (Test-Path -LiteralPath $DownloadedIconPath)) {
            Remove-Item -LiteralPath (Split-Path -Parent $DownloadedIconPath) -Recurse -Force -ErrorAction SilentlyContinue
        }

        if ($null -ne $Result -and $Result.Success) {
            # Step 12.
            Write-Log "The app was created in Intune and verified!" 'SUCCESS'
            Write-Log ""
            Write-Log "App ID: $($Result.AppId)"
            Write-Log "Portal: $($Result.PortalUrl)"
            foreach ($Warning in @($Result.Warnings)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$Warning)) { Write-Log $Warning 'WARNING' }
            }
            Write-Log ""
            Write-Log "Please verify installation, detection, and uninstall on a test device." 'WARNING'
            Write-Log ""
            Pause
            return $true
        }

        # Step 13.
        if ($null -eq $Result) {
            Write-Log "The uploader returned nothing; the outcome is unknown. Check Intune for '$($Common.DisplayName)' before creating it again." 'ERROR'
        } else {
            Write-Log "Automatic setup failed (stage: $($Result.Stage), cleanup: $($Result.CleanupStatus)):" 'ERROR'
            Show-GraphUploadError -Failure $Result.Message

            $Cleanup = [string]$Result.CleanupStatus
            if ($Cleanup -ne 'Deleted' -and $Cleanup -ne 'NotNeeded') {
                Write-Log ""
                if (-not [string]::IsNullOrWhiteSpace([string]$Result.AppId)) {
                    Write-Log "An app was left in Intune: $($Result.AppId)" 'WARNING'
                    if (-not [string]::IsNullOrWhiteSpace([string]$Result.PortalUrl)) { Write-Log "Portal: $($Result.PortalUrl)" 'WARNING' }
                } else {
                    Write-Log "An app named '$($Common.DisplayName)' may have been created. Check Intune before creating it again." 'WARNING'
                }
                Write-Log "Delete or finish that app before creating another one in the guided setup." 'WARNING'
            }
        }

        Write-Log ""
        Write-Log "Continuing with the guided manual setup." 'WARNING'
        Pause
        return $false

    } Catch {

        Show-GraphUploadError -Failure $_
        Write-Log "Continuing with the guided manual setup." 'WARNING'
        Pause
        return $false

    } Finally {

        if ($DownloadedIconPath -and (Test-Path -LiteralPath $DownloadedIconPath)) {
            Remove-Item -LiteralPath (Split-Path -Parent $DownloadedIconPath) -Recurse -Force -ErrorAction SilentlyContinue
        }

    }
}

Function InTuneAPI--Setup-and-Manage {

    <#
        .SYNOPSIS
        Provisioning menu for publishing apps through Microsoft Graph (spec 7.2).

        .DESCRIPTION
        Creates/configures the single-tenant upload application, takes hand-entered credentials, tests
        them, rotates this workstation's secret, shows the Multi-Admin Approval exclusion steps, and
        removes stored credentials. Everything else (metadata, groups, publishing) happens in the
        printer and application wizards; this menu only makes the credential exist and stay healthy.

        Publishing through the API stays optional: with no credential here, the wizards print the
        guided manual walkthrough exactly as before.
    #>

    Write-Log ""
    Write-Log "==========================================================================================="
    Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START"
    Write-Log "==========================================================================================="
    Write-Log ""

    if (-not $GraphUploadAvailable) {

        Write-Log "The Intune upload feature is not available on this machine, so this menu cannot run." 'ERROR'
        Write-Log ""
        Write-Log "Reason: $GraphUploadLoadError" 'ERROR'
        Write-Log ""
        Write-Log "Guided manual publishing is unaffected and still works from the printer and app wizards." 'WARNING'
        Write-Log ""
        Pause
        return

    }

    While ($true) {

        Show-GraphUploadMenu

        $Choice = ([string](Read-Host "Enter the # of your desired option")).Trim()

        if ($Choice -eq '0') { break }

        if ($Choice -eq '1') {

            # Two ways to end up with a working credential on this PC: let Setup create/configure the
            # Azure App Registration with an admin sign-in, or type in one that already exists.
            Write-Log ""
            Write-Log "How do you want to set up the Azure App Registration for this PC?" 'WARNING'
            Write-Log ""
            Write-Log "     1 - Automatic: sign in as an admin, and Setup creates or reuses the application, grants its permissions, and makes and saves a secret for this PC (recommended)"
            Write-Log ""
            Write-Log "     2 - Manual: enter the tenant ID, client ID and secret of an application that already exists (use this if you cannot sign in with the admin roles needed for option 1)"
            Write-Log ""
            Write-Log "     0 - Back"
            Write-Log ""

            $SetupChoice = ([string](Read-Host "Enter the # of your desired option")).Trim()

            if ($SetupChoice -eq '1') {
                Invoke-GraphUploadProvisionApplication
            } elseif ($SetupChoice -eq '2') {
                Invoke-GraphUploadEnterCredential
            } elseif ($SetupChoice -ne '0') {
                Write-Log "That is not one of the options above." 'ERROR'
            }

        } elseif ($Choice -eq '2') {
            Invoke-GraphUploadTestConnection
        } elseif ($Choice -eq '3') {
            Invoke-GraphUploadRotateSecret
        } elseif ($Choice -eq '4') {
            Invoke-GraphUploadRemoveCredential
        } elseif ($Choice -eq '5') {
            Show-GraphUploadMaaInstructions
        } else {
            Write-Log "That is not one of the options above." 'ERROR'
        }

        Write-Log ""
        Pause

    }

    Write-Log "==========================================================================================="
    Write-Log "SCRIPT: $LocalFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"
    Write-Log "==========================================================================================="
    Write-Log ""

}

#endregion Intune API upload (Graph)


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
# Write-Log ""
# Write-Log "When you are ready we will begin by checking pre-requisites..."
# Write-Log ""
# Write-Log "NOTE: Instructions and required info will be in Cyan. Please note these lines."
# Write-Log "NOTE: Progess feed and non required info will be in white. Feel free to ignore these lines." "INFO2"

# Pause

# Warnings
Write-Log ""
# If this script is not being ran against C:ProgramData\PowerDeploy, it is going to lock down files in the root of the repo parent folder. Give a big fat warning. 
# $WorkingDirectory = "C:\ProgramData\PowerDeploy"
if ($WorkingDirectory -notlike "C:\ProgramData\PowerDeploy*"){

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
Clear
# Grab organization custom registry values and set as local variables
Try{

# Grab organization custom registry values
    Write-Log "Retrieving organization custom registry values..." "INFO2"
    $ReturnHash = & $OrgRegReader_ScriptPath #| Out-Null
    Write-Log ""

    # Check the returned hashtable
    if(($ReturnHash -eq $null) -or ($ReturnHash.Count -eq 0)){

        Clear 

        Write-Log "No data returned from Organization Registry Entries reader script!" "ERROR"
        Write-Log ""
        Write-Log "If this is a new environment, this is expected." "WARNING"
        Write-Log "However, this is a serious error in a fully developed PowerDeploy environment." "WARNING"
        Write-Log ""
        Write-Log "You can continue with setup with just public data from here if you wish." "WARNING"
        Write-Log "If you want to exit now, press Ctrl+C to stop the script. Otherwise, press Enter to continue at your own risk." "INFO"
        Write-Log ""

        # Exit 1
        Pause

    } else {

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

    }

} Catch {
    Write-Log "Error retrieving organization custom registry values: $_" "ERROR"
    Exit 1
}

# Update this repo
# TODO: This isn't working quite yet. Need to add auth too.
$answer = "y"

Push-Location $RepoRoot


    if (!(Test-Path "$RepoRoot/.git")) {
        
        Write-Log "No local git repo initialized"
        Write-Log "Would you like to connect this local repo to the official public repo at $OfficialPublicRepoURL and pull the latest changes?" "WARNING"
        $answer = Read-Host "y/n"

        if ($answer -eq "y") {
            Write-Log "If there are any pending changes, they will be discarded. Is that okay?" "WARNING"; 

            $Answer = Read-Host "y/n"

        } else {
            Write-Log "Skipping git repo update." "WARNING"
        }

    } else {

        $TempURL = "ZZ" # Dummy value to avoid errors if repo is not yet cloned. TODO: I should probably add the ability to select the DEV env too.
    
    } 

    if ($answer -ne "n") {

        Write-Log "Dot sourcing Git Runner template script located at: $GitRunnerTemplate_ScriptPath" "INFO2"

        if ($answer -eq "y") {

            Write-Log "Attempting to connect and update local repo." "WARNING"

            $TempURL = $OfficialPublicRepoURL

            & { # Run in a script block to avoid scope issues. Using ZZ as a dummy value for RepoURL since we are only updating local repo. Not the cleanest way to do this but it works for now. TODO: Clean up this method in the future.

                . $GitRunnerTemplate_ScriptPath -RepoURL "$TempURL" -RepoNickName $ThisRepoNickName -WorkingDirectory $WorkingDirectory -StashChanges $False -InitOnly $True

            }

        } else {

            Write-Log "Checking/Installing Git and confirming safe directory for current repo." "WARNING"


            & { # Run in a script block to avoid scope issues. Using ZZ as a dummy value for RepoURL since we are only updating local repo. Not the cleanest way to do this but it works for now. TODO: Clean up this method in the future.
                
                . $GitRunnerTemplate_ScriptPath -RepoURL "$TempURL" -RepoNickName $ThisRepoNickName -WorkingDirectory $WorkingDirectory -StashChanges $False -DotSourceOnly $True

                # Not sure if these actually need to be ran here since the GitRunnerTemplate can handle it, but just in case, I'll leave them here for now. TODO: Clean up in the future.
                CheckAndInstall-Git
                Set-GitSafeDirectory

            }
   
        }

        Write-Log "Running Git pre-reqs" "INFO2"
        Write-Log "" "INFO2"

        Write-Log "RUNNING GIT: git fetch"
        $gitOutput = git fetch 2>&1
        ForEach ($line in $gitOutput) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $LocalFileName | END | Failed" "ERROR"; Exit 1 }

        Write-Log "RUNNING GIT: " "INFO2"
        $gitBranch = git rev-parse --abbrev-ref HEAD 2>&1
        ForEach ($line in $gitBranch) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $LocalFileName | END | Failed" "ERROR"; Exit 1 }

        Write-Log "RUNNING GIT: git rev-parse HEAD"
        $gitCommit = git rev-parse HEAD 2>&1
        ForEach ($line in $gitCommit) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $LocalFileName | END | Failed" "ERROR"; Exit 1 }

        Write-Log "RUNNING GIT: git remote get-url origin"
        $gitURL = git remote get-url origin 2>&1
        ForEach ($line in $gitURL) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $LocalFileName | END | Failed" "ERROR"; Exit 1 }

        Write-Log "RUNNING GIT: git ls-remote origin $gitBranch"
        $gitCommitRemote = git ls-remote origin $gitBranch | ForEach-Object { $_.Split("`t")[0] } 2>&1
        ForEach ($line in $gitCommitRemote) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $LocalFileName | END | Failed" "ERROR"; Exit 1 }
        
        Write-Log "" "INFO2"

    } elseif ($answer -eq "n") {

        Write-Log "Skipping connecting and updating local git repo." "WARNING"

        # Write-Log ""

        # Write-Log "Now installing git using git-runner script..."

        # & {

        #     . $GitRunnerTemplate_ScriptPath -RepoURL "N/A" -RepoNickName $ThisRepoNickName -WorkingDirectory $WorkingDirectory -installGitOnly $True
        
        # }

    }


    Clear

    if ($answer -ne "n"){
        # Determine the deploy mode
        Try{

            $GitURL_FORMATTED = ($GitURL -split 'github')[1]
            $CustomRepoURL_FORMATTED = ($CustomRepoURL -split 'github')[1]

        } catch {

            Write-Log "Error attempted to format URL's for analyzing: $_" "ERROR"

        }
        # if $gitURL contains the CustomRepoURL, then this is a custom org deployment
        if ($GitURL_FORMATTED -like "*$CustomRepoURL_FORMATTED*" -and $CustomRepoURL_FORMATTED -ne "" -and $CustomRepoURL_FORMATTED -ne $null) {

            if ($gitBranch -eq "Dev"){

                $PerceivedMode = "PRIVATE-DEVELOPMENT"
            } elseif ($gitBranch -eq "Main" -or $gitBranch -eq "Master") {
                $PerceivedMode = "PRODUCTION"
            } else {
                $PerceivedMode = "???"
            }

        } elseif ($gitURL -like "*$OfficialPublicRepoURL*") {

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

        } elseif ($gitURL -eq "" -or $gitURL -eq $null -or $gitURL -eq "N/A") {

            Write-Log ""
            Write-Log "Skipping update work."
            Write-Log ""

            # Write-Log "No local commits found. This likely means you have not yet connected this local repo to the official public repo or a custom org repo." "WARNING"
            # Write-Log "If you have not connected to a repo, it is recommended to connect to the official public repo at $OfficialPublicRepoURL to receive updates and contribute if desired." "WARNING"
            # Write-Log ""
            # Write-Log "Would you like to connect this local repo to the official public repo at $OfficialPublicRepoURL and pull the latest changes?" "WARNING"
            # $answer = Read-Host "y/n"

        } else {

            Write-Log ""
            Write-Log "A newer version of this repo is available." "WARNING"


            # Write-Log "NOTE: Operational mode indicates which version of the code this currently repo is using."
            Write-Log "NOTE: If you have made local changes to any files in the repo, they will be stashed prior to updating." "WARNING"
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

                $Gitouput = git stash 2>&1
                ForEach ($line in $gitOutput) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $LocalFileName | END | Failed" "ERROR"; Exit 1 }

                $gitOutput = git pull 2>&1
                ForEach ($line in $gitOutput) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $LocalFileName | END | Failed" "ERROR"; Exit 1 }
                
                Write-Log "" "INFO2"
            
                Write-Log "Repo updated to the latest version."
                #Pause

                $Updated = $True
                
            } 

        }

        if ($Updated -eq $True) {

            Write-Log ""
            Write-Log "Since the repo was updated, it is recommended to re-run this setup script to ensure all components are up to date." "WARNING"
            Write-Log ""
            Write-Log "Exiting now. Please re-run the Setup.ps1 script." "WARNING"
            Pause
            Exit 0

        }

    } else {

        Write-Log "Skipped git repo update." "WARNING"

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