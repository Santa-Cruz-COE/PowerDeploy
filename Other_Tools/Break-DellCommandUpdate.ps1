# Break Dell Command Update
# This script is designed to break Dell Command Update, simulating a scenario seen in our environment. The goal is for the the Install Dell Command Update full clean script to fix what this breaks.
# Tested and working so far!

### Other Vars ###
#$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$RepoRoot = Split-Path -Path $PSScriptRoot -Parent
#$WorkingDirector = (Resolve-Path "$PSScriptRoot\..\..").Path
$WorkingDirectory = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent


$LogRoot = "$WorkingDirectory\Logs\Installer_Logs"
$SafeAppID = $AppName -replace '[^\w]', '_'

# path of WinGet installer
$WinGetInstallerScript = "$RepoRoot\Installers\General_WinGet_Installer.ps1"

# path of General uninstaller
$UninstallerScript = "$RepoRoot\Uninstallers\General_Uninstaller.ps1"

$LogPath = "$LogRoot\DellCommandUpdate.Full_Clean_Install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"



$ExtraDamage = $False


If ($ExtraDamage -eq $False){

    $TargetApps = @{
        'Dell Core Services' = 'Remove-App-MSI-I-QN'
    }

} else {


    $TargetApps = @{
        'Dell SupportAssist' = 'Remove-App-MSI-QN'
        'Dell Digital Delivery Services' = 'Remove-App-MSI-QN'
        'Dell Optimizer Core' = 'Remove-App-EXE-SILENT'
        'Dell SupportAssist OS Recovery Plugin for Dell Update' = 'Remove-App-MSI_EXE-S'
        'Dell SupportAssist Remediation' = 'Remove-App-MSI_EXE-S'
        'Dell Display Manager 2.1' = 'Remove-App-EXE-S-QUOTES'
        'Dell Peripheral Manager' = 'Remove-App-EXE-S-QUOTES'
        'Dell Core Services' = 'Remove-App-MSI-I-QN'
        'Dell Trusted Device Agent' = 'Remove-App-MSI-I-QN'
        'Dell Optimizer' = 'Remove-App-MSI-I-QN'
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


##########
## Main ##
##########

## Pre-Check
$ThisFileName = $MyInvocation.MyCommand.Name
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



Write-Log "===== BREAK Dell Command Update  ====="
Write-Log "======================================"

# Write-Log "Steps:"



# Install DotNet 8 (Latest, or just uninstall it)


Write-Log "LOG PATH: $LogPath"
Write-Log "Steps:"
Write-Log " 1. Uninstall Target Apps:"
Foreach ($app in $TargetApps.keys){
    Write-Log "  - $app"
}
Write-Log " 2. Uninstall .Net 8"
Write-Log "======================================"
Write-Log "SCRIPT: $ThisFileName | 1. Uninstall Target Apps"
Write-Log "======================================"

Foreach ($TargetApp in $TargetApps.keys) {

        Try{ 

            $TargetMethod = $TargetApps[$TargetApp]

            Write-Log "SCRIPT: $ThisFileName | Attempting to uninstall $TargetApp with method $TargetMethod"

            #Powershell.exe -executionpolicy remotesigned -File $UninstallerScript -AppName "Dell.CommandUpdate" -UninstallType "All" -WorkingDirectory $WorkingDirectory
            & $UninstallerScript -AppName "$TargetApp" -UninstallType "$TargetMethod" -WorkingDirectory $WorkingDirectory
            if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

        } Catch {

            Write-Log "SCRIPT: $ThisFileName | END | Error uninstalling $TargetApp with method $TargetMethod Code: $_" "ERROR"
            Exit 1

        }

    Write-Log "======================================"


}

Write-Log "SCRIPT: $ThisFileName | 2. Uninstall .Net 8"
Write-Log "======================================"


$TargetApps = @(

    "Microsoft.DotNet.DesktopRuntime.8",
    "Microsoft.DotNet.AspNetCore.8",
    "Microsoft.DotNet.HostingBundle.8",
    "Microsoft.DotNet.Runtime.8",
    "Microsoft.DotNet.SDK.8"
)
$TargetMethod = "Remove-App-WinGet"

Foreach ($TargetApp in $TargetApps) {

        Try{ 

            Write-Log "SCRIPT: $ThisFileName | Attempting to uninstall $TargetApp with method $TargetMethod"

            #Powershell.exe -executionpolicy remotesigned -File $UninstallerScript -AppName "Dell.CommandUpdate" -UninstallType "All" -WorkingDirectory $WorkingDirectory
            & $UninstallerScript -AppName "$TargetApp" -UninstallType "$TargetMethod" -WorkingDirectory $WorkingDirectory
            if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

        } Catch {

            Write-Log "SCRIPT: $ThisFileName | END | Error uninstalling $TargetApp with method $TargetMethod Code: $_" "ERROR"
            Exit 1

        }

    Write-Log "======================================"


}

Write-Log "========================================"

Write-Log "SCRIPT: $ThisFileName | END " "SUCCESS"
