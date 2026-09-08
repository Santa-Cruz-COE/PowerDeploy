# Dell Command Update - Full Clean Install

# Param(

#     [Parameter(Mandatory=$true)]
#     [String]$WorkingDirectory, # Recommended param: "C:\ProgramData\COMPANY_NAME"
    
#     #[String]$VerboseLogs = $True,
#     [int]$timeoutSeconds = 900 # Timeout in seconds (300 sec = 5 minutes)

# )

### Other Vars ###
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

$LogPath = "$LogRoot\DellCommandUpdate.Full_Clean_Install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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



Write-Log "===== Preconfigured App Installer  ====="

Write-Log "Install App: Dell Command Update"
Write-Log "Install Method: Full Clean (Multiple steps)"
Write-Log "Steps:"
Write-Log " 1. Attempt clean uninstall of pre-existing installations of DCU"
Write-Log " 2. Uninstall .NET version 8"
Write-Log " 3. Install required .NET version 8 variant"
Write-Log " 4. Install DCU using WinGet"

Write-Log "LOG PATH: $LogPath"


Write-Log "========================================"
Write-Log "SCRIPT: $ThisFileName | 1. Attempt clean uninstall of pre-existing installations of DCU"
Write-Log "========================================"

$Success = $False 
$Attempts = 2

Try{ 

    While($Attempts -ne 0){

        # Registry: "Dell Command | Update" 
        # Can possibly remove, the below instances should work without the need to hit CIM. 
        Write-Log "SCRIPT: $ThisFileName | Attempting to uninstall via CIM: Dell Command | Update"
        #Powershell.exe -executionpolicy remotesigned -File $UninstallerScript -AppName "Dell.CommandUpdate.Universal" -UninstallType "All" -WorkingDirectory $WorkingDirectory
        & $UninstallerScript -AppName "Dell Command | Update" -DisplayName "Dell Command | Update" -UninstallType "Remove-App-CIM" -WorkingDirectory $WorkingDirectory
        if ($LASTEXITCODE -ne 0) { $Method3Success=$False } else { $Method3Success=$True}

        Write-Log "SCRIPT: $ThisFileName | Attempting to uninstall AppXPackage: DellInc.DellCommandUpdate"
        #Powershell.exe -executionpolicy remotesigned -File $UninstallerScript -AppName "Dell.CommandUpdate.Universal" -UninstallType "All" -WorkingDirectory $WorkingDirectory
        & $UninstallerScript -AppName "DellInc.DellCommandUpdate" -UninstallType "Remove-AppxPackage" -WorkingDirectory $WorkingDirectory
        if ($LASTEXITCODE -ne 0) { $Method3Success=$False } else { $Method3Success=$True}

        Write-Log "SCRIPT: $ThisFileName | Attempting to uninstall WinGet app: Dell.CommandUpdate"
        #Powershell.exe -executionpolicy remotesigned -File $UninstallerScript -AppName "Dell.CommandUpdate" -UninstallType "All" -WorkingDirectory $WorkingDirectory
        & $UninstallerScript -AppName "Dell.CommandUpdate" -UninstallType "Remove-App-WinGet" -WorkingDirectory $WorkingDirectory
        if ($LASTEXITCODE -ne 0) { $Method1Success=$False } else { $Method1Success=$True}

        Write-Log "SCRIPT: $ThisFileName | Attempting to uninstall WinGet app: Dell.CommandUpdate.Universal"
        #Powershell.exe -executionpolicy remotesigned -File $UninstallerScript -AppName "Dell.CommandUpdate.Universal" -UninstallType "All" -WorkingDirectory $WorkingDirectory
        & $UninstallerScript -AppName "Dell.CommandUpdate.Universal" -UninstallType "Remove-App-WinGet" -WorkingDirectory $WorkingDirectory
        if ($LASTEXITCODE -ne 0) { $Method2Success=$False } else { $Method2Success=$True}



        if (($Method1Success -eq $True) -and ($Method2Success -eq $True) -and ($Method3Success -eq $True)){ 
            
            $Success = $True
            $Attempts = 0

        } else {

            $Attempts--

        }

    }

    if ($Success -eq $False){

        Write-Log "Failed to uninstall Dell Command Update. Here are the uninstall attempt" "ERROR"

        Write-Log "WinGet app:      Dell.CommandUpdate               Uninstall Success: $Method1Success"
        Write-Log "WinGet app:      Dell.CommandUpdate.Universal     Uninstall Success: $Method2Success"
        Write-Log "AppXPackage:     DellInc.DellCommandUpdate        Uninstall Success: $Method3Success"

        Exit 1

    }


} Catch {

    Write-Log "SCRIPT: $ThisFileName | END | DCU Uninstall failed. Code: $_" "ERROR"
    Exit 1

}

Write-Log "========================================"
Write-Log "SCRIPT: $ThisFileName | 2. Uninstall .NET version 8"
Write-Log "========================================"

Try {

    Write-Log "SCRIPT: $ThisFileName | Attempting to uninstall .NET 8"
    & $UninstallerScript -AppName "Microsoft.DotNet.DesktopRuntime.8" -UninstallType "All" -WorkingDirectory $WorkingDirectory
    if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

} Catch {

    Write-Log "SCRIPT: $ThisFileName | Could not uninstall .NET 8. Will continue on anyways." "WARNING"

}

Write-Log "========================================"
Write-Log "SCRIPT: $ThisFileName | 3. Install required .NET version"
Write-Log "========================================"

Try {

    #Write-Log "Attempting to uninstall .NET 8"
    #Powershell.exe -executionpolicy remotesigned -File $UninstallerScript -AppName "Microsoft.DotNet.DesktopRuntime.8" -UninstallType "WinGet" -WorkingDirectory $WorkingDirectory
    
    Write-Log "SCRIPT: $ThisFileName | Attempting to install .NET 8.0.15"
    #Powershell.exe -executionpolicy remotesigned -File $DotNetInstallerScript -Version 8.0.15 -WorkingDirectory $WorkingDirectory
    & $DotNetInstallerScript -Version 8.0.15 -WorkingDirectory $WorkingDirectory
    if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

} Catch {

    Write-Log "SCRIPT: $ThisFileName | END | .NET install failed. There may be another version of .NET 8 Desktop Runtime already installed preventing rollback to 8.0.15. Code: $_" "ERROR"
    Exit 1

}

Write-Log "========================================"
Write-Log "SCRIPT: $ThisFileName | 4. Install DCU using WinGet"
Write-Log "========================================"

Try {

    Write-Log "SCRIPT: $ThisFileName | Attempting to install DCU"
    #Powershell.exe -executionpolicy remotesigned -File $WinGetInstallerScript -AppName "DellCommandUpdate" -AppID "Dell.CommandUpdate" -WorkingDirectory $WorkingDirectory
    & $WinGetInstallerScript -AppName "DellCommandUpdate" -AppID "Dell.CommandUpdate" -WorkingDirectory $WorkingDirectory
    if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

} Catch {

    Write-Log "SCRIPT: $ThisFileName | END | Failed to install DCU. Code: $_" "ERROR"
    Exit 1

}

Write-Log "========================================"

Write-Log "SCRIPT: $ThisFileName | END " "SUCCESS"
Exit 0