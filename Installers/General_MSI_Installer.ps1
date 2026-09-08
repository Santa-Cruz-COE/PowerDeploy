# General MSI Installer
# Primarily written by Claude, primarily borrowing from previously written scripts.
# Working from testing so far. Need to do more testing on InstallArgs. Also it may be capturing exit codes ineffectively.

<#
.SYNOPSIS
    Installs MSI packages with configurable arguments, timeout handling, and installation verification.

.DESCRIPTION
    This script provides a standardized way to install MSI packages with comprehensive logging,
    error handling, timeout protection, and post-install verification. It uses msiexec.exe with 
    customizable arguments and verifies installation via registry checks.

.PARAMETER MSIPath
    Full path to the MSI file to install.
    The file must exist and have a .msi extension.

.PARAMETER AppName
    Friendly name of the application being installed (used for logging).
    Example: "Adobe_Acrobat_Pro"

.PARAMETER DisplayName
    The display name of the application as it appears in Add/Remove Programs.
    Used for post-install verification. Supports wildcard matching.
    If not provided, verification step will be skipped.
    Example: "Adobe Acrobat" (will match "Adobe Acrobat Pro DC", etc.)

.PARAMETER WorkingDirectory
    Path to directory on the host machine that will be used to hold logs.
    Recommended: "C:\ProgramData\COMPANY_NAME"

.PARAMETER InstallArgs
    Custom MSI installation arguments.
    If not provided, defaults to: /i "[MSIPath]" /qn /norestart /l*v "[LogFile]"
    Example: "/i `"$MSIPath`" /qn /norestart INSTALLDIR=`"C:\CustomPath`""

.PARAMETER TimeoutSeconds
    Maximum time in seconds to wait for installation to complete.
    Default: 900 (15 minutes)

.PARAMETER SkipVerification
    If specified, skips the post-install verification check.
    Default: $false

.EXAMPLE
    .\General_MSI_Installer.ps1 -MSIPath "C:\Temp\Downloads\app.msi" -AppName "MyApp" -DisplayName "My Application" -WorkingDirectory "C:\ProgramData\COMPANY_NAME"
    Installs app.msi with verification

.EXAMPLE
    .\General_MSI_Installer.ps1 -MSIPath "C:\Temp\Downloads\AdobeAcrobat.msi" -AppName "Adobe_Acrobat_Pro" -DisplayName "Adobe Acrobat" -WorkingDirectory "C:\ProgramData\COMPANY_NAME"
    Installs Adobe Acrobat and verifies using wildcard match

.EXAMPLE
    .\General_MSI_Installer.ps1 -MSIPath "C:\Temp\Downloads\app.msi" -AppName "MyApp" -WorkingDirectory "C:\ProgramData\COMPANY_NAME" -SkipVerification
    Installs app.msi without post-install verification

.NOTES
    SOURCE: https://github.com/Santa-Cruz-COE/PowerDeploy
    
    Common MSI Exit Codes:
    0    - Success
    1602 - User cancelled installation
    1603 - Fatal error during installation
    1618 - Another installation already in progress
    1619 - Failed to open installation package
    1639 - Invalid command line argument
    3010 - Success, restart required
#>

Param(
    [Parameter(Mandatory=$true)]
    [String]$MSIPath,

    [Parameter(Mandatory=$true)]
    [String]$AppName,

    [Parameter(Mandatory=$false)]
    [String]$DisplayName = $null,

    [Parameter(Mandatory=$true)]
    [String]$WorkingDirectory,

    [Parameter(Mandatory=$false)]
    [String]$InstallArgs = $null,

    [Parameter(Mandatory=$false)]
    [int]$TimeoutSeconds = 900,

    [Parameter(Mandatory=$false)]
    [switch]$SkipVerification = $false # Consider removing, but could be useful in specific scenarios
)

############
### Vars ###
############

$ThisFileName = $MyInvocation.MyCommand.Name
$ScriptRoot = $PSScriptRoot
$RepoRoot = Split-Path $ScriptRoot -Parent

$LogRoot = "$WorkingDirectory\Logs\Installer_Logs"
$SafeAppName = $AppName -replace '[^\w]', '_'
$LogPath = "$LogRoot\$SafeAppName.MSI_Installer_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

$DetectionScript = "$RepoRoot\Templates\Detection-Script-Application_TEMPLATE.ps1"

$InstallSuccess = $false

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

function Test-MSIFile {
    param(
        [string]$Path
    )
    
    Write-Log "-----------------------------------------"
    Write-Log "Function: Test-MSIFile | Begin"
    Write-Log "Validating MSI file: $Path"
    
    # Check if file exists
    if (-not (Test-Path $Path)) {
        Write-Log "Function: Test-MSIFile | End | MSI file not found at path" "ERROR"
        Write-Log "-----------------------------------------"
        return $false
    }
    
    # Check if it's a file (not a directory)
    $item = Get-Item $Path
    if ($item.PSIsContainer) {
        Write-Log "Function: Test-MSIFile | End | Path is a directory, not a file" "ERROR"
        Write-Log "-----------------------------------------"
        return $false
    }
    
    # Check file extension
    if ($item.Extension -ne ".msi") {
        Write-Log "Function: Test-MSIFile | End | File does not have .msi extension (Extension: $($item.Extension))" "ERROR"
        Write-Log "-----------------------------------------"
        return $false
    }
    
    Write-Log "MSI file validated successfully"
    Write-Log "File size: $([math]::Round($item.Length / 1MB, 2)) MB"
    Write-Log "Function: Test-MSIFile | End"
    Write-Log "-----------------------------------------"
    return $true
}

# function Test-ApplicationInstalled {
#     param(
#         [Parameter(Mandatory=$true)]
#         [string]$DisplayName
#     )
    
#     Write-Log "-----------------------------------------"
#     Write-Log "Function: Test-ApplicationInstalled | Begin"
#     Write-Log "Searching for application: $DisplayName"
    
#     try {
#         # Check both 32-bit and 64-bit registry locations
#         $registryPaths = @(
#             'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
#             'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
#         )
        
#         Write-Log "Checking registry uninstall keys..."
        
#         $installedApp = Get-ItemProperty -Path $registryPaths -ErrorAction SilentlyContinue | 
#                         Where-Object { $_.DisplayName -like "*$DisplayName*" } | 
#                         Select-Object -Property DisplayName, DisplayVersion, Publisher, InstallDate, UninstallString -First 1
        
#         if ($installedApp) {
#             Write-Log "Application found in registry!" "SUCCESS"
#             Write-Log "  Display Name: $($installedApp.DisplayName)"
#             if ($installedApp.DisplayVersion) {
#                 Write-Log "  Version: $($installedApp.DisplayVersion)"
#             }
#             if ($installedApp.Publisher) {
#                 Write-Log "  Publisher: $($installedApp.Publisher)"
#             }
#             if ($installedApp.InstallDate) {
#                 Write-Log "  Install Date: $($installedApp.InstallDate)"
#             }
            
#             Write-Log "Function: Test-ApplicationInstalled | End | Application detected" "SUCCESS"
#             Write-Log "-----------------------------------------"
#             return $true
#         } else {
#             Write-Log "Application not found in registry" "WARNING"
#             Write-Log "Function: Test-ApplicationInstalled | End | Application not detected"
#             Write-Log "-----------------------------------------"
#             return $false
#         }
        
#     } catch {
#         Write-Log "Function: Test-ApplicationInstalled | Error checking registry: $_" "ERROR"
#         Write-Log "Function: Test-ApplicationInstalled | End"
#         Write-Log "-----------------------------------------"
#         return $false
#     }
# }

function Install-MSIPackage {
    param(
        [string]$MSIPath,
        [string]$Arguments,
        [int]$Timeout
    )
    
    Write-Log "-----------------------------------------"
    Write-Log "Function: Install-MSIPackage | Begin"
    Write-Log "Installing: $MSIPath"
    
    # Create log file paths for MSI installation
    $MSIOutputLog = "$LogRoot\$SafeAppName.MSI_InstallationOutput_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    $MSIErrorLog = "$LogRoot\$SafeAppName.MSI_InstallationError_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    
    Write-Log "MSI Output Log: $MSIOutputLog"
    Write-Log "MSI Error Log: $MSIErrorLog"
    
    # If no custom arguments provided, use default silent install
    if ([string]::IsNullOrWhiteSpace($Arguments)) {
        $MSIVerboseLog = "$LogRoot\$SafeAppName.MSI_VerboseInstall_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $Arguments = "/i `"$MSIPath`" /qn /norestart /l*v `"$MSIVerboseLog`""
        Write-Log "Using default silent installation arguments"
        Write-Log "MSI Verbose Log: $MSIVerboseLog"
    } else {
        Write-Log "Using custom installation arguments"
    }
    
    Write-Log "Installation command: msiexec.exe $Arguments"
    
    try {
        # Start the installation process
        $procParams = @{
            FilePath = "msiexec.exe"
            ArgumentList = $Arguments
            WindowStyle = 'Hidden'
            PassThru = $true
            RedirectStandardOutput = $MSIOutputLog
            RedirectStandardError = $MSIErrorLog
        }
        
        Write-Log "Starting MSI installation process..."
        $proc = Start-Process @procParams
        
        # Monitor process with timeout
        $startTime = Get-Date
        
        while (-not $proc.HasExited) {
            Start-Sleep -Seconds 10
            $elapsed = (Get-Date) - $startTime
            Write-Log "Time elapsed: $([math]::Round($elapsed.TotalSeconds, 0)) / $Timeout seconds"
            
            if ($elapsed.TotalSeconds -ge $Timeout) {
                Write-Log "Timeout reached ($Timeout seconds) for $AppName. Killing process..." "WARNING"
                
                try {
                    $proc.Kill()
                    Write-Log "Installation process killed due to timeout" "ERROR"
                } catch {
                    Write-Log "Failed to kill process: $_" "ERROR"
                }
                
                Write-Log "Function: Install-MSIPackage | End | Installation timed out" "ERROR"
                Write-Log "-----------------------------------------"
                return $false
            }
        }
        
        # Process has exited, check exit code
        $exitCode = $proc.ExitCode
        Write-Log "Installation process exited with code: $exitCode"
        
        # Interpret exit code
        switch ($exitCode) {
            0 {
                Write-Log "Installation completed successfully" "SUCCESS"
                $result = $true
            }
            3010 {
                Write-Log "Installation completed successfully - Restart required" "SUCCESS"
                Write-Log "Note: System restart may be needed to complete installation" "WARNING"
                $result = $true
            }
            1602 {
                Write-Log "Installation cancelled by user" "ERROR"
                $result = $false
            }
            1603 {
                Write-Log "Fatal error during installation" "ERROR"
                $result = $false
            }
            1618 {
                Write-Log "Another installation is already in progress" "ERROR"
                Write-Log "Please wait for other installations to complete and try again" "WARNING"
                $result = $false
            }
            1619 {
                Write-Log "Failed to open installation package - verify the MSI file is valid" "ERROR"
                $result = $false
            }
            1639 {
                Write-Log "Invalid command line argument" "ERROR"
                $result = $false
            }
            default {
                Write-Log "Nonstandard exit code. No info." "WARNING"
                $result = $false
            }
        }
        
        # Wait for file system to update
        Write-Log "Waiting for system to update..."
        Start-Sleep -Seconds 5
        
        Write-Log "Function: Install-MSIPackage | End"
        Write-Log "-----------------------------------------"

        return $result
        
    } catch {
        Write-Log "Function: Install-MSIPackage | Exception occurred: $_" "ERROR"
        Write-Log "Function: Install-MSIPackage | End"
        Write-Log "-----------------------------------------"
        return $false
    }
}

############
### MAIN ###
############

## Pre-Check
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX PRE-CHECK for SCRIPT: $ThisFileName"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX NOTE: PRE-CHECK is not logged"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Checking if supplied paths are valid"

# Test the paths
$pathsToValidate = @{
    'MSIPath' = $MSIPath
    'WorkingDirectory' = $WorkingDirectory
    'LogRoot' = $LogRoot
    'LogPath' = $LogPath
}

Test-PathSyntaxValidity -Paths $pathsToValidate -ExitOnError

Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

## Begin main body
Write-Log "===== MSI Installer Script Started ====="
Write-Log "AppName: $AppName"
Write-Log "MSI Path: $MSIPath"
Write-Log "WorkingDirectory: $WorkingDirectory"
Write-Log "Timeout: $TimeoutSeconds seconds"

if ($DisplayName) {
    Write-Log "Display Name (for verification): $DisplayName"
} else {
    Write-Log "Display Name: Not provided - verification will be skipped"
}

if ($SkipVerification) {
    Write-Log "Skip Verification: TRUE"
}

if ($InstallArgs) {
    Write-Log "Custom Arguments: $InstallArgs"
} else {
    Write-Log "Arguments: Using default silent installation"
}
Write-Log "==========================================="

## Check for pre-existing installation
if ($DisplayName -and -not $SkipVerification) {
    Write-Log "Checking for pre-existing installation..."
    #$preInstallCheck = Test-ApplicationInstalled -DisplayName $DisplayName

    Try {

        $preInstallCheck = $false
        & $DetectionScript -DisplayName $DisplayName -DetectMethod "MSI_Registry" -WorkingDirectory $WorkingDirectory
        if ($LASTEXITCODE -eq 0) {
            $preInstallCheck = $true
        } else {
            $preInstallCheck = $false
        }

    } catch {

        Write-Log "Error during verification script execution: $_" "ERROR"
        $preInstallCheck = $false
        
    }

    if ($preInstallCheck) {
        Write-Log "Application '$DisplayName' is already installed!" "SUCCESS"
        Write-Log "SCRIPT: $ThisFileName | END | Application already present, no installation needed" "SUCCESS"
        Exit 0
    } else {
        Write-Log "No pre-existing installation detected, proceeding with installation"
    }
}

## Validate MSI file
Write-Log "Validating MSI file..."
if (-not (Test-MSIFile -Path $MSIPath)) {
    Write-Log "SCRIPT: $ThisFileName | END | MSI file validation failed" "ERROR"
    Exit 1
}

## Perform installation
Write-Log "Beginning MSI installation for: $AppName"

$InstallSuccess = Install-MSIPackage -MSIPath $MSIPath -Arguments $InstallArgs -Timeout $TimeoutSeconds

## Post-install verification
if ($DisplayName -and -not $SkipVerification) {
    Write-Log "========================================="
    Write-Log "Performing post-install verification..."
    
    # Give system extra time to register the installation
    Write-Log "Waiting for system to register installation..."
    Start-Sleep -Seconds 10
    
    # Try verification up to 3 times with delays
    $maxAttempts = 3
    $verified = $false
    
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        Write-Log "Verification attempt $attempt of $maxAttempts"
        
        #$verified = Test-ApplicationInstalled -DisplayName $DisplayName
        
        Try {

            & $DetectionScript -DisplayName $DisplayName -DetectMethod "MSI_Registry" -WorkingDirectory $WorkingDirectory
            if ($LASTEXITCODE -eq 0) {
                $verified = $true
            } else {
                $verified = $false
            }

        } catch {

            Write-Log "Error during verification script execution: $_" "ERROR"
            $verified = $false

        }


        if ($verified) {
            Write-Log "Post-install verification successful!" "SUCCESS"
            $InstallSuccess = $True

            break
        } else {
            if ($attempt -lt $maxAttempts) {
                Write-Log "Verification failed, waiting 5 seconds before retry..." "WARNING"
                Start-Sleep -Seconds 5
            }
        }
    }
    
    if (-not $verified) {
        Write-Log "Post-install verification failed - application not found in registry" "ERROR"
        Write-Log "Installation may have succeeded but registry not updated, or DisplayName mismatch" "WARNING"
        $InstallSuccess = $false
    }

    Write-Log "========================================="

}

## Final result
Write-Log "========================================="
Write-Log "Final Result:"

if ($InstallSuccess -eq $true) {
    Write-Log "SCRIPT: $ThisFileName | END | Installation of $AppName successful!" "SUCCESS"
    Exit 0
} else {
    Write-Log "SCRIPT: $ThisFileName | END | Installation of $AppName failed!" "ERROR"
    Exit 1
}