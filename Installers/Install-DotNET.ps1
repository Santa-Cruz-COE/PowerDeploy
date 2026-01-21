# Install-DotNet.ps1

# NOTE: This script was almost entirely written by Claude. Entire script has been combed over and small changes and fixes have been made, testing is good so far.

<#
.SYNOPSIS
    Installs .NET Framework or .NET Runtime/SDK versions using either WinGet or Windows Optional Features.

.DESCRIPTION
    This script determines the appropriate installation method for the requested .NET version.
    - For .NET Framework 3.5: Uses Windows Optional Features
    - For .NET Core/.NET 5+: Uses WinGet via General_WinGet_Installer.ps1
    - Supports both generic version requests (e.g., "8") and specific versions (e.g., "8.0.17")

.PARAMETER Version
    The version of .NET to install. Examples:
    - "3.5" for .NET Framework 3.5 (uses Windows Features)
    - "6" for latest .NET 6 Desktop Runtime
    - "8.0.17" for specific .NET 8.0.17 Desktop Runtime
    - "sdk8" for .NET 8 SDK
    - "aspnet8" for ASP.NET Core 8 Runtime

.PARAMETER WorkingDirectory
    Path to directory on the host machine for logs and operations
    Recommended: "C:\ProgramData\YourCompanyName"

.PARAMETER InstallType
    Type of .NET component to install:
    - "Desktop" (default) - Desktop Runtime
    - "SDK" - Full SDK
    - "AspNet" - ASP.NET Core Runtime
    - "Runtime" - Base .NET Runtime

.EXAMPLE
    .\Install-DotNet.ps1 -Version "8" -WorkingDirectory "C:\ProgramData\COMPANY_NAME"
    Installs latest .NET 8 Desktop Runtime

.EXAMPLE
    .\Install-DotNet.ps1 -Version "8.0.17" -WorkingDirectory "C:\ProgramData\COMPANY_NAME"
    Installs specific .NET 8.0.17 Desktop Runtime

.EXAMPLE
    .\Install-DotNet.ps1 -Version "3.5" -WorkingDirectory "C:\ProgramData\COMPANY_NAME"
    Installs .NET Framework 3.5 using Windows Optional Features

.EXAMPLE
    .\Install-DotNet.ps1 -Version "8" -InstallType "SDK" -WorkingDirectory "C:\ProgramData\COMPANY_NAME"
    Installs .NET 8 SDK

.NOTES
    SOURCE: https://github.com/Santa-Cruz-COE/PowerDeploy
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Version,

    [Parameter(Mandatory=$true)]
    [string]$WorkingDirectory,

    [Parameter(Mandatory=$false)]
    [ValidateSet("Desktop", "SDK", "AspNet", "Runtime")]
    [string]$InstallType = "Desktop"
)

##########
## Vars ##
##########

$ThisFileName = $MyInvocation.MyCommand.Name
$ScriptRoot = $PSScriptRoot
$RepoRoot = Split-Path $ScriptRoot -Parent

$LogRoot = "$WorkingDirectory\Logs\Installer_Logs"
$LogPath = "$LogRoot\DotNet_Installer_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Path to other installer scripts
$WinGetInstallerPath = Join-Path $ScriptRoot "General_WinGet_Installer.ps1"
$WindowsFeaturesPath = Join-Path $RepoRoot "Configurators\Configure-WindowsOptionalFeatures.ps1"

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
    
    Add-Content -Path $LogPath -Value $logEntry
}

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

function Get-DotNetPackageInfo {
    param(
        [string]$Version,
        [string]$InstallType
    )
    
    # Parse the version to determine the major version
    $majorVersion = $Version.Split('.')[0]
    
    # Determine if this is a specific version request
    $isSpecificVersion = $Version -match '^\d+\.\d+\.\d+$'
    
    # Build the package ID based on type and major version
    switch ($InstallType) {
        "Desktop" {
            $packageId = "Microsoft.DotNet.DesktopRuntime.$majorVersion"
            $appName = "DotNet_Desktop_Runtime_$majorVersion"
        }
        "SDK" {
            $packageId = "Microsoft.DotNet.SDK.$majorVersion"
            $appName = "DotNet_SDK_$majorVersion"
        }
        "AspNet" {
            $packageId = "Microsoft.DotNet.AspNetCore.$majorVersion"
            $appName = "DotNet_AspNetCore_Runtime_$majorVersion"
        }
        "Runtime" {
            $packageId = "Microsoft.DotNet.Runtime.$majorVersion"
            $appName = "DotNet_Runtime_$majorVersion"
        }
    }
    
    return @{
        PackageId = $packageId
        AppName = $appName
        SpecificVersion = if ($isSpecificVersion) { $Version } else { $null }
        MajorVersion = $majorVersion
    }
}

##########
## Main ##
##########

## Pre-Check
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX PRE-CHECK for SCRIPT: $ThisFileName"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX NOTE: PRE-CHECK is not logged"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Checking if supplied paths are valid"

# Test the paths
$pathsToValidate = @{
    'WorkingDirectory' = $WorkingDirectory
    'LogRoot' = $LogRoot
    'LogPath' = $LogPath
}
Test-PathSyntaxValidity -Paths $pathsToValidate -ExitOnError

Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

## Begin main body
Write-Log "===== .NET Installer Script Started ====="
Write-Log "Version: $Version"
Write-Log "InstallType: $InstallType"
Write-Log "WorkingDirectory: $WorkingDirectory"
Write-Log "==========================================="

# Check if required scripts exist
if (-not (Test-Path $WinGetInstallerPath)) {
    Write-Log "SCRIPT: $ThisFileName | END | Required script not found: $WinGetInstallerPath" "ERROR"
    Exit 1
}

# Determine installation method based on version
if ($Version -eq "3.5" -or $Version -eq "3" -or $Version -eq "2") {
    # .NET Framework 3.5 - Use Windows Optional Features
    Write-Log "Detected .NET Framework 3.5, 3, or 2 request - using Windows Optional Features to install NetFx3 which includes all of these"
    
    if (Test-Path $WindowsFeaturesPath) {
        Write-Log "Calling Configure-WindowsOptionalFeatures.ps1 for .NET Framework 3.5"
        
        try {
            & $WindowsFeaturesPath -FeatureName "NetFx3" -Action "Enable" -WorkingDirectory $WorkingDirectory
            
            if ($LASTEXITCODE -eq 0) {
                Write-Log "SCRIPT: $ThisFileName | END | .NET Framework 3.5 installation completed successfully" "SUCCESS"
                Exit 0
            } else {
                Write-Log "SCRIPT: $ThisFileName | END | .NET Framework 3.5 installation failed" "ERROR"
                Exit 1
            }
        } catch {
            Write-Log "SCRIPT: $ThisFileName | END | Error calling Windows Features script: $_" "ERROR"
            Exit 1
        }
    } else {
        Write-Log "Windows Features script not found at: $WindowsFeaturesPath" "WARNING"
        Write-Log "Attempting to enable .NET Framework 3.5 directly..."
        
        try {
            Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -All -NoRestart
            Write-Log "SCRIPT: $ThisFileName | END | .NET Framework 3.5 enabled successfully" "SUCCESS"
            Exit 0
        } catch {
            Write-Log "SCRIPT: $ThisFileName | END | Failed to enable .NET Framework 3.5: $_" "ERROR"
            Exit 1
        }
    }
} else {
    
    # .NET Core/.NET 5+ - Use WinGet
    Write-Log "Detected .NET Core/.NET 5+ request - using WinGet"
    
    # Get package information
    $packageInfo = Get-DotNetPackageInfo -Version $Version -InstallType $InstallType
    
    Write-Log "Package ID: $($packageInfo.PackageId)"
    Write-Log "App Name: $($packageInfo.AppName)"
    if ($packageInfo.SpecificVersion) {
        Write-Log "Specific Version: $($packageInfo.SpecificVersion)"
    }
    
    # Build the command for General_WinGet_Installer.ps1
    $wingetParams = @{
        AppName = $packageInfo.AppName
        AppID = $packageInfo.PackageId
        WorkingDirectory = $WorkingDirectory
    }
    
    # Add specific version if provided
    if ($packageInfo.SpecificVersion) {
        $wingetParams.Version = $packageInfo.SpecificVersion
    }
    
    Write-Log "Calling General_WinGet_Installer.ps1..."
    
    try {
        # Call the WinGet installer with splatting
        & $WinGetInstallerPath @wingetParams
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "SCRIPT: $ThisFileName | END | .NET $Version $InstallType installation completed successfully" "SUCCESS"
            Exit 0
        } else {
            Write-Log "SCRIPT: $ThisFileName | END | .NET $Version $InstallType installation failed" "ERROR"
            Exit 1
        }
    } catch {
        Write-Log "SCRIPT: $ThisFileName | END | Error calling WinGet installer: $_" "ERROR"
        Exit 1
    }
}

Write-Log "SCRIPT: $ThisFileName | END | Unexpected end of script" "WARNING"
Exit 1