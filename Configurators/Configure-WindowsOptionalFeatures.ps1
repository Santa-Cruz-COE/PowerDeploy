# General Windows Optional Feature Installer

<#
NOTE: 
- This script was almost entirely written by Claude Sonnet 4.5 based on my other scripts. I mostly just made adjustments to logic as I tested.
- I tested Enable, Disable, and Check for NetFx3 and it worked great!
#>

<#
.SYNOPSIS
    Install or uninstall Windows Optional Features using DISM/Get-WindowsOptionalFeature

.DESCRIPTION
    This script provides a standardized way to manage Windows Optional Features with comprehensive logging,
    error handling, and validation. It can install, uninstall, or check the status of Windows features.

.PARAMETER FeatureName
    The exact name of the Windows Optional Feature to manage.
    Use 'List' to see all available features.
    Examples: "Microsoft-Hyper-V-All", "TelnetClient", "Microsoft-Windows-Subsystem-Linux"

.PARAMETER Action
    The action to perform on the feature.
    Valid values: "Enable", "Disable", "Check"
    Default: "Enable"

.PARAMETER WorkingDirectory
    Path to directory on the host machine that will be used to hold logs.
    Recommended: "C:\ProgramData\COMPANY_NAME"

.PARAMETER RestartIfNeeded
    If $true, automatically restart the computer if the feature installation requires it.
    If $false, will note that a restart is required but won't perform it.
    Default: $false

.PARAMETER VerboseLogs
    Enable verbose logging output.
    Default: $true

.EXAMPLE
    .\General_WindowsOptionalFeature_Installer.ps1 -FeatureName "TelnetClient" -Action "Enable" -WorkingDirectory "C:\ProgramData\COMPANY_NAME"
    
.EXAMPLE
    .\General_WindowsOptionalFeature_Installer.ps1 -FeatureName "Microsoft-Hyper-V-All" -Action "Enable" -WorkingDirectory "C:\ProgramData\COMPANY_NAME" -RestartIfNeeded $true

.EXAMPLE
    .\General_WindowsOptionalFeature_Installer.ps1 -FeatureName "List" -WorkingDirectory "C:\ProgramData\COMPANY_NAME"

.NOTES
    Requires administrative privileges
    Compatible with Windows 10/11 and Windows Server

    Common Features:
    - TelnetClient
    - TFTP
    - Microsoft-Hyper-V-All
    - Microsoft-Windows-Subsystem-Linux
    - VirtualMachinePlatform
    - Containers
    - NetFx3 (.NET Framework 3.5)
    - IIS-WebServerRole
    - IIS-ASPNET45
#>

Param(
    [Parameter(Mandatory=$true)]
    [String]$FeatureName,

    [Parameter(Mandatory=$false)]
    [ValidateSet("Enable", "Disable", "Check")]
    [String]$Action = "Enable",

    [Parameter(Mandatory=$true)]
    [String]$WorkingDirectory,

    [Parameter(Mandatory=$false)]
    [Boolean]$RestartIfNeeded = $false,

    [Parameter(Mandatory=$false)]
    [Boolean]$VerboseLogs = $true
)

############
### Vars ###
############

$LogRoot = "$WorkingDirectory\Logs\Config_Logs"
$SafeFeatureName = $FeatureName -replace '[^\w]', '_'
$LogPath = "$LogRoot\$SafeFeatureName.WindowsFeature.$Action._Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ActionSuccess = $false
$RestartRequired = $false

#################
### Functions ###
#################

function Test-PathSyntaxValidity {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Paths,
        [switch]$ExitOnError
    )
    
    $illegalChars = '[<>"|?*]'
    
    $reservedNames = @(
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    )
    
    $allValid = $true
    $issues = @()
    
    foreach ($paramName in $Paths.Keys) {
        $path = $Paths[$paramName]
        
        if ([string]::IsNullOrWhiteSpace($path)) {
            $issues += "Parameter '$paramName' is null or empty"
            $allValid = $false
            continue
        }
        
        if ($path -match '\\["\' + "']$") {
            $issues += "Parameter '$paramName' has trailing backslash before quote: '$path'"
            $allValid = $false
        }
        
        if ($path -match $illegalChars) {
            $matches = [regex]::Matches($path, $illegalChars)
            $foundChars = ($matches | ForEach-Object { $_.Value }) -join ', '
            $issues += "Parameter '$paramName' contains illegal characters ($foundChars): '$path'"
            $allValid = $false
        }
        
        if ($path -match '(?<!^)\\\\') {
            $issues += "Parameter '$paramName' contains double backslashes (not a UNC path): '$path'"
            $allValid = $false
        }
        
        $pathComponents = $path -split '[\\/]'
        foreach ($component in $pathComponents) {
            $nameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($component)
            if ($nameWithoutExt -in $reservedNames) {
                $issues += "Parameter '$paramName' contains reserved Windows name '$nameWithoutExt': '$path'"
                $allValid = $false
            }
        }
        
        if ($path.Length -gt 260) {
            $issues += "Parameter '$paramName' exceeds maximum path length (260 characters): '$path'"
            $allValid = $false
        }
        
        if ($path -match '^[a-zA-Z]:' -and $path -notmatch '^[a-zA-Z]:\\') {
            $issues += "Parameter '$paramName' has invalid drive format: '$path'"
            $allValid = $false
        }
        
        if ($path -ne $path.Trim()) {
            $issues += "Parameter '$paramName' has leading or trailing whitespace: '$path'"
            $allValid = $false
        }
    }
    
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

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FeatureStatus {
    param(
        [string]$Name
    )
    Write-Log "-----------------------------------------"
    Write-Log "Function: Get-FeatureStatus | Begin"
    Write-Log "Target Feature: $Name"

    
    Write-Log "Checking LOCAL status of feature: $Name"
    
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction Stop
        
        if ($VerboseLogs) {
            Write-Log "Feature Name: $($feature.FeatureName)"
            Write-Log "Display Name: $($feature.DisplayName)"
            Write-Log "State: $($feature.State)"
            Write-Log "Restart Required: $($feature.RestartRequired)"
        } else {
            Write-Log "Feature '$Name' current state: $($feature.State)"
        }

        Write-Log "Function: Get-FeatureStatus | End"
        Write-Log "-----------------------------------------"
        return $feature
    }
    catch {
        Write-Log "Failed to get feature status: $($_.Exception.Message)" "Warning"
        Write-Log "Function: Get-FeatureStatus | End"
        Write-Log "-----------------------------------------"
        return $null
    }
}

function Get-AllFeatures {
    Write-Log "Retrieving all Windows Optional Features..."
    
    try {
        $features = Get-WindowsOptionalFeature -Online -ErrorAction Stop
        
        Write-Log "==========================================="
        Write-Log "AVAILABLE WINDOWS OPTIONAL FEATURES"
        Write-Log "==========================================="
        Write-Log "Total Features: $($features.Count)"
        Write-Log ""
        
        $enabledCount = ($features | Where-Object { $_.State -eq "Enabled" }).Count
        $disabledCount = ($features | Where-Object { $_.State -eq "Disabled" }).Count
        
        Write-Log "Enabled: $enabledCount | Disabled: $disabledCount"
        Write-Log ""
        
        if ($VerboseLogs) {
            Write-Log "Feature List (Name | State):"
            Write-Log "-------------------------------------------"
            foreach ($feature in $features | Sort-Object FeatureName) {
                $stateColor = if ($feature.State -eq "Enabled") { "SUCCESS" } else { "INFO" }
                Write-Log "$($feature.FeatureName) | $($feature.State)" $stateColor
            }
        } else {
            Write-Log "Use -VerboseLogs `$true to see full feature list"
            Write-Log "Showing first 20 features:"
            Write-Log "-------------------------------------------"
            foreach ($feature in $features | Select-Object -First 20 | Sort-Object FeatureName) {
                Write-Log "$($feature.FeatureName) | $($feature.State)"
            }
        }
        
        Write-Log "==========================================="
        return $true
    }
    catch {
        Write-Log "Failed to retrieve features: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Enable-Feature {
    param(
        [string]$Name
    )
    
    Write-Log "========================================="
    Write-Log "Function: Enable-Feature | Begin"
    Write-Log "Target Feature: $Name"
    
    $preCheck = Get-FeatureStatus -Name $Name
    
    if ($null -eq $preCheck) {
        Write-Log "Function: Enable-Feature | Feature not found or inaccessible" "ERROR"
        return $false
    }
    
    if ($preCheck.State -eq "Enabled") {
        Write-Log "Function: Enable-Feature | Feature already enabled" "SUCCESS"
        return $true
    }
    
    Write-Log "Enabling feature: $Name"
    
    try {
        $result = Enable-WindowsOptionalFeature -Online -FeatureName $Name -All -NoRestart -ErrorAction Stop
        
        if ($result.RestartNeeded) {
            Write-Log "Feature enabled successfully - RESTART REQUIRED" "WARNING"
            $script:RestartRequired = $true
        } else {
            Write-Log "Feature enabled successfully - No restart required" "SUCCESS"
        }
        
        Start-Sleep -Seconds 3
        
        Write-Log "Running a post action check..."
        $postCheck = Get-FeatureStatus -Name $Name
        
        if ($postCheck.State -eq "Enabled") {
            Write-Log "Function: Enable-Feature | End | Verification successful" "SUCCESS"
            return $true
        } else {
            Write-Log "Function: Enable-Feature | End | Verification failed - State: $($postCheck.State)" "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Function: Enable-Feature | Failed to enable feature: $($_.Exception.Message)" "ERROR"
        return $false
    }
    
    Write-Log "Function: Enable-Feature | End"
    Write-Log "========================================="
}

function Disable-Feature {
    param(
        [string]$Name
    )
    
    Write-Log "========================================="
    Write-Log "Function: Disable-Feature | Begin"
    Write-Log "Target Feature: $Name"
    
    $preCheck = Get-FeatureStatus -Name $Name
    
    if ($null -eq $preCheck) {
        Write-Log "Function: Disable-Feature | Feature not found or inaccessible" "ERROR"
        return $false
    }
    
    # Check if already in any disabled state
    if ($preCheck.State -like "Disabled*") {
        Write-Log "Function: Disable-Feature | Feature already disabled (State: $($preCheck.State))" "SUCCESS"
        return $true
    }
    
    Write-Log "Disabling feature: $Name"
    
    try {
        $result = Disable-WindowsOptionalFeature -Online -FeatureName $Name -NoRestart -ErrorAction Stop
        
        if ($result.RestartNeeded) {
            Write-Log "Feature disabled successfully - RESTART REQUIRED" "WARNING"
            $script:RestartRequired = $true
        } else {
            Write-Log "Feature disabled successfully - No restart required" "SUCCESS"
        }
        
        Start-Sleep -Seconds 3
        
        Write-Log "Running a post action check..."
        $postCheck = Get-FeatureStatus -Name $Name
        
        # Accept any disabled state (Disabled or DisabledWithPayloadRemoved)
        if ($postCheck.State -like "Disabled*") {
            Write-Log "Function: Disable-Feature | End | Verification successful (State: $($postCheck.State))" "SUCCESS"
            return $true
        } else {
            Write-Log "Function: Disable-Feature | End | Verification failed - State: $($postCheck.State)" "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Function: Disable-Feature | Failed to disable feature: $($_.Exception.Message)" "ERROR"
        return $false
    }
    
    Write-Log "Function: Disable-Feature | End"
    Write-Log "========================================="
}

############
### MAIN ###
############

$ThisFileName = $MyInvocation.MyCommand.Name

Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX PRE-CHECK for SCRIPT: $ThisFileName"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX NOTE: PRE-CHECK is not logged"

if (-not (Test-Administrator)) {
    Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX ERROR: This script requires administrative privileges" -ForegroundColor Red
    Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Please run as Administrator"
    Exit 1
}

Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Administrator check: PASSED"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Checking if supplied paths are valid"

$pathsToValidate = @{
    'WorkingDirectory' = $WorkingDirectory
    'LogRoot' = $LogRoot
    'LogPath' = $LogPath
}

Test-PathSyntaxValidity -Paths $pathsToValidate -ExitOnError
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

Write-Log "===== Windows Optional Feature Management Script ====="
Write-Log "FEATURE NAME: $FeatureName"
Write-Log "ACTION: $Action"
Write-Log "WORKING DIRECTORY: $WorkingDirectory"
Write-Log "RESTART IF NEEDED: $RestartIfNeeded"
Write-Log "VERBOSE LOGS: $VerboseLogs"
Write-Log "========================================="

if ($FeatureName -eq "List") {
    Write-Log "List mode requested - displaying all features"
    $listResult = Get-AllFeatures
    
    if ($listResult) {
        Write-Log "SCRIPT: $ThisFileName | END | Feature list retrieved successfully" "SUCCESS"
        Exit 0
    } else {
        Write-Log "SCRIPT: $ThisFileName | END | Failed to retrieve feature list" "ERROR"
        Exit 1
    }
}

Write-Log "Beginning $Action operation for feature: $FeatureName"

switch ($Action) {
    "Enable" {
        $ActionSuccess = Enable-Feature -Name $FeatureName
    }
    "Disable" {
        $ActionSuccess = Disable-Feature -Name $FeatureName        
    }
    "Check" {
        $feature = Get-FeatureStatus -Name $FeatureName
        if ($null -ne $feature) {
            Write-Log "Feature Check Results:"
            Write-Log "  Feature Name: $($feature.FeatureName)"
            Write-Log "  Display Name: $($feature.DisplayName)"
            Write-Log "  Current State: $($feature.State)"
            Write-Log "  Restart Required: $($feature.RestartRequired)"
            
            # Check returns success only if feature is ENABLED
            if ($feature.State -eq "Enabled") {
                Write-Log "Status: Feature is ENABLED and ready to use" "SUCCESS"
                $ActionSuccess = $true
            } elseif ($feature.State -like "Disabled*") {
                Write-Log "Status: Feature is DISABLED" "WARNING"
                $ActionSuccess = $false
            } else {
                Write-Log "Status: Feature is in an unknown state: $($feature.State)" "WARNING"
                $ActionSuccess = $false
            }
            
        } else {
            Write-Log "Feature not found or inaccessible" "ERROR"
            $ActionSuccess = $false
        }
    }
}

Write-Log "========================================="
Write-Log "Final Result:"

if ($ActionSuccess) {
    if ($RestartRequired) {
        Write-Log "Action completed successfully - RESTART REQUIRED" "WARNING"
        
        if ($RestartIfNeeded) {
            Write-Log "RestartIfNeeded is enabled - initiating restart in 60 seconds..." "WARNING"
            Write-Log "Press Ctrl+C to cancel restart"
            Start-Sleep -Seconds 5
            shutdown /r /t 60 /c "Restart required to complete Windows feature configuration"
        } else {
            Write-Log "RestartIfNeeded is disabled - please restart manually to complete the operation" "WARNING"
        }
    }
    
    Write-Log "SCRIPT: $ThisFileName | END | $Action of $FeatureName successful!" "SUCCESS"
    Exit 0
} else {
    Write-Log "SCRIPT: $ThisFileName | END | $Action of $FeatureName failed!" "ERROR"
    Exit 1
}