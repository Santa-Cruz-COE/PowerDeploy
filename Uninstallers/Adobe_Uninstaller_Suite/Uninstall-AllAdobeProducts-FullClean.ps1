# Logic for adobe clean uninstall
<#
NOTES

- Needs to replace these EXE's with curls directly from web.
- Needs some basic updates like params for logs, param checks, proper exits



#>

Param(

    [string]$WorkingDirectory # If not inherited will default to local script directory structure

)


## Vars

$RepoRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
if (-not $WorkingDirectory) {
    $WorkingDirectory = Split-Path -Path $RepoRoot -Parent
}

$LogRoot = "$WorkingDirectory\Logs\Uninstaller_Logs"


$Adobe64uninstaller = "Creative Cloud Uninstaller (x64).exe"
$Adobe32uninstaller = "Creative Cloud Uninstaller (x86).exe"
$AdobeAdminUninstaller = "AdobeUninstaller.exe" # https://helpx.adobe.com/enterprise/using/uninstall-creative-cloud-products.html#uninstall-tool
$AdobeGenuineCleaner = "AdobeGenuineCleaner.exe" # https://helpx.adobe.com/enterprise/using/uninstall-creative-cloud-products.html#uninstall-tool

$LogPath = "$LogRoot\Adobe_FullClean_Uninstall_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

$AdobeFolderLocations = @(
    'C:\ProgramData',
    'C:\Program Files',
    'C:\Program Files (x86)',
    'C:\Program Files\Common Files',
    'C:\Program Files (x86)\Common Files',
    "$env:USERPROFILE\AppData\Local",
    "$env:USERPROFILE\AppData\LocalLow",
    "$env:USERPROFILE\AppData\Roaming"
)

## Functions

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

Function Stop-AdobeProcesses {
    Write-Log "Stopping Adobe processes..."
    
    $adobeProcesses = @(
        "Creative Cloud", "CCXProcess", "CCLibrary", "AdobeIPCBroker",
        "Adobe Desktop Service", "AdobeUpdateService", "armsvc",
        "Photoshop", "Illustrator", "InDesign", "AfterFX", "Premiere Pro",
        "AdobeARM", "AdobeCollabSync", "AdobeNotificationClient", "Acrobat"
    )
    
    foreach ($processName in $adobeProcesses) {
        try {
            $processes = Get-Process -Name "*$processName*" -ErrorAction SilentlyContinue
            if ($processes) {
                Write-Log "Stopping process: $processName"
                $processes | Stop-Process -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
            }
        } catch {
            Write-Log "Failed to stop $processName - Error: $($_.Exception.Message)" "WARNING"
        }
    }
}

Function Remove-App-CIM([string]$appName) {
    Write-Log "Now starting: $($MyInvocation.MyCommand.Name)"
    Write-Log "Target app: $appName"
    
    try {
        # Single query with error handling
        $appsToRemove = Get-CimInstance -ClassName Win32_Product -ErrorAction Stop | 
            Where-Object { $_.Name -like "*$appName*" }
        
        if ($appsToRemove) {
            Write-Log "Found $($appsToRemove.Count) application(s) matching '$appName'"
            
            foreach ($app in $appsToRemove) {
                Write-Log "Attempting to uninstall: $($app.Name)"
                try {
                    $result = Invoke-CimMethod -InputObject $app -MethodName Uninstall -ErrorAction Stop
                    
                    # Check the return value (0 = success)
                    if ($result.ReturnValue -eq 0) {
                        Write-Log "Successfully uninstalled: $($app.Name)" "SUCCESS"
                    } else {
                        Write-Log "Uninstall returned error code $($result.ReturnValue) for: $($app.Name)" "ERROR"
                    }
                } catch {
                    Write-Log "Failed to uninstall $($app.Name): $($_.Exception.Message)" "ERROR"
                }
            }
        } else {
            Write-Log "$appName applications not found via CIM query"
        }
    } catch {
        Write-Log "Failed to query installed applications: $($_.Exception.Message)" "ERROR"
        return $false
    }
    
    return $true
}

Function Remove-FolderWithRetry([string]$Path, [int]$MaxRetries = 3) {
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            if (Test-Path $Path) {
                Remove-Item $Path -Recurse -Force -ErrorAction Stop
                Write-Log "Successfully removed $Path on attempt $i" "SUCCESS"
                return $true
            } else {
                Write-Log "Path no longer exists: $Path"
                return $true
            }
        } catch {
            Write-Log "Attempt $i failed for $Path - Error: $($_.Exception.Message)" "WARNING"
            if ($i -lt $MaxRetries) {
                Write-Log "Waiting before retry..." "INFO"
                Start-Sleep -Seconds ($i * 2)  # Exponential backoff
            }
        }
    }
    
    Write-Log "Failed to remove $Path after $MaxRetries attempts" "ERROR"
    return $false
}

## Main Script

Write-Log "===== Adobe Clean Uninstall Script Started ====="

# Stop Adobe processes first
Stop-AdobeProcesses

# Uninstallers
Write-Log "===== Running Adobe Uninstallers ====="

# Interactive uninstallers (Creative Cloud)
$uninstallers = @($Adobe64uninstaller, $Adobe32uninstaller)
foreach ($uninstaller in $uninstallers) {
    $fullPath = Join-Path $PSScriptRoot $uninstaller
    if (Test-Path $fullPath) {
        Write-Log "Running $uninstaller"
        Write-Log "Click Uninstall in popup window. If no Adobe apps are found, it will complete with errors." "WARNING"
        try {
            Start-Process -FilePath $fullPath -Wait -ErrorAction Stop
            Write-Log "Completed running $uninstaller" "SUCCESS"
        } catch {
            Write-Log "Failed to run $uninstaller : $($_.Exception.Message)" "ERROR"
        }
    } else {
        Write-Log "Uninstaller not found: $fullPath" "WARNING"
    }

    Start-Sleep 5
}

# Commandline adobe admin uninstaller
$fullPath = Join-Path $PSScriptRoot $AdobeAdminUninstaller
if (Test-Path $fullPath) {
    Write-Log "Running $AdobeAdminUninstaller with --all parameter"
    try {
        Start-Process -FilePath $fullPath -ArgumentList "--all" -Wait -ErrorAction Stop
        Write-Log "Completed running $AdobeAdminUninstaller" "SUCCESS"
    } catch {
        Write-Log "Failed to run $AdobeAdminUninstaller : $($_.Exception.Message)" "ERROR"
    }
} else {
    Write-Log "Admin uninstaller not found: $fullPath" "WARNING"
}
Start-Sleep 5

# Adobe Genuine Service (AGS) uninstaller
$fullPath = Join-Path $PSScriptRoot $AdobeGenuineCleaner
if (Test-Path $fullPath) {
    Write-Log "Running $AdobeGenuineCleaner with --uninstalluserdriven parameter"
    try {
        Start-Process -FilePath $fullPath -ArgumentList "--uninstalluserdriven" -Wait -ErrorAction Stop
        Write-Log "Completed running $AdobeGenuineCleaner" "SUCCESS"
    } catch {
        Write-Log "Failed to run $AdobeGenuineCleaner : $($_.Exception.Message)" "ERROR"
    }
} else {
    Write-Log "Genuine cleaner not found: $fullPath" "WARNING"
}
Start-Sleep 5

Write-Log "===== Running CIM Application Removal ====="
# Search and destroy Logic
Remove-App-CIM "Adobe"
Remove-App-CIM "Acrobat"

Write-Log "===== Cleaning Residual Adobe Folders ====="
# Stop processes again before folder cleanup
Stop-AdobeProcesses
Start-Sleep 5

$failedRemovals = @()

ForEach ($directory in $AdobeFolderLocations) {
    $TargetPath = "$directory\Adobe"
    
    if (Test-Path $TargetPath) {
        Write-Log "Target path found: $TargetPath" "WARNING"
        $success = Remove-FolderWithRetry $TargetPath
        if (-not $success) {
            $failedRemovals += $TargetPath
        }
    } else {
        Write-Log "Target path NOT found: $TargetPath"
    }
}

# Report on failed removals
if ($failedRemovals.Count -gt 0) {
    Write-Log "===== CLEANUP SUMMARY ====="
    Write-Log "The following folders could not be removed:" "ERROR"
    foreach ($folder in $failedRemovals) {
        Write-Log "  - $folder" "ERROR"
    }
    Write-Log "Manual cleanup may be required after reboot" "WARNING"
} else {
    Write-Log "All Adobe folders successfully removed" "SUCCESS"
}

Write-Log "===== Adobe Clean Uninstall Script Completed ====="
Write-Log "Log file saved to: $LogPath"

# Optional: Prompt for reboot
Write-Host "Adobe uninstall completed. Reboot recommended. Reboot now?"
$reboot = Read-Host "(Y/N)"
if ($reboot -eq 'Y' -or $reboot -eq 'y') {
    Write-Log "Initiating system reboot..."
    Restart-Computer -Force
}