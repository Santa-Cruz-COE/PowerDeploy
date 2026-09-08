# Script for uninstalling a specified printer. Removesthe port as well.

Param(

    [Parameter(Mandatory=$true)]
    [String]$PrinterName,

    $RemoveDriver = $False, # Not implemented yet, may need in the future

    #[Parameter(Mandatory=$true)]
    [String]$WorkingDirectory="C:\ProgramData\PowerDeploy"

)

############
### Vars ###
############

# Log folder location. Recommend not to change.
$LogRoot = "$WorkingDirectory\Logs\Uninstaller_Logs"

$ThisFileName = $MyInvocation.MyCommand.Name
$LogPath = "$LogRoot\$ThisFileName.$PrinterName._$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$uninstallSuccess = $False

$RepoRoot = Split-Path -Path $PSScriptRoot -Parent

$DetectPrinterScript = "$RepoRoot\Templates\Detection-Script-Printer_TEMPLATE.ps1"


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

############
### MAIN ###
############

## Pre-Check
$ThisFileName = $MyInvocation.MyCommand.Name
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX PRE-CHECK for SCRIPT: $ThisFileName"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX NOTE: PRE-CHECK is not logged"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Checking if supplied paths are valid"
# Test the paths
$pathsToValidate = @{
    'WorkingDirectory' = $WorkingDirectory
    'LogRoot' = $LogRoot
    'LogPath' = $LogPath
    'RepoRoot' = $RepoRoot
}
Test-PathSyntaxValidity -Paths $pathsToValidate -ExitOnError
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

Write-Log "SCRIPT: $ThisFileName | START | TARGET PRINTER: $PrinterName"

# Detect if printer exists

Write-log "SCRIPT: $ThisFileName | Check #1 installed printer named: $PrinterName"


# Initial Detect
$Detect1 = & $DetectPrinterScript -PrinterName $PrinterName -WorkingDirectory $WorkingDirectory

if ($LASTEXITCODE -eq 0) {

    Write-Log "SCRIPT: $ThisFileName | Printer '$PrinterName' detected. Proceeding with uninstallation."

    # Try modern method
    if(get-command -name Remove-Printer -erroraction silentlyContinue){

        try {

            # Get the the port before deletion
            Write-Log "SCRIPT: $ThisFileName | Retrieving port name for printer '$PrinterName' before removal."
            $printer = Get-Printer -Name $PrinterName -ErrorAction Stop
            $portName = $printer.PortName
            Try { Get-PrinterPort -Name $portName -ErrorAction Stop; Write-Log "Verified port exists"; $PortExists = $True} Catch { Write-Log "Error verifying port existence." "WARNING" ; $PortExists = $False }

            Write-Log "SCRIPT: $ThisFileName | Retrieved port name '$portName' for printer '$PrinterName'."


            # Remove the printer
            Remove-Printer -Name $PrinterName -ErrorAction Stop
            Write-Log "SCRIPT: $ThisFileName | Successfully removed printer '$PrinterName' using Remove-Printer."
            
            If ($PortExists) {

                # Verify again if port exists after printer removal
                Try { 
                    
                    Get-PrinterPort -Name $portName -ErrorAction Stop; 
                    
                    Write-Log "Verified port exists after printer removal, this is unexpected behaviour. Will attempt to delete port." "WARNING" ; 
                    
                    $PortExists2 = $True
                
                } Catch { 
                    
                    Write-Log "Port existence could not be verified after printer removal. This is expected and preferred behaviour. No need to do further troubleshooting to delete port."; 
                    
                    $PortExists2 = $False 
                
                }

                # Attempt to remove associated port

                If ($PortExists2) {
                    Try {

                        Write-Log "SCRIPT: $ThisFileName | Now attempting to delete associated port '$portName'."

                        $port = Get-PrinterPort -Name $portName -ErrorAction Stop
                        Remove-PrinterPort -Name $portName -ErrorAction Stop
                        Write-Log "SCRIPT: $ThisFileName | Successfully removed port '$portName'."

                    } Catch {

                        Write-Log "SCRIPT: $ThisFileName | Failed to delete port associated with printer '$PrinterName': $_" "WARNING"
                        Throw $_

                    }
                }

            }

            
            $uninstallSuccess = $True

        } catch {

            Write-Log "SCRIPT: $ThisFileName | ERROR removing printer '$PrinterName' using Remove-Printer. Error: $_" "ERROR"
       
        }

    } 

} else {

    Write-Log "SCRIPT: $ThisFileName | Printer '$PrinterName' not detected." "WARNING"

}


# 2nd Detect

Write-log "SCRIPT: $ThisFileName | Check #2 for installed printer named: $PrinterName"

$Detect2 = & $DetectPrinterScript -PrinterName $PrinterName -WorkingDirectory $WorkingDirectory

if ($LASTEXITCODE -eq 0) {

    Write-Log "SCRIPT: $ThisFileName | Printer '$PrinterName' still detected. Proceeding with alternative uninstallation method."

    # Fallback to WMI method
    if (-not $uninstallSuccess) {

        try {

            $printer = Get-WmiObject -Class Win32_Printer -Filter "Name = '$PrinterName'"

            if ($printer) {

                $result = $printer.Delete()

                if ($result.ReturnValue -eq 0) {

                    Write-Log "SCRIPT: $ThisFileName | Successfully removed printer '$PrinterName' using WMI."


                    Try {

                        # Get and delete the port

                        Write-Log "SCRIPT: $ThisFileName | Now attempting to delete associated port '$($printer.PortName)'."

                        $port = Get-WmiObject -Query "SELECT * FROM Win32_TCPIPPrinterPort WHERE Name = '$($printer.PortName)'"
                        if ($port) {
                            $port.Delete()
                            Write-Log "Port '$($printer.PortName)' deleted."
                        }

                        $uninstallSuccess = $True

                    } Catch {

                        Write-Log "Failed to delete port '$($printer.PortName)': $_" "WARNING"
                        Write-Log "NOTE: This may be expected if the port was removed along with the printer." "WARNING"
                        Throw $_
                    }



                } else {

                    Write-Log "SCRIPT: $ThisFileName | ERROR removing printer '$PrinterName' using WMI. ReturnValue: $($result.ReturnValue)" "ERROR"
                
                }

            } else {

                Write-Log "SCRIPT: $ThisFileName | Printer '$PrinterName' found using Get-Printer but not found via WMI during uninstallation." "ERROR"
           
            }
        } catch {

            Write-Log "SCRIPT: $ThisFileName | ERROR removing printer '$PrinterName' using WMI. Error: $_" "ERROR"
        
        }
    }

} else {

    Write-Log "SCRIPT: $ThisFileName | Printer '$PrinterName' not detected." "WARNING"

}


# Final check

Write-log "SCRIPT: $ThisFileName | Final check for installed printer named: $PrinterName"

$Detect3 = & $DetectPrinterScript -PrinterName $PrinterName -WorkingDirectory $WorkingDirectory

if ($LASTEXITCODE -eq 0) {

    Write-Log "SCRIPT: $ThisFileName | Printer '$PrinterName' still detected after uninstallation attempts." "ERROR"
    $uninstallSuccess = $False

} else {

    Write-Log "SCRIPT: $ThisFileName | Printer '$PrinterName' no longer detected after uninstallation attempts." "SUCCESS"
    $uninstallSuccess = $True

}



# Return result
If ($uninstallSuccess){

    Write-Log "SCRIPT: $ThisFileName | END | Uninstallation of printer '$PrinterName' completed successfully." "SUCCESS"
    Exit 0

} else {

    Write-Log "SCRIPT: $ThisFileName | END | Uninstallation of printer '$PrinterName' failed." "ERROR"
    Exit 1

}

