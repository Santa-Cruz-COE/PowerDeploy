# General Remediation Script Suite - Registry
# This script can do both detection and remediation



Param(

    # $RegistryChanges = '`
    # -KeyPath "" -ValueName "" -Value "" -ValueType "",`
    # -KeyPath "" -ValueName "" -Value "" -ValueType "",`
    # -KeyPath "" -ValueName "" -Value "" -ValueType ""',

    $RegistryChanges,
    $WorkingDirectory,
    $RepoNickName,
    $AlsoLockDown = $False,
    [ValidateSet("Detect", "Remediate")]
    [String]$function

)

# $WorkingDirectory = "C:\ProgramData\PowerDeploy",
# $RepoNickName = "PowerDeploy-Repo"

if ($WorkingDirectory -eq "" -or $WorkingDirectory -eq $null -or $RepoNickName -eq "" -or $RepoNickName -eq $null){

    $LocalRepoPath = Split-Path -Path $PSScriptRoot -Parent
    $WorkingDirectory = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

} else {

    $LocalRepoPath = "$WorkingDirectory\$RepoNickName"

}




$LogRoot = "$WorkingDirectory\Logs\Detection_Logs"
$LogPath = "$LogRoot\General_Remediation_.$function._Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ThisFileName = $MyInvocation.MyCommand.Name

$RegEditScriptPath = "$LocalRepoPath\Configurators\Configure-Registry.ps1"


# if(    $RegistryChanges -eq '`
#     -KeyPath "" -ValueName "" -Value "" -ValueType "",`
#     -KeyPath "" -ValueName "" -Value "" -ValueType "",`
#     -KeyPath "" -ValueName "" -Value "" -ValueType ""') {$RegistryChanges = ""}


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

Function CheckReg {

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: CheckReg | START | Attemping to call reg read script"
    Write-Log ""

    if ($Value -eq "" -or $Value -eq $null){

        $EndValue = & $RegEditScriptPath -KeyPath $KeyPath -ValueName $ValueName -ValueType $ValueType -WorkingDirectory $WorkingDirectory -Function "Read"

    } else {

        $EndValue = & $RegEditScriptPath -KeyPath $KeyPath -ValueName $ValueName -ValueType $ValueType -WorkingDirectory $WorkingDirectory -Function "Read"

    }

    Write-Log "SCRIPT: $ThisFileName | Value read from registry: $EndValue"
    Write-Log "SCRIPT: $ThisFileName | Target Value to match: $Value"

    if($EndValue -eq $Value){

        Write-Log "SCRIPT: $ThisFileName | Registry values match for: $line" "SUCCESS"
        # Exit 0

    } elseif(($EndValue -eq "KeyPath exists, but could not read value" -or $EndValue -eq "KeyPath does not exist")) {

        Write-Log "SCRIPT: $ThisFileName | END | Could not read target registry value: $EndValue" "WARNING"
        Exit 1

    } else {

        Write-Log "SCRIPT: $ThisFileName | END | Local Registry Values do not match to $Line!" "WARNING"
        Exit 1

    }
    Write-Log ""
    Write-Log "SCRIPT: $ThisFileName | FUNCTION: CheckReg | END"

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

    }

Test-PathSyntaxValidity -Paths $pathsToValidate -ExitOnError

Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Checking the user contexts..."
Try{
    $scriptUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Script User: $scriptUser"

    $loggedInUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName
    Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Windows User: $loggedInUser"

    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Is Script User admin? $isAdmin"

} Catch {
    Write-Error "Could not collect user context info. Error: $_"
    Exit 1
}

# Format string into array for reg
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Formatting input string into an array. If this fails the RegistryChanges param was likely not formatted correctly."
Try{ 

    Write-host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Current value of RegistryChanges:"
    Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX $RegistryChanges"

    # Split on commas that are NOT inside quotes
    #Write-Log "Split on commas that are NOT inside quotes"
    # $TotalRegistryChangesArray = [regex]::Split(
    #     $RegistryChanges,
    #     ',(?=(?:[^"]*"[^"]*")*[^"]*$)'
    # ) | Where-Object { $_.Trim() }

    Write-host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Split on commas that are NOT inside brackets"
    $TotalRegistryChangesArray = $RegistryChanges -split '(?<=\])\s*,\s*(?=\[)'

    Write-host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Current value of TotalRegistryChangesArray:"
    write-host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX $TotalRegistryChangesArray"


    # Take out the brackets
    Write-host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Taking out the brackets..."
    # Foreach ($line in $TotalRegistryChangesArray){
    #     $Line
    #     $line = $line -replace "[\[\]]", ""
    #     $line
    # }

    #$TotalRegistryChangesArray -replace "[\[\]]", ""

    # for ($i = 0; $i -lt $TotalRegistryChangesArray.Length; $i++) {
    # $TotalRegistryChangesArray[$i] = $TotalRegistryChangesArray[$i] -replace "[\[\]]", ""

    # Create a new array without brackets
    $cleaned = $TotalRegistryChangesArray | ForEach-Object {
        $_ -replace "[\[\]]", ""
    }

    $TotalRegistryChangesArray = $cleaned

    Write-host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Current value of TotalRegistryChangesArray:"
    Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX $TotalRegistryChangesArray"


} catch {

    Write-Error "Could not format registry change string into array: $_"
    Exit 1
}


Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
Write-Log ""
Write-Log "===== SCRIPT: $ThisFileName | START ====="
Write-Log ""
Write-Log "Function: $Function"
Write-Log ""
Write-Log "Registry Changes:"
Write-Log ""
Foreach($line in $TotalRegistryChangesArray) {Write-Log "   $Line"; Write-Log ""}
Write-Log "========================================================"
Write-Log ""

# Registry changes

if ($RegistryChanges -ne "" -and $RegistryChanges -ne $null){

    Write-Log "SCRIPT: $ThisFileName | Registry changes requested. Beginning check work..."
    $counter = 1
    Foreach($line in $TotalRegistryChangesArray){

        Write-Log "SCRIPT: $ThisFileName | Processing line: $counter"

        # Build a key/value map from -Param "value" pairs (order doesn't matter)
        $pairs = @{}
        foreach ($m in [regex]::Matches($line, '-(?<k>KeyPath|ValueName|Value|ValueType)\s+"(?<v>(?:[^"]|"")*)"')) {
            $name = $m.Groups['k'].Value
            # Unescape doubled quotes inside values (e.g., "" -> ")
            $val  = $m.Groups['v'].Value -replace '""','"'
            $pairs[$name] = $val
        }

    
        [string]$KeyPath = $pairs['KeyPath']
        [string]$ValueName = $pairs['ValueName']
        [string]$Value   = $pairs['Value']
        [string]$ValueType = $pairs['ValueType']

        Write-Log ""


        Write-Log "Target values:"

        
        Write-Log "   KeyPath: $keypath"

        Write-log "   ValueName: $ValueName"

        Write-log "   Value: $Value"

        Write-Log "   ValueType: $ValueType"
        Write-Log ""



        if ($Function -eq "Detect"){

            Write-Log "SCRIPT: $ThisFileName | Now attempting to check the registry for these values..."

            CheckReg


        } elseif($Function -eq "Remediate") {

            Write-Log "SCRIPT: $ThisFileName | Now attempting to apply these values to the registry..."

            Try {

                # if ($Value -eq "" -or $Value -eq $null){

                #     $EndValue = & $RegEditScriptPath -KeyPath $KeyPath -ValueName $ValueName -ValueType $ValueType -Value $Value -WorkingDirectory $WorkingDirectory -Function 'Modify' -AlsoLockDown $AlsoLockDown -ValueNameOnly $True

                # } else {

                    $EndValue = & $RegEditScriptPath -KeyPath $KeyPath -ValueName $ValueName -ValueType $ValueType -Value $Value -WorkingDirectory $WorkingDirectory -Function 'Modify' -AlsoLockDown $AlsoLockDown

                # }

            } catch {


                Write-Log "SCRIPT: $ThisFileName | Failed to run the registry modification script. Error: $_" "ERROR"

                Write-Log "SCRIPT: $ThisFileName | Attempted command: $RegEditScriptPath -KeyPath $KeyPath -ValueName $ValueName -ValueType $ValueType -Value $Value -WorkingDirectory $WorkingDirectory -Function 'Modify' -AlsoLockDown $AlsoLockDown" "ERROR"

                Write-Log "SCRIPT: $ThisFileName | END | Failed to write these values to the registry: $line" "ERROR"


                Exit 1
            }

            Write-Log "SCRIPT: $ThisFileName | Now final checking..."

            CheckReg

            Write-Log "SCRIPT: $ThisFileName | Moving on the next line if there is one"

        }

        $counter++

        Write-Log ""

    }

    Write-Log "SCRIPT: $ThisFileName | END | All values confirmed exist!!!" "SUCCESS"
    Exit 0

}
