# Download file using Azure Blob Storage

# TODO: Create workflow/infrastructure to access a locally accessible SAS key. Add as an optional function.

Param(

    [Parameter(Mandatory=$true)]
    [string]$WorkingDirectory, # Recommended param: "C:\ProgramData\COMPANY_NAME"

    [Parameter(Mandatory=$true)]
    [string]$BlobName,


    # Scenario A: Full URL supplied
    [string]$BlobSASurl,
    #[string]$BlobSAStoken,


    # Scenario B: Individual pieces of URL supplied
    [string]$StorageAccountName,
    [string]$ContainerName, # Include path! Ex: "applications\7-zip" if file you are targetting is "applications\7-zip\7zip.exe"
    [string]$SasToken # Config tested: Signing method: Account key - Signing Key: key 1 - permissions: read - Allowed Protocols: HTTPS only


)

############
### Vars ###
############

##

$TargetDirectory = "$WorkingDirectory\TEMP\Downloads"
$LocalDestinationPath = "$TargetDirectory\$BlobName"

##

$ThisFileName = $MyInvocation.MyCommand.Name
$LogRoot = "$WorkingDirectory\Logs\Download_Logs"
$LogPath = "$LogRoot\$ThisFileName._$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

$ProgressPreference = 'SilentlyContinue' # for faster web invoke downloads without progress bars

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
### Main ###
############

## Pre-Check
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX PRE-CHECK for SCRIPT: $ThisFileName"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX NOTE: PRE-CHECK is not logged"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Checking if supplied paths have valid syntax"

# Test the paths syntax
$pathsToValidate = @{
    'WorkingDirectory' = $WorkingDirectory
    'LogRoot' = $LogRoot
    'LogPath' = $LogPath
    'LocalDestinationPath' = $LocalDestinationPath
}
Test-PathSyntaxValidity -Paths $pathsToValidate -ExitOnError

# Test the paths existance
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Checking if supplied paths exist"
$pathsToTest = @{
    'WorkingDirectory' = $WorkingDirectory
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


Write-Log "===== Azure Blob Downloader (SAS Token Method) ====="
Write-Log "Working Directory: $WorkingDirectory"
Write-Log "BlobName: $BlobName"
Write-Log "--- Scenario A vars: ---"
Write-Log "BlobSASurl = $BlobSASurl"
Write-Log "BlobSAStoken = $BlobSAStoken"
Write-Log "--- Scenario B vars: ---"
Write-Log "StorageAccountName = $StorageAccountName"
Write-Log "ContainerName = $ContainerName"
Write-Log "SasToken = $SasToken"
Write-Log "===================================================="



## Determine if this is scenario A or B

Write-Log "Determining if Scenario A or B was invoked based on supplied variables..."
If($BlobSASurl -ne "" -and $BlobSASurl -ne $null){

    # Scenario A
    Write-Log "Scenario A: Full URL supplied"

    $BlobUri = $BlobSASurl



} elseif ($StorageAccountName -ne "" -and $StorageAccountName -ne $null -and $ContainerName -ne "" -and $ContainerName -ne $null -and $SasToken -ne "" -and $SasToken -ne $null){

    # Scenario B
    Write-Log "Scenario B: Individual pieces of URL supplied"

    $BlobUri = "https://$StorageAccountName.blob.core.windows.net/$ContainerName/$BlobName"+"?"+"$SasToken"


} else {

    # Failed
    Write-Log "Not enough information supplied. Please make sure that you supplied enough/correct data." "ERROR"
    exit 1

}

Write-Log "Target URL: $BlobUri"


## The Download

Try {



    # Ensure directory exists


    $ExtraFilePath = Split-Path $LocalDestinationPath -Parent
    $FinalFileName = Split-Path $LocalDestinationPath -Leaf

    if ($ExtraFilePath -ne "" -and $ExtraFilePath -ne $null){
        $FinalDirectory = $ExtraFilePath
    } else {
        $FinalDirectory = $TargetDirectory
    }

    Write-Log "Checking if target directory exists at: $FinalDirectory"
    if (!(Test-Path $FinalDirectory)) {
        Write-Log "Target directory not detected. Attempting to create."
        New-Item -ItemType Directory -Path $FinalDirectory -Force | Out-Null
        Write-Log "Target directory has been created."
    } else {
        Write-Log "Target directory already exists."
    }

    # Check if the file already exists
    Write-Log "Checking if the target file already exists at: $LocalDestinationPath"
    if ((Test-Path $LocalDestinationPath)) {
        Write-Log "File already exists at ($LocalDestinationPath). Will attempt to overwrite." "WARNING"
    }

    # Download the file
    Write-Log "Attempting to download the file ($BlobName) from URL ($BlobUri)"
    $Result =Invoke-WebRequest -Uri $BlobUri -OutFile $LocalDestinationPath -UseBasicParsing


    foreach ($Line in $Result) {Write-Log "Invoke-WebRequest: $Line"}

    # Ensure file exists
    Write-Log "Checking if file exists at expected location ($LocalDestinationPath)"
    if ((Test-Path $LocalDestinationPath)) {
        
        # Ensure the file is not empty
        Write-Log "File detected. Making sure it isn't empty..."
        $FileSize = Get-ChildItem -path $LocalDestinationPath -File | % {[int]($_.length)}

        # Wait a sec
        Start-Sleep 3

        if ($FileSize -eq 0 -or $FileSize -eq $null -or $FileSize -eq ""){

            # Error out
            Write-Log "===================================================="
            Write-Log "SCRIPT: $ThisFileName | END | File is empty. Download failed." "ERROR"

            Exit 1

        } else {

            # Return success
            Write-Log "===================================================="
            Write-Log "SCRIPT: $ThisFileName | END | File is not empty. Download of $BlobName successful!" "SUCCESS"
            
            Exit 0

        }

    }



} Catch {

    Write-Log "===================================================="
    Write-Log "SCRIPT: $ThisFileName | END | Script failed: $_" "ERROR"

    Exit 1
}

