
<#

.SYNOPSIS
    Pull the latest commit from your target repo, and run a powershell script within, even passing parameters to that powershell script.

.DESCRIPTION
    This template...
        - can be used to pull the latest commit from your target repo, and run a powershell script within, even passing parameters to that powershell script.
        - was intended to be used as the primary component in this project: https://github.com/Santa-Cruz-COE/PowerDeploy and interacts with the scripts within
        - can be ran as-is, or set up to be ran independently by removing the parameters.
        - will not be updated much so safe to keep and run. If used as a part of the github repo above, it can update itself.

    Why is it just a "template?"
        - This script is used for different repos and different scripts within those repos.
        - This script is used as a template for generating custom scripts from the various scripts within this repo
        - Using with tools like InTune, Datto, Crowdstrike... etc that don't have direct GitHub integration may need to have a script uploaded
            - These tools may not play nice or at all with the script natively, and you may need to modify this script to accept the needed variables in a specific way, such as by environment variables, config files, or directly written to the script

    Can this script be ran as it?
        - Yes absolutely! It can be ran with params to do whatever you want!

    For a full walkthrough of how to use this script, please see the README.md in the root of this repo.

.PARAMETER RepoNickName
    Name to call the repo, for logging/local file path ($LocalRepoPath = "$WorkingDirectory\Git_Repos\$RepoNickName")
    EXAMPLE
        Win-PowerDeploy

.PARAMETER RepoUrl
    Link to the target repo
    EXAMPLE
        https://github.com/Santa-Cruz-COE/PowerDeploy.git

.PARAMETER UpdateLocalRepoOnly
    If $true, forces script to exit early right after it finishes pulling the latest commit.
    NOTE: There is no need to inlcude "ScriptPath" args if this is $true

.PARAMETER ScriptPath
    Path from repo root to the target script
    EXAMPLE
        Uninstallers\General_Uninstaller.ps1

.PARAMETER forcemachinecontext
    This isn't used yet 

.PARAMETER WorkingDirectory
    Path to directory on the host machine that will be used to hold the repo and logs
    NOTE: Recommended path "C:\ProgramData\YourCompanyName"  - Useful because user does not have visibility to this unless they enable it
    NOTE: The directory will be created if it does not already exist
    NOTE: A seperate WorkingDirectory path will need to be provided in the params passed to the target script
    EXAMPLE
        C:\ProgramData\PowerDeploy



.PARAMETER ScriptParams
    Params to pass to the target script
    NOTE: You will need to check the target script's description to see what params are needed
    NOTE: Enclose in single brackets
    EXAMPLE 
        for General_Uninstaller.ps1: 
            '-AppName "7-zip" -UninstallType "All" -WorkingDirectory "C:\ProgramData\PowerDeploy"'


.PARAMETER ScriptParamsBase64
    You can also pass base64 encoded params for better Intune compatibility using the ScriptParamsBase64 parameter. 
    This parameter is automatically decoded into a parameter string for the target script.
    How do you use this parameter? The Generate_Custom-Script_FromTemplate.ps1 will do it for you automatically! See that script for further instuctions.

.EXAMPLE
    .\Git-Runner_TEMPLATE.ps1 -RepoNickName "Win-PowerDeploy" -RepoURL "https://github.com/Santa-Cruz-COE/PowerDeploy.git" -ScriptPath "Uninstallers\General_Uninstaller.ps1" -WorkingDirectory "C:\ProgramData\PowerDeploy" -ScriptParams '-AppName "7-zip" -UninstallType "All" -WorkingDirectory "C:\ProgramData\PowerDeploy"'
    
    Template: .\Git-Runner_TEMPLATE.ps1 -RepoNickName "" -RepoURL "" -ScriptPath "" -WorkingDirectory "" -ScriptParams ""


.NOTES
    TODO:
        - Maybe add a timeout feature for the script?

    SOURCE:
        https://github.com/Santa-Cruz-COE/PowerDeploy


                

#>


param(
    [Parameter(Mandatory=$true)]
    [string]$RepoNickName, # Name to call the local repo directory. Recommended name: REPO_(name of repo)

    [Parameter(Mandatory=$true)]
    [string]$RepoUrl,

    [string]$RepoToken=$null, # Optional token for private repos. Not fully tested yet.

    [string]$RepoBranch="main", # Optional branch name. Default: main
    
    [boolean]$UpdateLocalRepoOnly, # If true, script exits early after just updating

    [string]$ScriptPath, # Path from repo root to the target script

    [Parameter(Mandatory=$true)]
    [string]$WorkingDirectory, # Recommended param: "C:\ProgramData\PowerDeploy"

    [Parameter(Mandatory=$false)]
    [string]$ScriptParamsBase64, # Base64 encoded params for better Intune compatibility,
    
    [Parameter(ValueFromRemainingArguments=$true)]
    $ScriptParams # Params to pass to the target script. Example for General_Uninstaller.ps1: -ScriptParams '-AppName "7-zip" -UninstallType "All" -WorkingDirectory "C:\ProgramData\COMPANY_NAME\Logs"'

)

####################
## base64 Decoder ##
####################

# Handle base64 encoded parameters if provided (for Intune compatibility)
if ($ScriptParamsBase64 -and -not $ScriptParams) {
    try {
        Write-Host "Decoding base64 parameters..."
        $decodedJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ScriptParamsBase64))
        $paramsHash = $decodedJson | ConvertFrom-Json
        
        # Convert to parameter string
        $paramArray = @()
        foreach ($key in $paramsHash.PSObject.Properties.Name) {
            $value = $paramsHash.$key
            if ($value -is [string]) {
                $paramArray += "-$key `"$value`""
            } else {
                $paramArray += "-$key $value"
            }
        }
        $ScriptParams = $paramArray -join ' '
        
        Write-Host "Decoded parameters: $ScriptParams"
    } catch {
        Write-Host "ERROR: Failed to decode base64 parameters: $_" -ForegroundColor Red
        Exit 1
    }
}


##########
## Vars ##
##########

# Uncomment this part if you don't want to use params
# $RepoNickName = zz
# $RepoUrl = zz
# $UpdateLocalRepoOnly = zz
# $ScriptPath = zz
# $WorkingDirectory = zz
# $ScriptParams = zz

#$LocalRepoPath = "$WorkingDirectory\Git_Repos\$RepoNickName"
$LocalRepoPath = "$WorkingDirectory\$RepoNickName"
$LogRoot = "$WorkingDirectory\Logs\Git_Logs"
#$LogPath = "$LogRoot\$RepoNickName._Git_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ThisFileName = $MyInvocation.MyCommand.Name


# Evaluate vars based on whether this run is just an update only
if(!($UpdateLocalRepoOnly -eq $true)) {
    
    $UpdateLocalRepoOnly = $False
    $LogPath = "$LogRoot\$RepoNickName._Git_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"


} else {

    $LogPath = "$LogRoot\Update_Local_Repo_Only._Git_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"


}

# Security Manager script path
$SecurityManagerScriptPath = "$WorkingDirectory\$RepoNickName\Other_Tools\Security_Manager.ps1"

# Registry change script path
$RegistryChangeScriptPath = "$WorkingDirectory\$RepoNickName\Configurators\Configure-Registry.ps1"


# Insert token into RepoUrl if provided. NOT TESTED YET!
# git clone https://oauth2:oauth-key-goes-here@github.com/username/repo.git
if ($RepoToken -ne "") {
    # Insert token into URL for authentication
    $RepoUrl = $RepoUrl -replace 'https://', "https://oauth2:$RepoToken@"
}
###############
## Functions ##
###############


function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    if ($Level -eq "INFO2") {
        $logEntry = "[$timestamp] [INFO] $Message"
    } else {
        $logEntry = "[$timestamp] [$Level] $Message"
    }

    
    
    switch ($Level) {
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "DRYRUN"  { Write-Host $logEntry -ForegroundColor Cyan }
        "INFO"    { Write-Host $logEntry -ForegroundColor Cyan }
        "INFO2"    { Write-Host $logEntry }

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

function CheckAndInstall-Git {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Log "Git not found. Installing via Invoke-WebRequest..." "WARNING"
        
        try {

            # Get latest release info from GitHub API
            $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/git-for-windows/git/releases/latest"
            $asset = $latestRelease.assets | Where-Object { $_.name -like "*64-bit.exe" } | Select-Object -First 1
            $downloadUrl = $asset.browser_download_url
            $installerPath = "$WorkingDirectory\TEMP\git-installer.exe"

            if (!(Test-path "$WorkingDirectory\TEMP")){
                Write-Log "Creating directory: $WorkingDirectory\TEMP"
                New-Item -Path "$WorkingDirectory\TEMP" -ItemType "Directory" -Force
            }
            
            Write-Log "Downloading latest Git version: $($latestRelease.tag_name)" -ForegroundColor Green
            Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath -UseBasicParsing
            
            Write-Log "Installing Git..." -ForegroundColor Green
            Start-Process -FilePath $installerPath -ArgumentList "/VERYSILENT", "/NORESTART" -Wait
            
            Write-Log "Attempting to do cleanup..."
            if(test-path ($installerPath)){
                Remove-Item $installerPath -Force
                Write-Log "Removed git installer file at: $installerPath"

            
            } else {
                Write-Log "Could not find git installer file at: ($installerPath). The script will not attempt to delete anything." "WARNING"
            }
            
            # Refresh environment variables
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            
            # Final test
            if ((Get-Command git -ErrorAction SilentlyContinue)){

                Write-Log "Git installation complete!"

            } else {

                Write-Log "Git is not working. Please investigate." "ERROR"
                Exit 1

            }


            #$Result = & $winget install --id Git.Git -e --source winget --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 #| Out-String
            # ForEach ($line in $result) { Write-Log "WINGET: $line" } 

            
            # if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

            # Write-Log "Git installed successfully!" "SUCCESS"
        }
        catch {
            Write-Log "SCRIPT: $ThisFileName | END | ERROR: Failed to install Git: $_" "ERROR"
            exit 1
        }
    }
    else {
        Write-Log "Git is already installed."
    }
}

Function Set-GitSafeDirectory {

    Write-Log "Configuring Git safe directory for: $LocalRepoPath"
    try {
        # Check if the directory is already in safe.directory list
        $safeDirectories = git config --global --get-all safe.directory 2>&1
        ForEach ($line in $safeDirectories) { Write-Log "GIT: $line" } #; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $ThisFileName | END | Failed" "ERROR"; Exit 1 }
        $normalizedRepoPath = $LocalRepoPath -replace '\\', '/'

        
        if ($safeDirectories -notcontains $LocalRepoPath -and $safeDirectories -notcontains $normalizedRepoPath) {
            Write-Log "Adding $LocalRepoPath to Git safe directories..."

            #git config --global --add safe.directory $normalizedRepoPath

            $GitOutput = git config --global --add safe.directory $normalizedRepoPath 2>&1
            ForEach ($line in $GitOutput) { Write-Log "GIT: $line" } #; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $ThisFileName | END | Failed" "ERROR"; Exit 1 }


            Write-Log "Successfully added to safe directories" "SUCCESS"


        } else {
            Write-Log "Repository already in safe directories"
        }
    } catch {
        Write-Log "Note: Could not configure safe directory (non-critical): $_" "WARNING"
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

if ($UpdateLocalRepoOnly -eq $True){

    $pathsToValidate = @{
        'WorkingDirectory' = $WorkingDirectory
        'LogRoot' = $LogRoot
        'LogPath' = $LogPath
        'LocalRepoPath' = $LocalRepoPath
        'SecurityManagerScriptPath' = $SecurityManagerScriptPath
    }

} else {

    $pathsToValidate = @{
        'WorkingDirectory' = $WorkingDirectory
        'LogRoot' = $LogRoot
        'LogPath' = $LogPath
        'ScriptPath' = $ScriptPath
        'LocalRepoPath' = $LocalRepoPath
        'SecurityManagerScriptPath' = $SecurityManagerScriptPath
    }

}
Test-PathSyntaxValidity -Paths $pathsToValidate -ExitOnError
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"



#####################
## Begin main body ##
#####################

Write-Log "+++++ Git Runner +++++"

Write-Log "RepoNickName: $RepoNickName"
Write-Log "RepoUrl: $RepoUrl"
Write-Log "RepoToken: $RepoToken"
Write-Log "RepoBranch: $RepoBranch"
Write-Log "ScriptPath: $ScriptPath"
Write-Log "WorkingDirectory: $WorkingDirectory"
Write-Log "ScriptParams: $ScriptParams"
Write-Log "UpdateLocalRepoOnly: $UpdateLocalRepoOnly"
Write-Log "++++++++++++++++++++++"

##
# Check if git is installed
Write-Log "Checking if Git is installed..."
CheckAndInstall-Git

# Add safe directory configuration
Set-GitSafeDirectory 

$DoClone = $False
Write-Log "Now checking if local repo exists..."
# Clone or update repository
if(Test-Path $LocalRepoPath){

    Write-Log "Local repository exists."
    Push-Location $LocalRepoPath

    if (!(Test-Path "$LocalRepoPath\.git"))
    {

        Write-Log "No .git folder. Attempting to add." "WARNING"


        # foreach ($line in $gitOutput) {
        #     Write-Log "GIT: $line"
        # }

        $gitOutput = git init -b main 2>&1
        ForEach ($line in $gitOutput) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $ThisFileName | END | Failed" "ERROR"; Exit 1 }
        
        $gitOutput = git remote add origin $RepoUrl 2>&1 
        ForEach ($line in $gitOutput) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $ThisFileName | END | Failed" "ERROR"; Exit 1 }
        
        $gitOutput = git fetch origin 2>&1
        ForEach ($line in $gitOutput) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $ThisFileName | END | Failed" "ERROR"; Exit 1 }
        
        $gitOutput = git reset --hard origin/main 2>&1
        ForEach ($line in $gitOutput) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $ThisFileName | END | Failed" "ERROR"; Exit 1 }
        
        $gitOutput = git branch --set-upstream-to=origin/main main 2>&1
        ForEach ($line in $gitOutput) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $ThisFileName | END | Failed" "ERROR"; Exit 1 }
    
       
        if (Test-Path "$LocalRepoPath\.git"){

            Write-Log ".git folder added" "SUCCESS"

        } else {
            Write-Log "++++++++++++++++++++++"
            Write-Log "SCRIPT: $ThisFileName | END | Could not add .git folder" "ERROR"
            Exit 1
        }

    }
   
    Write-Log "Pulling latest changes..."
    try {
        $gitOutput = git pull 2>&1 # TODO: Need to add timeout and backup plan! Sometimes it gets frozen here. Maybe add functionality to just do a manual download.
        foreach ($line in $gitOutput) {
            Write-Log "GIT: $line"
        }
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "++++++++++++++++++++++"
            Write-Log "SCRIPT: $ThisFileName | END | Failed at: git pull." "ERROR"
            Exit 1            
        } else {
            Write-Log "Successfully pulled latest changes" "SUCCESS"
        }
    }
    finally {
        Pop-Location
    }
} else {
    $DoClone = $True
}

if ($DoClone -eq $true){

    Write-Log "No local repo yet. Cloning repository..."
    $gitOutput = git clone $RepoUrl $LocalRepoPath 2>&1
    foreach ($line in $gitOutput) {
        Write-Log "GIT: $line"
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Log "SCRIPT: $ThisFileName | END | Failed to clone repository" "ERROR"
        exit 1
    } else {
        Write-Log "Successfully cloned repository" "SUCCESS"
    }
    
    #Exit 1
}
##

# Switch branch if needed
if ($RepoBranch -ne "main") {
    Write-Log "Switching to branch: $RepoBranch"
    Push-Location $LocalRepoPath
    try {

        # $gitOutput = git checkout $RepoBranch 2>&1

        Write-Log "RUNNING GIT: git switch $RepoBranch"
        $gitOutput = git switch $RepoBranch 2>&1
        foreach ($line in $gitOutput) {
            Write-Log "GIT: $line"
        }
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "++++++++++++++++++++++"
            Write-Log "SCRIPT: $ThisFileName | END | Failed at: ""git switch $RepoBranch"" $RepoBranch." "ERROR"
            Exit 1            
        }

        Write-Log "RUNNING GIT: git reset --hard HEAD"
        $gitOutput = git reset --hard HEAD 2>&1
        foreach ($line in $gitOutput) {
            Write-Log "GIT: $line"
        }
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "++++++++++++++++++++++"
            Write-Log "SCRIPT: $ThisFileName | END | Failed at: ""git reset --hard HEAD"" $RepoBranch." "ERROR"
            Exit 1            
        }

        Write-Log "RUNNING GIT: git pull"
        $gitOutput = git pull 2>&1
        foreach ($line in $gitOutput) {
            Write-Log "GIT: $line"
        }
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "++++++++++++++++++++++"
            Write-Log "SCRIPT: $ThisFileName | END | Failed at: ""git pull"" $RepoBranch." "ERROR"
            Exit 1            
        } else {
            Write-Log "Successfully switched to branch: $RepoBranch" "SUCCESS"
        }

    }
    finally {
        Pop-Location
    }
}

# Create the temp directory if it doesn't exist
if (!(Test-Path "$WorkingDirectory\TEMP")){
    Write-Log "Creating directory: $WorkingDirectory\TEMP"
    New-Item -Path "$WorkingDirectory\TEMP" -ItemType "Directory" -Force
}

# Create the working registry path if it doesn't exist
try{

    Write-Log "Ensuring working registry path exists: HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy"

    & $RegistryChangeScriptPath -WorkingDirectory $WorkingDirectory -KeyOnly $true -KeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy" -Function "Modify"
    if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

} catch {

    Write-Log "Failed to ensure working registry path exists: $_" "ERROR"
    Exit 1

}

# Run the Security Manager to ensure strict ACLs on key folders
try{

    Write-Log "Running Security Manager to ensure strict ACLs on key folders..."
    & $SecurityManagerScriptPath
    if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

} catch {

    Write-Log "Failed to run Security Manager: $_" "ERROR"
    Exit 1

}


# Exit script if this was update only
if($UpdateLocalRepoOnly -eq $true) {

    Write-Log "++++++++++++++++++++++"
    Write-Log "SCRIPT: $ThisFileName | END | Repo: $RepoNickName | Update local repo only completed." "SUCCESS"
    Exit 0

}


# Build full script path
$FullScriptPath = Join-Path $LocalRepoPath $ScriptPath

# Check if script exists
if (-not (Test-Path $FullScriptPath)) {
    Write-Log "SCRIPT: $ThisFileName | END | Script not found: $FullScriptPath" "ERROR"
    Exit 1
}

# Run the script with parameters
Write-Log "Running script: $ScriptPath"
Write-Log "With parameters: $ScriptParams"
$RunFail = $False
try {
    if ($ScriptParams) {
        $command = "& `"$FullScriptPath`" $ScriptParams"
        Invoke-Expression $command
    }
    else {
        & $FullScriptPath
    }

    if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

}
catch {
    $RunFail = $True
    Write-Log "SCRIPT: $ThisFileName | | ERROR: Script execution failed: $_" "ERROR"
}

# Run the Security Manager to ensure strict ACLs on key folders # TODO: This may be overkill, may remove in the future.
try{

    Write-Log "Re-running Security Manager to ensure strict ACLs on key folders after script execution..."
    #Write-Log "Running Security Manager to ensure strict ACLs on key folders..."
    & $SecurityManagerScriptPath
    if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

} catch {

    Write-Log "Failed to run Security Manager: $_" "ERROR"
    Exit 1

}

if ($RunFail -eq $False){

    Write-Log "++++++++++++++++++++++"
    Write-Log "SCRIPT: $ThisFileName | END | Repo: $RepoNickName | Script: $ScriptPath | Execution completed." "SUCCESS"
    Exit 0

} else {

    Write-Log "SCRIPT: $ThisFileName | END | Script failed: $FullScriptPath." "ERROR"
    Exit 1

}
