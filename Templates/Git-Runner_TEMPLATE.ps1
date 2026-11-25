
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

.PARAMETER RequireOrgKeys
    Optional. 'Printers' or 'Applications'. Before Git is installed or the repo is cloned, checks that the organization
    registry values that kind of install needs are present (HKLM\SOFTWARE\PowerDeploy, 64-bit view). If any is missing,
    exits 1618 so Intune retries the install. Only value names are logged, never the values.
    Empty (default) = no check. Any other value exits 1.

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
    [string]$RepoUrl, # Will be ignored if dot source only or install git only is true. Link to the target repo. 

    [string]$RepoToken=$null, # Optional token for private repos. Not fully tested yet.

    [string]$RepoBranch="main", # Optional branch name. Default: main
    
    [boolean]$UpdateLocalRepoOnly, # If true, script exits early after just updating
    [boolean]$DotSourceOnly=$false, # If true, only dot sources the script without executing anything by exiting early
    [boolean]$InitOnly=$false, # If true, only initializes the local repo without pulling or running anything. Exits early.
    [boolean]$installGitOnly=$false, # If true, only checks for Git and installs it if not found, then exits early.

    [boolean]$StashChanges=$true, # If true, stashes any local changes before pulling latest commit

    [string]$ScriptPath, # Path from repo root to the target script

    [Parameter(Mandatory=$true)]
    [string]$WorkingDirectory, # Recommended param: "C:\ProgramData\PowerDeploy"

    [Parameter(Mandatory=$false)]
    [string]$ScriptParamsBase64, # Base64 encoded params for better Intune compatibility,
    
    [Parameter(Mandatory=$false)]
    [string]$RequireOrgKeys='', # Optional: 'Printers' or 'Applications'. Exit 1618 (Intune retry) if the org registry values that install needs are missing. Empty = no check.

    [Parameter(ValueFromRemainingArguments=$true)]
    $ScriptParams # Params to pass to the target script. Example for General_Uninstaller.ps1: -ScriptParams '-AppName "7-zip" -UninstallType "All" -WorkingDirectory "C:\ProgramData\COMPANY_NAME\Logs"'

)

####################
## base64 Decoder ##
####################

# Handle base64 encoded parameters if provided (for Intune compatibility)
# The base64 payload is authoritative. Generated custom scripts have this param() block
# stripped, so $ScriptParams is undeclared there and would otherwise resolve to a leftover
# session/global variable via dynamic scoping - never trust a pre-existing value.
if ($ScriptParamsBase64) {
    if ($ScriptParams) {
        Write-Host "WARNING: A pre-existing ScriptParams value was found and will be ignored. Using the ScriptParamsBase64 payload instead." -ForegroundColor Yellow
    }
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

# Git for Windows install (CheckAndInstall-Git). Every step that runs while the install mutex is held has a
# wall-clock limit, so one stuck run cannot hold the mutex for long. Any "Git cannot be installed right now"
# outcome (mutex wait, latest-release lookup, download, installer still running) exits 1618 so Intune retries
# the install. The latest release is always looked up at run time; no Git version is built in.
$GitInstallMutexName = "Global\PowerDeploy_GitInstall"
$GitInstallMutexWaitSec = 300      # Wait for another run's Git install before giving up (exit 1618)
$GitReleaseLookupTimeoutSec = 30   # Lookup of the latest release tag (whole request)
$GitLatestTagUrl = "https://gitforwindows.org/latest-tag.txt"   # Plain text: vX.Y.Z.windows.N
$GitReleaseDownloadBaseUrl = "https://github.com/git-for-windows/git/releases/download"   # + /<tag>/<installer file>
$GitDownloadTimeoutSec = 300       # Whole installer download (connect, headers and body)
$GitInstallerTimeoutSec = 600      # Git installer run; after this it is left running and the run exits 1618

# Ensure RepoUrl starts with https://
$RepoUrl = if ($RepoUrl -notlike "https://*") { "https://$RepoUrl" } else { $RepoUrl }

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

function Get-PDRunningGitInstaller {
    # Returns every running Git installer process on the device, from any path: any deploy mode's working
    # directory, since the install mutex is device-wide. git-installer.exe is the file Git-Runner downloads;
    # git-installer.tmp is the child process its Inno Setup installer starts (.NET drops only ".exe" from
    # process names, so the child is reported as "git-installer.tmp").
    param([string[]]$ProcessName = @('git-installer', 'git-installer.tmp'))

    return @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
}

function Invoke-PDHttpGet {
    # GET $Url and return the response body as a byte array, with a hard wall-clock limit on the whole
    # transfer. In Windows PowerShell 5.1, Invoke-WebRequest/Invoke-RestMethod -TimeoutSec do not bound the
    # whole body read (a chunked body that trickles or stalls ran far past the limit when tested), so
    # HttpClient is used: its Timeout covers the
    # full body read (default ResponseContentRead behavior). A generic User-Agent is always sent (some
    # servers reject requests without one). Throws on any failure, non-success HTTP status, or timeout.
    param(
        [string]$Url,
        [int]$TimeoutSec
    )

    Add-Type -AssemblyName System.Net.Http
    $client = New-Object System.Net.Http.HttpClient
    try {
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        $client.DefaultRequestHeaders.UserAgent.ParseAdd('PowerDeploy-GitRunner')
        $response = $client.GetAsync($Url).GetAwaiter().GetResult()
        try {
            if (-not $response.IsSuccessStatusCode) {
                throw "HTTP $([int]$response.StatusCode) $($response.ReasonPhrase)"
            }
            $bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        } finally {
            $response.Dispose()
        }
    } finally {
        $client.Dispose()
    }
    return ,$bytes
}

function Get-PDLatestGitInstaller {
    # Reads the latest Git for Windows release tag (plain text, "vX.Y.Z.windows.N") from $TagUrl within
    # $TimeoutSec for the whole request, and builds the 64-bit installer URL from it:
    #   vX.Y.Z.windows.1 -> <DownloadBaseUrl>/vX.Y.Z.windows.1/Git-X.Y.Z-64-bit.exe
    #   vX.Y.Z.windows.N -> <DownloadBaseUrl>/vX.Y.Z.windows.N/Git-X.Y.Z.N-64-bit.exe (N other than 1)
    # The tag goes into a URL, so it must match the pattern exactly: case-sensitive, ASCII digits only ([0-9];
    # .NET's \d would also accept other scripts' digits), nothing else.
    # Returns Tag and Url. Throws on any failure, timeout, or text that is not a release tag.
    param(
        [string]$TagUrl,
        [string]$DownloadBaseUrl,
        [int]$TimeoutSec
    )

    $bytes = Invoke-PDHttpGet -Url $TagUrl -TimeoutSec $TimeoutSec
    $text = [System.Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF).Trim()
    $tagMatch = [regex]::Match($text, '^v([0-9]+)\.([0-9]+)\.([0-9]+)\.windows\.([0-9]+)\z')
    if (-not $tagMatch.Success) {
        $shown = $text
        if ($shown.Length -gt 40) { $shown = $shown.Substring(0, 40) + '...' }
        $shown = $shown -replace '[^A-Za-z0-9 ._-]', '?'
        throw "The latest-tag text is not a Git for Windows release tag: '$shown'"
    }

    $version = '{0}.{1}.{2}' -f $tagMatch.Groups[1].Value, $tagMatch.Groups[2].Value, $tagMatch.Groups[3].Value
    $build = $tagMatch.Groups[4].Value
    if ($build -eq '1') { $fileName = "Git-$version-64-bit.exe" } else { $fileName = "Git-$version.$build-64-bit.exe" }

    return [pscustomobject]@{
        Tag = $text
        Url = "$($DownloadBaseUrl.TrimEnd('/'))/$text/$fileName"
    }
}

function Save-PDGitInstaller {
    # Downloads $Url to $OutFile within $TimeoutSec for the whole transfer (see Invoke-PDHttpGet).
    # The file is written only after the full body has arrived. Throws on any failure or timeout.
    param(
        [string]$Url,
        [string]$OutFile,
        [int]$TimeoutSec
    )

    $bytes = Invoke-PDHttpGet -Url $Url -TimeoutSec $TimeoutSec
    [System.IO.File]::WriteAllBytes($OutFile, $bytes)
}

function CheckAndInstall-Git {

    # Refresh PATH from the registry before checking — this process may have started before a
    # previous run installed Git and updated the system PATH, so without this refresh every run
    # would see "git not found" even though Git is already on disk.
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Log "Git not found. Acquiring mutex lock for installation..." "WARNING"

        $mutexName = $GitInstallMutexName
        $mutex = $null
        $hasHandle = $false

        # Every "exit" below still runs the finally block, which releases (only if held) and disposes the mutex.
        try {
            $mutex = New-Object System.Threading.Mutex($false, $mutexName)

            Write-Log "Waiting for mutex lock (timeout: $($GitInstallMutexWaitSec)s)..."
            try {
                $hasHandle = $mutex.WaitOne($GitInstallMutexWaitSec * 1000)
            }
            catch [System.Threading.AbandonedMutexException] {
                $hasHandle = $true
                Write-Log "Acquired abandoned mutex - previous process likely crashed." "WARNING"
            }

            if (-not $hasHandle) {
                Write-Log "Timed out after $($GitInstallMutexWaitSec)s waiting for another Git installation to finish." "WARNING"
                Write-Log "SCRIPT: $ThisFileName | END | Git is not available yet. Exiting with 1618 so Intune retries this install." "WARNING"
                exit 1618
            }

            Write-Log "Mutex acquired. Checking Git again..."

            # Re-check after acquiring — refresh PATH first so we don't miss a Git install that
            # another process completed while we were waiting for the mutex.
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

            if (Get-Command git -ErrorAction SilentlyContinue) {
                Write-Log "Git was installed by another process while waiting."
                return
            }

            # Get the latest release tag and build the installer URL. If that fails, exit 1618 so Intune retries.
            # A wrong installer URL shows up as a failed download below, which also exits 1618.
            $releaseTag = $null
            $downloadUrl = $null
            try {
                $latestInstaller = Get-PDLatestGitInstaller -TagUrl $GitLatestTagUrl -DownloadBaseUrl $GitReleaseDownloadBaseUrl -TimeoutSec $GitReleaseLookupTimeoutSec
                $downloadUrl = $latestInstaller.Url
                $releaseTag = $latestInstaller.Tag
            } catch {
                $lookupError = $_.Exception
                while ($lookupError.InnerException) { $lookupError = $lookupError.InnerException }
                Write-Log "Could not get the latest Git for Windows release tag from $GitLatestTagUrl (time limit: $($GitReleaseLookupTimeoutSec)s) ($($lookupError.GetType().FullName): $($lookupError.Message))" "WARNING"
            }

            if (-not $downloadUrl) {
                Write-Log "SCRIPT: $ThisFileName | END | The latest Git release tag is not available right now. Exiting with 1618 so Intune retries this install." "WARNING"
                exit 1618
            }

            $installerPath = "$WorkingDirectory\TEMP\git-installer.exe"

            if (!(Test-Path "$WorkingDirectory\TEMP")) {
                Write-Log "Creating directory: $WorkingDirectory\TEMP"
                New-Item -Path "$WorkingDirectory\TEMP" -ItemType "Directory" -Force
            }

            # An installer left running by an earlier run (one that hit the installer time limit, in any deploy
            # mode) is still working. Do not overwrite its file or start a second one; it is never stopped here.
            $runningInstallers = @(Get-PDRunningGitInstaller)
            if ($runningInstallers.Count -gt 0) {
                Write-Log "A Git installer from an earlier attempt is still running (process ID: $(($runningInstallers | ForEach-Object { $_.Id }) -join ', ')). It is left running." "WARNING"
                Write-Log "SCRIPT: $ThisFileName | END | Git installation not finished yet. Exiting with 1618 so Intune retries this install." "WARNING"
                exit 1618
            }

            Write-Log "Downloading Git $releaseTag from: $downloadUrl (time limit: $($GitDownloadTimeoutSec)s)"
            try {
                Save-PDGitInstaller -Url $downloadUrl -OutFile $installerPath -TimeoutSec $GitDownloadTimeoutSec
            } catch {
                $downloadError = $_.Exception
                while ($downloadError.InnerException) { $downloadError = $downloadError.InnerException }
                Write-Log "Git installer download failed or did not finish within $($GitDownloadTimeoutSec)s ($($downloadError.GetType().FullName): $($downloadError.Message))" "WARNING"
                try {
                    if (Test-Path -LiteralPath $installerPath) { Remove-Item -LiteralPath $installerPath -Force -ErrorAction Stop }
                } catch {
                    Write-Log "Could not remove the partial installer file at: $installerPath" "WARNING"
                }
                Write-Log "SCRIPT: $ThisFileName | END | Git could not be downloaded right now. Exiting with 1618 so Intune retries this install." "WARNING"
                exit 1618
            }

            Write-Log "Installing Git (time limit: $($GitInstallerTimeoutSec)s)..."
            $installerProcess = Start-Process -FilePath $installerPath -ArgumentList "/VERYSILENT", "/NORESTART" -PassThru -ErrorAction Stop
            $null = $installerProcess.Handle # Windows PowerShell 5.1: holding the handle keeps ExitCode readable after the process ends

            if (-not $installerProcess.WaitForExit($GitInstallerTimeoutSec * 1000)) {
                # Deliberately not stopped: stopping the Git installer mid-install can leave a half-installed Git.
                # The installer file is kept because the running installer uses it.
                Write-Log "The Git installer (process ID: $($installerProcess.Id)) is still running after $($GitInstallerTimeoutSec)s. It is left running so it can finish; stopping it mid-install can leave a half-installed Git." "WARNING"
                Write-Log "SCRIPT: $ThisFileName | END | Git installation not finished yet. Exiting with 1618 so Intune retries this install." "WARNING"
                exit 1618
            }

            $installerExitCode = $installerProcess.ExitCode
            if ($installerExitCode -eq 0) {
                Write-Log "Git installer exited with code: $installerExitCode"
            } else {
                Write-Log "Git installer exited with code: $installerExitCode" "WARNING"
            }

            Write-Log "Attempting to do cleanup..."
            if (Test-Path $installerPath) {
                Remove-Item $installerPath -Force
                Write-Log "Removed git installer file at: $installerPath"
            } else {
                Write-Log "Could not find git installer file at: ($installerPath). The script will not attempt to delete anything." "WARNING"
            }

            # Refresh environment variables
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

            # Final test
            if (Get-Command git -ErrorAction SilentlyContinue) {
                Write-Log "Git installation complete!"
            } else {
                Write-Log "Git is not working. Please investigate." "ERROR"
                Exit 1
            }
        } catch {

            Write-Log "SCRIPT: $ThisFileName | END | ERROR: Failed to install Git: $_" "ERROR"
            exit 1

        } finally {

            if ($hasHandle -and $mutex) {

                $mutex.ReleaseMutex()

            }

            if ($mutex) {

                $mutex.Dispose()

            }
        }
    } else {
        Write-Log "Git is already installed."

        # An installer kept by an earlier run that hit the installer time limit, and has since finished.
        $leftoverInstallerPath = "$WorkingDirectory\TEMP\git-installer.exe"
        if ((Test-Path -LiteralPath $leftoverInstallerPath) -and (@(Get-PDRunningGitInstaller).Count -eq 0)) {
            try {
                Remove-Item -LiteralPath $leftoverInstallerPath -Force -ErrorAction Stop
                Write-Log "Removed leftover git installer file at: $leftoverInstallerPath"
            } catch {
                Write-Log "Could not remove leftover git installer file at: $leftoverInstallerPath"
            }
        }
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

if ($DotSourceOnly -eq $true) {

    Write-Host "DotSourceOnly is true; exiting script after dot sourcing." "INFO"
    Exit 0

}

## Pre-Check

Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX PRE-CHECK for SCRIPT: $ThisFileName"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX NOTE: PRE-CHECK is not logged"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Checking if supplied paths are valid"
# Test the paths

if ($UpdateLocalRepoOnly -eq $True -or $InitOnly -eq $true -or $DotSourceOnly -eq $true -or $installGitOnly -eq $true) {

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
Write-Log "UpdateLocalRepoOnly: $UpdateLocalRepoOnly"
Write-Log "DotSourceOnly: $DotSourceOnly"
Write-Log "InitOnly: $InitOnly"
Write-Log "installGitOnly: $installGitOnly"
Write-Log "StashChanges: $StashChanges"
Write-Log "ScriptParams: $ScriptParams"
Write-Log "RequireOrgKeys: $RequireOrgKeys"

Write-Log "++++++++++++++++++++++"

##
# Organization registry values pre-check (before Git install/clone, so a device without them stops in under a second)
# Empty $RequireOrgKeys = no check. Generated custom scripts have the param() block stripped and always get
# $RequireOrgKeys injected, so a leftover session/global variable can never turn this on.
# Only value names and present/missing are logged, never the values (the log folder may not be ACL-locked yet).
if ($RequireOrgKeys) {

    Write-Log "Checking organization registry values required for: $RequireOrgKeys"

    # Explicitly reset: never append to a leftover variable via dynamic scoping
    $RequiredOrgValues = @()
    $MissingOrgValues = @()

    switch ($RequireOrgKeys) {
        'Printers'     { $RequiredOrgValues = @('General\StorageAccountName', 'Printers\PrinterContainerSASkey', 'Printers\PrinterDataJSONpath') }
        'Applications' { $RequiredOrgValues = @('General\StorageAccountName', 'Applications\ApplicationContainerSASkey', 'Applications\ApplicationDataJSONpath') }
        default {
            Write-Log "++++++++++++++++++++++"
            Write-Log "SCRIPT: $ThisFileName | END | Unknown RequireOrgKeys value: '$RequireOrgKeys'. Expected 'Printers' or 'Applications' (or empty for no check)." "ERROR"
            Exit 1
        }
    }

    # Read-only, explicit 64-bit view (matches Configure-Registry.ps1). Never creates the key.
    $OrgBaseKey = $null
    try {
        $OrgBaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)

        foreach ($OrgValue in $RequiredOrgValues) {

            $OrgSubKeyName = 'SOFTWARE\PowerDeploy\' + ($OrgValue -split '\\')[0]
            $OrgValueName = ($OrgValue -split '\\')[1]
            $OrgValueData = $null
            $OrgSubKey = $null

            try {
                $OrgSubKey = $OrgBaseKey.OpenSubKey($OrgSubKeyName, $false)
                if ($OrgSubKey) { $OrgValueData = $OrgSubKey.GetValue($OrgValueName, $null) }
            } catch {
                Write-Log "   $OrgValue : could not be read ($($_.Exception.GetType().Name))" "WARNING"
                $OrgValueData = $null
            } finally {
                if ($OrgSubKey) { $OrgSubKey.Close() }
            }

            if ([string]::IsNullOrWhiteSpace([string]$OrgValueData)) {
                $MissingOrgValues += $OrgValue
                Write-Log "   $OrgValue : missing" "WARNING"
            } else {
                Write-Log "   $OrgValue : present"
            }
        }
    } finally {
        if ($OrgBaseKey) { $OrgBaseKey.Close() }
    }

    if ($MissingOrgValues.Count -gt 0) {
        Write-Log "Missing organization registry values (HKLM\SOFTWARE\PowerDeploy): $($MissingOrgValues -join ', ')" "WARNING"
        Write-Log "++++++++++++++++++++++"
        Write-Log "SCRIPT: $ThisFileName | END | Organization registry values not present yet. Exiting with 1618 so Intune retries this install." "WARNING"
        Exit 1618
    }

    Write-Log "All required organization registry values are present." "SUCCESS"

}

##
# Check if git is installed
Write-Log "Checking if Git is installed..."
CheckAndInstall-Git

if ($installGitOnly -eq $true) {

    Write-Log "InstallGitOnly is true; exiting script after installing Git." "INFO"
    Exit 0

}

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

        Write-Log "RUNNING GIT: git init -b main"
        $gitOutput = git init -b main 2>&1
        ForEach ($line in $gitOutput) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $ThisFileName | END | Failed" "ERROR"; Exit 1 }
        
        Write-Log "RUNNING GIT: git remote add origin $RepoUrl"
        $gitOutput = git remote add origin $RepoUrl 2>&1 
        ForEach ($line in $gitOutput) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $ThisFileName | END | Failed" "ERROR"; Exit 1 }
        
        Write-Log "RUNNING GIT: git fetch origin"
        $gitOutput = git fetch origin 2>&1
        ForEach ($line in $gitOutput) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $ThisFileName | END | Failed" "ERROR"; Exit 1 }
        
        Write-Log "RUNNING GIT: git reset --hard origin/main"
        $gitOutput = git reset --hard origin/main 2>&1
        ForEach ($line in $gitOutput) { Write-Log "GIT: $line" } ; if ($LASTEXITCODE -ne 0) {Write-Log "++++++++++++++++++++++"; Write-Log "SCRIPT: $ThisFileName | END | Failed" "ERROR"; Exit 1 }
        
        Write-Log "RUNNING GIT: git branch --set-upstream-to=origin/main main"
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
   
    if ($InitOnly -eq $true) {

        Write-Log "InitOnly is true; exiting script after initializing local repo." "INFO"
        Exit 0

    }

    Write-Log "Pulling latest changes..."
    try {

        if ($StashChanges -eq $true) {

            Write-Log "Stashing any local changes before pulling latest commit..."

            $gitOutput = git stash 2>&1 # Just in case there are local changes from a local admin or something
            foreach ($line in $gitOutput) {
                Write-Log "GIT: $line"
            }

            if ($LASTEXITCODE -ne 0) {
                Write-Log "++++++++++++++++++++++"
                Write-Log "SCRIPT: $ThisFileName | END | Failed at: git stashed." "ERROR"
                Exit 1            
            } else {
                Write-Log "Successfully ran git stash" "SUCCESS"
            }

        }

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

    Write-Log "SCRIPT: $ThisFileName | Ensuring working registry path exists: HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy"

    & $RegistryChangeScriptPath -WorkingDirectory $WorkingDirectory -KeyOnly $true -KeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy" -Function "Modify"
    if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

} catch {

    Write-Log "SCRIPT: $ThisFileName | Failed to ensure working registry path exists: $_" "ERROR"
    Exit 1

}

# Run the Security Manager to ensure strict ACLs on key folders
try{

    Write-Log "SCRIPT: $ThisFileName | Running Security Manager to ensure strict ACLs on key folders..."
    & $SecurityManagerScriptPath
    if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

} catch {

    Write-Log "SCRIPT: $ThisFileName | Failed to run Security Manager: $_" "ERROR"
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
Write-Log "SCRIPT: $ThisFileName | Running script: $ScriptPath"
Write-Log "SCRIPT: $ThisFileName | With parameters: $ScriptParams"
$RunFail = $False
try {
    if ($ScriptParams) {
        $command = "& `"$FullScriptPath`" $ScriptParams"
        Invoke-Expression $command
    }
    else {
        & $FullScriptPath
    }

    if($LASTEXITCODE -eq 0){
        Write-Log "SCRIPT: $ThisFileName | End script executed successfully with exit code 0!" "SUCCESS"
    } else {
        Write-Log "SCRIPT: $ThisFileName | End script execution failed with exit code: $LASTEXITCODE" "ERROR"
        throw "$LASTEXITCODE"
    }

    # if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

}
catch {
    $RunFail = $True
    Write-Log "SCRIPT: $ThisFileName | ERROR: Script execution failed with exit code/message: $_" "ERROR"
    $FailMessage = $_
}

# Run the Security Manager to ensure strict ACLs on key folders # TODO: This may be overkill, may remove in the future.
try{

    Write-Log "SCRIPT: $ThisFileName | Re-running Security Manager to ensure strict ACLs on key folders after script execution..."
    #Write-Log "Running Security Manager to ensure strict ACLs on key folders..."
    & $SecurityManagerScriptPath
    if ($LASTEXITCODE -ne 0) { throw "$LASTEXITCODE" }

} catch {

    Write-Log "SCRIPT: $ThisFileName | Failed to run Security Manager: $_" "ERROR"
    Exit 1

}

if ($RunFail -eq $False){

    Write-Log "++++++++++++++++++++++"
    Write-Log "SCRIPT: $ThisFileName | END | Repo: $RepoNickName | Script: $ScriptPath | Execution completed." "SUCCESS"
    Exit 0

} else {

    Write-Log "SCRIPT: $ThisFileName | END | Script failed: $FullScriptPath | Error Code/Message: $FailMessage" "ERROR"
    Exit 1

}
