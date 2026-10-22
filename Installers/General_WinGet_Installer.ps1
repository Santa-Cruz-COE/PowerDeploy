# WinGet  installer

<#
TODO

#>
<#

Notes
Requires: PowerShellGet module 

As of 9/26/25...

Name                          Id                             Version      Match            Source
--------------------------------------------------------------------------------------------------
Adobe Express                 9P94LH3Q1CP5                   Unknown                       msstore
Adobe Photoshop               XPFD4T9N395QN6                 Unknown                       msstore
Adobe Creative Cloud          XPDLPKWG9SW2WD                 Unknown                       msstore
Adobe Acrobat Reader DC       XPDP273C0XHQH2                 Unknown                       msstore
Adobe Photoshop Express       9WZDNCRFJ27N                   Unknown                       msstore
Adobe Premiere Elements 2025  XPDCG0J5HFNTKX                 Unknown                       msstore
Adobe Fresco                  XP8C8R0ZKZR27V                 Unknown                       msstore
Adobe Acrobat Reader (32-bit) Adobe.Acrobat.Reader.32-bit    25.001.20693 Tag: adobe       winget
Adobe Acrobat Reader (64-bit) Adobe.Acrobat.Reader.64-bit    25.001.20744 Tag: adobe       winget
Avocode                       Avocode.Avocode                4.15.6       Tag: adobe       winget
Adobe Acrobat Pro             Adobe.Acrobat.Pro              25.001.20693                  winget
Adobe Connect                 Adobe.AdobeConnect             21.11.22                      winget
Brackets                      Adobe.Brackets                 1.14.17770                    winget
Adobe Connect                 Adobe.Connect                  2025.8.189                    winget
Adobe Connect application MSI Adobe.Connect.MSI              25.8.189                      winget
Adobe Creative Cloud          Adobe.CreativeCloud            6.7.0.278                     winget
Cryptr                        Adobe.Cryptr                   0.6.0                         winget
Adobe DNG Converter           Adobe.DNGConverter             17.5                          winget
Workfront Proof               Adobe.WorkfrontProof           2.1.52                        winget
Adobe AIR                     HARMAN.AdobeAIR                51.2.1.5                      winget
FileOpen Client               FileOpenSystems.FileOpenClient 1.0.142.1016 Tag: adobereader winget

#>

# 

Param(

    [Parameter(Mandatory=$true)]
    [String]$AppName = $null,

    [Parameter(Mandatory=$true)]
    [String]$AppID = $null,

    [Parameter(Mandatory=$true)]
    [String]$WorkingDirectory, # Recommended param: "C:\ProgramData\COMPANY_NAME"


    [Parameter(Mandatory=$false)]
    $Version = $null,

    [Parameter(Mandatory=$false)]
    $ReChecks = 36, # Number of times to re-check for installation after install command is run (5 sec apart, so 36 = 3 min). This is to catch cases where the install process returns before the installation is fully complete and detectable. Was 15.
    
    #[String]$VerboseLogs = $True,
    [int]$timeoutSeconds = 1800, # Max seconds to wait for winget.exe to exit (download + install). Was 900 and unused. 1800 = 30 min, leaving room inside Intune's default 60 min install limit. WinGet is never killed when this is reached.

    [Parameter(Mandatory=$false)]
    [int]$ActivityTimeoutSeconds = 600 # After winget.exe exits, max seconds to keep waiting while the installer it started is still running or Windows Installer is busy (installers that return early)

)


### Other Vars ###
$LogRoot = "$WorkingDirectory\Logs\Installer_Logs"
$SafeAppID = $AppName -replace '[^\w]', '_'
$LogPath = "$LogRoot\$AppName.$SafeAppID._WinGet_Installer_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

$RepoRoot = Split-Path -Path $PSScriptRoot -Parent
$InstallWinGetScript = "$RepoRoot\Installers\Install-WinGet.ps1"

$InstallSuccess = $False

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

function WinGet-Detect{ # TODO: I may replace this function. I have a whole script that can do this, but this is simpler and cleaner for now. The other script is intended to be used from InTune.
    Param(
    $ID
    )

    Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | Checking if app $ID is installed"

    # May want to remove the --exact if it causes issues
    $result = & $winget list --id "$ID" --exact --disable-interactivity --accept-source-agreements --source winget 2>&1#| Out-String
    ForEach ($line in $result) { Write-Log "WINGET: $line" } #; if ($LASTEXITCODE -ne 0) {Write-Log "SCRIPT: $ThisFileName | END | Failed. Exit code: $LASTEXITCODE" "ERROR"; Exit 1 }

    if ($result -match "$ID") {
        Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | Installation detected of $ID"

        if ($Version -ne $null){

            Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | Now checking if local install is version: $Version"

            if ($result -match $Version) {
                Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | Specific version $Version detected"
                return $true
            } else {
                Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | Requested version $Version NOT detected"
                Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | NOTE: WinGet does not play nice with installing versions lower than your current install version. You must uninstall first if that is your intended purpose." "WARNING"
                return $false
            }

        }



        return $true
    } else {
        Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | Installation not detected of $ID"
        return $false
    }

}

function Test-WindowsInstallerBusy {
    # Windows Installer holds the Global\_MSIExecute mutex while any MSI install/uninstall is running.
    # NOTE: This is machine-wide (not just our install), so only use it for bounded waits.
    try {
        $mutex = [System.Threading.Mutex]::OpenExisting('Global\_MSIExecute')
        $mutex.Dispose()
        return $true
    } catch [System.Threading.WaitHandleCannotBeOpenedException] {
        return $false
    } catch [System.UnauthorizedAccessException] {
        return $true # The mutex exists, we just aren't allowed to open it
    } catch {
        return $false # Unknown result, don't let it hold up the script
    }
}

function WinGet-WaitForInstall {
    Param(
    $Process,
    $ID
    )

    # Replaces the old fixed "Start-Sleep -Seconds 15" after starting the winget install.
    # Step 1: Wait for winget.exe to exit, up to $timeoutSeconds. WinGet waits for the installer it launches, so for most apps this is the real end of the install.
    # Step 2: Some installers hand their work to another process and return early. While a process started by this winget (directly or further down)
    #         is still running, or Windows Installer is busy, keep waiting until the app is detected, up to $ActivityTimeoutSeconds.
    # Nothing is ever killed. This polls HasExited instead of using Start-Process -Wait, because -Wait also waits for every child process (e.g. an app that opens itself after install).
    # The exit code is only logged. Success is still decided by detection after this function returns.
    # Tested 10/2026 on 12 apps (MSI, WiX, Inno, Adobe/Logitech bootstrappers): winget never exited before the install was done, but detection was sometimes true up to 18 sec before it was done.

    if ($null -eq $Process) {
        Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | No process object was returned for WinGet. Falling back to a 15 second pause before detection." "WARNING"
        Start-Sleep -Seconds 15
        return
    }

    $null = $Process.Handle # Keeps the process handle open so ExitCode can still be read after it exits (Windows PowerShell quirk)
    $startTime = Get-Date
    $installerTree = @{ ([int]$Process.Id) = $true } # winget.exe plus every process it started, directly or further down

    # Adds newly started child processes to $installerTree and returns the ones still running (not counting winget.exe itself)
    function Update-InstallerTree {
        # If WMI fails, carry on with no process info (the wait then relies on WinGet's exit and Windows Installer only)
        try { $allProcs = @(Get-CimInstance -ClassName Win32_Process -Property ProcessId, ParentProcessId, Name, CreationDate -ErrorAction Stop) } catch { $allProcs = @() }
        do {
            $added = 0
            foreach ($p in $allProcs) {
                $procId = [int]$p.ProcessId
                # CreationDate check guards against Windows reusing the PID of an exited parent
                if (-not $installerTree.ContainsKey($procId) -and $installerTree.ContainsKey([int]$p.ParentProcessId) -and $p.CreationDate -ge $startTime.AddSeconds(-2)) {
                    $installerTree[$procId] = $true
                    $added++
                    Write-Log "FUNCTION: WinGet-WaitForInstall | Installer process started: $($p.Name) (PID $procId, parent PID $($p.ParentProcessId))"
                }
            }
        } while ($added -gt 0)
        $allProcs | Where-Object { $installerTree.ContainsKey([int]$_.ProcessId) -and [int]$_.ProcessId -ne $Process.Id } | ForEach-Object { "$($_.Name) (PID $($_.ProcessId))" }
    }

    # Step 1: wait for winget.exe to exit
    Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | Waiting for WinGet (PID $($Process.Id)) to finish installing $ID. Time limit: $timeoutSeconds seconds"
    $lastReport = 0
    while (-not $Process.HasExited) {
        $null = Update-InstallerTree
        $elapsed = ((Get-Date) - $startTime).TotalSeconds
        if ($elapsed -ge $timeoutSeconds) {
            Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | WinGet is still running after $timeoutSeconds seconds. It will NOT be stopped. Moving on to detection." "WARNING"
            return
        }
        if (($elapsed - $lastReport) -ge 30) {
            Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | WinGet still running. Time elapsed: $([int]$elapsed) / $timeoutSeconds seconds"
            $lastReport = $elapsed
        }
        Start-Sleep -Seconds 1
    }

    $exitCode = $Process.ExitCode
    if ($null -ne $exitCode) { $exitCodeHex = '0x{0:X8}' -f $exitCode } else { $exitCodeHex = "unknown" }
    Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | WinGet exited after $([int]((Get-Date) - $startTime).TotalSeconds) seconds with exit code $exitCode ($exitCodeHex). NOTE: The exit code is for reference only, detection decides success."

    # Step 2: keep waiting while the install still visibly has work going on
    $activityStart = Get-Date
    $lastCheck = [datetime]::MinValue
    while ($true) {
        $stillRunning = @(Update-InstallerTree)
        $msiBusy = Test-WindowsInstallerBusy
        $elapsed = ((Get-Date) - $activityStart).TotalSeconds

        if ($stillRunning.Count -eq 0 -and -not $msiBusy) {
            Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | No installer activity remaining (waited $([int]$elapsed) extra seconds after WinGet exited)."
            break
        }

        if ($elapsed -ge $ActivityTimeoutSeconds) {
            Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | Installer activity still present after $ActivityTimeoutSeconds seconds (processes: $($stillRunning -join ', '); Windows Installer busy: $msiBusy). Nothing will be stopped. Moving on to detection." "WARNING"
            break
        }

        if (((Get-Date) - $lastCheck).TotalSeconds -ge 15) {
            $lastCheck = Get-Date
            Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | WinGet has exited but the install still looks active. Installer processes running: $(if ($stillRunning.Count) { $stillRunning -join ', ' } else { 'none' }). Windows Installer busy: $msiBusy. Time elapsed: $([int]$elapsed) / $ActivityTimeoutSeconds seconds"

            # An app that opens itself after install (or leftover helper processes) would keep the process check busy forever, so stop once the app is detected and Windows Installer is idle
            if (-not $msiBusy -and (WinGet-Detect $ID) -eq $true) {
                Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | $ID is detected and Windows Installer is idle. Treating remaining processes as the app itself or leftovers. Done waiting."
                break
            }
        }

        Start-Sleep -Seconds 1
    }

}

Function Validate-WinGet-Search{


    if ($null -eq $Version){

        $result = & $winget show --id $AppId --exact --disable-interactivity --accept-source-agreements --source winget 2>&1 | Out-String
        ForEach ($line in $result) { Write-Log "WINGET: $line" } #; if ($LASTEXITCODE -ne 0) {Write-Log "SCRIPT: $ThisFileName | END | Failed. Exit code: $LASTEXITCODE" "ERROR"; Exit 1 }


    } else {

        Write-Log "Version $Version requested, checking if that exists as well"
        $result = & $winget show --id $AppId --version $Version --exact --disable-interactivity --accept-source-agreements --source winget 2>&1 | Out-String
        ForEach ($line in $result) { Write-Log "WINGET: $line" } #; if ($LASTEXITCODE -ne 0) {Write-Log "SCRIPT: $ThisFileName | END | Failed. Exit code: $LASTEXITCODE" "ERROR"; Exit 1 }

    }

    if ($result -match "No package found") {

        if ($null -eq $Version){
            Write-Log "SCRIPT: $ThisFileName | END | AppID $AppID is not valid. Please use WinGet Search to find a valid ID. Now exiting script." "ERROR"
        } else {
            Write-Log "SCRIPT: $ThisFileName | END | AppID $AppID with version $Version is not valid. Please use WinGet Search to find a valid ID and version. Now exiting script." "ERROR"
        }

        Exit 1

    } else {
        if ($null -eq $Version){
            Write-Log "App ID $AppID is valid. Now proceeding with script."

        } else {
            Write-Log "App ID $AppID with version $Version is valid. Now proceeding with script."

        }
    }

}

############
### Main ###
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
    'InstallWinGetScript' = $InstallWinGetScript
}
Test-PathSyntaxValidity -Paths $pathsToValidate -ExitOnError
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

## Begin main body

Write-Log "===== WinGet Installer Script Started ====="

Write-Log "AppName: $AppName"
Write-Log "AppID: $AppID"
Write-Log "WorkingDirectory: $WorkingDirectory"
Write-Log "Version: $Version"
Write-Log "TmeoutSeconds: $timeoutSeconds"
Write-Log "ActivityTimeoutSeconds: $ActivityTimeoutSeconds"

Write-Log "==========================================="

Write-Log ""
Write-Log "NOTE: WinGet logs generally stored here: %LOCALAPPDATA%\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir"
Write-Log ""

## Checks

Write-Log "Checking script params"
if ($AppName -eq $null -or $AppID -eq $null){

    Write-Log "SCRIPT: $ThisFileName | END | AppName and/or AppID params are empty. Cannot run script." "ERROR"
    Exit 1

} else {

    Write-Log "Params present. Proceeding with script."
}


Write-Log "Checking/Installing WinGet"
$WinGet = & $InstallWinGetScript -ReturnWinGetPath:$True -WorkingDirectory $WorkingDirectory | Select-Object -Last 1
if ($LASTEXITCODE -eq 1 -or $WinGet -eq $null -or $WinGet -eq "" -or $WinGet -eq "Failure") { 
    
    Write-Log "Could not verify or install WinGet. Check the Install WinGet log." "ERROR"
    Write-Log "Last exit code: $LASTEXITCODE" "ERROR"
    Write-Log "Received WinGet Path Value: $WinGet" "ERROR"
    
    Exit 1

}

Write-Log "Checking if AppID $AppID is valid"
Validate-WinGet-Search

Write-Log "----- Now attempting to install $appname -----"
# Write-Log "----------------------------------------------"


Write-Log "Target app ID to install: $AppID"
if($Version){ Write-Log "Target version to install: $Version"}

# Check if app ID is already installed
Write-Log "Checking for pre-existing local installation of $AppID $Version..."
$detectPreviousInstallation = WinGet-Detect $AppID
if($detectPreviousInstallation -eq $true){
    
    if ($null -ne $Version){

        Write-Log "Installation of $AppID with version $version already detected! If you need to uninstall this instance, please run the General Uninstall script with the WinGet method." "SUCCESS"    
    
    } else {

        Write-Log "Installation of $AppID already detected! If you need to uninstall this instance, please run the General Uninstall script with the WinGet method." "SUCCESS"

    }

    
    
    $InstallSuccess = $true


# if not...
}else{

    if ($null -ne $Version){

        Write-Log "No pre-existing local installation of $AppID with version $Version, proceeding with installation"


    } else {

        Write-Log "No pre-existing local installation of $AppID, proceeding with installation"


    }

    # Try installation of target ID
    try {

        <#
            
            NOTES:

            The --scope machine arg breaks the installer. Here are ideas to try out in the future for trying to force apps to install for all users if necessary:

            For MSI Installers:
            You can pass the standard Windows Installer property ALLUSERS=1.
            winget install --id Example.App --override "/qn ALLUSERS=1"

            For InnoSetup Installers:
            Many InnoSetup .exe files accept the /ALLUSERS argument.
            winget install --id Example.App --override "/VERYSILENT /SUPPRESSMSGBOXES /ALLUSERS"

            For Nullsoft (NSIS) Installers:
            These are trickier, but you can usually force them into the machine directory using the /D flag.
            winget install --id Example.App --override "/S /D=C:\Program Files\ExampleApp"

            A quick tip: If you ever want to see exactly what installer type an app uses so you know which override to use, you can run winget show <AppID>. It will list the installer type (MSI, Inno, Nullsoft, Wix, etc.) near the bottom.

            
        #>
    
        $cmd = "$winget"
        if ($null -eq $Version){
            
            $args = "install --id $AppID -e --silent --accept-package-agreements --accept-source-agreements --disable-interactivity --source winget --verbose-logs"

        } else {
            
            $args = "install --id $AppID --version $Version -e --silent --accept-package-agreements --accept-source-agreements --disable-interactivity --source winget --verbose-logs"

        }

        # Santitize the name of the log path
        $SafeAppID = $AppID -replace '[^\w]', '_'

        $InstallationOutputLog = "$LogRoot\$SafeAppID.InstallationOutputLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $InstallationErrorLog = "$LogRoot\$SafeAppID.InstallationErrorLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

        Write-Log "Executing command: $cmd $args"

        Write-Log "Installation Output log for $AppID located at: $InstallationOutputLog"
        Write-Log "Installation Error log for $AppID located at: $InstallationErrorLog"
        

        #$proc = Start-Process -FilePath "$cmd" -ArgumentList $args -NoNewWindow -PassThru -RedirectStandardOutput "$InstallationOutputLog" -RedirectStandardError "$InstallationErrorLog"
        
        #$proc = Start-Process -FilePath $cmd -ArgumentList $args -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$InstallationOutputLog" -RedirectStandardError "$InstallationErrorLog"
        # Start-Process -FilePath $cmd -ArgumentList $args -NoNewWindow -PassThru -RedirectStandardOutput "$InstallationOutputLog" -RedirectStandardError "$InstallationErrorLog"

        #$proc = 
        
        $proc = $null
        try { 
            
            $proc = Start-Process -FilePath "$cmd" -ArgumentList $args -NoNewWindow -PassThru -RedirectStandardOutput "$InstallationOutputLog" -RedirectStandardError "$InstallationErrorLog"

        } catch { 

            Throw $_ 
        
        }   

        # Wait for WinGet (and any installer work it leaves running) to finish before detecting
        WinGet-WaitForInstall -Process $proc -ID $AppID

        Write-Log "Installation process of $AppID completed, now detecting local installation..."
        # Start-Sleep -Seconds 15 # Replaced by WinGet-WaitForInstall above
        $detectInstallation = WinGet-Detect $AppID

        if($detectInstallation -eq $true){

            Write-Log "Local installation detected. Installation successful for $AppID" "SUCCESS"
            $InstallSuccess = $true

        } else { 

            Write-Log "No local installation detected. Install failure of $AppID." "ERROR"
            $InstallSuccess = $false
            
            Throw "Installation command ran, but installation check failed for $AppID"

        }

        
        # # Start the process and wait for the process with timeout
        # $startTime = Get-Date
        # while (-not $proc.HasExited) {
        #     Start-Sleep -Seconds 10
        #     $elapsed = (Get-Date) - $startTime
        #     Write-Log "Time elapsed: $elapsed / $TimeoutSeconds seconds"
        #     if ($elapsed.TotalSeconds -ge $timeoutSeconds) {
        #         Write-Log "Timeout reached ($timeoutSeconds seconds) for $AppID. Killing process..." "WARNING"
        #         try {
        #             $proc.Kill()
        #             Write-Log "Process killed due to timeout for $AppID" "ERROR"
        #         } catch {
        #             Write-Log "Failed to kill process for $AppID : $_" "ERROR"
        #         }
        #         break
        #     }
        # }
        
        
        # # If the process exited and had a success code...
        # if ($proc.HasExited -and $proc.ExitCode -eq 0) {

        #     Write-Log "Installation return success exit code, now detecting local installation..."
        #     $detectInstallation = WinGet-Detect $AppID

        #     if($detectInstallation -eq $true){

        #         Write-Log "Local installation detected. Installation successful for $AppID" "SUCCESS"
        #         $InstallSuccess = $true

        #     # If process did not exit...
        #     } elseif(-not $proc.HasExited) {

        #         Write-Log "Process still running after timeout, unexpected behavior." "WARNING"
        #         #$InstallSuccess = $false
            
        #     # If the detect was unsuccessful AND the process did not exit...
        #     } else {

        #         $InstallSuccess = $false
        #         Write-Log "No local installation detected. Install failure of $AppID." "ERROR"
            
        #     }


        
        # } else {
        #     Write-Log "Install process returned non-zero exit code ($($proc.ExitCode)) for $AppID" "WARNING"
        #     $InstallSuccess = $false
        # }           
        

        
        # Spit out each line of the process for logging


        # Write-Log "Logging captured WinGet process output for process:"
        # ForEach ($line in $proc) { Write-Log "WINGET PROCESS: $line" }

        
    # If installation returns a catchable error...

    } catch {
            

        Write-Log "Install failure of $AppID : $_" "ERROR"
        $InstallSuccess = $false

        # Check for specific error code that indicates a corrupted WinGet install
        # This logic branch is mostly untested.
        # if ($_ -match "-1073741701"){
        try {

            # Never reset WinGet while the install it started is still running (on 10/17/2026 this orphaned a LibreOffice install and started a second one in parallel)
            # This only happens if WinGet-WaitForInstall hit $timeoutSeconds. Skips the reset and retry, and goes straight to the final re-checks below.
            if ($null -ne $proc -and -not $proc.HasExited) {
                Throw "WinGet (PID $($proc.Id)) is still running, so WinGet will not be reset and the install will not be retried. Moving on to final checks."
            }

            Write-Log "Attempting WinGet reset just in case there is corruption..."
            # try clearing the WinGet cache and uninstall
            remove-item -path  "$env:LOCALAPPDATA\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\settings.json" -ErrorAction SilentlyContinue
            remove-item -path  "$env:LOCALAPPDATA\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\source" -ErrorAction SilentlyContinue
            
            Start-Sleep -Seconds 10 

            # Uninstall WinGet/App Installer
            # NOTE: This doesn't work. Returns the following error: error 0x80070032: AppX Deployment Remove operation on package Microsoft.DesktopAppInstaller_1.27.350.0_arm64__8wekyb3d8bbwe from: C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.27.350.0_arm64__8wekyb3d8bbwe failed. This app is part of Windows and cannot be uninstalled on a per-user basis. An administrator can attempt to remove the app from the computer using Turn Windows Features on or off. However, it may not be possible to uninstall the app
            # TODO: Replace this with Windows Feature Configurator call
            # get-appxpackage *AppInstaller* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            # Start-Sleep -Seconds 10 

            # Reintstall WinGet
            # TODO: Make this into a function later
            Write-Log "Checking/Installing WinGet"
            $WinGet = & $InstallWinGetScript -ReturnWinGetPath:$True -WorkingDirectory $WorkingDirectory | Select-Object -Last 1

            if ($LASTEXITCODE -eq 1 -or $WinGet -eq $null -or $WinGet -eq "" -or $WinGet -eq "Failure") { 
                
                Write-Log "Could not verify or install WinGet. Check the Install WinGet log." "ERROR"
                Write-Log "Last exit code: $LASTEXITCODE" "ERROR"
                Write-Log "Received WinGet Path Value: $WinGet" "ERROR"
                
                Exit 1

            }

            Write-Log "Retrying installation of $AppID after WinGet reset..."

            # Try installation of target ID again
            # TODO: make this into a function later
            
                $proc = $null
                try { 
            
                    $proc = Start-Process -FilePath "$cmd" -ArgumentList $args -NoNewWindow -PassThru -RedirectStandardOutput "$InstallationOutputLog" -RedirectStandardError "$InstallationErrorLog"

                } catch { 

                    Throw $_ 
                
                }   

                # Wait for WinGet (and any installer work it leaves running) to finish before detecting
                WinGet-WaitForInstall -Process $proc -ID $AppID

                Write-Log "Installation process of $AppID completed, now detecting local installation..."
                # Start-Sleep -Seconds 15 # Replaced by WinGet-WaitForInstall above
                $detectInstallation2 = WinGet-Detect $AppID

                if($detectInstallation2 -eq $true){

                    Write-Log "Local installation detected. Installation successful for $AppID" "SUCCESS"
                    $InstallSuccess = $true

                } else { 

                    Write-Log "No local installation detected. Install failure of $AppID." "ERROR"
                    $InstallSuccess = $false
                    
                    Throw "Installation command ran, but installation check failed for $AppID"

                }




                # $proc = Start-Process -FilePath "$cmd" -ArgumentList $args -NoNewWindow -PassThru -RedirectStandardOutput "$InstallationOutputLog" -RedirectStandardError "$InstallationErrorLog"

                #         # Start the process and wait for the process with timeout
                # $startTime = Get-Date
                # while (-not $proc.HasExited) {
                #     Start-Sleep -Seconds 10
                #     $elapsed = (Get-Date) - $startTime
                #     Write-Log "Time elapsed: $elapsed / $TimeoutSeconds seconds"
                #     if ($elapsed.TotalSeconds -ge $timeoutSeconds) {
                #         Write-Log "Timeout reached ($timeoutSeconds seconds) for $AppID. Killing process..." "WARNING"
                #         try {
                #             $proc.Kill()
                #             Write-Log "Process killed due to timeout for $AppID" "ERROR"
                #         } catch {
                #             Write-Log "Failed to kill process for $AppID : $_" "ERROR"
                #         }
                #         break
                #     }
                # }
                
                
                # # If the process exited and had a success code...
                # if ($proc.HasExited -and $proc.ExitCode -eq 0) {

                #     Write-Log "Installation return success exit code, now detecting local installation..."
                #     $detectInstallation = WinGet-Detect $AppID

                #     if($detectInstallation -eq $true){

                #         Write-Log "Local installation detected. Installation successful for $AppID" "SUCCESS"
                #         $InstallSuccess = $true

                #     # If process did not exit...
                #     } elseif(-not $proc.HasExited) {

                #         Write-Log "Process still running after timeout, unexpected behavior." "WARNING"
                #         #$InstallSuccess = $false
                    
                #     # If the detect was unsuccessful AND the process did not exit...
                #     } else {

                #         $InstallSuccess = $false
                #         Write-Log "No local installation detected. Install failure of $AppID." "ERROR"
                    
                #     }

                # } 

            } catch {


                Write-Log "Retry install failure of $AppID : $_" "ERROR" 
                $InstallSuccess = $false

                
            }

        # }

    }
    
    # Final Check (sometimes it installs anyways despite returning an error above)



    if ($InstallSuccess -eq $false){


        Write-Log "Running a final check to see if target app installed: $AppID $Version "

        $Counter=$ReChecks
        while($Counter -gt 0)
        {

            Write-Log "Re-check attempts remaining: $Counter"

            Write-Log "Pausing for 5 sec..."


            Start-Sleep -Seconds 5 # brief pause before re-checking


            $detectInstallation2 = WinGet-Detect $AppID

            if($detectInstallation2 -eq $true) {

                Write-Log "Local installation detected. Installation successful of $AppID $Version" "SUCCESS"
                $InstallSuccess = $true

            } else {

                Write-Log "Final check failed. No local installation of $AppID $Version detected." "ERROR"

            }

            if ($InstallSuccess -eq $true) {
                break
            } else {
                $Counter--
            }

            Write-Log ""
        }

        if ($InstallSuccess -eq $false) {
            Write-Log "All re-check attempts exhausted. No local installation of $AppID $Version detected." "ERROR"
        }

        Write-Log ""
    }

}


# Final result
Write-Log "----------------------------------------------"
Write-Log "Final Result:"

if ($InstallSuccess -eq $True) {

    Write-Log "SCRIPT: $ThisFileName | END | Installation of $appname $Version with ID $AppID success!" "SUCCESS"
    Exit 0

} else {

    Write-Log "SCRIPT: $ThisFileName | END | Critical Error: Could not install $appname $Version with ID $AppID" "ERROR"
    Exit 1
}
