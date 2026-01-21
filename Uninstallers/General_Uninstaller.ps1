# General Uninstaller

# Example run
# General_uninstaller.ps1 -AppName "AdobeCC" -UninstallType "Remove-App-MSI-QN"

# TODO
<#

- Seperate detection methods into their own individual scripts

- add descriptions to each method
- install winget
- sometimes the command outputs are blank; remove if so?

IDEA:

Instead of so many uninstall types just have a few main types and then have the external runner pass in extra args as needed. That gives more flexibility and reduces the number of uninstall types needed, both significantly.


# TODO: 

- For the UninstallerString method, the supplied AppName must be a valid, exact DisplayName
- Rename UninstallType to UninstallMethod for consistency

- Remove "AppPackage" stuff it's literally the same as AppxPackage.

#>

<#

Known working uninstall types

7-zip, Remove-App-EXE-S
Chrome, Remove-App-EXE-S

'Dell SupportAssist' = 'Remove-App-MSI-QN'
'Dell Digital Delivery Services' = 'Remove-App-MSI-QN'
'Dell Optimizer Core' = 'Remove-App-EXE-SILENT'
'Dell SupportAssist OS Recovery Plugin for Dell Update' = 'Remove-App-MSI_EXE-S'
'Dell SupportAssist Remediation' = 'Remove-App-MSI_EXE-S'
'Dell Display Manager 2.1' = 'Remove-App-EXE-S-QUOTES'
'Dell Peripheral Manager' = 'Remove-App-EXE-S-QUOTES'
'Dell Core Services' = 'Remove-App-MSI-I-QN'
'Dell Trusted Device Agent' = 'Remove-App-MSI-I-QN'
'Dell Optimizer' = 'Remove-App-MSI-I-QN'



#>

# NOTE/TODO: there is a flaw with uninstall based on registry DisplayName; sometimes there are duplicate DisplayNames. In the future we may want to list the found apps with indexes or other identifiers and have the user select one.
<#

    Example of duplicates from my test machine:

    DisplayName                                                     DisplayVersion   PSChildName                           
    -----------                                                     --------------   -----------                           
    Flameshot                                                       13.3.0           {8FA03992-037E-4A23-B8A8-AF2768116FBC}
    Git                                                             2.51.2           Git_is1                               
    Google Chrome                                                   143.0.7499.41    {AFEF3E4D-0F28-305F-94EA-B5F732F974C2}
    Microsoft .NET Host - 8.0.15 (arm64)                            64.60.31149      {45BFB9A6-1426-467E-9F8E-93D5E9E63883}
    Microsoft .NET Host FX Resolver - 8.0.15 (arm64)                64.60.31149      {1658430D-653D-43AF-8FD2-5C283EEDF162}
    Microsoft .NET Runtime - 8.0.15 (arm64)                         64.60.31149      {77ACC55A-6671-48E3-9A3D-21E79B6627EF}
    Microsoft 365 Apps for enterprise - en-us                       16.0.19328.20266 O365ProPlusRetail - en-us             
    Microsoft Edge                                                  143.0.3650.96    Microsoft Edge                        
    Microsoft Edge WebView2 Runtime                                 143.0.3650.96    Microsoft EdgeWebView                 
    Microsoft Visual C++ 2022 Arm64 Runtime - 14.44.35211           14.44.35211      {88A3EF6C-D7E4-4707-B3F5-E530B3AD6081}
    Microsoft Visual C++ 2022 Redistributable (Arm64) - 14.44.35211 14.44.35211.0    {a87e42cd-475d-4f15-8848-e0d60c63c02f}
    Microsoft Windows Desktop Runtime - 8.0.15 (arm64)              8.0.15.34718     {754291a4-39ad-4334-b288-97b2515eca65}
    Microsoft Windows Desktop Runtime - 8.0.15 (arm64)              64.60.31203      {CD4994D0-62B1-46E9-BC33-61FAD70FFA57}
    Office 16 Click-to-Run Extensibility Component                  16.0.19328.20106 {90160000-008C-0000-1000-0000000FF1CE}
    Office 16 Click-to-Run Licensing Component                      16.0.19029.20244 {90160000-007E-0000-1000-0000000FF1CE}
    OpenSSL 3.5.1 for ARM (64-bit)                                  3.5.1            {44B11A22-49CB-4C70-9350-DAA6181BC86A}
    Parallels Tools                                                 26.1.2.57293     {4254F5B9-8150-4F44-AD56-A356893E9C80}

#>


Param(

    [Parameter(Mandatory=$true)]
    [String]$AppName,

    [Parameter(Mandatory=$true)]
    [String]$UninstallType,

    [Parameter(Mandatory=$False)]
    $Version=$null,

    [Parameter(Mandatory=$true)]
    [String]$WorkingDirectory, # Recommended param: "C:\ProgramData\COMPANY_NAME"

    [Boolean]$VerboseLogs = $True,

    [Boolean]$SupremeErrorCatching = $True, 
    
    [int]$timeoutSeconds = 900, # Timeout in seconds (300 sec = 5 minutes)

    # These can be explicitly passed if the AppName is seperate
    $WinGetID=$null,
    $UninstallString_DisplayName=$null


)



############
### Vars ###
############

# Log folder location. Recommend not to change.
$LogRoot = "$WorkingDirectory\Logs\Uninstaller_Logs"

# Don't Change these
$SafeAppID = $AppName -replace '[^\w]', '_'
$LogPath = "$LogRoot\$SafeAppID.$UninstallType._MainUninstallLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$uninstallSuccess = $False

$RepoRoot = Split-Path -Path $PSScriptRoot -Parent
$InstallWinGetScript = "$RepoRoot\Installers\Install-WinGet.ps1"

# path to application detection script
$AppDetectionScriptPath = "$RepoRoot\Templates\Detection-Script-Application_TEMPLATE.ps1"


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
    
    Add-Content -Path $LogPath -Value $logEntry
}

Function Extreme-ErrorCatchingRunner {

    param(
        [String]$UninstallCommand_App,
        [String]$UninstallCommand_Args,
        [String]$DetectMethod
    )

    Write-Log "-----------------------------------------"
    Write-Log "Sub-Function: Extreme-ErrorCatchingRunner | Begin | Summary: Now attempting to run uninstall command with extreme error catching."

    try { 

        $UnInstallationOutputLog = "$LogRoot\$SafeAppID.$UninstallType.UninstallationCommandOutputLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $UnInstallationErrorLog = "$LogRoot\$SafeAppID.$UninstallType.UnistallationCommandErrorLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

        # Configure process args, capture as object $proc

            # $proc = Start-Process `
            # -FilePath $UninstallCommand_App `
            # -ArgumentList $UninstallCommand_Args `
            # -WindowStyle Hidden `
            # -PassThru `
            # -RedirectStandardOutput "$UnInstallationOutputLog" `
            # -RedirectStandardError "$UnInstallationErrorLog"

        $procParams = @{
            FilePath = $UninstallCommand_App
            ArgumentList = $UninstallCommand_Args
            WindowStyle = 'Hidden'
            PassThru = $true
            RedirectStandardOutput = $UnInstallationOutputLog
            RedirectStandardError = $UnInstallationErrorLog
        }

        Write-Log "This is the command that will be ran:"
        Write-Log "Start-Process with parameters:"
        $procParams.GetEnumerator() | ForEach-Object {
            Write-Log "  $($_.Key): $($_.Value)"
        }

        $proc = Start-Process @procParams
        # Default to view success as not successfully uninstalled yet
        $UnInstallSuccess = $false

        # Get the start time to determine low long to give process to run before timeout
        $startTime = Get-Date

        # Run the target process in the background ($proc runs when it gets evaluated as -not $proc.HasExited)...
        # While waiting for the process to exit...
        While (-not $proc.HasExited){ # Do...

            Start-Sleep -Seconds 10 # Wait 10 seconds
            $elapsed = (Get-Date) - $startTime # Check how much time is left
            Write-Log "Time elapsed: $elapsed / $TimeoutSeconds seconds" # Record to screen and log the time elapsed


            # If time has run out...
            if ($elapsed.TotalSeconds -ge $timeoutSeconds) {

                Write-Log "Timeout reached ($timeoutSeconds seconds) for Uninstallation. Killing process..." "WARNING"

                # Try killing the process...
                try {

                    $proc.Kill() # Attempt to kill process... (exits to the catch statement if it fails)
                    Write-Log "UnInstallation process killed due to timeout" "ERROR"

                } catch { # Catch the error if it fails to end the process...

                    Write-Log "Failed to kill process : $_" "ERROR" # Write and log the error
                }

                break # Break the loop once time runs out
                
            }

        }

        # After the $proc has ran out of time and the loops has been exited it is time to run some checks...

        # If the $proc has exited and $proc returned a success code...
        if ($proc.HasExited -and $proc.ExitCode -eq 0) {


            Write-Log "Process return success exit code" "INFO"
            

        }elseif(-not $proc.HasExited){
            
            
            Write-Log "Process still running after timeout, unexpected behavior" "ERROR"

        
        # If the process $proc is still running OR the exit code was not 0 (success code)
        } else {
            Write-Log "Uninstall process returned non-zero exit code ($($proc.ExitCode)) for $AppName" "WARNING" ## THIS IS WHERE THE EXIT CODE IS CAPTURED
            $UnInstallSuccess = $false
        }           

    
    } Catch {

        # If installation fails, return error
            
        Write-Log "Process Failed. Error: $_" "ERROR"
        $UnInstallSuccess = $false

    }


    # Final Check
    <#
    Write-Log "Attempting final check of application installation."

    $detect = App-Detector -AppName $AppName -DetectMethod $DetectMethod

    if ($detect -eq $false){

        Write-Log "Application not detected. Uninstall reported success." "SUCCESS"
        $UnInstallSuccess = $True

    } Else {

        Write-Log "Application  detected. Uninstall failed." "ERROR"
        $UnInstallSuccess = $False

    }
    #>

    
    Write-Log "Sub-Function: Extreme-ErrorCatchingRunner | End"
    Write-Log "-----------------------------------------"

    # Return true/false to the function call
    if ($UnInstallSuccess -eq $true){

        Return $True

    } Else {

        Return $False

    }

    # Write-Log "End of uninstall command function with superior logging."
    # Write-Log "-----------------------------------------"

}

Function Command-Runner {
    param(
        [String]$UninstallCommand_App,
        [String]$UninstallCommand_Args,
        [String]$DetectMethod
    )

    Write-Log "-----------------------------------------"
    Write-Log "Function: Command-Runner | Begin | Summary: Now attempting to run uninstall command."

    If($SupremeErrorCatching -eq $True){

        Write-Log "SupremeErrorCatching enabled. Using more complex logic."

        # Run the Extreme-ErrorCatchingRunner
        if ((Extreme-ErrorCatchingRunner -UninstallCommand_App $UninstallCommand_App -UninstallCommand_Args $UninstallCommand_Args -DetectMethod $DetectMethod) -eq $true){

            $UnInstallSuccess = $True

        } Else {

            $UnInstallSuccess = $False

        }


    } Else {


        # Run the regular uninstall command
        Try {

            $UninstallCommand = "$UninstallCommand_App $UninstallCommand_Args"
            Write-Log "Running this command: $UninstallCommand"

            & $UninstallCommand_App $UninstallCommand_Args

        } Catch {

            Write-Log "Command failed. Here is error message: $_" "ERROR"
            $uninstallSuccess = $False

        }

    }

    # After attempting uninstaller...

    Write-Log "Waiting for system to update..."
    # Registry cache refresh.  TODO: This may not work. Remove?
    [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Default).Close()
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    Start-Sleep -Seconds 10


    ## Final Check ##

    Write-Log "Function: Command-Runner | Attempting final check of application installation."
    <#
    $maxAttempts = 3
    $attemptCount = 0
    $detect = $true  # Assume it's there until proven otherwise

    while ($attemptCount -lt $maxAttempts -and $detect) {
        $attemptCount++
        Write-Log "Detection attempt $attemptCount of $maxAttempts"
        
        $detect = App-Detector -AppName $AppName -DetectMethod $DetectMethod
        
        if ($detect -and $attemptCount -lt $maxAttempts) {
            Write-Log "App still detected, waiting 2 seconds before retry..."
            Start-Sleep -Seconds 2
        }
    }
        #>

    
    # This part tries to detect if an uninstall string is still present in the registry
    $detect = App-Detector -AppName $AppName -DetectMethod $DetectMethod

    # If detection returns an object (for UninstallerString method), verify the uninstaller exists 
    if ($detect -and $DetectMethod -eq 'UninstallerString') {

        # Extract the uninstaller path (handle quoted and unquoted paths)
            $uninstallerPath = if ($detect.UninstallString -match '"([^"]+)"') {

                $matches[1]

        } else {

            $detect.UninstallString.Split(' ')[0]

        }
        
        if (-not (Test-Path $uninstallerPath)) {

            Write-Log "Ghost registry entry detected - uninstaller doesn't exist" "WARNING"
            $detect = $null  # Treat as not detected

        }

    }


    if ($detect -eq $false -or $detect -eq $null){
        Write-Log "Function: Command-Runner | Final Check: Application not detected. Uninstall reported success." "SUCCESS"
        $UnInstallSuccess = $True
    } Else {
        Write-Log "Function: Command-Runner | Final Check: Application detected. Uninstall failed." "ERROR"
        $UnInstallSuccess = $False
    }


    # Return true/false to the function call
    if ($UnInstallSuccess -eq $true){

        Write-Log "Function: Command-Runner | End | Final Result: Uninstall Success!" "SUCCESS"
        Write-Log "-----------------------------------------"
        Return $True

    } Else {

        Write-Log "Function: Command-Runner | End | Final Result: Result of uninstall command: Failure!" "ERROR"
        Write-Log "-----------------------------------------"
        Return $False

    }    


}

Function Validate-WinGet-Search{

    Param(

        $AppID

    )

    Write-Log "Checking if AppID $AppID is valid"

    if ($Version -eq $null -or $Version -eq ""){

        Write-Log "Running: & $winget show --id $AppId --exact"
        $result = & $winget show --id $AppId --exact 2>&1 | Out-String
        ForEach ($line in $result) { Write-Log "WINGET: $line" } #; if ($LASTEXITCODE -ne 0) {Write-Log "SCRIPT: $ThisFileName | END | Failed. Exit code: $LASTEXITCODE" "ERROR"; Exit 1 }


    } else {

        Write-Log "Version $Version requested, checking if that exists as well"
        $result = & $winget show --id $AppId --version $Version --exact 2>&1 | Out-String
        ForEach ($line in $result) { Write-Log "WINGET: $line" } #; if ($LASTEXITCODE -ne 0) {Write-Log "SCRIPT: $ThisFileName | END | Failed. Exit code: $LASTEXITCODE" "ERROR"; Exit 1 }

    }

    if ($result -match "No package found") {

        if ($Version -eq $null -or $Version -eq ""){
            Write-Log "SCRIPT: $ThisFileName | END | AppID $AppID is not valid. Please use WinGet Search to find a valid ID." "WARNING"
        } else {
            Write-Log "SCRIPT: $ThisFileName | END | AppID $AppID with version $Version is not valid. Please use WinGet Search to find a valid ID and version." "WARNING"
        }

        Throw "1"

    } else {
        if ($Version -eq $null -or $Version -eq ""){
            Write-Log "AppID $AppID is valid. Now proceeding with script."

        } else {
            Write-Log "AppID $AppID with version $Version is valid. Now proceeding with script."

        }

        Return "0"
    }

}

# Detection Checkers to add in the future?
Function App-Detector {
    Param (

        [String]$AppName,
        [String]$DetectMethod

    )

    Write-Log "-----------------------------------------"
    Write-Log "Function: App-Detector | Begin | Summary: Checking for App: $AppName using Method: $DetectMethod"


    # TODO: Convert to a switch?

    If ($DetectMethod -eq 'Win_Get'){

        Write-Log "For WinGet functions to work, the supplied AppName must be a valid, exact AppID" "WARNING"

        Write-Log "Checking if AppName is a valid AppID"

        Try {

            Validate-WinGet-Search -AppID $AppName

        } catch {

            Write-Log "Installation detected of $AppName not detected due to invalid AppID. Will continue on." "WARNING"

            return "AppIDinvalid"

        }
        
        #if ($response -ne 0) { return "AppIDinvalid" }


        Write-Log "Checking if AppID is present locally"
        $Detection = & $winget list --id "$AppName" --exact --accept-source-agreements| Out-String

        if ($Detection -match "$AppName") {
            Write-Log "Installation detected of $AppName"
            return $true
        } else {
            Write-Log "Installation not detected of $AppName"
            return $null
        }

    }

    If ($DetectMethod -eq 'UninstallerString'){

        Write-Log "For UninstallerString method, using wildcard search the registry uninstall strings for DisplayName equal to the supplied AppName"
        # TODO: the supplied AppName must be a valid, exact DisplayName

        $Detection = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, 
                                        HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue | 
                    Get-ItemProperty | 
                    Where-Object {$_.DisplayName -like "*$appName*"} | # Changed to use wildcard
                    Select-Object -Property DisplayName,UninstallString -First 1
        


        # Return the object directly for UninstallerString method
        return $Detection
    }    

    If ($DetectMethod -eq 'AppxPackage'){

        # TODO: Make this exact match?

        #Write-Log "Running detection"
        $Detection = Get-AppxPackage -AllUsers $appName

    }

    If ($DetectMethod -eq 'AppPackage'){

        # TODO: Make this exact match?

        $Detection = Get-AppPackage -AllUsers $appName

    }

    # UNTESTED
    If ($DetectMethod -eq 'AppxProvisionedPackage'){

        # TODO: Make this exact match?


        #Write-Log "Running detection"
        #$Detection = Get-AppxPackage -AllUsers $appName

        $provApp = Get-AppxProvisionedPackage -Online 
        $proPackageFullName = (Get-AppxProvisionedPackage -Online | where {$_.Displayname -eq $appName}).DisplayName


        if($proPackageFullName -ne $null){
            Return $True
        } else {
            Return $False
        }
    }

    # UNTESTED
    If ($DetectMethod -eq 'AppProvisionedPackage'){

        # TODO: Make this exact match?

        $provApp = Get-AppProvisionedPackage -Online 
        $proPackageFullName = (Get-AppProvisionedPackage -Online | where {$_.Displayname -eq $appName}).DisplayName


        if($proPackageFullName -ne $null){
            Return $True
        } else {
            Return $False
        }
    }



    If ($DetectMethod -eq 'CIM'){

        # TODO: Make this exact match?

        $Detection = Get-CimInstance -ClassName Win32_Product | Where-Object { $_.Name -like "$Appname*"} | Select-object name

    }

    If ($DetectMethod -eq 'Uninstallertring2'){

        # TODO: Make this exact match?

        $Detection = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like $appName} | Select UninstallString

    }

    # If ($DetectMethod -eq 'UninstallerString'){

    #     $Detection = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString

    # }

    # Run detection
    # NEED TO DO: check this verbose vs non-verbose

    # if ($VerboseLogs -eq $true){

    #     $Detection

    # } Else {

    #     If($Detection){
    #         return $True
    #     } else {
    #         return $False
    #     }

    # }
    


    If($Detection){

        Write-Log "Function: App-Detector | End | $AppName was detected" "WARNING"
        Write-Log "-----------------------------------------"

        return $Detection

    } else {

            Write-Log "Function: App-Detector | End | $AppName was not detected" "SUCCESS"
            Write-Log "-----------------------------------------"

            return $null

    }
}

Function Test-AllDetectionMethods {
    Param (
        [Parameter(Mandatory=$true)]
        [String]$AppName,
        [boolean]$IncludeCIM=$true,  # Optional flag since CIM is slow and problematic
        [boolean]$IncludeWinGet=$true # Not going to use this boolean yet, but reminder that I may want to use it
    )
    
    #Write-Log "========================================="
    Write-Log "========================================="
    Write-Log "Function: Test-AllDetectionMethods | Begin | Summary: Testing ALL detection methods for: $AppName"
    #Write-Log "========================================="
    
    # Get all available detection methods from the switch statement
    $detectionMethods = @(
        'AppxPackage', 
        'AppPackage',
        'AppxProvisionedPackage',
        'AppProvisionedPackage',
        'UninstallString',
        'UninstallString2',
        'AppxProvisionedPackage'
    )
    
    if ($VerboseLogs -eq $true){

        Write-Log "Available detection methods:"
        $detectionMethods | ForEach-Object { Write-Log "  - $_" "INFO" }
    }  


    # Include CIM method?
    if ($IncludeCIM) {     # Only include CIM if specifically requested

        Write-Log "Also including CIM method"
        $detectionMethods += 'CIM'
        Write-Log "WARNING: Including CIM method - this may be slow and trigger repairs" "WARNING"
    }

    # Include WinGet method?
    #if ($IncludeWinGet) {     # Only include Win_Get if specifically requested
    if ($UninstallType -eq 'All' -or $UninstallType -eq 'Win_Get' -or $UninstallType -eq 'Remove-App-WinGet'){ # Only include if it is specifically requested
        Write-Log "Also including Win_Get method"
        $detectionMethods += 'Win_Get'
    }
    #}





    
    $results = @{}
    
    foreach ($method in $detectionMethods) {
        Write-Log "Function: Test-AllDetectionMethods | Testing method: $method" "INFO"
        
        try {
            $detected = App-Detector -AppName $AppName -DetectMethod $method
            $results[$method] = $detected
            
            if ($detected -eq $true) {
                Write-Log "Function: Test-AllDetectionMethods | $method : Application FOUND" "WARNING"
            } else {
                Write-Log "Function: Test-AllDetectionMethods | $method : Application NOT found" "SUCCESS"
            }
        }
        catch {
            Write-Log "Function: Test-AllDetectionMethods | $method : Method failed with error: $_" "ERROR"
            $results[$method] = "ERROR"
        }
    }
    
    # Summary
    #Write-Log "========================================="
    Write-Log "Function: Test-AllDetectionMethods | Detection Methods Summary for $AppName" "INFO"
    #Write-Log "========================================="
    
    $successfulMethods = @()
    $failedMethods = @()
    
    foreach ($method in $results.Keys) {
        if ($results[$method] -eq $true) {
            $successfulMethods += $method
        } elseif ($results[$method] -eq $false) {
            $failedMethods += $method
        }
    }
    
    if ($successfulMethods.Count -gt 0) {
        Write-Log "Function: Test-AllDetectionMethods | End | $AppName was detected. Methods that detected: $($successfulMethods -join ', ')" "WARNING"
        Write-Log "========================================="
        Return $True
    } else {

        Write-Log "Function: Test-AllDetectionMethods | End | No detections of $AppName" "SUCCESS"
        Write-Log "========================================="
        Return $False
    }
    
    # if ($failedMethods.Count -gt 0) {
    #     Write-Log "Methods that did NOT detect the app: $($failedMethods -join ', ')" "INFO"
    #     Write-Log "========================================="
    #     #Return

    # }
    


    #Write-Log "========================================="
    
    #return $results
}


################################
## Uninstall Method Functions ##
################################

Function Remove-App-MSI-QN([String]$appName)
{
    Write-Log "========================================="
    

    Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"
    Write-Log "Target app: $appName"

    # Check for app
    $appCheck = App-Detector -AppName $AppName -DetectMethod 'UninstallerString'
    
    # If App was found...
    if($appCheck -ne $null){

        Write-Log "Function: $($MyInvocation.MyCommand.Name) | Application Detected. Now running uninstaller for: $($appCheck.DisplayName)" "WARNING"

        # Build uninstall string
        $uninst = $appCheck.UninstallString + " /qn /norestart"
        $UninstallCommand_App = "cmd" 
        $UninstallCommand_Args = "/c $uninst"

        # Run uninstaller
        if((Command-Runner -UninstallCommand_App $UninstallCommand_App -UninstallCommand_Args $UninstallCommand_Args -DetectMethod 'UninstallerString') -eq $true){

            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned success!" "SUCCESS"
            $uninstallSuccess = $True

        } Else {

            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned failure!" "ERROR"
            $uninstallSuccess = $False

        }
    } else {

        Write-Log "Function: $($MyInvocation.MyCommand.Name) | $appName is not installed on this computer!" "WARNING"
        $uninstallSuccess = "NotFound"
    }


    Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"
    Write-Log "========================================="
    if ($uninstallSuccess -eq $True){

        Return $True

    } elseif($uninstallSuccess -eq "NotFound") {

        Return "NotFound"

    } else {

        Return $False

    }
}

Function Remove-App-EXE-SILENT([String]$appName)
{

    Write-Log "========================================="

    Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"
    Write-Log "Target app: $appName"

    # Check for app
    #$appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    $appCheck = App-Detector -AppName $AppName -DetectMethod 'UninstallerString'
    
    # If App was found...
    if($appCheck -ne $null){

        Write-Log "Function: $($MyInvocation.MyCommand.Name) | Application Detected. Now running uninstaller for: $($appCheck.DisplayName)" "WARNING"

        $uninst = $appCheck.UninstallString + " -silent"
        $UninstallCommand_App = "cmd" 
        $UninstallCommand_Args = "/c $uninst"
        

        # Run uninstaller
        if((Command-Runner -UninstallCommand_App $UninstallCommand_App -UninstallCommand_Args $UninstallCommand_Args -DetectMethod 'UninstallerString') -eq $true){

            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned success!" "SUCCESS"
            $uninstallSuccess = $True

        } Else {

            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned failure!" "ERROR"
            $uninstallSuccess = $False

        }

    } else {

        Write-Log "Function: $($MyInvocation.MyCommand.Name) | $appName is not installed on this computer!" "WARNING"
        $uninstallSuccess = "NotFound"
    }


    Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"
    Write-Log "========================================="
    if ($uninstallSuccess -eq $True){

        Return $True

    } elseif($uninstallSuccess -eq "NotFound") {

        Return "NotFound"

    } else {

        Return $False

    }

}

Function Remove-App-CIM([string]$appName)
{
    # This method is like a last resort:
    <#
        When you query Win32_Product, Windows Installer performs a consistency check on ALL installed MSI products on the system, not just the ones you're targeting. This can:
            - Trigger repair operations on other products if Windows Installer detects any issues (missing files, registry keys, etc.)
            - Cause significant delays - it can take several minutes to enumerate all products
            - Generate event logs - you'll see entries in the Application event log for each product being verified
            - Potentially disrupt users - if a repair is triggered, users might see unexpected installer dialogs
    #>

    Write-Log "========================================="

    Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"
    Write-Log "Target app: $appName"

    # Check for app
    #$appcheck = Get-CimInstance -ClassName Win32_Product | Where-Object { $_.Name -like "$Appname*"} | Select-object name
    $appCheck = App-Detector -AppName $AppName -DetectMethod 'CIM'

    # If App was found...
    if($appcheck -ne $null){

        Write-Log "Function: $($MyInvocation.MyCommand.Name) | Application Detected. Now running uninstaller for: $AppName" "WARNING"
        <#
        $uninst = {
            
            Get-CimInstance -ClassName Win32_Product | Where-Object {
                $_.Name -like "*$appName*"
            } | ForEach-Object {
                Invoke-CimMethod -InputObject $_ -MethodName Uninstall
            }

        }

        $UninstallCommand_App = "powershell.exe" 
        $UninstallCommand_Args = "-Command $uninst"
        #>

        $uninstCommand = "Get-CimInstance -ClassName Win32_Product | Where-Object { `$_.Name -like '*$appName*' } | ForEach-Object { Invoke-CimMethod -InputObject `$_ -MethodName Uninstall }"
    
        $UninstallCommand_App = "powershell.exe"
        $UninstallCommand_Args = "-Command `"$uninstCommand`""
        
        # Run uninstaller
        if((Command-Runner -UninstallCommand_App $UninstallCommand_App -UninstallCommand_Args $UninstallCommand_Args -DetectMethod 'CIM') -eq $true){
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned success!" "SUCCESS"
            $uninstallSuccess = $True
            
        } Else {
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned failure!" "ERROR"
            $uninstallSuccess = $False
            
        }


    }else{
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | $appName is not installed on this computer!" "WARNING"
        $uninstallSuccess = "NotFound"
    }


    Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"
    Write-Log "========================================="
    if ($uninstallSuccess -eq $True){

        Return $True

    } elseif($uninstallSuccess -eq "NotFound") {

        Return "NotFound"

    } else {

        Return $False

    }
    
}

Function Remove-App-EXE-S([String]$appName)
{
    Write-Log "========================================="
    Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"
    Write-Log "Target app: $appName"

    # Check for app
    $appCheck = App-Detector -AppName $AppName -DetectMethod 'UninstallerString'
    
    # If App was found...
    if($appCheck -ne $null){
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | Application Detected. Now running uninstaller for: $($appCheck.DisplayName)" "WARNING"

        # Build uninstall string with /S flag (capital S)
        $uninst = $appCheck.UninstallString + " /S"
        $UninstallCommand_App = "cmd" 
        $UninstallCommand_Args = "/c $uninst"

        # Run uninstaller
        if((Command-Runner -UninstallCommand_App $UninstallCommand_App -UninstallCommand_Args $UninstallCommand_Args -DetectMethod 'UninstallerString') -eq $true){
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned success!" "SUCCESS"
            $uninstallSuccess = $True
        } Else {
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned failure!" "ERROR"
            $uninstallSuccess = $False
        }
    } else {
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | $appName is not installed on this computer!" "WARNING"
        $uninstallSuccess = "NotFound"
    }


    Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"
    Write-Log "========================================="
    if ($uninstallSuccess -eq $True){

        Return $True

    } elseif($uninstallSuccess -eq "NotFound") {

        Return "NotFound"

    } else {

        Return $False

    }
}

# UNTESTED
Function Remove-App-MSI_EXE-Quiet([String]$appName)
{

    Write-Log "========================================="

    Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"
    Write-Log "Target app: $appName"

    ## Will remove once tested
    Write-Log "THIS METHOD IS UNTESTED." "WARNING"

    if ($UninstallType -eq 'All'){

        Write-Log "SKIPPING METHOD" "WARNING"
        Write-Log "========================================="

        Return "Skipped"

    } else {

        Write-Log "Method requested anyways, continuing" "WARNING"
    }
    ##

    #$appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    $appCheck = App-Detector -AppName $AppName -DetectMethod 'UninstallerString'

    
    if($appCheck -ne $null){

        Write-Log "Function: $($MyInvocation.MyCommand.Name) | Application Detected. Now running uninstaller for: $($appCheck.DisplayName)" "WARNING"

        #Write-Log "Uninstalling "$appCheck.DisplayName
        $uninst = $appCheck.UninstallString +  " /qn /restart"
        $UninstallCommand_App = "cmd" 
        $UninstallCommand_Args = "/c $uninst"

        # Run uninstaller
        if((Command-Runner -UninstallCommand_App $UninstallCommand_App -UninstallCommand_Args $UninstallCommand_Args -DetectMethod 'UninstallerString') -eq $true){

            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned success!" "SUCCESS"
            $uninstallSuccess = $True

        } Else {

            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned failure!" "ERROR"
            $uninstallSuccess = $False

        }

    }
    else{

        Write-Log "Function: $($MyInvocation.MyCommand.Name) | $appName is not installed on this computer!" "WARNING"
        $uninstallSuccess = "NotFound"
    }


    Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"
    Write-Log "========================================="
    if ($uninstallSuccess -eq $True){

        Return $True

    } elseif($uninstallSuccess -eq "NotFound") {

        Return "NotFound"

    } else {

        Return $False

    }

}

# UNTESTED
Function Remove-App-MSI_EXE-S([String]$appName)
{

    Write-Log "========================================="

    Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"
    Write-Log "Target app: $appName"

    ## Will remove once tested
    Write-Log "THIS METHOD IS UNTESTED." "WARNING"

    if ($UninstallType -eq 'All'){

        Write-Log "SKIPPING METHOD" "WARNING"
        Write-Log "========================================="

        Return "Skipped"

    } else {

        Write-Log "Method requested anyways, continuing" "WARNING"
    }
    ##

    #$appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    $appCheck = App-Detector -AppName $AppName -DetectMethod 'UninstallerString'

    
    if($appCheck -ne $null){

        Write-Log "Function: $($MyInvocation.MyCommand.Name) | Application Detected. Now running uninstaller for: $($appCheck.DisplayName)" "WARNING"

        $uninst = $appCheck.UninstallString +  " /S"

        $UninstallCommand_App = "cmd" 
        $UninstallCommand_Args = "/c $uninst"
        

        # Run uninstaller
        if((Command-Runner -UninstallCommand_App $UninstallCommand_App -UninstallCommand_Args $UninstallCommand_Args -DetectMethod 'UninstallerString') -eq $true){

            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned success!" "SUCCESS"
            $uninstallSuccess = $True

        } Else {

            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned failure!" "ERROR"
            $uninstallSuccess = $False

        }




    }
    else{
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | $appName is not installed on this computer!" "WARNING"
        $uninstallSuccess = "NotFound"
    }


    Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"
    Write-Log "========================================="
    if ($uninstallSuccess -eq $True){

        Return $True

    } elseif($uninstallSuccess -eq "NotFound") {

        Return "NotFound"

    } else {

        Return $False

    }

}

# UNTESTED
Function Remove-App-EXE-S-QUOTES([String]$appName)
{
    Write-Log "========================================="
    Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"
    Write-Log "Target app: $appName"

    ## Will remove once tested
    Write-Log "THIS METHOD IS UNTESTED." "WARNING"

    if ($UninstallType -eq 'All'){

        Write-Log "SKIPPING METHOD" "WARNING"
        Write-Log "========================================="
        Return "Skipped"

    } else {

        Write-Log "Method requested anyways, continuing" "WARNING"
    }
    ##
    
    #$appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    $appCheck = App-Detector -AppName $AppName -DetectMethod 'UninstallerString'

    if($appCheck -ne $null){

        Write-Log "Function: $($MyInvocation.MyCommand.Name) | Application Detected. Now running uninstaller for: $($appCheck.DisplayName)" "WARNING"
        $uninst ="`""+$appCheck.UninstallString+"`"" + " /S"
        $UninstallCommand_App = "cmd" 
        $UninstallCommand_Args = "/c $uninst"

        # Run uninstaller
        if((Command-Runner -UninstallCommand_App $UninstallCommand_App -UninstallCommand_Args $UninstallCommand_Args -DetectMethod 'UninstallerString') -eq $true){
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned success!" "SUCCESS"
            $uninstallSuccess = $True
        } Else {
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned failure!" "ERROR"
            $uninstallSuccess = $False
        }

    }
    else{
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | $appName is not installed on this computer!" "WARNING"
        $uninstallSuccess = "NotFound"
    }


    Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"
    Write-Log "========================================="
    if ($uninstallSuccess -eq $True){

        Return $True

    } elseif($uninstallSuccess -eq "NotFound") {

        Return "NotFound"

    } else {

        Return $False

    }

}

# TESTED
Function Remove-AppxPackage([String]$appName){

    # I may need to break this in to 2 seperate functions.

    Write-Log "========================================="
    

    Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"
    Write-Log "Target app: $appName"


    ## Will remove once tested
    Write-Log "THIS METHOD IS UNTESTED." "WARNING"

    if ($UninstallType -eq 'All'){

        Write-Log "SKIPPING METHOD" "WARNING"
        Write-Log "========================================="

        Return "Skipped"

    } else {

        Write-Log "Method requested anyways, continuing" "WARNING"
    }
    ##

    Write-Log "Part 1 / 2: Checking for AppxPackage for $AppName"
    $appCheck = App-Detector -AppName $AppName -DetectMethod 'AppxPackage'
    #$app = Get-AppxPackage -AllUsers $appName
    $uninstallSuccess1 = $False

    if($appCheck -ne $null){

        Write-Log "Function: $($MyInvocation.MyCommand.Name) | Application Detected as a AppxPackage. Now running uninstaller for: $AppName" "WARNING"

        [string]$packageFullName = $appCheck.PackageFullName

        Write-Log "Detected PackageFullName: $packageFullName"

        if([string]$packageFullName -Match " ") { # So for some reason I was getting "Microsoft.MicrosoftOfficeHub_19.2601.41041.0_arm64__8wekyb3d8bbweMicrosoft.MicrosoftOfficeHub_19.2601.46121.0_arm64__8wekyb3d8bbwe"... So just gonna add this check as a fail safe
            # $packageFullName = $appCheck.name
            $packageFullName = $packageFullName.Split(" ")[0]
            Write-Log "Adjusted PackageFullName due to space issue: $packageFullName"
        }

        Write-Log "Using PackageFullName: $packageFullName"

        #Remove-AppxPackage -package $packageFullName -AllUsers

        $UninstallCommand_App = "powershell.exe" 
        $uninstCommand = "Remove-AppxPackage -package $packageFullName -AllUsers"
        $UninstallCommand_Args = "-Command `"$uninstCommand`""


        if((Command-Runner -UninstallCommand_App $UninstallCommand_App -UninstallCommand_Args $UninstallCommand_Args -DetectMethod 'AppxPackage') -eq $true){
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner for AppxPackage returned success, PART 1 / 2" "SUCCESS"
            $uninstallSuccess1 = $True
            
        } Else {
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner for AppxPackage returned failure, PART 1 / 2" "ERROR"
            $uninstallSuccess1 = $False
            
        }

    }
    else{
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | $appName as a AppxPackage is not installed on this computer!" "WARNING"
        $uninstallSuccess1 = "NotFound"
    }


    
    Write-Log "Part 2 / 2: Checking for AppxProvisionedPackage for $appName"
    $provApp = Get-AppxProvisionedPackage -Online 
    $proPackageFullName = (Get-AppxProvisionedPackage -Online | where {$_.Displayname -eq $appName}).DisplayName
    $appCheck2 = App-Detector -AppName $AppName -DetectMethod 'AppxProvisionedPackage'
    $uninstallSuccess2 = $False

    $uninstall2needed = $false
    if($appCheck2 -ne $null){

        $uninstall2needed = $True
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | Application Detected as a AppxProvisionedPackage. Now running uninstaller for: $AppName" "WARNING"

        $UninstallCommand_App = "powershell.exe" 
        $uninstCommand = "Remove-AppxProvisionedPackage -online -packagename $proPackageFullName -AllUsers"
        $UninstallCommand_Args = "-Command `"$uninstCommand`""

        #Remove-AppxProvisionedPackage -online -packagename $proPackageFullName -AllUsers

        if((Command-Runner -UninstallCommand_App $UninstallCommand_App -UninstallCommand_Args $UninstallCommand_Args -DetectMethod 'AppxProvisionedPackage') -eq $true){
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner for AppxProvisionedPackage returned success, PART 2 / 2" "SUCCESS"
            $uninstallSuccess2 = $True
            
        } Else {
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner for AppxProvisionedPackage returned failure, PART 2 / 2" "ERROR"
            $uninstallSuccess2 = $False
            
        }
        
    } else {

        Write-Log "Function: $($MyInvocation.MyCommand.Name) | $appName as a AppxProvisionedPackage is not installed on this computer!" "WARNING"
        $uninstallSuccess2 = "NotFound"

    }

    Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"
    Write-Log "========================================="
    

    # Evaluate results
    if($uninstallSuccess1 -eq $true -and $uninstallSuccess2 -eq $true){

        Return $True

    }elseif($uninstall2needed -eq $false -and $uninstallSuccess1 -eq $true){

        Return $True

    } elseif ($uninstallSuccess1 -eq "NotFound" -and $uninstallSuccess2 -eq "NotFound"){

        Return "NotFound"

    } else {

        Return $False

    } 
}

# TESTED
Function Remove-App-WinGet([String]$appName){

    Write-Log "========================================="
    Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"
    Write-Log "Target app: $appName"

    $appCheck = App-Detector -AppName $AppName -DetectMethod 'Win_Get'

    # If App was found...
    if($appCheck -eq $True){

        Write-Log "Function: $($MyInvocation.MyCommand.Name) | Application Detected. Now running uninstaller for: $AppName" "WARNING"


        #winget uninstall --id "$AppName" --exact --silent --accept-package-agreements --accept-source-agreements

        # $UninstallCommand_App = "powershell.exe" 
        # $uninstCommand = "winget uninstall --id '$AppName' --exact --silent --accept-package-agreements --accept-source-agreements"
        # $UninstallCommand_Args = "-Command `"$uninstCommand`""

        ##

        # Santitize the name of the log path

        if($Version -eq $null -or $Version -eq ""){

            $UninstallCommand_Args = "uninstall --id $AppName --exact --silent --accept-source-agreements --disable-interactivity --all-versions --force"

        }else{

            $UninstallCommand_Args = "uninstall --id $AppName --exact --silent --accept-source-agreements --disable-interactivity --version $Version --force"
        }

        $UninstallCommand_App = $WinGet

        #Write-Log "Executing command: $cmd $args"

        # Write-Log "Installation Output log for $AppName located at: $UninstallationOutputLog"
        # Write-Log "Installation Error log for $AppName located at: $UninstallationErrorLog"
        

        #$proc = Start-Process -FilePath $cmd -ArgumentList $args -NoNewWindow -PassThru 
        
        #-RedirectStandardOutput "$UninstallationOutputLog" -RedirectStandardError "$UninstallationErrorLog"
        #$proc = Start-Process -FilePath $cmd -ArgumentList $args -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$InstallationOutputLog" -RedirectStandardError "$InstallationErrorLog"


        ##
        # Run uninstaller
        if((Command-Runner -UninstallCommand_App $UninstallCommand_App -UninstallCommand_Args $UninstallCommand_Args -DetectMethod 'Win_Get') -eq $true){
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned success!" "SUCCESS"
            $uninstallSuccess = $True
        } Else {
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned failure!" "ERROR"
            $uninstallSuccess = $False
        }


    } elseif($appCheck -eq "AppIDinvalid") {

        Write-Log "Function: $($MyInvocation.MyCommand.Name) | $appName could not be found because the AppID is not valid" "ERROR"
        $uninstallSuccess = "AppIDinvalid"

    } else {
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | $appName is not installed on this computer!" "WARNING"
        $uninstallSuccess = "NotFound"
    }


    Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"
    Write-Log "========================================="
    if ($uninstallSuccess -eq $True){

        Return $True

    } elseif($uninstallSuccess -eq "NotFound") {

        Return "NotFound"

    } else {

        Return $False

    }

}

# UNTESTED
Function Remove-App-MSI-I-QN([String]$appName)
{
    Write-Log "========================================="
    Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"
    Write-Log "Target app: $appName"

        ## Will remove once tested
    Write-Log "THIS METHOD IS UNTESTED." "WARNING"

    if ($UninstallType -eq 'All'){

        Write-Log "SKIPPING METHOD" "WARNING"
        Write-Log "========================================="

        Return "Skipped"

    } else {

        Write-Log "Method requested anyways, continuing" "WARNING"


    }
    ##


    #$appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    $appCheck = App-Detector -AppName $AppName -DetectMethod 'UninstallerString'

    if($appCheck -ne $null){

        $uninst = $appCheck.UninstallString.Replace("/I","/X") + " /qn /norestart"
        cmd /c $uninst
        
        $uninst = $appCheck.UninstallString +  " /S"
        $UninstallCommand_App = "cmd" 
        $UninstallCommand_Args = "/c $uninst"

        # Run uninstaller
        if((Command-Runner -UninstallCommand_App $UninstallCommand_App -UninstallCommand_Args $UninstallCommand_Args -DetectMethod 'UninstallerString') -eq $true){

            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned success!" "SUCCESS"
            $uninstallSuccess = $True

        } Else {

            Write-Log "Function: $($MyInvocation.MyCommand.Name) | Uninstall runner returned failure!" "ERROR"
            $uninstallSuccess = $False

        }



    }
    else{
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | $appName is not installed on this computer!" "WARNING"
        $uninstallSuccess = "NotFound"
    }


    Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"
    Write-Log "========================================="
    if ($uninstallSuccess -eq $True){

        Return $True

    } elseif($uninstallSuccess -eq "NotFound") {

        Return "NotFound"

    } else {

        Return $False

    }
    

}

<#
Function Remove-AppxPackage([String]$appName){
    Write-Log "Now starting: $($MyInvocation.MyCommand.Name)"
    Write-Log "Target app: $appName"

    $app = Get-AppxPackage -AllUsers $appName
    if($app -ne $null){
        $packageFullName = $app.PackageFullName
        Write-Log "Uninstalling $appName"
        Remove-AppxPackage -package $packageFullName -AllUsers
        $provApp = Get-AppxProvisionedPackage -Online 
        $proPackageFullName = (Get-AppxProvisionedPackage -Online | where {$_.Displayname -eq $appName}).DisplayName
        if($proPackageFillName -ne $null){
            Write-Log "Uninstalling provisioned $appName"
            Remove-AppxProvisionedPackage -online -packagename $proPackageFullName -AllUsers
        }
    }
    else{
        Write-Log "$appName is not installed on this computer!!!!!!" "WARNING"
    }

    ""

}

Function Remove-App-M365([String]$appName)
{
    Write-Log "Now starting: $($MyInvocation.MyCommand.Name)"
    Write-Log "Target app: $appName"
    
    $uninstall = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like $appName} | Select UninstallString)
    if($uninstall -ne $null){
        Write-Log "Uninstalling $appName"
        $uninstall = $uninstall.UninstallString + " DisplayLevel=False"
        cmd /c $uninstall
    }
    else{
        Write-Log "$appName is not installed on this computer!!!!!!!" "WARNING"
    }

    ""

}

Function Check-UninstallString([String]$appName)
{
    Write-Log "Now starting: $($MyInvocation.MyCommand.Name)"
    Write-Log "Target app: $appName"
    
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($appCheck -ne $null){
        Write-Log $appCheck.DisplayName $appCheck.UninstallString
    }
    else{
        Write-Log "$appName is not installed on this computer!!!!!!!!" "WARNING"
    }

    ""

}



# NEEDS TESTING
Function Remove-App-CIM([string]$appName)
{

    Write-Log "Now starting: $($MyInvocation.MyCommand.Name)"
    Write-Log "Target app: $appName"

    $appcheck = Get-CimInstance -ClassName Win32_Product | Where-Object { $_.Name -like "$Appname*"} | Select-object name
    if($appcheck -ne $null){
        Write-Log "Uninstalling $appName"
        Get-CimInstance -ClassName Win32_Product | Where-Object {
            $_.Name -like "*$appName*"
        } | ForEach-Object {
            Invoke-CimMethod -InputObject $_ -MethodName Uninstall
        }
    } 
    else{
        Write-Log "$appName is not installed on this computer!!!!!!!!!!" "WARNING"
    }

    ""
}

#>

#####################################################
## Uninstall Methods to test and add in the future ##
#####################################################

<#

Function Remove-App-WinGet{}

function Remove-App-GetPackage {

    $package = Get-Package -Name "*$appName*" -Provider msi -ErrorAction SilentlyContinue
    if ($package) {
        $package | Uninstall-Package -Force
    }

}

function Remove-App-CIM3{

    # Less problematic, but not available on all systems
    Get-CimInstance -ClassName Win32_InstalledWin32Program | 
    Where-Object {$_.Name -like "*$appName*"}
}

#>

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
    'InstallWinGetScript' = $InstallWinGetScript
}
Test-PathSyntaxValidity -Paths $pathsToValidate -ExitOnError
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"



Write-Log "===== General Uninstallation Script ====="

Write-Log "TARGET APP: $AppName"
Write-Log "TARGET UNINSTALL METHOD: $UninstallType"
Write-Log "LOG PATH: $LogPath"
Write-Log "VERBOSE LOGGING ENABLED: $VerboseLogs"
Write-Log "SUPERIOR ERROR CATCHING LOGIC: $SupremeErrorCatching"
Write-Log "WORKING DIRECTORY: $WorkingDirectory"
Write-Log "WinGetID: $WinGetID"
Write-Log "UninstallString DisplayName: $UninstallString_DisplayName"

Write-Log "========================================="

## Function invoke

# List available uninstall functions
$methods = Get-Command -CommandType Function -Name "Remove-App*" | Select-Object -ExpandProperty Name


# If reporting is verbose, just spit out the available methods
if ($VerboseLogs -eq $True){

    Write-Log "Available uninstall methods:" "INFO"
    
    $methods | ForEach-Object { Write-Log "  - $_" "INFO" }

    Write-Log "You may also use -UninstallType 'All' to run through all these methods"
    Write-Log "========================================="

}

# TODO: I might be able to remove this snippet now
# Check for missing requirements
if ([string]::IsNullOrEmpty($AppName) -or [string]::IsNullOrEmpty($UninstallType)){

    Write-Log "SCRIPT: $ThisFileName | END | Missing required input parameters. Now exiting script." "ERROR"
    Exit 1

}

# Check if WinGet is required
if ($UninstallType -eq 'All' -or $UninstallType -eq 'Win_Get' -or $UninstallType -eq 'Remove-App-WinGet') {

    Write-Log "WinGet uninstall/detect method has been requested. Now checking/installing WinGet."
    $WinGet = & $InstallWinGetScript -ReturnWinGetPath:$True -WorkingDirectory $WorkingDirectory
    if ($LASTEXITCODE -ne 0) { Write-Log "Could not verify or install WinGet. Check the Install WinGet log. Last exit code: $LASTEXITCODE" "ERROR"; Exit 1}

}

# Consolidate AppName parameter
# TODO: Check if both are provided and log a warning if so
if($WinGetID -ne $null -and $WinGetID -ne ""){

    Write-Log "Using WinGetID parameter for uninstall method"
    $AppName = $WinGetID

} else {

    Write-Log "WinGetID not provided.Using supplied AppName parameter for uninstall method for WinGet if requested."
}

if($UninstallString_DisplayName -ne $null -and $UninstallString_DisplayName -ne ""){

    Write-Log "Using UninstallString DisplayName parameter for uninstall method"
    $AppName = $UninstallString_DisplayName

} else {

    Write-Log "UninstallString_DisplayName not provided. Using supplied AppName parameter for uninstall method for UninstallString if requested."
}




Write-Log "Final string for uninstall methods: $AppName"

Write-Log "Now beginning work."

# Check if the function is legit first
if ($Methods -contains $UninstallType) {

    Write-Log "Requested uninstall method found: $UninstallType"

    Write-Log "Attempting to call this method."
    $result = & $UninstallType -appName $AppName
    
    # Now run the uninstaller!!
    if ($result -eq $True) {
        Write-Log "Uninstallation completed successfully using the called method ($UninstallType)" "SUCCESS"
        $uninstallSuccess = $True
    } Elseif($Result -eq "NotFound"){

        Write-Log "App $AppName not found during uninstall method ($UninstallType)" "WARNING"

    } else {
        Write-Log "Uninstallation failed using the called method ($UninstallType) failed. Return message: $Result" "ERROR"
        $uninstallSuccess = $False
    }

# If the method is set to 'All', run through all available methods...
} elseif ($UninstallType -eq 'All') {


    Write-Log "Attempting to do all uninstall methods." "WARNING"
    $successfulMethods = @()

    #$methods | ForEach-Object { Write-Log "  - $_" "INFO" }
    Foreach ($ChosenMethod in $Methods){

        Write-Log "Attempting to call uninstall method: $ChosenMethod"
        $result = & $ChosenMethod -appName $AppName

            if ($result -eq $True) {
                Write-Log "Uninstallation completed successfully with method $ChosenMethod" "SUCCESS"
                $successfulMethods += $ChosenMethod
                $uninstallSuccess = $True

            } Elseif($Result -eq "NotFound"){

                Write-Log "App $AppName not found during uninstall method ($ChosenMethod)" "WARNING"

                
            } Elseif($Result -eq "Skipped"){

                Write-Log "Uninstall method $ChosenMethod was skipped" "WARNING"

            }else {
                Write-Log "Uninstallation attempt with $ChosenMethod failed. Received result: $Result" "ERROR"
                
            }
        Write-Log "Moving to next method."
        Write-Log "========================================="


    }

    if ($successfulMethods.Count -gt 0) {
        Write-Log "Succeeded with methods: $($successfulMethods -join ', ')" "SUCCESS"
    }

    Write-Log "End of available methods."
    Write-Log "========================================="


# If no matching methods...
} else {

    Write-Log "Unknown or undefined uninstall type: $UninstallType" "ERROR"
    # Write-Log "Available methods: Remove-App-MSI-QN" "INFO"

    Write-Log "Available uninstall methods:" "INFO"
    #$methods | ForEach-Object { Write-Log "  - $_" "INFO" }

    $methods | ForEach-Object { Write-Log "  - $_" "INFO" }

    Write-Log "========================================="

    Write-Log "SCRIPT: $ThisFileName | END | Uninstallation of $AppName failed!" "ERROR"
    exit 1


}



# Return final verdict with appropriate exit code]

# TODO: Return a final ultra check using all methods
Write-Log "SCRIPT: $ThisFileName | FINAL CHECK for app: $AppName using script: $AppDetectionScriptPath"
if (!($packageFullName)) {
    $packageFullName = $null
}
# NOTE: Using the external detection script for the final check, was having issues with the internal function and this is the direction we need to go anyways.
& $AppDetectionScriptPath -AppToDetect $AppName -DetectMethod 'All' -AppID $WinGetID -DisplayName $UninstallString_DisplayName -AppXpackageName $packageFullName -WorkingDirectory $WorkingDirectory

# if((Test-AllDetectionMethods -AppName $AppName) -eq $True){
if($LASTEXITCODE -eq 0){
    
    Write-Log "Detect all method found the target app" "ERROR"
    $uninstallSuccess = $False

} else {

    Write-Log "Detect all method did NOT find the target app" "SUCCESS"
    
    If ($uninstallSuccess -eq $False){

        $NeverInstalled = $true

        $uninstallSuccess = $True

    }


}

Write-Log "========================================="


Write-Log "Final Verdict:"
If($uninstallSuccess -eq $True){

    if ($neverInstalled -eq $True){

        Write-Log "SCRIPT: $ThisFileName | END | $AppName was never installed to begin with! Returning success code!" "WARNING"

    } Else {

        Write-Log "SCRIPT: $ThisFileName | END | Uninstallation of $AppName successful!" "SUCCESS"

    }
    
    exit 0

} else {

    Write-Log "SCRIPT: $ThisFileName | END | Uninstallation of $AppName failed!" "ERROR"
    exit 1

}