# This is a modified version of the Check/Install WinGet script and is to be used for running detections on InTune.

# TODO: Have this script use local repo WinGet functions?

## Vars

Param(

    [string]$AppToDetect,# = "Dell Command Update", # ENTER THE NICK NAME OF THE APPLICATION TO DETECT HERE    
    [Parameter(Mandatory=$true)]
    [string]$WorkingDirectory, # This is one of the few scripts that needs this param explicitly set. It is ran independently from InTune and doesn't inherit this param from anywhere.
    [string]$AppID,# = "Dell.CommandUpdate", # ENTER THE EXACT WINGET APP ID HERE
    [String]$DisplayName,# = "Dell Command Update", # ENTER THE DISPLAY NAME TO SEARCH FOR IN REGISTRY OR AppXProvisionedPackage HERE,
    [String]$AppXpackageName, # ENTER THE EXACT APPX PACKAGE NAME HERE

    [String]$DetectMethod# = "WinGet" # Possible values: "WinGet", "MSI_Registry"

)


$forcemachinecontext=$false
# $ReturnWinGetPath=$False # I don't remember why I had this here...


$LocalRepoPath = "$WorkingDirectory\$RepoNickName"
$LogRoot = "$WorkingDirectory\Logs\Detection_Logs"
$LogPath = "$LogRoot\DetectionScript-WinGet_$AppToDetect._Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ThisFileName = $MyInvocation.MyCommand.Name



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

Function TestWinGet {

    Try {

        Write-Log "Current WinGet command: $WinGet"
        $whoami = [Environment]::UserName
        Write-Log "Current user: $whoami"
        Write-Log "Running test..."
        #& $WinGet --info --accept-source-agreements| out-null
        & $winget search "7zip.7zip" --accept-source-agreements | out-null # this function will force accept of source agreements
        Write-Log "WinGet working at target destination."
        Return $True

    } catch {

        Write-Log "WinGet not working. Error: $_" "WARNING"
        Return "WinGet not working. Error: $_"

    }


}

# TODO: Could I just use the pre-existing script for WinGet install or does this script really need to be fully independent?
Function Check-WinGet{

    # TODO: I should turn this into sub-functions...

    #$NeedToInstallWinGet = $False


    # Determine if/where WinGet is 
    
    # Default path
        Write-Log "--- Checking if WinGet exists in PATH ---"
        Try {

            $winget = "winget.exe"
            $Test = TestWinGet
            if ($Test -ne $True){Throw $Test}


        } Catch {

            Write-Log "WinGet not accessible via path. Error: $_"
            # Write-Log "Assumed that it is not installed. Proceeding to install."
            # $NeedToInstallWinGet = $True
        }

    # Program Files location
        Write-Log "--- Checking if WinGet exists in Program Files location ---"
        $WinGetSystemFilesLocation = $Null
        $ProgramFilesLocationSuccess = $False
        Try {

                $resolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe"
                
                if ($resolveWingetPath) {
                    $wingetPath = $resolveWingetPath[-1].Path
                    $wingetPath = $wingetPath + "\winget.exe"
                    Write-Log "Found WinGet path: $wingetPath"
                    $winget = $wingetPath

                    $Test = TestWinGet
                    if ($Test -ne $True){Throw $Test} else {

                        Write-Log "WinGet is present and working in Program Files at: $winget"
                        $WinGetSystemFilesLocation = $Winget
                        $ProgramFilesLocationSuccess = $True

                    }

                
                } else {

                    Throw "Could not resolve WinGet path."

                }

        } Catch {

            Write-Log "WinGet at Program Files location could not be used. This could be because access to the path was denied. Return message: $_" "WARNING"

        }

    # AppData location
        Write-Log "--- Checking if WinGet exists in an AppData location ---"
        $AppDataLocationSuccess = $False
        $AppDataSuccessfulPaths = @()
        Try {

            # Paths to test
            $WinGetPaths = @(
                "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe",
                "$env:LOCALAPPDATA\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe"
            )

            ForEach ($WinGetPath in $WinGetPaths) {

                Write-Log "Testing WinGet path at: $WinGetPath"
                
                Try {

                    if (Test-Path ($WinGetPath)) {

                        Write-Log "Confirmed WinGet exists at: $WinGetPath"
                        Write-Log "Now checking if this path is callable"

                        $WinGet = $WinGetPath
                        $Test = TestWinGet
                        if ($Test -ne $True){
                            
                            Throw "WinGet found at $WinGetPath but not working: $Test"
                        
                        } else {

                            Write-Log "Confirmed this path for WinGet is callable: $WinGetPath"
                            $AppDataSuccessfulPaths += $WinGetPath
                            $AppDataLocationSuccess = $True

                        }


                    } else {

                        Throw "Could not find WinGet at $WinGetPath"
                    }

                } Catch {

                    Write-Log "Could not use path: $WinGetPath"
                    Write-Log "Error received: $_"

                }



            }

            if ($AppDataLocationSuccess -eq $False){

                Throw "No successful paths"

            } else {

                Write-Log "Here are your successful AppData paths for WinGet: $AppDataSuccessfulPaths"

            }
        } Catch {

            Write-Log "Could not resolve any AppData paths for WinGet. Error message: $_" "WARNING"

        }

    # NEEDS TESTING
    # This snippet will attempt to have WinGet run as System. Currently can't fully test because a bunch of Microsoft services are offline (10/29/25)
        <#
        Write-Log "--- Attempting to run as System ---"

        # TODO: I need to add proper logging
        $RunAsSystemSuccess = $False
        Try {

            Write-Log "Installing module: Invoke-CommandAs"
            Write-Log "Installing pre-reqs first."

            # Check your current PowerShellGet version
            $CurrentPSgetVer = Get-Module -Name PowerShellGet -ListAvailable | Select-Object "Version"
            Write-Log "Current PowerShellGet version: $CurrentPSgetVer"

            # Update PowerShellGet
            Write-Log "Attempting to update PowerShellGet"
            Install-Module -Name PowerShellGet -Force -AllowClobber

            Write-Log "Installing NuGet" # TODO: I should see if I can swap this out with the dedicated function
            # 1) Install NuGet package provider silently if missing
            if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false
            } else { Write-Log "NuGet already present"}

            Write-Log "Trusting PowerShell Gallery"
            # 2) Trust the PowerShell Gallery to avoid the "Untrusted repository" prompt
            if ((Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -ne 'Trusted') {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            } else {Write-Log "PowerShell Gallery already trusted"}

            Write-Log "Installing module: Invoke-CommandAs"
            # 3) Install the module without prompts
            # Use -Scope CurrentUser if you don't have admin rights; otherwise AllUsers is fine.
            Install-Module -Name Invoke-CommandAs -Repository PSGallery -Force -Confirm:$false -Scope AllUsers

            Write-Log "Attempting to test if WinGet runs" # NEEDS TESTING. Really just need to figure out how to pass vars in and out of this script block.

            Invoke-CommandAs -ScriptBlock {

                    Try {

                        Write-Log "Current WinGet command: $WinGet"
                        $whoami = [Environment]::UserName
                        Write-Log "Current user: $whoami"
                        Write-Log "Running test..."
                        #& $WinGet --info --accept-source-agreements| out-null
                        & $winget search "7zip.7zip" --accept-source-agreements | out-null # this function will force accept of source agreements
                        Write-Log "WinGet working at target destination."
                        Return $True

                    } catch {

                        Write-Log "WinGet not working. Error: $_" "WARNING"
                        Return "WinGet not working. Error: $_"

                    }
            
            
            } -AsSystem

            if ($LASTEXITCODE -ne 0) { Throw $LASTEXITCODE}

        } Catch {

            Write-Log "Failed to use Invoke-CommandAs. Error: $_"

        }
        #>

    # NEEDS TESTING
    # Another snippet that runs as logged in user instead of script runner.
        <#
    
        Write-Log "--- Attempting to run as Windows User ($LoggedInUser) ---"

        $RunAsWindowsUserSuccess = $False
        Try {

            Write-Log "Installing module: Invoke-CommandAs"
            Write-Log "Installing pre-reqs first."

            Write-Log "Installing NuGet"
            # 1) Install NuGet package provider silently if missing
            if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false
            } else { Write-Log "NuGet already present"}

            Write-Log "Trusting PowerShell Gallery"
            # 2) Trust the PowerShell Gallery to avoid the "Untrusted repository" prompt
            if ((Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -ne 'Trusted') {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            } else {Write-Log "PowerShell Gallery already trusted"}

            Write-Log "Installing module: Invoke-CommandAs"
            # 3) Install the module without prompts
            # Use -Scope CurrentUser if you don't have admin rights; otherwise AllUsers is fine.
            Install-Module -Name Invoke-CommandAs -Repository PSGallery -AcceptLicense -Force -Confirm:$false -Scope AllUsers


            Write-Log "Attempting to test if WinGet runs" # NEEDS TESTING
            Invoke-CommandAs -ScriptBlock { TestWinGet } -AsUser $LoggedInUser


            if ($LASTEXITCODE -ne 0) { Throw $LASTEXITCODE}

        } Catch {

            Write-Log "Failed to use Invoke-CommandAs. Error: $_"

        }

        #>

    # Return failure if nothing works so far
        if ($AppDataLocationSuccess -eq $False -and $ProgramFilesLocationSuccess -eq $False -and $RunAsSystemSuccess -eq $False){

            Write-Log "No Successful intances of WinGet found." "WARNING"
            Return "Failure"

        }

    #Determine if running in system or user context
    Write-Log "--- Checking if script is being ran as System or User ---"
    Try {
    
        if ($env:USERNAME -like "*$env:COMPUTERNAME*" -or $forcemachinecontext -eq $true -or $scriptUser -eq "NT AUTHORITY\SYSTEM") {
            Write-Log "Running in System Context"
            $Context = "Machine"

            if($ProgramFilesLocationSuccess -eq $True){

                # Use Program Files location
                Write-Log "Using ProgramFiles location..."
                $WinGet = $WinGetSystemFilesLocation

            } else {

                Write-Log "ProgramFiles location not available" "WARNING"
                Throw "ProgramFiles location not available"


            }



        } else {

            Write-Log "Running in User Context"
            $Context = "User"


            if ($AppDataLocationSuccess -eq $True){
            
                # Use AppData location primarily...
                Write-Log "Using AppData location..."
                $winget = $AppDataSuccessfulPaths[0] 

            } elseif ($ProgramFilesLocationSuccess -eq $True){

                # Use ProgramFiles location secondarily...
                Write-Log "Using ProgramFiles location..."
                $winget = $WinGetSystemFilesLocation

            } else {

                # Return error if neither are available...
                Write-Log "Neither AppData not ProgamFiles location are available." "WARNING"
                Throw "Neither AppData not ProgamFiles location are available." 

            }

        }

        Write-Log "Final WinGet path: $WinGet"
        Write-Log "Running final check if winget works"
        # Final check?
        $Test = TestWinGet
        if ($Test -ne $True){ 

            return "Failure"

        } else {

            return $WinGet
        }

    } Catch {

        Write-Log "Could not get WinGet running in config for $context context. Error: $_" "WARNING"
        return "Failure"

    }

    

    # default
    #$winget = "winget.exe"



    ###
    # Write-Log "We are going to pretend that WinGet is not working for testing purposes." "WARNING"
    # $Result = $False
    ###

    

}

Function CheckAndInstall-NuGet{

    Write-Log "Installing NuGet"
    # 1) Install NuGet package provider silently if missing
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false
    } else { Write-Log "NuGet already present"}

    Write-Log "Trusting PowerShell Gallery"
    # 2) Trust the PowerShell Gallery to avoid the "Untrusted repository" prompt
    if ((Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    } else {Write-Log "PowerShell Gallery already trusted"}

}

# This is an independent install-winget function to be used in InTune detection scripts or otherwise without having to access the full repo for the sake of full modularity
# TODO: Is it possible to have this function use a local repo instead of redoing everything here?
Function Install-WinGet {

    # Method 1
    Function Install-WinGet-1-AsherotoScript{

        # METHOD: Asheroto installer script
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"

        # Pre Reqs
        Write-Log "Running pre-reqs"
        CheckAndInstall-NuGet

        Try{

            Write-Log "Now installing WinGet via Asheroto script"
            Install-Script -Name winget-install -Force -Scope CurrentUser 2>&1
            # Refresh environment variables
            Start-Sleep 3
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            Start-Sleep 3
            #$result = 
            winget-install -force # More options to try: https://github.com/asheroto/winget-install
            #ForEach ($line in $result) { Write-Log "WINGET-INSTALL: $line" } #; if ($LASTEXITCODE -ne 0) {Write-Log "SCRIPT: $ThisFileName | END | Failed. Exit code: $LASTEXITCODE" "ERROR"; Exit 1 }

            Write-Log "WinGet installed successfully."

        } Catch {
            
            Write-Log "Provisioning failed: $_" "ERROR"
            throw "$_"

        }

        # Start-Sleep -Seconds 5
        # $winget = Get-WingetPath
    }

    # Method 2
    Function Install-WinGet-2-Offline-installer--Add-AppxProvisionedPackage-Online{
        # TODO: NEEDS TESTING
        # METHOD: Offline-installer--Add-AppxProvisionedPackage-Online 
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"

        try {

            Write-Log "Attempting to provision App Installer (offline)..."
            $temp = join-path $WorkingDirectory "Temp\AppInstaller"
            #y$temp = Join-Path $env:TEMP "AppInstaller"
            $Temp
            Write-Log 'Attempting to do this: New-Item $temp @newItemSplat'
            New-Item -path $temp -ItemType "Directory" -Force
            Write-Log 'Attempting to do this: $bundle = Join-Path $temp "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"'
            $bundle = Join-Path $temp "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
            
            # Use official shortlink which redirects to the current App Installer bundle
            Write-Log 'Invoking web requesty'
            $url = "https://aka.ms/getwinget"
            Invoke-WebRequest -Uri $url -OutFile $bundle -UseBasicParsing

            Add-AppxProvisionedPackage -Online -PackagePath $bundle -SkipLicense | Out-Null
            Write-Log "Provisioned App Installer."

        } catch {

            #throw "Provisioning failed: $($_.Exception.Message)"
            Write-Log "Provisioning failed: $_" "ERROR"
            throw "$_"

        }

    }

    # Method 3
    Function Install-WinGet-3-AppXpackage-latestWingetMsixBundle{
    
        # TODO: NEEDS TESTING
        # AppXpackage from latestWingetMsixBundle. SOURCE: https://stackoverflow.com/questions/74166150/install-winget-by-the-command-line-powershell
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"

        Try {
            $progressPreference = 'silentlyContinue'
            $latestWingetMsixBundleUri = $(Invoke-RestMethod https://api.github.com/repos/microsoft/winget-cli/releases/latest).assets.browser_download_url | Where-Object {$_.EndsWith(".msixbundle")}
            $latestWingetMsixBundle = $latestWingetMsixBundleUri.Split("/")[-1]
            Write-Log "Downloading winget to artifacts directory..."
            Invoke-WebRequest -Uri $latestWingetMsixBundleUri -OutFile "./$latestWingetMsixBundle"
            Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
            Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
            Add-AppxPackage $latestWingetMsixBundle
        } Catch {

            Write-Log "Provisioning failed: $_" "ERROR"
            throw "$_"

        }
    }

    # Method 4
    Function Install-WinGet-4-OfficialMethod{

        # TODO: NEEDS TESTING
        # Use official MS Sandbox snippet (modified): https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"
        
        # Pre Reqs?
        Write-Log "Running pre-reqs"
        CheckAndInstall-NuGet
        
        Try {
            
            $progressPreference = 'silentlyContinue'
            Write-Log "Installing WinGet PowerShell module from PSGallery..."
            # Install-PackageProvider -Name NuGet -Force | Out-Null
            Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery | Out-Null
            # Write-Host "Using Repair-WinGetPackageManager cmdlet to bootstrap WinGet..."
            # Repair-WinGetPackageManager -AllUsers
            # Write-Host "Done."
            
        } Catch {

            Write-Log "Provisioning failed: $_" "ERROR"
            throw "$_"

        }

    }

    ## Main Mini ##
    $InstallSuccess = $False
    $Counter = 0
    $MethodsToUse = @()
    $methods = Get-Command -CommandType Function -Name "Install-WinGet-*" | Select-Object -ExpandProperty Name
    $methods | ForEach-Object {$MethodsToUse+=$_}
    $max = $MethodsToUse.count
    $counterMax = $max

    # Run each WinGet install method until success
    Do {

        $TargetMethod = $MethodsToUse[$Counter]

        Try {


            Write-Log "--- Now doing: $TargetMethod ---"

            Write-Log "Killing WinGet processes..." # This may not be necessary
            Get-Process winget, AppInstallerCLI -ErrorAction SilentlyContinue | Stop-Process -Force
            Get-Process msiexec -ErrorAction SilentlyContinue | Stop-Process -Force
            taskkill /IM winget.exe /T /F
            taskkill /IM AppInstallerCLI.exe /T /F

            Write-Log "Now running method $TargetMethod"
            & $TargetMethod

            Write-Log "Resolving path of WinGet"
            $WinGet = Check-WinGet

            Write-Log "Testing method: $TargetMethod"
            $result = Check-WinGet
            If ($result -eq $True) {
                $InstallSuccess -eq $True
            } else {
                Throw $Result
            }

        } Catch {

            Write-Log "Failed at install winget method: $TargetMethod with the following error: $_" "WARNING"

        }

        $Counter++
        Write-Log "Counter: $counter / $counterMax"

    } while ($InstallSuccess -eq $False -and $counter -ne $counterMax) 


    If($InstallSuccess -eq $False){

        Write-Log "Could not install WinGet" "ERROR"
        Exit 1

    } else {

        Write-Log "--- Install of WinGet reported success by using method: $TargetMethod ---"

    }


    # Post-Install

        # Prep sources (first-run) and install packages
        Write-Log "Prepping WinGet source"
        $result = & $winget source reset --force | Out-String
        ForEach ($line in $result) { Write-Log "WINGET: $line" } #; if ($LASTEXITCODE -ne 0) {Write-Log "SCRIPT: $ThisFileName | END | Failed. Exit code: $LASTEXITCODE" "ERROR"; Exit 1 }
        $result = & $winget source update | Out-String
        ForEach ($line in $result) { Write-Log "WINGET: $line" } #; if ($LASTEXITCODE -ne 0) {Write-Log "SCRIPT: $ThisFileName | END | Failed. Exit code: $LASTEXITCODE" "ERROR"; Exit 1 }

    Write-Log "Install success"
    Return $WinGet

}

function Detect--MSI-ApplicationInstalled {

    if ($DisplayName -eq $null -or $DisplayName -eq ""){

        # Write-Log "SCRIPT: $ThisFileName | No DisplayName supplied for MSI_Registry detection. Exiting." "WARNING"
        # Return 1

        Write-Log "SCRIPT: $ThisFileName | No DisplayName supplied for MSI_Registry detection. Will attempt to use AppToDetect." "WARNING"
        $DisplayName = $AppToDetect

    }
    
    Write-Log "SCRIPT: $ThisFileName | Searching for application as MSI in registry: $DisplayName"
    
    try {
        # Check both 32-bit and 64-bit registry locations
        $registryPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        
        Write-Log "Checking registry uninstall keys..."
        
        $installedApp = Get-ItemProperty -Path $registryPaths -ErrorAction SilentlyContinue | 
                        Where-Object { $_.DisplayName -like "*$DisplayName*" } | 
                        Select-Object -Property DisplayName, DisplayVersion, Publisher, InstallDate, UninstallString -First 1
        
        if ($installedApp) {
            Write-Log "Application found in registry!" "SUCCESS"
            Write-Log "  Display Name: $($installedApp.DisplayName)"
            if ($installedApp.DisplayVersion) {
                Write-Log "  Version: $($installedApp.DisplayVersion)"
            }
            if ($installedApp.Publisher) {
                Write-Log "  Publisher: $($installedApp.Publisher)"
            }
            if ($installedApp.InstallDate) {
                Write-Log "  Install Date: $($installedApp.InstallDate)"
            }
            
            Write-Log "SCRIPT: $ThisFileName | End | Application ""$DisplayName"" detected in registry" "SUCCESS"
            Write-Log "-----------------------------------------"
            Return 0
        } else {
            #Write-Log "Application not found in registry" "WARNING"
            Write-Log "SCRIPT: $ThisFileName | End | Application ""$DisplayName"" not detected in registry" "WARNING"
            Write-Log "-----------------------------------------"
            Return 1
        }
        
    } catch {
        Write-Log "SCRIPT: $ThisFileName | End | Error checking registry: $_" "ERROR"
        #Write-Log "SCRIPT: $ThisFileName | End"
        Write-Log "-----------------------------------------"
        Return 1
    }
}

Function Detect--WinGetApplicationInstalled {

    if($appID -eq $null -or $AppID -eq ""){

        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | No AppID supplied for WinGet detection. Cannot run WinGet List." "WARNING"
        Return 1

    }

    # Check if WinGet is installed
    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) |Checking if WinGet is installed..."

    $WinGet = Check-WinGet

    # If check failed...
    if ($WinGet -eq "Failure"){
        
        # ...Attempt to install WinGet...
        Write-Log "Failed to confirm WinGet is installed and working. Now proceeding to attempt installing WinGet." "WARNING"
        
        Install-WinGet
        
        $WinGet = Check-WinGet
        if ($WinGet -eq "Failure"){

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END | Failed to confirm WinGet is working after installation. Please investigate." "ERROR"
            Return 1

        }

    }

    Write-Log "WinGet check/install success!! Final location: $WinGet" "SUCCESS"
    Write-Log "--------------------------------------"

    Write-Log "Now attempting to use WinGet to detect app: $AppID"

    $Result = $null
    Try {

        $Result = & $Winget list $AppID -e

        Foreach ($line in $result){Write-Log "WinGet List: $line"}

        if($result -eq $null){
            Throw "No returned valued when running: $WinGet List $AppID -e"
        }
        
        if(!($Result -like "No installed package found matching input criteria.")){
            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END | Application $AppID detected!" "SUCCESS"
            $Result = 0
        }else{
            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END | Application $AppID NOT detected!" "WARNING"
            $Result =  1
        }

    } Catch {

        Write-Log "FUNCTION: $($MyInvocation.MyCommand.Name) | Error encountered when running search: $_" "ERROR"
        $Result =  1

    }

    Return $Result

}

Function Detect--AppXPackageInstalled {

    if ($AppXpackageName -eq $null -or $AppXpackageName -eq ""){

        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | No AppXpackageName supplied for AppXpackage detection. Will attempt to use DisplayName and NickName." "WARNING"

        Try {

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Attempting to use nickname: $AppToDetect"
            $Detection1 = Get-AppxPackage -AllUsers -Name $AppToDetect

        } Catch {

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Error attempting to use nickname: $AppToDetect. Error: $_" "WARNING"
            $Detection1 = $null
        }

        Try {

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Attempting to use DisplayName: $DisplayName"
            $Detection2 = Get-AppxPackage -AllUsers -Name $DisplayName

        } Catch {

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Error attempting to use DisplayName: $DisplayName. Error: $_" "WARNING"
            $Detection2 = $null
        }

        if ($Detection1 -ne $null){

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Application detected by AppXpackageName: $AppToDetect" "SUCCESS"
            Return 0

        } elseif ($Detection2 -ne $null){

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Application detected by DisplayName: $DisplayName" "SUCCESS"
            Return 0

        } else {

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Application NOT detected by AppXpackageName or DisplayName" "WARNING"
            Return 1

        }
        

    } elseif ($AppXpackageName -ne $null -or $AppXpackageName -ne ""){
        
        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Searching for application as AppX package: $AppXpackageName"

        $Detection = Get-AppxPackage -AllUsers -Name$AppXpackageName

        if ($Detection -ne $null){

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Application detected by AppXpackageName: $AppXpackageName" "SUCCESS"
            Return 0

        } else {

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Application NOT detected by AppXpackageName: $AppXpackageName" "WARNING"
            Return 1

        }

    } else {

        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Insufficient parameters for AppXpackage detection." "WARNING"
        Return 1

    }

    



}

# TODO: Bring up to speed with the non provisiond function
Function Detect--AppXProvisionedPackageInstalled {

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Searching for application as AppX Provisioned package: $AppToDetect"

    if ($DisplayName -ne $null -and $DisplayName -ne ""){

        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Attempting detection by DisplayName: $DisplayName"
        $Detection = Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*$DisplayName*"}

        if ($Detection -ne $null){

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Application detected by DisplayName: $DisplayName" "SUCCESS"
            Return 0

        } else {

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Application NOT detected by DisplayName: $DisplayName" "WARNING"
            # Continue to next detection method

        }

    } elseif( $AppToDetect -ne $null -and $AppToDetect -ne ""){

        $Detection = Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -like "*$AppToDetect*"}

        if ($Detection -ne $null){

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Application detected by AppXProvisionedPackage: $AppToDetect" "SUCCESS"
            Return 0

        } else {

            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Application NOT detected by AppXProvisionedPackage: $AppToDetect" "WARNING"
            Return 1

        }

    }




}

Function Detect--CIM {

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Searching for application as CIM instance"

    Try {

        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Attempting detection by AppToDetect: $AppToDetect"
        $Detection1 = Get-CimInstance -ClassName Win32_Product | Where-Object { $_.Name -like "$AppToDetect*"} | Select-object name


        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Attempting detection by DisplayName: $DisplayName"
        $Detection2 = Get-CimInstance -ClassName Win32_Product | Where-Object { $_.Name -like "$DisplayName*"} | Select-object name

    } Catch {

        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Error during CIM detection: $_" "ERROR"
        Return 1

    }

    if ($Detection1 -ne $null -or $Detection2 -ne $null){
        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Application detected by CIM Win32_Product" "SUCCESS"
        Return 0

    } else {

        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Application NOT detected by CIM Win32_Product" "WARNING"
        Return 1

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

if ($UpdateLocalRepoOnly -eq $True){ # I don't remember why I had this condition...

    $pathsToValidate = @{
        'WorkingDirectory' = $WorkingDirectory

    }

} else {

    $pathsToValidate = @{
        'WorkingDirectory' = $WorkingDirectory
    }

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

Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"



#####################
## Begin main body ##
#####################

Write-Log "++++++++++++++++++++++++++++"

Write-Log "SCRIPT: $ThisFileName | START"
Write-Log "++++++++++++++++++++++++++++"

Write-Log "App to detect: $AppName"
Write-Log "WorkingDirectory: $WorkingDirectory"
Write-Log "Force Machine Install Context: $forcemachinecontext"
#Write-Log "Return WinGet Path: $ReturnWinGetPath"
Write-Log "Script User: $scriptUser"
Write-Log "Windows User: $loggedInUser"
Write-Log "Detect Method: $DetectMethod"
Write-Log "WinGet AppID to detect: $AppID"
Write-Log "DisplayName to detect: $DisplayName"

Write-Log "++++++++++++++++++++++++++++"

##  Figure out use case situation ##
Write-Log "SCRIPT: $ThisFileName | Determining script context "
# Am I running as the same account as the Windows session?
if ($scriptUser -eq $loggedInUser) {
    Write-Log "Script is running as the logged-in user: $scriptUser"

    # Am I running as an admin account?
    if ($isAdmin) {
        Write-Log "Running with Administrator privileges. All should be good."
    } else {
        Write-Log "NOT running with Administrator privileges. Script will likely fail. You are advised to either script while logged in to a local admin account, ran as that local admin. Script will not exit at this point." "WARNING"
    }

} else {

    Write-Log "Script user ($scriptUser) differs from logged-in user ($loggedInUser). If Script User is System, this should be fine."

    # Am I running as system?
    if ($scriptUser -eq "NT AUTHORITY\SYSTEM") {
        Write-Log "Running as SYSTEM account. All should be good."
    } else {
        Write-Log "NOT running as SYSTEM (Current Script User: $scriptUser). YOU MAY RUN IN TO ISSUES. If this user has their own profile on this machine already with WinGet installed in that profile, this script may return a success. Script will not exit at this point." "WARNING"
    }

}
Write-Log "--------------------------------------"

# Determine the detect method

$detectionSuccess = $False

$methods = @()

if ($DetectMethod -eq "WinGet") {

    Write-Log "SCRIPT: $ThisFileName | Using WinGet detection method."

    $methods = @("Detect--WinGetApplicationInstalled")

} elseif ($DetectMethod -eq "MSI_Registry") {

    Write-Log "SCRIPT: $ThisFileName | Using MSI Registry detection method."

    $methods = @("Detect--MSI-ApplicationInstalled")

} elseif($DetectMethod -eq "AppXpackage") {

    Write-Log "SCRIPT: $ThisFileName | Using AppXpackage detection method."

    $methods = @("Detect--AppXPackageInstalled")

} elseif($DetectMethod -eq "AppXProvisionedPackage") {

    Write-Log "SCRIPT: $ThisFileName | Using AppXProvisionedPackage detection method."

    $methods = @("Detect--AppXProvisionedPackageInstalled")

}elseif($DetectMethod -eq "CIM") {

    Write-Log "SCRIPT: $ThisFileName | Using CIM detection method."

    $methods = @("Detect--CIM")

} elseif ($DetectMethod -eq "All") {


    Write-Log "SCRIPT: $ThisFileName | Using ALL detection methods."

    $methods = Get-Command -CommandType Function -Name "Detect--*" | Select-Object -ExpandProperty Name
    
}else{

    Write-Log "Unsupported detect method: $DetectMethod" "ERROR"
    Write-Log "SCRIPT: $ThisFileName | END | Exiting script." "ERROR"
    Exit 1

}

ForEach ($method in $methods){

    Write-Log "SCRIPT: $ThisFileName | Attempting detection method: $method"

    Try {

        $Detect = & $method

        if ($Detect -eq 0){

            Write-Log "SCRIPT: $ThisFileName | Detection method $method reported success!" "SUCCESS"
            $detectionSuccess = $True
            Break

        } else {

            Write-Log "SCRIPT: $ThisFileName | Detection method $method reported failure." "WARNING"

        }

    } Catch {

        Write-Log "SCRIPT: $ThisFileName | Detection method $method encountered error: $_" "ERROR"

    }

}


if ($detectionSuccess -eq $True){

    Write-Log "SCRIPT: $ThisFileName | END | Application detected by method: $DetectMethod!" "SUCCESS"
    Exit 0

} else {

    Write-Log "SCRIPT: $ThisFileName | END | Application NOT detected by method: $DetectMethod!" "WARNING"
    Exit 1

}




# Return the path of WinGet to be used
# if ($ReturnWinGetPath -eq $True){

#     Write-Log "++++++++++++++++++++++++++++"
#     Write-Log "SCRIPT: $ThisFileName | END | Returning WinGet location..." "SUCCESS"
#     Return $WinGet
    
# } else {

#     Write-Log "++++++++++++++++++++++++++++"
#     Write-Log "SCRIPT: $ThisFileName | END" "SUCCESS"

# }

