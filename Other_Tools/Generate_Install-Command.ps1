<#

.SYNOPSIS
    Helper script to generate Intune commands and create custom Git Runners.

.DESCRIPTION
    This is the main script you will use to build your new infrastructure based on this suite.
    This script is called from the Setup.ps1 script. For most scenarios you will not use this script outside of that context.
    Currently the main exception is if you need to build Remedation scripts, but I will be adding that functionality to Setup.ps1 in the future.


.NOTES

    This specific script doesn't do logging, previously out of a desire to keep SAS keys out of logs. Now that log folders are locked down, this is less of a concern.

    Some old notes:

        Instructions:

        Build your command

        Open elevated cmd on the test machine

        navigate to the dir of git runner template (on mac VM you may need to do pushd)

#>



Param(

    [string]$DesiredFunction,
    [hashtable]$FunctionParams,
    [String]$RepoURL,
    [String]$RepoNickName,
    [String]$RepoBranch="main",
    [String]$TargetWorkingDirectory="C:\ProgramData\PowerDeploy"

)

########
# Vars #
########

# These are for identifying the running environment of this script not for the end script
$RepoRoot = Split-Path -Path $PSScriptRoot -Parent
$WorkingDirectory = Split-Path -Path $RepoRoot -Parent
$GitRunnerScript = "$RepoRoot\Templates\Git-Runner_TEMPLATE.ps1"
$CustomGitRunnerMakerScript = "$RepoRoot\Other_Tools\Generate_Custom-Script_FromTemplate.ps1"

$ThisFileName = $MyInvocation.MyCommand.Name

# $LocalRepoPath = "$WorkingDirectory\$RepoNickName"
$LogRoot = "$WorkingDirectory\Logs\Generator_Logs"
#$LogPath = "$LogRoot\$RepoNickName._Git_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
# $ThisFileName = $MyInvocation.MyCommand.Name
$LogPath = "$LogRoot\$ThisFileName.$DesiredFunction.$RepoNickName.$RepoBranch._Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"


# $RepoRoot = "C:\ProgramData\PowerDeploy\$RepoNickName"
# $WorkingDirectory = Split-Path -Path $RepoRoot -Parent


#############
# Functions #
#############

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



function New-IntuneGitRunnerCommand {
    param(
        [string]$RepoNickName,
        [string]$RepoUrl,
        [string]$TargetWorkingDirectory,
        [string]$ScriptPath,
        [hashtable]$ScriptParams,
        [string]$CustomNameModifier
    )

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START" -ForegroundColor Yellow
    Write-Log ""
    Write-Log "RepoNickName: $RepoNickName"
    Write-Log "RepoUrl: $RepoUrl"
    Write-Log "TargetWorkingDirectory: $TargetWorkingDirectory"
    Write-Log "ScriptPath: $ScriptPath"
    Write-Log "ScriptParams: $ScriptParams"
    Write-Log "CustomNameModifier: $CustomNameModifier"
    Write-Log ""

    Write-Log "Function parameters received:"
    Write-Log ""
    if ($ScriptParams) {

        Write-Log "Script parameters to encode:" #-ForegroundColor Cyan
        $ScriptParams | Format-List | Out-Host

        # Encode the parameters
        $paramsJson = $ScriptParams | ConvertTo-Json -Compress
        $paramsBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($paramsJson))
        
        # Build the command
        $command = @"
%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '.\Git-Runner_TEMPLATE.ps1' -RepoNickName '$RepoNickName' -RepoUrl '$RepoUrl' -WorkingDirectory '$TargetWorkingDirectory' -ScriptPath '$ScriptPath' -ScriptParamsBase64 '$paramsBase64'"
"@
    } else {
        # for a no param script
        $command = @"
%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '.\Git-Runner_TEMPLATE.ps1' -RepoNickName '$RepoNickName' -RepoUrl '$RepoUrl' -WorkingDirectory '$TargetWorkingDirectory' -ScriptPath '$ScriptPath'"
"@
    }
        Write-Log ""


    Write-Log "Custom command generated:" #-ForegroundColor Green
    Write-Log $command
    Write-Log ""
    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Creating custom script..." #-ForegroundColor Green
    Write-Log ""

    # Create the custom script with the current params
    if($CustomNameModifier){
        $global:CustomScript = & $CustomGitRunnerMakerScript -RepoNickName $RepoNickName -RepoUrl $RepoUrl -RepoBranch $RepoBranch -WorkingDirectory $TargetWorkingDirectory -ScriptPath $ScriptPath -ScriptParamsBase64 $paramsBase64 -CustomNameModifier $CustomNameModifier
    }
    else {
        $global:CustomScript = & $CustomGitRunnerMakerScript -RepoNickName $RepoNickName -RepoUrl $RepoUrl -RepoBranch $RepoBranch -WorkingDirectory $TargetWorkingDirectory -ScriptPath $ScriptPath -ScriptParamsBase64 $paramsBase64
    }   
    Write-Log ""

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Custom script created." #-ForegroundColor Green

    # done
    Write-Log ""
    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"
        Write-Log ""

    return $command
}


function ExportTXT {

    if($CustomNameModifier){

        $InstallCommandTXT = "$WorkingDirectory\TEMP\Intune_Install-Commands_Output\$CustomNameModifier.Install-Command_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    } else {

        $InstallCommandTXT = "$WorkingDirectory\TEMP\Intune_Install-Commands_Output\Install-Command_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
   
    }

    If (!(Test-Path $InstallCommandTXT)){New-item -path $InstallCommandTXT -ItemType File -Force | out-null}

    # Output the command to a txt file and to clipboard

    Write-Log "Final install command:"
    Write-Log $installCommand #-ForegroundColor Green
    Write-Log ""


    $installCommand | Set-Content -Encoding utf8 $InstallCommandTXT
    Write-Log "Install command saved here: $InstallCommandTXT"
    Write-Log ""

    $installCommand | Set-Clipboard 
    Write-Log "Install command saved to your clip board!"

    Write-Log ""

    return $InstallCommandTXT
}



# See the examples below. You can uncomment one to generate the command you want.

#################################
### Example: Update repo only ###
#################################

<#
$updateCommand = New-IntuneGitRunnerCommand `
    -RepoNickName "Test00" `
    -RepoUrl "$RepoURL" `
    -WorkingDirectory "C:\ProgramData\Test7"

Write-Log "Update Only Command:" -ForegroundColor Green
Write-Log $updateCommand
Write-Log ""
#>



############################################################
### Example: Create Detect/Remediation Script for InTune ###
############################################################
Function RegRemediationScript {

    Param(

    $StorageAccountName = "powerdeploy",

    $PrinterDataJSONpath = "printers/PrinterData.json",
    $PrinterContainerSASkey,

    $ApplicationDataJSONpath = "applications/ApplicationData.json",
    $ApplicationContainerSASkey,

    $CustomRepoURL=$NULL,
    $CustomRepoToken=$NULL

    )

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START" -ForegroundColor Yellow
    Write-Log ""
    # Display all the supplied parameters for the function:
    Write-Log "Function parameters received:"
        Write-Log ""

    # Check the returned hashtable
    Write-Log "StorageAccountName:         $StorageAccountName"
    Write-Log "PrinterDataJSONpath:        $PrinterDataJSONpath"
    Write-Log "PrinterContainerSASkey:     $PrinterContainerSASkey"
    Write-Log "ApplicationDataJSONpath:    $ApplicationDataJSONpath"
    Write-Log "ApplicationContainerSASkey: $ApplicationContainerSASkey"
    Write-Log "CustomRepoURL:              $CustomRepoURL"
    Write-Log "CustomRepoToken:            $CustomRepoToken"
    # End display of parameters
    Write-Log ""   
    Write-Log "Generating Detect/Remediation scripts for Registry changes..." -ForegroundColor Yellow
    # Choose the registry changes.

        # Declare as list to bypass the Git Runner's function of putting passed string params into double quotes. This breaks the pass to the remediation script.
        $RegistryChanges = @()

        # declare as string that will be parsed later
        [string]$RegistryChangesSTRING = ""

        <#
        # Registry Value 1
        $KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy-Test"
        $ValueName = "Test"
        $ValueType = "String"
        #$Value = "$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $Value = "1"

        $RegistryChangesSTRING = "["+"-KeyPath ""$KeyPath"" -ValueName ""$ValueName"" -ValueType ""$ValueType"" -Value ""$Value"""+"]"+","


        # Registry Value 2
        $KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy-Test"
        $ValueName = "Test 2"
        $ValueType = "String"
        #$Value = "$(Get-Date -Format 'yyyyMMdd_HHmmss') 2"
        $Value = "2"

        $RegistryChangesSTRING += "["+"-KeyPath ""$KeyPath"" -ValueName ""$ValueName"" -ValueType ""$ValueType"" -Value ""$Value"""+"]" # no comma at the end cuz this is the end of the list
        #>


        $KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\General"
        $ValueName = "StorageAccountName"
        $ValueType = "String"
        #$Value = "$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $Value = "$StorageAccountName" # Modify this
        $RegistryChangesSTRING += "["+"-KeyPath ""$KeyPath"" -ValueName ""$ValueName"" -ValueType ""$ValueType"" -Value ""$Value"""+"]"+","

        $KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\General"
        $ValueName = "CustomRepoURL"
        $ValueType = "String"
        #$Value = "$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $Value = "$CustomRepoURL" # Modify this
        $RegistryChangesSTRING += "["+"-KeyPath ""$KeyPath"" -ValueName ""$ValueName"" -ValueType ""$ValueType"" -Value ""$Value"""+"]"+","

        $KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\General"
        $ValueName = "CustomRepoToken"
        $ValueType = "String"
        #$Value = "$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $Value = "$CustomRepoToken" # Modify this
        $RegistryChangesSTRING += "["+"-KeyPath ""$KeyPath"" -ValueName ""$ValueName"" -ValueType ""$ValueType"" -Value ""$Value"""+"]"+","


        $KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\Printers"
        $ValueName = "PrinterDataJSONpath"
        $ValueType = "String"
        #$Value = "$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $Value = "$PrinterDataJSONpath" # Modify this
        $RegistryChangesSTRING += "["+"-KeyPath ""$KeyPath"" -ValueName ""$ValueName"" -ValueType ""$ValueType"" -Value ""$Value"""+"]"+","

        $KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\Printers"
        $ValueName = "PrinterContainerSASkey"
        $ValueType = "String"
        #$Value = "$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $Value = "$PrinterContainerSASkey" # Modify this
        $RegistryChangesSTRING += "["+"-KeyPath ""$KeyPath"" -ValueName ""$ValueName"" -ValueType ""$ValueType"" -Value ""$Value"""+"]"+","


        $KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\Applications"
        $ValueName = "ApplicationDataJSONpath"
        $ValueType = "String"
        #$Value = "$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $Value = "$ApplicationDataJSONpath" # Modify this
        $RegistryChangesSTRING += "["+"-KeyPath ""$KeyPath"" -ValueName ""$ValueName"" -ValueType ""$ValueType"" -Value ""$Value"""+"]"+","

        $KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\Applications"
        $ValueName = "ApplicationContainerSASkey"
        $ValueType = "String"
        #$Value = "$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $Value = "$ApplicationContainerSASkey" # Modify this
        $RegistryChangesSTRING += "["+"-KeyPath ""$KeyPath"" -ValueName ""$ValueName"" -ValueType ""$ValueType"" -Value ""$Value"""+"]"


        # Make as many as you need

        # Create a passable object
        $RegistryChangesSTRING = ''''+$RegistryChangesSTRING+''''
        $RegistryChanges+=$RegistryChangesSTRING

    
        # This works too!
        # $RegistryChanges = @()
        # $RegistryChanges += '''[-KeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy-Test" -ValueName "Test" -ValueType "String" -Value "zz"],[-KeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy-Test" -ValueName "Test 2" -ValueType "String" -Value "zz 2"]'''

        Write-Log "Registry Changes to process: $RegistryChanges" #-ForegroundColor Yellow

    # Then compose the install command args and run for DETECT
    Write-Log ""
    Write-Log "DETECT SCRIPT" -ForegroundColor Yellow
    $CustomNameModifier = "Detect"
    $installCommand = New-IntuneGitRunnerCommand `
        -RepoNickName "$RepoNickName" `
        -RepoUrl "$RepoUrl" `
        -RepoBranch "$RepoBranch" `
        -TargetWorkingDirectory "$TargetWorkingDirectory" `
        -ScriptPath "Templates\General_RemediationScript-Registry_TEMPLATE.ps1" `
        -CustomNameModifier "$CustomNameModifier" `
        -ScriptParams @{
            RegistryChanges = $RegistryChanges
            RepoNickName = "$RepoNickName"
            WorkingDirectory = "$TargetWorkingDirectory"
            Function = "Detect"
        }

    # # Export the txt file
    # ExportTXT

    $DetectScript = $global:CustomScript
    # Export the txt file
    $DetectScriptCommandTXT = ExportTXT

    # Then compose the install command args and run for REMEDIATE
    Write-Log ""
    Write-Log "REMEDIATION SCRIPT" -ForegroundColor Yellow
    $CustomNameModifier = "Remediate"
    $installCommand = New-IntuneGitRunnerCommand `
        -RepoNickName "$RepoNickName" `
        -RepoUrl "$RepoUrl" `
        -RepoBranch "$RepoBranch" `
        -TargetWorkingDirectory "$TargetWorkingDirectory" `
        -ScriptPath "Templates\General_RemediationScript-Registry_TEMPLATE.ps1" `
        -CustomNameModifier "$CustomNameModifier" `
        -ScriptParams @{
            RegistryChanges = $RegistryChanges
            RepoNickName = "$RepoNickName"
            WorkingDirectory = "$TargetWorkingDirectory"
            Function = "Remediate"
            AlsoLockDown = $True
        }

    # # Export the txt file
    # ExportTXT

    $RemediationScript = $global:CustomScript
    # Export the txt file
    $RemediationScriptCommandTXT = ExportTXT

    <#

    Output for detect:
    %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '.\Git-Runner_TEMPLATE.ps1' -RepoNickName '$RepoNickName' -RepoUrl '$RepoURL' -WorkingDirectory 'C:\ProgramData\PowerDeploy' -ScriptPath 'Templates\General_RemediationScript-Registry_TEMPLATE.ps1' -ScriptParamsBase64 'eyJSZWdpc3RyeUNoYW5nZXMiOlsiXHUwMDI3Wy1LZXlQYXRoIFwiSEtFWV9MT0NBTF9NQUNISU5FXFxTT0ZUV0FSRVxcQWRtaW5TY3JpcHRTdWl0ZS1UZXN0XCIgLUtleU5hbWUgXCJUZXN0XCIgLUtleVR5cGUgXCJTdHJpbmdcIiAtVmFsdWUgXCIyMDI1MTExOF8xNTE3MzJcIl0sWy1LZXlQYXRoIFwiSEtFWV9MT0NBTF9NQUNISU5FXFxTT0ZUV0FSRVxcQWRtaW5TY3JpcHRTdWl0ZS1UZXN0XCIgLUtleU5hbWUgXCJUZXN0IDJcIiAtS2V5VHlwZSBcIlN0cmluZ1wiIC1WYWx1ZSBcIjIwMjUxMTE4XzE1MTczMiAyXCJdXHUwMDI3Il0sIkZ1bmN0aW9uIjoiRGV0ZWN0IiwiUmVwb05pY2tOYW1lIjoiQWRtaW5TY3JpcHRTdWl0ZS1SZXBvIiwiV29ya2luZ0RpcmVjdG9yeSI6IkM6XFxQcm9ncmFtRGF0YVxcQWRtaW5TY3JpcHRTdWl0ZSJ9'"

    Output for remediate
    #>


     # Store results in script-scoped variables so the main script can package them up

    $script:GI_DetectScript = $DetectScript
    $script:GI_DetectScriptCommandTXT = $DetectScriptCommandTXT
    $script:GI_RemediationScript = $RemediationScript
    $script:GI_RemediationScriptCommandTXT = $RemediationScriptCommandTXT

    # Just for visibility, still log what we *think* we produced
    Write-Log "Return values prepared."


    Write-Log "script:GI_DetectScript = $script:GI_DetectScript"
    Write-Log "script:GI_DetectScriptCommandTXT = $script:GI_DetectScriptCommandTXT"
    Write-Log "script:GI_RemediationScript = $script:GI_RemediationScript"
    Write-Log "script:GI_RemediationScriptCommandTXT = $script:GI_RemediationScriptCommandTXT"



    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"
    Write-Log ""



    $Script:HashPattern = "RegRemediation"

    return "BuildMe"
}
###


####################################################################
### Example: Install Dell Command Update (custom install script) ###
####################################################################

<#
$installCommand = New-IntuneGitRunnerCommand `
    -RepoNickName "$RepoNickName" `
    -RepoUrl "$RepoURL" `
    -WorkingDirectory "C:\ProgramData\PowerDeploy" `
    -ScriptPath "Installers\Install-DellCommandUpdate-FullClean.ps1"
#>


#################################################################
### Example: Install Zoom Workplace (standard WinGet install) ###
#################################################################

<#
$installCommand = New-IntuneGitRunnerCommand `
    -RepoNickName "$RepoNickName" `
    -RepoUrl "$RepoURL" `
    -WorkingDirectory "C:\ProgramData\PowerDeploy" `
    -ScriptPath "Installers\General_WinGet_Installer.ps1" `
    -ScriptParams @{
        AppName = "Zoom.Zoom.EXE"
        AppID = "Zoom.Zoom.EXE"
        WorkingDirectory = "C:\ProgramData\PowerDeploy"
    }
#>


##############################################################
### Example: Install Printer by IP (custom install script) ###
##############################################################
function InstallPrinterByIP {

    Param(

        [hashtable]$FunctionParams, # NOTE: This works for my intended use case but this with the param received snippet below are NOT done according to intent...
        [String]$PrinterName="zz" # Didn't want to set to $false or $null for eval purposes. If printername is contained inside functionparams this gets overwritten. If I set default as $True, $False, or $Null it will be difficult to evaluate that no printername was passed either way, hence I made it "zz" as a dummy value.

    )
    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START" -ForegroundColor Yellow

    Write-Log "Generating Install script for Printer by IP..." -ForegroundColor Yellow

    Write-Log "Function parameters received:"
    # Check the returned hashtable
    # TODO: May want to replace this with the method from InstallAppWithJSON function that checks for specific keys instead of just any keys. This method here can produce errors.
    if(($FunctionParams -eq $null) -or ($FunctionParams.Count -eq 0)){ 
        Write-Log "No data returned! Checking if a printer was explicitly specified..." #"ERROR"
        if(-not $PrinterName){
            Write-Log "No printer specified. Exiting!" #"ERROR"
            Exit 1

        } else {
            Write-Log "Printer specified as: $PrinterName"
        }
    } else {

        Write-Log "Values retrieved:"
        foreach ($key in $FunctionParams.Keys) {
            $value = $FunctionParams[$key]
            Write-Log "   $key : $value"
        }    

        # Turn the returned hashtable into variables
        Write-Log "Setting values as local variables..."
        foreach ($key in $FunctionParams.Keys) {
            Set-Variable -Name $key -Value $FunctionParams[$key] -Scope Local
            # Write-Log "Should be: $key = $($ReturnHash[$key])"
            $targetValue = Get-Variable -Name $key -Scope Local
            Write-Log "Ended up as: $key = $($targetValue.Value)"

        }

    }


    If ($PrinterName -eq "zz"){
        Write-Log "PrinterName is still the default 'zz'. Please specify a valid PrinterName. Exiting!" #"ERROR"
        Exit 1
    }


    #$PrinterName = "Auckland"

    # Main install command:
    Write-Log ""
    Write-Log "INSTALL COMMAND" -ForegroundColor Yellow
    $CustomNameModifier = "Install-Printer-IP.$PrinterName"
    $installCommand = New-IntuneGitRunnerCommand `
        -RepoNickName "$RepoNickName" `
        -RepoUrl "$RepoURL" `
        -RepoBranch "$RepoBranch" `
        -TargetWorkingDirectory "$TargetWorkingDirectory" `
        -ScriptPath "Installers\General_IP-Printer_Installer.ps1" `
        -CustomNameModifier "$CustomNameModifier" `
        -ScriptParams @{
            PrinterName = "$PrinterName"
            WorkingDirectory = "$TargetWorkingDirectory"
        }

    $InstallPrinterScript = $global:CustomScript
    # Export the txt file
    $InstallCommandTXT = ExportTXT

    # Detection script command:
    Write-Log ""
    Write-Log "DETECT SCRIPT" -ForegroundColor Yellow
    $CustomNameModifier = "Detect-Printer.$PrinterName"
    $detectCommand = New-IntuneGitRunnerCommand `
        -RepoNickName "$RepoNickName" `
        -RepoUrl "$RepoURL" `
        -RepoBranch "$RepoBranch" `
        -TargetWorkingDirectory "$TargetWorkingDirectory" `
        -ScriptPath "Templates\Detection-Script-Printer_TEMPLATE.ps1" `
        -CustomNameModifier "$CustomNameModifier" `
        -ScriptParams @{
            PrinterName = "$PrinterName"
            WorkingDirectory = "$TargetWorkingDirectory"
        }

    $DetectPrinterScript = $global:CustomScript

    # Export the txt file
    $DetectCommandTXT = ExportTXT

    <#
    $ReturnHash = @{
        MainInstallCommand = $installCommand
        MainInstallCommandTXT = $InstallCommandTXT
        MainDetectCommand = $detectCommand
        MainDetectCommandTXT = $DetectCommandTXT
        InstallPrinterScript = $InstallPrinterScript
        DetectPrinterScript = $DetectPrinterScript
    }

    Write-Log "Return values prepared."
    $ReturnHash.Keys | ForEach-Object { Write-Log "   $_ : $($ReturnHash[$_])" }   
    Return $ReturnHash

    #>

    # Store results in script-scoped variables so the main script can package them up
    $script:GI_MainInstallCommand    = $installCommand # I don't remember why I named these "main"
    $script:GI_MainInstallCommandTXT = $InstallCommandTXT
    $script:GI_MainDetectCommand     = $detectCommand
    $script:GI_MainDetectCommandTXT  = $DetectCommandTXT
    $script:GI_InstallPrinterScript      = $InstallPrinterScript
    $script:GI_DetectPrinterScript       = $DetectPrinterScript

    # Just for visibility, still log what we *think* we produced
    Write-Log "Return values prepared."
    Write-Log "   MainInstallCommand     : $script:GI_MainInstallCommand"
    Write-Log "   MainInstallCommandTXT  : $script:GI_MainInstallCommandTXT"
    Write-Log "   MainDetectCommand      : $script:GI_MainDetectCommand"
    Write-Log "   MainDetectCommandTXT   : $script:GI_MainDetectCommandTXT"
    Write-Log "   InstallPrinterScript       : $script:GI_InstallPrinterScript"
    Write-Log "   DetectPrinterScript        : $script:GI_DetectPrinterScript"

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"
    Write-Log ""

    $Script:HashPattern = "InstallPrinterByIP"

    return "BuildMe"


}

##################################################################
### Example: Uninstall Printer by name (custom install script) ###
##################################################################
function UninstallPrinterByName {

    Param(

        [hashtable]$FunctionParams, # NOTE: This works for my intended use case but this with the param received snippet below are NOT done according to intent...
        [String]$PrinterName="zz" # Didn't want to set to $false or $null for eval purposes. If printername is contained inside functionparams this gets overwritten. If I set default as $True, $False, or $Null it will be difficult to evaluate that no printername was passed either way, hence I made it "zz" as a dummy value.

    )

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START" -ForegroundColor Yellow

    Write-Log "Generating Uninstall script for Printer by name..." -ForegroundColor Yellow

    ###

    Write-Log "Function parameters received:"
    # Check the returned hashtable
    # TODO: May want to replace this with the method from InstallAppWithJSON function that checks for specific keys instead of just any keys. This method here can produce errors.

    if(($FunctionParams -eq $null) -or ($FunctionParams.Count -eq 0)){
        Write-Log "No data returned! Checking if a printer was explicitly specified..." #"ERROR"
        if(-not $PrinterName){
            Write-Log "No printer specified. Exiting!" #"ERROR"
            Exit 1

        } else {
            Write-Log "Printer specified as: $PrinterName"
        }
    } else {

        Write-Log "Values retrieved:"
        foreach ($key in $FunctionParams.Keys) {
            $value = $FunctionParams[$key]
            Write-Log "   $key : $value"
        }    

        # Turn the returned hashtable into variables
        Write-Log "Setting values as local variables..."
        foreach ($key in $FunctionParams.Keys) {
            Set-Variable -Name $key -Value $FunctionParams[$key] -Scope Local
            # Write-Log "Should be: $key = $($ReturnHash[$key])"
            $targetValue = Get-Variable -Name $key -Scope Local
            Write-Log "Ended up as: $key = $($targetValue.Value)"

        }

    }

    ###

    If ($PrinterName -eq "zz"){
        Write-Log "PrinterName is still the default 'zz'. Please specify a valid PrinterName. Exiting!" #"ERROR"
        Exit 1
    }


    #$PrinterName = "Auckland"

    # Main install command:
    Write-Log ""
    Write-Log "UNINSTALL COMMAND" -ForegroundColor Yellow
    $CustomNameModifier = "Uninstall-Printer-Name.$PrinterName"
    $InstallCommand = New-IntuneGitRunnerCommand `
        -RepoNickName "$RepoNickName" `
        -RepoUrl "$RepoURL" `
        -RepoBranch "$RepoBranch" `
        -TargetWorkingDirectory "$TargetWorkingDirectory" `
        -ScriptPath "Uninstallers\Uninstall-Printer.ps1" `
        -CustomNameModifier "$CustomNameModifier" `
        -ScriptParams @{
            PrinterName = "$PrinterName"
            WorkingDirectory = "$TargetWorkingDirectory"
        }

    $UninstallPrinterScript = $global:CustomScript
    # Export the txt file
    $UninstallCommandTXT = ExportTXT

    $UninstallCommand = $InstallCommand
    <#
    $ReturnHash = @{
        MainInstallCommand = $installCommand
        MainInstallCommandTXT = $InstallCommandTXT
        MainDetectCommand = $detectCommand
        MainDetectCommandTXT = $DetectCommandTXT
        InstallPrinterScript = $InstallPrinterScript
        DetectPrinterScript = $DetectPrinterScript
    }

    Write-Log "Return values prepared."
    $ReturnHash.Keys | ForEach-Object { Write-Log "   $_ : $($ReturnHash[$_])" }   
    Return $ReturnHash

    #>

    # Store results in script-scoped variables so the main script can package them up
    # $script:GI_MainInstallCommand    = $installCommand
    # $script:GI_MainInstallCommandTXT = $InstallCommandTXT

    $script:GI_UninstallCommand    = $UninstallCommand
    $script:GI_UninstallCommandTXT  = $UninstallCommandTXT
    $script:GI_UninstallPrinterScript      = $UninstallPrinterScript

    # Just for visibility, still log what we *think* we produced
    Write-Log "Return values prepared."
    Write-Log "   UninstallCommand     : $script:GI_UninstallCommand"
    Write-Log "   UninstallCommandTXT  : $script:GI_UninstallCommandTXT"
    Write-Log "   UninstallPrinterScript  : $script:GI_UninstallPrinterScript"

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"
    Write-Log ""

    $Script:HashPattern = "UninstallPrinterByName"

    return "BuildMe"


}



######################################
### Example: Install App with JSON ###
######################################
function InstallAppWithJSON {

    Param(

        [String]$ApplicationName="zz", # I don't remember why I had to do this...
        $DetectMethod,
        $DisplayName,
        $AppID
        # [Parameter(ValueFromRemainingArguments=$true)] # NOTE: Can't get this working the way I want, just gonna hardcode below.
        # $FunctionParams


    )
    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START" -ForegroundColor Yellow
    Write-Log "Generating Install script for App with JSON..." -ForegroundColor Yellow
    Write-Log "Function parameters received:"
    # Check the returned hashtable
    #if(($FunctionParams -eq $null) -or ($FunctionParams.Count -eq 0)){
    # if(($FunctionParams -eq $null)){
    #     Write-Log "No data returned! Checking if an app was explicitly specified..." #"ERROR"
    #     if(-not $ApplicationName){
    #         Write-Log "No app specified. Exiting!" #"ERROR"
    #         Exit 1

    #     } else {
            
    #         Write-Log "App specified as: $ApplicationName"

    #     }
    # } else {

    #     Write-Log "Values retrieved:"
    #     foreach ($key in $FunctionParams.Keys) {
    #         $value = $FunctionParams[$key]
    #         Write-Log "   $key : $value"
    #     }    

    #     # Turn the returned hashtable into variables
    #     Write-Log "Setting values as local variables..."
    #     foreach ($key in $FunctionParams.Keys) {
    #         Set-Variable -Name $key -Value $FunctionParams[$key] -Scope Local
    #         # Write-Log "Should be: $key = $($ReturnHash[$key])"
    #         $targetValue = Get-Variable -Name $key -Scope Local
    #         Write-Log "Ended up as: $key = $($targetValue.Value)"

    #     }

    # }
    
    Write-Log "App specified as: $ApplicationName"
    Write-Log "DetectMethod specified as: $DetectMethod"
    Write-Log "DisplayName specified as: $DisplayName"
    Write-Log "AppID specified as: $AppID"


    If ($ApplicationName -eq "zz"){
        Write-Log "AppName is still the default 'zz'. Please specify a valid AppName. Exiting!" #"ERROR"
        Exit 1
    }


    # Main install command:
    Write-Log ""
    Write-Log "INSTALL COMMAND" -ForegroundColor Yellow
    $CustomNameModifier = "Install-JSON-App.$ApplicationName"
    $installCommand = New-IntuneGitRunnerCommand `
        -RepoNickName "$RepoNickName" `
        -RepoUrl "$RepoURL" `
        -RepoBranch "$RepoBranch" `
        -TargetWorkingDirectory "$TargetWorkingDirectory" `
        -ScriptPath "Installers\General_JSON-App_Installer.ps1" `
        -CustomNameModifier "$CustomNameModifier" `
        -ScriptParams @{
            TargetAppName = "$ApplicationName"
            WorkingDirectory = "$TargetWorkingDirectory"
        }


        
    $InstallAppScript = $global:CustomScript
    # Export the txt file
    $InstallCommandTXT = ExportTXT

    # Detection script command:
    Write-Log ""
    Write-Log "DETECT SCRIPT" -ForegroundColor Yellow

    If ($DetectMethod -eq "WinGet"){

        Write-Log "Using WinGet detection method."

        if (-not $AppID){
            Write-Error "AppID must be specified for WinGet detection method."
            Exit 1
        }

        $CustomNameModifier = "Detect-App.Winget.$ApplicationName"
        $detectCommand = New-IntuneGitRunnerCommand `
            -RepoNickName "$RepoNickName" `
            -RepoUrl "$RepoURL" `
            -RepoBranch "$RepoBranch" `
            -TargetWorkingDirectory "$TargetWorkingDirectory" `
            -ScriptPath "Templates\Detection-Script-Application_TEMPLATE.ps1" `
            -CustomNameModifier "$CustomNameModifier" `
            -ScriptParams @{
                WorkingDirectory = "$TargetWorkingDirectory"
                AppToDetect = $ApplicationName
                AppID = $AppID
                DetectMethod = $DetectMethod
            }

    } elseif ( $DetectMethod -eq "MSI_Registry" ) {

        Write-Log "Using MSI Registry detection method."

 
        $CustomNameModifier = "Detect-App.MSIRegistry.$ApplicationName"
        $detectCommand = New-IntuneGitRunnerCommand `
            -RepoNickName "$RepoNickName" `
            -RepoUrl "$RepoURL" `
            -RepoBranch "$RepoBranch" `
            -TargetWorkingDirectory "$TargetWorkingDirectory" `
            -ScriptPath "Templates\Detection-Script-Application_TEMPLATE.ps1" `
            -CustomNameModifier "$CustomNameModifier" `
            -ScriptParams @{
                WorkingDirectory = "$TargetWorkingDirectory"
                DisplayName = $DisplayName
                AppToDetect = $ApplicationName
                DetectMethod = $DetectMethod

            }


    } {

        Write-Error "Unsupported DetectMethod specified: $DetectMethod"
        Exit 1

    }


    $DetectAppScript = $global:CustomScript

    # Export the txt file
    $DetectCommandTXT = ExportTXT


    <# # For some reason this doesn't work here even though it works for the printer function...
    $ReturnHash = @{
        MainInstallCommand = $installCommand
        MainInstallCommandTXT = $InstallCommandTXT
        MainDetectCommand = $detectCommand
        MainDetectCommandTXT = $DetectCommandTXT
        InstallAppScript = $InstallAppScript
        DetectAppScript = $DetectAppScript
    }

    Write-Log "Return values prepared."
    $ReturnHash.Keys | ForEach-Object { Write-Log "   $_ : $($ReturnHash[$_])" }   
    Return $ReturnHash

    #>

    # ...So instead we are doing this:

    # Store results in script-scoped variables so the main script can package them up
    $script:GI_MainInstallCommand    = $installCommand
    $script:GI_MainInstallCommandTXT = $InstallCommandTXT
    $script:GI_MainDetectCommand     = $detectCommand
    $script:GI_MainDetectCommandTXT  = $DetectCommandTXT
    $script:GI_InstallAppScript      = $InstallAppScript
    $script:GI_DetectAppScript       = $DetectAppScript

    # Just for visibility, still log what we *think* we produced
    Write-Log "Return values prepared."
    Write-Log "   MainInstallCommand     : $script:GI_MainInstallCommand"
    Write-Log "   MainInstallCommandTXT  : $script:GI_MainInstallCommandTXT"
    Write-Log "   MainDetectCommand      : $script:GI_MainDetectCommand"
    Write-Log "   MainDetectCommandTXT   : $script:GI_MainDetectCommandTXT"
    Write-Log "   InstallAppScript       : $script:GI_InstallAppScript"
    Write-Log "   DetectAppScript        : $script:GI_DetectAppScript"

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"
    Write-Log ""

    $Script:HashPattern = "InstallAppWithJSON"

    return "BuildMe"

}

##############################
### Example: Uninstall App ###
##############################
function UninstallApp {

    Param(

        [hashtable]$FunctionParams # NOTE: This works for my intended use case but this with the param received snippet below are NOT done according to intent...

    )

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START" -ForegroundColor Yellow

    Write-Log "Generating Uninstall script for an application..." -ForegroundColor Yellow

    ###

    Write-Log "Function parameters received:"

    # Check the returned hashtable
    # if(($FunctionParams -eq $null) -or ($FunctionParams.Count -eq 0)){

    #     Write-Log "No data returned! Checking if a app was explicitly specified..." #"ERROR"

    #     if(-not $AppName){

    #         Write-Log "No app specified. Exiting!" #"ERROR"
    #         Exit 1

    #     } else {
    #         Write-Log "App specified as: $AppName"
    #     }

    # } else {

    #     Write-Log "Values retrieved:"
    #     foreach ($key in $FunctionParams.Keys) {
    #         $value = $FunctionParams[$key]
    #         Write-Log "   $key : $value"
    #     }    

    #     # Turn the returned hashtable into variables
    #     Write-Log "Setting values as local variables..."
    #     foreach ($key in $FunctionParams.Keys) {
    #         Set-Variable -Name $key -Value $FunctionParams[$key] -Scope Local
    #         # Write-Log "Should be: $key = $($ReturnHash[$key])"
    #         $targetValue = Get-Variable -Name $key -Scope Local
    #         Write-Log "Ended up as: $key = $($targetValue.Value)"

    #     }

    # }

    ###

    Write-Log "App specified as: $ApplicationName"
    Write-Log "UninstallType specified as: $UninstallType"
    Write-Log "Version specified as: $Version"
    Write-Log "UninstallString_DisplayName specified as: $UninstallString_DisplayName"
    Write-Log "WinGetID specified as: $WinGetID"


    If ($ApplicationName -eq $null -or $ApplicationName -eq ""){
        Write-Log "ApplicationName was not passed within the function parameters or explicityly set. Please specify a valid ApplicationName. Exiting!" #"ERROR"
        Exit 1
    }


    #$PrinterName = "Auckland"

    if(!($Version)){$Version = $null}
    # winget ID
    if(!($WinGetID)){ $WinGetID = $null }
    # Uninstaller String Display Name
    if(!($UninstallString_DisplayName)){ $UninstallString_DisplayName = $null }

    # Main install command:
    Write-Log ""
    Write-Log "UNINSTALL COMMAND" -ForegroundColor Yellow
    $CustomNameModifier = "Uninstall-App.$ApplicationName"
    $InstallCommand = New-IntuneGitRunnerCommand `
        -RepoNickName "$RepoNickName" `
        -RepoUrl "$RepoURL" `
        -RepoBranch "$RepoBranch" `
        -TargetWorkingDirectory "$TargetWorkingDirectory" `
        -ScriptPath "Uninstallers\General_Uninstaller.ps1" `
        -CustomNameModifier "$CustomNameModifier" `
        -ScriptParams @{
            AppName = "$ApplicationName"
            UninstallType = "$UninstallType"
            Version = "$Version"
            WinGetID = "$WinGetID"
            UninstallString_DisplayName = "$UninstallString_DisplayName"
            WorkingDirectory = "$TargetWorkingDirectory"
        }


    $UninstallAppScript = $global:CustomScript
    # Export the txt file
    $UninstallCommandTXT = ExportTXT

    $UninstallCommand = $InstallCommand
    <#
    $ReturnHash = @{
        MainInstallCommand = $installCommand
        MainInstallCommandTXT = $InstallCommandTXT
        MainDetectCommand = $detectCommand
        MainDetectCommandTXT = $DetectCommandTXT
        InstallPrinterScript = $InstallPrinterScript
        DetectPrinterScript = $DetectPrinterScript
    }

    Write-Log "Return values prepared."
    $ReturnHash.Keys | ForEach-Object { Write-Log "   $_ : $($ReturnHash[$_])" }   
    Return $ReturnHash

    #>

    # Store results in script-scoped variables so the main script can package them up
    # $script:GI_MainInstallCommand    = $installCommand
    # $script:GI_MainInstallCommandTXT = $InstallCommandTXT

    $script:GI_UninstallCommand    = $UninstallCommand
    $script:GI_UninstallCommandTXT  = $UninstallCommandTXT
    $script:GI_UninstallAppScript      = $UninstallAppScript

    # Just for visibility, still log what we *think* we produced
    Write-Log "Return values prepared."
    Write-Log "   UninstallCommand     : $script:GI_UninstallCommand"
    Write-Log "   UninstallCommandTXT  : $script:GI_UninstallCommandTXT"
    Write-Log "   UninstallAppScript  : $script:GI_UninstallAppScript"

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"
    Write-Log ""

    $Script:HashPattern = "UninstallApp"

    return "BuildMe"

    #Write-Log "For WinGet functions to work, the supplied AppName must be a valid, exact AppID" "WARNING"
    #Write-Log "For UninstallerString method, using wildcard search the registry uninstall strings for DisplayName equal to the supplied AppName"



}


########
# MAIN #
########

# Choose what function to run here:
# TODO: Make this a selectable menu
#Write-Log "Generating Intune Install Commands from function: $DesiredFunction..."
#Write-Log ""
Write-Log ""

Write-Log "SCRIPT: $ThisFileName | DESIRED FUNCTION: $DesiredFunction | PARAMS: $FunctionParams | START"

Write-Log ""
# Output all vars to command line for debugging
Write-Log "--- Input Parameters ---"
Foreach ($var in $PSBoundParameters.GetEnumerator()) {
    Write-Log "$($var.Key): $($var.Value)"
}
Write-Log "--- End Input Parameters ---"
Write-Log ""

# Write-Log "Function Parameters:"
# @FunctionParams

<#
$ReturnHash = & $DesiredFunction @FunctionParams


Write-Log "Values to return to caller."
$ReturnHash.Keys | ForEach-Object { Write-Log "   $_ : $($ReturnHash[$_])" }   
Write-Log ""
Write-Log "SCRIPT: $ThisFileNameName | DESIRED FUNCTION: $DesiredFunction | PARAMS: $FunctionParams | END"

Return $ReturnHash

#Write-Log "End of script."
# Return something

#>

if ($DesiredFunction -eq $null -or $DesiredFunction -eq ""){

    $DesiredFunction = Read-Host "Please enter the name of your desired function (InstallAppWithJSON, InstallPrinterByIP, RemediationScript)"

}

Write-Log ""
Write-Log "Invoking function: $DesiredFunction ..."
Write-Log ""
# Invoke the selected function and capture its result
$result = & $DesiredFunction @FunctionParams

# Write-Log ""
# Write-Log "Function '$DesiredFunction' returned: "  
# $result
Write-Log ""

# If the function indicates that we need to build the final hashtable, do so
if ($result -eq "BuildMe") {

    if ($Script:HashPattern -eq "InstallAppWithJSON") {
        Write-Log "Building return hashtable for InstallAppWithJSON..."

        $result = @{
            MainInstallCommand     = $script:GI_MainInstallCommand
            MainInstallCommandTXT  = $script:GI_MainInstallCommandTXT
            MainDetectCommand      = $script:GI_MainDetectCommand
            MainDetectCommandTXT   = $script:GI_MainDetectCommandTXT
            InstallAppScript       = $script:GI_InstallAppScript
            DetectAppScript        = $script:GI_DetectAppScript
        }


    } elseif($Script:HashPattern -eq "InstallPrinterByIP") {

        Write-Log "Building return hashtable for InstallPrinterByIP..."

        $result = @{
            MainInstallCommand     = $script:GI_MainInstallCommand
            MainInstallCommandTXT  = $script:GI_MainInstallCommandTXT
            MainDetectCommand      = $script:GI_MainDetectCommand
            MainDetectCommandTXT   = $script:GI_MainDetectCommandTXT
            InstallPrinterScript   = $script:GI_InstallPrinterScript
            DetectPrinterScript    = $script:GI_DetectPrinterScript
        }


    } elseif($Script:HashPattern -eq "UninstallPrinterByName") {

        Write-Log "Building return hashtable for UninstallPrinterByName..."

        $result = @{
            UninstallCommand     = $script:GI_UninstallCommand
            UninstallCommandTXT  = $script:GI_UninstallCommandTXT
            UninstallPrinterScript   = $script:GI_UninstallPrinterScript
        }


    } elseif($Script:HashPattern -eq "UninstallApp"){

        Write-Log "Building return hashtable for UninstallApp..."

        $result = @{
            UninstallCommand     = $script:GI_UninstallCommand
            UninstallCommandTXT  = $script:GI_UninstallCommandTXT
            UninstallAppScript   = $script:GI_UninstallAppScript
        }


    } elseif ($Script:HashPattern -eq "RegRemediation"){


        $result = @{

            DetectScript = $script:GI_DetectScript
            DetectScriptCommandTXT = $script:GI_DetectScriptCommandTXT
            RemediationScript = $script:GI_RemediationScript
            RemediationScriptCommandTXT = $script:GI_RemediationScriptCommandTXT
        }


    }Else{

        Write-Log "Unknown HashPattern: $($Script:HashPattern). Cannot build return hashtable!" -ForegroundColor Red
        Exit 1

    }

    #Write-Log "SCRIPT: $ThisFileName | | START" -ForegroundColor Yellow

    Write-Log ""


    Write-Log "Values to return to caller."
    foreach ($key in $result.Keys) {
        Write-Log "   $key : $($result[$key])"
    }

    #Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END | Returning hashtable above to caller."
    Write-Log "SCRIPT: $ThisFileName | DESIRED FUNCTION: $DesiredFunction | PARAMS: $FunctionParams | END"

    return $result

}

Write-Log ""
Write-Log "SCRIPT: $ThisFileName | DESIRED FUNCTION: $DesiredFunction | PARAMS: $FunctionParams | END"

return $result