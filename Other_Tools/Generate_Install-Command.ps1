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

    [Parameter(Mandatory=$true)]
    [String]$TargetWorkingDirectory

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



function New-IntuneGitRunnerCommand {
    param(
        [string]$RepoNickName,
        [string]$RepoUrl,
        [string]$TargetWorkingDirectory,
        [string]$ScriptPath,
        [hashtable]$ScriptParams,
        [string]$RequireOrgKeys='', # '' (no check), 'Printers' or 'Applications'. Install commands only.
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
    Write-Log "RequireOrgKeys: $RequireOrgKeys"
    Write-Log ""

    # Only '' (no check), 'Printers' or 'Applications'. A typo must never silently turn the endpoint check off.
    if ($RequireOrgKeys -and ($RequireOrgKeys -cnotin @('Printers', 'Applications'))) {
        Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END | Invalid RequireOrgKeys value: '$RequireOrgKeys'. Allowed: 'Printers', 'Applications', or empty." "ERROR"
        Exit 1
    }

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

    # Org registry values pre-check: added inside the -Command string, before its closing quote.
    # Empty = the command above is left exactly as built.
    # "; exit $LASTEXITCODE" is required: under powershell.exe -Command, Windows PowerShell 5.1 turns a
    # script's "Exit 1618" into process exit code 1 (tested), and Intune would read that as Failed instead
    # of Retry. Passing $LASTEXITCODE back out keeps 1618, 0 and 1 exactly; an uncaught error still gives 1.
    if ($RequireOrgKeys) {
        if (-not $command.EndsWith('"')) {
            Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END | Unexpected command shape; cannot add -RequireOrgKeys." "ERROR"
            Exit 1
        }
        $command = $command.Substring(0, $command.Length - 1) + " -RequireOrgKeys '$RequireOrgKeys'" + '; exit $LASTEXITCODE' + '"'
    }
        Write-Log ""


    Write-Log "Custom command generated:" #-ForegroundColor Green
    Write-Log $command
    Write-Log ""
    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | Creating custom script..." #-ForegroundColor Green
    Write-Log ""

    # Create the custom script with the current params
    if($CustomNameModifier){
        $global:CustomScript = & $CustomGitRunnerMakerScript -RepoNickName $RepoNickName -RepoUrl $RepoUrl -RepoBranch $RepoBranch -WorkingDirectory $TargetWorkingDirectory -ScriptPath $ScriptPath -ScriptParamsBase64 $paramsBase64 -CustomNameModifier $CustomNameModifier -RequireOrgKeys $RequireOrgKeys
    }
    else {
        $global:CustomScript = & $CustomGitRunnerMakerScript -RepoNickName $RepoNickName -RepoUrl $RepoUrl -RepoBranch $RepoBranch -WorkingDirectory $TargetWorkingDirectory -ScriptPath $ScriptPath -ScriptParamsBase64 $paramsBase64 -RequireOrgKeys $RequireOrgKeys
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



#####################################################################
### Organization registry values (shared by Intune and local setup) ###
#####################################################################
# The one place the org registry layout and its defaults are defined on the writer side.
# Returns the seven entries in order, each { KeyPath; ValueName; ValueType; Value }. Value is always a
# string ("$x", so an omitted or $null value is ""). Used by:
#   - OrgRegistryChangesString   (the bracketed string for the Intune Remediation and local setup)
#   - OrgRegistryPlatformScript  (the self-contained Intune Platform Script)
# Logs nothing: callers decide what is shown, and the platform script path never shows values.
Function OrgRegistryEntryList {

    Param(

        $StorageAccountName = "powerdeploy",

        $PrinterDataJSONpath = "printers/PrinterData.json",
        $PrinterContainerSASkey,

        $ApplicationDataJSONpath = "applications/ApplicationData.json",
        $ApplicationContainerSASkey,

        $CustomRepoURL=$NULL,
        $CustomRepoToken=$NULL

    )

    # Make as many as you need (keep this order: the bracketed string is built in this order)
    return @(
        [pscustomobject]@{ KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\General";      ValueName = "StorageAccountName";         ValueType = "String"; Value = "$StorageAccountName" }
        [pscustomobject]@{ KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\General";      ValueName = "CustomRepoURL";              ValueType = "String"; Value = "$CustomRepoURL" }
        [pscustomobject]@{ KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\General";      ValueName = "CustomRepoToken";            ValueType = "String"; Value = "$CustomRepoToken" }
        [pscustomobject]@{ KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\Printers";     ValueName = "PrinterDataJSONpath";        ValueType = "String"; Value = "$PrinterDataJSONpath" }
        [pscustomobject]@{ KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\Printers";     ValueName = "PrinterContainerSASkey";     ValueType = "String"; Value = "$PrinterContainerSASkey" }
        [pscustomobject]@{ KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\Applications"; ValueName = "ApplicationDataJSONpath";    ValueType = "String"; Value = "$ApplicationDataJSONpath" }
        [pscustomobject]@{ KeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\Applications"; ValueName = "ApplicationContainerSASkey"; ValueType = "String"; Value = "$ApplicationContainerSASkey" }
    )
}

# Returns the bracketed RegistryChanges string that General_RemediationScript-Registry_TEMPLATE.ps1
# parses. RegRemediationScript wraps it for Intune; Setup.ps1's OrganizationRegistryEntries--Local-Setup
# passes it straight to the remediation template to write this PC's registry.
# Layout and defaults come from OrgRegistryEntryList; the string and the log lines are the same as
# before that function existed.
Function OrgRegistryChangesString {

    # Same parameters as OrgRegistryEntryList; the defaults live there only.
    Param(

        $StorageAccountName,

        $PrinterDataJSONpath,
        $PrinterContainerSASkey,

        $ApplicationDataJSONpath,
        $ApplicationContainerSASkey,

        $CustomRepoURL,
        $CustomRepoToken

    )

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START" -ForegroundColor Yellow
    Write-Log ""

    $Entries = @(OrgRegistryEntryList @PSBoundParameters)
    $EntryValue = @{}
    foreach ($Entry in $Entries) { $EntryValue[$Entry.ValueName] = $Entry.Value }

    # Display all the supplied parameters for the function:
    Write-Log "Function parameters received:"
        Write-Log ""

    # Check the returned hashtable
    Write-Log "StorageAccountName:         $($EntryValue['StorageAccountName'])"
    Write-Log "PrinterDataJSONpath:        $($EntryValue['PrinterDataJSONpath'])"
    Write-Log "PrinterContainerSASkey:     $($EntryValue['PrinterContainerSASkey'])"
    Write-Log "ApplicationDataJSONpath:    $($EntryValue['ApplicationDataJSONpath'])"
    Write-Log "ApplicationContainerSASkey: $($EntryValue['ApplicationContainerSASkey'])"
    Write-Log "CustomRepoURL:              $($EntryValue['CustomRepoURL'])"
    Write-Log "CustomRepoToken:            $($EntryValue['CustomRepoToken'])"
    # End display of parameters
    Write-Log ""
    # Choose the registry changes.

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

        # One bracketed entry per value, comma-separated (no comma after the last one)
        $Brackets = foreach ($Entry in $Entries) {
            $KeyPath   = $Entry.KeyPath
            $ValueName = $Entry.ValueName
            $ValueType = $Entry.ValueType
            $Value     = $Entry.Value
            "["+"-KeyPath ""$KeyPath"" -ValueName ""$ValueName"" -ValueType ""$ValueType"" -Value ""$Value"""+"]"
        }
        $RegistryChangesSTRING = @($Brackets) -join ","

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"
    Write-Log ""

    return $RegistryChangesSTRING
}

############################################################
### Example: Create Detect/Remediation Script for InTune ###
############################################################
Function RegRemediationScript {

    # Same parameters as OrgRegistryChangesString; the defaults live there only, so anything not
    # supplied here falls through to them.
    Param(

        $StorageAccountName,

        $PrinterDataJSONpath,
        $PrinterContainerSASkey,

        $ApplicationDataJSONpath,
        $ApplicationContainerSASkey,

        $CustomRepoURL,
        $CustomRepoToken

    )

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START" -ForegroundColor Yellow
    Write-Log ""
    Write-Log "Generating Detect/Remediation scripts for Registry changes..." -ForegroundColor Yellow

        # Declare as list to bypass the Git Runner's function of putting passed string params into double quotes. This breaks the pass to the remediation script.
        $RegistryChanges = @()

        [string]$RegistryChangesSTRING = OrgRegistryChangesString @PSBoundParameters

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


##########################################################################
### Org registry values as a self-contained Intune Platform Script     ###
##########################################################################
# Stamps Templates\OrgRegistry-PlatformScript_TEMPLATE.ps1 with the same seven values the Remediation
# writes (layout and defaults from OrgRegistryEntryList), so the values exist before PowerDeploy's
# Win32 apps install during Autopilot (Intune Platform Scripts run before Win32 apps; Remediations
# do not run during the Enrollment Status Page). The result needs no Git, network or repo files.
#
# Values are embedded as single-quoted PowerShell literals (every kind of single quote doubled, via
# CodeGeneration.EscapeSingleQuotedStringContent), so any character is safe. The script is encoded with
# a strict UTF-8 encoder (a value that cannot be encoded, such as a lone surrogate, stops generation),
# and the SAVED file is read back, parsed, and every value compared with what was meant before it is
# returned; on any mismatch the file is deleted.
# This function's own lines log only value names and set/blank, never a value. NOTE: the generator's
# dispatcher (MAIN, "Function Parameters Breakdown") still logs every FunctionParams value, SAS keys and
# token included, on this path too; that existing logging is deferred to the security audit.
#
# Writes TEMP\Custom_Scripts_Output\PowerDeploy-OrgRegistry_<commit>_<yyyyMMdd_HHmmss>.ps1 (UTF-8 with BOM)
# and returns it to the caller through the same "BuildMe" / $Script:HashPattern pattern as the others.
Function OrgRegistryPlatformScript {

    # The same seven value parameters as RegRemediationScript (defaults live in OrgRegistryEntryList
    # only), plus the deploy mode for the stamped header.
    Param(

        $StorageAccountName,

        $PrinterDataJSONpath,
        $PrinterContainerSASkey,

        $ApplicationDataJSONpath,
        $ApplicationContainerSASkey,

        $CustomRepoURL,
        $CustomRepoToken,

        [string]$DeployMode,

        # TEST ONLY (Tests\OrgRegistryPlatformScript.Tests.ps1). Setup.ps1 never passes these.
        [string]$RegistryRoot = 'SOFTWARE\PowerDeploy',
        [string]$OutputDirectory

    )

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | START" -ForegroundColor Yellow
    Write-Log ""
    Write-Log "Generating the Intune Platform Script for the organization registry values..." -ForegroundColor Yellow

    $TemplatePath = "$RepoRoot\Templates\OrgRegistry-PlatformScript_TEMPLATE.ps1"
    $HelpersPath  = "$RepoRoot\Other_Tools\OrgRegistry-Intune_Helpers.ps1"
    $MaxBytes     = 200 * 1024   # Intune platform script limit: the file must be smaller than 200 KB

    # The real root, or the test-only root. Anything else could lock down some unrelated key.
    # Every pattern here ends in \z, not $: .NET's $ also matches before a final newline, so
    # "SOFTWARE\PowerDeploy`n" would pass a $-anchored check and stamp a sibling key with a line feed
    # in its name.
    $RootPattern = '^SOFTWARE\\PowerDeploy(-Test-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})?\z'

    function Stop-PlatformScriptGeneration {
        param([string]$Reason)
        Write-Log "SCRIPT: $ThisFileName | FUNCTION: OrgRegistryPlatformScript | END | $Reason" "ERROR"
        Exit 1
    }

    # Deploy mode, registry root and working directory go into comments and paths in the generated
    # script, so only plain characters are allowed (a value can never ride along in them).
    if ($DeployMode -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]*\z') { Stop-PlatformScriptGeneration "DeployMode is missing or has unexpected characters." }
    if ($RegistryRoot -cnotmatch $RootPattern) { Stop-PlatformScriptGeneration "RegistryRoot must be SOFTWARE\PowerDeploy (or the test-only SOFTWARE\PowerDeploy-Test-<guid>)." }
    if ([string]::IsNullOrWhiteSpace($TargetWorkingDirectory) -or ($TargetWorkingDirectory -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9 ._\\()-]*\z')) { Stop-PlatformScriptGeneration "TargetWorkingDirectory must be a local path such as C:\ProgramData\PowerDeploy--<MODE>." }
    if (-not (Test-Path -LiteralPath $TemplatePath)) { Stop-PlatformScriptGeneration "Template not found: $TemplatePath" }
    if (-not (Test-Path -LiteralPath $HelpersPath))  { Stop-PlatformScriptGeneration "Helpers not found: $HelpersPath" }

    # Functions only; defines Get-PDOrgRegistrySourceCommit in this function's scope.
    . $HelpersPath

    # Same commit string as the app wizard, keyed to this template's uncommitted edits.
    $SourceCommit = Get-PDOrgRegistrySourceCommit -RepoRoot $RepoRoot
    $Now = Get-Date
    $GeneratedAt = $Now.ToString('yyyy-MM-dd HH:mm:ss')

    Write-Log "DeployMode:             $DeployMode"
    Write-Log "Source commit:          $SourceCommit"
    Write-Log "Registry root:          HKLM\$RegistryRoot"
    Write-Log "TargetWorkingDirectory: $TargetWorkingDirectory"
    Write-Log ""

    # Values: only the seven value parameters go to the layout function, so its defaults apply to the rest.
    $ValueParams = @{}
    foreach ($ParamName in @('StorageAccountName', 'PrinterDataJSONpath', 'PrinterContainerSASkey', 'ApplicationDataJSONpath', 'ApplicationContainerSASkey', 'CustomRepoURL', 'CustomRepoToken')) {
        if ($PSBoundParameters.ContainsKey($ParamName)) { $ValueParams[$ParamName] = $PSBoundParameters[$ParamName] }
    }
    $Entries = @(OrgRegistryEntryList @ValueParams)

    # Parse the layout here, at generation time: the device only gets subkey / name / value.
    $AllowedSubKeys = @('General', 'Printers', 'Applications')
    $Stamped = @()
    foreach ($Entry in $Entries) {
        if ($Entry.ValueType -cne 'String') { Stop-PlatformScriptGeneration "Only String values are supported; $($Entry.ValueName) is $($Entry.ValueType)." }
        $KeyMatch = [regex]::Match([string]$Entry.KeyPath, '^HKEY_LOCAL_MACHINE\\SOFTWARE\\PowerDeploy\\(?<sub>[A-Za-z]+)\z')
        if ((-not $KeyMatch.Success) -or ($AllowedSubKeys -cnotcontains $KeyMatch.Groups['sub'].Value)) { Stop-PlatformScriptGeneration "Unexpected key path for $($Entry.ValueName): $($Entry.KeyPath)" }
        if ([string]$Entry.ValueName -cnotmatch '^[A-Za-z0-9]+\z') { Stop-PlatformScriptGeneration "Unexpected value name: $($Entry.ValueName)" }
        if (([string]$Entry.Value).IndexOf([char]0) -ge 0) { Stop-PlatformScriptGeneration "$($Entry.ValueName) contains a NUL character, which a registry String value cannot hold." }
        $Stamped += [pscustomobject]@{ SubKey = $KeyMatch.Groups['sub'].Value; Name = [string]$Entry.ValueName; Value = [string]$Entry.Value }
    }

    Write-Log "Values to stamp (names only):"
    foreach ($Entry in $Stamped) {
        $State = 'set'
        if ([string]::IsNullOrEmpty($Entry.Value)) { $State = 'blank' }
        Write-Log "   $($Entry.SubKey)\$($Entry.Name) : $State"
    }
    Write-Log ""

    function ConvertTo-PDQuotedLiteral {
        param([AllowNull()][AllowEmptyString()][string]$Text)
        return "'" + [System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent([string]$Text) + "'"
    }

    # Header comment: deploy mode, commit, time only (all checked above). Never a value.
    $HeaderLines = @(
        "# PowerDeploy organization registry values - Intune Platform Script (GENERATED; do not edit by hand)"
        "# Deploy mode   : $DeployMode"
        "# Source commit : $SourceCommit"
        "# Generated     : $GeneratedAt"
        "# Generated by PowerDeploy Setup from Templates\OrgRegistry-PlatformScript_TEMPLATE.ps1"
        "# Intune: run as SYSTEM (logged on credentials = No), signature check = No, 64-bit host = Yes, device groups."
    )

    $StampLines = @(
        '$PDStamped          = $true'
        ('$PDDeployMode       = ' + (ConvertTo-PDQuotedLiteral $DeployMode))
        ('$PDSourceCommit     = ' + (ConvertTo-PDQuotedLiteral $SourceCommit))
        ('$PDRegistryRoot     = ' + (ConvertTo-PDQuotedLiteral $RegistryRoot))
        ('$PDWorkingDirectory = ' + (ConvertTo-PDQuotedLiteral $TargetWorkingDirectory))
        '$PDOrgValues        = @('
    )
    for ($i = 0; $i -lt $Stamped.Count; $i++) {
        $Separator = ','
        if ($i -eq ($Stamped.Count - 1)) { $Separator = '' }
        $StampLines += ('    [pscustomobject]@{ SubKey = ' + (ConvertTo-PDQuotedLiteral $Stamped[$i].SubKey) + '; Name = ' + (ConvertTo-PDQuotedLiteral $Stamped[$i].Name) + '; Value = ' + (ConvertTo-PDQuotedLiteral $Stamped[$i].Value) + ' }' + $Separator)
    }
    $StampLines += ')'

    # Fill the template's two stamp regions (each marker must appear exactly once).
    $Template = [System.IO.File]::ReadAllText($TemplatePath)
    $HeaderToken = '#__PD_STAMP_HEADER__'
    $BeginToken  = '#__PD_STAMP_BEGIN__'
    $EndToken    = '#__PD_STAMP_END__'
    foreach ($Token in @($HeaderToken, $BeginToken, $EndToken)) {
        $Count = ([regex]::Matches($Template, [regex]::Escape($Token))).Count
        if ($Count -ne 1) { Stop-PlatformScriptGeneration "The template must contain $Token exactly once (found $Count)." }
    }

    $BeginAt = $Template.IndexOf($BeginToken, [System.StringComparison]::Ordinal) + $BeginToken.Length
    $EndAt   = $Template.IndexOf($EndToken, [System.StringComparison]::Ordinal)
    if ($EndAt -le $BeginAt) { Stop-PlatformScriptGeneration "The template's stamp markers are out of order." }

    $NL = "`r`n"
    $Content = $Template.Substring(0, $BeginAt) + $NL + ($StampLines -join $NL) + $NL + $Template.Substring($EndAt)
    $Content = $Content.Replace($HeaderToken, ($HeaderLines -join $NL))

    # Checks script text the way the device will read it: it must parse, and every stamped value must
    # come back exactly. Returns '' when it does, otherwise the reason (names only, never a value).
    function Test-PDStampedContent {
        param([AllowEmptyString()][string]$Text)

        $ParseErrors = $null
        $Ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$null, [ref]$ParseErrors)
        if (@($ParseErrors).Count -gt 0) { return "The generated script does not parse ($(@($ParseErrors).Count) error(s))." }

        $ValuesAssignment = @($Ast.FindAll({ param($Node) ($Node -is [System.Management.Automation.Language.AssignmentStatementAst]) -and ($Node.Left.Extent.Text -ceq '$PDOrgValues') }, $true))
        if ($ValuesAssignment.Count -ne 1) { return "The generated script must assign the values exactly once." }
        $Tables = @($ValuesAssignment[0].FindAll({ param($Node) $Node -is [System.Management.Automation.Language.HashtableAst] }, $true))
        if ($Tables.Count -ne $Stamped.Count) { return "The generated script holds $($Tables.Count) entries instead of $($Stamped.Count)." }
        for ($i = 0; $i -lt $Stamped.Count; $i++) {
            $Parsed = @{}
            foreach ($Pair in $Tables[$i].KeyValuePairs) {
                $Constant = @($Pair.Item2.FindAll({ param($Node) $Node -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true))
                if ($Constant.Count -ne 1) { return "Entry $($i + 1) is not a plain string literal." }
                $Parsed[$Pair.Item1.Value] = $Constant[0].Value
            }
            if (($Parsed['SubKey'] -cne $Stamped[$i].SubKey) -or ($Parsed['Name'] -cne $Stamped[$i].Name) -or ($Parsed['Value'] -cne $Stamped[$i].Value)) {
                return "$($Stamped[$i].SubKey)\$($Stamped[$i].Name) did not survive embedding."
            }
        }
        return ''
    }

    $Problem = Test-PDStampedContent -Text $Content
    if ($Problem) { Stop-PlatformScriptGeneration "$Problem Nothing was saved." }

    # UTF-8 with BOM: Windows PowerShell 5.1 reads a BOM-less file as ANSI, which would corrupt a
    # non-ASCII value. Strict (throwOnInvalidBytes): a value that cannot be encoded, such as a lone
    # surrogate, stops generation instead of being saved silently as U+FFFD.
    $Encoding = New-Object System.Text.UTF8Encoding($true, $true)
    try {
        $Bytes = [byte[]]($Encoding.GetPreamble() + $Encoding.GetBytes($Content))
    } catch {
        Stop-PlatformScriptGeneration "A value cannot be encoded as UTF-8 (for example a lone surrogate character; $($_.Exception.GetType().Name)). Nothing was saved."
    }
    if ($Bytes.Length -ge $MaxBytes) { Stop-PlatformScriptGeneration "The generated script is $($Bytes.Length) bytes; Intune platform scripts must be smaller than $MaxBytes bytes. Nothing was saved." }

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = "$WorkingDirectory\TEMP\Custom_Scripts_Output" }
    $SafeCommit = $SourceCommit -replace '[^A-Za-z0-9._-]', '_'
    $PlatformScriptPath = Join-Path $OutputDirectory ("PowerDeploy-OrgRegistry_{0}_{1}.ps1" -f $SafeCommit, $Now.ToString('yyyyMMdd_HHmmss'))

    try {
        if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force -ErrorAction Stop | Out-Null }
        [System.IO.File]::WriteAllBytes($PlatformScriptPath, $Bytes)
    } catch {
        if (Test-Path -LiteralPath $PlatformScriptPath) { Remove-Item -LiteralPath $PlatformScriptPath -Force -ErrorAction SilentlyContinue }
        Stop-PlatformScriptGeneration "Could not save the platform script to $PlatformScriptPath ($($_.Exception.GetType().Name))."
    }

    # Read the SAVED file back (strict UTF-8, BOM required) and check it again: what Intune will get is
    # what was checked. Any mismatch deletes the file.
    $SavedProblem = ''
    try {
        $SavedBytes = [System.IO.File]::ReadAllBytes($PlatformScriptPath)
        $Preamble = $Encoding.GetPreamble()
        if (($SavedBytes.Length -lt $Preamble.Length) -or ($SavedBytes[0] -ne $Preamble[0]) -or ($SavedBytes[1] -ne $Preamble[1]) -or ($SavedBytes[2] -ne $Preamble[2])) {
            $SavedProblem = "The saved file has no UTF-8 BOM."
        } else {
            $SavedText = $Encoding.GetString($SavedBytes, $Preamble.Length, $SavedBytes.Length - $Preamble.Length)
            if ($SavedText -cne $Content) { $SavedProblem = "The saved file does not match the generated script." }
            else { $SavedProblem = Test-PDStampedContent -Text $SavedText }
        }
    } catch {
        $SavedProblem = "The saved file could not be read back ($($_.Exception.GetType().Name))."
    }
    if ($SavedProblem) {
        Remove-Item -LiteralPath $PlatformScriptPath -Force -ErrorAction SilentlyContinue
        Stop-PlatformScriptGeneration "$SavedProblem The file was deleted."
    }

    Write-Log "Platform script saved here: $PlatformScriptPath ($($Bytes.Length) bytes)" "SUCCESS"
    Write-Log ""

    # Store results in script-scoped variables so the main script can package them up
    $script:GI_PlatformScript             = $PlatformScriptPath
    $script:GI_PlatformScriptSourceCommit = $SourceCommit
    $script:GI_PlatformScriptGeneratedAt  = $GeneratedAt
    $script:GI_PlatformScriptDeployMode   = $DeployMode

    Write-Log "Return values prepared."
    Write-Log "   PlatformScript             : $script:GI_PlatformScript"
    Write-Log "   PlatformScriptSourceCommit : $script:GI_PlatformScriptSourceCommit"
    Write-Log "   PlatformScriptGeneratedAt  : $script:GI_PlatformScriptGeneratedAt"
    Write-Log "   PlatformScriptDeployMode   : $script:GI_PlatformScriptDeployMode"

    Write-Log "SCRIPT: $ThisFileName | FUNCTION: $($MyInvocation.MyCommand.Name) | END"
    Write-Log ""

    $Script:HashPattern = "OrgRegistryPlatformScript"

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
        [string]$RequireOrgKeys='', # Passed to the INSTALL command only; the detect command never gets it.
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
        -RequireOrgKeys "$RequireOrgKeys" `
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
        [string]$RequireOrgKeys='', # Passed to the INSTALL command only; the detect command never gets it.
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
    Write-Log "RequireOrgKeys specified as: $RequireOrgKeys"


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
        -RequireOrgKeys "$RequireOrgKeys" `
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

        #[hashtable]$FunctionParams # NOTE: This works for my intended use case but this with the param received snippet below are NOT done according to intent...
        $ApplicationName,
        $UninstallType,
        $Version,
        $UninstallString_DisplayName,
        $WinGetID,
        $UninstallArgs,
        $UninstallCustomString
        
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
    Write-Log "UninstallArgs specified as: $UninstallArgs"


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
            UninstallArgs = "$UninstallArgs"
            UninstallCustomString = "$UninstallCustomString"
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

Write-Log ""

if($FunctionParams -eq $null -or $FunctionParams.Count -eq 0){

    Write-Log "No function parameters provided."

} else {

    Write-Log "Function Parameters Breakdown:"
    Write-Log ""

    ForEach($Param in $FunctionParams.GetEnumerator()){
        Write-Log "   $($Param.Key): $($Param.Value)"
    }

}

Write-Log ""
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


    } elseif ($Script:HashPattern -eq "OrgRegistryPlatformScript"){

        Write-Log "Building return hashtable for OrgRegistryPlatformScript..."

        $result = @{
            PlatformScript             = $script:GI_PlatformScript
            PlatformScriptSourceCommit = $script:GI_PlatformScriptSourceCommit
            PlatformScriptGeneratedAt  = $script:GI_PlatformScriptGeneratedAt
            PlatformScriptDeployMode   = $script:GI_PlatformScriptDeployMode
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