<#

.SYNOPSIS
Custom script maker, makes scripts from templates


.DESCRIPTION
Run Generate_Install-Command.ps1 to call this script
It can technically create custom scripts from any template script, but it's primarily designed to create custom Git-Runner scripts. Almost every command can be passed as a parameter to the Git-Runner script.

#>



param(
    [string]$RepoNickName,
    [string]$RepoUrl,
    [string]$RepoBranch,
    [string]$WorkingDirectory,
    [string]$ScriptPath,
    #[hashtable]$ScriptParams,
    [string]$ScriptParamsBase64,
    [string]$CustomNameModifier,
    [string]$TemplateScript="GitRunnerScript"
)

# $RepoNickName = 'TEST'
# $RepoUrl = 'TEST'
# $WorkingDirectory = 'TEST'
# $ScriptPath = 'TEST'
# $ScriptParams

# Fix the params
$OldRepoNickName = $RepoNickName

$RepoNickName = "'" +    $RepoNickName + "'"
$RepoUrl = "'" +    $RepoUrl + "'"
$RepoBranch = "'" +    $RepoBranch + "'"
$WorkingDirectory = "'" +    $WorkingDirectory + "'"
$ScriptPath = "'" +    $ScriptPath + "'"
$ScriptParamsBase64 = "'" +    $ScriptParamsBase64 + "'"

    # $RepoNickName
    # $RepoUrl
    # $WorkingDirectory
    # $ScriptPath
    # $ScriptParams

$ThisFileName = $MyInvocation.MyCommand.Name
$RepoRoot = Split-Path -Path $PSScriptRoot -Parent
$ThisWorkingDirectory = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

$LogRoot = "$ThisWorkingDirectory\Logs\Other_Logs"
$LogPath = "$LogRoot\$ThisFileName._Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

$DestinationPath = "$ThisWorkingDirectory\TEMP\Custom_Scripts_Output"

$GitRunnerScript = "$RepoRoot\Templates\Git-Runner_TEMPLATE.ps1"
$PrinterDetectionScript = "$RepoRoot\Templates\Detection-Script-Printer_TEMPLATE.ps1"
$WinGetDetectionScript = "$RepoRoot\Templates\Detection-Script-WinGetApp_TEMPLATE.ps1"


Write-Host "SCRIPT: $ThisFileName | START" -ForegroundColor Yellow
Write-Host ""
# Output all vars to command line for debugging
Write-Host "`n--- Input Parameters ---`n"
Foreach ($var in $PSBoundParameters.GetEnumerator()) {
    Write-Host "$($var.Key): $($var.Value)"
}
Write-Host "`n--- End Input Parameters ---`n"
Write-Host ""

# Main 

if ($TemplateScript -eq "GitRunnerScript"){
    
    #$GitRunnerScript = "$RepoRoot\Templates\Git-Runner_TEMPLATE.ps1"
    $EndScriptNameTemplate = "Git-Runner_Custom"
    $TargetScript = $GitRunnerScript   # original script
    # ---

    $RepoNickName_DEC = '$RepoNickName = '+$RepoNickName
    $RepoUrl_DEC = '$RepoUrl = '+$RepoUrl
    $RepoBranch_DEC = '$RepoBranch = '+$RepoBranch
    $WorkingDirectory_DEC = '$WorkingDirectory = '+$WorkingDirectory
    $ScriptPath_DEC = '$ScriptPath = '+$ScriptPath
    $ScriptParamsBase64_DEC = '$ScriptParamsBase64 = '+$ScriptParamsBase64
    $StashChanges_DEC = '$StashChanges = $true'
    # The template's param() block gets stripped below, so explicitly clear $ScriptParams
    # to keep the script from inheriting a leftover session variable via dynamic scoping
    $ScriptParamsReset_DEC = '$ScriptParams = $null'


# --- config for GitRunnerScript ---
$KeyPhrase    = "#####" # the marker/keyphrase
$NewCode      = @"
# --- injected code start ---

    $RepoNickName_DEC
    $RepoUrl_DEC
    $RepoBranch_DEC
    $WorkingDirectory_DEC
    $ScriptPath_DEC
    $StashChanges_DEC
    $ScriptParamsReset_DEC
    $ScriptParamsBase64_DEC

# --- injected code end ---
"@

} elseif( $TemplateScript -eq "PrinterDetectionScript"){ # If you want to add more templates, copy this block and modify accordingly

    # $EndScriptNameTemplate = "Detect-Printer_Custom"
    # Write-Log "this functionality is not yet implemented" "ERROR"
    # Exit 1
    
}else {
    Write-Host "ERROR: Unknown TemplateScript value: $TemplateScript"
    #return
    Exit 1
}


# $BaseName = [System.IO.Path]::GetFileNameWithoutExtension($TargetScript)
$Ext      = [System.IO.Path]::GetExtension($TargetScript)

if($CustomNameModifier){
    $EndScript ="$EndScriptNameTemplate.$OldRepoNickName.$CustomNameModifier.$(Get-Date -Format 'yyyyMMdd_HHmmss')$Ext"
}
else {
    $EndScript ="$EndScriptNameTemplate.$OldRepoNickName.$(Get-Date -Format 'yyyyMMdd_HHmmss')$Ext"
}


TRY{


    # --- 1. Make a copy of the target script ---

    $CopyPath = Join-Path $DestinationPath $EndScript

    if(!(Test-Path -Path $DestinationPath)){
        New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
    }

    Copy-Item -Path $TargetScript -Destination $CopyPath -Force

    # --- 2. Load the copied script as a single string ---
    $content = Get-Content -Path $CopyPath -Raw

    # Find the keyphrase position
    $index = $content.IndexOf($KeyPhrase)
    if ($index -lt 0) {
        throw "Key phrase '$KeyPhrase' not found in script '$CopyPath'."
    }

    # Erase everything *before* the keyphrase, keep from keyphrase onward
    $restOfScript = $content.Substring($index)

    # Build new content: injected code + newline + original from keyphrase down
    $updatedContent = $NewCode + "`r`n" + $restOfScript

    # Overwrite the copied script (original remains untouched)
    $updatedContent | Set-Content -Path $CopyPath -Encoding UTF8

    Write-Host "Custom Git-Runner script written to: $CopyPath"

    Return $CopyPath

}CATCH{

    $ErrorMessage = $_.Exception.Message
    $FailedItem   = $_.Exception.ItemName
    Write-Host "Error: $ErrorMessage"
    Write-Host "Failed Item: $FailedItem"
    Exit 1

}