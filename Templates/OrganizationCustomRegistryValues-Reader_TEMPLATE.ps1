# This scripts acts as a centralized configurator to read organization-specific custom registry values. It's just a middleman. See the template section below to see what to add.

Param(

    [string]$RegistryStoredScriptValuesRoot="HKLM:\Software\PowerDeploy"

)


$RepoRoot = Split-Path -Path $PSScriptRoot -Parent
$WorkingDirectory = Split-Path -Path $RepoRoot -Parent
$ThisFileName = $MyInvocation.MyCommand.Name

$RegEditScriptPath = "$RepoRoot\Configurators\Configure-Registry.ps1"



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


##########
## MAIN ##
##########

Write-Log "SCRIPT: $ThisFileName | START"

# checks
if( !(Test-Path $RegEditScriptPath) ) {
    Write-Log "SCRIPT: $ThisFileName | ERROR: Registry edit script not found at path: $RegEditScriptPath" "ERROR"
    return $null
}

#Write-Host "Requesting read of all registry values under: $RegistryRoot`n"
$RegData = & $RegEditScriptPath `
    -Function "Read-All" `
    -WorkingDirectory $WorkingDirectory `
    -KeyPath $RegistryStoredScriptValuesRoot

#Write-Host "`nTesting access to specific registry values:"
if((!$RegData) -or ($RegData.Count -eq 0) -or $RegData -eq $null) {
    Write-Log "SCRIPT: $ThisFileName | No data returned from registry read!" "ERROR"
    return $null
}


## TEMPLATE: Set the needed variables for your organization
    $ApplicationContainerSASkey = $RegData["HKLM:\Software\PowerDeploy\Applications"]["ApplicationContainerSASkey"]
    $ApplicationDataJSONpath = $RegData["HKLM:\Software\PowerDeploy\Applications"]["ApplicationDataJSONpath"]
    $PrinterDataJSONpath = $RegData["HKLM:\Software\PowerDeploy\Printers"]["PrinterDataJSONpath"]
    $PrinterContainerSASkey = $RegData["HKLM:\Software\PowerDeploy\Printers"]["PrinterContainerSASkey"]
    $StorageAccountName = $RegData["HKLM:\Software\PowerDeploy\General"]["StorageAccountName"]
    $CustomRepoURL = $RegData["HKLM:\Software\PowerDeploy\General"]["CustomRepoURL"]
    $CustomRepoToken = $RegData["HKLM:\Software\PowerDeploy\General"]["CustomRepoToken"]
##

    # Build a hashtable of the values
    $Hash = @{
        "ApplicationContainerSASkey" = $ApplicationContainerSASkey
        "ApplicationDataJSONpath"    = $ApplicationDataJSONpath
        "PrinterDataJSONpath"        = $PrinterDataJSONpath
        "PrinterContainerSASkey"     = $PrinterContainerSASkey
        "StorageAccountName"         = $StorageAccountName
        "CustomRepoURL"              = $CustomRepoURL
        "CustomRepoToken"            = $CustomRepoToken
    }
##

Write-Log "SCRIPT: $ThisFileName | Retrieved the following organization custom registry values:"
foreach ($key in $Hash.Keys) {
    $value = $Hash[$key]
    Write-Log "SCRIPT: $ThisFileName |     $key : $value"
}   

Write-Log "SCRIPT: $ThisFileName | END | Returning hashtable of organization custom registry values." 


return $Hash




