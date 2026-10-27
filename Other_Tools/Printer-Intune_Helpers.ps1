<#

.SYNOPSIS
    Shared builders for publishing PowerDeploy printers to Intune: field formatting, the printer
    Description, the technical Notes block, the display name (and its parser), and the complete
    upload metadata for one printer.

.DESCRIPTION
    One copy of this logic, used by:
      - Setup.ps1  Printer--InTune-Setup        (the one-printer wizard)
      - Setup.ps1  Printer--InTune-BulkCreate   (Other_Tools\Printer-IntuneBulk.ps1)
      - Setup.ps1  WindowsApp--InTune-Setup     (field formatting and the Notes block only)

    The bulk tools find existing printer apps by parsing display names, so the name builder and the
    parser live side by side here and are tested as a pair. Before 2026-10-17 these functions lived
    inside Setup.ps1; the first five below were moved here unchanged.

    This file may be dot-sourced: functions only, no top-level param() block, no output, no side
    effects at import. Setup.ps1 dot-sources it at script scope (see the comment there for why).

.LINK
    .claude/plans/printer-bulk-tools.buildplan.md section 4.2

#>

# ---------------------------------------------------------------------------
# Field formatting, Description and Notes (moved unchanged from Setup.ps1)
# ---------------------------------------------------------------------------

Function Test-IntuneFieldMissing {
    param([AllowNull()][object]$Value)

    # Null, whitespace and the N/A placeholder all mean "not supplied" (spec 4.1 / 4.3).
    $Text = [string]$Value
    return ([string]::IsNullOrWhiteSpace($Text) -or ($Text.Trim() -eq 'N/A'))
}

Function ConvertTo-IntuneFieldText {
    param([AllowNull()][object]$Value)

    if (Test-IntuneFieldMissing -Value $Value) { return 'N/A' }
    return [string]$Value
}

Function Get-IntuneDisplayUrl {
    param([AllowNull()][string]$Url)

    # Display/Notes only. The real $RepoUrl used to build commands is never changed (spec 12.1).
    if ([string]::IsNullOrWhiteSpace($Url)) { return 'N/A' }

    if (Get-Command -Name 'Remove-UrlCredential' -CommandType Function -ErrorAction SilentlyContinue) {
        return (Remove-UrlCredential -Url $Url)
    }

    # Helper library not loaded: still never print user:token@ into a description.
    return ($Url -replace '(?i)^(https?://)[^/@\s]+@', '$1')
}

Function New-IntunePrinterDescription {
    param(
        [AllowNull()][object]$Department,
        [AllowNull()][object]$Location,
        [AllowNull()][object]$Model,
        [AllowNull()][object]$Asset,
        [AllowNull()][object]$PrinterIP
    )

    # Always all five labels, in this order, each N/A on its own (spec 4.2).
    $Lines = @(
        ('Department: {0}' -f (ConvertTo-IntuneFieldText -Value $Department)),
        ('Location: {0}'   -f (ConvertTo-IntuneFieldText -Value $Location)),
        ('Model: {0}'      -f (ConvertTo-IntuneFieldText -Value $Model)),
        ('Asset: {0}'      -f (ConvertTo-IntuneFieldText -Value $Asset)),
        ('PrinterIP: {0}'  -f (ConvertTo-IntuneFieldText -Value $PrinterIP))
    )

    return ($Lines -join "`r`n")
}

Function New-IntuneTechnicalNotes {
    param(
        [AllowNull()][System.Collections.Specialized.OrderedDictionary]$AppFields,
        [AllowNull()][string]$TargetRepo,
        [AllowNull()][string]$TargetBranch,
        [AllowNull()][string]$SourceCommit,
        [AllowNull()][object]$Verified,
        [AllowNull()][string]$WaitsForOrgKeys, # Optional. Adds one "Waits for org keys" line only when passed; callers that omit it get unchanged Notes.
        [AllowNull()][string]$SourceRepoRoot
    )

    # The source repo/branch are read from the repo that built the package, not from whatever
    # directory Setup was started in (spec I03).
    $SourceRepo   = $null
    $SourceBranch = $null

    if (-not [string]::IsNullOrWhiteSpace($SourceRepoRoot)) {
        try { $SourceRepo   = [string](git -C $SourceRepoRoot remote get-url origin 2>$null) } Catch { $SourceRepo = $null }
        try { $SourceBranch = [string](git -C $SourceRepoRoot rev-parse --abbrev-ref HEAD 2>$null) } Catch { $SourceBranch = $null }
    }

    $Lines = @()

    if ($null -ne $AppFields) {
        # Labelled like the POWERDEPLOY DATA block below, so neither section reads as stray data.
        $Lines += 'INSTALLER DATA'
        foreach ($Key in $AppFields.Keys) {
            $Lines += ('{0}: {1}' -f $Key, (ConvertTo-IntuneFieldText -Value $AppFields[$Key]))
        }
        $Lines += ''
    }

    $Lines += 'POWERDEPLOY DATA'
    $Lines += ('Target Repo: {0}'   -f (Get-IntuneDisplayUrl -Url $TargetRepo))
    $Lines += ('Target Branch: {0}' -f (ConvertTo-IntuneFieldText -Value $TargetBranch))
    $Lines += ('Source Repo: {0}'   -f (Get-IntuneDisplayUrl -Url $SourceRepo))
    $Lines += ('Source Branch: {0}' -f (ConvertTo-IntuneFieldText -Value $SourceBranch))
    $Lines += ('Source Commit: {0}' -f (ConvertTo-IntuneFieldText -Value $SourceCommit))
    $Lines += ('Verified: {0}'      -f (ConvertTo-IntuneFieldText -Value $Verified))
    if ($PSBoundParameters.ContainsKey('WaitsForOrgKeys')) {
        # Whether the install command carries -RequireOrgKeys (Git-Runner exits 1618 = Intune retry until the org registry values exist)
        $Lines += ('Waits for org keys: {0}' -f (ConvertTo-IntuneFieldText -Value $WaitsForOrgKeys))
    }

    return ($Lines -join "`r`n")
}

# ---------------------------------------------------------------------------
# Printer display name, source commit, and the full upload metadata
# ---------------------------------------------------------------------------

Function Get-PDPrinterSourceCommit {
    param([AllowNull()][string]$RepoRoot)

    # Commit of the local repo, plus a marker if the packaged Git-Runner has uncommitted edits.
    # The try/catch keeps "git is not installed" meaning "unknown", as it did when this was inline in
    # the wizard: its callers now run inside try blocks, which would otherwise turn a missing command
    # into a caught failure and stop the wizard.
    $CurrentGitVer = $null
    try { $CurrentGitVer = git -C $RepoRoot rev-parse --short HEAD 2>$null } catch { $CurrentGitVer = $null }
    if (-not $CurrentGitVer) { $CurrentGitVer = "unknown" }
    $RunnerChanges = $null
    try { $RunnerChanges = git -C $RepoRoot status --porcelain -- "Templates/Git-Runner_TEMPLATE.ps1" } catch { $RunnerChanges = $null }
    if ($RunnerChanges) { $CurrentGitVer = "$CurrentGitVer.UnstagedChanges" }

    return $CurrentGitVer
}

Function Get-PDPrinterIntuneDisplayName {
    param(
        [AllowNull()][object]$PrinterName,
        [AllowNull()][object]$Department,
        [AllowNull()][string]$DeployMode,
        [AllowNull()][string]$SourceCommit
    )

    # Production:  PRINTER: <Name>          or  PRINTER - <Department>: <Name>
    # Other modes: the same, followed by " [<MODE>] [VER: <commit>]"
    if ($Department){
        $PRn = "PRINTER - $DEPARTMENT"
    } else {
        $PRn = "PRINTER"
    }

    if ($DeployMode -eq "Production"){

            $PotentialPrinterInTuneName = "$PRn"+": $PrinterName"

    } else {
            $PotentialPrinterInTuneName = "$PRn"+": $PrinterName [$DeployMode] [VER: $SourceCommit]"
    }

    return $PotentialPrinterInTuneName
}

Function ConvertFrom-PDPrinterIntuneDisplayName {
    <#
        .SYNOPSIS
        The inverse of Get-PDPrinterIntuneDisplayName. Never throws.

        .OUTPUTS
        { IsPrinter; PrinterName; Department; DeployMode; Version }. IsPrinter is $false (and every
        other field empty) for any name Setup would not have produced.

        .NOTES
        The match is case-sensitive on purpose: Setup always writes "PRINTER", so "Printer Tools: x"
        is somebody else's app. A Department containing ": " cannot be told apart from a printer
        name starting after it; the first ": " wins, which is how such a name reads to a person too.
        A name without a " [MODE] [VER: x]" tail is PRODUCTION, including hand-renamed apps such as
        "PRINTER: Lobby [OLD - f9068c8]", whose PrinterName then keeps the bracketed part and so
        never matches a printer in the JSON.
    #>
    param([AllowNull()][string]$DisplayName)

    $result = [pscustomobject]@{ IsPrinter = $false; PrinterName = ''; Department = ''; DeployMode = ''; Version = '' }
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { return $result }

    $text = $DisplayName.Trim()

    $found = [regex]::Match($text, '^PRINTER(?: - (?<dept>.*?))?: (?<rest>.+)$')
    if (-not $found.Success) { return $result }

    $rest = $found.Groups['rest'].Value
    $mode = 'PRODUCTION'
    $version = ''

    $tail = [regex]::Match($rest, '^(?<name>.+?) \[(?<mode>[A-Z][A-Z0-9-]*)\] \[VER: (?<ver>[^\]]*)\]$')
    if ($tail.Success) {
        $rest    = $tail.Groups['name'].Value
        $mode    = $tail.Groups['mode'].Value
        $version = $tail.Groups['ver'].Value
    }

    if ([string]::IsNullOrWhiteSpace($rest)) { return $result }

    $result.IsPrinter   = $true
    $result.PrinterName = $rest
    $result.Department  = $(if ($found.Groups['dept'].Success) { $found.Groups['dept'].Value } else { '' })
    $result.DeployMode  = $mode
    $result.Version     = $version
    return $result
}

Function New-PDPrinterIntuneMetadata {
    <#
        .SYNOPSIS
        Builds everything Intune needs for one printer: the install and uninstall commands and the
        detection script (through Generate_Install-Command.ps1), the display name, the Description,
        the Notes block, and the metadata hashtable Invoke-InTuneAutoUpload / Invoke-PDIntuneUpload
        take.

        .DESCRIPTION
        Every input arrives as a parameter; nothing is read from the caller's variables, so a batch
        of printers can never leak one printer's Location into the next (the reason Setup.ps1 clears
        those fields before each wizard run).

        -Log receives (Message, Level) for every line the wizard used to log at this point, in the
        same order. Pass $null to stay quiet.

        Throws 'No data returned!' when the generator produces nothing (the wizard exits 1 on it,
        exactly as it did when this code lived inline).

        .OUTPUTS
        Hashtable: Metadata, DisplayName, Description, TechnicalNotes, SourceCommit,
        InstallValues, UninstallValues (the generator's two return hashtables).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$PrinterName,
        [AllowNull()][object]$Department,
        [AllowNull()][object]$Location,
        [AllowNull()][object]$Model,
        [AllowNull()][object]$Asset,
        [AllowNull()][object]$PrinterIP,
        [AllowNull()][object]$Verified,
        [AllowNull()][object]$Publisher,
        [AllowNull()][string]$IntuneWinPath,
        [AllowNull()][string]$RepoUrl,
        [AllowNull()][string]$RepoNickName,
        [AllowNull()][string]$RepoBranch,
        [AllowNull()][string]$TargetWorkingDirectory,
        [AllowNull()][string]$DeployMode,
        [AllowNull()][string]$RepoRoot,
        [AllowNull()][string]$IconPath,
        [Parameter(Mandatory = $true)][string]$GenerateInstallCommandPath,
        [AllowNull()][scriptblock]$Log
    )

    $PDLog = {
        param($Message, $Level)
        if ($null -ne $Log) { $null = & $Log $Message $Level }
    }

        # Create install command

        [hashtable]$FunctionParams = @{
            PrinterName = $PrinterName
            RequireOrgKeys = 'Printers' # Always: the printer catalog and driver zips are private. Git-Runner exits 1618 (Intune retry) until the org registry values exist.
        }



        $ReturnHash2 = & $GenerateInstallCommandPath -DesiredFunction "InstallPrinterByIP" -RepoURL $RepoUrl -RepoNickName $RepoNickName -RepoBranch $RepoBranch -TargetWorkingDirectory $TargetWorkingDirectory -FunctionParams $FunctionParams

        # Check the returned hashtable
        if(($ReturnHash2 -eq $null) -or ($ReturnHash2.Count -eq 0)){
            & $PDLog "No data returned!" "ERROR"
            throw "No data returned!"
        }

        & $PDLog "Values retrieved:" "INFO2"

        foreach ($key in $ReturnHash2.Keys) {

            $value = $ReturnHash2[$key]
            & $PDLog "   $key : $value" "INFO2"

        }

        # $result = $ReturnHash2
        # foreach ($key in $result.Keys) {

        #     Write-Host "   $key : $($result[$key])"

        # }


        # Turn the returned hashtable into variables
        & $PDLog "Setting values as local variables..." "INFO2"
        foreach ($key in $ReturnHash2.Keys) {
            Set-Variable -Name $key -Value $ReturnHash2[$key] -Scope Local
            # Write-Log "Should be: $key = $($ReturnHash[$key])"
            $targetValue = Get-Variable -Name $key -Scope Local
            & $PDLog "Ended up as: $key = $($targetValue.Value)" "INFO2"


        }

        # Create uninstall command

        [hashtable]$FunctionParams = @{
            PrinterName = $PrinterName
        }

        $ReturnHash3 = & $GenerateInstallCommandPath -DesiredFunction "UninstallPrinterByName" -RepoURL $RepoUrl -RepoNickName $RepoNickName -RepoBranch $RepoBranch -TargetWorkingDirectory $TargetWorkingDirectory -FunctionParams $FunctionParams

        # Check the returned hashtable
        if(($ReturnHash3 -eq $null) -or ($ReturnHash3.Count -eq 0)){
            & $PDLog "No data returned!" "ERROR"
            throw "No data returned!"
        }

        & $PDLog "Values retrieved:" "INFO2"

        foreach ($key in $ReturnHash3.Keys) {

            $value = $ReturnHash3[$key]
            & $PDLog "   $key : $value" "INFO2"

        }

        # $result = $ReturnHash2
        # foreach ($key in $result.Keys) {

        #     Write-Host "   $key : $($result[$key])"

        # }


        # Turn the returned hashtable into variables
        & $PDLog "Setting values as local variables..." "INFO2"
        foreach ($key in $ReturnHash3.Keys) {
            Set-Variable -Name $key -Value $ReturnHash3[$key] -Scope Local
            # Write-Log "Should be: $key = $($ReturnHash[$key])"
            $targetValue = Get-Variable -Name $key -Scope Local
            & $PDLog "Ended up as: $key = $($targetValue.Value)" "INFO2"


        }

        # Specs of working repo
            # Commit of the local repo, plus a marker if the packaged Git-Runner has uncommitted edits
            $CurrentGitVer = Get-PDPrinterSourceCommit -RepoRoot $RepoRoot

    $PotentialPrinterInTuneName = Get-PDPrinterIntuneDisplayName -PrinterName $PrinterName -Department $Department -DeployMode $DeployMode -SourceCommit $CurrentGitVer

    # Set the publisher to PowerDeploy if it is missing
    if($Publisher -eq "" -or $null -eq $Publisher){$Publisher = "PowerDeploy"}

    # Intune text, built once before any publishing choice (spec 5.1 step 2). Description is what
    # users see in the Company Portal; Notes is the admin-only technical block (spec 4.2 / 4.4).
    $PrinterDescriptionText = New-IntunePrinterDescription -Department $Department -Location $Location -Model $Model -Asset $Asset -PrinterIP $PrinterIP
    $PrinterTechnicalNotes  = New-IntuneTechnicalNotes -TargetRepo $RepoUrl -TargetBranch $RepoBranch -SourceCommit $CurrentGitVer -Verified $Verified -SourceRepoRoot $RepoRoot -WaitsForOrgKeys 'Yes'

    $IconFileValue = ""
    if (-not [string]::IsNullOrWhiteSpace($IconPath)) {
        if (Test-Path -LiteralPath $IconPath) { $IconFileValue = $IconPath }
    }

    $PrinterIntuneMetadata = @{
        IntuneWinPath           = $IntuneWinPath
        DisplayName             = $PotentialPrinterInTuneName
        Description             = $PrinterDescriptionText
        Publisher               = $Publisher
        AppVersion              = $CurrentGitVer
        Category                = 'Printers'
        Notes                   = $PrinterTechnicalNotes
        InstallCommandFile      = $MainInstallCommandTXT
        UninstallCommandFile    = $UninstallCommandTXT
        DetectionScriptFile     = $DetectPrinterScript
        AllowAvailableUninstall = $true
        IconFile                = $IconFileValue
    }

    return @{
        Metadata        = $PrinterIntuneMetadata
        DisplayName     = $PotentialPrinterInTuneName
        Description     = $PrinterDescriptionText
        TechnicalNotes  = $PrinterTechnicalNotes
        SourceCommit    = $CurrentGitVer
        InstallValues   = $ReturnHash2
        UninstallValues = $ReturnHash3
    }
}
