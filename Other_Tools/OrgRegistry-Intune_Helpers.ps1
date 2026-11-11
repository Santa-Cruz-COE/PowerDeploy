<#

.SYNOPSIS
    Shared naming for the two Intune objects that carry PowerDeploy's organization registry values:
    the Intune Remediation and the Intune Platform Script. Display name (and its parser), Description,
    the platform script's Intune file name, and the source commit they are stamped with.

.DESCRIPTION
    One copy of this logic, used by:
      - Setup.ps1  OrganizationRegistryEntries--InTune-Setup  (guided manual steps)
      - Other_Tools\Upload-InTuneOrgRegistryScripts.ps1  (API upload: finding existing copies, the
        deletion list)
      - Other_Tools\Generate_Install-Command.ps1  OrgRegistryPlatformScript  (source commit)

    Existing copies in Intune are found by parsing display names (name + deploy mode, ignoring the
    [VER: x] part), so the name builder and the parser live side by side here and are tested as a pair
    in Tests\OrgRegistryPlatformScript.Tests.ps1.

    Name style is the app style (Setup.ps1 WindowsApp--InTune-Setup): " [MODE: <mode>] [VER: <commit>]",
    not the printer style " [<mode>] [VER: <commit>]".

    This file may be dot-sourced: functions only, no top-level param() block, no output, no side
    effects at import. No function name here contains "--" (Setup.ps1 builds its menu from functions
    whose names contain "--").

#>

Function Get-PDOrgRegistrySourceCommit {
    <#
        .SYNOPSIS
        Same commit string as the app wizard: git rev-parse --short HEAD of the local repo, plus
        ".UnstagedChanges" when the template the object is built from has uncommitted edits: the
        platform script template by default; pass 'Templates/Git-Runner_TEMPLATE.ps1' for the
        Remediation (its scripts are stamped Git-Runners, exactly like the app wizard's). "unknown"
        when git is missing or the folder is not a repo. Never throws.
    #>
    param(
        [AllowNull()][string]$RepoRoot,
        [string]$TemplateRelativePath = 'Templates/OrgRegistry-PlatformScript_TEMPLATE.ps1'
    )

    $CurrentGitVer = $null
    try { $CurrentGitVer = [string](git -C $RepoRoot rev-parse --short HEAD 2>$null) } catch { $CurrentGitVer = $null }
    if ($CurrentGitVer) { $CurrentGitVer = $CurrentGitVer.Trim() }
    # Only a plain hex commit is ever used: the result goes into file names and script comments.
    if (-not ($CurrentGitVer -cmatch '^[0-9a-f]{4,40}\z')) { $CurrentGitVer = "unknown" }

    $TemplateChanges = $null
    try { $TemplateChanges = git -C $RepoRoot status --porcelain -- $TemplateRelativePath 2>$null } catch { $TemplateChanges = $null }
    if ($TemplateChanges) { $CurrentGitVer = "$CurrentGitVer.UnstagedChanges" }

    return $CurrentGitVer
}

Function Get-PDOrgRegistryIntuneDisplayName {
    <#
        .SYNOPSIS
        PRODUCTION:  POWERDEPLOY ORG REGISTRY: Platform Script   /   POWERDEPLOY ORG REGISTRY: Remediation
        Other modes: the same, followed by " [MODE: <mode>] [VER: <commit>]"
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PlatformScript', 'Remediation')][string]$Type,
        [Parameter(Mandatory = $true)][string]$DeployMode,
        [AllowNull()][AllowEmptyString()][string]$SourceCommit
    )

    if ([string]::IsNullOrWhiteSpace($DeployMode)) { throw "DeployMode is required to build the org registry Intune display name." }

    # The label each object type carries in its display name.
    $TypeLabel = 'Remediation'
    if ($Type -eq 'PlatformScript') { $TypeLabel = 'Platform Script' }

    $Name = "POWERDEPLOY ORG REGISTRY: $TypeLabel"

    # Case-insensitive on purpose, like the app wizard's check (Setup.ps1 WindowsApp--InTune-Setup).
    if ($DeployMode -ne "Production") {
        if ([string]::IsNullOrWhiteSpace($SourceCommit)) { $SourceCommit = 'unknown' }
        $Name = "$Name [MODE: $DeployMode] [VER: $SourceCommit]"
    }

    return $Name
}

Function ConvertFrom-PDOrgRegistryIntuneDisplayName {
    <#
        .SYNOPSIS
        The inverse of Get-PDOrgRegistryIntuneDisplayName. Never throws.

        .OUTPUTS
        { IsOrgRegistry; Type; DeployMode; Version }. Type is 'PlatformScript' or 'Remediation'.
        IsOrgRegistry is $false (and every other field empty) for any name Setup would not have produced.

        .NOTES
        Case-sensitive on purpose: Setup always writes "POWERDEPLOY ORG REGISTRY", so a differently
        cased name is somebody else's object. A name without the " [MODE: x] [VER: y]" tail is PRODUCTION.
        The mode is the printer parser's class ([A-Z][A-Z0-9-]*, Printer-Intune_Helpers.ps1
        ConvertFrom-PDPrinterIntuneDisplayName): no spaces, no lower case. A near-copy such as
        "[MODE:  PUBLIC-TESTING ]" is therefore not an org registry name and is never matched or updated.
        Takes [object] so that anything (an array, a Graph object, $null) binds; only a single string
        can be an org registry name.
    #>
    param([AllowNull()][object]$DisplayName)

    $result = [pscustomobject]@{ IsOrgRegistry = $false; Type = ''; DeployMode = ''; Version = '' }

    try {
        if ($DisplayName -isnot [string]) { return $result }
        if ([string]::IsNullOrWhiteSpace($DisplayName)) { return $result }

        $found = [regex]::Match($DisplayName.Trim(), '^POWERDEPLOY ORG REGISTRY: (?<type>Platform Script|Remediation)(?: \[MODE: (?<mode>[A-Z][A-Z0-9-]*)\] \[VER: (?<ver>[^\[\]\r\n]*)\])?\z')
        if (-not $found.Success) { return $result }

        $type = 'Remediation'
        if ($found.Groups['type'].Value -ceq 'Platform Script') { $type = 'PlatformScript' }

        $mode = 'PRODUCTION'
        $version = ''
        if ($found.Groups['mode'].Success) {
            $mode    = $found.Groups['mode'].Value
            $version = $found.Groups['ver'].Value
        }

        $result.IsOrgRegistry = $true
        $result.Type          = $type
        $result.DeployMode    = $mode
        $result.Version       = $version
    } catch {
        $result = [pscustomobject]@{ IsOrgRegistry = $false; Type = ''; DeployMode = ''; Version = '' }
    }

    return $result
}

Function Test-PDOrgRegistryIntuneNameMatch {
    <#
        .SYNOPSIS
        $true when DisplayName is the org registry object of this Type for this DeployMode, whatever
        its [VER: x]. This is how an existing copy is found so it is replaced rather than duplicated.
        Never throws.
    #>
    param(
        [AllowNull()][object]$DisplayName,
        [Parameter(Mandatory = $true)][ValidateSet('PlatformScript', 'Remediation')][string]$Type,
        [AllowNull()][object]$DeployMode
    )

    if (($DeployMode -isnot [string]) -or [string]::IsNullOrWhiteSpace($DeployMode)) { return $false }

    $parsed = ConvertFrom-PDOrgRegistryIntuneDisplayName -DisplayName $DisplayName
    if (-not $parsed.IsOrgRegistry) { return $false }
    if ($parsed.Type -cne $Type) { return $false }

    # Mode names compare case-insensitively, the same way the name builder decides PRODUCTION.
    return ($parsed.DeployMode -eq $DeployMode.Trim())
}

Function Get-PDOrgRegistryIntuneDescription {
    <#
        .SYNOPSIS
        The Intune Description for either object: what it does, deploy mode, source commit, generated
        date/time, and "Generated by PowerDeploy Setup". Never contains a registry value.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PlatformScript', 'Remediation')][string]$Type,
        [Parameter(Mandatory = $true)][string]$DeployMode,
        [AllowNull()][AllowEmptyString()][string]$SourceCommit,
        [AllowNull()][object]$GeneratedAt
    )

    if ([string]::IsNullOrWhiteSpace($SourceCommit)) { $SourceCommit = 'unknown' }

    if ($GeneratedAt -is [datetime]) {
        $GeneratedText = $GeneratedAt.ToString('yyyy-MM-dd HH:mm:ss')
    } elseif ([string]::IsNullOrWhiteSpace([string]$GeneratedAt)) {
        $GeneratedText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    } else {
        $GeneratedText = [string]$GeneratedAt
    }

    if ($Type -eq 'PlatformScript') {
        $Purpose = "Writes PowerDeploy's organization registry values (HKLM\SOFTWARE\PowerDeploy) before PowerDeploy's Win32 apps install, including during Autopilot. Self-contained: no Git, no network."
    } else {
        $Purpose = "Keeps PowerDeploy's organization registry values (HKLM\SOFTWARE\PowerDeploy) current on an hourly schedule (key rotation and drift)."
    }

    $Lines = @(
        $Purpose,
        "Deploy mode: $DeployMode",
        "Source commit: $SourceCommit",
        "Generated: $GeneratedText",
        "Generated by PowerDeploy Setup",
        "More information: https://github.com/Santa-Cruz-COE/PowerDeploy"
    )

    return ($Lines -join "`n")
}

Function Get-PDOrgRegistryPlatformScriptFileName {
    <#
        .SYNOPSIS
        The file name the Intune Platform Script carries in Intune: PowerDeploy-OrgRegistry_<commit>.ps1
        (the generated file on disk adds _<yyyyMMdd_HHmmss>).
    #>
    param([AllowNull()][AllowEmptyString()][string]$SourceCommit)

    if ([string]::IsNullOrWhiteSpace($SourceCommit)) { $SourceCommit = 'unknown' }
    $SafeCommit = $SourceCommit -replace '[^A-Za-z0-9._-]', '_'

    return "PowerDeploy-OrgRegistry_$SafeCommit.ps1"
}
