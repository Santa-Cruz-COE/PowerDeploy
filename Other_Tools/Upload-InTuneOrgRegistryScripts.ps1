<#

.SYNOPSIS
    Creates or updates PowerDeploy's two organization registry objects in Intune through Microsoft
    Graph: the Intune Remediation and the Intune Platform Script. Also lists and deletes them.

.DESCRIPTION
    The non-interactive engine behind Setup.ps1 OrganizationRegistryEntries--InTune-Setup
    (automatic setup via API, and the deletion list). Modelled on Upload-InTuneWin32App.ps1:

      - No prompts here. Setup.ps1 owns every question; each stage below returns data for it.
      - Every Graph call goes through Invoke-PDGraphRequest / Get-PDGraphCollection in
        InTune-GraphAPI_Helpers.ps1, so the helper library's TestTransport seam makes the whole
        engine testable offline (Tests\IntuneOrgRegistryScripts.Tests.ps1).
      - Writes use RetryMode Write: a write is never repeated automatically.
      - Script content carries SAS keys and the repository token. It is read from disk at write time,
        sent as base64, compared by SHA256 on read-back, and never placed in a result object, a log
        line or a message. Listings never request it ($select).
      - On a failure, only an object created in THIS run is deleted. A pre-existing object is never
        deleted by the upload; the result says exactly what was and was not changed.

    Stages, in the order Setup.ps1 calls them:
      Get-PDOrgRegistryAuthContext          credential, token, application roles
      Get-PDOrgRegistryIntuneObjects        every "POWERDEPLOY ORG REGISTRY:" object, both types, all
                                            deploy modes, with its direct assignments
      New-PDOrgRegistryUploadPlan           create / update / choose, per object type in scope
      Get-PDOrgRegistryKeepOption           can Enter keep the current assignments?
      ConvertTo-PDOrgRegistryTargets        resolved groups -> assignment targets
      Find-PDOrgRegistryAssignmentOverlap   other org registry objects already assigned to a group
      Invoke-PDOrgRegistryUpload            write, assign, read back, roll back
      Get-PDOrgRegistryDeletionList / ConvertFrom-PDOrgRegistryDeletionSelection /
      Remove-PDOrgRegistryIntuneObject      the deletion list

    This file may be dot-sourced: functions only, no top-level param() block, no output, no side
    effects at import. No function name here contains "--" (Setup.ps1 builds its menu from functions
    whose names contain "--"). It needs InTune-GraphAPI_Helpers.ps1 and OrgRegistry-Intune_Helpers.ps1
    and loads them from this folder when the caller has not.

.LINK
    Other_Tools/Upload-InTuneWin32App.ps1
    Other_Tools/InTune-GraphAPI_Helpers.ps1
    Other_Tools/OrgRegistry-Intune_Helpers.ps1

#>

# ---------------------------------------------------------------------------
# Dependencies (script scope, like Upload-InTuneWin32App.ps1: a dot-source inside a function would
# vanish when that function returns)
# ---------------------------------------------------------------------------

$script:PDOrgRegistryEngineDirectory = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($script:PDOrgRegistryEngineDirectory)) {
    $script:PDOrgRegistryEngineDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
}

if (-not (Get-Command -Name 'Stop-PDGraphError' -CommandType Function -ErrorAction SilentlyContinue)) {
    $script:PDOrgRegistryDependency = Join-Path $script:PDOrgRegistryEngineDirectory 'InTune-GraphAPI_Helpers.ps1'
    if (-not (Test-Path -LiteralPath $script:PDOrgRegistryDependency)) {
        throw "The Graph helper library (Other_Tools\InTune-GraphAPI_Helpers.ps1) was not found next to Upload-InTuneOrgRegistryScripts.ps1; the repository may be incomplete."
    }
    . $script:PDOrgRegistryDependency
}

if (-not (Get-Command -Name 'Test-PDOrgRegistryIntuneNameMatch' -CommandType Function -ErrorAction SilentlyContinue)) {
    $script:PDOrgRegistryDependency = Join-Path $script:PDOrgRegistryEngineDirectory 'OrgRegistry-Intune_Helpers.ps1'
    if (-not (Test-Path -LiteralPath $script:PDOrgRegistryDependency)) {
        throw "The org registry naming helpers (Other_Tools\OrgRegistry-Intune_Helpers.ps1) were not found next to Upload-InTuneOrgRegistryScripts.ps1; the repository may be incomplete."
    }
    . $script:PDOrgRegistryDependency
}

# ---------------------------------------------------------------------------
# Graph shapes. Kept together so a shape the live test corrects is changed in one place.
# ---------------------------------------------------------------------------

$script:PDOrgRegistryGraph = @{
    NamePrefix = 'POWERDEPLOY ORG REGISTRY:'
    Publisher  = 'PowerDeploy'
    # Listings: never the script content.
    ListSelect = 'id,displayName,description,lastModifiedDateTime'

    Types = @{
        PlatformScript = @{
            Label               = 'Intune Platform Script'
            Path                = '/beta/deviceManagement/deviceManagementScripts'
            ODataType           = '#microsoft.graph.deviceManagementScript'
            AssignProperty      = 'deviceManagementScriptAssignments'
            AssignmentODataType = '#microsoft.graph.deviceManagementScriptAssignment'
            ContentProperties   = @('scriptContent')
            # Intune admin center page of one Intune Platform Script.
            PortalUrlFormat     = 'https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/ConfigureWMPolicyMenuBlade/~/properties/policyId/{0}/policyType~/0'
        }
        Remediation = @{
            Label               = 'Intune Remediation'
            Path                = '/beta/deviceManagement/deviceHealthScripts'
            ODataType           = '#microsoft.graph.deviceHealthScript'
            AssignProperty      = 'deviceHealthScriptAssignments'
            AssignmentODataType = '#microsoft.graph.deviceHealthScriptAssignment'
            ContentProperties   = @('detectionScriptContent', 'remediationScriptContent')
            # Intune admin center page of one Intune Remediation.
            PortalUrlFormat     = 'https://intune.microsoft.com/#view/Microsoft_Intune_Enrollment/UXAnalyticsScriptMenu/~/properties/id/{0}'
        }
    }

    # New Intune Remediation assignments run hourly. Kept assignments are re-sent as Intune returned them.
    HourlyScheduleODataType = '#microsoft.graph.deviceHealthScriptHourlySchedule'
    HourlyInterval          = 1

    GroupTargetODataType     = '#microsoft.graph.groupAssignmentTarget'
    ExclusionTargetODataType = '#microsoft.graph.exclusionGroupAssignmentTarget'

    # One order everywhere (writes, reviews, results, the deletion list), the same as the menu:
    # the Intune Remediation, then the Intune Platform Script.
    TypeOrder = @('Remediation', 'PlatformScript')
}

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

function Get-PDOrgRegistryTypeLabel {
    <# 'Intune Platform Script' or 'Intune Remediation'. #>
    param([Parameter(Mandatory = $true)][ValidateSet('PlatformScript', 'Remediation')][string]$Type)
    return [string]$script:PDOrgRegistryGraph.Types[$Type].Label
}

# The exact secret values the scripts in this run were generated from (repository token, SAS keys,
# a repository URL with an embedded token), in every form a message could carry them. Set by
# Set-PDOrgRegistryRedactValues; never logged, never returned.
$script:PDOrgRegistryRedact = @()
$script:PDOrgRegistryRedactPatterns = @()

function Set-PDOrgRegistryRedactValues {
    <#
        .SYNOPSIS
        Replaces the list of exact values Protect-PDOrgRegistryText removes. An empty list clears it.

        .DESCRIPTION
        Each value of 8 or more characters is kept as given, URL-encoded once and twice (upper- and
        lower-case hex) and JSON-escaped (both engines' escaping), longest first. Each form is also
        kept as a case-insensitive pattern that allows a line break (CR, LF or CRLF) between any two
        of its characters, so a value a service wrapped across lines is still found. Shorter values
        are ignored: they are not secrets, and removing them would damage ordinary text. Never
        throws, never logs.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Values)

    $lowerHex = { param($Text) [regex]::Replace($Text, '%[0-9A-F]{2}', { param($m) $m.Value.ToLowerInvariant() }) }
    # The start of JSON's 4-hex-digit escapes, as Windows PowerShell 5.1's ConvertTo-Json writes & ' < >
    $u = ([string][char]92) + 'u00'

    $forms = @{}
    foreach ($item in @($Values)) {
        $raw = [string]$item
        if ($raw.Length -lt 8) { continue }

        $candidates = @($raw)
        try {
            $once = [System.Uri]::EscapeDataString($raw)
            $twice = [System.Uri]::EscapeDataString($once)
            $candidates += @($once, (& $lowerHex $once), $twice, (& $lowerHex $twice))
        } catch { }
        try { $candidates += ([string](ConvertTo-Json -InputObject $raw -Compress)).Trim('"') } catch { }
        $candidates += $raw.Replace('\', '\\').Replace('"', '\"').Replace('&', $u + '26').Replace("'", $u + '27').Replace('<', $u + '3c').Replace('>', $u + '3e')

        foreach ($candidate in $candidates) {
            if (-not [string]::IsNullOrEmpty($candidate)) { $forms[$candidate.ToLowerInvariant()] = $candidate }
        }
    }

    $sorted = @($forms.Values | Sort-Object -Property Length -Descending)
    $script:PDOrgRegistryRedact = $sorted
    $script:PDOrgRegistryRedactPatterns = @($sorted | ForEach-Object {
        $chars = @($_.ToCharArray() | ForEach-Object { [regex]::Escape([string]$_) })
        New-Object System.Text.RegularExpressions.Regex (($chars -join '(?:\r?\n|\r)?'), ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant))
    })
}

function Protect-PDOrgRegistryText {
    <#
        .SYNOPSIS
        Display-safe text. Every message this engine returns or logs passes through here. Never throws.

        .DESCRIPTION
        In order:
          1 the exact secret values of this run (Set-PDOrgRegistryRedactValues), in every form, case
            ignored, also when a line break was inserted into them, and any start of one (8+
            characters) cut off by a "..." truncation;
          2 URL userinfo anywhere in the text: https://user:password@host -> https://***@host;
          3 SAS signatures, plain, URL-encoded or double URL-encoded: sig= / sig%3D / sig%253D;
          4 GitHub and GitLab token shapes (ghp_, gho_, ghs_, ghu_, ghr_, github_pat_, glpat-);
          5 base64 runs of 40+ characters (script content is sent as base64), and runs of 16+ that a
            "..." truncation cut short, when they look like base64 (a digit, +, / or =; or 100+
            characters), so a long ordinary word is left alone.
        IDs are GUIDs, whose dashes keep every run far shorter than that. When the input cannot be
        turned into text, or a step fails, the result is a fixed message plus the protected
        .Message of the input when it has one: never the unprotected text.
    #>
    param([AllowNull()][object]$Text)

    $unsafe = 'The error details could not be shown safely.'

    try {
        $value = [string]$Text
    } catch {
        $part = ''
        try { $part = [string]$Text.Message } catch { $part = '' }
        if ([string]::IsNullOrWhiteSpace($part)) { return $unsafe }
        $shown = Protect-PDOrgRegistryText -Text $part
        if ($shown -eq $unsafe) { return $unsafe }
        return ('{0} {1}' -f $unsafe, $shown)
    }

    try {
        if ([string]::IsNullOrEmpty($value)) { return '' }

        foreach ($pattern in @($script:PDOrgRegistryRedactPatterns)) { $value = $pattern.Replace($value, '<redacted>') }
        if ($value.Contains('...')) {
            foreach ($secret in @($script:PDOrgRegistryRedact)) {
                for ($length = $secret.Length - 1; $length -ge 8; $length--) {
                    $cut = $secret.Substring(0, $length) + '...'
                    $at = $value.IndexOf($cut, [System.StringComparison]::OrdinalIgnoreCase)
                    if ($at -ge 0) { $value = $value.Remove($at, $cut.Length).Insert($at, '<redacted>...'); break }
                }
            }
        }

        $value = [regex]::Replace($value, '(?i)\b(https?://)[^/\s@]+@', '$1***@')
        $value = [regex]::Replace($value, '(?i)((?:(?<![A-Za-z])|(?<=%(?:25)?[0-9A-Fa-f]{2}))sig(?:=|%3D|%253D))(?:%(?!26|2526)[0-9A-F]{2}|[A-Za-z0-9+/=._-])+', '$1<redacted>')
        $value = [regex]::Replace($value, '(?i)(?:gh[pousr]_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{10,}|glpat-[A-Za-z0-9_-]{10,})', '<redacted>')
        # A run counts as base64 when it has a digit, +, / or = (or is 100+ characters): a long ordinary
        # word such as an OData type name is left alone.
        $value = [regex]::Replace($value, '[A-Za-z0-9+/]{40,}={0,2}', { param($m) if ($m.Value -match '[0-9+/=]' -or $m.Value.Length -ge 100) { '<redacted>' } else { $m.Value } })
        $value = [regex]::Replace($value, '[A-Za-z0-9+/]{16,}={0,2}(?=\.\.\.)', { param($m) if ($m.Value -match '[0-9+/=]') { '<redacted>' } else { $m.Value } })

        if (Get-Command -Name 'Remove-UrlCredential' -CommandType Function -ErrorAction SilentlyContinue) {
            $value = Remove-UrlCredential -Url $value
        }
        return $value
    } catch {
        return $unsafe
    }
}

function Write-PDOrgRegistryLog {
    <# Hands one protected line to the caller's -Log script block. Never throws; does nothing without one. #>
    param(
        [AllowNull()][scriptblock]$Log,
        [AllowNull()][string]$Message,
        [string]$Level = 'INFO2'
    )

    if ($null -eq $Log) { return }
    try { $null = & $Log (Protect-PDOrgRegistryText -Text $Message) $Level } catch { }
}

function Get-PDOrgRegistryErrorText {
    <# The sanitized message of a caught error, protected. #>
    param([AllowNull()][object]$ErrorRecord)

    $info = Get-PDGraphErrorInfo -ErrorRecord $ErrorRecord
    $text = [string]$info.Message
    if ([string]::IsNullOrWhiteSpace($text)) { $text = 'The request failed for a reason that could not be described.' }
    return (Protect-PDOrgRegistryText -Text $text)
}

function Get-PDOrgRegistryObjectPath {
    <# /beta/deviceManagement/<collection>/<escaped id><suffix> #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PlatformScript', 'Remediation')][string]$Type,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Id,
        [string]$Suffix = ''
    )

    $trimmed = ([string]$Id).Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        Stop-PDGraphError -Message ('An {0} id is required to address it.' -f (Get-PDOrgRegistryTypeLabel -Type $Type)) -Stage 'Address'
    }
    return ('{0}/{1}{2}' -f [string]$script:PDOrgRegistryGraph.Types[$Type].Path, [System.Uri]::EscapeDataString($trimmed), $Suffix)
}

function Get-PDOrgRegistryPortalUrl {
    <# The Intune admin center page of one object. #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PlatformScript', 'Remediation')][string]$Type,
        [AllowNull()][string]$Id
    )

    if ([string]::IsNullOrWhiteSpace($Id)) { return '' }
    return ([string]$script:PDOrgRegistryGraph.Types[$Type].PortalUrlFormat -f [System.Uri]::EscapeDataString($Id.Trim()))
}

function Get-PDOrgRegistrySha256 {
    <# Upper-case hex SHA256 of a byte array. #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([System.BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '') } finally { $sha.Dispose() }
}

function Get-PDOrgRegistryFileFingerprint {
    <#
        .SYNOPSIS
        { Path; Sha256; Length } of a script file, taken at review time. The bytes are not kept:
        Invoke-PDOrgRegistryUpload reads the file again and refuses to send it if the hash changed.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = Get-PDResolvedFilePath -Path $Path -Stage 'Review' -Label 'script file'
    $bytes = [System.IO.File]::ReadAllBytes($full)
    if ($bytes.Length -eq 0) { Stop-PDGraphError -Message ("The script file '{0}' is empty." -f $full) -Stage 'Review' }
    return [pscustomobject]@{ Path = $full; Sha256 = (Get-PDOrgRegistrySha256 -Bytes $bytes); Length = $bytes.Length }
}

function Get-PDOrgRegistryDisplayDate {
    <# A Graph date (string or DateTime) as local 'yyyy-MM-dd HH:mm', or '' when absent. #>
    param([AllowNull()][object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return '' }
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    try {
        if ($Value -is [DateTime]) {
            $date = [DateTime]$Value
            if ($date.Kind -eq [DateTimeKind]::Utc) { $date = $date.ToLocalTime() }
            return $date.ToString('yyyy-MM-dd HH:mm', $culture)
        }
        $parsed = [System.DateTimeOffset]::MinValue
        if ([System.DateTimeOffset]::TryParse([string]$Value, $culture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
            return $parsed.ToLocalTime().ToString('yyyy-MM-dd HH:mm', $culture)
        }
    } catch { }
    return [string]$Value
}

# ---------------------------------------------------------------------------
# Credential
# ---------------------------------------------------------------------------

function Get-PDOrgRegistryAuthContext {
    <#
        .SYNOPSIS
        Loads this PC's client secret, gets a token and checks the application roles.

        .OUTPUTS
        { AuthContext; Warnings; SecretExpiresOn }. Throws a sanitized error when the credential is
        missing, expired, refused, or lacks a required role. Never returns the secret or the token.
    #>
    param([AllowNull()][string]$CredentialPath)

    $credential = Get-PDGraphCredential -Path $CredentialPath
    $warnings = @()
    foreach ($warning in @($credential.Warnings)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$warning)) { $warnings += [string]$warning }
    }

    $authContext = @{ Credential = $credential }
    $token = Get-PDGraphToken -Credential $credential

    $roles = @()
    try { $roles = @($token.Roles) } catch { $roles = @() }

    if ($roles.Count -gt 0) {
        $missing = @()
        foreach ($role in @($script:PDGraph.RequiredAppRoles)) {
            if (@($roles | Where-Object { ([string]$_) -eq [string]$role }).Count -eq 0) { $missing += [string]$role }
        }
        if ($missing.Count -gt 0) {
            Stop-PDGraphError -Message ("The Azure App Registration's token does not include {0}. Run InTuneAPI--Setup-and-Manage > Azure App Registration - Setup/Config > Automatic. It needs an Entra admin sign-in, grants only the missing permission(s), and also creates and saves a new client secret for this PC; then retry. Nothing was changed in Intune." -f (($missing | ForEach-Object { "'$_'" }) -join ', ')) -Stage 'Credential'
        }
    } else {
        $warnings += 'The token carried no readable application roles, so permissions could not be confirmed before writing. The first Graph call will report any missing permission.'
    }

    return [pscustomobject]@{ AuthContext = $authContext; Warnings = @($warnings); SecretExpiresOn = $credential.SecretExpiresOn }
}

# ---------------------------------------------------------------------------
# Assignments: keys and text
# ---------------------------------------------------------------------------

function Get-PDOrgRegistryTargetType {
    <# A target's @odata.type, lower case, without the leading '#'. '' when absent. #>
    param([AllowNull()][object]$Target)

    $type = ([string](Get-PDGraphPropertyValue -Object $Target -Name '@odata.type')).Trim().TrimStart('#').ToLowerInvariant()
    return $type
}

function Get-PDOrgRegistryOverlapKey {
    <#
        .SYNOPSIS
        The direct target an assignment points at, for the overlap check: 'group:<id>', 'alldevices'
        or 'allusers'. '' for anything else (an exclusion is not an assignment to that group).
    #>
    param([AllowNull()][object]$Target)

    $type = Get-PDOrgRegistryTargetType -Target $Target
    switch ($type) {
        'microsoft.graph.groupassignmenttarget' {
            $groupId = ([string](Get-PDGraphPropertyValue -Object $Target -Name 'groupId')).Trim().ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($groupId)) { return '' }
            return ('group:' + $groupId)
        }
        'microsoft.graph.alldevicesassignmenttarget'        { return 'alldevices' }
        'microsoft.graph.alllicensedusersassignmenttarget'  { return 'allusers' }
    }
    return ''
}

function Get-PDOrgRegistryTargetKey {
    <#
        .SYNOPSIS
        Everything that makes one assignment target distinct: type, group and assignment filter.
        Used to decide whether two objects have the same assignment set, and for read-back.
    #>
    param([AllowNull()][object]$Target)

    $type    = Get-PDOrgRegistryTargetType -Target $Target
    $groupId = ([string](Get-PDGraphPropertyValue -Object $Target -Name 'groupId')).Trim().ToLowerInvariant()
    $filterType = ([string](Get-PDGraphPropertyValue -Object $Target -Name 'deviceAndAppManagementAssignmentFilterType')).Trim().ToLowerInvariant()
    $filterId   = ([string](Get-PDGraphPropertyValue -Object $Target -Name 'deviceAndAppManagementAssignmentFilterId')).Trim().ToLowerInvariant()

    # "No filter" has three spellings in Graph: absent, 'none', and an all-zero id.
    if ([string]::IsNullOrWhiteSpace($filterType) -or $filterType -eq 'none' -or [string]::IsNullOrWhiteSpace($filterId) -or $filterId -eq '00000000-0000-0000-0000-000000000000') {
        $filterType = ''
        $filterId   = ''
    }

    return ('{0}|{1}|{2}|{3}' -f $type, $groupId, $filterType, $filterId)
}

function Get-PDOrgRegistryAssignmentSetKey {
    <# One string for a whole assignment set (order-independent), from the targets' keys. #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Assignments)

    $keys = @()
    foreach ($assignment in @($Assignments)) {
        if ($null -eq $assignment) { continue }
        $keys += (Get-PDOrgRegistryTargetKey -Target (Get-PDGraphPropertyValue -Object $assignment -Name 'target'))
    }
    return ((@($keys | Sort-Object -Unique)) -join ';')
}

function Get-PDOrgRegistryGroupName {
    <#
        .SYNOPSIS
        A group's display name by id, through a per-run cache. Never throws: a group that cannot be
        read is shown by its id, and one that no longer exists says so.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$GroupId,
        [AllowNull()][object]$AuthContext,
        [Parameter(Mandatory = $true)][hashtable]$Cache
    )

    $key = $GroupId.Trim().ToLowerInvariant()
    if ($Cache.ContainsKey($key)) { return [string]$Cache[$key] }

    $name = ''
    try {
        $path = New-PDGraphQueryPath -Path ([string]$script:PDGraph.GroupsPath + '/' + [System.Uri]::EscapeDataString($GroupId.Trim())) -Query @{ '$select' = 'id,displayName' }
        $group = Invoke-PDGraphRequest -Method Get -Uri $path -AuthContext $AuthContext -RetryMode 'Read' -Stage 'List' -Description 'group name'
        $name = [string](Get-PDGraphPropertyValue -Object $group -Name 'displayName')
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        if ($info.Status -eq 404) { $name = '(group not found)' } else { $name = '' }
    }

    $Cache[$key] = $name
    return $name
}

function Get-PDOrgRegistryTargetText {
    <#
        .SYNOPSIS
        One assignment target as a person reads it: 'All devices (built-in Intune target)',
        'IT PCs (<id>)', 'Excluded: IT PCs (<id>)', plus the assignment filter when there is one.
    #>
    param(
        [AllowNull()][object]$Target,
        [AllowNull()][object]$AuthContext,
        [AllowNull()][hashtable]$Cache
    )

    if ($null -eq $Cache) { $Cache = @{} }

    $type = Get-PDOrgRegistryTargetType -Target $Target
    $text = $type

    $builtIn = Get-PDBuiltInAssignmentTargetByType -ODataType $type
    if ($null -ne $builtIn) {
        $text = [string]$script:PDGraph.BuiltInTargets[$builtIn.ToLowerInvariant()].DisplayName
    } else {
        $groupId = ([string](Get-PDGraphPropertyValue -Object $Target -Name 'groupId')).Trim()
        if (-not [string]::IsNullOrWhiteSpace($groupId)) {
            $name = Get-PDOrgRegistryGroupName -GroupId $groupId -AuthContext $AuthContext -Cache $Cache
            if ([string]::IsNullOrWhiteSpace($name)) { $text = $groupId } else { $text = ('{0} ({1})' -f $name, $groupId) }
            if ($type -eq ([string]$script:PDOrgRegistryGraph.ExclusionTargetODataType).TrimStart('#').ToLowerInvariant()) { $text = 'Excluded: ' + $text }
        }
    }

    $filterType = ([string](Get-PDGraphPropertyValue -Object $Target -Name 'deviceAndAppManagementAssignmentFilterType')).Trim()
    $filterId   = ([string](Get-PDGraphPropertyValue -Object $Target -Name 'deviceAndAppManagementAssignmentFilterId')).Trim()
    if (-not [string]::IsNullOrWhiteSpace($filterType) -and $filterType -ine 'none' -and -not [string]::IsNullOrWhiteSpace($filterId) -and $filterId -ne '00000000-0000-0000-0000-000000000000') {
        $text = ('{0} [assignment filter: {1} {2}]' -f $text, $filterType, $filterId)
    }

    return $text
}

function Get-PDOrgRegistryScheduleText {
    <# An Intune Remediation assignment's schedule as a person reads it. #>
    param([AllowNull()][object]$Assignment)

    $schedule = Get-PDGraphPropertyValue -Object $Assignment -Name 'runSchedule'
    if ($null -eq $schedule) { return 'no schedule' }

    $type = ([string](Get-PDGraphPropertyValue -Object $schedule -Name '@odata.type')).Trim().TrimStart('#')
    $interval = [string](Get-PDGraphPropertyValue -Object $schedule -Name 'interval')
    $time = [string](Get-PDGraphPropertyValue -Object $schedule -Name 'time')

    $every = { param($Count, $Unit) if ([string]$Count -eq '1') { return ('every 1 {0}' -f $Unit) } return ('every {0} {1}s' -f $Count, $Unit) }

    switch -Regex ($type) {
        'HourlySchedule$' { return ('Hourly, {0}' -f (& $every $interval 'hour')) }
        'DailySchedule$'  { if ($time) { return ('Daily, {0} at {1}' -f (& $every $interval 'day'), $time) } else { return ('Daily, {0}' -f (& $every $interval 'day')) } }
        'RunOnceSchedule$' { return 'Once' }
    }
    if ([string]::IsNullOrWhiteSpace($type)) { return 'unknown schedule' }
    return $type
}

function Get-PDOrgRegistryAssignmentLines {
    <#
        .SYNOPSIS
        One line per assignment for lists and reviews: the target, and for an Intune Remediation its
        schedule. '(none)' when there are no assignments.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PlatformScript', 'Remediation')][string]$Type,
        [AllowNull()][AllowEmptyCollection()][object[]]$Assignments,
        [AllowNull()][object]$AuthContext,
        [AllowNull()][hashtable]$Cache
    )

    $lines = @()
    foreach ($assignment in @($Assignments)) {
        if ($null -eq $assignment) { continue }
        $text = Get-PDOrgRegistryTargetText -Target (Get-PDGraphPropertyValue -Object $assignment -Name 'target') -AuthContext $AuthContext -Cache $Cache
        if ($Type -eq 'Remediation') { $text = ('{0} - {1}' -f $text, (Get-PDOrgRegistryScheduleText -Assignment $assignment)) }
        $lines += $text
    }
    if ($lines.Count -eq 0) { $lines = @('(none)') }
    return $lines
}

# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

function Get-PDOrgRegistryIntuneObjects {
    <#
        .SYNOPSIS
        Every Intune Remediation and Intune Platform Script whose display name starts with
        "POWERDEPLOY ORG REGISTRY:", across all deploy modes, with each one's direct assignments.

        .DESCRIPTION
        The collections are read with $select (id, display name, description, last modified) and
        every @odata.nextLink page is followed; script content is never requested. The prefix is
        matched case-sensitively, like the name parser. An object that starts with the prefix but is
        not a name Setup produces (IsRecognized = $false) is still returned, so it appears in the
        deletion list, but it is never matched for an update.

        .OUTPUTS
        { Type; TypeLabel; Id; DisplayName; IsRecognized; DeployMode; Commit; LastModified;
          Assignments (as Graph returned them); AssignmentLines }
    #>
    param(
        [AllowNull()][object]$AuthContext,
        [string[]]$Types = @('PlatformScript', 'Remediation'),
        [switch]$SkipGroupNames
    )

    $cache = @{}
    $objects = @()

    foreach ($type in @($script:PDOrgRegistryGraph.TypeOrder)) {
        if (@($Types) -notcontains $type) { continue }
        $shape = $script:PDOrgRegistryGraph.Types[$type]

        $path  = New-PDGraphQueryPath -Path ([string]$shape.Path) -Query @{ '$select' = [string]$script:PDOrgRegistryGraph.ListSelect }
        $items = Get-PDGraphCollection -Path $path -AuthContext $AuthContext -Stage 'List' -Description ('{0} list' -f [string]$shape.Label)

        foreach ($item in (Get-PDGraphItems -Payload $items)) {
            $id   = ([string](Get-PDGraphPropertyValue -Object $item -Name 'id')).Trim()
            $name = [string](Get-PDGraphPropertyValue -Object $item -Name 'displayName')
            if ([string]::IsNullOrWhiteSpace($id)) { continue }
            if (-not $name.Trim().StartsWith([string]$script:PDOrgRegistryGraph.NamePrefix, [System.StringComparison]::Ordinal)) { continue }

            $parsed = ConvertFrom-PDOrgRegistryIntuneDisplayName -DisplayName $name
            $recognized = ($parsed.IsOrgRegistry -and $parsed.Type -ceq $type)

            # The commit: the name's [VER: x] when it has one, otherwise the description's
            # "Source commit:" line (PRODUCTION names carry no version).
            $commit = ''
            if ($recognized) { $commit = [string]$parsed.Version }
            if ([string]::IsNullOrWhiteSpace($commit)) {
                $found = [regex]::Match([string](Get-PDGraphPropertyValue -Object $item -Name 'description'), '(?m)^Source commit: (?<c>[0-9A-Za-z._-]{1,80})\s*$')
                if ($found.Success) { $commit = $found.Groups['c'].Value }
            }

            $assignments = @(Get-PDGraphCollection -Path (Get-PDOrgRegistryObjectPath -Type $type -Id $id -Suffix '/assignments') -AuthContext $AuthContext -Stage 'List' -Description ('assignments of {0} {1}' -f [string]$shape.Label, $id))
            $assignments = @(Get-PDGraphItems -Payload $assignments)

            $lines = @()
            if (-not $SkipGroupNames) { $lines = @(Get-PDOrgRegistryAssignmentLines -Type $type -Assignments $assignments -AuthContext $AuthContext -Cache $cache) }

            $objects += [pscustomobject]@{
                Type            = $type
                TypeLabel       = [string]$shape.Label
                Id              = $id
                DisplayName     = $name
                IsRecognized    = [bool]$recognized
                DeployMode      = $(if ($recognized) { [string]$parsed.DeployMode } else { '' })
                Commit          = $commit
                LastModified    = (Get-PDOrgRegistryDisplayDate -Value (Get-PDGraphPropertyValue -Object $item -Name 'lastModifiedDateTime'))
                Assignments     = @($assignments)
                AssignmentLines = @($lines)
            }
        }
    }

    return $objects
}

# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------

function New-PDOrgRegistryUploadPlan {
    <#
        .SYNOPSIS
        Decides, per object type in scope, what the upload does for this deploy mode.

        .DESCRIPTION
        Existing copies are found by name and deploy mode, ignoring [VER: x]
        (Test-PDOrgRegistryIntuneNameMatch). 0 matches: Create. 1 match: Update it in place. Several:
        Choose, with the candidates, until SelectedIds names one of them; the others are left alone
        (they appear in the deletion list afterwards).

        The partner of an entry is the object of the other type for the same deploy mode: the one
        this run writes, or - when only one type is in scope - the single existing one. It is
        excluded from the overlap check, because the two are meant to share groups.

        .OUTPUTS
        { DeployMode; Entries = @( { Type; TypeLabel; Action; Target; Candidates } ); NeedsChoice;
          PartnerIds }
    #>
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Inventory,
        [Parameter(Mandatory = $true)][string[]]$Types,
        [Parameter(Mandatory = $true)][string]$DeployMode,
        [AllowNull()][hashtable]$SelectedIds
    )

    if ($null -eq $SelectedIds) { $SelectedIds = @{} }
    $entries = @()

    foreach ($type in @($script:PDOrgRegistryGraph.TypeOrder)) {
        if (@($Types) -notcontains $type) { continue }

        $candidates = @(@($Inventory) | Where-Object { $null -ne $_ -and $_.Type -eq $type -and $_.IsRecognized -and (Test-PDOrgRegistryIntuneNameMatch -DisplayName $_.DisplayName -Type $type -DeployMode $DeployMode) })

        $entry = [pscustomobject]@{
            Type       = $type
            TypeLabel  = (Get-PDOrgRegistryTypeLabel -Type $type)
            Action     = 'Create'
            Target     = $null
            Candidates = @($candidates)
        }

        if ($candidates.Count -eq 1) {
            $entry.Action = 'Update'
            $entry.Target = $candidates[0]
        } elseif ($candidates.Count -gt 1) {
            $entry.Action = 'Choose'
            $chosen = [string]$SelectedIds[$type]
            if (-not [string]::IsNullOrWhiteSpace($chosen)) {
                $pick = @($candidates | Where-Object { $_.Id -ieq $chosen.Trim() })
                if ($pick.Count -ne 1) {
                    Stop-PDGraphError -Message ("'{0}' is not one of the existing {1} copies for deploy mode {2}." -f $chosen, $entry.TypeLabel, $DeployMode) -Stage 'Plan'
                }
                $entry.Action = 'Update'
                $entry.Target = $pick[0]
            }
        }

        $entries += $entry
    }

    # Partner ids, per type: the object of the OTHER type this run writes, or the single existing
    # same-mode object of the other type when that type is not in scope.
    $partnerIds = @{}
    foreach ($type in @($script:PDOrgRegistryGraph.TypeOrder)) {
        $other = @($script:PDOrgRegistryGraph.TypeOrder | Where-Object { $_ -ne $type })[0]
        $otherEntry = @($entries | Where-Object { $_.Type -eq $other })
        $ids = @()
        if ($otherEntry.Count -gt 0) {
            if ($null -ne $otherEntry[0].Target) { $ids += [string]$otherEntry[0].Target.Id }
        } else {
            $same = @(@($Inventory) | Where-Object { $null -ne $_ -and $_.Type -eq $other -and $_.IsRecognized -and (Test-PDOrgRegistryIntuneNameMatch -DisplayName $_.DisplayName -Type $other -DeployMode $DeployMode) })
            if ($same.Count -eq 1) { $ids += [string]$same[0].Id }
        }
        $partnerIds[$type] = @($ids)
    }

    return [pscustomobject]@{
        DeployMode  = $DeployMode
        Entries     = @($entries)
        NeedsChoice = (@($entries | Where-Object { $_.Action -eq 'Choose' }).Count -gt 0)
        PartnerIds  = $partnerIds
    }
}

function Get-PDOrgRegistryKeepOption {
    <#
        .SYNOPSIS
        Whether Enter may keep the current assignments: only when every object in the plan is an
        update and all of them have the same assignment set (targets and filters). A run that
        creates an object always needs groups.

        .OUTPUTS
        { Available; Reason; Assignments (the first object's, for display) }
    #>
    param([Parameter(Mandatory = $true)][object]$Plan)

    $entries = @($Plan.Entries)
    if ($entries.Count -eq 0) { return [pscustomobject]@{ Available = $false; Reason = 'Nothing is in scope.'; Assignments = @() } }

    foreach ($entry in $entries) {
        if ($entry.Action -ne 'Update' -or $null -eq $entry.Target) {
            return [pscustomobject]@{ Available = $false; Reason = ('The {0} is new, so it needs groups.' -f $entry.TypeLabel); Assignments = @() }
        }
    }

    $first = Get-PDOrgRegistryAssignmentSetKey -Assignments @($entries[0].Target.Assignments)
    foreach ($entry in $entries) {
        if ((Get-PDOrgRegistryAssignmentSetKey -Assignments @($entry.Target.Assignments)) -ne $first) {
            return [pscustomobject]@{ Available = $false; Reason = 'The Intune Remediation and the Intune Platform Script are assigned to different groups, so the groups must be entered.'; Assignments = @() }
        }
    }

    return [pscustomobject]@{ Available = $true; Reason = ''; Assignments = @($entries[0].Target.Assignments) }
}

function ConvertTo-PDOrgRegistryTargets {
    <#
        .SYNOPSIS
        Resolve-PDGraphGroups output -> assignment targets: a group target per group id, or the
        built-in target for /AllDevices and /AllUsers. Throws when there is nothing to assign.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$ResolvedGroups)

    $targets = @()
    $seen = @{}
    foreach ($group in @($ResolvedGroups)) {
        if ($null -eq $group) { continue }
        $id = ([string](Get-PDGraphPropertyValue -Object $group -Name 'Id')).Trim()
        if ([string]::IsNullOrWhiteSpace($id)) { continue }

        $builtIn = Get-PDBuiltInAssignmentTarget -Term $id -Stage 'Groups'
        if ($null -ne $builtIn) {
            $target = @{ '@odata.type' = [string]$builtIn.ODataType }
        } else {
            $target = @{ '@odata.type' = [string]$script:PDOrgRegistryGraph.GroupTargetODataType; groupId = $id }
        }

        $key = Get-PDOrgRegistryTargetKey -Target $target
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $targets += $target
    }

    if ($targets.Count -eq 0) { Stop-PDGraphError -Message 'No group was given, so there is nothing to assign.' -Stage 'Groups' }
    return $targets
}

function Find-PDOrgRegistryAssignmentOverlap {
    <#
        .SYNOPSIS
        Other live org registry objects (all deploy modes, both types) that are already assigned
        directly to a target this upload assigns. Groups are compared by id and not expanded; All
        devices and All users compare as themselves.

        .DESCRIPTION
        Excluded: the objects this run updates, and each one's partner (New-PDOrgRegistryUploadPlan).
        Exclusion targets on the other objects are not assignments to that group and are ignored.

        .OUTPUTS
        { Type; TypeLabel; Id; DisplayName; DeployMode; SharedTarget (text) } per object and shared target.
    #>
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Inventory,
        [Parameter(Mandatory = $true)][object]$Plan,
        [AllowNull()][AllowEmptyCollection()][object[]]$Targets,
        [AllowNull()][object]$AuthContext
    )

    $wanted = @{}
    foreach ($target in @($Targets)) {
        $key = Get-PDOrgRegistryOverlapKey -Target $target
        if ($key) { $wanted[$key] = $target }
    }
    if ($wanted.Count -eq 0) { return @() }

    $skip = @{}
    foreach ($entry in @($Plan.Entries)) {
        if ($null -ne $entry.Target) { $skip[([string]$entry.Target.Id).ToLowerInvariant()] = $true }
        foreach ($partnerId in @($Plan.PartnerIds[$entry.Type])) {
            if (-not [string]::IsNullOrWhiteSpace([string]$partnerId)) { $skip[([string]$partnerId).ToLowerInvariant()] = $true }
        }
    }

    $cache = @{}
    $found = @()
    foreach ($object in @($Inventory)) {
        if ($null -eq $object) { continue }
        if ($skip.ContainsKey(([string]$object.Id).ToLowerInvariant())) { continue }

        $reported = @{}
        foreach ($assignment in @($object.Assignments)) {
            $target = Get-PDGraphPropertyValue -Object $assignment -Name 'target'
            $key = Get-PDOrgRegistryOverlapKey -Target $target
            if (-not $key -or -not $wanted.ContainsKey($key) -or $reported.ContainsKey($key)) { continue }
            $reported[$key] = $true

            $found += [pscustomobject]@{
                Type         = [string]$object.Type
                TypeLabel    = [string]$object.TypeLabel
                Id           = [string]$object.Id
                DisplayName  = [string]$object.DisplayName
                DeployMode   = [string]$object.DeployMode
                SharedTarget = (Get-PDOrgRegistryTargetText -Target $target -AuthContext $AuthContext -Cache $cache)
            }
        }
    }

    return $found
}

# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------

function New-PDOrgRegistryObjectBody {
    <#
        .SYNOPSIS
        The create / PATCH body for one object. Content arrives as base64 and is placed only here.
        Internal: never log or return this body.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PlatformScript', 'Remediation')][string]$Type,
        [Parameter(Mandatory = $true)][hashtable]$Metadata,
        [Parameter(Mandatory = $true)][hashtable]$ContentBase64
    )

    $body = @{
        '@odata.type'         = [string]$script:PDOrgRegistryGraph.Types[$Type].ODataType
        displayName           = [string]$Metadata.DisplayName
        description           = [string]$Metadata.Description
        runAsAccount          = 'system'
        enforceSignatureCheck = $false
        runAs32Bit            = $false
    }

    if ($Type -eq 'PlatformScript') {
        $body['fileName']      = [string]$Metadata.FileName
        $body['scriptContent'] = [string]$ContentBase64['scriptContent']
    } else {
        $body['publisher']                = [string]$script:PDOrgRegistryGraph.Publisher
        $body['detectionScriptContent']   = [string]$ContentBase64['detectionScriptContent']
        $body['remediationScriptContent'] = [string]$ContentBase64['remediationScriptContent']
    }

    return $body
}

function New-PDOrgRegistryAssignments {
    <#
        .SYNOPSIS
        The assignment objects to send. New targets: an Intune Remediation gets
        runRemediationScript = $true and the hourly schedule (interval 1); an Intune Platform Script
        gets the target only. Kept assignments: exactly as Intune returned them; -OmitIds drops only
        their read-only 'id'.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PlatformScript', 'Remediation')][string]$Type,
        [AllowNull()][AllowEmptyCollection()][object[]]$Targets,
        [AllowNull()][AllowEmptyCollection()][object[]]$KeptAssignments,
        [switch]$Keep,
        [switch]$OmitIds
    )

    $shape = $script:PDOrgRegistryGraph.Types[$Type]
    $assignments = @()

    if ($Keep) {
        foreach ($kept in @($KeptAssignments)) {
            if ($null -eq $kept) { continue }
            if (-not $OmitIds) { $assignments += $kept; continue }
            $copy = [ordered]@{}
            foreach ($property in $kept.PSObject.Properties) {
                if ($property.Name -ceq 'id') { continue }
                $copy[$property.Name] = $property.Value
            }
            $assignments += [pscustomobject]$copy
        }
        return $assignments
    }

    foreach ($target in @($Targets)) {
        if ($null -eq $target) { continue }
        $assignment = @{
            '@odata.type' = [string]$shape.AssignmentODataType
            target        = $target
        }
        if ($Type -eq 'Remediation') {
            $assignment['runRemediationScript'] = $true
            $assignment['runSchedule'] = @{
                '@odata.type' = [string]$script:PDOrgRegistryGraph.HourlyScheduleODataType
                interval      = [int]$script:PDOrgRegistryGraph.HourlyInterval
            }
        }
        $assignments += $assignment
    }

    return $assignments
}

function New-PDOrgRegistryAssignBody {
    <# The /assign body: { <deviceManagementScriptAssignments | deviceHealthScriptAssignments>: [...] }. #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PlatformScript', 'Remediation')][string]$Type,
        [AllowNull()][AllowEmptyCollection()][object[]]$Assignments
    )

    return @{ ([string]$script:PDOrgRegistryGraph.Types[$Type].AssignProperty) = @($Assignments) }
}

# ---------------------------------------------------------------------------
# Read-back
# ---------------------------------------------------------------------------

function Compare-PDOrgRegistryReadBack {
    <#
        .SYNOPSIS
        Differences between what was sent and what Intune holds: name, description, settings, file
        name or publisher, the content's SHA256, the assignment targets and (Intune Remediation)
        each assignment's schedule. Returns one sentence per difference; empty means verified.
        Content is compared by hash only and never appears in a sentence.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PlatformScript', 'Remediation')][string]$Type,
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][hashtable]$Metadata,
        [Parameter(Mandatory = $true)][hashtable]$SentHashes,
        [AllowNull()][AllowEmptyCollection()][object[]]$ExpectedAssignments,
        [AllowNull()][AllowEmptyCollection()][object[]]$ActualAssignments
    )

    $problems = @()
    if ($null -eq $Object) { return @('Intune returned nothing when the object was read back.') }

    $normalize = { param($Text) ((([string]$Text) -replace "`r`n", "`n") -replace "`r", "`n").Trim() }

    if ([string](Get-PDGraphPropertyValue -Object $Object -Name 'displayName') -cne [string]$Metadata.DisplayName) { $problems += 'The name differs.' }
    if ((& $normalize (Get-PDGraphPropertyValue -Object $Object -Name 'description')) -cne (& $normalize $Metadata.Description)) { $problems += 'The description differs.' }
    if ([string](Get-PDGraphPropertyValue -Object $Object -Name 'runAsAccount') -ine 'system') { $problems += 'It does not run as System.' }
    if ([string](Get-PDGraphPropertyValue -Object $Object -Name 'enforceSignatureCheck') -ine 'False') { $problems += 'The signature check is not off.' }
    if ([string](Get-PDGraphPropertyValue -Object $Object -Name 'runAs32Bit') -ine 'False') { $problems += 'It does not run in 64-bit PowerShell.' }

    if ($Type -eq 'PlatformScript') {
        if ([string](Get-PDGraphPropertyValue -Object $Object -Name 'fileName') -cne [string]$Metadata.FileName) { $problems += 'The file name differs.' }
    } else {
        if ([string](Get-PDGraphPropertyValue -Object $Object -Name 'publisher') -cne [string]$script:PDOrgRegistryGraph.Publisher) { $problems += 'The publisher differs.' }
    }

    $contentNames = @{ scriptContent = 'script'; detectionScriptContent = 'detection script'; remediationScriptContent = 'remediation script' }
    foreach ($property in @($script:PDOrgRegistryGraph.Types[$Type].ContentProperties)) {
        $returned = [string](Get-PDGraphPropertyValue -Object $Object -Name $property)
        $label = [string]$contentNames[$property]
        if ([string]::IsNullOrWhiteSpace($returned)) { $problems += ('Intune did not return the {0} content, so it could not be verified.' -f $label); continue }
        $hash = $null
        try { $hash = Get-PDOrgRegistrySha256 -Bytes ([System.Convert]::FromBase64String($returned)) } catch { $hash = $null }
        $returned = $null
        if ($null -eq $hash) { $problems += ('The {0} content Intune returned could not be read.' -f $label); continue }
        if ($hash -ne [string]$SentHashes[$property]) { $problems += ('The {0} content Intune holds is not the content that was sent (SHA256 differs).' -f $label) }
    }

    # Assignments: the same set of targets, and for an Intune Remediation the same schedule per target.
    $expectedByKey = @{}
    foreach ($assignment in @($ExpectedAssignments)) {
        if ($null -eq $assignment) { continue }
        $expectedByKey[(Get-PDOrgRegistryTargetKey -Target (Get-PDGraphPropertyValue -Object $assignment -Name 'target'))] = $assignment
    }
    $actualByKey = @{}
    foreach ($assignment in @($ActualAssignments)) {
        if ($null -eq $assignment) { continue }
        $actualByKey[(Get-PDOrgRegistryTargetKey -Target (Get-PDGraphPropertyValue -Object $assignment -Name 'target'))] = $assignment
    }

    $missing = @($expectedByKey.Keys | Where-Object { -not $actualByKey.ContainsKey($_) })
    $extra   = @($actualByKey.Keys | Where-Object { -not $expectedByKey.ContainsKey($_) })
    if ($missing.Count -gt 0) { $problems += ('{0} assignment(s) that were sent are missing.' -f $missing.Count) }
    if ($extra.Count -gt 0)   { $problems += ('{0} assignment(s) are there that were not sent.' -f $extra.Count) }

    if ($Type -eq 'Remediation') {
        foreach ($key in @($expectedByKey.Keys)) {
            if (-not $actualByKey.ContainsKey($key)) { continue }
            $sent = Get-PDGraphPropertyValue -Object $expectedByKey[$key] -Name 'runSchedule'
            $held = Get-PDGraphPropertyValue -Object $actualByKey[$key] -Name 'runSchedule'
            $sentType = ([string](Get-PDGraphPropertyValue -Object $sent -Name '@odata.type')).TrimStart('#')
            $heldType = ([string](Get-PDGraphPropertyValue -Object $held -Name '@odata.type')).TrimStart('#')
            $sentInterval = [string](Get-PDGraphPropertyValue -Object $sent -Name 'interval')
            $heldInterval = [string](Get-PDGraphPropertyValue -Object $held -Name 'interval')
            if (($sentType -ine $heldType) -or ($sentInterval -ne $heldInterval)) {
                $problems += ('An assignment''s schedule is {0}, not {1}.' -f (Get-PDOrgRegistryScheduleText -Assignment $actualByKey[$key]), (Get-PDOrgRegistryScheduleText -Assignment $expectedByKey[$key]))
            }
        }
    }

    return $problems
}

# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

function Invoke-PDOrgRegistryUpload {
    <#
        .SYNOPSIS
        Writes every object in the plan, in order: create or PATCH, assign, read back. Stops at the
        first failure. Never throws, never prompts.

        .PARAMETER Metadata
        @{ PlatformScript = @{ DisplayName; Description; FileName }; Remediation = @{ DisplayName; Description } }

        .PARAMETER Content
        @{ PlatformScript = @{ Script = <fingerprint> }; Remediation = @{ Detection = <fingerprint>; Remediation = <fingerprint> } }
        Fingerprints come from Get-PDOrgRegistryFileFingerprint at review time. Each file is read
        again here; a file whose SHA256 changed since the review is not sent.

        .PARAMETER Targets
        New assignment targets (ConvertTo-PDOrgRegistryTargets), for every object. Or -KeepAssignments.

        .PARAMETER KeepAssignments
        Re-send each updated object's current assignments unchanged. If Graph refuses them with HTTP
        400 (not Multi-Admin Approval), they are sent once more without their read-only 'id'.

        .OUTPUTS
        { Success; ApprovalRequired; Objects = @( per entry { Type; TypeLabel; Action; Id; DisplayName;
          PortalUrl; Created; Adopted; Written; Assigned; Verified; Status; CleanupStatus; Message } ) }
        Status is Verified, Failed or NotAttempted. Message says exactly what was and was not changed.
        CleanupStatus is NotNeeded, Deleted (created in this run and removed again), Failed, Unknown
        (a create with no answer and nothing new found), or KeptForReview (an object found by its name
        after a lost create response: it gets no write of any kind and is never deleted).
    #>
    param(
        [AllowNull()][object]$AuthContext,
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][hashtable]$Metadata,
        [Parameter(Mandatory = $true)][hashtable]$Content,
        [AllowNull()][AllowEmptyCollection()][object[]]$Targets,
        [switch]$KeepAssignments,
        [AllowNull()][scriptblock]$Log,
        # The exact secret values in the scripts (repository token, SAS keys, a repository URL with a
        # token). Removed from every message and log line of this call; never logged.
        [AllowNull()][AllowEmptyCollection()][object[]]$RedactValues
    )

    $previousRedact = @($script:PDOrgRegistryRedact)
    if ($PSBoundParameters.ContainsKey('RedactValues')) { Set-PDOrgRegistryRedactValues -Values $RedactValues }

    try {

    $results = @()
    $approval = $false
    $stopped = $false

    if ($Plan.NeedsChoice) {
        foreach ($entry in @($Plan.Entries)) {
            $results += [pscustomobject]@{ Type = $entry.Type; TypeLabel = $entry.TypeLabel; Action = $entry.Action; Id = ''; DisplayName = ''; PortalUrl = ''
                Created = $false; Written = $false; Assigned = $false; Verified = $false; Status = 'NotAttempted'; CleanupStatus = 'NotNeeded'
                Message = 'Not attempted: an existing copy still has to be chosen. Nothing was changed.' }
        }
        return [pscustomobject]@{ Success = $false; ApprovalRequired = $false; Objects = @($results) }
    }

    $refusal = ''
    if (-not $KeepAssignments -and @($Targets).Count -eq 0) { $refusal = 'Not attempted: no groups were given. Nothing was changed.' }
    if ($KeepAssignments -and @($Plan.Entries | Where-Object { $_.Action -ne 'Update' -or $null -eq $_.Target }).Count -gt 0) {
        $refusal = 'Not attempted: a new object has no assignments to keep, so groups are needed. Nothing was changed.'
    }
    if ($refusal) {
        foreach ($entry in @($Plan.Entries)) {
            $results += [pscustomobject]@{ Type = $entry.Type; TypeLabel = $entry.TypeLabel; Action = $entry.Action; Id = ''; DisplayName = ''; PortalUrl = ''
                Created = $false; Written = $false; Assigned = $false; Verified = $false; Status = 'NotAttempted'; CleanupStatus = 'NotNeeded'
                Message = $refusal }
        }
        return [pscustomobject]@{ Success = $false; ApprovalRequired = $false; Objects = @($results) }
    }

    foreach ($entry in @($Plan.Entries)) {
        $type  = [string]$entry.Type
        $label = [string]$entry.TypeLabel
        $meta  = $Metadata[$type]

        $state = [pscustomobject]@{
            Type = $type; TypeLabel = $label; Action = [string]$entry.Action; Id = ''; DisplayName = [string]$meta.DisplayName; PortalUrl = ''
            Created = $false; Adopted = $false; Written = $false; Assigned = $false; Verified = $false; Status = 'NotAttempted'; CleanupStatus = 'NotNeeded'; Message = ''
        }

        if ($stopped) {
            $state.Message = 'Not attempted, because an earlier step failed. Nothing was changed.'
            $results += $state
            continue
        }

        if ($entry.Action -eq 'Update') { $state.Id = [string]$entry.Target.Id }

        $stage = 'Content'
        $lost  = $false
        try {
            # --- Content: re-read, check against the review, encode ---------------------------
            $contentFiles = @{}
            if ($type -eq 'PlatformScript') { $contentFiles['scriptContent'] = $Content[$type]['Script'] }
            else { $contentFiles['detectionScriptContent'] = $Content[$type]['Detection']; $contentFiles['remediationScriptContent'] = $Content[$type]['Remediation'] }

            $base64 = @{}
            $sentHashes = @{}
            foreach ($property in @($contentFiles.Keys)) {
                $fingerprint = $contentFiles[$property]
                if ($null -eq $fingerprint -or [string]::IsNullOrWhiteSpace([string]$fingerprint.Path)) {
                    Stop-PDGraphError -Message ('The {0} has no script file to send.' -f $label) -Stage $stage
                }
                $bytes = [System.IO.File]::ReadAllBytes([string]$fingerprint.Path)
                $hash = Get-PDOrgRegistrySha256 -Bytes $bytes
                if ($hash -ne [string]$fingerprint.Sha256) {
                    Stop-PDGraphError -Message ("The script file '{0}' changed after the review, so it was not sent." -f [string]$fingerprint.Path) -Stage $stage
                }
                $base64[$property] = [System.Convert]::ToBase64String($bytes)
                $sentHashes[$property] = $hash
                $bytes = $null
            }

            $body = New-PDOrgRegistryObjectBody -Type $type -Metadata $meta -ContentBase64 $base64
            $base64 = $null

            # --- Create or update ---------------------------------------------------------------
            if ($entry.Action -eq 'Create') {
                $stage = 'Create'
                $listPath = New-PDGraphQueryPath -Path ([string]$script:PDOrgRegistryGraph.Types[$type].Path) -Query @{ '$select' = 'id,displayName' }

                # Every id of this type that exists right before the POST. After a lost response, only
                # an id that was not in this set can be the object this run created; one another admin
                # made while this run waited at its prompts is in the set and is never adopted.
                $before = @{}
                foreach ($item in (Get-PDGraphItems -Payload (Get-PDGraphCollection -Path $listPath -AuthContext $AuthContext -Stage $stage -Description ('{0} list before the create' -f $label)))) {
                    $itemId = [string](Get-PDGraphPropertyValue -Object $item -Name 'id')
                    if (-not [string]::IsNullOrWhiteSpace($itemId)) { $before[$itemId.ToLowerInvariant()] = $true }
                }

                Write-PDOrgRegistryLog -Log $Log -Message ("Creating the {0} '{1}'." -f $label, $state.DisplayName)
                $created = $null
                try {
                    $created = Invoke-PDGraphRequest -Method Post -Uri ([string]$script:PDOrgRegistryGraph.Types[$type].Path) -Body $body -AuthContext $AuthContext -RetryMode 'Write' -Stage $stage -Description ('create the {0}' -f $label)
                } catch {
                    $info = Get-PDGraphErrorInfo -ErrorRecord $_
                    if (-not (($info.Status -eq 0) -or ($info.Status -ge 500))) { throw }

                    # The create may or may not have happened. Never send it again: look for exactly one
                    # object with this name whose id was not there right before the POST.
                    $reconciled = $null
                    try {
                        foreach ($item in (Get-PDGraphItems -Payload (Get-PDGraphCollection -Path $listPath -AuthContext $AuthContext -Stage $stage -Description ('{0} list' -f $label)))) {
                            $itemId = [string](Get-PDGraphPropertyValue -Object $item -Name 'id')
                            if ([string](Get-PDGraphPropertyValue -Object $item -Name 'displayName') -cne $state.DisplayName) { continue }
                            if ([string]::IsNullOrWhiteSpace($itemId) -or $before.ContainsKey($itemId.ToLowerInvariant())) { continue }
                            if ($null -eq $reconciled) { $reconciled = $itemId } else { $reconciled = $null; break }
                        }
                    } catch { $reconciled = $null }

                    if ([string]::IsNullOrWhiteSpace($reconciled)) { $lost = $true; throw }

                    # Adopted, not created: it may be this run's object or another admin's identical copy,
                    # so it gets no write of any kind (no assign, no PATCH) and is never deleted.
                    $state.Id = $reconciled
                    $state.Adopted = $true
                    $state.CleanupStatus = 'KeptForReview'
                    Write-PDOrgRegistryLog -Log $Log -Message ("The create response was lost; the {0} '{1}' ({2}) was found by its name and left unchanged for review." -f $label, $state.DisplayName, $reconciled) -Level 'WARNING'
                    Stop-PDGraphError -Message ("An {0} named {1} (ID {2}) appeared after the create request was sent. It may have been created by this run or by another admin, so it was left unchanged for review." -f $label, $state.DisplayName, $reconciled) -Stage $stage -Detail 'Adopted'
                }
                $newId = [string](Get-PDGraphPropertyValue -Object $created -Name 'id')
                if ([string]::IsNullOrWhiteSpace($newId)) {
                    $lost = $true
                    Stop-PDGraphError -Message ('Intune accepted the new {0} but returned no id.' -f $label) -Stage $stage
                }
                $state.Id = $newId
                $state.Created = $true
                $state.Written = $true
                Write-PDOrgRegistryLog -Log $Log -Message ("Created the {0} '{1}' ({2})." -f $label, $state.DisplayName, $newId)
            } else {
                $stage = 'Update'
                Write-PDOrgRegistryLog -Log $Log -Message ("Updating the {0} '{1}' ({2})." -f $label, [string]$entry.Target.DisplayName, $state.Id)
                try {
                    $null = Invoke-PDGraphRequest -Method Patch -Uri (Get-PDOrgRegistryObjectPath -Type $type -Id $state.Id) -Body $body -AuthContext $AuthContext -RetryMode 'Write' -Stage $stage -Description ('update the {0}' -f $label)
                } catch {
                    $info = Get-PDGraphErrorInfo -ErrorRecord $_
                    if (($info.Status -eq 0) -or ($info.Status -ge 500)) { $lost = $true }
                    throw
                }
                $state.Written = $true
                Write-PDOrgRegistryLog -Log $Log -Message ("Updated the name, description, content and settings of {0}." -f $state.Id)
            }
            $body = $null

            # --- Assign ------------------------------------------------------------------------
            $stage = 'Assign'
            if ($KeepAssignments) {
                $expected = @(New-PDOrgRegistryAssignments -Type $type -KeptAssignments @($entry.Target.Assignments) -Keep)
            } else {
                $expected = @(New-PDOrgRegistryAssignments -Type $type -Targets @($Targets))
            }
            $assignPath = Get-PDOrgRegistryObjectPath -Type $type -Id $state.Id -Suffix '/assign'
            try {
                $null = Invoke-PDGraphRequest -Method Post -Uri $assignPath -Body (New-PDOrgRegistryAssignBody -Type $type -Assignments $expected) -AuthContext $AuthContext -RetryMode 'Write' -Stage $stage -Description ('assign the {0}' -f $label)
            } catch {
                $info = Get-PDGraphErrorInfo -ErrorRecord $_
                $hasIds = $KeepAssignments -and (@($expected | Where-Object { $null -ne (Get-PDGraphPropertyValue -Object $_ -Name 'id') }).Count -gt 0)
                if (-not ($hasIds -and $info.Status -eq 400 -and -not $info.ApprovalRequired)) {
                    if (($info.Status -eq 0) -or ($info.Status -ge 500)) { $lost = $true }
                    throw
                }
                # Refused outright (nothing was assigned): the same assignments once more, without the
                # read-only id Graph returned them with.
                Write-PDOrgRegistryLog -Log $Log -Message ("Intune refused the current assignments with their ids (HTTP 400); sending them again without the read-only id.") -Level 'WARNING'
                $expected = @(New-PDOrgRegistryAssignments -Type $type -KeptAssignments @($entry.Target.Assignments) -Keep -OmitIds)
                try {
                    $null = Invoke-PDGraphRequest -Method Post -Uri $assignPath -Body (New-PDOrgRegistryAssignBody -Type $type -Assignments $expected) -AuthContext $AuthContext -RetryMode 'Write' -Stage $stage -Description ('assign the {0}' -f $label)
                } catch {
                    $info = Get-PDGraphErrorInfo -ErrorRecord $_
                    if (($info.Status -eq 0) -or ($info.Status -ge 500)) { $lost = $true }
                    throw
                }
            }
            $state.Assigned = $true
            Write-PDOrgRegistryLog -Log $Log -Message ("Assigned {0} to {1} target(s)." -f $state.Id, @($expected).Count)

            # --- Read back -----------------------------------------------------------------------
            $stage = 'Verify'
            $readObject = Invoke-PDGraphRequest -Method Get -Uri (Get-PDOrgRegistryObjectPath -Type $type -Id $state.Id) -AuthContext $AuthContext -RetryMode 'Read' -Stage $stage -Description ('read back the {0}' -f $label)
            $readAssignments = @(Get-PDGraphItems -Payload (Get-PDGraphCollection -Path (Get-PDOrgRegistryObjectPath -Type $type -Id $state.Id -Suffix '/assignments') -AuthContext $AuthContext -Stage $stage -Description ('read back the assignments of the {0}' -f $label)))

            $problems = @(Compare-PDOrgRegistryReadBack -Type $type -Object $readObject -Metadata $meta -SentHashes $sentHashes -ExpectedAssignments $expected -ActualAssignments $readAssignments)
            $readObject = $null
            if ($problems.Count -gt 0) {
                Stop-PDGraphError -Message ('The read-back does not match what was sent: {0}' -f ($problems -join ' ')) -Stage $stage -Detail 'ReadBackMismatch'
            }

            $state.Verified = $true
            $state.Status = 'Verified'
            $state.PortalUrl = Get-PDOrgRegistryPortalUrl -Type $type -Id $state.Id
            if ($entry.Action -eq 'Create') { $state.Message = ('Created, assigned and verified (ID {0}).' -f $state.Id) }
            else { $state.Message = ('Updated, assigned and verified (ID {0}).' -f $state.Id) }
            Write-PDOrgRegistryLog -Log $Log -Message ("Verified the {0} {1}." -f $label, $state.Id) -Level 'SUCCESS'
        } catch {
            $body = $null
            $base64 = $null
            $stopped = $true
            $state.Status = 'Failed'
            $info = Get-PDGraphErrorInfo -ErrorRecord $_
            if ($info.ApprovalRequired) { $approval = $true }
            $reason = Get-PDOrgRegistryErrorText -ErrorRecord $_
            Write-PDOrgRegistryLog -Log $Log -Message ("The {0} failed at stage {1}: {2}" -f $label, $stage, $reason) -Level 'ERROR'

            $changed = ''
            if ($entry.Action -eq 'Create' -and $state.Adopted) {
                # Found by its name after a lost response: never deleted automatically.
                $state.CleanupStatus = 'KeptForReview'
                $changed = ("An {0} named {1} (ID {2}) appeared after the create request was sent. It may have been created by this run or by another admin, so it was left unchanged for review." -f $label, $state.DisplayName, $state.Id)
            } elseif ($entry.Action -eq 'Create') {
                if (-not $state.Created) {
                    if ($lost) { $changed = ("The create request got no answer, so the {0} may or may not exist. Check the Intune admin center for '{1}' before trying again." -f $label, $state.DisplayName); $state.CleanupStatus = 'Unknown' }
                    else { $changed = 'Nothing was created.' }
                } else {
                    # Created in this run: the only kind of object this engine ever deletes.
                    try {
                        $null = Invoke-PDGraphRequest -Method Delete -Uri (Get-PDOrgRegistryObjectPath -Type $type -Id $state.Id) -AuthContext $AuthContext -RetryMode 'Write' -Stage 'Rollback' -Description ('delete the incomplete {0}' -f $label)
                        $state.CleanupStatus = 'Deleted'
                        $changed = ('It was created ({0}) and then deleted again, so nothing was left in Intune.' -f $state.Id)
                        Write-PDOrgRegistryLog -Log $Log -Message ("Deleted the incomplete {0} {1}." -f $label, $state.Id) -Level 'WARNING'
                    } catch {
                        $state.CleanupStatus = 'Failed'
                        $changed = ('It was created ({0}) but could not be deleted again: {1} Delete it in the Intune admin center.' -f $state.Id, (Get-PDOrgRegistryErrorText -ErrorRecord $_))
                        Write-PDOrgRegistryLog -Log $Log -Message ("Could not delete the incomplete {0} {1}." -f $label, $state.Id) -Level 'ERROR'
                    }
                }
            } else {
                $state.CleanupStatus = 'NotNeeded'
                if (-not $state.Written) {
                    if ($lost) { $changed = 'The update request got no answer, so its name, description, content and settings may or may not have changed. Its assignments were not changed.' }
                    else { $changed = 'Nothing was changed.' }
                } elseif (-not $state.Assigned) {
                    if ($lost) { $changed = 'Its name, description, content and settings were updated. The assign request got no answer, so its assignments may or may not have changed.' }
                    else { $changed = 'Its name, description, content and settings were updated. Its assignments were not changed.' }
                } else {
                    $changed = 'Its name, description, content, settings and assignments were sent. It was not deleted, because it existed before this run.'
                }
            }

            if ($state.Adopted) { $state.Message = (Protect-PDOrgRegistryText -Text $changed) }
            else { $state.Message = ('{0} {1}' -f $reason, $changed) }
        }

        $results += $state
    }

    $success = (@($results).Count -gt 0) -and (@($results | Where-Object { $_.Status -ne 'Verified' }).Count -eq 0)
    return [pscustomobject]@{ Success = [bool]$success; ApprovalRequired = [bool]$approval; Objects = @($results) }

    } finally {
        $script:PDOrgRegistryRedact = @($previousRedact)
    }
}

# ---------------------------------------------------------------------------
# Deletion list
# ---------------------------------------------------------------------------

function Get-PDOrgRegistryDeletionList {
    <#
        .SYNOPSIS
        One numbered list of every org registry object (the inventory), sorted by type, deploy mode
        and name. Objects whose id is in JustUploadedIds are listed but cannot be selected.

        .OUTPUTS
        { Number; Type; TypeLabel; DisplayName; DeployMode; Commit; Id; LastModified; AssignmentLines;
          Assignments; Selectable; JustUploaded }
    #>
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Inventory,
        [AllowNull()][AllowEmptyCollection()][string[]]$JustUploadedIds
    )

    $uploaded = @{}
    foreach ($id in @($JustUploadedIds)) { if (-not [string]::IsNullOrWhiteSpace($id)) { $uploaded[$id.Trim().ToLowerInvariant()] = $true } }

    $order = @{}
    $index = 0
    foreach ($type in @($script:PDOrgRegistryGraph.TypeOrder)) { $order[$type] = $index; $index++ }

    $sorted = @(@($Inventory) | Where-Object { $null -ne $_ } | Sort-Object @{ Expression = { $order[$_.Type] } }, @{ Expression = { $_.DeployMode } }, @{ Expression = { $_.DisplayName } }, @{ Expression = { $_.Id } })

    $list = @()
    $number = 0
    foreach ($object in $sorted) {
        $number++
        $just = $uploaded.ContainsKey(([string]$object.Id).ToLowerInvariant())
        $list += [pscustomobject]@{
            Number          = $number
            Type            = [string]$object.Type
            TypeLabel       = [string]$object.TypeLabel
            DisplayName     = [string]$object.DisplayName
            DeployMode      = $(if ($object.IsRecognized) { [string]$object.DeployMode } else { '(name not recognized)' })
            Commit          = $(if ([string]::IsNullOrWhiteSpace([string]$object.Commit)) { '(unknown)' } else { [string]$object.Commit })
            Id              = [string]$object.Id
            LastModified    = [string]$object.LastModified
            AssignmentLines = @($object.AssignmentLines)
            Assignments     = @($object.Assignments)
            Selectable      = (-not $just)
            JustUploaded    = [bool]$just
        }
    }

    return $list
}

function ConvertFrom-PDOrgRegistryDeletionSelection {
    <#
        .SYNOPSIS
        Reads the admin's answer to "Enter the numbers to delete, separated by commas".

        .DESCRIPTION
        Blank: nothing. Otherwise every comma-separated piece must be a listed number; a repeated
        number counts once. A number belonging to an object just uploaded is refused. Any problem
        means nothing is selected and every problem is reported, so the question can be asked again.

        .OUTPUTS
        { Selected = list entries, in list order; Errors = sentences }
    #>
    param(
        [AllowNull()][string]$Text,
        [AllowNull()][AllowEmptyCollection()][object[]]$List
    )

    $result = [pscustomobject]@{ Selected = @(); Errors = @() }
    if ([string]::IsNullOrWhiteSpace($Text)) { return $result }

    $byNumber = @{}
    foreach ($entry in @($List)) { if ($null -ne $entry) { $byNumber[[int]$entry.Number] = $entry } }

    $picked = @{}
    $errors = @()
    foreach ($piece in ($Text -split ',')) {
        $token = $piece.Trim()
        if ($token -eq '') { continue }
        $number = 0
        if (-not ($token -match '^[0-9]{1,6}$') -or -not [int]::TryParse($token, [ref]$number)) { $errors += ("'{0}' is not a number from the list." -f $token); continue }
        if (-not $byNumber.ContainsKey($number)) { $errors += ("{0} is not in the list." -f $number); continue }
        if (-not $byNumber[$number].Selectable) { $errors += ("{0} was just uploaded, so it cannot be deleted here." -f $number); continue }
        $picked[$number] = $true
    }

    if ($errors.Count -gt 0) { $result.Errors = @($errors); return $result }

    $result.Selected = @(@($List) | Where-Object { $null -ne $_ -and $picked.ContainsKey([int]$_.Number) } | Sort-Object Number)
    return $result
}

function Remove-PDOrgRegistryIntuneObject {
    <#
        .SYNOPSIS
        Deletes one listed object. Its name, ID and current assignments are logged first, read fresh
        from Intune; if they cannot be read, nothing is deleted. Never throws.

        .OUTPUTS
        { Result = Deleted | AlreadyGone | ReadFailed | DeleteFailed; Message }
    #>
    param(
        [AllowNull()][object]$AuthContext,
        [Parameter(Mandatory = $true)][object]$Entry,
        [AllowNull()][scriptblock]$Log
    )

    $type = [string]$Entry.Type
    $id = [string]$Entry.Id
    $label = Get-PDOrgRegistryTypeLabel -Type $type

    try {
        $assignments = @(Get-PDGraphItems -Payload (Get-PDGraphCollection -Path (Get-PDOrgRegistryObjectPath -Type $type -Id $id -Suffix '/assignments') -AuthContext $AuthContext -Stage 'Delete' -Description ('assignments of {0} {1}' -f $label, $id)))
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        if ($info.Status -eq 404) { return [pscustomobject]@{ Result = 'AlreadyGone'; Message = 'It was no longer in Intune.' } }
        $reason = Get-PDOrgRegistryErrorText -ErrorRecord $_
        Write-PDOrgRegistryLog -Log $Log -Message ("Not deleting the {0} '{1}' ({2}): its assignments could not be read for the log. {3}" -f $label, [string]$Entry.DisplayName, $id, $reason) -Level 'ERROR'
        return [pscustomobject]@{ Result = 'ReadFailed'; Message = ('Its assignments could not be read for the log, so it was not deleted. {0}' -f $reason) }
    }

    $assignmentJson = '[]'
    if ($assignments.Count -gt 0) { $assignmentJson = ConvertTo-Json -InputObject @($assignments) -Depth 10 -Compress }
    Write-PDOrgRegistryLog -Log $Log -Message ("Deleting the {0} '{1}' ({2}). Its assignments: {3}" -f $label, [string]$Entry.DisplayName, $id, $assignmentJson) -Level 'WARNING'

    try {
        $null = Invoke-PDGraphRequest -Method Delete -Uri (Get-PDOrgRegistryObjectPath -Type $type -Id $id) -AuthContext $AuthContext -RetryMode 'Write' -Stage 'Delete' -Description ('delete the {0} {1}' -f $label, $id)
        Write-PDOrgRegistryLog -Log $Log -Message ("Deleted the {0} {1}." -f $label, $id) -Level 'SUCCESS'
        return [pscustomobject]@{ Result = 'Deleted'; Message = 'Deleted.' }
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        if ($info.Status -eq 404) { return [pscustomobject]@{ Result = 'AlreadyGone'; Message = 'It was no longer in Intune.' } }
        $reason = Get-PDOrgRegistryErrorText -ErrorRecord $_
        Write-PDOrgRegistryLog -Log $Log -Message ("Could not delete the {0} {1}: {2}" -f $label, $id, $reason) -Level 'ERROR'
        return [pscustomobject]@{ Result = 'DeleteFailed'; ApprovalRequired = [bool]$info.ApprovalRequired; Message = $reason }
    }
}
