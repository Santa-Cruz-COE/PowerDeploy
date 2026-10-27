<#

.SYNOPSIS
    Prepares and (in a later milestone) publishes a Win32 application to Intune through
    Microsoft Graph, returning exactly one result object.

.DESCRIPTION
    M3 of .claude/plans/intune-graph-upload.buildplan.md delivered the public parameter block,
    the uploader-owned logger, the whole of preflight (spec 9.2), the review data, and the
    duplicate-name execution gate. M4 added the write stages (spec 10.3) and the rollback
    (spec 11.2): create app, content version, file record, storage URI, block upload, commit,
    publish, category, assignments, and verification by read-back.

    This file may be dot-sourced: functions only, no prompts, no output, no side effects at
    import. Running it as a script prints the review summary and returns the result object.

        . Other_Tools\Upload-InTuneWin32App.ps1
        $result = Invoke-PDIntuneUpload -IntuneWinPath app.intunewin -DisplayName 'App' ... -DryRun

    or

        powershell -NoProfile -ExecutionPolicy Bypass -File Other_Tools\Upload-InTuneWin32App.ps1 `
            -IntuneWinPath app.intunewin -DisplayName 'App' -Publisher 'PowerDeploy' `
            -Description 'N/A' -InstallCommandFile install.txt -UninstallCommandFile uninstall.txt `
            -DetectionScriptFile detect.ps1 -DryRun

    Contract (spec 9):
      - One return object; operational failures are reported inside it, never as a crash.
      - No interactive prompts here - Setup.ps1 owns prompting.
      - Never truncates a command and never imposes an undocumented length limit (spec 14.3).
      - DryRun issues zero mutation calls, including category creation and secret operations.
      - Install/uninstall command text never appears in the returned object or the log: it can
        contain repository credentials. Only its length is reported.
      - Package encryption key material stays inside this process and is never logged.

.PARAMETER DryRun
    Full preflight, review data returned, no tenant writes of any kind.

.PARAMETER AllowDuplicateName
    Required to create an app whose DisplayName already exists. Never implied.

.PARAMETER NoRollback
    Keep a created app when a later stage fails. M4 uses this; accepted now so the signature is
    stable for Setup.ps1.

.LINK
    Other_Tools/InTune-GraphAPI_Helpers.ps1
    .claude/plans/intune-graph-upload.md sections 9, 10, 11

#>

# ---------------------------------------------------------------------------
# There is deliberately no top-level param block
# ---------------------------------------------------------------------------
#
# Setup.ps1 and the test harness dot-source this file. Dot-sourcing a script that declares
# parameters writes every one of them - as $null when not supplied - into the CALLER's scope,
# which would silently erase Setup.ps1's live wizard state ($Notes, $Category, $Publisher,
# $AppVersion, and the rest; spec 4.1 says those are live variables). So the public parameter
# block lives on Invoke-PDIntuneUpload, command-line use goes through
# ConvertTo-PDUploaderRunArgument below, and importing this file only ever creates
# $script:PD-prefixed state.

$script:PDUploaderDotSourced = ($MyInvocation.InvocationName -eq '.')

function Get-PDUploaderCanonicalName {
    <#
        .SYNOPSIS
        Case-insensitive lookup of an option name, matching PowerShell's own behaviour.
        Returns $null when the option is unknown so the caller can report every typo.
    #>
    param(
        [AllowNull()][string]$Name,
        [Parameter(Mandatory = $true)][string[]]$Known
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    foreach ($candidate in $Known) {
        if (([string]$candidate) -ieq $Name) { return $candidate }
    }
    return $null
}

function Test-PDUploaderTruthy {
    <#
        .SYNOPSIS
        Reads a command-line boolean ($true, true, 1, yes / $false, false, 0, no). Anything else
        is an error rather than a silent false.
    #>
    param([AllowNull()][string]$Text, [string]$OptionName)

    $normalized = ([string]$Text).Trim().Replace('$', '').ToLowerInvariant()
    if (@('true', '1', 'yes') -ccontains $normalized) { return $true }
    if (@('false', '0', 'no') -ccontains $normalized) { return $false }
    throw ("-{0} must be true or false, not '{1}'." -f $OptionName, [string]$Text)
}

function ConvertTo-PDUploaderRunArgument {
    <#
        .SYNOPSIS
        Parses this script's own command line into a splat for Invoke-PDIntuneUpload.

        .DESCRIPTION
        Deliberately small and strict: -Name value, -Name:value, -Switch, -Switch:$true|:$false.
        -RequiredGroups and -AvailableGroups may be repeated and/or semicolon-delimited. An
        unknown option or a missing value is an error, because a typo in a publish command must
        never be treated as "the operator left it out".
    #>
    param([AllowEmptyCollection()][string[]]$RawArguments)

    $valueNames   = @('IntuneWinPath', 'DisplayName', 'Description', 'Publisher',
                      'InstallCommandFile', 'UninstallCommandFile', 'DetectionScriptFile',
                      'AppVersion', 'Category', 'Notes', 'CredentialPath', 'IconFile', 'InformationUrl', 'PrivacyUrl',
                      'LogDirectory', 'TempDirectory')
    $listNames    = @('RequiredGroups', 'AvailableGroups')
    $switchNames  = @('DryRun', 'AllowDuplicateName', 'NoRollback')
    $booleanNames = @('AllowAvailableUninstall')

    $parsed = @{}
    $lists  = @{}
    foreach ($name in $listNames) { $lists[$name] = @() }

    $index = 0
    while ($index -lt @($RawArguments).Count) {
        $token = [string]$RawArguments[$index]

        if (-not $token.StartsWith('-')) {
            throw ("Unexpected argument '{0}'. Options are -Name value or -Switch." -f $token)
        }

        $optionName = $token.TrimStart('-')
        $inline     = $null
        if ($optionName.Contains(':')) {
            $splitAt    = $optionName.IndexOf(':')
            $inline     = $optionName.Substring($splitAt + 1)
            $optionName = $optionName.Substring(0, $splitAt)
        }

        $canonical = Get-PDUploaderCanonicalName -Name $optionName -Known (@($valueNames) + @($listNames) + @($switchNames) + @($booleanNames))
        if ($null -eq $canonical) {
            throw ("Unknown option '-{0}'. Known options: {1}" -f $optionName, ((@($valueNames) + @($listNames) + @($switchNames) + @($booleanNames) | Sort-Object) -join ', '))
        }

        $needsValue = ((@($valueNames) -ccontains $canonical) -or (@($listNames) -ccontains $canonical))

        if ($needsValue -and ($null -eq $inline)) {
            $index++
            if ($index -ge @($RawArguments).Count) {
                throw ("-{0} requires a value." -f $canonical)
            }
            $inline = [string]$RawArguments[$index]
        }

        if (@($valueNames) -ccontains $canonical) {
            $parsed[$canonical] = $inline
        } elseif (@($listNames) -ccontains $canonical) {
            # Repeatable; preflight splits each member on semicolons anyway.
            $lists[$canonical] += $inline
        } elseif (@($switchNames) -ccontains $canonical) {
            if ($null -eq $inline) {
                $parsed[$canonical] = [switch]::Present
            } else {
                $parsed[$canonical] = [bool](Test-PDUploaderTruthy -Text $inline -OptionName $canonical)
            }
        } else {
            if ($null -eq $inline) {
                $index++
                if ($index -ge @($RawArguments).Count) {
                    throw ("-{0} requires a value (true or false)." -f $canonical)
                }
                $inline = [string]$RawArguments[$index]
            }
            $parsed[$canonical] = [bool](Test-PDUploaderTruthy -Text $inline -OptionName $canonical)
        }

        $index++
    }

    foreach ($name in $listNames) {
        if (@($lists[$name]).Count -gt 0) { $parsed[$name] = @($lists[$name]) }
    }

    return $parsed
}

# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------

$script:PDGraphHelpersLoaded = $false

# The library has to be dot-sourced HERE, at script scope. Dot-sourcing it inside a function puts
# the definitions in that function's local scope, and they vanish when it returns - which fails
# in the strangest possible way: "run as a script" cannot see Stop-PDGraphError, while "dot-sourced
# by a caller that already loaded the library" works fine. If the caller already loaded it, nothing
# happens here, and that is also how a caller supplies a different library file: load yours first.
if (Get-Command -Name 'Stop-PDGraphError' -CommandType Function -ErrorAction SilentlyContinue) {
    $script:PDGraphHelpersLoaded = $true
} else {
    $script:PDHelperLibraryPath = $null

    $script:PDHelperScriptDirectory = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($script:PDHelperScriptDirectory)) {
        $script:PDHelperScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    if ([string]::IsNullOrWhiteSpace($script:PDHelperScriptDirectory)) {
        $script:PDHelperScriptDirectory = (Get-Location).Path
    }

    foreach ($script:PDHelperCandidate in @(
            (Join-Path (Split-Path $script:PDHelperScriptDirectory -Parent) 'Other_Tools\InTune-GraphAPI_Helpers.ps1'),
            (Join-Path $script:PDHelperScriptDirectory 'InTune-GraphAPI_Helpers.ps1'))) {
        if (Test-Path -LiteralPath $script:PDHelperCandidate) {
            $script:PDHelperLibraryPath = $script:PDHelperCandidate
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace($script:PDHelperLibraryPath)) {
        throw "The Graph helper library (Other_Tools\\InTune-GraphAPI_Helpers.ps1) was not found next to Upload-InTuneWin32App.ps1; the repository may be incomplete."
    }

    . $script:PDHelperLibraryPath
    $script:PDGraphHelpersLoaded = $true

    if (-not (Get-Command -Name 'Stop-PDGraphError' -CommandType Function -ErrorAction SilentlyContinue)) {
        throw "The Graph helper library at '$script:PDHelperLibraryPath' loaded without defining its entry points; it may be truncated or from a different version."
    }
}

function Initialize-PDUploaderHelpers {
    <#
        .SYNOPSIS
        Confirms the helper library is loaded, and says so plainly when it is not.
        Idempotent, so every entry point can call it.
    #>
    if ($script:PDGraphHelpersLoaded -and
        (Get-Command -Name 'Stop-PDGraphError' -CommandType Function -ErrorAction SilentlyContinue)) {
        return
    }

    throw 'The Graph helper library is not loaded. Dot-source Other_Tools\InTune-GraphAPI_Helpers.ps1 first, or run Upload-InTuneWin32App.ps1 from inside the repository it ships with.'
}

# ---------------------------------------------------------------------------
# Logger (owned by this script; the helper library never defines a logger)
# ---------------------------------------------------------------------------

$script:PDUploadLogPath = $null

function Write-PDUploadLog {
    <#
        .SYNOPSIS
        Appends one timestamped line to this run's uploader log. Never throws and writes nothing
        when no log path was established (a dot-sourced library call stays silent).

        .DESCRIPTION
        Uses the repo's Logs\Other_Logs convention and the same retrying atomic append as
        Convert-VendorPack-ToDriverZip.ps1, because an AV/EDR file lock must not spam the console
        or kill a publish. Messages are already sanitized by the caller; commands, tokens, SAS
        URIs, and package encryption material are never passed here.
    #>
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )

    if ([string]::IsNullOrWhiteSpace($script:PDUploadLogPath)) { return }

    $entry = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, [string]$Message

    try {
        $logDir = Split-Path -Parent $script:PDUploadLogPath
        if (-not (Test-Path -LiteralPath $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force -ErrorAction Stop | Out-Null
        }

        for ($attempt = 1; $attempt -le 5; $attempt++) {
            try {
                [System.IO.File]::AppendAllText($script:PDUploadLogPath, $entry + [Environment]::NewLine, [System.Text.Encoding]::Default)
                break
            } catch {
                if ($attempt -ge 5) { break }
                Start-Sleep -Milliseconds 40
            }
        }
    } catch {
        # A log failure never changes the upload outcome, and never leaks the message content.
    }
}

# ---------------------------------------------------------------------------
# Result object (spec 9.1)
# ---------------------------------------------------------------------------

function New-PDIntuneUploadResult {
    <#
        .SYNOPSIS
        Builds the single result object with every documented field present.

        .DESCRIPTION
        Internal-only material is deliberately unreachable from here: no token, no credential,
        no install/uninstall command text, no package encryption fields, no bearer anything.
        Review fields are populated on a dry run and on execution, using null/empty for preflight
        steps that were never reached.
    #>
    param(
        [switch]$DryRun,
        [string]$Stage = 'Preflight',
        [switch]$Success,
        [AllowNull()][string]$Message,
        [AllowNull()][object]$AppId = $null,
        [AllowNull()][object]$PortalUrl = $null,
        [AllowNull()][object]$Preflight,
        [string]$CleanupStatus = 'NotNeeded',
        [AllowNull()][DateTimeOffset]$SecretExpiresOn = [DateTimeOffset]::MinValue,
        [AllowNull()][string]$NotesTimestampNote,
        # Content-upload storage renewals and waits for a new storage URI (0 when the upload never
        # reached that stage). Counts only: no SAS, no URI.
        [int]$StorageRenewals = 0,
        [int]$StorageAccessWaits = 0
    )

    $resolvedGroups  = @()
    $duplicateApps   = @()
    $categoryResult  = $null
    $reviewMetadata  = $null
    $commandLengths  = $null
    $inputHashes     = $null
    $warnings        = @()
    $expiresOn       = $null

    if ($null -ne $Preflight) {
        if ($Preflight.ContainsKey('ResolvedGroups'))  { $resolvedGroups = @($Preflight.ResolvedGroups) }
        if ($Preflight.ContainsKey('DuplicateApps'))   { $duplicateApps  = @($Preflight.DuplicateApps) }
        if ($Preflight.ContainsKey('CategoryResult'))  { $categoryResult = $Preflight.CategoryResult }
        if ($Preflight.ContainsKey('ReviewMetadata'))  { $reviewMetadata = $Preflight.ReviewMetadata }
        if ($Preflight.ContainsKey('CommandLengths'))  { $commandLengths = $Preflight.CommandLengths }
        if ($Preflight.ContainsKey('InputHashes'))     { $inputHashes    = $Preflight.InputHashes }
        if ($Preflight.ContainsKey('Warnings'))        { $warnings       = @($Preflight.Warnings) }
        if ($Preflight.ContainsKey('SecretExpiresOn') -and ($null -ne $Preflight.SecretExpiresOn)) {
            $expiresOn = $Preflight.SecretExpiresOn
        }
    }

    if ($SecretExpiresOn -ne [DateTimeOffset]::MinValue) { $expiresOn = $SecretExpiresOn }

    if ($null -ne $Preflight) {
        if ($null -ne $reviewMetadata) {
            # Dry run keeps the technical block and says plainly that the timestamp is added when
            # the create request is actually issued (spec 4.4).
            $reviewMetadata | Add-Member -NotePropertyName NotesTimestampNote -NotePropertyValue $NotesTimestampNote -Force
        }
    }

    return [pscustomobject]@{
        Success         = [bool]$Success
        DryRun          = [bool]$DryRun
        Stage           = $Stage
        AppId           = $AppId
        PortalUrl       = $PortalUrl
        ResolvedGroups  = $resolvedGroups
        DuplicateApps   = $duplicateApps
        SecretExpiresOn = $expiresOn
        ReviewMetadata  = $reviewMetadata
        CategoryResult  = $categoryResult
        CommandLengths  = $commandLengths
        Warnings        = $warnings
        CleanupStatus   = $CleanupStatus
        Message         = [string]$Message
        InputHashes     = $inputHashes
        StorageRenewals    = [int]$StorageRenewals
        StorageAccessWaits = [int]$StorageAccessWaits
    }
}

# ---------------------------------------------------------------------------
# Preflight (spec 9.2)
# ---------------------------------------------------------------------------

function Get-PDInstallationDefaultsReview {
    <#
        .SYNOPSIS
        The fixed installation settings this feature always sends (spec 4.5), as review data.
        Display only: the payload builder owns the real values.
    #>
    return [pscustomobject]@{
        InstallContext        = 'System'
        InstallTimeoutMinutes = 15
        RestartBehavior       = 'No specific action (Graph deviceRestartBehavior=allow)'
        DetectionMethod       = 'Generated PowerShell script, 64-bit, signature checking disabled'
        Architectures         = 'x64,x86'
        MinimumWindowsVersion = 'Windows 10 1607'
        ReturnCodes           = '0/1707 success; 3010 softReboot; 1641 hardReboot; 1618 retry'
    }
}

function Start-PDIntunePreflight {
    <#
        .SYNOPSIS
        Runs preflight in spec 9.2 order and returns the internal preflight hashtable.

        .DESCRIPTION
        Order matters and is not parallelised:
          1 required text and files, resolved to absolute paths
          2 command files read as single-line text (trailing CR/LF removed, nothing else)
          3 detection bytes base64-encoded without transcoding
          4 package inspection plus InputHashes
          5 credential, expiry, token, permission confirmation
          6 groups, duplicates, category (paginated, via Get-PDGraphItems)
          7 dry run returns here
          8 duplicate-name gate for execution

        Throws sanitized terminating errors (Get-PDGraphErrorInfo reads them back). Never writes
        to the tenant, never prompts, and never returns the credential or a token to the caller's
        result object - this hashtable is internal to the uploader.
    #>
    param(
        [string]$IntuneWinPath,
        [string]$DisplayName,
        [string]$Description,
        [string]$Publisher,
        [string]$InstallCommandFile,
        [string]$UninstallCommandFile,
        [string]$DetectionScriptFile,
        [string]$AppVersion,
        [string]$Category,
        [string]$Notes,
        [string[]]$RequiredGroups,
        [string[]]$AvailableGroups,
        [bool]$AllowAvailableUninstall = $false,
        [string]$CredentialPath,
        [switch]$DryRun,
        [switch]$AllowDuplicateName,
        [switch]$NoRollback,
        [string]$TempDirectory,
        # Optional PNG or JPEG shown as the app's icon. Cosmetic: a problem with it is a warning, never a failure.
        [string]$IconFile,
        # Optional Company Portal links (http/https). Cosmetic, like the icon.
        [string]$InformationUrl,
        [string]$PrivacyUrl,
        [string]$Stage = 'Preflight'
    )

    Initialize-PDUploaderHelpers

    $warnings = @()

    # --- 1. Required text and files -------------------------------------------------------
    $packagePath  = Get-PDGraphTrimmedText -Value $IntuneWinPath
    $name         = Get-PDGraphTrimmedText -Value $DisplayName
    $description  = $Description
    $publisher    = Get-PDGraphTrimmedText -Value $Publisher
    $installFile  = Get-PDGraphTrimmedText -Value $InstallCommandFile
    $uninstallFile = Get-PDGraphTrimmedText -Value $UninstallCommandFile
    $detectFile   = Get-PDGraphTrimmedText -Value $DetectionScriptFile

    if ([string]::IsNullOrWhiteSpace($packagePath))  { Stop-PDGraphError -Message 'IntuneWinPath is required.' -Stage $Stage }
    if ([string]::IsNullOrWhiteSpace($name))         { Stop-PDGraphError -Message 'DisplayName is required.' -Stage $Stage }
    if ($null -eq $description) { $description = '' }
    if ([string]::IsNullOrWhiteSpace($description))  { Stop-PDGraphError -Message 'Description is required. Use N/A when there is genuinely nothing to say.' -Stage $Stage }

    # Spec 4.1: an empty publisher means PowerDeploy, in both the guided and API paths.
    if ([string]::IsNullOrWhiteSpace($publisher)) { $publisher = 'PowerDeploy' }

    if ([string]::IsNullOrWhiteSpace($installFile))   { Stop-PDGraphError -Message 'InstallCommandFile is required.' -Stage $Stage }
    if ([string]::IsNullOrWhiteSpace($uninstallFile)) { Stop-PDGraphError -Message 'UninstallCommandFile is required.' -Stage $Stage }
    if ([string]::IsNullOrWhiteSpace($detectFile))    { Stop-PDGraphError -Message 'DetectionScriptFile is required.' -Stage $Stage }

    $sourcePackage = Get-PDResolvedFilePath -Path $packagePath -Stage $Stage -Label 'IntuneWin package'
    $installPath   = Get-PDResolvedFilePath -Path $installFile   -Stage $Stage -Label 'install command file'
    $uninstallPath = Get-PDResolvedFilePath -Path $uninstallFile -Stage $Stage -Label 'uninstall command file'
    $detectPath    = Get-PDResolvedFilePath -Path $detectFile    -Stage $Stage -Label 'detection script'

    # --- 2. Commands ----------------------------------------------------------------------
    # Nothing is truncated and no length limit is applied: the service maximum is not documented
    # (spec 14.3), and a silently shortened command installs nothing.
    $installCommand   = Get-PDCommandFileText -Path $installPath   -Stage $Stage -Label 'install command file'
    $uninstallCommand = Get-PDCommandFileText -Path $uninstallPath -Stage $Stage -Label 'uninstall command file'

    # --- 3. Detection ---------------------------------------------------------------------
    $detection = Get-PDDetectionScriptBase64 -Path $detectPath -Stage $Stage

    # --- 4. Package and input hashes ------------------------------------------------------
    $runTempDirectory = Get-PDGraphTrimmedText -Value $TempDirectory
    if ([string]::IsNullOrWhiteSpace($runTempDirectory)) {
        $runTempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('PowerDeploy-IntuneUpload-' + [guid]::NewGuid().ToString('N'))
    }

    $package = Read-PDIntuneWinPackage -IntuneWinPath $sourcePackage -TempDirectory $runTempDirectory -Stage $Stage

    $inputHashes = @{
        Package   = (Get-PDFileSha256 -Path $sourcePackage -Stage $Stage)
        Install   = (Get-PDFileSha256 -Path $installPath   -Stage $Stage)
        Uninstall = (Get-PDFileSha256 -Path $uninstallPath -Stage $Stage)
        Detection = $detection.Sha256
    }

    # --- 5. Credential, token, permissions ------------------------------------------------
    $credential = Get-PDGraphCredential -Path $CredentialPath
    foreach ($warning in @($credential.Warnings)) {
        if (-not [string]::IsNullOrWhiteSpace($warning)) { $warnings += $warning }
    }

    $authContext = @{ Credential = $credential }
    $token       = Get-PDGraphToken -Credential $credential

    $tokenRoles = @()
    try { $tokenRoles = @($token.Roles) } catch { }

    if ($tokenRoles.Count -gt 0) {
        $missingRoles = @()
        foreach ($role in @($script:PDGraph.RequiredAppRoles)) {
            $hit = $false
            foreach ($granted in $tokenRoles) {
                if (([string]$granted) -eq $role) { $hit = $true; break }
            }
            if (-not $hit) { $missingRoles += $role }
        }
        if ($missingRoles.Count -gt 0) {
            Stop-PDGraphError -Message ("The upload identity's token does not include {0}. Grant the missing application role(s) to the app registration in Entra, then retry. No tenant resource was touched." -f (($missingRoles | ForEach-Object { "'$_'" }) -join ', ')) -Stage 'Credential'
        }
    } else {
        $warnings += 'The token carried no readable application roles, so permissions could not be confirmed before writing. The first Graph call will report any missing permission.'
    }

    # --- 6. Groups, duplicates, category --------------------------------------------------
    $resolvedGroups = Resolve-PDGraphGroups -RequiredGroups $RequiredGroups -AvailableGroups $AvailableGroups -AuthContext $authContext -Stage $Stage
    $duplicateApps  = Find-PDIntuneDuplicateApps -DisplayName $name -AuthContext $authContext -Stage $Stage

    # An empty Category means "not requested": no lookup, no association, no warning (spec 4.5).
    $requestedCategory = Get-PDGraphTrimmedText -Value $Category -TreatNotApplicableAsMissing
    if ([string]::IsNullOrWhiteSpace($requestedCategory)) {
        $categoryResult = [pscustomobject]@{ RequestedName = ''; Id = $null; Status = 'NotRequested'; Warning = $null }
    } else {
        $categoryResult = Find-PDIntuneCategory -Category $requestedCategory -AuthContext $authContext -Stage $Stage
    }

    if ($null -ne $categoryResult) {
        if (-not [string]::IsNullOrWhiteSpace($categoryResult.Warning)) { $warnings += [string]$categoryResult.Warning }
    }

    # --- Review data ----------------------------------------------------------------------
    $technicalNotes = [string]$Notes
    if ($null -eq $technicalNotes) { $technicalNotes = '' }

    $displayVersion = Get-PDGraphTrimmedText -Value $AppVersion -TreatNotApplicableAsMissing

    # --- Icon (optional, cosmetic) ----------------------------------------------------------
    # A missing or invalid icon is a warning and the upload goes on without one: an icon must
    # never be the reason a printer or app is not published.
    $iconPath  = $null
    $iconMime  = $null
    $iconBytes = 0
    $iconRequested = Get-PDGraphTrimmedText -Value $IconFile
    if (-not [string]::IsNullOrWhiteSpace($iconRequested)) {
        try {
            $iconFull = (Resolve-Path -LiteralPath $iconRequested -ErrorAction Stop).ProviderPath
            $head = New-Object byte[] 8
            $iconStream = [System.IO.File]::OpenRead($iconFull)
            try { $read = $iconStream.Read($head, 0, 8); $iconBytes = [long]$iconStream.Length } finally { $iconStream.Dispose() }
            $pngSignature = [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
            $isPng  = ($read -eq 8) -and (@(Compare-Object $head $pngSignature -SyncWindow 0).Count -eq 0)
            $isJpeg = ($read -ge 3) -and ($head[0] -eq 0xFF) -and ($head[1] -eq 0xD8) -and ($head[2] -eq 0xFF)
            if ($isPng) {
                $iconPath = $iconFull; $iconMime = 'image/png'
            } elseif ($isJpeg) {
                $iconPath = $iconFull; $iconMime = 'image/jpeg'
            } else {
                $warnings += ("The icon '{0}' is not a PNG or JPEG file, so the app will be created without an icon." -f $iconRequested)
            }
        } catch {
            $warnings += ("The icon '{0}' could not be read, so the app will be created without an icon." -f $iconRequested)
        }
    }

    # --- Company Portal links (optional, cosmetic) -----------------------------------------
    $links = @{}
    foreach ($link in @(@{ Name = 'Information URL'; Key = 'informationUrl'; Value = $InformationUrl }, @{ Name = 'Privacy URL'; Key = 'privacyInformationUrl'; Value = $PrivacyUrl })) {
        $text = Get-PDGraphTrimmedText -Value ([string]$link.Value) -TreatNotApplicableAsMissing
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        $parsedLink = $null
        if ([System.Uri]::TryCreate($text, [System.UriKind]::Absolute, [ref]$parsedLink) -and (($parsedLink.Scheme -eq 'https') -or ($parsedLink.Scheme -eq 'http'))) {
            $links[[string]$link.Key] = $text
        } else {
            $warnings += ("The {0} '{1}' is not an http(s) link, so it was left out." -f $link.Name, $text)
        }
    }

    $reviewMetadata = [pscustomobject]@{
        DisplayName             = $name
        Description             = $description
        Publisher               = $publisher
        AppVersion              = $displayVersion
        Notes                   = $technicalNotes
        AllowAvailableUninstall = [bool]$AllowAvailableUninstall
        PackageFileName         = $package.FileName
        SetupFilePath           = $package.SetupFile
        PackageUnencryptedBytes = $package.UnencryptedContentSize
        PackageEncryptedBytes   = $package.PayloadBytes
        PackageToolVersion      = $package.ToolVersion
        DetectionBytes          = $detection.Bytes
        IconFile                = $(if ($null -ne $iconPath) { Split-Path -Leaf $iconPath } else { $null })
        InformationUrl          = $links['informationUrl']
        PrivacyUrl              = $links['privacyInformationUrl']
        InstallationDefaults    = (Get-PDInstallationDefaultsReview)
        GroupAssignmentSummary  = $(if (@($resolvedGroups).Count -eq 0) { 'No assignments' } else { ('{0} assignment(s)' -f @($resolvedGroups).Count) })
    }

    $preflight = @{
        Stage                    = $Stage
        Warnings                 = $warnings
        IntuneWinPath            = $sourcePackage
        InstallCommandPath       = $installPath
        UninstallCommandPath     = $uninstallPath
        DetectionScriptPath      = $detectPath
        InstallCommand           = $installCommand
        UninstallCommand         = $uninstallCommand
        CommandLengths           = @{ Install = $installCommand.Length; Uninstall = $uninstallCommand.Length }
        Detection                = $detection
        Package                  = $package
        InputHashes              = $inputHashes
        Credential               = $credential
        CredentialPath           = [string]$credential.Path
        SecretExpiresOn          = $credential.SecretExpiresOn
        AuthContext              = $authContext
        ResolvedGroups           = @($resolvedGroups)
        DuplicateApps            = @($duplicateApps)
        CategoryResult           = $categoryResult
        ReviewMetadata           = $reviewMetadata
        TechnicalNotes           = $technicalNotes
        Publisher                = $publisher
        DisplayNameValue         = $name
        DescriptionValue         = $description
        AppVersionValue          = $displayVersion
        AllowAvailableUninstall  = [bool]$AllowAvailableUninstall
        TempDirectory            = $package.TempDirectory
        TempDirectoryOwned       = $package.TempDirectoryOwned
        NoRollback               = [bool]$NoRollback
        AllowDuplicateName       = [bool]$AllowDuplicateName
        IconPath                 = $iconPath
        IconMime                 = $iconMime
        Links                    = $links
    }

    # --- 7. A dry run stops here ----------------------------------------------------------
    if ($DryRun) {
        Write-PDUploadLog -Message ("Preflight complete (dry run). Package '{0}', {1} group assignment(s), category {2}, {3} duplicate name(s). No tenant writes." -f $package.FileName, @($resolvedGroups).Count, $categoryResult.Status, @($duplicateApps).Count) -Level 'DRYRUN'
        return $preflight
    }

    # --- 8. Duplicate names block execution unless explicitly accepted --------------------
    if (@($duplicateApps).Count -gt 0) {
        if (-not $AllowDuplicateName) {
            $listed = (@($duplicateApps) | ForEach-Object { '{0} ({1})' -f $_.DisplayName, $_.Id }) -join '; '
            Stop-PDGraphError -Message ("{0} Intune app(s) already have the display name '{1}': {2}. Nothing was created. Confirm with the operator, then re-run with -AllowDuplicateName to create another app with the same name." -f @($duplicateApps).Count, $name, $listed) -Stage $Stage
        }
    }

    return $preflight
}

# ---------------------------------------------------------------------------
# Write stages (M4): the spec 10.3 sequence with spec 11.2 rollback
# ---------------------------------------------------------------------------

function New-PDIntuneAppPath {
    <#
        .SYNOPSIS
        Builds a relative Graph path under one app: /beta/.../mobileApps/{id}<suffix>.
        The id is escaped here so no caller can paste one into a URL unescaped.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$AppId,
        [AllowEmptyString()][string]$Suffix = ''
    )

    $id = ([string]$AppId).Trim()
    if ([string]::IsNullOrWhiteSpace($id)) {
        Stop-PDGraphError -Message 'An Intune app id is required to address that app.' -Stage 'CreateApp'
    }

    return ('{0}/{1}{2}' -f [string]$script:PDGraph.MobileAppsPath, [System.Uri]::EscapeDataString($id), [string]$Suffix)
}

function New-PDIntuneContentPath {
    <#
        .SYNOPSIS
        The content path of one file of one content version (spec 10.3's V and file URLs).
        -VersionId/-FileId may be empty to address the collection instead of a single item.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$AppId,
        [AllowEmptyString()][string]$VersionId = '',
        [AllowEmptyString()][string]$FileId = '',
        [AllowEmptyString()][string]$Suffix = ''
    )

    $path = New-PDIntuneAppPath -AppId $AppId -Suffix ('/' + [string]$script:PDGraph.Win32AppCast + '/contentVersions')

    if (-not [string]::IsNullOrWhiteSpace($VersionId)) {
        $path += '/' + [System.Uri]::EscapeDataString(([string]$VersionId).Trim())
        $path += '/files'

        if (-not [string]::IsNullOrWhiteSpace($FileId)) {
            $path += '/' + [System.Uri]::EscapeDataString(([string]$FileId).Trim())
        }
    }

    return ($path + [string]$Suffix)
}

function Get-PDIntuneReturnCodeSignature {
    <#
        .SYNOPSIS
        A return-code collection as one order-independent string, so a read-back comparison
        is about the codes and their types and not about the order the service chose.
    #>
    param([AllowNull()][object]$ReturnCodes)

    $parts = @()
    foreach ($code in (Get-PDGraphItems -Payload $ReturnCodes)) {
        if ($null -eq $code) { continue }
        $value  = Get-PDIntuneReadBackValue -Object $code -Path 'returnCode'
        $type   = Get-PDIntuneReadBackValue -Object $code -Path 'type'
        $parts += ('{0}={1}' -f ([string]$value), ([string]$type))
    }

    return ((@($parts) | Sort-Object -Unique) -join ';')
}

function Get-PDIntuneAppReadBackActual {
    <#
        .SYNOPSIS
        Flattens the read-back app into the field names the expectation map uses.

        .DESCRIPTION
        Two things happen here that a raw property copy cannot do: the detection rule is found
        inside the rules collection (the service may return more than one rule), and the return
        codes are reduced to an order-independent signature. Both keep "did the service store
        what we sent?" answerable without depending on collection order.
    #>
    param([AllowNull()][object]$App)

    $detection = $null
    foreach ($rule in (Get-PDGraphItems -Payload (Get-PDIntuneReadBackValue -Object $App -Path 'rules'))) {
        if ($null -eq $rule) { continue }
        if ((([string](Get-PDIntuneReadBackValue -Object $rule -Path 'ruleType')).Trim() -ieq 'detection')) {
            $detection = $rule
            break
        }
    }

    $minimumOs = Get-PDIntuneReadBackValue -Object $App -Path 'minimumSupportedOperatingSystem'

    $actual = @{}
    $actual['displayName']           = Get-PDIntuneReadBackValue -Object $App -Path 'displayName'
    $actual['description']           = Get-PDIntuneReadBackValue -Object $App -Path 'description'
    $actual['publisher']             = Get-PDIntuneReadBackValue -Object $App -Path 'publisher'
    $actual['notes']                 = Get-PDIntuneReadBackValue -Object $App -Path 'notes'
    $actual['displayVersion']        = Get-PDIntuneReadBackValue -Object $App -Path 'displayVersion'
    $actual['fileName']              = Get-PDIntuneReadBackValue -Object $App -Path 'fileName'
    $actual['setupFilePath']         = Get-PDIntuneReadBackValue -Object $App -Path 'setupFilePath'
    $actual['installCommandLine']    = Get-PDIntuneReadBackValue -Object $App -Path 'installCommandLine'
    $actual['uninstallCommandLine']  = Get-PDIntuneReadBackValue -Object $App -Path 'uninstallCommandLine'
    $actual['applicableArchitectures'] = Get-PDIntuneReadBackValue -Object $App -Path 'applicableArchitectures'
    $actual['allowAvailableUninstall'] = Get-PDIntuneReadBackValue -Object $App -Path 'allowAvailableUninstall'
    $actual['runAsAccount']          = Get-PDIntuneReadBackValue -Object $App -Path 'installExperience/runAsAccount'
    $actual['maxRunTimeInMinutes']   = Get-PDIntuneReadBackValue -Object $App -Path 'installExperience/maxRunTimeInMinutes'
    $actual['deviceRestartBehavior'] = Get-PDIntuneReadBackValue -Object $App -Path 'installExperience/deviceRestartBehavior'
    $actual['minimumOsV10_1607']     = Get-PDGraphPropertyValue -Object $minimumOs -Name 'v10_1607'
    $actual['committedContentVersion'] = Get-PDIntuneReadBackValue -Object $App -Path 'committedContentVersion'
    $actual['publishingState']       = Get-PDIntuneReadBackValue -Object $App -Path 'publishingState'
    $actual['detectionScript']       = Get-PDIntuneReadBackValue -Object $detection -Path 'scriptContent'
    $actual['detectionRunAs32Bit']   = Get-PDIntuneReadBackValue -Object $detection -Path 'runAs32Bit'
    $actual['detectionEnforceSignatureCheck'] = Get-PDIntuneReadBackValue -Object $detection -Path 'enforceSignatureCheck'
    $actual['returnCodes']           = Get-PDIntuneReturnCodeSignature -ReturnCodes (Get-PDIntuneReadBackValue -Object $App -Path 'returnCodes')

    return $actual
}
function Get-PDIntuneAppReadBackExpectation {
    <#
        .SYNOPSIS
        The field-by-field expectation for spec 10.4's read-back, built from the payload that
        was actually submitted.

        .DESCRIPTION
        One table, read top to bottom, is the whole read-back contract: label, Graph field,
        submitted value. Install/uninstall commands and the detection script are marked Secret
        because those fields can carry repository credentials, so Compare-PDIntuneAppReadBack
        reports lengths only when one of them disagrees.

        An expectation with no value is skipped rather than compared, so an optional field that
        was never sent (displayVersion) can never fail the check.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Payload,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$FinalNotes,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$VersionId
    )

    $experience = $Payload['installExperience']
    $minimumOs  = $Payload['minimumSupportedOperatingSystem']
    $rules      = @($Payload['rules'])
    $detection  = $null
    if ($rules.Count -gt 0) { $detection = $rules[0] }
    if ($null -eq $detection) { $detection = @{} }

    $fields = @(
        @{ Label = 'Display name';               Path = 'displayName';             Value = $Payload['displayName'] }
        @{ Label = 'Description';                Path = 'description';             Value = $Payload['description'] }
        @{ Label = 'Publisher';                  Path = 'publisher';               Value = $Payload['publisher'] }
        @{ Label = 'Notes';                      Path = 'notes';                   Value = $FinalNotes }
        @{ Label = 'Version';                    Path = 'displayVersion';          Value = $Payload['displayVersion'] }
        @{ Label = 'Package file name';          Path = 'fileName';                Value = $Payload['fileName'] }
        @{ Label = 'Setup file path';            Path = 'setupFilePath';           Value = $Payload['setupFilePath'] }
        @{ Label = 'Install command';            Path = 'installCommandLine';      Value = $Payload['installCommandLine']; Secret = $true }
        @{ Label = 'Uninstall command';          Path = 'uninstallCommandLine';    Value = $Payload['uninstallCommandLine']; Secret = $true }
        @{ Label = 'Architectures';              Path = 'applicableArchitectures'; Value = $Payload['applicableArchitectures']; Set = $true }
        @{ Label = 'Allow available uninstall';  Path = 'allowAvailableUninstall'; Value = [bool]$Payload['allowAvailableUninstall'] }
        @{ Label = 'Install context';            Path = 'runAsAccount';            Value = $(if ($null -ne $experience) { $experience['runAsAccount'] } else { $null }) }
        @{ Label = 'Install timeout (minutes)';  Path = 'maxRunTimeInMinutes';     Value = $(if ($null -ne $experience) { [long]$experience['maxRunTimeInMinutes'] } else { $null }) }
        @{ Label = 'Restart behaviour';          Path = 'deviceRestartBehavior';   Value = $(if ($null -ne $experience) { $experience['deviceRestartBehavior'] } else { $null }) }
        @{ Label = 'Minimum Windows 10 1607';    Path = 'minimumOsV10_1607';       Value = $(if ($null -ne $minimumOs) { [bool]$minimumOs['v10_1607'] } else { $null }) }
        @{ Label = 'Detection script';           Path = 'detectionScript';         Value = [string]$detection['scriptContent']; Secret = $true }
        @{ Label = 'Detection runs as 32-bit';   Path = 'detectionRunAs32Bit';     Value = [bool]$detection['runAs32Bit'] }
        @{ Label = 'Detection signature check';  Path = 'detectionEnforceSignatureCheck'; Value = [bool]$detection['enforceSignatureCheck'] }
        @{ Label = 'Return codes';               Path = 'returnCodes';             Value = (Get-PDIntuneReturnCodeSignature -ReturnCodes $Payload['returnCodes']) }
        @{ Label = 'Committed content version';  Path = 'committedContentVersion'; Value = $VersionId }
        @{ Label = 'Publishing state';           Path = 'publishingState';         Value = 'published' }
    )

    $expected = [ordered]@{}
    foreach ($field in $fields) {
        $value = $field['Value']
        if ($null -eq $value) { continue }
        if (($value -is [string]) -and [string]::IsNullOrWhiteSpace($value)) { continue }
        $expected[[string]$field['Label']] = @{
            Path   = [string]$field['Path']
            Value  = $value
            Secret = [bool]$field['Secret']
            Set    = [bool]$field['Set']
        }
    }

    return $expected
}


function Invoke-PDIntuneUploadWriteStages {
    <#
        .SYNOPSIS
        Runs the spec 10.3 write sequence and, on failure, the spec 11.2 rollback.

        .DESCRIPTION
        Order is the sequence, not a suggestion: create app -> content version -> file record ->
        storage URI -> block upload + block list -> commit -> publish (wait for 'published') ->
        category -> assignments -> verify. Assignments come near the end because they are the
        point of no return: an app that is published but not assigned can be fixed by a person,
        while an assignment that fired while the content was wrong has already installed
        something on a device.

        Rules this function exists to keep:
          - The app id is recorded only from a confirmed create response, or from an exact
            reconciliation of a lost response. Rollback deletes that id and never searches
            by display name (spec 11.2).
          - A lost create is never blindly repeated.
          - Storage requests carry no Graph bearer (Invoke-PDStorageRequest makes that
            structural), and a SAS never appears in a message (Remove-PDSecretQueryString).
          - Terminal service states fail immediately; pending states are waited for inside a
            bounded deadline; nothing is ever assumed complete.
          - Success requires the read-back to agree (spec 10.4), so a completed POST or a
            completed byte upload is never reported as a published app.
          - A rollback failure keeps the original error as the reported failure, and the
            surviving app id is surfaced with the portal link.

        .OUTPUTS
        @{ Success; Stage; Message; AppId; PortalUrl; CleanupStatus; Warnings; DurationSec }
        This is internal uploader state; New-PDIntuneUploadResult is still the only way anything
        becomes a public object.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Preflight,
        [Parameter(Mandatory = $true)][hashtable]$Payload,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$FinalNotes,
        [switch]$NoRollback
    )

    Initialize-PDUploaderHelpers

    $auth      = $Preflight.AuthContext
    $package   = $Preflight.Package
    $warnings  = @()
    $started   = [DateTime]::UtcNow
    $appId     = $null
    $cleanup   = 'NotNeeded'
    $stage     = 'CreateApp'
    $failure   = $null
    # Storage renewals and waits, returned in the result: a dot-sourced caller (Setup, the bulk
    # tools) keeps no uploader log, so this is the only place they can see them. Renewals are
    # counted as they are requested, so a renewal that then fails is still counted.
    $storageStats = @{ Renewals = 0; AccessWaits = 0 }

    $appDisplayName = [string]$Preflight.DisplayNameValue
    $knownAppIds    = @{}
    foreach ($dupe in @($Preflight.DuplicateApps)) {
        $knownId = [string](Get-PDGraphPropertyValue -Object $dupe -Name 'Id')
        if ([string]::IsNullOrWhiteSpace($knownId)) { continue }
        $knownAppIds[$knownId.ToLowerInvariant()] = $true
    }

    function Get-PDIntuneUploadResult {
        param(
            [switch]$Succeeded,
            [string]$StageName,
            [string]$Text,
            [string]$AppId = '',
            [string]$Cleanup = 'NotNeeded',
            [object[]]$ExtraWarnings = $null
        )

        $allWarnings = @($warnings)
        foreach ($extra in @($ExtraWarnings)) {
            if (-not [string]::IsNullOrWhiteSpace($extra)) { $allWarnings += [string]$extra }
        }

        return @{
            Success     = [bool]$Succeeded
            Stage       = $StageName
            Message     = [string]$Text
            AppId       = $AppId
            PortalUrl   = $(if ([string]::IsNullOrWhiteSpace($AppId)) { $null } else { [string]$script:PDGraph.PortalAppsUrl })
            CleanupStatus = $Cleanup
            Warnings    = @($allWarnings)
            DurationSec = [int]([DateTime]::UtcNow - $started).TotalSeconds
            StorageRenewals    = [int]$storageStats.Renewals
            StorageAccessWaits = [int]$storageStats.AccessWaits
        }
    }

    try {
        # --- 1. Create the app ------------------------------------------------------------
        Write-PDUploadLog -Message ("Submitting the app '{0}' ({1} content file(s))." -f $appDisplayName, [string]$package.FileName)

        $created = $null
        try {
            $created = Invoke-PDGraphRequest -Method Post -Uri ([string]$script:PDGraph.MobileAppsPath) `
                                            -Body $Payload -AuthContext $auth -RetryMode 'Write' `
                                            -Stage 'CreateApp' -Description 'create the Win32 app'
        } catch {
            # A lost create response is not a licence to POST again: spec 11.1 says report the
            # unknown outcome unless it can be reconciled exactly.
            $info   = Get-PDGraphErrorInfo -ErrorRecord $_
            $lost   = ([bool]$info.Retryable) -or ($info.Status -eq 0) -or ($info.Status -ge 500)

            if (-not $lost) { throw }

            $reconciled = $null
            try {
                foreach ($app in @(Find-PDIntuneDuplicateApps -DisplayName $appDisplayName -AuthContext $auth -Stage 'CreateApp')) {
                    $candidateId = [string](Get-PDGraphPropertyValue -Object $app -Name 'Id')
                    if ([string]::IsNullOrWhiteSpace($candidateId)) { continue }
                    if ($knownAppIds.ContainsKey($candidateId.ToLowerInvariant())) { continue }
                    if ($null -eq $reconciled) { $reconciled = $candidateId } else { $reconciled = $null; break }
                }
            } catch {
                $reconciled = $null
            }

            if ([string]::IsNullOrWhiteSpace($reconciled)) {
                $cleanup = 'Unknown'
                $failure = $info
                throw
            }

            # Exactly one app now carries this display name and it was not there before the
            # attempt: that is the app the lost response created.
            $appId = $reconciled
            $warnings += ("The create request did not produce a response, so it was reconciled: app '{0}' is the only app with that display name and it did not exist before the attempt. The upload continued with that id." -f $appId)
            Write-PDUploadLog -Message ("Create response lost; reconciled to app id {0}." -f $appId) -Level 'WARNING'
        }

        if ([string]::IsNullOrWhiteSpace($appId)) {
            $appId = [string](Get-PDGraphPropertyValue -Object $created -Name 'id')
        }
        if ([string]::IsNullOrWhiteSpace($appId)) {
            $cleanup = 'Unknown'
            Stop-PDGraphError -Message 'Microsoft Graph accepted the new app but returned no id, so nothing could be uploaded to it and nothing can be cleaned up automatically. Inspect Intune for an app named before retrying.' -Stage 'CreateApp' -Detail 'NoAppId'
        }

        $appPath = New-PDIntuneAppPath -AppId $appId
        Write-PDUploadLog -Message ("App created (id {0}); uploading content." -f $appId)

        # --- 2. Content version ---------------------------------------------------------
        $stage = 'ContentVersion'
        $versionResponse = Invoke-PDGraphRequest -Method Post `
                                                -Uri (New-PDIntuneContentPath -AppId $appId) `
                                                -Body @{} -AuthContext $auth -RetryMode 'Write' `
                                                -Stage $stage -Description 'create the content version'

        $versionId = [string](Get-PDGraphPropertyValue -Object $versionResponse -Name 'id')
        if ([string]::IsNullOrWhiteSpace($versionId)) {
            Stop-PDGraphError -Message 'Intune created a content version but returned no version id. The next version is never guessed.' -Stage $stage
        }

        # --- 3. File record -------------------------------------------------------------
        $fileResponse = Invoke-PDGraphRequest -Method Post `
                                             -Uri (New-PDIntuneContentPath -AppId $appId -VersionId $versionId) `
                                             -Body (New-PDIntuneContentFilePayload -Package $package -Stage $stage) `
                                             -AuthContext $auth -RetryMode 'Write' `
                                             -Stage $stage -Description 'create the content file record'

        $fileId = [string](Get-PDGraphPropertyValue -Object $fileResponse -Name 'id')
        if ([string]::IsNullOrWhiteSpace($fileId)) {
            Stop-PDGraphError -Message 'Intune created the content file record but returned no file id, so there is nothing to upload against.' -Stage $stage
        }

        $fileUri = New-PDIntuneContentPath -AppId $appId -VersionId $versionId -FileId $fileId

        # --- 4. Storage URI -------------------------------------------------------------
        $stage = 'StorageUri'

        $getFreshTarget = {
            param($Info)

            $reason = 'before the upload could finish'
            if (($null -ne $Info) -and (([string]$Info['Reason']) -eq 'rejected')) {
                $reason = ('because the storage endpoint refused a block with HTTP ' + [string]$Info['Status'])
                if (-not [string]::IsNullOrWhiteSpace([string]$Info['Detail'])) { $reason += (' [' + [string]$Info['Detail'] + ']') }
                if ([int]$Info['Waits'] -gt 0) { $reason += (' after ' + [string]$Info['Waits'] + ' wait(s) for it to start accepting blocks') }
            }
            # Which trigger fired, and the SAS window it fired on (never the signature): the
            # 2026-10-19 bulk runs renewed often and left no trace of why.
            $sasWindow = 'SAS window unknown'
            try { $sasWindow = Get-PDStorageSasSummary -Target $Info['Target'] } catch { }
            Write-PDUploadLog -Message ("The content file storage URI needs renewing {0}." -f $reason) -Level 'WARNING'
            Write-PDUploadLog -Message ("Storage URI being renewed: {0}." -f $sasWindow) -Level 'WARNING'
            $storageStats.Renewals = [int]$storageStats.Renewals + 1
            if (($null -ne $Info) -and ([int]$Info['Waits'] -gt [int]$storageStats.AccessWaits)) { $storageStats.AccessWaits = [int]$Info['Waits'] }

            # No request body: Microsoft documents renewUpload as "Do not supply a request body",
            # and the service rejects the body that used to be sent (see RenewUploadBody).
            $null = Invoke-PDGraphRequest -Method Post -Uri ($fileUri + '/' + [string]$script:PDGraph.RenewUploadAction) `
                                         -AuthContext $auth -RetryMode 'Write' `
                                         -Stage 'Upload' -Description 'renew the content file storage URI'

            $renewed = Wait-PDGraphCondition -Description 'the renewed storage URI to become available' -Stage 'Upload' -Test {
                $record = Invoke-PDGraphRequest -Method Get -Uri $fileUri -AuthContext $auth -RetryMode 'Read' `
                                               -Stage 'Upload' -Description 'content file record'
                switch (Get-PDIntuneContentFileState -File $record -Phase 'RenewUpload') {
                    'Success' { return $record }
                    # The service's own state and why renewal was asked for go into the message,
                    # because this message is all a dot-sourced caller (Setup, the bulk tools) keeps.
                    'Failed'  { Stop-PDGraphError -Message ("Intune reported a terminal failure (uploadState '{0}') while renewing the content file storage URI, so the upload stopped here. The renewal was needed {1}; {2}." -f `
                                    ([string](Get-PDGraphPropertyValue -Object $record -Name 'uploadState')), $reason, $sasWindow) -Stage 'Upload' }
                    'Absent'  { Stop-PDGraphError -Message 'The content file record disappeared while its storage URI was being renewed.' -Stage 'Upload' }
                }
                return $null
            }

            return (Get-PDStorageUploadTarget -AzureStorageUri ([string](Get-PDGraphPropertyValue -Object $renewed -Name 'azureStorageUri')) -Stage 'Upload')
        }

        $fileRecord = Wait-PDGraphCondition -Description 'the content file storage URI to become available' -Stage $stage -Test {
            $record = Invoke-PDGraphRequest -Method Get -Uri $fileUri -AuthContext $auth -RetryMode 'Read' `
                                           -Stage 'StorageUri' -Description 'content file record'
            switch (Get-PDIntuneContentFileState -File $record -Phase 'StorageUri') {
                'Success' { return $record }
                'Failed'  { Stop-PDGraphError -Message 'Intune reported a terminal failure while preparing the storage URI for the content file, so nothing was uploaded.' -Stage 'StorageUri' }
                'Absent'  { Stop-PDGraphError -Message 'The content file record disappeared before a storage URI was available for it.' -Stage 'StorageUri' }
            }
            return $null
        }

        $target = Get-PDStorageUploadTarget `
                    -AzureStorageUri ([string](Get-PDGraphPropertyValue -Object $fileRecord -Name 'azureStorageUri')) `
                    -Stage $stage
        try { Write-PDUploadLog -Message ("Storage URI ready: {0}." -f (Get-PDStorageSasSummary -Target $target)) } catch { }

        # --- 5. Upload ------------------------------------------------------------------
        $stage = 'Upload'
        $upload = Send-PDIntuneContentBlob -Target $target `
                                           -FilePath ([string]$package.PayloadPath) `
                                           -WhenExpiring $getFreshTarget -Stage $stage
        Write-PDUploadLog -Message ("Uploaded {0} block(s), {1} byte(s), {2} renewal(s), {3} wait(s) for a new storage URI to start accepting blocks." -f $upload.Blocks, $upload.Bytes, $upload.Renewals, [int]$upload.AccessWaits)
        $storageStats.Renewals    = [int]$upload.Renewals
        $storageStats.AccessWaits = [int]$upload.AccessWaits

        # --- 6. Commit ------------------------------------------------------------------
        $stage = 'Commit'
        $null = Invoke-PDGraphRequest -Method Post -Uri ($fileUri + '/' + [string]$script:PDGraph.CommitActionName) `
                                     -Body (New-PDIntuneCommitPayload -EncryptionInfo $package.EncryptionInfo -Stage $stage) `
                                     -AuthContext $auth -RetryMode 'Write' `
                                     -Stage $stage -Description 'commit the content file'

        $null = Wait-PDGraphCondition -Description 'the content file commit to succeed' -Stage $stage -Test {
            $record = Invoke-PDGraphRequest -Method Get -Uri $fileUri -AuthContext $auth -RetryMode 'Read' `
                                           -Stage 'Commit' -Description 'content file record'
            switch (Get-PDIntuneContentFileState -File $record -Phase 'Commit') {
                'Success' { return $record }
                'Failed'  { Stop-PDGraphError -Message 'Intune reported a terminal failure while committing the content file, so the app was not published.' -Stage 'Commit' }
                'Absent'  { Stop-PDGraphError -Message 'The content file record disappeared before the commit could be confirmed.' -Stage 'Commit' }
            }
            return $null
        }

        # --- 7. Publish the committed version -------------------------------------------
        $stage = 'Publish'
        $null = Invoke-PDGraphRequest -Method Patch -Uri $appPath `
                                     -Body @{ '@odata.type' = ('#' + $script:PDGraph.Win32AppCast); committedContentVersion = $versionId } `
                                     -AuthContext $auth -RetryMode 'Write' `
                                     -Stage $stage -Description ('publish content version ' + $versionId)

        $null = Wait-PDGraphCondition -Description 'the app to reach publishingState=published' -Stage $stage -Test {
            $app = Invoke-PDGraphRequest -Method Get -Uri $appPath -AuthContext $auth -RetryMode 'Read' `
                                        -Stage 'Publish' -Description 'app publishing state'
            $state = ([string](Get-PDGraphPropertyValue -Object $app -Name 'publishingState')).Trim().ToLowerInvariant()
            if ($state -eq 'published') { return $app }
            if (($state -eq 'failed') -or ($state -eq 'unknown')) {
                Stop-PDGraphError -Message ("Intune reported publishing state '{0}' for the new app, which is a terminal failure rather than a state to wait out." -f $state) -Stage 'Publish'
            }
            return $null
        }

        # --- 7a. Company Portal links (best effort) ------------------------------------------
        # Like the icon: after publishing, its own PATCH, a refusal is only a warning.
        $linkSet = $Preflight.Links
        if (($null -ne $linkSet) -and ($linkSet.Count -gt 0)) {
            try {
                $linkBody = @{ '@odata.type' = ('#' + $script:PDGraph.Win32AppCast) }
                foreach ($key in $linkSet.Keys) { $linkBody[$key] = [string]$linkSet[$key] }
                $null = Invoke-PDGraphRequest -Method Patch -Uri $appPath -Body $linkBody `
                                             -AuthContext $auth -RetryMode 'Write' `
                                             -Stage 'Links' -Description 'set the Company Portal links'
                Write-PDUploadLog -Message ("Set the Company Portal links: {0}." -f ((@($linkSet.Keys) | Sort-Object) -join ', ')) -Level 'INFO'
            } catch {
                $linkInfo = Get-PDGraphErrorInfo -ErrorRecord $_
                $warnings += ("The app was published, but its information/privacy links could not be set ({0}). Add them in the Intune portal if you want them." -f [string]$linkInfo.Message)
            }
        }

        # --- 7b. Icon (best effort) --------------------------------------------------------
        # Its own PATCH, after publishing: if Intune refuses the icon the app is still published
        # and assigned, and the operator gets a warning instead of a rollback.
        if (-not [string]::IsNullOrWhiteSpace([string]$Preflight.IconPath)) {
            try {
                $iconValue = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes([string]$Preflight.IconPath))
                $null = Invoke-PDGraphRequest -Method Patch -Uri $appPath `
                                             -Body @{
                                                 '@odata.type' = ('#' + $script:PDGraph.Win32AppCast)
                                                 largeIcon     = @{ '@odata.type' = '#microsoft.graph.mimeContent'; type = $(if ([string]$Preflight.IconMime) { [string]$Preflight.IconMime } else { 'image/png' }); value = $iconValue }
                                             } `
                                             -AuthContext $auth -RetryMode 'Write' `
                                             -Stage 'Icon' -Description 'set the app icon'
                Write-PDUploadLog -Message ("Set the app icon from {0}." -f (Split-Path -Leaf ([string]$Preflight.IconPath))) -Level 'INFO'
            } catch {
                $iconInfo = Get-PDGraphErrorInfo -ErrorRecord $_
                $warnings += ("The app was published, but its icon could not be set ({0}). Add it in the Intune portal if you want one." -f [string]$iconInfo.Message)
            }
        }

        # --- 8. Category (never created, only associated) -------------------------------
        $categoryId = $null
        if ($null -ne $Preflight.CategoryResult) {
            if (([string]$Preflight.CategoryResult.Status) -eq 'Resolved') {
                $stage = 'Category'
                $categoryId = [string]$Preflight.CategoryResult.Id
                $null = Invoke-PDGraphRequest -Method Post -Uri ($appPath + '/categories/$ref') `
                                             -Body (New-PDIntuneCategoryRefPayload -CategoryId $categoryId -Stage $stage) `
                                             -AuthContext $auth -RetryMode 'Write' `
                                             -Stage $stage -Description 'associate the existing category'
            } elseif (([string]$Preflight.CategoryResult.Status) -ne 'NotRequested') {
                # Only worth saying when a category was asked for and could not be used.
                $warnings += ("The category was not associated (status {0})." -f [string]$Preflight.CategoryResult.Status)
            }
        }

        # --- 9. Assignments, last before verification -----------------------------------
        $resolvedGroups = @($Preflight.ResolvedGroups)
        if (@($resolvedGroups).Count -gt 0) {
            $stage = 'Assign'
            $null = Invoke-PDGraphRequest -Method Post -Uri (New-PDIntuneAppPath -AppId $appId -Suffix ('/' + [string]$script:PDGraph.AssignActionName)) `
                                         -Body (New-PDIntuneAssignmentPayload -ResolvedGroups $resolvedGroups -Stage $stage) `
                                         -AuthContext $auth -RetryMode 'Write' `
                                         -Stage $stage -Description ('assign the app to ' + @($resolvedGroups).Count + ' group(s)')
        }

        # --- 10. Verify by read-back ----------------------------------------------------
        $stage = 'Verify'
        $readApp = Invoke-PDGraphRequest -Method Get -Uri $appPath -AuthContext $auth -RetryMode 'Read' `
                                        -Stage $stage -Description 'read back the published app'

        $problems = @()
        $problems += @(Compare-PDIntuneAppReadBack -Expected (Get-PDIntuneAppReadBackExpectation -Payload $Payload `
                                                                                              -FinalNotes $FinalNotes `
                                                                                              -VersionId $versionId) `
                                                -App (Get-PDIntuneAppReadBackActual -App $readApp))

        $actualAssignments = $null
        if (@($resolvedGroups).Count -gt 0) {
            $actualAssignments = Invoke-PDGraphRequest -Method Get -Uri (New-PDIntuneAppPath -AppId $appId -Suffix '/assignments') `
                                                     -AuthContext $auth -RetryMode 'Read' `
                                                     -Stage $stage -Description 'read back the assignments'
        }

        # The category links are read back whenever this run linked one. Comparison lives in
        # the helper so that a missing link, an extra link, and a duplicated link are all
        # differences rather than a success (spec 10.4).
        $categories = $null
        if (-not [string]::IsNullOrWhiteSpace($categoryId)) {
            $categories = Invoke-PDGraphRequest -Method Get -Uri (New-PDIntuneAppPath -AppId $appId -Suffix '/categories') `
                                              -AuthContext $auth -RetryMode 'Read' `
                                              -Stage $stage -Description 'read back the category links'
        }

        $problems += @(Compare-PDIntuneAssignmentSet -Expected $resolvedGroups -Assignments $actualAssignments `
                                                    -ExpectedCategoryIds @($categoryId) -Categories $categories)

        if (@($problems).Count -gt 0) {
            Stop-PDGraphError -Message ("Intune does not hold what was submitted: {0}. The upload is reported as a failure rather than a success." -f ((@($problems) | ForEach-Object { $_ }) -join ' ')) `
                              -Stage $stage -Detail 'ReadBackMismatch'
        }

        Write-PDUploadLog -Message ("Upload verified for app {0} (content version {1})." -f $appId, $versionId)

        return (Get-PDIntuneUploadResult -Succeeded -StageName 'Complete' `
                    -Text ("Published '{0}' to Intune (app id {1})." -f $appDisplayName, $appId) `
                    -AppId $appId -Cleanup 'NotNeeded')
    }
    catch {
        if ($null -eq $failure) { $failure = Get-PDGraphErrorInfo -ErrorRecord $_ }
        # An error raised by Stop-PDGraphError names its own stage; anything else (an unexpected
        # fault) is reported against the stage that was actually running.
        $errorStage = [string]$failure.Stage
        if ([string]::IsNullOrWhiteSpace($errorStage)) { $errorStage = $stage }

        $message = [string]$failure.Message
        if ([string]::IsNullOrWhiteSpace($message)) { $message = 'The upload failed for a reason the uploader could not describe.' }

        # --- Rollback (spec 11.2) -------------------------------------------------------
        # Deletion is right even when the failure came after the assignments POST: this run made
        # the app, it is not known-good, and an app that cannot be verified may already be
        # installing onto a device. The id deleted is only ever the recorded one.
        if ([string]::IsNullOrWhiteSpace($appId)) {
            # Nothing was confirmed as created. Either the create itself was never confirmed
            # (Unknown) or it was refused outright (nothing to clean).
            if ($cleanup -ne 'Unknown') { $cleanup = 'NotNeeded' }
            if ($cleanup -eq 'Unknown') {
                $message = ($message + ' The app may or may not exist in Intune: the create request produced no usable response and its outcome could not be established. Inspect Intune for an app named ' + $appDisplayName + ' before retrying.')
            }
            return (Get-PDIntuneUploadResult -StageName $errorStage -Text $message -Cleanup $cleanup)
        }

        if ($NoRollback -or [bool]$Preflight.NoRollback) {
            $cleanup = 'KeptByRequest'
            $message = ($message + (' An Intune app was created and kept as requested: {0} (see {1}).' -f $appId, [string]$script:PDGraph.PortalAppsUrl))
            return (Get-PDIntuneUploadResult -StageName $errorStage -Text $message -AppId $appId -Cleanup $cleanup)
        }

        try {
            $null = Invoke-PDGraphRequest -Method Delete -Uri (New-PDIntuneAppPath -AppId $appId) `
                                         -AuthContext $auth -RetryMode 'Write' `
                                         -Stage $errorStage -Description ('delete the incomplete app ' + $appId)
            $cleanup = 'Deleted'
            Write-PDUploadLog -Message ("Deleted the incomplete app {0}." -f $appId)
        } catch {
            $cleanup   = 'Failed'
            $deleteInfo = Get-PDGraphErrorInfo -ErrorRecord $_
            # The original failure stays the reported error; the cleanup problem is added to it.
            $message = ($message + (' Automatic removal of the incomplete app failed (' + [string]$deleteInfo.Message + '). It is still in Intune: ' + $appId + ' (see ' + [string]$script:PDGraph.PortalAppsUrl + ').'))
            Write-PDUploadLog -Message ("Cleanup failed for app {0}: {1}" -f $appId, $deleteInfo.Message) -Level 'ERROR'
        }

        return (Get-PDIntuneUploadResult -StageName $errorStage -Text $message -AppId $appId -Cleanup $cleanup)
    }
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

function Invoke-PDIntuneUpload {
    <#
        .SYNOPSIS
        One call, one result object, no throws, no prompts, no process exit.

        .DESCRIPTION
        Setup.ps1 calls this for both the dry run and the execution. Every operational failure is
        reported through the result object (Success=false plus Stage, Message, CleanupStatus) so
        the wizard can fall back to the guided walkthrough instead of dying.

        Temporary files are per-run and removed in finally; the temp directory is only deleted
        when this call created it.
    #>
    param(
        [string]$IntuneWinPath,
        [string]$DisplayName,
        [string]$Description,
        [string]$Publisher,
        [string]$InstallCommandFile,
        [string]$UninstallCommandFile,
        [string]$DetectionScriptFile,
        [string]$AppVersion,
        [string]$Category,
        [string]$Notes,
        [string[]]$RequiredGroups,
        [string[]]$AvailableGroups,
        [bool]$AllowAvailableUninstall = $false,
        [string]$CredentialPath,
        [switch]$DryRun,
        [switch]$AllowDuplicateName,
        [switch]$NoRollback,
        [string]$TempDirectory,
        # Optional PNG or JPEG shown as the app's icon. Cosmetic: a problem with it is a warning, never a failure.
        [string]$IconFile,
        # Optional Company Portal links (http/https). Cosmetic, like the icon.
        [string]$InformationUrl,
        [string]$PrivacyUrl
    )

    Initialize-PDUploaderHelpers

    $runTempDirectory = Get-PDGraphTrimmedText -Value $TempDirectory
    if ([string]::IsNullOrWhiteSpace($runTempDirectory)) {
        $runTempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('PowerDeploy-IntuneUpload-' + [guid]::NewGuid().ToString('N'))
    }

    # Ownership is decided BEFORE preflight: if preflight throws (a mistyped group, a refused
    # lookup) it never returns TempDirectoryOwned, and every failed dry run used to leave its
    # extracted payload behind in %TEMP% (found during the first live runs, 2026-10-12).
    $tempWasOurs   = -not (Test-Path -LiteralPath $runTempDirectory)
    $preflight     = $null
    $failureStage  = 'Preflight'
    $cleanupStatus = 'NotNeeded'
    $createdAppId  = $null

    try {
        $preflight = Start-PDIntunePreflight `
            -IntuneWinPath $IntuneWinPath `
            -DisplayName $DisplayName `
            -Description $Description `
            -Publisher $Publisher `
            -InstallCommandFile $InstallCommandFile `
            -UninstallCommandFile $UninstallCommandFile `
            -DetectionScriptFile $DetectionScriptFile `
            -AppVersion $AppVersion `
            -Category $Category `
            -Notes $Notes `
            -RequiredGroups $RequiredGroups `
            -AvailableGroups $AvailableGroups `
            -AllowAvailableUninstall $AllowAvailableUninstall `
            -CredentialPath $CredentialPath `
            -DryRun:$DryRun `
            -AllowDuplicateName:$AllowDuplicateName `
            -NoRollback:$NoRollback `
            -TempDirectory $runTempDirectory `
            -IconFile $IconFile `
            -InformationUrl $InformationUrl `
            -PrivacyUrl $PrivacyUrl

        if ($preflight.ContainsKey('TempDirectoryOwned')) { $tempWasOurs = ($tempWasOurs -or [bool]$preflight.TempDirectoryOwned) }

        if ($DryRun) {
            Write-PDUploadLog -Message 'Dry run finished; zero mutation calls were issued.' -Level 'DRYRUN'
            return (New-PDIntuneUploadResult -DryRun -Success -Stage 'Preflight' -Preflight $preflight `
                        -Message 'Preflight completed. No tenant resources were created or changed.' `
                        -NotesTimestampNote 'A single Created: timestamp is appended to Notes when the create request is issued.')
        }

        # Execution path. Preflight has run again immediately before writes, as spec 5.1 requires.
        $notesTimestamp = [System.DateTimeOffset]::UtcNow
        $finalNotes     = Complete-PDIntuneNotes -Notes $preflight.TechnicalNotes -CreatedAt $notesTimestamp
        $payload        = New-PDWin32AppPayload -DisplayName $preflight.DisplayNameValue `
                                                -Description $preflight.DescriptionValue `
                                                -Publisher $preflight.Publisher `
                                                -AppVersion $preflight.AppVersionValue `
                                                -InstallCommand $preflight.InstallCommand `
                                                -UninstallCommand $preflight.UninstallCommand `
                                                -DetectionBase64 $preflight.Detection.Base64 `
                                                -FinalNotes $finalNotes `
                                                -Package $preflight.Package `
                                                -AllowAvailableUninstall $preflight.AllowAvailableUninstall

        # One timestamp per create attempt: Notes are finalized here, immediately before the one
        # POST, and are never rebuilt by a retry because a lost POST is never repeated.
        Write-PDUploadLog -Message ("Create payload assembled ({0} keys)." -f $payload.Keys.Count)

        $upload = Invoke-PDIntuneUploadWriteStages -Preflight $preflight `
                                                   -Payload $payload `
                                                   -FinalNotes $finalNotes `
                                                   -NoRollback:$NoRollback

        $createdAppId = [string]$upload.AppId

        # Write-stage warnings (a reconciled create, a renewed SAS, an unassociated category)
        # belong to the same run, so they join the review warnings in the one result object.
        foreach ($writeWarning in @($upload.Warnings)) {
            if (-not [string]::IsNullOrWhiteSpace($writeWarning)) {
                $preflight.Warnings = @($preflight.Warnings) + [string]$writeWarning
            }
        }

        $resultArguments = @{
            DryRun        = [bool]$DryRun
            Stage         = [string]$upload.Stage
            Preflight     = $preflight
            CleanupStatus = [string]$upload.CleanupStatus
            Message       = [string]$upload.Message
            StorageRenewals    = [int]$upload.StorageRenewals
            StorageAccessWaits = [int]$upload.StorageAccessWaits
        }
        if ($upload.Success) { $resultArguments['Success'] = [switch]::Present }
        if (-not [string]::IsNullOrWhiteSpace($createdAppId)) { $resultArguments['AppId'] = $createdAppId }
        if (-not [string]::IsNullOrWhiteSpace([string]$upload.PortalUrl)) {
            $resultArguments['PortalUrl'] = [string]$upload.PortalUrl
        }

        Write-PDUploadLog -Message ("Upload finished (success: {0}, stage: {1}, cleanup: {2}, {3}s)." -f `
                    $upload.Success, $upload.Stage, $upload.CleanupStatus, $upload.DurationSec)

        return (New-PDIntuneUploadResult @resultArguments)
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        $failureStage = $info.Stage
        if ([string]::IsNullOrWhiteSpace($failureStage)) { $failureStage = 'Preflight' }

        Write-PDUploadLog -Message ("Failed at stage {0}: {1}" -f $failureStage, $info.Message) -Level 'ERROR'

        # The write stages own rollback and report their own outcome, so a throw reaching here is
        # either a preflight failure (nothing was created) or an unexpected fault after an id was
        # known, which is reported as Unknown rather than as a clean state (spec 11.2).
        if (-not [string]::IsNullOrWhiteSpace($createdAppId)) { $cleanupStatus = 'Unknown' } else { $cleanupStatus = 'NotNeeded' }

        return (New-PDIntuneUploadResult -Stage $failureStage -Preflight $preflight -CleanupStatus $cleanupStatus `
                    -Message $info.Message `
                    -DryRun:$DryRun)
    } finally {
        if ($tempWasOurs -and (-not [string]::IsNullOrWhiteSpace($runTempDirectory))) {
            if (Test-Path -LiteralPath $runTempDirectory) {
                Remove-Item -LiteralPath $runTempDirectory -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Console output (script execution only)
# ---------------------------------------------------------------------------

function Write-PDReviewSummary {
    <#
        .SYNOPSIS
        Prints the review block from a result object. Display only, and never prints commands,
        credentials, tokens, or package encryption values.
    #>
    param([Parameter(Mandatory = $true)][object]$Result)

    function Show-Line {
        param([string]$Label, [object]$Value)
        if ($null -eq $Value) { $Value = '' }
        Write-Host ("  {0,-26} {1}" -f ($Label + ':'), ([string]$Value))
    }

    if ($Result.DryRun) {
        Write-Host ''
        Write-Host 'Intune upload - review (no changes were made)' -ForegroundColor Cyan
    } else {
        Write-Host ''
        Write-Host 'Intune upload - result' -ForegroundColor Cyan
    }

    if ($null -ne $Result.ReviewMetadata) {
        $meta = $Result.ReviewMetadata
        Show-Line 'Display name'      $meta.DisplayName
        Show-Line 'Publisher'         $meta.Publisher
        Show-Line 'Version'           $(if ([string]::IsNullOrWhiteSpace($meta.AppVersion)) { 'N/A (displayVersion omitted)' } else { $meta.AppVersion })
        Show-Line 'Description'       $meta.Description
        Show-Line 'Package file'      $meta.PackageFileName
        Show-Line 'Setup file'        $meta.SetupFilePath
        Show-Line 'Payload bytes'     ("{0} (encrypted) / {1} (content)" -f $meta.PackageEncryptedBytes, $meta.PackageUnencryptedBytes)
        Show-Line 'Available uninstall' $meta.AllowAvailableUninstall
        Show-Line 'Assignments'       $meta.GroupAssignmentSummary

        if ($null -ne $meta.InstallationDefaults) {
            Show-Line 'Install context'  $meta.InstallationDefaults.InstallContext
            Show-Line 'Install timeout'  $meta.InstallationDefaults.InstallTimeoutMinutes
            Show-Line 'Restart'          $meta.InstallationDefaults.RestartBehavior
            Show-Line 'Detection'        $meta.InstallationDefaults.DetectionMethod
            Show-Line 'Architectures'    $meta.InstallationDefaults.Architectures
            Show-Line 'Minimum Windows'  $meta.InstallationDefaults.MinimumWindowsVersion
            Show-Line 'Return codes'     $meta.InstallationDefaults.ReturnCodes
        }

        if (-not [string]::IsNullOrWhiteSpace($meta.Notes)) {
            Write-Host '  Notes:'
            foreach ($line in ($meta.Notes -split "`r?`n")) { Write-Host ("    {0}" -f $line) }
        }
        if (-not [string]::IsNullOrWhiteSpace($meta.NotesTimestampNote)) {
            Show-Line 'Notes timestamp' $meta.NotesTimestampNote
        }
    }

    if ($null -ne $Result.CommandLengths) {
        Show-Line 'Install command length'   $Result.CommandLengths.Install
        Show-Line 'Uninstall command length' $Result.CommandLengths.Uninstall
    }

    if (@($Result.ResolvedGroups).Count -eq 0) {
        Show-Line 'Groups' 'No assignments'
    } else {
        Write-Host '  Groups:'
        foreach ($group in @($Result.ResolvedGroups)) {
            Write-Host ("    {0,-6} {1} ({2})" -f $group.Intent, $group.DisplayName, $group.Id)
        }
    }

    if ($null -ne $Result.CategoryResult) {
        Show-Line 'Category' ("{0} ({1})" -f $Result.CategoryResult.RequestedName, $Result.CategoryResult.Status)
    }

    if (@($Result.DuplicateApps).Count -gt 0) {
        Write-Host '  Existing apps with this display name:' -ForegroundColor Yellow
        foreach ($dupe in @($Result.DuplicateApps)) { Write-Host ("    {0} ({1})" -f $dupe.DisplayName, $dupe.Id) -ForegroundColor Yellow }
    }

    if ($null -ne $Result.SecretExpiresOn) {
        Show-Line 'Secret expires' $Result.SecretExpiresOn
    }

    foreach ($warning in @($Result.Warnings)) {
        if (-not [string]::IsNullOrWhiteSpace($warning)) { Write-Host ("  WARNING: {0}" -f $warning) -ForegroundColor Yellow }
    }

    if (-not [string]::IsNullOrWhiteSpace($Result.Message)) {
        Show-Line 'Message' $Result.Message
    }

    Show-Line 'Stage'  $Result.Stage
    Show-Line 'Result' $(if ($Result.Success) { 'success' } else { 'failed' })
    Show-Line 'Cleanup' $Result.CleanupStatus
    if (-not [string]::IsNullOrWhiteSpace($Result.AppId)) {
        Show-Line 'App id' $Result.AppId
        Show-Line 'Portal' $Result.PortalUrl
    }
}

# ---------------------------------------------------------------------------
# Script body (skipped when dot-sourced)
# ---------------------------------------------------------------------------

if (-not $script:PDUploaderDotSourced) {
    $runArguments = ConvertTo-PDUploaderRunArgument -RawArguments @($args)

    # Diagnostics overrides are consumed here and never passed on to the upload function.
    $logDirectory = $null
    if ($runArguments.ContainsKey('LogDirectory')) {
        $logDirectory = [string]$runArguments['LogDirectory']
        $runArguments.Remove('LogDirectory')
    }

    Initialize-PDUploaderHelpers

    if ([string]::IsNullOrWhiteSpace($logDirectory)) {
        $scriptDir = $PSScriptRoot
        if ([string]::IsNullOrWhiteSpace($scriptDir)) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
        if ([string]::IsNullOrWhiteSpace($scriptDir)) { $scriptDir = (Get-Location).Path }

        $repoRoot         = Split-Path $scriptDir -Parent
        $workingDirectory = Split-Path $repoRoot -Parent
        if (-not (Test-Path $workingDirectory)) { $workingDirectory = $repoRoot }

        $logDirectory = Join-Path $workingDirectory 'Logs\Other_Logs'
    }

    $script:PDUploadLogPath = Join-Path $logDirectory ('Upload-InTuneWin32App.ps1._Log_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')

    Write-PDUploadLog -Message ("Upload run started (dry run: {0}, options: {1})." -f [bool]$runArguments['DryRun'], (($runArguments.Keys | Sort-Object) -join ', '))

    $uploadResult = Invoke-PDIntuneUpload @runArguments

    Write-PDReviewSummary -Result $uploadResult
    Write-PDUploadLog -Message ("Upload run finished (success: {0}, stage: {1})." -f $uploadResult.Success, $uploadResult.Stage)

    # The object stays available to anything that captured this script's output.
    $uploadResult
}
