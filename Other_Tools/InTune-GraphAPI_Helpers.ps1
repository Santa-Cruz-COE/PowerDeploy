<#

.SYNOPSIS
    Microsoft Graph helper library for PowerDeploy's optional Intune upload path.

.DESCRIPTION
    DOT-SOURCE THIS FILE. It defines functions only.

    Importing this library performs no authentication, writes no files, emits no output, and
    never replaces a caller's Write-Log. It is safe to dot-source from Setup.ps1, from
    Upload-InTuneWin32App.ps1, or from a test harness.

    Provides:
      - Local credential storage for the "PowerDeploy Intune Upload" app identity
        (%LOCALAPPDATA%\PowerDeploy\GraphUpload\credential.clixml, DPAPI-protected SecureString)
      - Client-credentials token acquisition, cached in memory only, never on disk
      - One Graph REST entry point with retry, sanitized errors, Multi-Admin-Approval
        detection, and a hard refusal to send authorization to a non-Graph host
      - Pure formatters: Complete-PDIntuneNotes and Remove-UrlCredential

    Every network call this library makes flows through Invoke-PDGraphTransport. That is the
    documented test seam: set $PDGraph.TestTransport to a script block and the whole request
    stack becomes deterministic and offline. Keep any new network call behind it.

    Windows PowerShell 5.1 and PowerShell 7 compatible. Source is ASCII-only so that 5.1
    cannot misread it.

.LINK
    .claude/plans/intune-graph-upload.md - specification and security constraints

.NOTES
    Secrets leave this library only as (a) the SecureString inside a returned credential
    object and (b) the in-memory token object's AccessToken. They are never returned in upload
    results, never logged, and never written to the repository or the fleet registry key.
    Note that .NET strings are immutable: a plaintext secret that must briefly exist for a
    request body cannot be reliably erased from memory, so the discipline is to never log it,
    return it, or pass it onward.

#>

# ---------------------------------------------------------------------------
# Configuration (pure assignment; tests may override after dot-sourcing)
# ---------------------------------------------------------------------------

if (-not $script:PDGraph) {

    $script:PDGraph = @{

        # --- Endpoints (global cloud only; spec section 10) ---
        GraphBetaBase       = 'https://graph.microsoft.com/beta'
        GraphV1Base         = 'https://graph.microsoft.com/v1.0'
        TokenEndpointFormat = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token'
        GraphScope          = 'https://graph.microsoft.com/.default'
        GraphHost           = 'graph.microsoft.com'

        # --- Required application roles (spec 7.1) ---
        RequiredAppRoles  = @('DeviceManagementApps.ReadWrite.All', 'Group.Read.All')
        GraphServiceAppId = '00000003-0000-0000-c000-000000000000'
        AppDisplayName    = 'PowerDeploy Intune Upload'

        # --- Retry / timing policy (spec 11.1) ---
        RequestTimeoutSec      = 60
        MaxAttempts            = 5
        MaxRetryDelaySec       = 30
        BaseRetryDelaySec      = 1
        PollDeadlineSec        = 600    # per polling stage
        PropagationDeadlineSec = 120    # token/permission propagation after provisioning
        StorageBlockBytes      = 4194304  # 4 MiB

        # --- Credentials ---
        CredentialSubPath         = 'PowerDeploy\GraphUpload'
        CredentialFileName        = 'credential.clixml'
        CredentialSchema          = 1
        NearExpiryWarningDays     = 30
        DefaultSecretLifetimeDays = 180

        # --- Locking (spec 7.3: serialize concurrent credential changes) ---
        LockWaitSeconds  = 10
        LockStaleSeconds = 300

        # --- Misc ---
        MaxErrorBodyChars = 900

        # Test seam: script block receiving the request hashtable, returning a normalized
        # response hashtable (see Invoke-PDGraphTransport). Null in production.
        TestTransport = $null

        # In-memory token cache: 'tenant|clientId' -> token object. Never persisted.
        TokenCache = @{}
    }
}

# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------

function Test-PDGraphGuid {
    <#
        .SYNOPSIS
        True when the value parses as a GUID. Never throws.
    #>
    param( [AllowNull()][object]$Value )

    if ($null -eq $Value) { return $false }

    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $false }

    $parsed = [guid]::Empty
    return [guid]::TryParse($text, [ref]$parsed)
}

function Get-PDGraphTrimmedText {
    <#
        .SYNOPSIS
        Trims a value to a string. -TreatNotApplicableAsMissing maps the literal 'N/A' to empty.
    #>
    param(
        [AllowNull()][object]$Value,
        [switch]$TreatNotApplicableAsMissing
    )

    if ($null -eq $Value) { return '' }

    $text = ([string]$Value).Trim()
    if ($TreatNotApplicableAsMissing -and ($text -eq 'N/A')) { return '' }
    return $text
}

function ConvertTo-PDGraphJson {
    <#
        .SYNOPSIS
        Serializes a payload with sufficient depth for nested Intune objects.
        Explicit depth matters: the default of 2 silently flattens installExperience.
    #>
    param(
        [Parameter(Mandatory = $true)][object]$InputObject,
        [int]$Depth = 40
    )

    return ($InputObject | ConvertTo-Json -Depth $Depth -Compress)
}

function New-PDGraphError {
    <#
        .SYNOPSIS
        Builds a terminating error carrying sanitized, structured, display-safe detail.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Stage,
        [int]$Status = 0,
        [string]$RequestId,
        [string]$RetryAfter,
        [bool]$ApprovalRequired = $false,
        [bool]$Retryable = $false,
        [string]$Detail
    )

    $parts = @()
    if ($Message) { $parts += $Message }
    if ($Stage)   { $parts += "(stage: $Stage)" }

    if ($Status -gt 0) {
        $statusBits = "HTTP $Status"
        if ($RequestId) { $statusBits += ", request-id $RequestId" }
        $parts += "($statusBits)"
    }
    if ($RetryAfter) { $parts += "(retry-after $RetryAfter)" }
    if ($ApprovalRequired) { $parts += '(Multi-Admin Approval required for this application identity)' }
    if ($Detail) { $parts += "[detail: $Detail]" }

    $exception = New-Object System.Management.Automation.RuntimeException ($parts -join ' ')

    $exception | Add-Member -NotePropertyName Stage            -NotePropertyValue $Stage
    $exception | Add-Member -NotePropertyName Status           -NotePropertyValue $Status
    $exception | Add-Member -NotePropertyName RequestId        -NotePropertyValue $RequestId
    $exception | Add-Member -NotePropertyName RetryAfter       -NotePropertyValue $RetryAfter
    $exception | Add-Member -NotePropertyName ApprovalRequired -NotePropertyValue $ApprovalRequired
    $exception | Add-Member -NotePropertyName Retryable        -NotePropertyValue $Retryable
    $exception | Add-Member -NotePropertyName Detail           -NotePropertyValue $Detail
    $exception | Add-Member -NotePropertyName PDSanitized      -NotePropertyValue $true

    return $exception
}

function Stop-PDGraphError {
    <#
        .SYNOPSIS
        Throws a sanitized terminating error (see New-PDGraphError).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Stage,
        [int]$Status = 0,
        [string]$RequestId,
        [string]$RetryAfter,
        [bool]$ApprovalRequired = $false,
        [bool]$Retryable = $false,
        [string]$Detail
    )

    throw (New-PDGraphError -Message $Message -Stage $Stage -Status $Status -RequestId $RequestId `
            -RetryAfter $RetryAfter -ApprovalRequired $ApprovalRequired -Retryable $Retryable -Detail $Detail)
}

function Get-PDGraphErrorInfo {
    <#
        .SYNOPSIS
        Extracts sanitized structured detail from a caught ErrorRecord or Exception.
    #>
    param( [Parameter(Mandatory = $true)][AllowNull()][object]$ErrorRecord )

    $info = @{
        Stage            = $null
        Status           = 0
        RequestId        = $null
        RetryAfter       = $null
        ApprovalRequired = $false
        Retryable        = $false
        Detail           = $null
        Message          = $null
        Sanitized        = $false
    }

    if ($null -eq $ErrorRecord) { return $info }

    $exception = $null
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $exception = $ErrorRecord.Exception }
    elseif ($ErrorRecord -is [System.Exception]) { $exception = $ErrorRecord }
    else {
        $info.Message = [string]$ErrorRecord
        return $info
    }

    if ($null -eq $exception) { return $info }

    $info.Message = [string]$exception.Message

    foreach ($name in @('Stage', 'Status', 'RequestId', 'RetryAfter', 'ApprovalRequired', 'Retryable', 'Detail', 'PDSanitized')) {
        try {
            $member = $exception.PSObject.Properties[$name]
            if ($null -eq $member) { continue }
            if ($null -eq $member.Value) { continue }
            if ($name -eq 'PDSanitized') { $info.Sanitized = [bool]$member.Value }
            else { $info[$name] = $member.Value }
        } catch {
            # A missing note property must never break an error path.
        }
    }

    return $info
}

function Get-PDGraphResponseHeader {
    <#
        .SYNOPSIS
        Reads one header value across the shapes each engine exposes: hashtable,
        WebHeaderCollection (5.1) and HttpHeaders (7). Never throws.
    #>
    param(
        [AllowNull()][object]$Headers,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Headers) { return $null }

    if ($Headers -is [System.Collections.IDictionary]) {
        foreach ($key in $Headers.Keys) {
            if (([string]$key) -eq $Name) { return [string]$Headers[$key] }
        }
        return $null
    }

    # Both WebHeaderCollection and HttpHeaders expose string GetValues(string).
    try {
        $method = $Headers.GetType().GetMethod('GetValues', [type[]]@([string]))
        if ($null -ne $method) {
            $values = $method.Invoke($Headers, @([string]$Name))
            if ($null -ne $values) {
                $list = @($values)
                if ($list.Count -gt 0) { return [string]$list[0] }
            }
        }
    } catch { }

    # HttpHeaders also offers TryGetValues(string, out IEnumerable<string>).
    try {
        $valueType = [type]::MakeByRefType(([System.Collections.Generic.IEnumerable[string]] -as [type]))
        $method = $Headers.GetType().GetMethod('TryGetValues', [type[]]@([string], $valueType))
        if ($null -ne $method) {
            $callArgs = [object[]]@([string]$Name, $null)
            $ok = $method.Invoke($Headers, $callArgs)
            if ($ok -and ($null -ne $callArgs[1])) {
                $list = @($callArgs[1])
                if ($list.Count -gt 0) { return [string]$list[0] }
            }
        }
    } catch { }

    return $null
}

function Test-PDGraphUrlIsGraph {
    <#
        .SYNOPSIS
        True only for https on exactly the Microsoft Graph host. Gates whether an
        Authorization header may be forwarded (spec 11.1).
    #>
    param( [AllowNull()][string]$Url )

    if ([string]::IsNullOrWhiteSpace($Url)) { return $false }

    $uri = $null
    if (-not [System.Uri]::TryCreate($Url.Trim(), [System.UriKind]::Absolute, [ref]$uri)) { return $false }
    if ($uri.Scheme -ne 'https') { return $false }

    return ($uri.Host -eq $script:PDGraph.GraphHost)
}

function Remove-UrlCredential {
    <#
        .SYNOPSIS
        Returns a display-safe copy of a URL with userinfo (user and password) removed.

        .DESCRIPTION
        Pure and total: never throws, and never emits the credential it removed.

        Non-HTTP Git remote forms such as git@github.com:org/repo.git are returned unchanged:
        the 'git' user there is a protocol convention, not a secret, and rewriting it protects
        nothing. A malformed userinfo-only authority is reported as redacted rather than echoed.

        DISPLAY AND NOTES TEXT ONLY. Never use this on the repository URL handed to command
        generation, and never on install/uninstall command file contents.
    #>
    param( [AllowNull()][string]$Url )

    if ([string]::IsNullOrWhiteSpace($Url)) { return '' }

    try {
        # Collapse embedded newlines first: a value containing a line break must not be able
        # to smuggle text past the line-oriented parsing below, and must never reach a console
        # or log as two lines.
        $text = (([string]$Url) -replace "`r`n", ' ' -replace "`r", ' ' -replace "`n", ' ').Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { return '' }

        if ($text -notmatch '^(?<scheme>[Hh][Tt][Tt][Pp][Ss]?)://(?<rest>.*)$') { return $text }

        $scheme = $Matches['scheme']
        $rest   = $Matches['rest']

        $authorityEnd = $rest.Length
        for ($i = 0; $i -lt $rest.Length; $i++) {
            $c = $rest[$i]
            if (($c -eq '/') -or ($c -eq '?') -or ($c -eq '#')) { $authorityEnd = $i; break }
        }

        $authority = $rest.Substring(0, $authorityEnd)
        $tail      = $rest.Substring($authorityEnd)

        $at = $authority.LastIndexOf('@')
        if ($at -lt 0) { return $text }

        $hostPart = $authority.Substring($at + 1)
        if ([string]::IsNullOrWhiteSpace($hostPart)) { return "${scheme}://<redacted>" }

        return ($scheme + '://' + $hostPart + $tail)
    } catch {
        return '<redacted>'
    }
}

function Complete-PDIntuneNotes {
    <#
        .SYNOPSIS
        Appends exactly one 'Created: <ISO-8601 with offset>' line to a technical Notes block.

        .DESCRIPTION
        Pure formatting: inspects nothing but its inputs and adds no user or computer
        attribution. Idempotent by design - a block whose final non-empty line is already a
        Created line is returned unchanged, so a retry inside one create attempt can never
        append a second timestamp.
    #>
    param(
        [AllowNull()][string]$Notes,
        [AllowNull()][object]$CreatedAt
    )

    if ($null -eq $CreatedAt) {
        $moment = [System.DateTimeOffset]::UtcNow
    } elseif ($CreatedAt -is [System.DateTimeOffset]) {
        $moment = $CreatedAt
    } elseif ($CreatedAt -is [DateTime]) {
        $moment = [System.DateTimeOffset]::new(([DateTime]$CreatedAt).ToUniversalTime())
    } else {
        $parsed = [DateTime]::MinValue
        if ([DateTime]::TryParse(([string]$CreatedAt), [ref]$parsed)) {
            $moment = [System.DateTimeOffset]::new($parsed.ToUniversalTime())
        } else {
            Stop-PDGraphError -Message 'Notes timestamp could not be understood; refusing to create a malformed Created line.' -Stage 'Preflight'
        }
    }

    $stamp = 'Created: ' + $moment.ToString('yyyy-MM-ddTHH:mm:sszzz', [System.Globalization.CultureInfo]::InvariantCulture)

    $block = [string]$Notes
    if ($null -eq $block) { $block = '' }
    $block = $block -replace "`r`n", "`n"
    $block = $block -replace "`r", "`n"
    $block = $block.TrimEnd([char[]]@("`n", "`r", ' ', "`t"))

    if ($block.Length -eq 0) { return $stamp }

    # Emit one consistent CRLF shape, so a second call on already-finalized text produces
    # byte-identical output instead of mixing LF and CRLF line endings.
    $block = (($block -split "`n") -join "`r`n")

    $lines = @($block -split "`r`n")
    for ($i = $lines.Count - 1; $i -ge 0; $i--) {
        if ([string]::IsNullOrWhiteSpace($lines[$i])) { continue }
        if ($lines[$i] -match '^Created:\s') { return ($block + "`r`n") }
        break
    }

    return ($block + "`r`n" + $stamp)
}

function Get-PDJwtClaims {
    <#
        .SYNOPSIS
        Decodes the claims of a JWT for READING the 'roles' claim only.

        .DESCRIPTION
        Performs no signature or validity verification and must never be used to authorize
        anything: the token was obtained directly from the tenant, and Graph remains the
        authority on what the call may do.
    #>
    param( [AllowNull()][string]$Token )

    if ([string]::IsNullOrWhiteSpace($Token)) { return @{} }

    try {
        $parts = @($Token.Split('.'))
        if ($parts.Count -lt 2) { return @{} }

        $payload = $parts[1] -replace '-', '+' -replace '_', '/'
        switch ($payload.Length % 4) {
            2 { $payload = $payload + '==' }
            3 { $payload = $payload + '=' }
        }

        $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
        return ($json | ConvertFrom-Json)
    } catch {
        return @{}
    }
}

# ---------------------------------------------------------------------------
# Credential storage (spec 7.3)
# ---------------------------------------------------------------------------

function Get-PDGraphCredentialPath {
    <#
        .SYNOPSIS
        Absolute path of the local upload credential file.
        .PARAMETER Path
        Optional override (used by tests and by the uploader's -CredentialPath).
    #>
    param( [AllowNull()][string]$Path )

    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $expanded = [Environment]::ExpandEnvironmentVariables($Path.Trim())
        try {
            return [System.IO.Path]::GetFullPath($expanded)
        } catch {
            Stop-PDGraphError -Message 'The credential path provided is not a valid file path.' -Stage 'Credential'
        }
    }

    $root = $env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($root)) {
        $root = [Environment]::GetFolderPath('LocalApplicationData')
    }
    if ([string]::IsNullOrWhiteSpace($root)) {
        Stop-PDGraphError -Message 'Cannot locate the per-user application data folder (LOCALAPPDATA) required for credential storage.' -Stage 'Credential'
    }

    $dir = Join-Path $root $script:PDGraph.CredentialSubPath
    return [System.IO.Path]::GetFullPath((Join-Path $dir $script:PDGraph.CredentialFileName))
}

function New-PDGraphCredentialObject {
    <#
        .SYNOPSIS
        Validates inputs and builds the on-disk credential object (no secrets in the result
        beyond the SecureString itself).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true)][System.Security.SecureString]$ClientSecret,
        [AllowNull()][object]$SecretExpiresOn,
        [AllowNull()][string]$SecretKeyId,
        [AllowNull()][string]$AppObjectId,
        [AllowNull()][string]$ServicePrincipalId,
        [AllowNull()][string]$AppDisplayName
    )

    if (-not (Test-PDGraphGuid $TenantId)) {
        Stop-PDGraphError -Message 'TenantId is not a valid GUID.' -Stage 'Credential'
    }
    if (-not (Test-PDGraphGuid $ClientId)) {
        Stop-PDGraphError -Message 'ClientId is not a valid GUID.' -Stage 'Credential'
    }
    if ($null -eq $ClientSecret) {
        Stop-PDGraphError -Message 'ClientSecret is required.' -Stage 'Credential'
    }

    $expires = $null
    if ($SecretExpiresOn -is [System.DateTimeOffset]) {
        $expires = [System.DateTimeOffset]$SecretExpiresOn
    } elseif ($SecretExpiresOn -is [DateTime]) {
        $expires = [System.DateTimeOffset]::new(([DateTime]$SecretExpiresOn).ToUniversalTime())
    } else {
        $text = ([string]$SecretExpiresOn).Trim()
        if ([string]::IsNullOrWhiteSpace($text)) {
            Stop-PDGraphError -Message 'SecretExpiresOn is required so that expiry can be enforced.' -Stage 'Credential'
        }
        $dot = [System.DateTimeOffset]::MinValue
        if (-not [System.DateTimeOffset]::TryParse($text, [System.Globalization.DateTimeFormatInfo]::InvariantInfo, [System.Globalization.DateTimeStyles]::None, [ref]$dot)) {
            $plain = [DateTime]::MinValue
            if (-not [DateTime]::TryParse($text, [ref]$plain)) {
                Stop-PDGraphError -Message 'SecretExpiresOn is not a valid date and time.' -Stage 'Credential'
            }
            $dot = [System.DateTimeOffset]::new($plain.ToUniversalTime())
        }
        $expires = $dot
    }

    foreach ($optional in @(@{ n = 'SecretKeyId'; v = $SecretKeyId }, @{ n = 'AppObjectId'; v = $AppObjectId }, @{ n = 'ServicePrincipalId'; v = $ServicePrincipalId })) {
        if (-not [string]::IsNullOrWhiteSpace([string]$optional.v)) {
            if (-not (Test-PDGraphGuid $optional.v)) {
                Stop-PDGraphError -Message "$($optional.n) is present but is not a valid GUID." -Stage 'Credential'
            }
        }
    }

    return @{
        SchemaVersion      = $script:PDGraph.CredentialSchema
        TenantId           = ([string]$TenantId).Trim().ToLowerInvariant()
        ClientId           = ([string]$ClientId).Trim().ToLowerInvariant()
        ClientSecret       = $ClientSecret
        SecretExpiresOn    = $expires.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        SecretKeyId        = (Get-PDGraphTrimmedText $SecretKeyId)
        AppObjectId        = (Get-PDGraphTrimmedText $AppObjectId)
        ServicePrincipalId = (Get-PDGraphTrimmedText $ServicePrincipalId)
        AppDisplayName     = (Get-PDGraphTrimmedText $AppDisplayName)
    }
}

function ConvertFrom-PDGraphCredentialFile {
    <#
        .SYNOPSIS
        Validates an object read from the credential file. Internal; called by both save
        (round-trip proof) and load. Returns the normalized credential plus computed expiry,
        or adds problems without throwing.
    #>
    param(
        [AllowNull()][object]$Raw,
        [ref]$Problem
    )

    $problems = @()

    if ($null -eq $Raw) {
        $Problem.Value = 'The credential file is empty or could not be read.'
        return $null
    }

    $rawType = $Raw.GetType().Name
    if (($rawType -ne 'Hashtable') -and ($rawType -ne 'OrderedDictionary') -and
        ($rawType -ne 'PSCustomObject') -and ($rawType -notlike 'Deserialized*')) {
        $Problem.Value = "The credential file did not contain a credential record (found $rawType)."
        return $null
    }

    $get = {
        param($name)
        try {
            $member = $Raw.PSObject.Properties[$name]
            if ($null -ne $member) { return $member.Value }
        } catch { }
        try {
            if ($Raw -is [System.Collections.IDictionary] -and $Raw.Contains($name)) { return $Raw[$name] }
        } catch { }
        return $null
    }

    $schema = & $get 'SchemaVersion'
    if ($null -eq $schema) { $problems += 'SchemaVersion is missing.' }
    elseif ([int]$schema -ne $script:PDGraph.CredentialSchema) {
        $problems += "SchemaVersion $schema is not supported (expected $($script:PDGraph.CredentialSchema))."
    }

    $tenantId = [string](& $get 'TenantId')
    $clientId = [string](& $get 'ClientId')
    if (-not (Test-PDGraphGuid $tenantId)) { $problems += 'TenantId is missing or is not a GUID.' }
    if (-not (Test-PDGraphGuid $clientId)) { $problems += 'ClientId is missing or is not a GUID.' }

    $secret = & $get 'ClientSecret'
    if ($null -eq $secret) { $problems += 'ClientSecret is missing.' }
    elseif ($secret -isnot [System.Security.SecureString]) {
        $problems += ('ClientSecret is not a protected SecureString (found ' + $secret.GetType().Name + '); refusing to use it.')
    }

    $expiresRaw = & $get 'SecretExpiresOn'
    $expires = $null
    if ($null -eq $expiresRaw) {
        $problems += 'SecretExpiresOn is missing.'
    } else {
        if ($expiresRaw -is [System.DateTimeOffset]) {
            $expires = [System.DateTimeOffset]$expiresRaw
        } elseif ($expiresRaw -is [DateTime]) {
            $expires = [System.DateTimeOffset]::new(([DateTime]$expiresRaw).ToUniversalTime())
        } else {
            $dot = [System.DateTimeOffset]::MinValue
            if ([System.DateTimeOffset]::TryParse(([string]$expiresRaw), [System.Globalization.DateTimeFormatInfo]::InvariantInfo, [System.Globalization.DateTimeStyles]::None, [ref]$dot)) {
                $expires = $dot
            } else {
                $plain = [DateTime]::MinValue
                if ([DateTime]::TryParse(([string]$expiresRaw), [ref]$plain)) {
                    $expires = [System.DateTimeOffset]::new($plain.ToUniversalTime())
                } else {
                    $problems += 'SecretExpiresOn is present but cannot be understood.'
                }
            }
        }
    }

    foreach ($optional in @('SecretKeyId', 'AppObjectId', 'ServicePrincipalId')) {
        $value = [string](& $get $optional)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            if (-not (Test-PDGraphGuid $value)) { $problems += "$optional is present but is not a GUID." }
        }
    }

    if ($problems.Count -gt 0) {
        $Problem.Value = ($problems -join ' ')
        return $null
    }

    $daysUntilExpiry = $null
    if ($null -ne $expires) { $daysUntilExpiry = [math]::Ceiling(($expires - [System.DateTimeOffset]::UtcNow).TotalDays) }

    return @{
        SchemaVersion      = [int]$schema
        TenantId           = $tenantId.Trim().ToLowerInvariant()
        ClientId           = $clientId.Trim().ToLowerInvariant()
        ClientSecret       = $secret
        SecretExpiresOn    = $expires
        SecretKeyId        = (Get-PDGraphTrimmedText ([string](& $get 'SecretKeyId')))
        AppObjectId        = (Get-PDGraphTrimmedText ([string](& $get 'AppObjectId')))
        ServicePrincipalId = (Get-PDGraphTrimmedText ([string](& $get 'ServicePrincipalId')))
        AppDisplayName     = (Get-PDGraphTrimmedText ([string](& $get 'AppDisplayName')))
        DaysUntilExpiry    = $daysUntilExpiry
        Warnings           = @()
    }
}

function Enter-PDGraphCredentialLock {
    <#
        .SYNOPSIS
        Takes an exclusive lock beside the credential file (spec 7.3: serialize concurrent
        credential changes). Returns the owning FileStream; pass it to
        Exit-PDGraphCredentialLock in a finally block.
    #>
    param( [Parameter(Mandatory = $true)][string]$CredentialPath )

    $lockPath = "$CredentialPath.lock"
    $dir      = Split-Path $lockPath -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $deadline = (Get-Date).AddSeconds([double]$script:PDGraph.LockWaitSeconds)

    while ($true) {
        try {
            $stream = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            try {
                $note  = [System.Text.Encoding]::ASCII.GetBytes("PID $PID`n")
                $stream.Write($note, 0, $note.Length)
                $stream.Flush()
            } catch { }
            return $stream
        } catch {
            $took = $false
            try {
                if ([System.IO.File]::Exists($lockPath)) {
                    $age = ((Get-Date) - [System.IO.File]::GetLastWriteTime($lockPath)).TotalSeconds
                    if ($age -gt [double]$script:PDGraph.LockStaleSeconds) {
                        [System.IO.File]::Delete($lockPath)
                        $took = $true
                    }
                }
            } catch { }

            if ($took) { continue }

            if ((Get-Date) -gt $deadline) {
                Stop-PDGraphError -Message 'Another credential operation is already in progress for this user. Wait for it to finish and try again.' -Stage 'Credential'
            }
            Start-Sleep -Milliseconds 200
        }
    }
}

function Exit-PDGraphCredentialLock {
    <#
        .SYNOPSIS
        Releases a lock from Enter-PDGraphCredentialLock and removes the lock file.
        Safe to call with $null.
    #>
    param( [AllowNull()][object]$Lock )

    if ($null -eq $Lock) { return }

    $path = $null
    try { $path = $Lock.Name } catch { }

    try { $Lock.Dispose() } catch { }

    if ($path) {
        try { [System.IO.File]::Delete($path) } catch { }
    }
}

function Get-PDGraphCredential {
    <#
        .SYNOPSIS
        Loads, validates, and returns the local upload credential.
        .DESCRIPTION
        Refuses expired credentials, warns within NearExpiryWarningDays (as a returned
        Warnings entry, so the caller decides how to display it), and turns an unreadable,
        corrupt, foreign-account, or wrong-schema file into one clear operator message.
        The plaintext secret is never produced here.
    #>
    param( [AllowNull()][string]$Path )

    $resolved = Get-PDGraphCredentialPath -Path $Path

    if (-not [System.IO.File]::Exists($resolved)) {
        Stop-PDGraphError -Message ("No upload credential is stored for this Windows account. Run the Setup menu function Graph_API_Upload--InTune-Setup to create or enter one. Expected: $resolved") -Stage 'Credential'
    }

    $raw = $null
    try {
        $raw = Import-Clixml -LiteralPath $resolved -ErrorAction Stop
    } catch {
        $reason = ([string]$_.Exception.Message)
        if ($reason -match '(?i)decrypt|cryptograph|key|padding|mac|bad data|not valid|rmtp|protected') {
            Stop-PDGraphError -Message 'The stored credential could not be decrypted by this Windows account. It was saved by a different user or machine; re-enter it through Graph_API_Upload--InTune-Setup.' -Stage 'Credential'
        }
        Stop-PDGraphError -Message "The stored credential file could not be read and may be corrupt. Re-enter it through Graph_API_Upload--InTune-Setup. ($reason)" -Stage 'Credential'
    }

    $problem = $null
    $credential = ConvertFrom-PDGraphCredentialFile -Raw $raw -Problem ([ref]$problem)

    if ($null -eq $credential) {
        Stop-PDGraphError -Message "The stored credential file is not usable: $problem Re-enter it through Graph_API_Upload--InTune-Setup." -Stage 'Credential'
    }

    $warnings = @()

    if ($credential.SecretExpiresOn -le [System.DateTimeOffset]::UtcNow) {
        $shown = $credential.SecretExpiresOn.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
        Stop-PDGraphError -Message "The stored application secret expired on $shown. Rotate it with Graph_API_Upload--InTune-Setup." -Stage 'Credential'
    }

    if ($credential.DaysUntilExpiry -le [int]$script:PDGraph.NearExpiryWarningDays) {
        $warnings += ("The stored application secret expires in {0} day(s) ({1}). Plan a rotation." -f $credential.DaysUntilExpiry, $credential.SecretExpiresOn.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture))
    }

    if ([string]::IsNullOrWhiteSpace($credential.SecretKeyId)) {
        $warnings += 'No secret key id is recorded, so rotation cannot revoke the previous secret automatically; it will report that key for manual cleanup.'
    }

    $credential.Warnings = $warnings
    $credential.Path     = $resolved
    return $credential
}

function Save-PDGraphCredential {
    <#
        .SYNOPSIS
        Validates, then atomically saves the credential. A failed save leaves the previous
        file untouched (spec 7.3).
        .OUTPUTS
        Hashtable of safe metadata: Path, SecretExpiresOn, DaysUntilExpiry. Never a secret.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Credential,
        [AllowNull()][string]$Path
    )

    $resolved = Get-PDGraphCredentialPath -Path $Path
    $dir      = Split-Path $resolved -Parent

    if (-not (Test-Path $dir)) {
        try {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        } catch {
            Stop-PDGraphError -Message "The credential folder could not be created: $dir" -Stage 'Credential'
        }
    }

    $fileObject = @{
        SchemaVersion      = $script:PDGraph.CredentialSchema
        TenantId           = $Credential.TenantId
        ClientId           = $Credential.ClientId
        ClientSecret       = $Credential.ClientSecret
        SecretExpiresOn    = $Credential.SecretExpiresOn
        SecretKeyId        = (Get-PDGraphTrimmedText $Credential.SecretKeyId)
        AppObjectId        = (Get-PDGraphTrimmedText $Credential.AppObjectId)
        ServicePrincipalId = (Get-PDGraphTrimmedText $Credential.ServicePrincipalId)
        AppDisplayName     = (Get-PDGraphTrimmedText $Credential.AppDisplayName)
    }

    $lock = $null
    try {
        $lock = Enter-PDGraphCredentialLock -CredentialPath $resolved

        $tempPath = Join-Path $dir ("credential.{0}.tmp" -f [guid]::NewGuid().ToString('N'))

        try {
            Export-Clixml -LiteralPath $tempPath -InputObject $fileObject -Depth 5 -ErrorAction Stop
        } catch {
            try { [System.IO.File]::Delete($tempPath) } catch { }
            Stop-PDGraphError -Message 'The credential could not be written. The existing credential is unchanged.' -Stage 'Credential'
        }

        # Prove the file we just wrote is readable and valid before touching the live copy.
        $problem = $null
        try {
            $roundTrip = ConvertFrom-PDGraphCredentialFile -Raw (Import-Clixml -LiteralPath $tempPath -ErrorAction Stop) -Problem ([ref]$problem)
        } catch {
            $roundTrip = $null
        }

        if ($null -eq $roundTrip) {
            try { [System.IO.File]::Delete($tempPath) } catch { }
            Stop-PDGraphError -Message "The credential was not saved because the written file did not validate: $problem The existing credential is unchanged." -Stage 'Credential'
        }

        try {
            if ([System.IO.File]::Exists($resolved)) {
                [System.IO.File]::Replace($tempPath, $resolved, $null)
            } else {
                [System.IO.File]::Move($tempPath, $resolved)
            }
        } catch {
            try { [System.IO.File]::Delete($tempPath) } catch { }
            Stop-PDGraphError -Message 'The credential could not be put in place. The existing credential is unchanged.' -Stage 'Credential'
        }

        return @{
            Path            = $resolved
            SecretExpiresOn = $roundTrip.SecretExpiresOn
            DaysUntilExpiry = $roundTrip.DaysUntilExpiry
        }
    } finally {
        Exit-PDGraphCredentialLock -Lock $lock
    }
}

function Remove-PDGraphCredential {
    <#
        .SYNOPSIS
        Removes the specified local credential file only. Never touches the repository, the
        fleet registry key, or any other administrator's credentials.
    #>
    param( [AllowNull()][string]$Path )

    $resolved = Get-PDGraphCredentialPath -Path $Path

    if (-not [System.IO.File]::Exists($resolved)) {
        return @{ Removed = $false; Path = $resolved; Message = 'No stored credential was present; nothing to remove.' }
    }

    try {
        [System.IO.File]::Delete($resolved)
        return @{ Removed = $true; Path = $resolved; Message = 'Stored credential removed. Any Entra secret it held is still active until revoked.' }
    } catch {
        Stop-PDGraphError -Message "The stored credential file could not be removed: $resolved" -Stage 'Credential'
    }
}

# ---------------------------------------------------------------------------
# Transport (the single seam; spec 11.1)
# ---------------------------------------------------------------------------

function Get-PDGraphNormalizedResponse {
    <#
        .SYNOPSIS
        Normalizes a successful response, an HTTP error, or a transport failure into one
        hashtable: StatusCode, Body, Headers, TransportError. Internal.
    #>
    param(
        [AllowNull()][object]$Response,
        [AllowNull()][object]$ErrorRecord
    )

    if ($null -eq $ErrorRecord) {
        $headers = @{}
        try {
            foreach ($name in @('request-id', 'apim-request-id', 'Retry-After', 'x-msft-approval-justification', 'x-ms-request-id', 'Location')) {
                $value = Get-PDGraphResponseHeader -Headers $Response.Headers -Name $name
                if ($null -ne $value) { $headers[$name] = $value }
            }
        } catch { }

        $body = ''
        try {
            if ($null -ne $Response.Content) {
                if ($Response.Content -is [string]) { $body = $Response.Content }
                else { $body = ($Response.Content | Out-String) }
            }
        } catch { }

        return @{
            StatusCode     = [int]$Response.StatusCode
            Body           = $body
            Headers        = $headers
            TransportError = $null
        }
    }

    $info  = Get-PDGraphErrorInfo -ErrorRecord $ErrorRecord
    $inner = $null
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $inner = $ErrorRecord.Exception }

    $status       = 0
    $headers      = @{}
    $body         = ''
    $transportMsg = $info.Message

    # PowerShell 7: HttpResponseException carries the HttpResponseMessage.
    try {
        if ($null -ne $inner -and $inner.PSObject.Properties['Response'] -and ($null -ne $inner.Response)) {
            $responseMessage = $inner.Response

            if ($responseMessage.PSObject.Properties['StatusCode']) {
                $status = [int]$responseMessage.StatusCode
            }
            if ($responseMessage.PSObject.Properties['Headers']) {
                foreach ($name in @('request-id', 'apim-request-id', 'Retry-After', 'x-msft-approval-justification', 'x-ms-request-id')) {
                    $value = Get-PDGraphResponseHeader -Headers $responseMessage.Headers -Name $name
                    if ($null -ne $value) { $headers[$name] = $value }
                }
            }
            # The response body is already consumed by Invoke-WebRequest and surfaced in
            # ErrorDetails.Message; do not attempt to re-read the content stream here.
            try {
                if ($null -ne $ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
                    $body = [string]$ErrorRecord.ErrorDetails.Message
                }
            } catch { }
        }
    } catch { }

    # Windows PowerShell 5.1: WebException carries HttpWebResponse.
    if ($status -eq 0) {
        try {
            if ($null -ne $inner -and $inner -is [System.Net.WebException] -and ($null -ne $inner.Response)) {
                $webResponse = $inner.Response
                $status = [int]$webResponse.StatusCode

                foreach ($name in @('request-id', 'apim-request-id', 'Retry-After', 'x-msft-approval-justification', 'x-ms-request-id')) {
                    $value = Get-PDGraphResponseHeader -Headers $webResponse.Headers -Name $name
                    if ($null -ne $value) { $headers[$name] = $value }
                }

                try {
                    $stream = $webResponse.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($stream)
                    $body   = $reader.ReadToEnd()
                    $reader.Close()
                    $stream.Close()
                } catch { }
            }
        } catch { }
    }

    if ([string]::IsNullOrWhiteSpace($body)) {
        try {
            if ($null -ne $ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
                $body = [string]$ErrorRecord.ErrorDetails.Message
            }
        } catch { }
    }

    $isTransportFailure = ($status -eq 0)

    return @{
        StatusCode     = $status
        Body           = $body
        Headers        = $headers
        TransportError = @{
            TransportFailure = $isTransportFailure
            Message          = (Remove-UrlCredential $transportMsg)
        }
    }
}

function Invoke-PDGraphTransport {
    <#
        .SYNOPSIS
        THE ONLY place this library performs network I/O. Everything else goes through it,
        which is what makes the whole request stack testable offline.

        .DESCRIPTION
        Accepts a request hashtable:
            Method       string   'Get','Post','Patch','Put','Delete'
            Uri          string   absolute
            Headers      hashtable (may be $null)
            BodyText     string   raw body, already serialized (may be $null)
            BodyBytes    byte[]   preferred over BodyText when present
            ContentType  string   (may be $null)
            TimeoutSec   int
        Returns a normalized response hashtable (Get-PDGraphNormalizedResponse) and does NOT
        throw on an HTTP status error - only on a transport/parse failure it cannot describe.

        Tests set $PDGraph.TestTransport = { param($Request) ... } and receive that same
        hashtable, returning the same normalized shape.
    #>
    param( [Parameter(Mandatory = $true)][hashtable]$Request )

    if ($null -ne $script:PDGraph.TestTransport) {
        return (& $script:PDGraph.TestTransport $Request)
    }

    $params = @{
        Uri                        = $Request.Uri
        Method                     = $Request.Method
        UseBasicParsing            = $true
        TimeoutSec                 = [int]$Request.TimeoutSec
        ErrorAction                = 'Stop'
        ErrorVariable              = 'pdTransportError'
    }

    if ($Request.ContainsKey('Headers') -and ($null -ne $Request.Headers) -and ($Request.Headers.Count -gt 0)) {
        $params['Headers'] = $Request.Headers
    }
    if ($Request.ContainsKey('BodyBytes') -and ($null -ne $Request.BodyBytes)) {
        $params['Body'] = $Request.BodyBytes
    } elseif ($Request.ContainsKey('BodyText') -and ($null -ne $Request.BodyText)) {
        $params['Body'] = $Request.BodyText
    }
    if ($Request.ContainsKey('ContentType') -and ($null -ne $Request.ContentType) -and ($Request.ContentType -ne '')) {
        $params['ContentType'] = $Request.ContentType
    }

    $response = $null
    try {
        $response = Microsoft.PowerShell.Utility\Invoke-WebRequest @params
    } catch {
        return (Get-PDGraphNormalizedResponse -ErrorRecord $_)
    } finally {
        # Nothing to dispose; Invoke-WebRequest owns its response object lifetime.
    }

    if ($null -eq $response) {
        $failed = $null
        if (Test-Path Variable:pdTransportError) { $failed = (Get-Variable -Name pdTransportError -ValueOnly) }
        if ($null -ne $failed) { return (Get-PDGraphNormalizedResponse -ErrorRecord $failed) }
        return (Get-PDGraphNormalizedResponse -ErrorRecord (New-Object System.Management.Automation.ErrorRecord (New-Object System.Exception 'The request produced no response.'), 'PDNoResponse', 'NotSpecified', $null))
    }

    return (Get-PDGraphNormalizedResponse -Response $response)
}

# ---------------------------------------------------------------------------
# Requests (retry, auth, sanitized errors)
# ---------------------------------------------------------------------------

function Get-PDGraphServiceMessage {
    <#
        .SYNOPSIS
        Pulls the service's own error message out of a response body, truncated and sanitized.
        Internal. Returns $null when there is nothing safe to report.
    #>
    param([AllowNull()][string]$Body)

    if ([string]::IsNullOrWhiteSpace($Body)) { return $null }

    $text = $Body.Trim()
    $parsed = $null
    try { $parsed = $text | ConvertFrom-Json -ErrorAction Stop } catch { }

    if ($null -ne $parsed) {
        $errorNode = $null
        try { if ($parsed.PSObject.Properties['error']) { $errorNode = $parsed.error } } catch { }

        # The token endpoint uses the OAuth shape (error + error_description) rather than the
        # Graph shape (error.code + error.message); the AADSTS code is the whole point, so it
        # must not be dropped.
        $description = $null
        try {
            if ($parsed.PSObject.Properties['error_description'] -and $parsed.error_description) {
                $description = [string]$parsed.error_description
            }
        } catch { }

        if (($null -ne $errorNode) -and ($errorNode -is [string])) {
            $pieces = @([string]$errorNode)
            if ($description) { $pieces += $description }
            $text = ($pieces -join ': ')
        }
        elseif ($null -ne $errorNode) {
            $pieces = @()
            try { if ($errorNode.PSObject.Properties['code']    -and $errorNode.code)    { $pieces += [string]$errorNode.code } } catch { }
            try { if ($errorNode.PSObject.Properties['message'] -and $errorNode.message) { $pieces += [string]$errorNode.message } } catch { }
            if ($pieces.Count -eq 0) { $pieces += ([string]$errorNode) }
            if ($description) { $pieces += $description }
            $text = ($pieces -join ': ')
        }
        elseif ($description) {
            $text = $description
        }
        elseif ($parsed.PSObject.Properties['error_codes']) {
            $text = [string]($parsed | ConvertTo-Json -Depth 4 -Compress)
        }
    }

    $text = ($text -replace '\s+', ' ')
    $text = Remove-UrlCredential $text

    if ($text.Length -gt [int]$script:PDGraph.MaxErrorBodyChars) {
        $text = $text.Substring(0, [int]$script:PDGraph.MaxErrorBodyChars) + '...'
    }
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text
}

function Test-PDGraphApprovalRequired {
    <#
        .SYNOPSIS
        Multi-Admin Approval detection (spec 11.1): status AND body/header evidence, so an
        ordinary 400/403 is never mislabeled as MAA.
        Internal.
    #>
    param(
        [int]$Status,
        [AllowNull()][string]$Body,
        [AllowNull()][hashtable]$Headers
    )

    try {
        if ($null -ne $Headers) {
            if ($Headers.ContainsKey('x-msft-approval-justification')) { return $true }
        }
    } catch { }

    if ($Status -eq 412) {
        if ((-not [string]::IsNullOrWhiteSpace($Body)) -and ($Body -match '(?i)approval')) { return $true }
    }

    if (($Status -eq 400) -or ($Status -eq 403)) {
        if (-not [string]::IsNullOrWhiteSpace($Body)) {
            # Require admin-and-approval adjacency (in any of the wordings Microsoft has used)
            # rather than the bare word 'approval', so ordinary refusals stay unlabeled.
            if ($Body -match '(?i)multi(ple)?[- ]?admin(istrator)?[- ]?approval') { return $true }
            if ($Body -match '(?i)approval[- ]?(is[- ])?required')                 { return $true }
            if ($Body -match '(?i)\bMAA\b')                                        { return $true }
            if ($Body -match '(?i)approval[ _-]?(code|justification)')             { return $true }
        }
    }

    return $false
}

function Send-PDGraphRequest {
    <#
        .SYNOPSIS
        Shared request core: attempts, backoff, Retry-After, retryability by mode.
        Internal. Returns the normalized response, or throws a sanitized error.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Request,
        [ValidateSet('Read', 'Write', 'Block', 'Token')][string]$RetryMode = 'Read',
        [string]$Stage,
        [string]$Description
    )

    if (-not $Request.ContainsKey('TimeoutSec')) { $Request['TimeoutSec'] = [int]$script:PDGraph.RequestTimeoutSec }
    if (-not $Request.ContainsKey('Method'))    { $Request['Method'] = 'Get' }

    $maxAttempts = [int]$script:PDGraph.MaxAttempts
    if ($RetryMode -eq 'Write') { $maxAttempts = 1 }
    if ($RetryMode -eq 'Token') { $maxAttempts = 3 }

    $target = $Description
    if ([string]::IsNullOrWhiteSpace($target)) { $target = "$($Request.Method) $($Request.Uri)" }

    $lastResponse = $null
    $attempt      = 0

    while ($true) {
        $attempt++
        $response = Invoke-PDGraphTransport -Request $Request

        # A transport failure produces status 0 and is retryable except for writes.
        $isTransport = ($response.StatusCode -eq 0)
        $retryable   = $false

        if ($isTransport) {
            $retryable = ($RetryMode -ne 'Write')
        }
        elseif ($response.StatusCode -eq 429) {
            $retryable = ($RetryMode -ne 'Write')
        }
        elseif ($response.StatusCode -ge 500) {
            $retryable = ($RetryMode -ne 'Write')
        }
        elseif ($response.StatusCode -ge 400) {
            $retryable = $false
        }

        $ok = ($response.StatusCode -ge 200) -and ($response.StatusCode -lt 300)
        if ($ok) { return $response }

        $lastResponse = $response

        if ($retryable -and ($attempt -lt $maxAttempts)) {
            $delay = [double]$script:PDGraph.BaseRetryDelaySec * [math]::Pow(2, [double]($attempt - 1))

            $retryAfter = Get-PDGraphResponseHeader -Headers $response.Headers -Name 'Retry-After'
            if ($null -ne $retryAfter) {
                $seconds = 0.0
                if ([double]::TryParse($retryAfter.Trim(), [ref]$seconds)) { $delay = $seconds }
            }
            if ($delay -gt [double]$script:PDGraph.MaxRetryDelaySec) { $delay = [double]$script:PDGraph.MaxRetryDelaySec }
            if ($delay -lt 0) { $delay = 0 }

            Start-Sleep -Milliseconds ([int]($delay * 1000))
            continue
        }

        break
    }

    # One sanitized failure path for every non-success outcome.
    $status       = [int]$lastResponse.StatusCode
    $transport    = ($null -ne $lastResponse.TransportError) -and [bool]$lastResponse.TransportError.TransportFailure
    $requestId    = $null
    $retryAfter   = Get-PDGraphResponseHeader -Headers $lastResponse.Headers -Name 'Retry-After'
    $approval     = $false
    $detail       = $null

    if (-not $transport) {
        if ($lastResponse.Headers.ContainsKey('request-id'))     { $requestId = $lastResponse.Headers['request-id'] }
        elseif ($lastResponse.Headers.ContainsKey('apim-request-id')) { $requestId = $lastResponse.Headers['apim-request-id'] }
        $detail   = Get-PDGraphServiceMessage -Body $lastResponse.Body
        $approval = Test-PDGraphApprovalRequired -Status $status -Body $lastResponse.Body -Headers $lastResponse.Headers
    }

    if ($transport) {
        $why = 'no HTTP response was received'
        if ($null -ne $lastResponse.TransportError) { $why = $lastResponse.TransportError.Message }
        Stop-PDGraphError -Message "The request ($target) failed before reaching the service: $why" -Stage $Stage -Retryable ([bool]$retryable)
    }

    $headline = "The request ($target) was refused by Microsoft Graph."
    if ($approval) {
        $headline = 'Microsoft Graph requires Multi-Admin Approval for this application identity, so the write was blocked.'
    }

    Stop-PDGraphError -Message $headline -Stage $Stage -Status $status -RequestId $requestId `
        -RetryAfter $retryAfter -ApprovalRequired $approval -Retryable ([bool]$retryable) -Detail $detail
}

function Get-PDGraphToken {
    <#
        .SYNOPSIS
        Acquires (or reuses) an app-only token via client credentials. Memory only.
        .OUTPUTS
        Hashtable: AccessToken, ExpiresOn (UTC DateTime), TenantId, ClientId, Roles (string[])
    #>
    param(
        [Parameter(Mandatory = $true)][object]$Credential,
        [switch]$Force,
        [int]$TimeoutSec = 0
    )

    if ($null -eq $Credential.TenantId -or $null -eq $Credential.ClientId -or $null -eq $Credential.ClientSecret) {
        Stop-PDGraphError -Message 'A credential with TenantId, ClientId, and ClientSecret is required to obtain a token.' -Stage 'Credential'
    }
    if ($Credential.ClientSecret -isnot [System.Security.SecureString]) {
        Stop-PDGraphError -Message 'The stored credential does not hold a protected secret; re-enter it.' -Stage 'Credential'
    }
    if ($Credential.SecretExpiresOn -and ($Credential.SecretExpiresOn -le [System.DateTimeOffset]::UtcNow)) {
        Stop-PDGraphError -Message 'The application secret on file has expired; rotate it before uploading.' -Stage 'Credential'
    }

    $tenantId = ([string]$Credential.TenantId).Trim()
    $clientId = ([string]$Credential.ClientId).Trim()
    $key      = "$tenantId|$clientId"

    if (-not $Force) {
        $cached = $null
        if ($script:PDGraph.TokenCache.ContainsKey($key)) { $cached = $script:PDGraph.TokenCache[$key] }
        if ($null -ne $cached) {
            if ($cached.ExpiresOn -gt ([DateTime]::UtcNow.AddMinutes(5))) { return $cached }
        }
    }

    $plaintext = $null
    try {
        $plaintext = ([System.Management.Automation.PSCredential]::new('PowerDeploy', $Credential.ClientSecret)).GetNetworkCredential().Password
        if ([string]::IsNullOrEmpty($plaintext)) {
            Stop-PDGraphError -Message 'The stored secret is empty; re-enter the credential.' -Stage 'Credential'
        }

        $scope    = [System.Uri]::EscapeDataString([string]$script:PDGraph.GraphScope)
        $bodyText = 'grant_type=client_credentials' +
                    '&client_id='    + [System.Uri]::EscapeDataString($clientId) +
                    '&client_secret=' + [System.Uri]::EscapeDataString($plaintext) +
                    '&scope='         + $scope

        $request = @{
            Method      = 'Post'
            Uri         = ([string]::Format([string]$script:PDGraph.TokenEndpointFormat, $tenantId))
            BodyText    = $bodyText
            ContentType = 'application/x-www-form-urlencoded'
            Headers     = $null
            TimeoutSec  = $(if ($TimeoutSec -gt 0) { $TimeoutSec } else { [int]$script:PDGraph.RequestTimeoutSec })
        }

        $response = Send-PDGraphRequest -Request $request -RetryMode 'Token' -Stage 'Credential' -Description 'token request for the upload identity'

        $parsed = $null
        try { $parsed = $response.Body | ConvertFrom-Json -ErrorAction Stop } catch {
            Stop-PDGraphError -Message 'The token response could not be read.' -Stage 'Credential' -Status $response.StatusCode
        }

        $accessToken = $null
        try { if ($parsed.PSObject.Properties['access_token']) { $accessToken = [string]$parsed.access_token } } catch { }

        if ([string]::IsNullOrWhiteSpace($accessToken)) {
            Stop-PDGraphError -Message 'The token request did not return an access token. Confirm TenantId, ClientId, and the secret, and that the application is not subject to a conditional access policy that blocks app-only sign-in.' `
                -Stage 'Credential' -Status $response.StatusCode -Detail (Get-PDGraphServiceMessage -Body $response.Body)
        }

        $expiresIn = 3600
        try { if ($parsed.PSObject.Properties['expires_in']) { $expiresIn = [int]$parsed.expires_in } } catch { }

        $token = @{
            AccessToken = $accessToken
            ExpiresOn   = [DateTime]::UtcNow.AddSeconds([double]$expiresIn)
            TenantId    = $tenantId
            ClientId    = $clientId
            Roles       = @()
        }

        try {
            $claims = Get-PDJwtClaims -Token $accessToken
            if ($claims -isnot [hashtable]) {
                if ($claims.PSObject.Properties['roles']) {
                    $token.Roles = @($claims.roles | ForEach-Object { [string]$_ })
                }
            }
        } catch { $token.Roles = @() }

        $script:PDGraph.TokenCache[$key] = $token
        return $token
    } finally {
        $plaintext = $null
    }
}

function Invoke-PDGraphRequest {
    <#
        .SYNOPSIS
        One Graph REST call: builds the URL, attaches authorization only to Graph, parses the
        response, and throws a sanitized error on failure.

        .PARAMETER Uri
        A relative Graph path ('/beta/deviceAppManagement/mobileApps') or an absolute Graph
        URL (a service @odata.nextLink). An absolute URL on any other host is rejected rather
        than sent an Authorization header.

        .PARAMETER RetryMode
        Read    retries 429/5xx/transport (the default; safe for GET and repeatable reads)
        Write   never retries automatically - a lost response must be reconciled, not repeated
        Block   storage block PUT semantics
        Token   reserved for the token endpoint core

        .OUTPUTS
        The parsed JSON object, or $null for an empty (204) response. If the body is a
        top-level JSON array, 5.1 hands back one Object[] where 7 enumerates it - pass the
        result through Get-PDGraphItems instead of counting it directly.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Get', 'Post', 'Patch', 'Put', 'Delete')][string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [AllowNull()][object]$Body,
        [AllowNull()][object]$AuthContext,
        [ValidateSet('Read', 'Write', 'Block', 'Token')][string]$RetryMode = 'Read',
        [AllowNull()][hashtable]$Headers,
        [AllowNull()][string]$BaseUri,
        [string]$Stage,
        [string]$Description
    )

    $target = $Uri.Trim()

    # A path may arrive already carrying its API version ('/beta/...' or '/v1.0/...'). Strip it
    # from the path and pick the matching base; concatenating a versioned base onto a versioned
    # path silently produced /beta/beta/... which Graph rejects with an unhelpful 404.
    $versionedBase = $null
    if ($target -match '^/v1\.0(?=/|$)') {
        $versionedBase = [string]$script:PDGraph.GraphV1Base
        $target = $target.Substring(5)
    } elseif ($target -match '^/beta(?=/|$)') {
        $versionedBase = [string]$script:PDGraph.GraphBetaBase
        $target = $target.Substring(5)
    }

    if ($target -match '^/') {
        $base = [string]$script:PDGraph.GraphBetaBase
        if ($BaseUri) { $base = $BaseUri }
        if ($versionedBase) { $base = $versionedBase }
        $target = $base.TrimEnd('/') + $target
    }

    $isGraph = Test-PDGraphUrlIsGraph -Url $target

    $requestHeaders = @{}
    if ($null -ne $Headers) {
        foreach ($name in $Headers.Keys) { $requestHeaders[$name] = $Headers[$name] }
    }

    if ($null -ne $AuthContext) {
        if ($isGraph) {
            $token = $AuthContext
            if ($AuthContext -is [hashtable] -and $AuthContext.ContainsKey('Credential')) {
                $token = Get-PDGraphToken -Credential $AuthContext.Credential
            }
            if ($null -eq $token -or [string]::IsNullOrWhiteSpace([string]$token.AccessToken)) {
                Stop-PDGraphError -Message 'No usable Graph token was supplied.' -Stage $Stage
            }
            $requestHeaders['Authorization'] = "Bearer $($token.AccessToken)"
        } else {
            Stop-PDGraphError -Message 'Refusing to send a Graph bearer token to a non-Graph host. Storage (SAS) requests must be sent without authorization.' -Stage $Stage
        }
    }

    $request = @{
        Method      = $Method
        Uri         = $target
        Headers     = $requestHeaders
        TimeoutSec  = [int]$script:PDGraph.RequestTimeoutSec
        ContentType = $null
        BodyBytes   = $null
    }

    if ($null -ne $Body) {
        $json = $Body
        if (($Body -is [hashtable]) -or ($Body -is [System.Collections.IDictionary]) -or ($Body -is [Object[]])) {
            $json = ConvertTo-PDGraphJson -InputObject $Body
        }
        $request['BodyBytes']   = [System.Text.Encoding]::UTF8.GetBytes([string]$json)
        $request['ContentType'] = 'application/json; charset=utf-8'
    }

    if (-not $requestHeaders.ContainsKey('Accept')) { $requestHeaders['Accept'] = 'application/json' }
    $request['Headers'] = $requestHeaders

    $response = Send-PDGraphRequest -Request $request -RetryMode $RetryMode -Stage $Stage -Description $Description

    if ($response.StatusCode -eq 204) { return $null }
    if ([string]::IsNullOrWhiteSpace($response.Body)) { return $null }

    try {
        return ($response.Body | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        # Not JSON (a plain-text or HTML body). Return the raw body so callers can decide.
        return $response.Body
    }
}

function Get-PDGraphItems {
    <#
        .SYNOPSIS
        Normalizes a Graph collection payload into a flat array of items, identically on
        Windows PowerShell 5.1 and PowerShell 7.

        .DESCRIPTION
        5.1 emits a top-level JSON array from ConvertFrom-Json as a single Object[], while 7
        enumerates it. Anything that counts or matches collection members must come through
        here, or duplicate-app and category lookups silently see one odd element on 5.1 instead
        of N items. A string is one item, never a character stream.

        Callers still wrap the call in @() when they need array semantics for a single-item
        result, which is ordinary PowerShell.
    #>
    param( [AllowNull()][object]$Payload )

    $items = @()
    if ($null -eq $Payload) { return $items }

    $source = $Payload
    try {
        if ($Payload -isnot [string]) {
            $valueMember = $Payload.PSObject.Properties['value']
            if ($null -ne $valueMember) { $source = $valueMember.Value }
        }
    } catch { }

    if ($null -eq $source) { return $items }

    foreach ($item in $source) {
        if ($null -ne $item) { $items += $item }
    }

    return $items
}

function Get-PDGraphCollection {
    <#
        .SYNOPSIS
        Collects every value across a Graph collection and its @odata.nextLink pages.
        Each nextLink is verified to be an https Graph URL before it is followed, and
        authorization is therefore only ever forwarded to Graph (spec 11.1).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][object]$AuthContext,
        [string]$Stage,
        [int]$MaxPages = 200
    )

    $values  = @()
    $target  = $Path
    $pages   = 0

    while ($true) {
        $pages++
        if ($pages -gt $MaxPages) {
            Stop-PDGraphError -Message "A Graph collection did not finish after $MaxPages pages; refusing to continue." -Stage $Stage
        }

        if ($target -match '^https?://') {
            if (-not (Test-PDGraphUrlIsGraph -Url $target)) {
                Stop-PDGraphError -Message 'A Graph collection returned a pagination link that is not an https Graph URL, so it was not followed.' -Stage $Stage
            }
        }

        $page = Invoke-PDGraphRequest -Method Get -Uri $target -AuthContext $AuthContext -RetryMode 'Read' -Stage $Stage -Description 'collection page'

        if ($null -eq $page) { break }

        if ($page -is [string]) {
            $values += $page
            break
        }

        try {
            foreach ($item in (Get-PDGraphItems -Payload $page)) { $values += $item }
        } catch {
            $values += $page
        }

        $next = $null
        try {
            if ($page.PSObject.Properties['@odata.nextLink']) { $next = [string]$page.'@odata.nextLink' }
        } catch { }

        if ([string]::IsNullOrWhiteSpace($next)) { break }
        $target = $next
    }

    return $values
}
