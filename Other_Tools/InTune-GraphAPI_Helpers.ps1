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
      - Read-only .intunewin package inspection (metadata + encrypted payload, never executed)
      - The Win32 app creation payload, group resolution, duplicate and category lookups
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

        # Intune's built-in assignment targets, typed as commands so they can never collide with
        # a real group's display name. The key is the lower-cased command; Id is what flows through
        # review -> execution -> read-back in place of a group object id.
        BuiltInTargets    = @{
            '/alldevices' = @{ Id = '/AllDevices'; DisplayName = 'All devices (built-in Intune target)'; ODataType = '#microsoft.graph.allDevicesAssignmentTarget' }
            '/allusers'   = @{ Id = '/AllUsers';   DisplayName = 'All users (built-in Intune target)';   ODataType = '#microsoft.graph.allLicensedUsersAssignmentTarget' }
        }
        GraphServiceAppId = '00000003-0000-0000-c000-000000000000'
        AppDisplayName    = 'PowerDeploy Intune Upload'

        # --- Retry / timing policy (spec 11.1) ---
        RequestTimeoutSec      = 60
        MaxAttempts            = 5
        MaxRetryDelaySec       = 30
        BaseRetryDelaySec      = 1
        PollDeadlineSec        = 600    # per polling stage
        PropagationDeadlineSec = 300    # token/permission propagation after provisioning (a brand-new secret can take minutes)
        StorageBlockBytes      = 4194304  # 4 MiB
        PollIntervalMs          = 2000   # gap between two reads of a pending service state
        StorageRenewMarginSec   = 300    # renew a SAS this close to its expiry, not at 0
        MaxStorageRenewals      = 3      # renewals allowed for one content file
        StorageBlockIdWidth     = 6      # Azure requires every block id in a blob to be the same length
        StorageRenewCheckBlocks = 20     # how often the SAS expiry is re-checked during an upload

        # --- Win32 content workflow shapes (spec 10.3) ---
        Win32AppCast      = 'microsoft.graph.win32LobApp'
        AssignActionName  = 'microsoft.graph.assign'
        CommitActionName  = 'microsoft.graph.commit'
        RenewUploadAction = 'microsoft.graph.renewUpload'
        RenewUploadBody   = @{
            # NOT SENT (2026-10-19). Microsoft documents renewUpload as "Do not supply a request
            # body", and the live service refuses this one with HTTP 400 ModelValidationFailure
            # ("The annotation 'odata.type' was found ... not expected"): 30 of 70 printers in the
            # first bulk run failed on it. The uploader now posts the action with no body; this
            # definition is kept only as the record of what was tried.
            # The body for the renewUpload action. 'fileForceRenewedContentVersionStorage'
            # must be $true here: this code renews because the previous SAS expired, possibly
            # after blocks were already written, and a fresh container is the only target those
            # blocks cannot be assumed to live in. Spec 14 live acceptance confirms the action
            # name and this property against the service.
            '@odata.type'                          = '#microsoft.graph.renewUpload'
            fileForceRenewedContentVersionStorage  = $true
        }
        PortalAppsUrl     = 'https://endpoint.microsoft.com'

        # --- Credentials ---
        CredentialSubPath         = 'PowerDeploy\GraphUpload'
        CredentialFileName        = 'credential.clixml'
        CredentialSchema          = 1
        NearExpiryWarningDays     = 30
        DefaultSecretLifetimeDays = 180

        # --- Locking (spec 7.3: serialize concurrent credential changes) ---
        LockWaitSeconds  = 10
        LockStaleSeconds = 300

        # --- Provisioning (spec 7.1, 7.2, 7.4) ---
        MgModuleName           = 'Microsoft.Graph.Authentication'
        MgModuleInstallHint    = 'Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
        ProvisioningScopes     = @('Application.ReadWrite.All')
        ConsentScope           = 'AppRoleAssignment.ReadWrite.All'
        ApplicationsPath       = '/v1.0/applications'
        ServicePrincipalsPath  = '/v1.0/servicePrincipals'
        # The "small Intune read" of the connection test (spec 7.2). Deliberately the same
        # collection the uploader works on, because that is the permission being tested.
        ConnectionTestPath     = '/beta/deviceAppManagement/mobileApps?$top=1&$select=id,displayName'
        SecretLabelDateFormat  = 'yyyy-MM-dd'
        SecretEndDateFormat    = 'yyyy-MM-ddTHH:mm:ssZ'
        # Entra itself refuses what the tenant will not allow; these bounds exist to stop an
        # operator typing 99999 by accident, not to out-guess the service.
        MaxSecretLifetimeDays  = 730
        WarnSecretLifetimeDays = 365
        PropagationIntervalMs  = 5000

        # --- Misc ---
        MaxErrorBodyChars = 900

        # --- Graph paths used by this feature (spec 10) ---
        MobileAppsPath = '/beta/deviceAppManagement/mobileApps'
        AppCategoriesPath = '/beta/deviceAppManagement/mobileAppCategories'
        GroupsPath     = '/v1.0/groups'

        # --- Win32 package reading (spec 10.1) ---
        IntuneWinMetadataEntry = 'IntuneWinPackage/Metadata/Detection.xml'
        IntuneWinContentFolder = 'IntuneWinPackage/Contents/'
        # Detection.xml is a few hundred bytes in real packages. The cap stops a hostile archive
        # from persuading us to hold hundreds of megabytes of "metadata" in memory.
        MaxDetectionXmlBytes   = 1048576
        PackageCopyBufferSize  = 81920
        # Only used when an archive entry declares no length at all: a ceiling, not a product
        # limit, so a lying archive cannot make us copy the disk into a temp file.
        PackageStreamCeilingBytes = 2147483648

        # Test seam: script block receiving the request hashtable, returning a normalized
        # response hashtable (see Invoke-PDGraphTransport). Null in production.
        TestTransport = $null

        # Test seam for the OTHER network boundary: the temporary interactive administrator
        # session used by provisioning (see Invoke-PDMgChannelAction). It is separate from
        # TestTransport on purpose - spec 7.1 forbids the upload identity from holding the
        # application-management permissions that provisioning needs, so the two channels carry
        # different identities and cannot share a seam. Null in production.
        MgChannel = $null

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
            # PSObject.Properties also exposes .NET members the exception happens to have:
            # System.Net.WebException.Status is a WebExceptionStatus enum, not an HTTP status
            # code, and treating it as one made a dead connection look like a 5xx answer. Only
            # a real number counts; anything else stays 0, which is what "no HTTP status
            # reached us" means here.
            $value = $member.Value
            if ($name -eq 'Status') {
                $numeric = 0
                if (-not [int]::TryParse([string]$value, [ref]$numeric)) { continue }
                $info[$name] = $numeric
                continue
            }

            if ($name -eq 'PDSanitized') { $info.Sanitized = [bool]$value }
            else { $info[$name] = $value }
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
        Stop-PDGraphError -Message ("No upload credential is stored for this Windows account. Run the Setup menu function InTuneAPI--Setup-and-Manage to create or enter one. Expected: $resolved") -Stage 'Credential'
    }

    $raw = $null
    try {
        $raw = Import-Clixml -LiteralPath $resolved -ErrorAction Stop
    } catch {
        $reason = ([string]$_.Exception.Message)
        if ($reason -match '(?i)decrypt|cryptograph|key|padding|mac|bad data|not valid|rmtp|protected') {
            Stop-PDGraphError -Message 'The stored credential could not be decrypted by this Windows account. It was saved by a different user or machine; re-enter it through InTuneAPI--Setup-and-Manage.' -Stage 'Credential'
        }
        Stop-PDGraphError -Message "The stored credential file could not be read and may be corrupt. Re-enter it through InTuneAPI--Setup-and-Manage. ($reason)" -Stage 'Credential'
    }

    $problem = $null
    $credential = ConvertFrom-PDGraphCredentialFile -Raw $raw -Problem ([ref]$problem)

    if ($null -eq $credential) {
        Stop-PDGraphError -Message "The stored credential file is not usable: $problem Re-enter it through InTuneAPI--Setup-and-Manage." -Stage 'Credential'
    }

    $warnings = @()

    if ($credential.SecretExpiresOn -le [System.DateTimeOffset]::UtcNow) {
        $shown = $credential.SecretExpiresOn.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
        Stop-PDGraphError -Message "The stored application secret expired on $shown. Rotate it with InTuneAPI--Setup-and-Manage." -Stage 'Credential'
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
                # $null would reach .NET as "" (the path is empty), so every overwrite would fail.
                [System.IO.File]::Replace($tempPath, $resolved, [NullString]::Value)
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

    # PowerShell 7: HttpResponseException carries the HttpResponseMessage. A 5.1 WebException ALSO
    # has a Response property, so it must be excluded here: taking this branch on 5.1 read the
    # status but took the body from ErrorDetails (empty for real Graph errors), and the stream read
    # below never ran - every live 5.1 refusal lost Graph's reason (first live run, 2026-10-12).
    try {
        if ($null -ne $inner -and -not ($inner -is [System.Net.WebException]) -and $inner.PSObject.Properties['Response'] -and ($null -ne $inner.Response)) {
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
                    # Rewind when possible, so an earlier reader cannot leave this one at the end.
                    if ($stream.CanSeek) { $stream.Position = 0 }
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
        # The seam has to be the seam. A test transport that throws a raw .NET exception - a
        # connection that died mid-response, which is exactly what a lost create response looks
        # like - must be described the same way Invoke-WebRequest failures are below, or the
        # tests exercise an error shape production can never produce and the retry/lost-request
        # logic goes untested.
        try {
            return (& $script:PDGraph.TestTransport $Request)
        } catch {
            return (Get-PDGraphNormalizedResponse -ErrorRecord $_)
        }
    }

    # Windows PowerShell 5.1 draws a progress bar for every Invoke-WebRequest (the flashing box
    # seen during the first live upload), which also slows large transfers badly. Local to this
    # function, so the caller's preference is untouched.
    $ProgressPreference = 'SilentlyContinue'

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

    # Named honestly: the same core serves Graph, the token endpoint, and blob storage, and
    # telling the operator that Graph refused a storage upload sends them hunting the wrong tenant.
    $service = 'Microsoft Graph'
    try {
        $parsedTarget = $null
        if ([System.Uri]::TryCreate([string]$Request.Uri, [System.UriKind]::Absolute, [ref]$parsedTarget)) {
            if ($parsedTarget.Host -and ($parsedTarget.Host -ne [string]$script:PDGraph.GraphHost)) {
                $service = "the service at $($parsedTarget.Host)"
            }
        }
    } catch { }

    $headline = "The request ($target) was refused by $service."
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
            elseif ($Payload -is [hashtable]) {
                # A hashtable has no adapter properties, so the "value" lookup above finds
                # nothing and the enumeration below would walk the hashtable's KEYS - silently
                # counting the fields of one object as the items of a collection. Unwrap a
                # { value = ... } envelope, and treat any other hashtable as the single item
                # it is.
                if ($Payload.ContainsKey('value')) { $source = $Payload['value'] }
                else { return @($Payload) }
            }
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
        [int]$MaxPages = 200,
        [string]$Description = 'collection page'
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

        $page = Invoke-PDGraphRequest -Method Get -Uri $target -AuthContext $AuthContext -RetryMode 'Read' -Stage $Stage -Description $Description

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

# ---------------------------------------------------------------------------
# Small shared accessors (files, XML, Graph object shapes)
# ---------------------------------------------------------------------------

function Get-PDGraphPropertyValue {
    <#
        .SYNOPSIS
        Reads one property from a Graph object, a hashtable, or a PSCustomObject without
        throwing when it is absent.

        .DESCRIPTION
        ConvertFrom-Json shapes differ between engines and some payloads arrive as hashtables
        (retries, tests, locally-built bodies). Absent and null are both $null here; use
        -Contains only to tell "missing" from "present but empty" when it actually matters.
    #>
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Object) { return $null }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if (([string]$key) -eq $Name) { return $Object[$key] }
        }
        return $null
    }

    try {
        $member = $Object.PSObject.Properties[$Name]
        if ($null -ne $member) { return $member.Value }
    } catch { }

    return $null
}

function Get-PDResolvedFilePath {
    <#
        .SYNOPSIS
        Resolves a local path to an absolute existing file, or throws a sanitized error that
        names the input. -AllowMissing normalizes without requiring existence.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Stage,
        [string]$Label = 'file',
        [switch]$AllowMissing
    )

    $trimmed = Get-PDGraphTrimmedText -Value $Path
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        Stop-PDGraphError -Message "No $Label path was supplied." -Stage $Stage
    }

    $item = Get-Item -LiteralPath $trimmed -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        if ($AllowMissing) {
            try { return [System.IO.Path]::GetFullPath($trimmed) } catch {
                Stop-PDGraphError -Message "The $Label path '$trimmed' is not a usable local path." -Stage $Stage
            }
        }
        Stop-PDGraphError -Message "The $Label '$trimmed' was not found." -Stage $Stage
    }

    if ($item.PSIsContainer) {
        Stop-PDGraphError -Message "The $Label '$trimmed' is a folder, not a file." -Stage $Stage
    }

    return $item.FullName
}

function Get-PDTextFileContents {
    <#
        .SYNOPSIS
        Reads a text file as a string, decoding from a byte-order mark when one is present.

        .DESCRIPTION
        Deliberately not Get-Content: the default encoding differs between 5.1 (ANSI) and 7
        (UTF-8), and a silently mis-decoded install command is worse than a loud failure. A BOM
        is consumed by the decoder and never reaches the returned text, because a BOM inside an
        Intune command line would break the installer.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Stage
    )

    $full = Get-PDResolvedFilePath -Path $Path -Stage $Stage -Label 'text file'

    try {
        $bytes = [System.IO.File]::ReadAllBytes($full)
    } catch {
        Stop-PDGraphError -Message "The file '$full' could not be read." -Stage $Stage -Detail (($_.Exception.Message -replace '\s+', ' '))
    }

    if ($null -eq $bytes) { return '' }

    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    $offset   = 0

    if (($bytes.Length -ge 3) -and ($bytes[0] -eq 0xEF) -and ($bytes[1] -eq 0xBB) -and ($bytes[2] -eq 0xBF)) {
        $offset = 3
    } elseif (($bytes.Length -ge 2) -and ($bytes[0] -eq 0xFF) -and ($bytes[1] -eq 0xFE)) {
        $encoding = [System.Text.Encoding]::Unicode
        $offset   = 2
    } elseif (($bytes.Length -ge 2) -and ($bytes[0] -eq 0xFE) -and ($bytes[1] -eq 0xFF)) {
        $encoding = [System.Text.Encoding]::BigEndianUnicode
        $offset   = 2
    }

    try {
        return $encoding.GetString($bytes, $offset, ($bytes.Length - $offset))
    } catch {
        Stop-PDGraphError -Message "The file '$full' is not readable as text." -Stage $Stage -Detail (($_.Exception.Message -replace '\s+', ' '))
    }
}

function Get-PDCommandFileText {
    <#
        .SYNOPSIS
        Reads an install/uninstall command file the way Intune needs it (spec 9.2 step 2).

        .DESCRIPTION
        Strips trailing CR/LF only - quoting and meaningful inner spaces are preserved - and
        rejects an empty file or a command with an embedded newline, because a multi-line value
        is not a command line and Intune will not run it. Nothing is ever truncated, and no
        length limit is imposed: the service maximum is not documented (spec 14.3).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Stage,
        [string]$Label = 'command file'
    )

    $full = Get-PDResolvedFilePath -Path $Path -Stage $Stage -Label $Label
    $text = Get-PDTextFileContents -Path $full -Stage $Stage

    $trimmed = $text -replace '[\r\n]+$', ''

    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        Stop-PDGraphError -Message "The $Label '$full' is empty. A command is required." -Stage $Stage
    }

    if ($trimmed.Contains("`r") -or $trimmed.Contains("`n")) {
        Stop-PDGraphError -Message "The $Label '$full' contains more than one line. An Intune command must be a single line; put extra steps in the detection or packaging layer instead." -Stage $Stage
    }

    return $trimmed
}

function Get-PDDetectionScriptBase64 {
    <#
        .SYNOPSIS
        Base64 of the detection script's raw bytes (spec 9.2 step 3).

        .DESCRIPTION
        The bytes are taken exactly as stored: no transcoding, no BOM removal, no re-encoding, so
        what Intune runs is byte-for-byte the script that was generated and tested. Empty files
        are refused because a detection rule that detects nothing installs nothing verifiable.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Stage
    )

    $full = Get-PDResolvedFilePath -Path $Path -Stage $Stage -Label 'detection script'

    try {
        $bytes = [System.IO.File]::ReadAllBytes($full)
    } catch {
        Stop-PDGraphError -Message "The detection script '$full' could not be read." -Stage $Stage -Detail (($_.Exception.Message -replace '\s+', ' '))
    }

    if (($null -eq $bytes) -or ($bytes.Length -eq 0)) {
        $bytes = [byte[]]@()
    }

    if ($bytes.Length -eq 0) {
        Stop-PDGraphError -Message "The detection script '$full' is empty." -Stage $Stage
    }

    return [pscustomobject]@{
        Path   = $full
        Bytes  = $bytes.Length
        Base64 = [System.Convert]::ToBase64String($bytes)
        Sha256 = (Get-PDStreamSha256 -Bytes $bytes)
    }
}

function Get-PDStreamSha256 {
    <#
        .SYNOPSIS
        SHA-256 of an in-memory byte array as lowercase hex.
    #>
    param([AllowNull()][byte[]]$Bytes)

    if (($null -eq $Bytes) -or ($Bytes.Length -eq 0)) { $Bytes = [byte[]]@() }

    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $hasher.ComputeHash($Bytes)
        return ([System.BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}

function Get-PDFileSha256 {
    <#
        .SYNOPSIS
        SHA-256 of a file as lowercase hex, without taking an exclusive lock.

        .DESCRIPTION
        Setup compares these hashes between the dry run and the real run so a file that changed
        while the operator was reviewing the summary forces a fresh review (spec 5.1).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Stage
    )

    $full   = Get-PDResolvedFilePath -Path $Path -Stage $Stage -Label 'file'
    $stream = $null
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::Open($full, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $hash   = $hasher.ComputeHash($stream)
        return ([System.BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    } catch {
        Stop-PDGraphError -Message "The file '$full' could not be hashed." -Stage $Stage -Detail (($_.Exception.Message -replace '\s+', ' '))
    } finally {
        $hasher.Dispose()
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

# ---------------------------------------------------------------------------
# .intunewin package reading (spec 10.1)
# ---------------------------------------------------------------------------

function Test-PDArchiveEntryName {
    <#
        .SYNOPSIS
        True when an archive entry name is a safe relative path.

        .DESCRIPTION
        Entry names come from an untrusted file and must never influence where bytes are written.
        Rejected: rooted paths, drive letters, UNC, NTFS stream syntax, control characters, and
        any '..' segment.
    #>
    param([AllowNull()][string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -match '[\x00-\x1F]') { return $false }

    $normalized = $Name.Replace('\', '/')

    if ($normalized.StartsWith('/')) { return $false }
    if ($normalized -match '^[A-Za-z]:') { return $false }
    if ($normalized.IndexOf(':') -ge 0) { return $false }
    if ($normalized.EndsWith('/')) { return $false }

    foreach ($segment in $normalized.Split('/')) {
        if ($segment -eq '..') { return $false }
    }

    return $true
}

function Get-PDXmlElementNode {
    <#
        .SYNOPSIS
        First child element with the given local name, or $null.

        .DESCRIPTION
        Deliberately walks ChildNodes instead of using $Node.$Name: for an XmlElement, $Node.Name
        is the element's own tag name, so reading <Name> that way silently returns the wrong
        thing. LocalName comparison also keeps this working if a future tool emits a namespace.
    #>
    param(
        [AllowNull()][object]$Node,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Node) { return $null }

    $children = $null
    try { $children = $Node.ChildNodes } catch { return $null }
    if ($null -eq $children) { return $null }

    foreach ($child in $children) {
        if ($child.NodeType -eq 'Element' -and ($child.LocalName -eq $Name)) { return $child }
    }
    return $null
}

function Get-PDXmlElementText {
    <#
        .SYNOPSIS
        Trimmed text of a child element, or an empty string when it is absent. Never throws.
    #>
    param(
        [AllowNull()][object]$Node,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $found = Get-PDXmlElementNode -Node $Node -Name $Name
    if ($null -eq $found) { return '' }

    try { return ([string]$found.InnerText).Trim() } catch { return '' }
}

function Read-PDIntuneWinPackage {
    <#
        .SYNOPSIS
        Inspects an .intunewin package: reads Detection.xml and copies the encrypted payload to a
        temp file. Read-only - the package is never executed, never re-encrypted, and its entry
        names are never used as output paths.

        .DESCRIPTION
        Requirements (spec 10.1): one metadata/payload pairing and safe archive paths. Any
        ambiguity is a failure, not something to guess at, because a wrong payload uploads the
        wrong product to every device.

        ApplicationInfo/UnencryptedContentSize is the declared *unencrypted* size; the payload in
        the archive is larger than that (envelope overhead), so 'size' comes from the XML and
        'sizeEncrypted' is always measured from the copied payload.

        .OUTPUTS
        Hashtable:
          SourcePath, SourceBytes, ToolVersion, PackageName, FileName, SetupFile,
          UnencryptedContentSize, ContentEntry, PayloadPath, PayloadBytes, EncryptionInfo,
          TempDirectory, TempDirectoryOwned

        EncryptionInfo carries key material. It is handed to the commit step only, and is never
        logged, returned in an upload result, or serialized.

        .PARAMETER TempDirectory
        Directory for the extracted payload. Created when missing. The caller owns deletion;
        TempDirectoryOwned says whether this call created it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$IntuneWinPath,
        [Parameter(Mandatory = $true)][string]$TempDirectory,
        [string]$Stage = 'Preflight'
    )

    # Loaded lazily so that importing this library stays free of side effects.
    if (-not ('System.IO.Compression.ZipArchiveMode' -as [type])) {
        foreach ($assembly in @('System.IO.Compression', 'System.IO.Compression.FileSystem')) {
            try { Add-Type -AssemblyName $assembly -ErrorAction Stop } catch { }
        }
    }
    if (-not ('System.IO.Compression.ZipArchiveMode' -as [type])) {
        Stop-PDGraphError -Message 'This system cannot open ZIP archives (System.IO.Compression is unavailable), so the .intunewin package cannot be inspected.' -Stage $Stage
    }

    $source = Get-PDResolvedFilePath -Path $IntuneWinPath -Stage $Stage -Label 'IntuneWin package'

    # --- The temp directory: created if missing, resolved, and verified to be a directory ---
    $tempRequested = Get-PDGraphTrimmedText -Value $TempDirectory
    if ([string]::IsNullOrWhiteSpace($tempRequested)) {
        Stop-PDGraphError -Message 'A temp directory for the package payload is required.' -Stage $Stage
    }

    $tempExisted = $false
    $tempItem    = Get-Item -LiteralPath $tempRequested -ErrorAction SilentlyContinue
    if ($null -ne $tempItem) {
        if (-not $tempItem.PSIsContainer) {
            Stop-PDGraphError -Message "The temp directory '$tempRequested' exists but is not a folder." -Stage $Stage
        }
        $tempExisted = $true
    } else {
        try { New-Item -ItemType Directory -Path $tempRequested -Force -ErrorAction Stop | Out-Null } catch {
            Stop-PDGraphError -Message "The temp directory '$tempRequested' could not be created." -Stage $Stage -Detail (($_.Exception.Message -replace '\s+', ' '))
        }
    }

    $tempDir = $null
    try { $tempDir = (Get-Item -LiteralPath $tempRequested).FullName } catch {
        Stop-PDGraphError -Message "The temp directory '$tempRequested' could not be resolved." -Stage $Stage
    }

    $fileStream = $null
    $archive    = $null
    $payloadPath = $null

    try {
        try {
            $fileStream = [System.IO.File]::Open($source, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            $archive    = New-Object System.IO.Compression.ZipArchive($fileStream, [System.IO.Compression.ZipArchiveMode]::Read)
        } catch {
            Stop-PDGraphError -Message "The package '$source' could not be opened as a ZIP archive. Re-create it with IntuneWinAppUtil." -Stage $Stage -Detail (($_.Exception.Message -replace '\s+', ' '))
        }

        # --- Every entry name is validated before any of them is used ---
        $entries = @()
        foreach ($entry in $archive.Entries) {
            if (-not (Test-PDArchiveEntryName -Name $entry.FullName)) {
                Stop-PDGraphError -Message ("The package '{0}' contains the archive entry '{1}', whose path is not a safe relative path. Nothing was extracted." -f $source, $entry.FullName) -Stage $Stage
            }

            $normalized = ([string]$entry.FullName).Replace('\', '/')
            $leaf       = $normalized
            $slash      = $leaf.LastIndexOf('/')
            if ($slash -ge 0) { $leaf = $leaf.Substring($slash + 1) }

            $entries += [pscustomobject]@{ Entry = $entry; Path = $normalized; Leaf = $leaf }
        }

        # --- Metadata entry ---
        $metadataPath = [string]$script:PDGraph.IntuneWinMetadataEntry
        $metadata     = @($entries | Where-Object { $_.Path -ieq $metadataPath })

        if (@($metadata).Count -eq 0) {
            # Tolerate a different top-level folder, but never a second Detection.xml.
            $fallback = @($entries | Where-Object { $_.Leaf -ieq 'Detection.xml' })
            if (@($fallback).Count -eq 1) {
                $metadata = $fallback
            } elseif (@($fallback).Count -gt 1) {
                Stop-PDGraphError -Message ("The package contains {0} Detection.xml entries, so there is no single source of truth for the payload." -f @($fallback).Count) -Stage $Stage
            }
        }

        if (@($metadata).Count -ne 1) {
            Stop-PDGraphError -Message ("The package has no '{0}' entry, so the payload name, size, and encryption information are unknown." -f $metadataPath) -Stage $Stage
        }

        $metaEntry = $metadata[0].Entry
        if ($metaEntry.Length -gt [long]$script:PDGraph.MaxDetectionXmlBytes) {
            Stop-PDGraphError -Message ("Detection.xml is {0} bytes, which is more than the {1} byte limit for package metadata. The package looks malformed." -f $metaEntry.Length, $script:PDGraph.MaxDetectionXmlBytes) -Stage $Stage
        }

        $xmlText = ''
        $reader  = $null
        try {
            $reader  = New-Object System.IO.StreamReader($metaEntry.Open(), [System.Text.Encoding]::UTF8, $true)
            $xmlText = $reader.ReadToEnd()
        } catch {
            Stop-PDGraphError -Message 'Detection.xml could not be read from the package.' -Stage $Stage -Detail (($_.Exception.Message -replace '\s+', ' '))
        } finally {
            if ($null -ne $reader) { $reader.Dispose() }
        }

        $xml = $null
        try { $xml = [xml]$xmlText } catch {
            Stop-PDGraphError -Message 'Detection.xml is not valid XML, so the package cannot be used. Re-create it with IntuneWinAppUtil.' -Stage $Stage
        }

        $root = $null
        try { $root = $xml.DocumentElement } catch { }
        if (($null -eq $root) -or ($root.LocalName -ne 'ApplicationInfo')) {
            Stop-PDGraphError -Message 'Detection.xml does not have an ApplicationInfo root element, so it is not an IntuneWin package.' -Stage $Stage
        }

        $packageName = Get-PDXmlElementText -Node $root -Name 'Name'
        $fileName    = Get-PDXmlElementText -Node $root -Name 'FileName'
        $setupFile   = Get-PDXmlElementText -Node $root -Name 'SetupFile'
        $sizeText    = Get-PDXmlElementText -Node $root -Name 'UnencryptedContentSize'

        $toolVersion = ''
        try { $toolVersion = [string]$root.GetAttribute('ToolVersion') } catch { }

        if ([string]::IsNullOrWhiteSpace($fileName)) {
            Stop-PDGraphError -Message 'Detection.xml has no FileName, so the content file name is unknown.' -Stage $Stage
        }
        if (($fileName.Contains('/')) -or ($fileName.Contains('\')) -or ($fileName -eq '..')) {
            Stop-PDGraphError -Message "Detection.xml FileName '$fileName' is not a bare file name, so it cannot be used as the Intune content file name." -Stage $Stage
        }
        if ([string]::IsNullOrWhiteSpace($setupFile)) {
            Stop-PDGraphError -Message 'Detection.xml has no SetupFile, so Intune would not know what to run.' -Stage $Stage
        }

        $unencryptedSize = [long]0
        if ((-not [long]::TryParse($sizeText, [ref]$unencryptedSize)) -or ($unencryptedSize -le 0)) {
            Stop-PDGraphError -Message "Detection.xml UnencryptedContentSize '$sizeText' is not a positive size, so the content file size cannot be reported to Intune." -Stage $Stage
        }

        # --- Encryption info: presence only is checked here; values are never displayed ---
        $encNode = Get-PDXmlElementNode -Node $root -Name 'EncryptionInfo'
        if ($null -eq $encNode) {
            Stop-PDGraphError -Message 'Detection.xml has no EncryptionInfo, so this package can never be committed to Intune.' -Stage $Stage
        }

        $encryption = @{}
        $missingFields = @()
        foreach ($field in @('EncryptionKey', 'MacKey', 'InitializationVector', 'Mac', 'ProfileIdentifier', 'FileDigest', 'FileDigestAlgorithm')) {
            $value = Get-PDXmlElementText -Node $encNode -Name $field
            if ([string]::IsNullOrWhiteSpace($value)) {
                $missingFields += $field
            } else {
                $encryption[$field] = $value
            }
        }
        if ($missingFields.Count -gt 0) {
            Stop-PDGraphError -Message ("Detection.xml EncryptionInfo is missing {0}. These values are never guessed." -f (($missingFields | ForEach-Object { "'$_'" }) -join ', ')) -Stage $Stage
        }

        # --- Exactly one content entry, matching the metadata ---
        $contentFolder = [string]$script:PDGraph.IntuneWinContentFolder
        $contents      = @($entries | Where-Object { $_.Path.StartsWith($contentFolder, [System.StringComparison]::OrdinalIgnoreCase) })

        if (@($contents).Count -eq 0) {
            Stop-PDGraphError -Message ("The package has no entry under '{0}', so there is no payload to upload." -f $contentFolder) -Stage $Stage
        }
        if (@($contents).Count -gt 1) {
            $listed = (@($contents) | ForEach-Object { $_.Path }) -join ', '
            Stop-PDGraphError -Message ("The package has {0} entries under '{1}' ({2}). Spec 10.1 requires one unambiguous metadata/payload pairing, so nothing was guessed." -f @($contents).Count, $contentFolder, $listed) -Stage $Stage
        }

        $content = @($contents)[0]
        if ($content.Leaf -ne $fileName) {
            Stop-PDGraphError -Message ("Detection.xml names the payload '{0}' but the package's content entry is '{1}'. The package is inconsistent, so it was not used." -f $fileName, $content.Leaf) -Stage $Stage
        }

        # --- Copy the payload to a name we chose, inside the directory we verified ---
        $payloadPath = Join-Path $tempDir ('intunewin-payload-' + [guid]::NewGuid().ToString('N') + '.bin')

        $declared = [long]$content.Entry.Length
        $ceiling  = [long]$script:PDGraph.PackageStreamCeilingBytes
        $written  = [long]0

        $payloadIn  = $null
        $payloadOut = $null
        try {
            $payloadIn  = $content.Entry.Open()
            $payloadOut = [System.IO.File]::Open($payloadPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)

            $buffer = New-Object byte[] ([int]$script:PDGraph.PackageCopyBufferSize)
            while ($true) {
                $read = $payloadIn.Read($buffer, 0, $buffer.Length)
                if ($read -le 0) { break }

                $written += $read

                # A declared length is a promise. Exceeding it means the archive is lying about
                # its contents (a classic archive-bomb shape), so stop instead of filling the disk.
                if (($declared -gt 0) -and ($written -gt $declared)) {
                    Stop-PDGraphError -Message ("The payload entry declared {0} bytes but produced more. The package is corrupt or tampered with." -f $declared) -Stage $Stage
                }
                if (($declared -le 0) -and ($written -gt $ceiling)) {
                    Stop-PDGraphError -Message ("The payload entry declared no size and exceeded {0} bytes. Refusing to continue." -f $ceiling) -Stage $Stage
                }

                $payloadOut.Write($buffer, 0, $read)
            }
        } catch {
            if (Test-Path -LiteralPath $payloadPath) {
                Remove-Item -LiteralPath $payloadPath -Force -ErrorAction SilentlyContinue
            }
            $payloadPath = $null

            # A tamper/corruption error from the loop above is already the clearest possible
            # wording; anything else (disk full, locked file) is wrapped with the same care.
            $alreadySanitized = $false
            try { $alreadySanitized = ($null -ne $_.Exception.PSObject.Properties['PDSanitized']) } catch { }
            if ($alreadySanitized) { throw }

            Stop-PDGraphError -Message 'The encrypted payload could not be extracted from the package. Any partial temp file was deleted.' -Stage $Stage -Detail (($_.Exception.Message -replace '\s+', ' '))
        } finally {
            if ($null -ne $payloadOut) { $payloadOut.Dispose() }
            if ($null -ne $payloadIn) { $payloadIn.Dispose() }
        }

        if (($written -le 0) -or (($declared -gt 0) -and ($written -ne $declared))) {
            if (Test-Path -LiteralPath $payloadPath) {
                Remove-Item -LiteralPath $payloadPath -Force -ErrorAction SilentlyContinue
            }
            $payloadPath = $null
            Stop-PDGraphError -Message ("The encrypted payload should be {0} bytes but {1} were read. The package is incomplete." -f $declared, $written) -Stage $Stage
        }

        # Belt and braces: the payload must still be inside the requested directory.
        $resolvedPayload = [System.IO.Path]::GetFullPath($payloadPath)
        if (-not $resolvedPayload.StartsWith(($tempDir + [System.IO.Path]::DirectorySeparatorChar), [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedPayload -Force -ErrorAction SilentlyContinue
            $payloadPath = $null
            Stop-PDGraphError -Message 'The extracted payload resolved outside the requested temp directory, so it was deleted.' -Stage $Stage
        }

        $sourceBytes = 0
        try { $sourceBytes = (Get-Item -LiteralPath $source).Length } catch { }

        return @{
            SourcePath             = $source
            SourceBytes            = $sourceBytes
            ToolVersion            = $toolVersion
            PackageName            = $packageName
            FileName               = $fileName
            SetupFile              = $setupFile
            UnencryptedContentSize = $unencryptedSize
            ContentEntry           = $content.Path
            PayloadPath            = $resolvedPayload
            PayloadBytes           = $written
            EncryptionInfo         = $encryption
            TempDirectory          = $tempDir
            TempDirectoryOwned     = (-not $tempExisted)
        }
    } finally {
        if ($null -ne $archive) { $archive.Dispose() }
        if ($null -ne $fileStream) { $fileStream.Dispose() }
    }
}

# ---------------------------------------------------------------------------
# Win32 app payload (spec 10.2)
# ---------------------------------------------------------------------------

function New-PDWin32AppPayload {
    <#
        .SYNOPSIS
        Builds the POST body for /beta/deviceAppManagement/mobileApps exactly as spec 10.2.

        .DESCRIPTION
        There is deliberately no way to pass owner, developer, allowedArchitectures,
        minimumSupportedWindowsRelease, detectionRules, activeInstallScript,
        activeUninstallScript, or any service-managed state field: this function is the only
        place the create payload is assembled, and it does not contain those keys.

        displayVersion is added only when a usable version exists (null, whitespace, and 'N/A'
        all count as missing).

        .PARAMETER FinalNotes
        Notes already passed through Complete-PDIntuneNotes, i.e. containing exactly one
        'Created:' timestamp. Pass the technical block only if the caller has not finalized it.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$DisplayName,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Description,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Publisher,
        [AllowEmptyString()][AllowNull()][string]$AppVersion,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$InstallCommand,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$UninstallCommand,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$DetectionBase64,
        [AllowEmptyString()][AllowNull()][string]$FinalNotes,
        [Parameter(Mandatory = $true)][object]$Package,
        [bool]$AllowAvailableUninstall = $false,
        [string]$Stage = 'Preflight'
    )

    $name      = Get-PDGraphTrimmedText -Value $DisplayName
    $publisher = Get-PDGraphTrimmedText -Value $Publisher
    $install   = Get-PDGraphTrimmedText -Value $InstallCommand
    $uninstall = Get-PDGraphTrimmedText -Value $UninstallCommand

    if ([string]::IsNullOrWhiteSpace($name))      { Stop-PDGraphError -Message 'DisplayName is required.' -Stage $Stage }
    if ([string]::IsNullOrWhiteSpace($publisher)) { Stop-PDGraphError -Message 'Publisher is required (PowerDeploy is the default).' -Stage $Stage }
    if ([string]::IsNullOrWhiteSpace($install))   { Stop-PDGraphError -Message 'The install command is required.' -Stage $Stage }
    if ([string]::IsNullOrWhiteSpace($uninstall)) { Stop-PDGraphError -Message 'The uninstall command is required.' -Stage $Stage }

    if ([string]::IsNullOrWhiteSpace($DetectionBase64)) {
        Stop-PDGraphError -Message 'A detection script (base64) is required; an app without detection cannot be verified.' -Stage $Stage
    }

    $decoded = $null
    try { $decoded = [System.Convert]::FromBase64String($DetectionBase64) } catch { }
    if (($null -eq $decoded) -or ($decoded.Length -eq 0)) {
        Stop-PDGraphError -Message 'The detection script did not base64-encode to anything usable.' -Stage $Stage
    }

    $packageFileName    = [string](Get-PDGraphPropertyValue -Object $Package -Name 'FileName')
    $packageSetupFile   = [string](Get-PDGraphPropertyValue -Object $Package -Name 'SetupFile')
    $packageUnencrypted = Get-PDGraphPropertyValue -Object $Package -Name 'UnencryptedContentSize'

    if ([string]::IsNullOrWhiteSpace($packageFileName)) {
        Stop-PDGraphError -Message 'Package metadata is missing FileName; read the package with Read-PDIntuneWinPackage first.' -Stage $Stage
    }
    if ([string]::IsNullOrWhiteSpace($packageSetupFile)) {
        Stop-PDGraphError -Message 'Package metadata is missing SetupFile; read the package with Read-PDIntuneWinPackage first.' -Stage $Stage
    }
    if ($null -eq $packageUnencrypted) {
        Stop-PDGraphError -Message 'Package metadata is missing UnencryptedContentSize; read the package with Read-PDIntuneWinPackage first.' -Stage $Stage
    }

    $payload = @{
        '@odata.type'                   = '#microsoft.graph.win32LobApp'
        displayName                     = $name
        description                     = [string]$Description
        publisher                       = $publisher
        notes                           = [string]$FinalNotes
        fileName                        = $packageFileName
        setupFilePath                   = $packageSetupFile
        installCommandLine              = $install
        uninstallCommandLine            = $uninstall
        applicableArchitectures         = 'x64,x86'
        minimumSupportedOperatingSystem = @{ v10_1607 = $true }
        allowAvailableUninstall         = [bool]$AllowAvailableUninstall
        installExperience               = @{
            '@odata.type'           = '#microsoft.graph.win32LobAppInstallExperience'
            runAsAccount           = 'system'
            deviceRestartBehavior  = 'allow'
            maxRunTimeInMinutes    = 15
        }
        rules                           = @(
            @{
                '@odata.type'           = '#microsoft.graph.win32LobAppPowerShellScriptRule'
                ruleType               = 'detection'
                scriptContent          = $DetectionBase64
                enforceSignatureCheck  = $false
                runAs32Bit             = $false
                operationType          = 'notConfigured'
                operator               = 'notConfigured'
            }
        )
        returnCodes                     = @(
            @{ returnCode = 0;    type = 'success' }
            @{ returnCode = 1707; type = 'success' }
            @{ returnCode = 3010; type = 'softReboot' }
            @{ returnCode = 1641; type = 'hardReboot' }
            @{ returnCode = 1618; type = 'retry' }
        )
    }

    $version = Get-PDGraphTrimmedText -Value $AppVersion -TreatNotApplicableAsMissing
    if (-not [string]::IsNullOrWhiteSpace($version)) {
        $payload['displayVersion'] = $version
    }

    return $payload
}

# ---------------------------------------------------------------------------
# Query building and collection lookups (spec 5.2, 9.2)
# ---------------------------------------------------------------------------

function Get-PDDelimitedList {
    <#
        .SYNOPSIS
        Flattens group input: splits every member on semicolons, trims, and discards empties.
        Never throws and never returns $null.
    #>
    param([AllowNull()][object]$Values)

    $list = @()
    if ($null -eq $Values) { return $list }

    foreach ($value in @($Values)) {
        if ($null -eq $value) { continue }
        foreach ($piece in ([string]$value).Split(';')) {
            $trimmed = $piece.Trim()
            if ($trimmed.Length -gt 0) { $list += $trimmed }
        }
    }

    return $list
}

function ConvertTo-PDODataStringLiteral {
    <#
        .SYNOPSIS
        A quoted OData string literal with apostrophes doubled (OData's only escape).
    #>
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) { return 'null' }
    return "'" + $Value.Replace("'", "''") + "'"
}

function New-PDGraphQueryPath {
    <#
        .SYNOPSIS
        Builds a relative Graph path with a percent-encoded query string.

        .DESCRIPTION
        Both the parameter names (which start with $, hence %24filter) and the values are
        escaped with EscapeDataString, so an OData literal containing apostrophes leaves this
        function as %27 and can never break out of the query it is inside.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][hashtable]$Query
    )

    $target = $Path.Trim()

    if (($null -eq $Query) -or ($Query.Count -eq 0)) { return $target }

    $parts = @()
    foreach ($key in $Query.Keys) {
        $value = [string]$Query[$key]
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        # EscapeDataString leaves apostrophes alone on .NET Framework but escapes them on .NET
        # Core, which would make the same filter produce two different URLs. Force %27 so the
        # wire format (and the OData doubling inside it) is identical on both engines.
        $parts += ('{0}={1}' -f ([System.Uri]::EscapeDataString([string]$key)).Replace("'", '%27'), (([System.Uri]::EscapeDataString($value)).Replace("'", '%27')))
    }

    if ($parts.Count -eq 0) { return $target }

    $separator = '?'
    if ($target.Contains('?')) { $separator = '&' }

    return ($target + $separator + ($parts -join '&'))
}

function Resolve-PDGraphGroup {
    <#
        .SYNOPSIS
        Resolves exactly one group name or object id to { Id; DisplayName; Intent }.

        .DESCRIPTION
        A GUID is read directly. Anything else is looked up with an exact displayName filter and
        full pagination, then re-checked locally for exact (case-insensitive, trimmed) equality so
        a service-side behaviour change cannot turn a filter into a substring search.

        Zero matches and multiple matches are failures that name the input; the first match is
        never silently chosen, and a group is never created.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Query,
        [AllowNull()][object]$AuthContext,
        [ValidateSet('required', 'available')][string]$Intent = 'required',
        [string]$Stage = 'Preflight'
    )

    $term = Get-PDGraphTrimmedText -Value $Query
    if ([string]::IsNullOrWhiteSpace($term)) {
        Stop-PDGraphError -Message 'A group name or object id is required.' -Stage $Stage
    }

    $select = 'id,displayName'
    $groupsPath = [string]$script:PDGraph.GroupsPath

    if (Test-PDGraphGuid -Value $term) {
        $byId = $null
        try {
            $byId = Invoke-PDGraphRequest -Method Get -Uri (New-PDGraphQueryPath -Path ($groupsPath + '/' + [System.Uri]::EscapeDataString($term)) -Query @{ '$select' = $select }) -AuthContext $AuthContext -RetryMode 'Read' -Stage $Stage -Description 'group by id'
        } catch {
            $info = Get-PDGraphErrorInfo -ErrorRecord $_
            if ($info.Status -eq 404) {
                Stop-PDGraphError -Message ("No Entra group has the object id '{0}'. Check the id, or enter the group's display name instead." -f $term) -Stage $Stage
            }
            throw
        }

        $id   = [string](Get-PDGraphPropertyValue -Object $byId -Name 'id')
        $name = [string](Get-PDGraphPropertyValue -Object $byId -Name 'displayName')

        if ([string]::IsNullOrWhiteSpace($id)) {
            Stop-PDGraphError -Message ("The directory did not return a usable id for '{0}'." -f $term) -Stage $Stage
        }

        return [pscustomobject]@{ Id = $id; DisplayName = $name; Intent = $Intent }
    }

    $filter = "displayName eq " + (ConvertTo-PDODataStringLiteral -Value $term)
    $path   = New-PDGraphQueryPath -Path $groupsPath -Query @{ '$filter' = $filter; '$select' = $select }

    $items  = Get-PDGraphCollection -Path $path -AuthContext $AuthContext -Stage $Stage -Description ('group lookup for ''{0}''' -f $term)

    $matches = @()
    foreach ($item in (Get-PDGraphItems -Payload $items)) {
        $candidateName = [string](Get-PDGraphPropertyValue -Object $item -Name 'displayName')
        $candidateId   = [string](Get-PDGraphPropertyValue -Object $item -Name 'id')

        if ([string]::IsNullOrWhiteSpace($candidateId)) { continue }
        if ($candidateName.Trim() -ne $term) { continue }

        $matches += [pscustomobject]@{ Id = $candidateId; DisplayName = $candidateName; Intent = $Intent }
    }

    if (@($matches).Count -eq 0) {
        Stop-PDGraphError -Message ("No Entra group is named exactly '{0}'. Correct the name, or supply the group's object id." -f $term) -Stage $Stage
    }

    if (@($matches).Count -gt 1) {
        $candidates = (@($matches) | ForEach-Object { '{0} ({1})' -f $_.DisplayName, $_.Id }) -join '; '
        Stop-PDGraphError -Message ("{0} groups are named '{1}': {2}. Re-enter the intended group by object id." -f @($matches).Count, $term, $candidates) -Stage $Stage
    }

    return @($matches)[0]
}

function Get-PDBuiltInAssignmentTarget {
    <#
        .SYNOPSIS
        Maps /AllDevices or /AllUsers to Intune's built-in assignment target; $null for anything
        that is not a command. An unknown /command is an error, never a group lookup, so a typo
        like /AllDevice cannot quietly become a search for a group of that name.
    #>
    param(
        [AllowNull()][string]$Term,
        [string]$Stage = 'Preflight'
    )

    $text = Get-PDGraphTrimmedText -Value $Term
    if ([string]::IsNullOrWhiteSpace($text) -or (-not $text.StartsWith('/'))) { return $null }

    $known = $script:PDGraph.BuiltInTargets[$text.ToLowerInvariant()]
    if ($null -eq $known) {
        $names = (@($script:PDGraph.BuiltInTargets.Values | ForEach-Object { $_.Id }) | Sort-Object) -join ' or '
        Stop-PDGraphError -Message ("Unknown option '{0}'. Use {1}, or a group name or object id." -f $text, $names) -Stage $Stage
    }
    return $known
}

function Get-PDBuiltInAssignmentTargetByType {
    <# The command (/AllDevices, /AllUsers) for a target @odata.type read back from Intune, or $null. #>
    param([AllowNull()][string]$ODataType)

    $type = Get-PDGraphTrimmedText -Value $ODataType
    if ([string]::IsNullOrWhiteSpace($type)) { return $null }
    if (-not $type.StartsWith('#')) { $type = '#' + $type }
    foreach ($entry in @($script:PDGraph.BuiltInTargets.Values)) {
        if ([string]$entry.ODataType -ieq $type) { return [string]$entry.Id }
    }
    return $null
}

function Resolve-PDGraphGroups {
    <#
        .SYNOPSIS
        Resolves RequiredGroups/AvailableGroups into { Id; DisplayName; Intent } assignments
        (spec 5.2), applying the dedupe and conflict rules.

        .DESCRIPTION
        Within one intent, the same group reached by name and by id produces ONE assignment.
        The same id in both intents is a preflight failure - neither intent wins, and silently
        dropping one would change who is supposed to get the app.

        Empty input is valid and produces an empty array, which the uploader reports as
        'No assignments' and skips the assign endpoint for. Groups are never created and display
        names are never used as identity.
    #>
    param(
        [AllowNull()][string[]]$RequiredGroups,
        [AllowNull()][string[]]$AvailableGroups,
        [AllowNull()][object]$AuthContext,
        [string]$Stage = 'Preflight'
    )

    $requested = @()
    foreach ($term in (Get-PDDelimitedList -Values $RequiredGroups))  { $requested += [pscustomobject]@{ Term = $term; Intent = 'required' } }
    foreach ($term in (Get-PDDelimitedList -Values $AvailableGroups)) { $requested += [pscustomobject]@{ Term = $term; Intent = 'available' } }

    $resolved  = @()
    $seenByIntent = @{}
    $ownerByGroup = @{}

    foreach ($item in $requested) {
        # /AllDevices and /AllUsers are Intune's built-in targets, not directory groups.
        $builtIn = Get-PDBuiltInAssignmentTarget -Term $item.Term -Stage $Stage
        if ($null -ne $builtIn) {
            $entry = [pscustomobject]@{ Id = [string]$builtIn.Id; DisplayName = [string]$builtIn.DisplayName; Intent = $item.Intent }
        } else {
            $entry = Resolve-PDGraphGroup -Query $item.Term -AuthContext $AuthContext -Intent $item.Intent -Stage $Stage
        }

        $key = $entry.Id.ToLowerInvariant()
        $intentKey = $item.Intent + '|' + $key

        if ($seenByIntent.ContainsKey($intentKey)) {
            # Same group twice in one intent: one assignment, whatever the input looked like.
            continue
        }
        $seenByIntent[$intentKey] = $true

        if ($ownerByGroup.ContainsKey($key) -and ($ownerByGroup[$key] -ne $item.Intent)) {
            Stop-PDGraphError -Message ("'{0}' ({1}) was given as both a Required and an Available target. Choose one intent." -f $entry.DisplayName, $entry.Id) -Stage $Stage
        }
        $ownerByGroup[$key] = $item.Intent

        $resolved += $entry
    }

    return $resolved
}

function Find-PDIntuneDuplicateApps {
    <#
        .SYNOPSIS
        Apps that already have this exact display name (spec 9.2 step 6, test A02).

        .DESCRIPTION
        Informational: duplicates are shown during a dry run and only block execution when
        -AllowDuplicateName was not supplied. Intune permits duplicate display names, so a
        match is the operator's decision, not this function's.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [AllowNull()][object]$AuthContext,
        [string]$Stage = 'Preflight'
    )

    $term = Get-PDGraphTrimmedText -Value $DisplayName
    if ([string]::IsNullOrWhiteSpace($term)) { return @() }

    # Intune's displayName eq filter never matches a name containing [ or ] (measured live
    # 2026-10-12: an existing "...[OLD - f9068c8]" app was not found), and PowerDeploy's
    # development-mode names always carry "[MODE] [VER: ...]". For those, ask for everything that
    # starts with the part before the first bracket; the exact comparison below does the matching.
    $filter  = 'displayName eq ' + (ConvertTo-PDODataStringLiteral -Value $term)
    $bracket = $term.IndexOfAny([char[]]@('[', ']'))
    if ($bracket -ge 0) {
        $prefix = $term.Substring(0, $bracket)
        $filter = $null
        if ($prefix.Trim().Length -gt 0) { $filter = 'startswith(displayName,' + (ConvertTo-PDODataStringLiteral -Value $prefix) + ')' }
    }

    $query = @{ '$select' = 'id,displayName,publishingState' }
    if ($null -ne $filter) { $query['$filter'] = $filter }
    $path = New-PDGraphQueryPath -Path ([string]$script:PDGraph.MobileAppsPath) -Query $query

    $items = Get-PDGraphCollection -Path $path -AuthContext $AuthContext -Stage $Stage -Description 'duplicate app name check'

    $duplicates = @()
    foreach ($item in (Get-PDGraphItems -Payload $items)) {
        $id   = [string](Get-PDGraphPropertyValue -Object $item -Name 'id')
        $name = [string](Get-PDGraphPropertyValue -Object $item -Name 'displayName')

        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        if ($name.Trim() -ne $term) { continue }

        $duplicates += [pscustomobject]@{ Id = $id; DisplayName = $name }
    }

    return $duplicates
}

function Find-PDIntuneCategory {
    <#
        .SYNOPSIS
        Resolves an existing app category by exact display name (spec 4.5).

        .OUTPUTS
        { RequestedName; Id; Status; Warning } where Status is Resolved | Missing | Ambiguous.

        .DESCRIPTION
        Categories are never created (spec 12.2 invariant 12). A missing category is a warning
        and no association; several exact matches are Ambiguous, also a warning, because picking
        one arbitrarily would put the app in a folder nobody asked for.
    #>
    param(
        [AllowEmptyString()][AllowNull()][string]$Category,
        [AllowNull()][object]$AuthContext,
        [string]$Stage = 'Preflight'
    )

    # An empty or N/A category is not an error and not a lookup: it means "no category asked for".
    $term = Get-PDGraphTrimmedText -Value $Category -TreatNotApplicableAsMissing
    if ([string]::IsNullOrWhiteSpace($term)) {
        return [pscustomobject]@{ RequestedName = $term; Id = $null; Status = 'NotRequested'; Warning = $null }
    }

    $filter = 'displayName eq ' + (ConvertTo-PDODataStringLiteral -Value $term)
    $path   = New-PDGraphQueryPath -Path ([string]$script:PDGraph.AppCategoriesPath) -Query @{
        '$filter' = $filter
        '$select' = 'id,displayName'
    }

    $items = Get-PDGraphCollection -Path $path -AuthContext $AuthContext -Stage $Stage -Description 'category lookup'

    $found = @()
    foreach ($item in (Get-PDGraphItems -Payload $items)) {
        $id   = [string](Get-PDGraphPropertyValue -Object $item -Name 'id')
        $name = [string](Get-PDGraphPropertyValue -Object $item -Name 'displayName')

        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        if ($name.Trim() -ne $term) { continue }

        $found += [pscustomobject]@{ Id = $id; DisplayName = $name }
    }

    if (@($found).Count -eq 0) {
        return [pscustomobject]@{
            RequestedName = $term
            Id            = $null
            Status        = 'Missing'
            Warning       = ("No Intune app category is named exactly '{0}'. The app will be published without a category; categories are never created here." -f $term)
        }
    }

    if (@($found).Count -gt 1) {
        $candidates = (@($found) | ForEach-Object { '{0} ({1})' -f $_.DisplayName, $_.Id }) -join '; '
        return [pscustomobject]@{
            RequestedName = $term
            Id            = $null
            Status        = 'Ambiguous'
            Warning       = ("{0} Intune categories are named '{1}' ({2}). No category was associated; rename them or leave Category empty." -f @($found).Count, $term, $candidates)
        }
    }

    return [pscustomobject]@{ RequestedName = $term; Id = @($found)[0].Id; Status = 'Resolved'; Warning = $null }
}

# ---------------------------------------------------------------------------
# Storage transfer (spec 10.3, 11.1)
#
# A content file's SAS URI is a write credential with an expiry. These functions are
# the only place that touches it, and they hold two rules: the SAS never appears in a
# message, and a Graph authorization header can never exist on a storage request.
# Invoke-PDGraphRequest refuses a bearer off-host; this half of the boundary refuses
# storage requests aimed at Graph, so neither direction is a convention someone has
# to remember.
# ---------------------------------------------------------------------------

function Remove-PDSecretQueryString {
    <#
        .SYNOPSIS
        Redacts shared-access-signature query values (sv, se, st, sig, ...) in any text.

        .DESCRIPTION
        Anything about a storage request that might reach a log, a result object, or a
        displayed exception goes through here. Host and path survive, so a failure is
        still diagnosable, while the signature and its window are replaced. Idempotent:
        already-redacted text comes back unchanged.

        This is separate from Remove-UrlCredential, which strips URL userinfo: a SAS
        hides in the query string, where userinfo rules cannot reach it.
    #>
    param([AllowNull()][object]$Text)

    if ($null -eq $Text) { return '' }

    $value = [string]$Text
    if ($value.Length -eq 0) { return $value }
    if ($value.Contains('<redacted>')) { return $value }

    $names = @('sv', 'se', 'sr', 'st', 'sp', 'sip', 'sqp', 'ss', 'skd', 'spr', 'srt', 'ssk', 'qte', 'rsr', 'rscd', 'rcp', 'rk', 'rid', 'sig')
    $pattern = '(?i)([?&])(' + ($names -join '|') + ')=([^&<>''"\s]|%[0-9a-fA-F]{2})*'

    return ([regex]::Replace($value, $pattern, '$1$2=<redacted>'))
}

function Get-PDStorageUploadTarget {
    <#
        .SYNOPSIS
        Parses a content file's azureStorageUri into a validated upload target.

        .DESCRIPTION
        Graph returns the same SAS URI up to four times, space-separated (one per
        endpoint family), so the first token is used. Exactly one absolute https URL is
        accepted, and never one on the Graph host.

        The returned Query holds a live signature: use it inside these helpers only, and
        never log it or return it in an object that leaves the process.

        .OUTPUTS
        @{ Base; Query; Host; Path; ExpiresOn (DateTimeOffset or $null); SasExpiresAtText }
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$AzureStorageUri,
        [string]$Stage
    )

    $candidate = $null
    foreach ($token in (([string]$AzureStorageUri) -split '\s+')) {
        if (-not [string]::IsNullOrWhiteSpace($token)) { $candidate = $token; break }
    }
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        Stop-PDGraphError -Message 'Intune did not return a storage URI for the content file, so no content could be uploaded.' -Stage $Stage
    }

    $parsed = $null
    if (-not [System.Uri]::TryCreate($candidate, [System.UriKind]::Absolute, [ref]$parsed)) {
        Stop-PDGraphError -Message 'The storage URI Intune returned for the content file is not an absolute URL, so it was not used.' -Stage $Stage
    }
    if (-not [string]::Equals($parsed.Scheme, 'https', [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-PDGraphError -Message 'The storage URI Intune returned is not https, so the encrypted payload was not sent to it.' -Stage $Stage
    }
    if ([string]::Equals($parsed.Host, [string]$script:PDGraph.GraphHost, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-PDGraphError -Message 'The content file storage URI points at Microsoft Graph rather than blob storage, which is not somewhere a payload is uploaded to.' -Stage $Stage
    }

    # The signature must stay exactly as issued, so the raw string is split rather than
    # rebuilt from the parsed Uri (which can normalize escapes).
    $base  = $candidate
    $query = ''
    $mark  = $candidate.IndexOf('?')
    if ($mark -ge 0) {
        $base  = $candidate.Substring(0, $mark)
        $query = $candidate.Substring($mark + 1)
    }
    # A real service SAS always carries a signature; requiring it rejects a plain blob URL
    # that was never meant to be writable.
    if ($query -notmatch '(?i)(^|&)sig=') {
        Stop-PDGraphError -Message 'The storage URI Intune returned carries no shared access signature, so nothing could be uploaded to it.' -Stage $Stage
    }

    $expiresOn   = $null
    $expiresText = $null
    foreach ($pair in ($query -split '&')) {
        $parts = $pair -split '=', 2
        if (($parts.Count -eq 2) -and ($parts[0] -ieq 'se')) {
            $expiresText = [System.Uri]::UnescapeDataString($parts[1])
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($expiresText)) {
        $unix = [long]0
        if ([long]::TryParse($expiresText.Trim(), [ref]$unix) -and ($unix -gt 631152000)) {
            # Newer SAS versions express 'se' as Unix seconds rather than ISO-8601.
            try { $expiresOn = [DateTimeOffset]::FromUnixTimeSeconds($unix) } catch { $expiresOn = $null }
        } else {
            $moment = [DateTimeOffset]::MinValue
            if ([DateTimeOffset]::TryParse($expiresText, [ref]$moment)) { $expiresOn = $moment }
        }
    }

    return @{
        Base             = $base
        Query            = $query
        Host             = $parsed.Host
        Path             = $parsed.AbsolutePath
        ExpiresOn        = $expiresOn
        SasExpiresAtText = $expiresText
    }
}

function Test-PDStorageUriExpiring {
    <#
        .SYNOPSIS
        True when the SAS is already expired or expires within -MarginSec.

        .DESCRIPTION
        An unknown expiry is NOT treated as expiring: an SAS this code cannot read is
        used and the service decides, rather than the uploader renewing in a loop.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()][hashtable]$Target,
        [int]$MarginSec = -1,
        [AllowNull()][object]$Now
    )

    if ($null -eq $Target) { return $false }
    if ($null -eq $Target['ExpiresOn']) { return $false }

    if ($MarginSec -lt 0) { $MarginSec = [int]$script:PDGraph.StorageRenewMarginSec }

    $moment = [DateTimeOffset]::UtcNow
    if ($Now -is [DateTimeOffset]) { $moment = $Now }
    elseif ($Now -is [DateTime]) { $moment = [DateTimeOffset]::new(([DateTime]$Now).ToUniversalTime()) }

    return ($moment -ge $Target['ExpiresOn'].AddSeconds(-1 * [double]$MarginSec))
}

function New-PDStorageBlockId {
    <#
        .SYNOPSIS
        One fixed-width sequential block id for a zero-based block number (spec 10.3).

        .DESCRIPTION
        Azure requires every block id in a blob to have the same length, hence the
        zero-padding, and wants the base64 form escaped on the wire but raw in the
        block list XML. Both forms come from here so they can never drift.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$Index,
        [int]$Width = 0
    )

    if ($Index -lt 0) {
        Stop-PDGraphError -Message 'A storage block number cannot be negative.' -Stage 'Upload'
    }
    if ($Width -le 0) { $Width = [int]$script:PDGraph.StorageBlockIdWidth }

    # Padding is the whole point of the width, so running past it has to be loud: 10^Width
    # blocks is far past any .intunewin that exists, and silently widening the ids would put a
    # block list Azure rejects in the middle of an upload.
    if ($Index -ge [math]::Pow(10, $Width)) {
        Stop-PDGraphError -Message ("The content file would need more than the {0} block numbers this uploader supports, so the upload stopped before sending anything." -f ([math]::Pow(10, $Width))) -Stage 'Upload'
    }

    # Parenthesized because -f binds tighter than + : 'a' + 'b' -f x is 'a' + ('b' -f x).
    $raw = (('{0:d' + [string]$Width + '}') -f $Index)
    $b64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($raw))

    return @{
        Raw     = $raw
        Base64  = $b64
        Escaped = [System.Uri]::EscapeDataString($b64)
    }
}

function New-PDStorageRequestUri {
    <#
        .SYNOPSIS
        Builds one storage URL: <base>?<sas>&comp=<block|blocklist>[&blockid=<escaped b64>].
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Target,
        [Parameter(Mandatory = $true)][ValidateSet('block', 'blocklist')][string]$Comp,
        [AllowNull()][hashtable]$BlockId,
        [string]$Stage
    )

    if ([string]::IsNullOrWhiteSpace([string]$Target['Query'])) {
        Stop-PDGraphError -Message 'The storage URI had no shared access signature, so no upload request could be built from it.' -Stage $Stage
    }

    $uri = '{0}?{1}&comp={2}' -f [string]$Target['Base'], [string]$Target['Query'], $Comp

    if ($Comp -eq 'block') {
        if (($null -eq $BlockId) -or [string]::IsNullOrWhiteSpace([string]$BlockId['Escaped'])) {
            Stop-PDGraphError -Message 'A storage block request needs a block id.' -Stage $Stage
        }
        $uri += '&blockid=' + [string]$BlockId['Escaped']
    }

    return $uri
}

function Invoke-PDStorageRequest {
    <#
        .SYNOPSIS
        One storage (SAS) HTTP request, with no authentication of any kind.

        .DESCRIPTION
        There is deliberately no -AuthContext parameter and there is a guard against a
        Graph target, so "no Graph bearer on a storage request" is structural. Retry,
        backoff, and sanitized errors come from the same core the Graph requests use, so
        a throttled or refused storage write still reports the service's own status -
        with the SAS removed from every message that leaves this function.

        .OUTPUTS
        The normalized response hashtable (2xx only; failures throw).
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Target,
        [Parameter(Mandatory = $true)][ValidateSet('Get', 'Put', 'Post', 'Patch', 'Delete')][string]$Method,
        [Parameter(Mandatory = $true)][ValidateSet('block', 'blocklist')][string]$Comp,
        [AllowNull()][hashtable]$BlockId,
        [AllowNull()][byte[]]$BodyBytes,
        [AllowNull()][string]$BodyText,
        [AllowNull()][string]$ContentType,
        [ValidateSet('Read', 'Write', 'Block', 'Token')][string]$RetryMode = 'Block',
        [string]$Stage,
        [string]$Description
    )

    $uri = New-PDStorageRequestUri -Target $Target -Comp $Comp -BlockId $BlockId -Stage $Stage

    if (Test-PDGraphUrlIsGraph -Url $uri) {
        Stop-PDGraphError -Message 'A storage request was aimed at Microsoft Graph; content bytes only ever go to the storage URI Intune supplied.' -Stage $Stage
    }

    # Deliberately not named $target: PowerShell variables are case-insensitive, so $target here
    # would BE the [hashtable]$Target parameter and assigning a description to it fails with
    # "Cannot convert ... to System.Collections.Hashtable".
    $descriptionText = $Description
    if ([string]::IsNullOrWhiteSpace($descriptionText)) {
        $descriptionText = ('storage {0} request ({1})' -f $Comp, $Method)
    }

    $request = @{
        Method      = $Method
        Uri         = $uri
        Headers     = $null
        BodyBytes   = $null
        BodyText    = $null
        ContentType = $ContentType
        TimeoutSec  = [int]$script:PDGraph.RequestTimeoutSec
    }
    if ($null -ne $BodyBytes) { $request['BodyBytes'] = $BodyBytes }
    if (-not [string]::IsNullOrWhiteSpace($BodyText)) { $request['BodyText'] = $BodyText }

    try {
        return (Send-PDGraphRequest -Request $request -RetryMode $RetryMode -Stage $Stage -Description $descriptionText)
    } catch {
        # Belt and braces: the SAS must not survive in any message, whatever the transport
        # decided to quote. If nothing needed redacting the original error is rethrown so
        # its type and stack stay exactly as they were.
        $info = Get-PDGraphErrorInfo -ErrorRecord $_

        $safeMessage = Remove-PDSecretQueryString -Text $info.Message
        $safeDetail  = Remove-PDSecretQueryString -Text $info.Detail

        if (($safeMessage -eq $info.Message) -and ($safeDetail -eq $info.Detail)) { throw }

        $errorStage = $Stage
        if (-not [string]::IsNullOrWhiteSpace($info.Stage)) { $errorStage = $info.Stage }

        throw (New-PDGraphError -Message $safeMessage -Stage $errorStage -Status $info.Status -RequestId $info.RequestId `
                -RetryAfter $info.RetryAfter -ApprovalRequired ([bool]$info.ApprovalRequired) -Retryable ([bool]$info.Retryable) `
                -Detail $safeDetail)
    }
}

# ---------------------------------------------------------------------------
# Content workflow payloads and polling (spec 10.3)
# ---------------------------------------------------------------------------

function New-PDIntuneContentFilePayload {
    <#
        .SYNOPSIS
        The POST body for creating the content file record (spec 10.3).

        .DESCRIPTION
        name/size/sizeEncrypted come from the package, never from a guess: size is
        ApplicationInfo/UnencryptedContentSize and sizeEncrypted is the measured length of
        the encrypted payload that is actually uploaded (spec 10.1).
    #>
    param(
        [Parameter(Mandatory = $true)][object]$Package,
        [string]$Stage = 'StorageUri'
    )

    $fileName = [string](Get-PDGraphPropertyValue -Object $Package -Name 'FileName')
    $contentSize = Get-PDGraphPropertyValue -Object $Package -Name 'UnencryptedContentSize'
    $encryptedSize = Get-PDGraphPropertyValue -Object $Package -Name 'PayloadBytes'

    if ([string]::IsNullOrWhiteSpace($fileName)) {
        Stop-PDGraphError -Message 'The content file record needs the package file name; read the package with Read-PDIntuneWinPackage first.' -Stage $Stage
    }
    if (($null -eq $contentSize) -or ($null -eq $encryptedSize)) {
        Stop-PDGraphError -Message 'The content file record needs both the declared content size and the measured encrypted size.' -Stage $Stage
    }

    return @{
        '@odata.type' = '#microsoft.graph.mobileAppContentFile'
        name          = $fileName
        size          = [long]$contentSize
        sizeEncrypted = [long]$encryptedSize
        isDependency  = $false
    }
}

function New-PDIntuneCommitPayload {
    <#
        .SYNOPSIS
        The POST body for microsoft.graph.commit, built from the package's own
        EncryptionInfo (spec 10.3).
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$EncryptionInfo,
        [string]$Stage = 'Commit'
    )

    if ($null -eq $EncryptionInfo) {
        Stop-PDGraphError -Message 'The commit request needs the package encryption information; it is never guessed.' -Stage $Stage
    }

    # XML element name -> Graph property name. Values are read but never displayed: these
    # are the keys that decrypt the payload.
    $map = [ordered]@{
        encryptionKey         = 'EncryptionKey'
        macKey                = 'MacKey'
        initializationVector  = 'InitializationVector'
        mac                   = 'Mac'
        profileIdentifier     = 'ProfileIdentifier'
        fileDigest            = 'FileDigest'
        fileDigestAlgorithm   = 'FileDigestAlgorithm'
    }

    $info     = @{}
    $missing  = @()
    foreach ($property in $map.Keys) {
        $value = [string](Get-PDGraphPropertyValue -Object $EncryptionInfo -Name ([string]$map[$property]))
        if ([string]::IsNullOrWhiteSpace($value)) {
            $missing += ([string]$map[$property])
        } else {
            $info[$property] = $value
        }
    }
    if ($missing.Count -gt 0) {
        # Names only - a missing key is the diagnosis, and the values are never printed.
        Stop-PDGraphError -Message ("The commit request is missing encryption field(s) {0} from the package metadata." -f (($missing | ForEach-Object { "'$_'" }) -join ', ')) -Stage $Stage
    }

    return @{ fileEncryptionInfo = $info }
}

function New-PDIntuneAssignmentPayload {
    <#
        .SYNOPSIS
        The assignment body (spec 10.3): intent plus a group target, nothing else.

        .DESCRIPTION
        Assignment settings are omitted so the service applies its own defaults; inventing
        schedules or deadlines here would be a silent policy decision. Callers must not
        call this with no groups - "no assignments" means never touching the endpoint.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object[]]$ResolvedGroups,
        [string]$Stage = 'Assign'
    )

    $assignments = @()
    foreach ($group in @($ResolvedGroups)) {
        if ($null -eq $group) { continue }

        $id      = [string](Get-PDGraphPropertyValue -Object $group -Name 'Id')
        $intent  = [string](Get-PDGraphPropertyValue -Object $group -Name 'Intent')
        $intent  = $intent.Trim().ToLowerInvariant()

        if ([string]::IsNullOrWhiteSpace($id)) {
            Stop-PDGraphError -Message 'An assignment target has no group id, so the assignment was not sent.' -Stage $Stage
        }
        if (($intent -ne 'required') -and ($intent -ne 'available')) {
            Stop-PDGraphError -Message ("An assignment for group '{0}' has the intent '{1}'; only 'required' and 'available' exist." -f $id, $intent) -Stage $Stage
        }

        $builtIn = Get-PDBuiltInAssignmentTarget -Term $id -Stage $Stage
        if ($null -ne $builtIn) {
            # A built-in target carries no group id: its type IS the target.
            $target = @{ '@odata.type' = [string]$builtIn.ODataType }
        } else {
            $target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $id }
        }

        $assignments += @{
            '@odata.type' = '#microsoft.graph.mobileAppAssignment'
            intent        = $intent
            target        = $target
        }
    }

    if (@($assignments).Count -eq 0) {
        Stop-PDGraphError -Message 'There are no groups to assign, so the assign request must not be sent at all.' -Stage $Stage
    }

    # The assign action's body is exactly { "mobileAppAssignments": [ ... ] }. A root '@odata.type'
    # (there is no mobileAppAssignments type) is refused with "ModelValidationFailure: The
    # annotation 'odata.type' was found ... not expected at the current position" (first live
    # upload, 2026-10-12). Type annotations belong only on each assignment and its target.
    return @{
        mobileAppAssignments = $assignments
    }
}

function New-PDIntuneCategoryRefPayload {
    <#
        .SYNOPSIS
        The $ref body that associates an existing category (spec 10.3).
        Only ever an id that was resolved in preflight; categories are never created.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$CategoryId,
        [string]$Stage = 'Category'
    )

    $id = ([string]$CategoryId).Trim()
    if ([string]::IsNullOrWhiteSpace($id)) {
        Stop-PDGraphError -Message 'No category id was resolved, so no category association was sent.' -Stage $Stage
    }

    return @{ '@odata.id' = (([string]$script:PDGraph.GraphBetaBase).TrimEnd('/') + '/deviceAppManagement/mobileAppCategories/' + [System.Uri]::EscapeDataString($id)) }
}

function Get-PDIntuneContentFileState {
    <#
        .SYNOPSIS
        Reads the service's uploadState off a mobileAppContentFile record.

        .DESCRIPTION
        Graph reports progress in ONE string property, uploadState (mobileAppContentFileUploadState:
        azureStorageUriRequestSuccess, azureStorageUriRenewalSuccess, commitFileSuccess, ...). An
        earlier version looked for boolean properties named after those values, which do not exist,
        so a real upload never left "Pending" (first live upload, 2026-10-12). Anything not
        recognized is 'Pending' - bounded by the caller's polling deadline - so a service change can
        never be mistaken for success.
        .OUTPUTS
        'Success' | 'Pending' | 'Failed' | 'Absent'
    #>
    param(
        [AllowNull()][object]$File,
        [Parameter(Mandatory = $true)][ValidateSet('StorageUri', 'RenewUpload', 'Commit')][string]$Phase
    )

    if ($null -eq $File) { return 'Absent' }

    $states = @{
        StorageUri  = @{
            Success = @('azureStorageUriRequestSuccess', 'azureStorageUriRenewalSuccess')
            Failed  = @('azureStorageUriRequestFailed', 'azureStorageUriRequestTimedOut', 'azureStorageUriRenewalFailed', 'azureStorageUriRenewalTimedOut', 'error')
        }
        RenewUpload = @{
            Success = @('azureStorageUriRenewalSuccess')
            Failed  = @('azureStorageUriRenewalFailed', 'azureStorageUriRenewalTimedOut', 'error')
        }
        Commit      = @{
            Success = @('commitFileSuccess')
            Failed  = @('commitFileFailed', 'commitFileTimedOut', 'error')
        }
    }

    $state = ([string](Get-PDGraphPropertyValue -Object $File -Name 'uploadState')).Trim()
    if ([string]::IsNullOrWhiteSpace($state)) { return 'Pending' }

    foreach ($name in @($states[$Phase].Failed))  { if ($state -ieq $name) { return 'Failed' } }
    foreach ($name in @($states[$Phase].Success)) { if ($state -ieq $name) { return 'Success' } }
    return 'Pending'
}
function Wait-PDGraphCondition {
    <#
        .SYNOPSIS
        One bounded polling loop (spec 11.1: every polling stage is time-boxed).

        .DESCRIPTION
        -Test is re-invoked until it returns something truthy, which becomes this
        function's return value (so a poll that fetches a resource hands it straight back).
        A -Test that throws ends the wait immediately - that is how a terminal service
        state fails fast instead of burning the deadline. Running out of time is a failure
        that names what was being waited for; it is never reported as success.

        .PARAMETER TimeoutSec
        Defaults to the centralized PollDeadlineSec so no stage invents its own budget.
    #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Test,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Description,
        [int]$TimeoutSec = 0,
        [int]$IntervalMs = -1,
        [string]$Stage
    )

    if ($TimeoutSec -le 0) { $TimeoutSec = [int]$script:PDGraph.PollDeadlineSec }
    if ($IntervalMs -lt 0) { $IntervalMs = [int]$script:PDGraph.PollIntervalMs }

    $deadline = [DateTime]::UtcNow.AddSeconds([double]$TimeoutSec)
    $checks   = 0

    while ($true) {
        $checks++

        $outcome = & $Test $checks
        if ($outcome) { return $outcome }

        if ([DateTime]::UtcNow -ge $deadline) {
            Stop-PDGraphError -Message ("Timed out after {0} seconds ({1} checks) waiting for {2}. Nothing was assumed to be finished." -f $TimeoutSec, $checks, $Description) -Stage $Stage
        }

        if ($IntervalMs -gt 0) {
            $remaining = [int]([DateTime]::UtcNow - $deadline).TotalMilliseconds
            $pause     = $IntervalMs
            if (($remaining -gt 0) -and ($remaining -lt $pause)) { $pause = $remaining }
            Start-Sleep -Milliseconds $pause
        }
    }
}

# ---------------------------------------------------------------------------
# The content upload itself (spec 10.3)
# ---------------------------------------------------------------------------

function Send-PDIntuneContentBlob {
    <#
        .SYNOPSIS
        Uploads the encrypted payload to the content file's storage URI (spec 10.3).

        .DESCRIPTION
        Fixed 4 MiB blocks PUT with comp=block and sequential fixed-width block ids, then
        one comp=blocklist PUT naming the kept ids in order. Nothing here carries a Graph
        token, and no message leaves with the SAS in it (Invoke-PDStorageRequest guarantees
        both).

        SAS handling: a URI that is already expired - or expires inside
        StorageRenewMarginSec - is renewed before the first block, and a block the service
        refuses with 401/403/410 restarts the upload against a renewed URI, up to
        MaxStorageRenewals times. Restarting from block 0 is deliberate: a renewal can hand
        back a different container, and uncommitted blocks are only meaningful in the
        container they were written to.

        .PARAMETER WhenExpiring
        Optional callback invoked when a fresh URI is needed. It receives
        @{ Reason; Target; Attempt } and must return a target hashtable from
        Get-PDStorageUploadTarget. Without it an expired URI is a plain failure.

        .OUTPUTS
        @{ Blocks; Bytes; BlockIds; Renewals }
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()][hashtable]$Target,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [int]$BlockBytes = 0,
        [AllowNull()][scriptblock]$WhenExpiring,
        [string]$Stage = 'Upload'
    )

    if ($BlockBytes -le 0) { $BlockBytes = [int]$script:PDGraph.StorageBlockBytes }

    $payloadPath = [System.IO.Path]::GetFullPath([string]$FilePath)
    if (-not (Test-Path -LiteralPath $payloadPath)) {
        Stop-PDGraphError -Message 'The extracted encrypted payload is no longer on disk, so it cannot be uploaded.' -Stage $Stage
    }

    $totalBytes = [long](New-Object System.IO.FileInfo($payloadPath)).Length
    if ($totalBytes -le 0) {
        Stop-PDGraphError -Message 'The encrypted payload is empty, so there is nothing to upload.' -Stage $Stage
    }

    $blockCount   = [int][math]::Ceiling([double]$totalBytes / [double]$BlockBytes)
    $renewals     = 0
    $maxRenewals  = [int]$script:PDGraph.MaxStorageRenewals
    $current      = $Target
    $buffer       = New-Object byte[] $BlockBytes
    $keptIds      = @()

    try {
        while ($true) {
            if ($null -eq $current) {
                Stop-PDGraphError -Message 'There is no storage URI left to upload to.' -Stage $Stage
            }

            # A URI that is already no good is renewed before anything is written to it.
            if (Test-PDStorageUriExpiring -Target $current) {
                if ($null -eq $WhenExpiring) {
                    Stop-PDGraphError -Message 'The storage URI for the content file has expired before the upload could finish. No replacement URI was available.' -Stage $Stage
                }
                $renewals++
                if ($renewals -gt $maxRenewals) {
                    Stop-PDGraphError -Message ("The storage URI needed more than {0} renewals during one upload, so the upload stopped instead of repeating itself." -f $maxRenewals) -Stage $Stage
                }
                $current = & $WhenExpiring @{ Reason = 'expiring'; Target = $current; Attempt = $renewals }
                $keptIds = @()
                continue
            }

            $stream = $null
            $restart = $false
            try {
                $stream = [System.IO.File]::Open($payloadPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)

                for ($index = 0; $index -lt $blockCount; $index++) {
                    # A long upload on a short SAS must not discover the expiry on block 900.
                    if (($index -gt 0) -and
                        ($null -ne $WhenExpiring) -and
                        (($index % [int]$script:PDGraph.StorageRenewCheckBlocks) -eq 0) -and
                        (Test-PDStorageUriExpiring -Target $current)) {
                        $restart = $true
                        break
                    }

                    $null = $stream.Seek([long]($index * $BlockBytes), [System.IO.SeekOrigin]::Begin)

                    $wanted = $BlockBytes
                    if (($totalBytes - [long]($index * $BlockBytes)) -lt $BlockBytes) {
                        $wanted = [int]($totalBytes - [long]($index * $BlockBytes))
                    }

                    $read    = 0
                    while ($read -lt $wanted) {
                        $got = $stream.Read($buffer, $read, ($wanted - $read))
                        if ($got -le 0) { break }
                        $read += $got
                    }
                    if ($read -ne $wanted) {
                        Stop-PDGraphError -Message ("Only {0} of {1} bytes of the encrypted payload could be read for block {2}; the upload stopped rather than sending a short block." -f $read, $wanted, $index) -Stage $Stage
                    }

                    $chunk = $buffer
                    if ($read -ne $BlockBytes) {
                        $chunk = New-Object byte[] $read
                        [Array]::Copy($buffer, $chunk, $read)
                    }

                    $blockId = New-PDStorageBlockId -Index $index

                    try {
                        $null = Invoke-PDStorageRequest -Target $current -Method Put -Comp 'block' -BlockId $blockId `
                                                        -BodyBytes $chunk -ContentType 'application/octet-stream' `
                                                        -Stage $Stage -Description ('content block {0} of {1}' -f ($index + 1), $blockCount)
                        $keptIds += $blockId['Base64']
                    } catch {
                        $info = Get-PDGraphErrorInfo -ErrorRecord $_

                        # 401/403/410 on a SAS means the access signature, not the payload,
                        # is the problem; anything else is a real failure of this block.
                        $looksExpired = (($info.Status -eq 401) -or ($info.Status -eq 403) -or ($info.Status -eq 410))

                        if ($looksExpired -and ($null -ne $WhenExpiring) -and (($renewals + 1) -le $maxRenewals)) {
                            $renewals++
                            $current = & $WhenExpiring @{ Reason = 'rejected'; Target = $current; Attempt = $renewals; Status = $info.Status }
                            $restart = $true
                            break
                        }
                        throw
                    }
                }
            } finally {
                if ($null -ne $stream) { $stream.Dispose() }
            }

            if ($restart) { continue }
            break
        }

        if (@($keptIds).Count -eq 0) {
            Stop-PDGraphError -Message 'No storage block was accepted, so no block list was sent.' -Stage $Stage
        }
        if (@($keptIds).Count -ne $blockCount) {
            Stop-PDGraphError -Message ("Only {0} of {1} blocks were accepted, so the block list was not sent." -f @($keptIds).Count, $blockCount) -Stage $Stage
        }

        $blockList = '<?xml version="1.0" encoding="utf-8"?><BlockList>' + ((@($keptIds) | ForEach-Object { '<Latest>' + [string]$_ + '</Latest>' }) -join '') + '</BlockList>'

        $null = Invoke-PDStorageRequest -Target $current -Method Put -Comp 'blocklist' -BodyText $blockList `
                                        -ContentType 'text/plain; charset=utf-8' -RetryMode 'Write' `
                                        -Stage $Stage -Description 'content block list'

        return @{
            Blocks   = [int]$blockCount
            Bytes    = [long]$totalBytes
            BlockIds = @($keptIds)
            Renewals = [int]$renewals
        }
    } finally {
        $buffer = $null
    }
}

# ---------------------------------------------------------------------------
# Read-back comparison (spec 10.4)
# ---------------------------------------------------------------------------

function Get-PDIntuneReadBackValue {
    <#
        .SYNOPSIS
        Reads one (possibly nested) property from a read-back object, case-insensitively,
        without throwing. -Path is slash-separated: 'target/groupId'.
    #>
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $current = $Object
    foreach ($segment in ($Path -split '/')) {
        if ($null -eq $current) { return $null }

        $found = $null
        if ($current -is [System.Collections.IDictionary]) {
            foreach ($key in $current.Keys) {
                if (([string]$key) -ieq $segment) { $found = $current[$key]; break }
            }
        } else {
            try {
                foreach ($property in $current.PSObject.Properties) {
                    if ($property.Name -ieq $segment) { $found = $property.Value; break }
                }
            } catch { return $null }
        }

        $current = $found
    }

    return $current
}

function Compare-PDIntuneAppReadBack {
    <#
        .SYNOPSIS
        Compares the app the service now holds against what was submitted (spec 10.4).

        .DESCRIPTION
        Pure comparison; it issues no requests, which is what makes "no false success"
        testable. -Expected is a dictionary of label -> @{ Path; Value; Secret }: Path is
        the read-back path, Value is what was sent, and Secret suppresses the value in the
        mismatch message (commands and detection scripts can carry repository credentials,
        so for those the message reports lengths only).

        An expected value of $null means "not sent, nothing to verify" and is skipped.
        Service-normalized whitespace is tolerated (line endings and trailing space only);
        anything else is a mismatch, because a silent normalization here is a different app.

        .OUTPUTS
        Array of mismatch descriptions. Empty means the read-back agrees.
    #>
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [AllowNull()][object]$App
    )

    if ($Expected -isnot [System.Collections.IDictionary]) {
        Stop-PDGraphError -Message 'The read-back comparison needs a dictionary of expected values.' -Stage 'Verify'
    }

    $mismatches = @()

    foreach ($label in $Expected.Keys) {
        $entry  = $Expected[$label]
        $path   = [string]$entry['Path']
        $want   = $entry['Value']
        $secret = [bool]$entry['Secret']
        $isSet  = [bool]$entry['Set']

        if ([string]::IsNullOrWhiteSpace($path)) { $path = $label }
        if ($null -eq $want) { continue }

        $got = Get-PDIntuneReadBackValue -Object $App -Path $path

        $normalizedWant = $want
        $normalizedGot  = $got

        $isComparable = $true
        if ($isSet) {
            # A flags value ("x64,x86"): Intune hands it back in its own order ("x86,x64"), which
            # is the same setting (first live upload, 2026-10-12). Compared as a set.
            $normalizedWant = ((@(([string]$want) -split ',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique) -join ',')
            $normalizedGot  = ((@(([string]$got)  -split ',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique) -join ',')
        } elseif ($want -is [bool]) {
            $normalizedWant = [bool]$want
            try { $normalizedGot = [bool]$got } catch { $isComparable = $false }
        } elseif ($want -is [long]) {
            $normalizedWant = [long]$want
            $parsed = [long]0
            if ([long]::TryParse(([string]$got), [ref]$parsed)) { $normalizedGot = $parsed }
            elseif ($got -is [long]) { $normalizedGot = [long]$got }
            else { $normalizedGot = $got }
        } else {
            $normalizedWant = (([string]$want) -replace "`r`n", "`n" -replace "`r", "`n").TrimEnd([char[]]@("`n", " ", "`t"))
            $normalizedGot  = (([string]$got) -replace "`r`n", "`n" -replace "`r", "`n").TrimEnd([char[]]@("`n", " ", "`t"))
        }

        $same = ($isComparable -and ($normalizedWant -eq $normalizedGot))

        if (-not $same) {
            if ($secret) {
                # Lengths only: this is the field that can hold a repository credential.
                $mismatches += ("{0} does not match what was submitted (submitted {1} character(s), Intune reports {2})." -f `
                                $label, ([string]$want).Length, ([string]$got).Length)
            } else {
                $mismatches += ("{0} does not match what was submitted (submitted '{1}', Intune reports '{2}')." -f `
                                $label, (Remove-UrlCredential -Url ([string]$want)), (Remove-UrlCredential -Url ([string]$got)))
            }
        }
    }

    return $mismatches
}

function Compare-PDIntuneAssignmentSet {
    <#
        .SYNOPSIS
        Compares assignments as sets of group id + intent, ignoring order and the
        service-generated assignment ids (spec 10.4 / U07), and the app's category links as a
        set of category ids.

        .DESCRIPTION
        Returns one description per difference: a missing pair, an unexpected pair, a pair
        with the wrong intent, and the service reporting one group twice. Empty output means
        the tenant holds exactly what was asked for. Category links are compared the same way,
        but only when the caller read them back ($null Categories means no read was done).
    #>
    param(
        [AllowNull()][object[]]$Expected,
        [AllowNull()][object]$Assignments,
        [AllowNull()][string[]]$ExpectedCategoryIds,
        [AllowNull()][object]$Categories
    )

    $expectedKeys = @{}
    foreach ($group in @($Expected)) {
        if ($null -eq $group) { continue }
        $id     = [string](Get-PDIntuneReadBackValue -Object $group -Path 'Id')
        $intent = [string](Get-PDIntuneReadBackValue -Object $group -Path 'Intent')
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $expectedKeys[(($id.Trim()) + '|' + (($intent.Trim()).ToLowerInvariant()))] = $true
    }

    $actualKeys = @{}
    $duplicates = @()
    foreach ($assignment in (Get-PDGraphItems -Payload $Assignments)) {
        if ($null -eq $assignment) { continue }
        $id     = [string](Get-PDIntuneReadBackValue -Object $assignment -Path 'target/groupId')
        $intent = [string](Get-PDIntuneReadBackValue -Object $assignment -Path 'intent')
        if ([string]::IsNullOrWhiteSpace($id)) {
            # A built-in target has no group id; it is identified by its type (/AllDevices, /AllUsers).
            $id = Get-PDBuiltInAssignmentTargetByType -ODataType ([string](Get-PDIntuneReadBackValue -Object $assignment -Path 'target/@odata.type'))
        }
        if ([string]::IsNullOrWhiteSpace($id)) { continue }

        $key = (($id.Trim()) + '|' + (($intent.Trim()).ToLowerInvariant()))
        if ($actualKeys.ContainsKey($key)) {
            $duplicates += $key
        }
        $actualKeys[$key] = $true
    }

    $differences = @()

    foreach ($key in $expectedKeys.Keys) {
        if (-not $actualKeys.ContainsKey($key)) {
            $parts  = $key -split '\|'
            $found  = $false
            foreach ($actualKey in $actualKeys.Keys) {
                $actualParts = $actualKey -split '\|'
                if ($actualParts[0] -eq $parts[0]) {
                    $differences += ("group '{0}' is assigned with intent '{1}' instead of the requested '{2}'." -f $parts[0], [string]$actualParts[1], $parts[1])
                    $found = $true
                    break
                }
            }
            if (-not $found) { $differences += ("group '{0}' has no '{1}' assignment." -f $parts[0], $parts[1]) }
        }
    }

    foreach ($key in $actualKeys.Keys) {
        if (-not $expectedKeys.ContainsKey($key)) {
            $parts = $key -split '\|'
            $differences += ("Intune reports an assignment that was not requested: group '{0}' with intent '{1}'." -f $parts[0], $parts[1])
        }
    }

    foreach ($key in (@($duplicates) | Sort-Object -Unique)) {
        $parts = $key -split '\|'
        $differences += ("Intune reports more than one '{1}' assignment for group '{0}'." -f $parts[0], $parts[1])
    }

    # Categories: the links the app holds must be the links we asked for. Only compared when
    # the caller actually read them back.
    $wantedCategories = @{}
    foreach ($id in @($ExpectedCategoryIds)) {
        if ([string]::IsNullOrWhiteSpace([string]$id)) { continue }
        $wantedCategories[([string]$id).Trim()] = $true
    }

    if ($null -ne $Categories) {
        $actualCategories   = @{}
        $categoryDuplicates = @()
        foreach ($category in @(Get-PDGraphItems -Payload $Categories)) {
            if ($null -eq $category) { continue }
            $id = [string](Get-PDIntuneReadBackValue -Object $category -Path 'Id')
            if ([string]::IsNullOrWhiteSpace($id)) { continue }
            $id = $id.Trim()
            if ($actualCategories.ContainsKey($id)) { $categoryDuplicates += $id; continue }
            $actualCategories[$id] = $true
        }

        foreach ($id in $wantedCategories.Keys) {
            if (-not $actualCategories.ContainsKey($id)) {
                $differences += ("category '{0}' is not associated with the app." -f $id)
            }
        }

        foreach ($id in $actualCategories.Keys) {
            if (-not $wantedCategories.ContainsKey($id)) {
                $differences += ("Intune reports a category that was not requested: '{0}'." -f $id)
            }
        }

        foreach ($id in (@($categoryDuplicates) | Sort-Object -Unique)) {
            $differences += ("Intune reports category '{0}' more than once." -f $id)
        }
    }

    return $differences
}

# ---------------------------------------------------------------------------
# Provisioning: the interactive administrator channel (spec 7.1, 7.2, 7.4)
# ---------------------------------------------------------------------------
#
# Provisioning and rotation cannot run as the upload identity: spec 7.1 forbids the application
# that publishes apps from holding any application-management permission. The writes that create
# the registration, grant its two roles and add or remove its secrets are therefore made by a
# temporary, interactive, administrator-authenticated session (Microsoft.Graph.Authentication,
# -ContextScope Process), which is a second identity and a second network boundary:
#
#   Invoke-PDGraphTransport  - app-only (client credentials) Graph and storage calls: the upload
#                              path, tested through $PDGraph.TestTransport
#   Invoke-PDMgChannelAction - delegated (signed-in administrator) calls: provisioning only,
#                              tested through $PDGraph.MgChannel
#
# Both boundaries are single functions with one documented override each, both refuse to send a
# credential to a host that is not Microsoft Graph, and both hand every failure to the same
# sanitized error plumbing (New-PDGraphError, Get-PDGraphErrorInfo, Remove-UrlCredential).
#
# Nothing here is tenant-tested: spec 14 live acceptance covers the real service behaviour.

$script:PDMgModuleImported = $false

function Get-PDGraphProvisioningPrerequisite {
    <#
        .SYNOPSIS
        Can the interactive administrator channel be used on this machine at all?

        .OUTPUTS
        @{ Available; Version; Message } - Message is the exact prerequisite to show the operator,
        empty when nothing is missing.

        .DESCRIPTION
        Reports; never installs and never imports. Spec 7.1: an absent module must produce the
        exact prerequisite and return to the menu, and must not be installed as a side effect of
        loading Setup or this library, while uploads and the guided walkthrough stay usable.

        -Probe exists for tests, which cannot uninstall a module that is installed here: return
        $null (or nothing) from it to simulate a machine without the module.
    #>
    param( [AllowNull()][scriptblock]$Probe )

    if ($null -ne $script:PDGraph.MgChannel) {
        # An injected channel stands in for the whole module, prerequisite included.
        return @{ Available = $true; Version = 'injected'; Message = '' }
    }

    $version = $null

    if ($null -ne $Probe) {
        $version = [string](& $Probe)
    } else {
        try {
            $command = Get-Command -Name 'Connect-MgGraph' -ErrorAction SilentlyContinue
            if ($null -ne $command) {
                $version = [string]$command.Version
                if ([string]::IsNullOrWhiteSpace($version)) { $version = 'unknown' }
            }
        } catch { $version = $null }

        if ([string]::IsNullOrWhiteSpace($version)) {
            try {
                $installed = Get-Module -ListAvailable -Name ([string]$script:PDGraph.MgModuleName) |
                             Sort-Object -Property Version -Descending | Select-Object -First 1
                if ($null -ne $installed) { $version = [string]$installed.Version }
            } catch { $version = $null }
        }
    }

    if ([string]::IsNullOrWhiteSpace($version)) {
        return @{
            Available = $false
            Version   = $null
            Message   = ('The administrator sign-in needs the Microsoft Graph PowerShell module ({0}), which is not installed for this Windows account. Install it with: {1}' -f [string]$script:PDGraph.MgModuleName, [string]$script:PDGraph.MgModuleInstallHint)
        }
    }

    return @{ Available = $true; Version = $version; Message = '' }
}

function Get-PDGraphDelegatedChannel {
    <#
        .SYNOPSIS
        Resolves the administrator channel, refusing with the prerequisite text when the module is
        missing. Internal.
    #>
    param([string]$Stage = 'Provision')

    $injected = $script:PDGraph.MgChannel

    if ($null -ne $injected) {
        if ($injected -isnot [System.Collections.IDictionary]) {
            Stop-PDGraphError -Stage $Stage -Message 'The administrator channel override ($PDGraph.MgChannel) must be a hashtable of script blocks.'
        }
        foreach ($required in @('Connect', 'Disconnect', 'GetContext', 'Invoke')) {
            if ($null -eq $injected[$required]) {
                Stop-PDGraphError -Stage $Stage -Message ("The administrator channel override is missing its '{0}' script block, so a half-written fake cannot quietly pretend to work." -f $required)
            }
        }
        return @{ Name = 'injected'; Channel = $injected; Version = 'injected' }
    }

    $prerequisite = Get-PDGraphProvisioningPrerequisite
    if (-not $prerequisite.Available) {
        Stop-PDGraphError -Stage $Stage -Message $prerequisite.Message
    }

    return @{ Name = 'module'; Channel = $null; Version = $prerequisite.Version }
}

function Invoke-PDMgChannelRequest {
    <#
        .SYNOPSIS
        The real administrator-channel request: Invoke-MgGraphRequest, returned in the same
        normalized shape the app-only transport produces. Internal.
    #>
    param([AllowNull()][hashtable]$Arguments, [string]$Stage = 'Provision')

    $uri = [string]$Arguments['Uri']

    # The signed-in administrator's token can create applications and mint secrets, so the
    # non-Graph refusal protects far more here than it does on the upload path (spec 11.1).
    if (-not (Test-PDGraphUrlIsGraph -Url $uri)) {
        Stop-PDGraphError -Stage $Stage -Message 'Refusing to send the signed-in administrator credential to a host that is not Microsoft Graph.'
    }

    $method = ([string]$Arguments['Method']).ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($method)) { $method = 'GET' }

    $headers = @{}
    if ($null -ne $Arguments['Headers']) {
        foreach ($name in $Arguments['Headers'].Keys) { $headers[$name] = $Arguments['Headers'][$name] }
    }

    $body = [string]$Arguments['Body']
    if ([string]::IsNullOrWhiteSpace($body)) {
        $body = $null
    } elseif (-not $headers.ContainsKey('Content-Type')) {
        $headers['Content-Type'] = 'application/json'
    }

    $requestArguments = @{
        Uri         = $uri
        Method      = $method
        Headers     = $headers
        ErrorAction = 'Stop'
    }
    if ($null -ne $body) { $requestArguments['Body'] = $body }

    # Current versions can hand back the status code and headers without turning a 4xx into an
    # exception, which is what the retry policy needs. Older versions only throw, so the same
    # request is made again in a catch block below; the capability is probed, not assumed.
    $command       = $null
    try { $command = Get-Command -Name 'Invoke-MgGraphRequest' -ErrorAction SilentlyContinue } catch { $command = $null }
    $capturesStatus = ($null -ne $command) -and
                      $command.Parameters.ContainsKey('SkipHttpErrorCheck') -and
                      $command.Parameters.ContainsKey('StatusCodeVariable')

    if ($capturesStatus) {
        $statusCode  = 0
        $outHeaders  = $null
        $requestArguments['OutputType']            = 'Json'
        $requestArguments['SkipHttpErrorCheck']    = $true
        $requestArguments['StatusCodeVariable']    = 'statusCode'
        $requestArguments['ResponseHeadersVariable'] = 'outHeaders'

        $text = $null
        try {
            $text = Invoke-MgGraphRequest @requestArguments
        } catch {
            return (Get-PDGraphNormalizedResponse -ErrorRecord $_)
        }

        $normalisedHeaders = @{}
        try {
            foreach ($name in @('request-id', 'apim-request-id', 'Retry-After', 'x-ms-request-id')) {
                $value = Get-PDGraphResponseHeader -Headers $outHeaders -Name $name
                if ($null -ne $value) { $normalisedHeaders[$name] = $value }
            }
        } catch { }

        $status = 0
        $parsed = 0
        if ([int]::TryParse([string]$statusCode, [ref]$parsed)) { $status = $parsed }
        if ($null -eq $text) { $text = '' }
        if (($status -eq 0) -and (-not [string]::IsNullOrWhiteSpace($text))) { $status = 200 }

        if ($status -eq 0) {
            # No status code and no body: the module answered nothing at all. Say so instead of
            # inventing a 200, because a 200 here would be reported as a completed write.
            return (Get-PDGraphNormalizedResponse -ErrorRecord (
                    New-Object System.Management.Automation.ErrorRecord (
                        New-Object System.InvalidOperationException 'The Microsoft Graph module returned no status code for the administrator-channel request.'),
                        'PDMgChannelNoStatus', 'ReadError', $null))
        }

        return @{ StatusCode = $status; Body = [string]$text; Headers = $normalisedHeaders; TransportError = $null }
    }

    try {
        $text = Invoke-MgGraphRequest @requestArguments -OutputType Json
        if ($null -eq $text) { $text = '' }
        return @{ StatusCode = 200; Body = [string]$text; Headers = @{}; TransportError = $null }
    } catch {
        $normalized = Get-PDGraphNormalizedResponse -ErrorRecord $_
        if (($normalized.StatusCode -eq 0) -and (-not [string]::IsNullOrWhiteSpace($normalized.Body))) {
            # An older module turns an HTTP refusal into a plain exception. The status cannot be
            # recovered honestly, but the service's own reason must not be thrown away with it.
            $reason = Get-PDGraphServiceMessage -Body $normalized.Body
            if (-not [string]::IsNullOrWhiteSpace($reason)) {
                $normalized['TransportError']['Message'] = ('{0} The service answered: {1}' -f [string]$normalized['TransportError']['Message'], $reason)
            }
        }
        return $normalized
    }
}

function Invoke-PDMgChannelAction {
    <#
        .SYNOPSIS
        The single place the interactive administrator channel is touched: Connect, Disconnect,
        GetContext or Invoke. Internal.

        .DESCRIPTION
        Tests replace the whole channel with

            $PDGraph.MgChannel = @{ Connect = {...}; Disconnect = {...}; GetContext = {...}; Invoke = {...} }

        so a provisioning scenario is asserted on recorded requests exactly like an upload
        scenario, and no test can open a real sign-in prompt.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Connect', 'Disconnect', 'GetContext', 'Invoke')][string]$Action,
        [AllowNull()][hashtable]$Arguments,
        [string]$Stage = 'Provision'
    )

    $channel = Get-PDGraphDelegatedChannel -Stage $Stage

    if ($channel.Name -eq 'injected') {
        $handler = $channel.Channel[$Action]

        if ($Action -ne 'Invoke') { return (& $handler $Arguments) }

        try {
            return (& $handler $Arguments)
        } catch {
            # The seam has to fail the way the real channel fails (M4 finding 3): a scripted dead
            # connection is normalized into exactly the shape an Invoke-MgGraphRequest fault makes,
            # so the tests exercise the retry and lost-write logic instead of a shape production
            # cannot produce.
            return (Get-PDGraphNormalizedResponse -ErrorRecord $_)
        }
    }

    if ($Action -eq 'Invoke') {
        return (Invoke-PDMgChannelRequest -Arguments $Arguments -Stage $Stage)
    }

    if (-not $script:PDMgModuleImported) {
        try {
            Import-Module ([string]$script:PDGraph.MgModuleName) -ErrorAction Stop
            $script:PDMgModuleImported = $true
        } catch {
            Stop-PDGraphError -Stage $Stage -Message ((Get-PDGraphProvisioningPrerequisite).Message)
        }
    }

    try {
        if ($Action -eq 'Connect') {
            $connectArguments = @{ ContextScope = 'Process'; NoWelcome = $true; ErrorAction = 'Stop' }
            $tenant = Get-PDGraphTrimmedText -Value $Arguments['TenantId']
            if (-not [string]::IsNullOrWhiteSpace($tenant)) { $connectArguments['TenantId'] = $tenant }
            $scopes = @($Arguments['Scopes'])
            if ($scopes.Count -gt 0) { $connectArguments['Scopes'] = $scopes }

            # This is the one call in this library that may show a sign-in prompt, and only
            # because an operator asked for provisioning.
            $null = Connect-MgGraph @connectArguments
            return $null
        }

        if ($Action -eq 'Disconnect') {
            $null = Disconnect-MgGraph -ErrorAction SilentlyContinue
            return $null
        }

        return (Get-MgContext -ErrorAction Stop)
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        Stop-PDGraphError -Stage $Stage -Message ("The Microsoft Graph sign-in session could not be used for '{0}': {1}" -f $Action, [string]$info.Message)
    }
}

function New-PDGraphRequestUrl {
    <#
        .SYNOPSIS
        Turns a relative Graph path into the absolute URL that will actually be requested.

        .DESCRIPTION
        The same rule Invoke-PDGraphRequest applies: a path that already carries its API version
        ('/beta/...' or '/v1.0/...') has that prefix stripped and it selects the base, because
        concatenating a versioned base onto a versioned path produces /beta/beta/... and an
        unhelpful 404. An absolute URL is returned as-is so the caller can host-check it. The
        administrator channel needs the rule without Invoke-PDGraphRequest's app-only token, so
        both channels share this one implementation (a test asserts they agree).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [AllowNull()][string]$BaseUri
    )

    $target = ([string]$Uri).Trim()

    $versionedBase = $null
    if ($target -match '^/v1\.0(?=/|$)') {
        $versionedBase = [string]$script:PDGraph.GraphV1Base
        $target = $target.Substring(5)
    } elseif ($target -match '^/beta(?=/|$)') {
        $versionedBase = [string]$script:PDGraph.GraphBetaBase
        $target = $target.Substring(5)
    }

    if ($target -match '^https?://') { return $target }

    if ($target -notmatch '^/') { $target = '/' + $target }

    $base = [string]$script:PDGraph.GraphBetaBase
    if ($BaseUri) { $base = $BaseUri }
    if ($versionedBase) { $base = $versionedBase }

    return ($base.TrimEnd('/') + $target)
}

function Send-PDGraphDelegatedRequest {
    <#
        .SYNOPSIS
        Attempt/backoff/Retry-After policy for the administrator channel. Internal.

        .DESCRIPTION
        Mirrors Send-PDGraphRequest and reads the same centralized constants (spec 11.1), but the
        two channels cannot share a code path: one is raw HTTP with a client-credentials bearer,
        the other is a delegated cmdlet. 'Write' means never retry automatically - a lost
        addPassword or appRoleAssignment must be reconciled, not repeated.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Request,
        [ValidateSet('Read', 'Write')][string]$RetryMode = 'Read',
        [string]$Stage = 'Provision',
        [string]$Description
    )

    $maxAttempts = [int]$script:PDGraph.MaxAttempts
    if ($RetryMode -eq 'Write') { $maxAttempts = 1 }

    $target = $Description
    if ([string]::IsNullOrWhiteSpace($target)) { $target = Remove-UrlCredential ([string]$Request['Uri']) }

    $attempt      = 0
    $lastResponse = $null

    while ($true) {
        $attempt++
        $response = Invoke-PDMgChannelAction -Action 'Invoke' -Arguments $Request -Stage $Stage

        $isTransport = ([int]$response.StatusCode -eq 0)
        $retryable   = ($RetryMode -ne 'Write')
        if ($response.StatusCode -ge 400) {
            if ($response.StatusCode -lt 500 -and ($response.StatusCode -ne 429)) { $retryable = $false }
        }

        if (([int]$response.StatusCode -ge 200) -and ([int]$response.StatusCode -lt 300)) { return $response }

        $lastResponse = $response

        if ($retryable -and ($attempt -lt $maxAttempts)) {
            $delay = [double]$script:PDGraph.BaseRetryDelaySec * [math]::Pow(2, [double]($attempt - 1))

            $retryAfter = Get-PDGraphResponseHeader -Headers $response.Headers -Name 'Retry-After'
            if ($null -ne $retryAfter) {
                $seconds = 0.0
                if ([double]::TryParse(([string]$retryAfter).Trim(), [ref]$seconds)) { $delay = $seconds }
            }
            if ($delay -gt [double]$script:PDGraph.MaxRetryDelaySec) { $delay = [double]$script:PDGraph.MaxRetryDelaySec }
            if ($delay -lt 0) { $delay = 0 }

            Start-Sleep -Milliseconds ([int]($delay * 1000))
            continue
        }

        break
    }

    $status     = [int]$lastResponse.StatusCode
    $transport  = ($null -ne $lastResponse.TransportError) -and [bool]$lastResponse.TransportError.TransportFailure
    $requestId  = $null
    $retryAfter = Get-PDGraphResponseHeader -Headers $lastResponse.Headers -Name 'Retry-After'
    $approval   = $false
    $detail     = $null

    if (-not $transport) {
        if ($lastResponse.Headers.ContainsKey('request-id'))         { $requestId = $lastResponse.Headers['request-id'] }
        elseif ($lastResponse.Headers.ContainsKey('apim-request-id')) { $requestId = $lastResponse.Headers['apim-request-id'] }
        $detail   = Get-PDGraphServiceMessage -Body $lastResponse.Body
        $approval = Test-PDGraphApprovalRequired -Status $status -Body $lastResponse.Body -Headers $lastResponse.Headers
    }

    if ($transport) {
        $why = 'no HTTP response was received'
        if ($null -ne $lastResponse.TransportError) { $why = [string]$lastResponse.TransportError.Message }
        Stop-PDGraphError -Stage $Stage -Retryable ([bool]$retryable) -Message "The signed-in administrator request ($target) failed before reaching the service: $why"
    }

    $headline = "The signed-in administrator request ($target) was refused by Microsoft Graph."
    if ($approval) {
        $headline = 'Microsoft Graph requires Multi-Admin Approval for the signed-in administrator, so the provisioning write was blocked.'
    }

    Stop-PDGraphError -Stage $Stage -Message $headline -Status $status -RequestId $requestId `
        -RetryAfter $retryAfter -ApprovalRequired $approval -Retryable ([bool]$retryable) -Detail $detail
}

function Invoke-PDGraphDelegatedRequest {
    <#
        .SYNOPSIS
        One Microsoft Graph call made with the temporary interactive administrator session.

        .OUTPUTS
        The parsed JSON object, or $null for an empty (204) response. Pass collections through
        Get-PDGraphItems, exactly as for the app-only channel.

        .DESCRIPTION
        Provisioning only. Uploads never use this: the upload identity has no application
        permission to manage applications (spec 7.1).
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Get', 'Post', 'Patch', 'Put', 'Delete')][string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [AllowNull()][object]$Body,
        [ValidateSet('Read', 'Write')][string]$RetryMode = 'Read',
        [string]$Stage = 'Provision',
        [string]$Description
    )

    $target = New-PDGraphRequestUrl -Uri $Uri

    # Checked here, not only in the production channel, so the rule holds for an injected channel
    # too and is testable: the bearer this channel carries is an administrator's (spec 11.1).
    if (-not (Test-PDGraphUrlIsGraph -Url $target)) {
        Stop-PDGraphError -Stage $Stage -Message 'Refusing to send the signed-in administrator credential to a host that is not Microsoft Graph.'
    }

    $request = @{
        Method = $Method
        Uri    = $target
        Body   = $null
    }

    if ($null -ne $Body) {
        $json = $Body
        if (($Body -is [hashtable]) -or ($Body -is [System.Collections.IDictionary]) -or ($Body -is [Object[]])) {
            $json = ConvertTo-PDGraphJson -InputObject $Body
        }
        $request['Body'] = [string]$json
    }

    $response = Send-PDGraphDelegatedRequest -Request $request -RetryMode $RetryMode -Stage $Stage -Description $Description

    if ([int]$response.StatusCode -eq 204) { return $null }
    if ([string]::IsNullOrWhiteSpace($response.Body)) { return $null }

    try {
        return ($response.Body | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        return $response.Body
    }
}

function Get-PDGraphDelegatedCollection {
    <#
        .SYNOPSIS
        Every value across a delegated Graph collection and its @odata.nextLink pages.

        .DESCRIPTION
        The administrator-channel twin of Get-PDGraphCollection: a pagination link is only
        followed when it is an https Graph URL, because the authorization it would carry is an
        administrator's (spec 11.1).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Stage = 'Provision',
        [int]$MaxPages = 200
    )

    $values = @()
    $target = $Path
    $pages  = 0

    while ($true) {
        $pages++
        if ($pages -gt $MaxPages) {
            Stop-PDGraphError -Stage $Stage -Message "A Graph collection did not finish after $MaxPages pages; refusing to continue."
        }

        if ($target -match '^https?://') {
            if (-not (Test-PDGraphUrlIsGraph -Url $target)) {
                Stop-PDGraphError -Stage $Stage -Message 'A Graph collection returned a pagination link that is not an https Graph URL, so it was not followed.'
            }
        }

        $page = Invoke-PDGraphDelegatedRequest -Method Get -Uri $target -RetryMode 'Read' -Stage $Stage -Description 'collection page'

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

# ---------------------------------------------------------------------------
# Entra objects this feature creates and grants (spec 7.2)
# ---------------------------------------------------------------------------

function Find-PDEntraUploadApp {
    <#
        .SYNOPSIS
        Registrations whose displayName is exactly the upload application's name (spec 7.2 step 2).

        .OUTPUTS
        @{ Apps; Count; Found; Multiple; Message }

        .DESCRIPTION
        Several matches are reported, never resolved by picking one: the operator chooses, because
        the wrong choice would grant consent to somebody else's application. Matching is exact on
        the way in and re-checked locally, so a service-side change to filter semantics cannot
        turn this into a substring search.
    #>
    param(
        [AllowNull()][string]$DisplayName,
        [string]$Stage = 'Provision'
    )

    $name = Get-PDGraphTrimmedText -Value $DisplayName
    if ([string]::IsNullOrWhiteSpace($name)) { $name = [string]$script:PDGraph.AppDisplayName }

    $path = New-PDGraphQueryPath -Path ([string]$script:PDGraph.ApplicationsPath) -Query @{
        '$filter' = 'displayName eq ' + (ConvertTo-PDODataStringLiteral -Value $name)
        '$select' = 'id,appId,displayName,createdDateTime'
    }

    $apps = @()
    foreach ($item in (Get-PDGraphItems -Payload (Get-PDGraphDelegatedCollection -Path $path -Stage $Stage))) {
        if ($null -eq $item) { continue }

        $id       = [string](Get-PDGraphPropertyValue -Object $item -Name 'id')
        $itemname = [string](Get-PDGraphPropertyValue -Object $item -Name 'displayName')
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        if ($itemname.Trim() -ne $name) { continue }

        $apps += [pscustomobject]@{
            ApplicationId = $id
            ClientId      = [string](Get-PDGraphPropertyValue -Object $item -Name 'appId')
            DisplayName   = $itemname
            Created       = [string](Get-PDGraphPropertyValue -Object $item -Name 'createdDateTime')
        }
    }

    $message = "No application named '$name' exists in this tenant yet."
    if ($apps.Count -eq 1) { $message = "Found '$name' (application id $($apps[0].ApplicationId))." }
    if ($apps.Count -gt 1) { $message = "$($apps.Count) applications are named '$name'; choose which one PowerDeploy should use." }

    return @{
        Apps     = $apps
        Count    = $apps.Count
        Found    = ($apps.Count -ge 1)
        Multiple = ($apps.Count -gt 1)
        Message  = $message
    }
}

function Get-PDEntraApplication {
    <#
        .SYNOPSIS
        Reads one application registration by object id or by client (application) id.

        .DESCRIPTION
        "Not found here" is the answer to spec 7.2 step 1's question: a stored application id that
        belongs to another tenant simply does not exist in the tenant the operator signed in to,
        and saying that is safer than operating on a same-named app in the wrong directory.
    #>
    param(
        [AllowNull()][string]$ApplicationId,
        [AllowNull()][string]$ClientId,
        [string]$Stage = 'Provision'
    )

    $id   = Get-PDGraphTrimmedText -Value $ApplicationId
    $app  = Get-PDGraphTrimmedText -Value $ClientId

    if ([string]::IsNullOrWhiteSpace($id) -and [string]::IsNullOrWhiteSpace($app)) {
        Stop-PDGraphError -Stage $Stage -Message 'An application id or a client id is required to read an application registration.'
    }

    $select  = 'id,appId,displayName,createdDateTime,signInAudience'
    $objects = @()

    if (-not [string]::IsNullOrWhiteSpace($id)) {
        # An object id goes into the URL path, so it is either a GUID or nothing at all.
        if (-not (Test-PDGraphGuid $id)) {
            Stop-PDGraphError -Stage $Stage -Message 'The stored application object id is not a GUID, so it was not used to build a request.'
        }
        $path = New-PDGraphQueryPath -Path (([string]$script:PDGraph.ApplicationsPath) + '/' + ([guid]$id).ToString()) -Query @{ '$select' = $select }
        $objects = @((Invoke-PDGraphDelegatedRequest -Method Get -Uri $path -RetryMode 'Read' -Stage $Stage -Description 'application by object id'))
    } else {
        if (-not (Test-PDGraphGuid $app)) {
            Stop-PDGraphError -Stage $Stage -Message 'The client id is not a GUID, so no application lookup was attempted.'
        }
        $path = New-PDGraphQueryPath -Path ([string]$script:PDGraph.ApplicationsPath) -Query @{
            '$filter' = 'appId eq ' + (ConvertTo-PDODataStringLiteral -Value ([guid]$app).ToString())
            '$select' = $select
        }
        $objects = @(Get-PDGraphDelegatedCollection -Path $path -Stage $Stage)
    }

    $found = @()
    foreach ($item in $objects) {
        if ($null -eq $item) { continue }
        $itemId = [string](Get-PDGraphPropertyValue -Object $item -Name 'id')
        if ([string]::IsNullOrWhiteSpace($itemId)) { continue }
        $found += [pscustomobject]@{
            ApplicationId  = $itemId
            ClientId       = [string](Get-PDGraphPropertyValue -Object $item -Name 'appId')
            DisplayName    = [string](Get-PDGraphPropertyValue -Object $item -Name 'displayName')
            Created        = [string](Get-PDGraphPropertyValue -Object $item -Name 'createdDateTime')
            SignInAudience = [string](Get-PDGraphPropertyValue -Object $item -Name 'signInAudience')
        }
    }

    if ($found.Count -eq 0) {
        return @{ Found = $false; App = $null; Ambiguous = $false; Matches = @()
                  Message = 'This tenant has no such application registration. If the stored credential belongs to a different tenant, sign in to that one instead.' }
    }

    if ($found.Count -gt 1) {
        return @{ Found = $false; App = $null; Ambiguous = $true; Matches = $found
                  Message = "$($found.Count) registrations match, so none was chosen." }
    }

    return @{ Found = $true; App = $found[0]; Ambiguous = $false; Matches = $found; Message = "Found '$($found[0].DisplayName)'." }
}

function Ensure-PDEntraApplication {
    <#
        .SYNOPSIS
        The one registration PowerDeploy uploads as: verify the stored one, take the only one that
        exists, ask when several do, or create a single-tenant application when none does.

        .DESCRIPTION
        Spec 7.2 steps 1 and 2. Never deletes, never renames, and never guesses between two
        same-named applications: it answers NeedsSelection with the candidate ids and waits.
    #>
    param(
        [AllowNull()][string]$ApplicationId,
        [AllowNull()][string]$DisplayName,
        [AllowNull()][scriptblock]$Selection,
        [switch]$DryRun,
        [string]$Stage = 'Provision'
    )

    $name = Get-PDGraphTrimmedText -Value $DisplayName
    if ([string]::IsNullOrWhiteSpace($name)) { $name = [string]$script:PDGraph.AppDisplayName }

    if (-not [string]::IsNullOrWhiteSpace($ApplicationId)) {
        $looked = Get-PDEntraApplication -ApplicationId $ApplicationId -Stage $Stage
        if (-not $looked.Found) {
            $reason = 'NotFoundInTenant'
            if ($looked.Ambiguous) { $reason = 'Ambiguous' }
            return @{ Success = $false; Reason = $reason; Created = $false; App = $null; Candidates = @($looked.Matches); Message = $looked.Message }
        }
        return @{ Success = $true; Reason = 'Existing'; Created = $false; App = $looked.App; Candidates = @()
                    ApplicationId = $looked.App.ApplicationId; ClientId = $looked.App.ClientId; DisplayName = $looked.App.DisplayName
                    Message = "Using the stored application '$($looked.App.DisplayName)' ($($looked.App.ApplicationId)) in this tenant." }
    }

    $found = Find-PDEntraUploadApp -DisplayName $name -Stage $Stage

    if ($found.Multiple) {
        if ($null -eq $Selection) {
            return @{ Success = $false; Reason = 'NeedsSelection'; Created = $false; App = $null; Candidates = @($found.Apps)
                        Message = "$($found.Message) Re-run with one of those application ids." }
        }

        $chosen = $null
        try { $chosen = [string](& $Selection @($found.Apps)) } catch {
            Stop-PDGraphError -Stage $Stage -Message 'Choosing between the matching applications was cancelled.'
        }

        $picked = $null
        foreach ($candidate in @($found.Apps)) {
            if (([string]$candidate.ApplicationId) -ieq $chosen) { $picked = $candidate; break }
        }
        if ($null -eq $picked) {
            Stop-PDGraphError -Stage $Stage -Message 'The application chosen is not one of the matches in this tenant, so nothing was used.'
        }

        return @{ Success = $true; Reason = 'Selected'; Created = $false; App = $picked; Candidates = @()
                    ApplicationId = $picked.ApplicationId; ClientId = $picked.ClientId; DisplayName = $picked.DisplayName
                    Message = "Using the application '$($picked.DisplayName)' ($($picked.ApplicationId)) you selected." }
    }

    if ($found.Found) {
        $only = @($found.Apps)[0]
        return @{ Success = $true; Reason = 'Existing'; Created = $false; App = $only; Candidates = @()
                    ApplicationId = $only.ApplicationId; ClientId = $only.ClientId; DisplayName = $only.DisplayName
                    Message = $found.Message }
    }

    if ($DryRun) {
        return @{ Success = $true; Reason = 'DryRun'; Created = $false; App = $null; Candidates = @()
                  Message = "No application named '$name' exists; a dry run does not create it." }
    }

    $created = $null
    try {
        $created = Invoke-PDGraphDelegatedRequest -Method Post -Uri ([string]$script:PDGraph.ApplicationsPath) -RetryMode 'Write' -Stage $Stage `
                        -Description "create the '$name' application" `
                        -Body @{ displayName = $name; signInAudience = 'AzureADMyOrg' }
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        if ([int]$info.Status -eq 0) {
            return @{ Success = $false; Reason = 'UnknownCreate'; Created = $false; App = $null; Candidates = @()
                      Message = ("The create request for '$name' did not come back, so it is not known whether the application exists. It was not repeated. Run this option again and choose that application by id if it has appeared, or remove it in Entra. ({0})" -f [string]$info.Message) }
        }
        return @{ Success = $false; Reason = 'CreateFailed'; Created = $false; App = $null; Candidates = @(); Message = $info.Message }
    }

    $newId  = [string](Get-PDGraphPropertyValue -Object $created -Name 'id')
    $newApp = [string](Get-PDGraphPropertyValue -Object $created -Name 'appId')
    if ([string]::IsNullOrWhiteSpace($newId)) {
        return @{ Success = $false; Reason = 'CreateUnreadable'; Created = $false; App = $null; Candidates = @()
                  Message = "The create request for '$name' returned no application id, so nothing further was attempted." }
    }

    return @{ Success = $true; Reason = 'Created'; Created = $true; App = $created; Candidates = @()
                ApplicationId = $newId; ClientId = $newApp; DisplayName = $name
                Message = "Created the single-tenant application '$name' ($newId)." }
}

function Get-PDGraphServicePrincipal {
    <#
        .SYNOPSIS
        Reads the service principal for an application id (spec 7.2 steps 3 and 4).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$AppId,
        [switch]$WithAppRoles,
        [string]$Stage = 'Provision'
    )

    if (-not (Test-PDGraphGuid $AppId)) {
        Stop-PDGraphError -Stage $Stage -Message 'An application id GUID is required to look up a service principal.'
    }

    $select = 'id,appId,displayName'
    if ($WithAppRoles) { $select = 'id,appId,displayName,appRoles' }

    $path = New-PDGraphQueryPath -Path ([string]$script:PDGraph.ServicePrincipalsPath) -Query @{
        '$filter' = 'appId eq ' + (ConvertTo-PDODataStringLiteral -Value ([guid]$AppId).ToString())
        '$select' = $select
    }

    $found = @()
    foreach ($item in @(Get-PDGraphDelegatedCollection -Path $path -Stage $Stage)) {
        if ($null -eq $item) { continue }
        $id = [string](Get-PDGraphPropertyValue -Object $item -Name 'id')
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $found += [pscustomobject]@{
            ServicePrincipalId = $id
            AppId              = [string](Get-PDGraphPropertyValue -Object $item -Name 'appId')
            DisplayName        = [string](Get-PDGraphPropertyValue -Object $item -Name 'displayName')
            AppRoles           = (Get-PDGraphPropertyValue -Object $item -Name 'appRoles')
        }
    }

    if ($found.Count -eq 0) {
        return @{ Found = $false; Principal = $null; Ambiguous = $false; Matches = @(); Message = 'This tenant has no service principal for that application id.' }
    }
    if ($found.Count -gt 1) {
        return @{ Found = $false; Principal = $null; Ambiguous = $true; Matches = $found; Message = "$($found.Count) service principals share that application id, so none was used." }
    }

    return @{ Found = $true; Principal = $found[0]; Ambiguous = $false; Matches = $found; Message = "Found service principal '$($found[0].DisplayName)'." }
}

function Ensure-PDServicePrincipal {
    <#
        .SYNOPSIS
        Makes sure the upload application has a service principal, creating it from the client id
        when the tenant has not created one yet (spec 7.2 step 3).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ClientId,
        [switch]$DryRun,
        [string]$Stage = 'Provision'
    )

    if (-not (Test-PDGraphGuid $ClientId)) {
        Stop-PDGraphError -Stage $Stage -Message 'The upload application has no usable client id, so its service principal was not created.'
    }

    $clientText = ([guid]$ClientId).ToString()
    $looked     = Get-PDGraphServicePrincipal -AppId $clientText -Stage $Stage

    if ($looked.Ambiguous) {
        return @{ Success = $false; Reason = 'Ambiguous'; ServicePrincipalId = $null; Message = $looked.Message }
    }
    if ($looked.Found) {
        return @{ Success = $true; Reason = 'Existing'; ServicePrincipalId = $looked.Principal.ServicePrincipalId; Message = $looked.Message }
    }

    if ($DryRun) {
        return @{ Success = $false; Reason = 'DryRun'; ServicePrincipalId = $null
                  Message = 'No service principal exists yet; a dry run does not create one.' }
    }

    try {
        $created = Invoke-PDGraphDelegatedRequest -Method Post -Uri ([string]$script:PDGraph.ServicePrincipalsPath) -RetryMode 'Write' -Stage $Stage `
                        -Description 'create the upload service principal' -Body @{ appId = $clientText }
        $newId = [string](Get-PDGraphPropertyValue -Object $created -Name 'id')
        if ([string]::IsNullOrWhiteSpace($newId)) {
            return @{ Success = $false; Reason = 'CreateUnreadable'; ServicePrincipalId = $null
                      Message = 'The service principal create request returned no object id.' }
        }
        return @{ Success = $true; Reason = 'Created'; ServicePrincipalId = $newId; Message = 'Created the service principal for the upload application.' }
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        if ([int]$info.Status -eq 0) {
            return @{ Success = $false; Reason = 'UnknownCreate'; ServicePrincipalId = $null
                      Message = ("The service principal create request did not come back and was not repeated, so it may already exist. Run this option again to reuse it if it has appeared. ({0})" -f [string]$info.Message) }
        }
        return @{ Success = $false; Reason = 'CreateFailed'; ServicePrincipalId = $null; Message = $info.Message }
    }
}

function Resolve-PDEntraApplicationRole {
    <#
        .SYNOPSIS
        Turns required role NAMES into the role IDS the grant call needs (spec 7.2 step 4).

        .DESCRIPTION
        Pure: it takes the Graph service principal's appRoles and answers with ids. A role is only
        usable when its allowedMemberTypes include Application, because these are app-only
        permissions and a delegated-only role of the same name would grant nothing. A name with no
        match is reported, never approximated: 'DeviceManagementApps.ReadWrite.All' must not be
        satisfied by a substring match on some other DeviceManagement role.
    #>
    param(
        [AllowNull()][object]$AppRoles,
        [AllowNull()][string[]]$RequiredRoles
    )

    $wanted = @($RequiredRoles | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })

    $roleIds = @{}
    $missing = @()

    foreach ($roleName in $wanted) {
        $name  = ([string]$roleName).Trim()
        $found = $null

        foreach ($role in @(Get-PDGraphItems -Payload $AppRoles)) {
            if ($null -eq $role) { continue }

            $value = [string](Get-PDGraphPropertyValue -Object $role -Name 'value')
            if ($value.Trim() -ne $name) { continue }

            $memberTypes   = @(Get-PDGraphItems -Payload (Get-PDGraphPropertyValue -Object $role -Name 'allowedMemberTypes'))
            $applicationRole = $false
            foreach ($memberType in $memberTypes) {
                if (([string]$memberType).Trim() -eq 'Application') { $applicationRole = $true; break }
            }
            if (-not $applicationRole) { continue }

            $roleId = [string](Get-PDGraphPropertyValue -Object $role -Name 'id')
            if ([string]::IsNullOrWhiteSpace($roleId)) { continue }

            $found = $roleId.Trim()
            break
        }

        if ([string]::IsNullOrWhiteSpace($found)) { $missing += $name } else { $roleIds[$name] = $found }
    }

    return @{ RoleIds = $roleIds; Missing = $missing }
}

function Set-PDEntraRequiredResourceAccess {
    <#
        .SYNOPSIS
        Merges the resolved Graph roles into the registration's requested permissions without
        disturbing anything else it already asks for (spec 7.2 step 5).

        .DESCRIPTION
        Requested permissions are not consent (spec 7.2 step 6); this only records what the
        application would like, which is what makes it safe to run on a tenant where the operator
        cannot consent yet. The merge is additive by construction: every unrelated resourceAppId
        entry is carried over untouched and the Graph entry keeps its existing resourceAccess
        entries, because PATCH replaces the whole collection rather than adding to it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ApplicationId,
        [AllowNull()][hashtable]$RoleIds,
        [switch]$DryRun,
        [string]$Stage = 'Provision'
    )

    if (-not (Test-PDGraphGuid $ApplicationId)) {
        Stop-PDGraphError -Stage $Stage -Message 'The application object id is not a GUID, so its requested permissions were not changed.'
    }

    $wanted = @{}
    if ($null -ne $RoleIds) {
        foreach ($name in @($RoleIds.Keys)) {
            $wantedId = [string]$RoleIds[$name]
            if ([string]::IsNullOrWhiteSpace($wantedId)) { continue }
            $wanted[$wantedId.Trim()] = [string]$name
        }
    }

    if ($wanted.Count -eq 0) {
        return @{ Changed = $false; Added = @(); Message = 'No role ids were resolved, so the requested permissions were left exactly as they were.' }
    }

    $graphAppId = [string]$script:PDGraph.GraphServiceAppId
    $appPath    = ([string]$script:PDGraph.ApplicationsPath) + '/' + ([guid]$ApplicationId).ToString()

    $readPath = New-PDGraphQueryPath -Path $appPath -Query @{ '$select' = 'id,requiredResourceAccess' }
    $app      = Invoke-PDGraphDelegatedRequest -Method Get -Uri $readPath -RetryMode 'Read' -Stage $Stage -Description 'application requested permissions'

    $carried     = @()
    $graphAccess = @()
    $foundGraph  = $false

    foreach ($entry in @(Get-PDGraphItems -Payload (Get-PDGraphPropertyValue -Object $app -Name 'requiredResourceAccess'))) {
        if ($null -eq $entry) { continue }

        $resourceAppId = [string](Get-PDGraphPropertyValue -Object $entry -Name 'resourceAppId')
        $access        = @()

        foreach ($item in @(Get-PDGraphItems -Payload (Get-PDGraphPropertyValue -Object $entry -Name 'resourceAccess'))) {
            if ($null -eq $item) { continue }
            $accessId = [string](Get-PDGraphPropertyValue -Object $item -Name 'id')
            if ([string]::IsNullOrWhiteSpace($accessId)) { continue }
            $access += @{ id = $accessId.Trim(); type = [string](Get-PDGraphPropertyValue -Object $item -Name 'type') }
        }

        if ((-not [string]::IsNullOrWhiteSpace($resourceAppId)) -and ($resourceAppId.Trim() -eq $graphAppId)) {
            $foundGraph  = $true
            $graphAccess = $access
            continue
        }

        $carried += @{ resourceAppId = $resourceAppId; resourceAccess = $access }
    }

    $have = @()
    foreach ($existing in $graphAccess) { $have += [string]$existing['id'] }

    $added  = @()
    foreach ($roleId in $wanted.Keys) {
        if ($have -ccontains $roleId) { continue }
        $graphAccess += @{ id = $roleId; type = 'Role' }
        $added      += ("{0} ({1})" -f [string]$wanted[$roleId], $roleId)
    }

    if (@($added).Count -eq 0) {
        return @{ Changed = $false; Added = @(); Message = 'Both roles are already in the application requested permissions.' }
    }

    if ($DryRun) {
        return @{ Changed = $false; DryRun = $true; Added = $added
                  Message = ("A dry run does not change requested permissions. Would add: {0}." -f ($added -join ', ')) }
    }

    $entries = @()
    foreach ($kept in $carried) { $entries += $kept }
    $entries += @{ resourceAppId = $graphAppId; resourceAccess = $graphAccess }

    $null = Invoke-PDGraphDelegatedRequest -Method Patch -Uri $appPath -RetryMode 'Write' -Stage $Stage `
                -Description 'merge the requested permissions' -Body @{ requiredResourceAccess = $entries }

    return @{ Changed = $true; Added = $added
              Message = ("Added to the application requested permissions: {0}. Requesting permissions is not consent; the grant below is what consents." -f ($added -join ', ')) }
}

function Ensure-PDAppRoleAssignments {
    <#
        .SYNOPSIS
        Grants only the missing application roles, addressed by exact ids (spec 7.2 step 6).

        .DESCRIPTION
        Each grant is three ids and nothing else: principalId is the upload service principal,
        resourceId is the Microsoft Graph service principal, appRoleId is the resolved role id. No
        display name decides anything, an existing grant is never issued twice, and nothing is ever
        removed here - taking a permission away is a deliberate act, not a side effect of running
        the setup option.

        A grant is a write: a lost response is reported as unconfirmed and never repeated blind
        (spec 11.1), and one failed grant never stops the other role from being reported.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$UploadServicePrincipalId,
        [Parameter(Mandatory = $true)][string]$GraphServicePrincipalId,
        [AllowNull()][hashtable]$RoleIds,
        [switch]$DryRun,
        [string]$Stage = 'Provision'
    )

    foreach ($check in @(@{ n = 'upload service principal id'; v = $UploadServicePrincipalId },
                         @{ n = 'Microsoft Graph service principal id'; v = $GraphServicePrincipalId })) {
        if (-not (Test-PDGraphGuid $check.v)) {
            Stop-PDGraphError -Stage $Stage -Message ("The {0} is not a GUID, so no role was granted." -f $check.n)
        }
    }

    $principalId = ([guid]$UploadServicePrincipalId).ToString()
    $resourceId  = ([guid]$GraphServicePrincipalId).ToString()

    $wanted = @{}
    if ($null -ne $RoleIds) {
        foreach ($name in @($RoleIds.Keys)) {
            $wantedId = [string]$RoleIds[$name]
            if ([string]::IsNullOrWhiteSpace($wantedId)) { continue }
            $wanted[$wantedId.Trim()] = [string]$name
        }
    }

    if ($wanted.Count -eq 0) {
        return @{ Success = $false; Granted = @(); AlreadyGranted = @(); Failed = @()
                  Message = 'No role ids were resolved, so nothing was granted.' }
    }

    # The roles granted TO the upload service principal live under that principal:
    # /servicePrincipals/{upload principal}/appRoleAssignments. (Under the Microsoft Graph principal
    # that path lists roles granted to Microsoft Graph itself - the wrong list, and Graph refuses a
    # grant posted there.) Only grants on the Microsoft Graph resource count here.
    $assignPath = ([string]$script:PDGraph.ServicePrincipalsPath) + '/' + $principalId + '/appRoleAssignments'

    $listPath = New-PDGraphQueryPath -Path $assignPath -Query @{
        '$select' = 'id,appRoleId,principalId,resourceId'
    }

    $have = @()
    foreach ($grant in @(Get-PDGraphDelegatedCollection -Path $listPath -Stage $Stage)) {
        if ($null -eq $grant) { continue }
        $grantedTo = [string](Get-PDGraphPropertyValue -Object $grant -Name 'principalId')
        if ($grantedTo.Trim() -ne $principalId) { continue }
        $grantedOn = [string](Get-PDGraphPropertyValue -Object $grant -Name 'resourceId')
        if ($grantedOn.Trim() -ne $resourceId) { continue }
        $grantedRole = [string](Get-PDGraphPropertyValue -Object $grant -Name 'appRoleId')
        if ([string]::IsNullOrWhiteSpace($grantedRole)) { continue }
        $have += $grantedRole.Trim()
    }

    $granted       = @()
    $already       = @()
    $failed        = @()
    $unconfirmed   = @()

    foreach ($roleId in $wanted.Keys) {
        $roleName = [string]$wanted[$roleId]

        if ($have -ccontains $roleId) {
            $already += $roleName
            continue
        }

        if ($DryRun) {
            $granted += ("{0} (would grant)" -f $roleName)
            continue
        }

        try {
            $null = Invoke-PDGraphDelegatedRequest -Method Post -Uri $assignPath -RetryMode 'Write' -Stage $Stage `
                        -Description ("grant {0}" -f $roleName) `
                        -Body @{ principalId = $principalId; resourceId = $resourceId; appRoleId = $roleId }
            $granted += $roleName
        } catch {
            $info = Get-PDGraphErrorInfo -ErrorRecord $_
            if ([int]$info.Status -eq 0) {
                $unconfirmed += $roleName
                $failed += ("{0}: the grant request did not come back and was not repeated, so the role may or may not be granted. Check API permissions on the Azure App Registration in Entra before running this again." -f $roleName)
            } else {
                $failed += ("{0}: {1}" -f $roleName, [string]$info.Message)
            }
        }
    }

    # Only name the lists that have something in them ("Granted roles: ." read as a glitch).
    $parts = @()
    if (@($granted).Count -gt 0)   { $parts += ("Granted: {0}." -f (@($granted) -join ', ')) }
    if (@($already).Count -gt 0)   { $parts += ("Already granted: {0}." -f (@($already) -join ', ')) }
    $message = ($parts -join ' ')
    if ($DryRun)                   { $message = 'Dry run: no role was granted. ' + $message }
    if (@($failed).Count -gt 0)    { $message += (' Not confirmed: ' + (@($failed) -join ' | ')) }
    if (@($granted).Count -gt 0)   { $message += ' A newly granted role can take a minute to appear in the app-only token.' }

    return @{
        Success       = (@($failed).Count -eq 0)
        Granted       = @($granted)
        AlreadyGranted = @($already)
        Failed        = @($failed)
        Unconfirmed   = @($unconfirmed)
        Message       = $message
    }
}

function New-PDGraphSecretLabel {
    <#
        .SYNOPSIS
        The display name of a workstation secret: <user>@<computer> <date> (spec 7.2 step 7).

        .DESCRIPTION
        Pure, so the format is pinned by a test. The label is how an operator tells which of the
        application's secrets is theirs, which is what makes rotation safe to do on one workstation
        while other administrators keep their own secrets.
    #>
    param(
        [AllowNull()][object]$CreatedAt,
        [AllowNull()][string]$User,
        [AllowNull()][string]$Computer
    )

    $when = $CreatedAt
    if ($when -isnot [System.DateTimeOffset]) {
        if ($null -eq $when) {
            $when = [System.DateTimeOffset]::UtcNow
        } else {
            $parsed = [System.DateTimeOffset]::UtcNow
            if (-not [System.DateTimeOffset]::TryParse(([string]$when), [ref]$parsed)) { $parsed = [System.DateTimeOffset]::UtcNow }
            $when = $parsed
        }
    }

    $who = Get-PDGraphTrimmedText -Value $User
    if ([string]::IsNullOrWhiteSpace($who)) { $who = [string][Environment]::UserName }

    $where = Get-PDGraphTrimmedText -Value $Computer
    if ([string]::IsNullOrWhiteSpace($where)) { $where = [string][Environment]::MachineName }

    # A label is a display string: it must not be able to break a console line or a log line.
    # Whitespace (including a forged line break) collapses first, so the words it separated stay
    # separate; then anything left that is not printable goes.
    $who   = (($who   -replace '\s+', ' ') -replace '[^\P{C}]', '').Trim()
    $where = (($where -replace '\s+', ' ') -replace '[^\P{C}]', '').Trim()

    $date = $when.ToUniversalTime().ToString([string]$script:PDGraph.SecretLabelDateFormat, [System.Globalization.CultureInfo]::InvariantCulture)

    return ('{0}@{1} {2}' -f $who, $where, $date)
}

function Add-PDAppSecret {
    <#
        .SYNOPSIS
        Creates one secret on the upload application (spec 7.2 step 7).

        .OUTPUTS
        @{ Success; Outcome; KeyId; Secret; ExpiresOn; LifetimeDays; Label; Warnings; Message }

        Secret is a SecureString and the only place the value travels. It is never returned inside
        another object that gets logged, never written anywhere except the DPAPI credential store,
        and never shown. The plaintext string that the request body needs cannot be erased from
        memory (see the header note), so the rule is: never log it, never pass it further.

        .DESCRIPTION
        addPassword is a POST whose response can be lost, and repeating it blind would create a
        second secret, so a request that never came back answers Outcome='Unknown' with the
        instruction to reconcile in Entra (spec 11.1).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ApplicationId,
        [int]$LifetimeDays = 0,
        [AllowNull()][string]$Label,
        [switch]$DryRun,
        [string]$Stage = 'Provision'
    )

    if (-not (Test-PDGraphGuid $ApplicationId)) {
        Stop-PDGraphError -Stage $Stage -Message 'The application object id is not a GUID, so no secret was created.'
    }

    $days = [int]$LifetimeDays
    if ($days -le 0) { $days = [int]$script:PDGraph.DefaultSecretLifetimeDays }

    $warnings = @()

    if ($days -gt [int]$script:PDGraph.MaxSecretLifetimeDays) {
        return @{ Success = $false; Outcome = 'InvalidLifetime'; LifetimeDays = $days; Secret = $null; ExpiresOn = $null
                  Message = ("A {0}-day secret is beyond the {1}-day ceiling this tool will ask for. Choose a shorter lifetime (the tenant decides the real maximum)." -f $days, [int]$script:PDGraph.MaxSecretLifetimeDays) }
    }

    if ($days -gt [int]$script:PDGraph.WarnSecretLifetimeDays) {
        $warnings += ("A secret lasting {0} days is longer than the {1} days Entra recommends; the tenant may refuse it." -f $days, [int]$script:PDGraph.WarnSecretLifetimeDays)
    }

    $label = Get-PDGraphTrimmedText -Value $Label
    if ([string]::IsNullOrWhiteSpace($label)) { $label = New-PDGraphSecretLabel }

    $expires = [System.DateTimeOffset]::UtcNow.AddDays([double]$days)

    if ($DryRun) {
        return @{ Success = $true; Outcome = 'DryRun'; LifetimeDays = $days; Label = $label; Secret = $null; ExpiresOn = $null; Warnings = $warnings
                  Message = 'A dry run never creates a secret.' }
    }

    $secretPath = ([string]$script:PDGraph.ApplicationsPath) + '/' + ([guid]$ApplicationId).ToString() + '/addPassword'
    $endText    = $expires.ToUniversalTime().ToString([string]$script:PDGraph.SecretEndDateFormat, [System.Globalization.CultureInfo]::InvariantCulture)

    $created = $null
    try {
        $created = Invoke-PDGraphDelegatedRequest -Method Post -Uri $secretPath -RetryMode 'Write' -Stage $Stage `
                        -Description 'create the workstation secret' `
                        -Body @{ passwordCredential = @{ displayName = $label; endDateTime = $endText } }
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        if ([int]$info.Status -eq 0) {
            return @{ Success = $false; Outcome = 'Unknown'; LifetimeDays = $days; Label = $label; Secret = $null; ExpiresOn = $null; Warnings = $warnings
                      Message = ("The secret request did not come back, so it is not known whether a secret was created. It was not repeated. List the application secrets in Entra and use 'Azure App Registration - Remove local PC secret' if one was left behind. ({0})" -f [string]$info.Message) }
        }
        return @{ Success = $false; Outcome = 'Failed'; LifetimeDays = $days; Label = $label; Secret = $null; ExpiresOn = $null; Warnings = $warnings
                  Message = $info.Message }
    }

    $keyId      = [string](Get-PDGraphPropertyValue -Object $created -Name 'keyId')
    $secretText = [string](Get-PDGraphPropertyValue -Object $created -Name 'secretText')

    if ([string]::IsNullOrWhiteSpace($secretText)) {
        return @{ Success = $false; Outcome = 'NoSecretText'; LifetimeDays = $days; Label = $label; Secret = $null; ExpiresOn = $null; Warnings = $warnings
                  Message = 'The secret request answered without a secret value, so nothing was saved.' }
    }

    $expiresOn = $expires
    $endRead   = [string](Get-PDGraphPropertyValue -Object $created -Name 'endDateTime')
    if (-not [string]::IsNullOrWhiteSpace($endRead)) {
        $parsedEnd = [System.DateTimeOffset]::UtcNow
        if ([System.DateTimeOffset]::TryParse($endRead, [System.Globalization.DateTimeFormatInfo]::InvariantInfo, [System.Globalization.DateTimeStyles]::None, [ref]$parsedEnd)) {
            $expiresOn = $parsedEnd
        }
    }

    $secure = $null
    try {
        $secure = ConvertTo-SecureString -String $secretText -AsPlainText -Force
    } catch {
        return @{ Success = $false; Outcome = 'Failed'; LifetimeDays = $days; Label = $label; Secret = $null; ExpiresOn = $null; Warnings = $warnings
                  Message = 'The secret could not be protected as a SecureString, so it was not kept.' }
    } finally {
        $secretText = $null
    }

    return @{
        Success      = $true
        Outcome      = 'Created'
        KeyId        = (Get-PDGraphTrimmedText -Value $keyId)
        Secret       = $secure
        ExpiresOn    = $expiresOn
        LifetimeDays = $days
        Label        = $label
        Warnings     = $warnings
        Message      = ("Created a secret (key id {0}) that expires {1}." -f (Get-PDGraphTrimmedText -Value $keyId), $expiresOn.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture))
    }
}

function Remove-PDAppSecret {
    <#
        .SYNOPSIS
        Revokes exactly one secret, by its recorded key id (spec 7.4).

        .DESCRIPTION
        Never throws: rotation has to keep going when revocation fails, because the replacement
        secret already works and abandoning it would leave the workstation unable to upload. The
        caller reports the outcome.

        No key id means no revocation. The old secret is then reported for manual identification -
        it is never looked up by display name, and no other administrator's secret is ever touched.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ApplicationId,
        [AllowNull()][string]$KeyId,
        [AllowNull()][string]$Description,
        [switch]$DryRun,
        [string]$Stage = 'Provision'
    )

    $what = Get-PDGraphTrimmedText -Value $Description
    if ([string]::IsNullOrWhiteSpace($what)) { $what = 'secret' }

    if (-not (Test-PDGraphGuid $ApplicationId)) {
        return @{ Success = $false; Outcome = 'InvalidApplication'; Revoked = $false
                  Message = 'The application object id is not a GUID, so no secret was revoked.' }
    }

    if ([string]::IsNullOrWhiteSpace($KeyId)) {
        return @{ Success = $false; Outcome = 'NoKeyId'; Revoked = $false
                  Message = ("No key id is recorded for the old {0}, so it cannot be revoked automatically and nothing was attempted. Find it among the application secrets in Entra (by its label and expiry date) and revoke it there." -f $what) }
    }

    if (-not (Test-PDGraphGuid $KeyId)) {
        return @{ Success = $false; Outcome = 'InvalidKeyId'; Revoked = $false
                  Message = 'The recorded secret key id is not a GUID, so no secret was revoked.' }
    }

    $keyText = ([guid]$KeyId).ToString()

    if ($DryRun) {
        return @{ Success = $true; Outcome = 'DryRun'; Revoked = $false; KeyId = $keyText
                  Message = ("A dry run never revokes the {0} (key id {1})." -f $what, $keyText) }
    }

    $secretPath = ([string]$script:PDGraph.ApplicationsPath) + '/' + ([guid]$ApplicationId).ToString() + '/removePassword'

    try {
        $null = Invoke-PDGraphDelegatedRequest -Method Post -Uri $secretPath -RetryMode 'Write' -Stage $Stage `
                    -Description ("revoke the {0}" -f $what) -Body @{ keyId = $keyText }
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        if ([int]$info.Status -eq 0) {
            return @{ Success = $false; Outcome = 'Unknown'; Revoked = $false; KeyId = $keyText
                      Message = ("The revoke request for the {0} (key id {1}) did not come back and was not repeated, so the secret may still be active. Check the application secrets in Entra. ({2})" -f $what, $keyText, [string]$info.Message) }
        }
        return @{ Success = $false; Outcome = 'Failed'; Revoked = $false; KeyId = $keyText
                  Message = ("The {0} (key id {1}) could not be revoked and is still active: {2}" -f $what, $keyText, [string]$info.Message) }
    }

    return @{ Success = $true; Outcome = 'Removed'; Revoked = $true; KeyId = $keyText
              Message = ("Revoked the {0} (key id {1})." -f $what, $keyText) }
}

function Get-PDEntraAppSecretKey {
    <#
        .SYNOPSIS
        The application's secret key ids and expiry dates - never their values.

        .DESCRIPTION
        Used when a key id was never recorded and the operator has to identify the old secret in
        Entra: this shows what is there, and PowerDeploy still revokes nothing that it cannot
        address by id.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ApplicationId,
        [string]$Stage = 'Provision'
    )

    if (-not (Test-PDGraphGuid $ApplicationId)) {
        Stop-PDGraphError -Stage $Stage -Message 'The application object id is not a GUID, so its secrets were not listed.'
    }

    $path = New-PDGraphQueryPath -Path (([string]$script:PDGraph.ApplicationsPath) + '/' + ([guid]$ApplicationId).ToString()) -Query @{
        '$select' = 'id,displayName,passwordCredentials'
    }

    $app    = Invoke-PDGraphDelegatedRequest -Method Get -Uri $path -RetryMode 'Read' -Stage $Stage -Description 'application secret key ids'
    $keys   = @()

    foreach ($entry in @(Get-PDGraphItems -Payload (Get-PDGraphPropertyValue -Object $app -Name 'passwordCredentials'))) {
        if ($null -eq $entry) { continue }
        $keys += [pscustomobject]@{
            KeyId  = [string](Get-PDGraphPropertyValue -Object $entry -Name 'keyId')
            Label  = [string](Get-PDGraphPropertyValue -Object $entry -Name 'customKeyIdentifier')
            Starts = [string](Get-PDGraphPropertyValue -Object $entry -Name 'startDateTime')
            Expires = [string](Get-PDGraphPropertyValue -Object $entry -Name 'endDateTime')
        }
    }

    $message = 'This application has no secrets.'
    if (@($keys).Count -gt 0) { $message = "$(@($keys).Count) secret(s) on the application; PowerDeploy can only revoke one whose key id it recorded." }

    return @{ Keys = @($keys); Count = @($keys).Count; Message = $message }
}

# ---------------------------------------------------------------------------
# Interactive session (spec 7.1: temporary, delegated, verified, and disconnected again)
# ---------------------------------------------------------------------------

function Resolve-PDGraphDelegatedContext {
    <#
        .SYNOPSIS
        Decides what a Microsoft.Graph sign-in context means for provisioning. Pure.

        .DESCRIPTION
        Spec 7.1: verify the resulting context's tenant and delegated AuthType, and never reuse an
        unrelated connection silently. An application-only context (an automation identity that
        happens to be signed in) is exactly the "unrelated connection" that must be refused, and a
        context for another tenant would provision into the wrong directory.

        .OUTPUTS
        @{ Usable; Reason; Message; TenantId; Account; AuthType; Scopes; MissingScopes }
        Reason is Connected | NotConnected | NotDelegated | TenantMismatch | MissingScopes.
    #>
    param(
        [AllowNull()][object]$Context,
        [AllowNull()][string]$ExpectedTenantId,
        [AllowNull()][string[]]$RequiredScopes
    )

    $result = @{
        Usable        = $false
        Reason        = 'NotConnected'
        Message       = 'No Microsoft Graph sign-in session is open.'
        TenantId      = $null
        Account       = $null
        AuthType      = $null
        Scopes        = @()
        MissingScopes = @()
    }

    if ($null -eq $Context) { return $result }

    $tenant   = [string](Get-PDGraphPropertyValue -Object $Context -Name 'TenantId')
    $authType = [string](Get-PDGraphPropertyValue -Object $Context -Name 'AuthType')
    $account  = [string](Get-PDGraphPropertyValue -Object $Context -Name 'Account')
    $scopes   = @(Get-PDGraphItems -Payload (Get-PDGraphPropertyValue -Object $Context -Name 'Scopes'))

    $result.TenantId = $tenant
    $result.Account  = $account
    $result.AuthType = $authType
    $result.Scopes   = $scopes

    if ([string]::IsNullOrWhiteSpace($tenant) -and [string]::IsNullOrWhiteSpace($authType)) {
        return $result
    }

    if ($authType.Trim() -ne 'Delegated') {
        $result.Reason  = 'NotDelegated'
        $result.Message = ("The open Microsoft Graph session is not a delegated sign-in (it reports AuthType '{0}'). Provisioning needs an administrator to sign in, because the upload identity must not hold application-management permissions." -f $authType)
        return $result
    }

    $wanted = Get-PDGraphTrimmedText -Value $ExpectedTenantId
    if (-not [string]::IsNullOrWhiteSpace($wanted)) {
        if ($tenant.Trim() -ne $wanted) {
            $result.Reason  = 'TenantMismatch'
            $result.Message = ("The open Microsoft Graph session is for tenant '{0}', not the tenant '{1}' that was asked for." -f $tenant, $wanted)
            return $result
        }
    }

    $missing = @()
    foreach ($scope in @($RequiredScopes)) {
        $name = Get-PDGraphTrimmedText -Value $scope
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $granted = $false
        foreach ($held in $scopes) {
            if (([string]$held).Trim() -eq $name) { $granted = $true; break }
        }
        if (-not $granted) { $missing += $name }
    }

    $result.MissingScopes = $missing

    if (@($missing).Count -gt 0) {
        $result.Reason  = 'MissingScopes'
        $result.Message = ("The open Microsoft Graph session does not include {0}. Sign in again with those permissions; PowerDeploy cannot ask the tenant for them by itself." -f (($missing | ForEach-Object { "'$_'" }) -join ', '))
        return $result
    }

    $result.Usable  = $true
    $result.Reason  = 'Connected'
    $result.Message = "Signed in to tenant '$tenant' as '$account'."
    return $result
}

function Connect-PDGraphInteractive {
    <#
        .SYNOPSIS
        Opens (or reuses, when told to) the temporary interactive administrator session used by
        provisioning and rotation.

        .DESCRIPTION
        Spec 7.1: -ContextScope Process, verified tenant and delegated AuthType, disconnected when
        the operation finishes, and never silently reuse an unrelated connection. If the module is
        absent the exact prerequisite is returned and nothing is installed - uploads and the guided
        walkthrough stay usable either way.

        This is the only function in the library that may show a sign-in prompt, and only when an
        operator chose a provisioning option.

        .OUTPUTS
        @{ Success; Reason; Message; Session; Context }
        Reason is Connected | Reused | ModuleAbsent | ExistingContext | NotDelegated |
        TenantMismatch | MissingScopes | ConnectFailed.
    #>
    param(
        [AllowNull()][string]$TenantId,
        [AllowNull()][string[]]$Scope,
        [switch]$IncludeConsent,
        [switch]$ReuseExistingContext,
        [switch]$ReplaceExistingContext,
        [string]$Stage = 'Provision'
    )

    $prerequisite = Get-PDGraphProvisioningPrerequisite
    if (-not $prerequisite.Available) {
        return @{ Success = $false; Reason = 'ModuleAbsent'; Message = $prerequisite.Message; Session = $null; Context = $null }
    }

    # @($null) has ONE element, so "did the caller name any scope?" cannot be answered by counting
    # @($Scope): a blank-filter has to come first, or the default provisioning scope is never applied
    # and the sign-in would ask for nothing at all.
    $wanted = @()
    foreach ($entry in @($Scope)) {
        $entryText = ([string]$entry).Trim()
        if ([string]::IsNullOrWhiteSpace($entryText)) { continue }
        if ($wanted -ccontains $entryText) { continue }
        $wanted += $entryText
    }
    if (@($wanted).Count -eq 0) { $wanted = @($script:PDGraph.ProvisioningScopes) }
    if ($IncludeConsent) {
        $consent = [string]$script:PDGraph.ConsentScope
        if ($wanted -cnotcontains $consent) { $wanted = @($wanted) + $consent }
    }
    $wanted = @($wanted | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })

    $expectedTenant = Get-PDGraphTrimmedText -Value $TenantId

    $existing = $null
    try { $existing = Invoke-PDMgChannelAction -Action 'GetContext' -Stage $Stage } catch { $existing = $null }

    if ($null -ne $existing) {
        $existingVerdict = Resolve-PDGraphDelegatedContext -Context $existing -ExpectedTenantId $expectedTenant -RequiredScopes $wanted

        if (-not $ReuseExistingContext -and -not $ReplaceExistingContext) {
            return @{
                Success = $false
                Reason  = 'ExistingContext'
                Message = ("A Microsoft Graph sign-in session is already open ({0}). Choose whether to reuse it or sign in again; nothing was changed. {1}" -f $existingVerdict.Message, 'Reusing somebody else''s connection without saying so is not something this menu does.')
                Session = $null
                Context = $existingVerdict
            }
        }

        if ($ReuseExistingContext) {
            if (-not $existingVerdict.Usable) {
                return @{ Success = $false; Reason = $existingVerdict.Reason; Message = $existingVerdict.Message; Session = $null; Context = $existingVerdict }
            }
            return @{
                Success = $true
                Reason  = 'Reused'
                Message = ("Reusing the Microsoft Graph session already open in this process ({0}). It stays open afterwards because this operation did not create it." -f $existingVerdict.Message)
                Session = @{ TenantId = $existingVerdict.TenantId; Account = $existingVerdict.Account; AuthType = $existingVerdict.AuthType
                             Scopes = @($existingVerdict.Scopes); Owned = $false; Reused = $true; Version = $prerequisite.Version }
                Context = $existingVerdict
            }
        }
    }

    try {
        $null = Invoke-PDMgChannelAction -Action 'Connect' -Stage $Stage -Arguments @{ TenantId = $expectedTenant; Scopes = @($wanted) }
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        return @{ Success = $false; Reason = 'ConnectFailed'; Message = ("The sign-in did not complete: {0}" -f [string]$info.Message); Session = $null; Context = $null }
    }

    $context = $null
    try { $context = Invoke-PDMgChannelAction -Action 'GetContext' -Stage $Stage } catch { $context = $null }

    $verdict = Resolve-PDGraphDelegatedContext -Context $context -ExpectedTenantId $expectedTenant -RequiredScopes $wanted
    if (-not $verdict.Usable) {
        return @{ Success = $false; Reason = $verdict.Reason; Message = $verdict.Message; Session = $null; Context = $verdict }
    }

    return @{
        Success = $true
        Reason  = 'Connected'
        Message = $verdict.Message
        Session = @{ TenantId = $verdict.TenantId; Account = $verdict.Account; AuthType = $verdict.AuthType
                     Scopes = @($verdict.Scopes); Owned = $true; Reused = $false; Version = $prerequisite.Version }
        Context = $verdict
    }
}

function Disconnect-PDGraphInteractive {
    <#
        .SYNOPSIS
        Closes the sign-in session this tool created - and never somebody else's.

        .DESCRIPTION
        Spec 7.1: disconnect a session created by the wizard when the operation completes. A
        session that was already open when the option started is left where it was, because closing
        it would be an unrelated side effect on whatever else the operator was doing.
    #>
    param(
        [AllowNull()][object]$Session,
        [string]$Stage = 'Provision'
    )

    if ($null -eq $Session) {
        return @{ Disconnected = $false; Reason = 'NoSession'; Message = 'There was no sign-in session to close.' }
    }

    $owned = $false
    try { $owned = [bool](Get-PDGraphPropertyValue -Object $Session -Name 'Owned') } catch { $owned = $false }

    if (-not $owned) {
        return @{ Disconnected = $false; Reason = 'NotOwned'; Message = 'The sign-in session was already open when this started, so it was left open.' }
    }

    try {
        $null = Invoke-PDMgChannelAction -Action 'Disconnect' -Stage $Stage
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        return @{ Disconnected = $false; Reason = 'Failed'; Message = ("The sign-in session could not be closed: {0} It will expire on its own." -f [string]$info.Message) }
    }

    return @{ Disconnected = $true; Reason = 'Disconnected'; Message = 'The temporary sign-in session was closed.' }
}

# ---------------------------------------------------------------------------
# Using a credential: proving it works without ever showing it
# ---------------------------------------------------------------------------

function Get-PDGraphCredentialProbe {
    <#
        .SYNOPSIS
        The shape Get-PDGraphToken needs, built from either credential shape. Internal.

        .DESCRIPTION
        New-PDGraphCredentialObject holds SecretExpiresOn as the ISO-8601 string that goes to disk;
        Get-PDGraphCredential hands back a DateTimeOffset. Both are correct for their purpose, and a
        token test that compared one of them as a string would be comparing nonsense. This
        normalizes it and carries nothing else onward.
    #>
    param( [Parameter(Mandatory = $true)][AllowNull()][object]$Credential )

    if ($null -eq $Credential) {
        Stop-PDGraphError -Stage 'Credential' -Message 'A credential is required to test it.'
    }

    $secret = Get-PDGraphPropertyValue -Object $Credential -Name 'ClientSecret'
    if ($secret -isnot [System.Security.SecureString]) {
        Stop-PDGraphError -Stage 'Credential' -Message 'The credential does not hold a protected SecureString secret, so it cannot be tested.'
    }

    $raw     = Get-PDGraphPropertyValue -Object $Credential -Name 'SecretExpiresOn'
    $expires = $null

    if ($raw -is [System.DateTimeOffset]) {
        $expires = [System.DateTimeOffset]$raw
    } elseif ($raw -is [DateTime]) {
        $expires = [System.DateTimeOffset]::new(([DateTime]$raw).ToUniversalTime())
    } else {
        $text  = ([string]$raw).Trim()
        $dot   = [System.DateTimeOffset]::UtcNow
        $plain = [DateTime]::MinValue
        if ([System.DateTimeOffset]::TryParse($text, [System.Globalization.DateTimeFormatInfo]::InvariantInfo, [System.Globalization.DateTimeStyles]::None, [ref]$dot)) {
            $expires = $dot
        } elseif ([DateTime]::TryParse($text, [ref]$plain)) {
            $expires = [System.DateTimeOffset]::new($plain.ToUniversalTime())
        }
    }

    if ($null -eq $expires) {
        Stop-PDGraphError -Stage 'Credential' -Message 'The credential has no usable expiry date, so it cannot be tested safely.'
    }

    return @{
        TenantId        = [string](Get-PDGraphPropertyValue -Object $Credential -Name 'TenantId')
        ClientId        = [string](Get-PDGraphPropertyValue -Object $Credential -Name 'ClientId')
        ClientSecret    = $secret
        SecretExpiresOn = $expires
    }
}

function Wait-PDGraphUploadSecretReady {
    <#
        .SYNOPSIS
        Waits, within spec 11.1's propagation deadline, for a brand-new secret and its newly
        granted roles to work.

        .DESCRIPTION
        A secret or a role that was just created is not always immediately accepted, and the
        operator cannot tell that apart from a mistake. So: retry the real thing (a token request
        plus the roles it carries) until it works or the deadline passes. A secret the token
        endpoint rejects outright (wrong or unknown application) is reported at once instead of
        being retried until the deadline - unless -SecretJustCreated says the secret (and maybe the
        application) was created moments ago. Then "invalid client secret" and "application not
        found" are exactly what replication lag looks like, so they are waited out too (first live
        run, 2026-10-12: AADSTS7000215 in the same second the secret was created). A wrong tenant
        is still reported at once.

        The secret value is never part of the answer, and neither is the token.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Credential,
        [AllowNull()][string[]]$RequiredRoles,
        [double]$DeadlineSec = 0,
        [switch]$SecretJustCreated,
        [string]$Stage = 'Credential'
    )

    # The same @($null).Count trap as the sign-in scopes, and a nastier one: with a blank filter the
    # required-role default actually applies, instead of "no role is required" silently meaning any
    # token at all counts as ready.
    $roles = @()
    foreach ($entry in @($RequiredRoles)) {
        $entryText = ([string]$entry).Trim()
        if ([string]::IsNullOrWhiteSpace($entryText)) { continue }
        if ($roles -ccontains $entryText) { continue }
        $roles += $entryText
    }
    if (@($roles).Count -eq 0) { $roles = @($script:PDGraph.RequiredAppRoles) }

    $deadlineSeconds = [double]$DeadlineSec
    if ($deadlineSeconds -le 0) { $deadlineSeconds = [double]$script:PDGraph.PropagationDeadlineSec }

    $probe    = Get-PDGraphCredentialProbe -Credential $Credential
    $deadline = [DateTime]::UtcNow.AddSeconds($deadlineSeconds)
    $attempts = 0
    $last     = 'The token endpoint has not answered yet.'

    while ($true) {
        $attempts++

        $token      = $null
        $failure    = $null
        try {
            $token = Get-PDGraphToken -Credential $probe -Force
        } catch {
            $failure = Get-PDGraphErrorInfo -ErrorRecord $_
            $last    = [string]$failure.Message

            $hardCodes = @('invalid_client', 'AADSTS7000215', 'AADSTS700016', 'AADSTS90002')
            if ($SecretJustCreated) { $hardCodes = @('AADSTS90002') }

            foreach ($hard in $hardCodes) {
                if ($last -like "*$hard*") {
                    return @{ Ready = $false; Roles = @(); MissingRoles = @($roles); Attempts = $attempts
                              Reason = 'SecretRejected'
                              Message = ("The token endpoint refused this secret outright, so waiting will not help: {0}" -f $last) }
                }
            }
        }

        if ($null -ne $token) {
            $held        = @()
            try { $held = @($token.Roles) } catch { $held = @() }

            $missing = @()
            foreach ($role in $roles) {
                $name = ([string]$role).Trim()
                if ([string]::IsNullOrWhiteSpace($name)) { continue }

                $found = $false
                foreach ($grant in $held) {
                    if (([string]$grant).Trim() -eq $name) { $found = $true; break }
                }
                if (-not $found) { $missing += $name }
            }

            if (@($missing).Count -eq 0) {
                return @{ Ready = $true; Roles = @($held); MissingRoles = @(); Attempts = $attempts; Reason = 'Ready'
                          Message = ("The secret works and the token carries {0} application role(s) (attempt {1})." -f @($held).Count, $attempts) }
            }

            $last = ("The secret works but the token does not carry {0} yet." -f (($missing | ForEach-Object { "'$_'" }) -join ', '))
        }

        if ([DateTime]::UtcNow -ge $deadline) {
            return @{ Ready = $false; Roles = @(); MissingRoles = @($roles); Attempts = $attempts; Reason = 'Deadline'
                      Message = ("Waited {0} second(s) for the new secret and its permissions to become usable, and it still is not: {1} Nothing was saved, so the credential that works today is unchanged." -f [math]::Round($deadlineSeconds, 0), $last) }
        }

        Start-Sleep -Milliseconds ([int]$script:PDGraph.PropagationIntervalMs)
    }
}

function Get-PDGraphCredentialSummary {
    <#
        .SYNOPSIS
        What is stored, in display-safe terms: identifiers and expiry, never the secret.
    #>
    param( [AllowNull()][string]$CredentialPath )

    $resolved = Get-PDGraphCredentialPath -Path $CredentialPath

    if (-not [System.IO.File]::Exists($resolved)) {
        return @{ Stored = $false; Path = $resolved; Message = 'No credential is stored for this Windows account at that path.' }
    }

    $credential = $null
    try {
        $credential = Get-PDGraphCredential -Path $CredentialPath
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        return @{ Stored = $true; Usable = $false; Path = $resolved; Message = $info.Message }
    }

    return @{
        Stored            = $true
        Usable            = $true
        Path              = $resolved
        AppDisplayName    = [string]$credential.AppDisplayName
        TenantId          = [string]$credential.TenantId
        ClientId          = [string]$credential.ClientId
        AppObjectId       = [string]$credential.AppObjectId
        ServicePrincipalId = [string]$credential.ServicePrincipalId
        SecretKeyId       = [string]$credential.SecretKeyId
        SecretExpiresOn   = $credential.SecretExpiresOn
        DaysUntilExpiry   = $credential.DaysUntilExpiry
        Warnings          = @($credential.Warnings)
        Message           = 'A usable credential is stored for this Windows account.'
    }
}

function Get-PDGraphCredentialMetadata {
    <#
        .SYNOPSIS
        Reads the stored credential for administration, not for uploading.

        .DESCRIPTION
        Rotation has to work with an EXPIRED secret - that is the whole point - while uploads must
        refuse one. Get-PDGraphCredential does the latter, so this loader runs the same format and
        safety validation (schema, GUIDs, SecureString-only) and simply does not apply the expiry
        rule. It returns no more than the loader does: the secret stays a SecureString.
    #>
    param( [AllowNull()][string]$Path )

    $resolved = Get-PDGraphCredentialPath -Path $Path

    if (-not [System.IO.File]::Exists($resolved)) {
        Stop-PDGraphError -Stage 'Credential' -Message ("No upload credential is stored for this Windows account, so there is nothing to rotate. Expected: $resolved")
    }

    $raw = $null
    try {
        $raw = Import-Clixml -LiteralPath $resolved -ErrorAction Stop
    } catch {
        $reason = ([string]$_.Exception.Message)
        if ($reason -match '(?i)decrypt|cryptograph|key|padding|mac|bad data|not valid|rmtp|protected') {
            Stop-PDGraphError -Stage 'Credential' -Message 'The stored credential could not be decrypted by this Windows account, so it cannot be rotated. Re-enter it ('Azure App Registration - Setup/Config', Manual) or remove it ('Azure App Registration - Remove local PC secret').'
        }
        Stop-PDGraphError -Stage 'Credential' -Message ("The stored credential file could not be read and may be corrupt, so it cannot be rotated. ({0})" -f $reason)
    }

    $problem = $null
    $record  = ConvertFrom-PDGraphCredentialFile -Raw $raw -Problem ([ref]$problem)

    if ($null -eq $record) {
        Stop-PDGraphError -Stage 'Credential' -Message ("The stored credential file is not usable, so it cannot be rotated: {0}" -f $problem)
    }

    $record.Path = $resolved
    return $record
}

function Start-PDGraphSecretRotation {
    <#
        .SYNOPSIS
        Rotates this workstation's secret in the exact order spec 7.4 requires.

        .DESCRIPTION
        1. Load the stored credential (an expired secret still rotates - that is the point) and use
           the administrator session that was verified against the right tenant.
        2. Add the replacement secret while the old credential and old key are still in place.
        3. Test the replacement, with bounded propagation retries.
        4. Save it and read it back.
        5. Only then remove the OLD secret, by its recorded key id.

        If the test or the save fails, the old local credential is still there and untouched, and
        the just-created key is revoked - but only when its exact id is known, otherwise the id is
        reported for cleanup. If removing the old key fails, the new credential is kept and working
        and the old key is reported as still active. Nothing is ever revoked by display name.
    #>
    param(
        [AllowNull()][string]$CredentialPath,
        [AllowNull()][object]$Session,
        [AllowNull()][string]$AppObjectId,
        [int]$SecretLifetimeDays = 0,
        [AllowNull()][string]$Label,
        [switch]$SkipOldKeyRevocation,
        [switch]$DryRun,
        [string]$Stage = 'Rotate'
    )

    $answer = @{
        Success                = $false
        Reason                 = $null
        Stage                  = $Stage
        ApplicationId          = $null
        SecretKeyId            = $null
        NewSecretExpiresOn     = $null
        NewDaysUntilExpiry     = $null
        SavedTo                = $null
        OldCredentialRetained  = $true
        OldKeyRemoved          = $false
        OldKeyId               = $null
        LeftoverKeyId          = $null
        Warnings               = @()
        Message                = $null
    }

    $cleanupNewKey = {
        param($CreatedApplicationId, $CreatedKeyId, $Why)

        if ([string]::IsNullOrWhiteSpace($CreatedKeyId)) {
            return @{ Leftover = 'unknown'; Note = 'The replacement secret was created but its key id is not known, so it could not be revoked automatically. Find it in Entra by its label and expiry, and revoke it there.' }
        }

        $removal = Remove-PDAppSecret -ApplicationId $CreatedApplicationId -KeyId $CreatedKeyId -Description 'replacement secret (rotation aborted)' -Stage $Stage
        if ($removal.Success) {
            return @{ Leftover = $null; Note = ("The replacement secret (key id {0}) was revoked again, so only the original secret remains." -f ([guid]$CreatedKeyId).ToString()) }
        }
        return @{ Leftover = ([guid]$CreatedKeyId).ToString(); Note = ("The replacement secret (key id {0}) could not be revoked and is still active: {1}" -f ([guid]$CreatedKeyId).ToString(), [string]$removal.Message) }
    }

    # --- 1. stored credential + verified tenant ------------------------------------------
    $old = $null
    try {
        $old = Get-PDGraphCredentialMetadata -Path $CredentialPath
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        $answer.Reason  = 'NoCredential'
        $answer.Message = $info.Message
        return $answer
    }

    $answer.OldKeyId = [string]$old.SecretKeyId

    $expired = ($old.SecretExpiresOn -le [System.DateTimeOffset]::UtcNow)
    if ($expired) {
        $answer.Warnings += ("The stored secret expired on {0}; rotation can still replace it." -f $old.SecretExpiresOn.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture))
    }

    $sessionTenant = [string](Get-PDGraphPropertyValue -Object $Session -Name 'TenantId')
    if ((-not [string]::IsNullOrWhiteSpace($sessionTenant)) -and
        ($sessionTenant.Trim().ToLowerInvariant() -ne ([string]$old.TenantId).Trim().ToLowerInvariant())) {
        $answer.Reason  = 'TenantMismatch'
        $answer.Message = ("You are signed in to tenant '{0}' but the stored credential belongs to tenant '{1}'. Sign in to the tenant that owns this application; nothing was changed." -f $sessionTenant, [string]$old.TenantId)
        return $answer
    }

    # --- 2. which application, verified to be in this tenant -------------------------------
    $wantedApplication = Get-PDGraphTrimmedText -Value $AppObjectId
    if ([string]::IsNullOrWhiteSpace($wantedApplication)) { $wantedApplication = Get-PDGraphTrimmedText -Value $old.AppObjectId }

    $looked = $null
    if (-not [string]::IsNullOrWhiteSpace($wantedApplication)) {
        $looked = Get-PDEntraApplication -ApplicationId $wantedApplication -Stage $Stage
    } else {
        $looked = Get-PDEntraApplication -ClientId $old.ClientId -Stage $Stage
    }

    if (-not $looked.Found) {
        $answer.Reason  = 'NoApplication'
        $answer.Message = ("The stored credential's application could not be found in the tenant you signed in to ({0}). Nothing was changed; re-enter the credential instead ('Azure App Registration - Setup/Config', Manual)." -f $looked.Message)
        return $answer
    }

    $applicationId = [string]$looked.App.ApplicationId
    $answer.ApplicationId = $applicationId

    $label = Get-PDGraphTrimmedText -Value $Label
    if ([string]::IsNullOrWhiteSpace($label)) { $label = New-PDGraphSecretLabel }

    if ($DryRun) {
        $answer.Success        = $true
        $answer.Reason         = 'DryRun'
        $answer.Message        = ("A dry run: it would add a new secret to '{0}' ({1}), test it, save it, and then revoke the old secret {2}. Nothing was created, saved, or revoked." -f $looked.App.DisplayName, $applicationId, $(if ([string]::IsNullOrWhiteSpace($old.SecretKeyId)) { '(none recorded - it would be reported for manual cleanup)' } else { ([guid]$old.SecretKeyId).ToString() }))
        $answer.LeftoverKeyId  = $null
        return $answer
    }

    # --- 3. add the replacement while the old one still works ------------------------------
    $created = Add-PDAppSecret -ApplicationId $applicationId -LifetimeDays $SecretLifetimeDays -Label $label -Stage $Stage
    if (-not $created.Success) {
        $answer.Reason  = $(if ($created.Outcome -eq 'Unknown') { 'SecretUnknown' } else { 'SecretFailed' })
        $answer.Message = ("The new secret could not be created, so the existing credential is unchanged. {0}" -f [string]$created.Message)
        return $answer
    }

    foreach ($warning in @($created.Warnings)) {
        if (-not [string]::IsNullOrWhiteSpace($warning)) { $answer.Warnings += [string]$warning }
    }

    $answer.SecretKeyId        = [string]$created.KeyId
    $answer.NewSecretExpiresOn = $created.ExpiresOn

    $candidate = New-PDGraphCredentialObject -TenantId $old.TenantId -ClientId $old.ClientId `
                    -ClientSecret $created.Secret -SecretExpiresOn $created.ExpiresOn `
                    -SecretKeyId $created.KeyId -AppObjectId $applicationId `
                    -ServicePrincipalId $old.ServicePrincipalId -AppDisplayName $old.AppDisplayName

    # --- 4a. prove it works before anything is overwritten ---------------------------------
    $test = Wait-PDGraphUploadSecretReady -Credential $candidate -SecretJustCreated -Stage $Stage
    if (-not $test.Ready) {
        $cleanup = & $cleanupNewKey $applicationId $created.KeyId
        $answer.Reason                = 'TestFailed'
        $answer.OldCredentialRetained = $true
        $answer.LeftoverKeyId         = $cleanup.Leftover
        $answer.Message               = ("The new secret did not become usable, so the stored credential was NOT replaced and the old secret is still valid. {0} {1}" -f [string]$test.Message, [string]$cleanup.Note)
        return $answer
    }

    # --- 4b. save, then read back ----------------------------------------------------------
    $saved = $null
    try {
        $saved = Save-PDGraphCredential -Credential $candidate -Path $CredentialPath
    } catch {
        $info    = Get-PDGraphErrorInfo -ErrorRecord $_
        $cleanup = & $cleanupNewKey $applicationId $created.KeyId
        $answer.Reason                = 'SaveFailed'
        $answer.OldCredentialRetained = $true
        $answer.LeftoverKeyId         = $cleanup.Leftover
        $answer.Message               = ("The new secret works but could not be stored, so the previous credential is unchanged. {0} {1}" -f [string]$info.Message, [string]$cleanup.Note)
        return $answer
    }

    try {
        $null = Get-PDGraphCredential -Path $CredentialPath
    } catch {
        $info              = Get-PDGraphErrorInfo -ErrorRecord $_
        $answer.Success    = $false
        $answer.Reason     = 'ReloadFailed'
        $answer.SavedTo    = [string]$saved.Path
        $answer.OldCredentialRetained = $false
        $answer.Message    = ("The replacement credential was written but could not be read back: {0} Nothing was revoked, so the original secret is still active and can be used again once the file is sorted out." -f [string]$info.Message)
        return $answer
    }

    $answer.Success           = $true
    $answer.Reason            = 'Rotated'
    $answer.OldKeyRemoved     = $false
    $answer.OldCredentialRetained = $false
    $answer.SavedTo           = [string]$saved.Path
    $answer.NewDaysUntilExpiry = $saved.DaysUntilExpiry
    #$answer.Warnings += 'The Multi-Admin Approval exclusion belongs to the application, so it still covers this workstation after the rotation.'

    # --- 5. only now revoke the old key, by exact id ---------------------------------------
    if ($SkipOldKeyRevocation) {
        $answer.Reason = 'RotatedOldKeyKept'
        $answer.Warnings += 'You asked to keep the old secret, so it is still active and will need revoking in Entra when you are sure this workstation is using the new one.'
        $answer.Message = ("Rotation finished. The new secret (key id {0}) is saved and works; the old secret {1} was left active as requested." -f [string]$created.KeyId, $(if ([string]::IsNullOrWhiteSpace($old.SecretKeyId)) { '(no key id recorded)' } else { ([guid]$old.SecretKeyId).ToString() }))
        return $answer
    }

    $revoked = Remove-PDAppSecret -ApplicationId $applicationId -KeyId $old.SecretKeyId -Description 'previous secret' -Stage $Stage
    if ($revoked.Success) {
        $answer.OldKeyRemoved = $true
        $answer.Message = ("Rotation finished. The new secret (key id {0}) works and is saved, expiring {1}; the old secret {2} was revoked." -f [string]$created.KeyId, $created.ExpiresOn.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture), ([guid]$old.SecretKeyId).ToString())
        return $answer
    }

    # Spec 7.4: the new credential stays, and the still-active old key is reported, not hidden.
    $answer.Reason          = 'RotatedOldKeyActive'
    $answer.LeftoverKeyId   = $revoked.KeyId
    $answer.Warnings       += [string]$revoked.Message
    $answer.Message = ("Rotation finished: this workstation now uses the new secret (key id {0}), which was saved and tested. {1}" -f [string]$created.KeyId, [string]$revoked.Message)
    return $answer
}

function Remove-PDGraphUploadCredential {
    <#
        .SYNOPSIS
        Removal (spec 7.4): the local file, and optionally its own Entra key - nothing else.

        .DESCRIPTION
        Never deletes the shared application or its service principal, and never touches another
        administrator's secret: the only Entra write is removePassword for the key id recorded in
        this workstation's credential. Revocation and file removal are offered separately, and when
        revocation was asked for and failed the local file is kept, because that file is the only
        record of which key still needs revoking.
    #>
    param(
        [AllowNull()][string]$CredentialPath,
        [switch]$RevokeEntraKey,
        [AllowNull()][object]$Session,
        [switch]$DryRun,
        [string]$Stage = 'Remove'
    )

    $answer = @{
        Success          = $false
        Reason           = $null
        Removed          = $false
        Revoked          = $false
        Path             = $null
        LeftoverKeyId    = $null
        Warnings         = @()
        Message          = $null
    }

    $answer.Path = Get-PDGraphCredentialPath -Path $CredentialPath

    $credential = $null
    $loadFailure = $null
    try {
        $credential = Get-PDGraphCredentialMetadata -Path $CredentialPath
    } catch {
        $loadFailure = Get-PDGraphErrorInfo -ErrorRecord $_
    }

    if ($null -eq $credential) {
        # An unreadable file still has to be removable, or the operator is stuck; but nothing can
        # be revoked when its key id cannot be read, so say which is which.
        if ($RevokeEntraKey) {
            $answer.Reason  = 'CredentialUnreadable'
            $answer.Message = ("The stored credential could not be read, so no secret key id is known and nothing was revoked: {0} Choose local-file-only removal to clear the file, or re-enter the credential first." -f [string]$loadFailure.Message)
            return $answer
        }

        if ($DryRun) {
            $answer.Success = $true
            $answer.Reason  = 'DryRun'
            $answer.Message = 'A dry run: it would remove the unreadable credential file and revoke nothing.'
            return $answer
        }

        $removed = Remove-PDGraphCredential -Path $CredentialPath
        $answer.Success = [bool]$removed.Removed
        $answer.Removed = [bool]$removed.Removed
        $answer.Reason  = 'RemovedUnreadable'
        $answer.Message = ("{0} Any Entra secret that file held is still active and must be identified and revoked in Entra by hand." -f [string]$removed.Message)
        return $answer
    }

    $answer.Warnings += ("Removing this file does not revoke anything in Entra by itself. The application '{0}' keeps its secret until it is revoked." -f $(if ([string]::IsNullOrWhiteSpace($credential.AppDisplayName)) { [string]$script:PDGraph.AppDisplayName } else { [string]$credential.AppDisplayName }))

    if ($RevokeEntraKey) {
        if ($null -eq $Session) {
            $answer.Reason  = 'NoSession'
            $answer.Message = 'Revoking the Entra secret needs a signed-in administrator, because the upload identity is not allowed to manage its own secrets. Sign in first, or choose local-file-only removal.'
            return $answer
        }

        $sessionTenant = [string](Get-PDGraphPropertyValue -Object $Session -Name 'TenantId')
        if ((-not [string]::IsNullOrWhiteSpace($sessionTenant)) -and
            ($sessionTenant.Trim().ToLowerInvariant() -ne ([string]$credential.TenantId).Trim().ToLowerInvariant())) {
            $answer.Reason  = 'TenantMismatch'
            $answer.Message = ("You are signed in to tenant '{0}' but this credential belongs to tenant '{1}', so nothing was revoked." -f $sessionTenant, [string]$credential.TenantId)
            return $answer
        }

        $applicationId = Get-PDGraphTrimmedText -Value $credential.AppObjectId
        if ([string]::IsNullOrWhiteSpace($applicationId)) {
            $looked = Get-PDEntraApplication -ClientId $credential.ClientId -Stage $Stage
            if (-not $looked.Found) {
                $answer.Reason  = 'NoApplication'
                $answer.Message = ("The application behind this credential could not be found in this tenant, so nothing was revoked: {0}" -f $looked.Message)
                return $answer
            }
            $applicationId = [string]$looked.App.ApplicationId
        }

        $revoked = Remove-PDAppSecret -ApplicationId $applicationId -KeyId $credential.SecretKeyId -Description 'stored credential secret' -DryRun:$DryRun -Stage $Stage
        $answer.Revoked = [bool]$revoked.Success

        if (-not $revoked.Success) {
            $answer.Reason        = 'RevokeFailed'
            $answer.LeftoverKeyId = $revoked.KeyId
            $answer.Warnings     += [string]$revoked.Message
            $answer.Message       = ("The secret could not be revoked, so the credential file was kept: it is the only record of which key still needs revoking. {0}" -f [string]$revoked.Message)
            if ($DryRun) { $answer.Reason = 'DryRun'; $answer.Message = ("A dry run: it would revoke key id {0} and then remove {1}." -f $(if ([string]::IsNullOrWhiteSpace($credential.SecretKeyId)) { '(none recorded)' } else { ([guid]$credential.SecretKeyId).ToString() }), $answer.Path) }
            return $answer
        }

        if ($DryRun) {
            $answer.Success = $true
            $answer.Reason  = 'DryRun'
            $answer.Message = ("A dry run: it would revoke key id {0} and then remove {1}. Nothing was revoked or removed." -f ([guid]$credential.SecretKeyId).ToString(), $answer.Path)
            return $answer
        }

        $answer.Warnings += [string]$revoked.Message
    } elseif ($DryRun) {
        $answer.Success = $true
        $answer.Reason  = 'DryRun'
        $answer.Message = ("A dry run: it would remove {0} and revoke nothing. The secret stays active in Entra." -f $answer.Path)
        return $answer
    }

    $removed = Remove-PDGraphCredential -Path $CredentialPath
    $answer.Removed  = [bool]$removed.Removed
    $answer.Success  = [bool]$removed.Removed
    $answer.Reason   = $(if ($RevokeEntraKey) { 'RemovedAndRevoked' } else { 'Removed' })
    $answer.Message  = ("{0} {1}" -f [string]$removed.Message, $(if ($RevokeEntraKey) { '' } else { 'The Entra secret itself was not revoked.' }))

    if ($RevokeEntraKey) { $answer.Message = ("{0} The application and its other secrets were left alone." -f [string]$removed.Message) }

    return $answer
}

function Start-PDGraphUploadProvisioning {
    <#
        .SYNOPSIS
        The whole of spec 7.2 "Create/configure", as one non-interactive, reviewable operation.

        .DESCRIPTION
        Every step is carried out by a separate function so a test can prove which objects were
        touched: the registration, its service principal, the requested permissions, the role
        grants, the secret, the token test, and the local credential file - in that order, each step
        idempotent, each recorded in Steps.

        The secret is created only after the permissions are in place, is tested before anything is
        saved, and is revoked again if that test fails. The credential file is replaced only by a
        secret that has already been proven to work, and never in a dry run.

        Prompting belongs to the menu: when several registrations share the name, this answers
        NeedsSelection with the candidate ids, and the caller re-runs it with -ApplicationId.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Session,
        [AllowNull()][string]$ApplicationId,
        [int]$SecretLifetimeDays = 0,
        [AllowNull()][string]$CredentialPath,
        [AllowNull()][string]$Label,
        [AllowNull()][scriptblock]$Selection,
        [switch]$DryRun,
        [string]$Stage = 'Provision'
    )

    $answer = @{
        Success            = $false
        Reason             = $null
        Steps              = @()
        ApplicationId      = $null
        ClientId           = $null
        ServicePrincipalId = $null
        SecretKeyId        = $null
        SecretExpiresOn    = $null
        DaysUntilExpiry    = $null
        SavedTo            = $null
        Candidates         = @()
        Warnings           = @()
        Message            = $null
    }

    # Mutating the hashtable's own keys (rather than assigning a local of the same name) is what
    # lets this helper reach the caller's $answer: the object is shared, the variable is not.
    $addStep = {
        param($Step, $Success, $Message)
        $answer.Steps = @($answer.Steps) + @{ Step = [string]$Step; Success = [bool]$Success; Message = [string]$Message }
    }

    $answerOnly = {
        param($Reason, $Message, $Success)
        $answer.Success = [bool]$Success
        $answer.Reason  = [string]$Reason
        $answer.Message = [string]$Message
        return $answer
    }

    # --- 0. the session, verified ---------------------------------------------------------
    $verdict = Resolve-PDGraphDelegatedContext -Context $Session -RequiredScopes @($script:PDGraph.ProvisioningScopes)
    if (-not $verdict.Usable) {
        return (& $answerOnly $verdict.Reason ("Provisioning needs a delegated Microsoft Graph sign-in for this tenant: {0}" -f [string]$verdict.Message) $false)
    }

    $consentScope = [string]$script:PDGraph.ConsentScope
    $hasConsent   = $false
    foreach ($held in @($verdict.Scopes)) {
        if (([string]$held).Trim() -eq $consentScope) { $hasConsent = $true; break }
    }
    if (-not $hasConsent) {
        $answer.Warnings += ("The sign-in session does not list {0}, so the role grant step may be refused. A refusal there is fixed by signing in again with that permission, not by retrying the write." -f $consentScope)
    }

    $existing = Get-PDGraphCredentialSummary -CredentialPath $CredentialPath
    if ($existing.Stored) {
        $answer.Warnings += 'A credential is already stored for this Windows account; it is replaced only after the new secret has been tested, and never by a dry run.'
    }

    # --- 1 and 2. the registration --------------------------------------------------------
    $application = Ensure-PDEntraApplication -ApplicationId $ApplicationId -Selection $Selection -DryRun:$DryRun -Stage $Stage
    & $addStep 'Application' $application.Success $application.Message

    if (-not $application.Success) {
        $answer.Candidates = @($application.Candidates)
        return (& $answerOnly $application.Reason $application.Message $false)
    }

    if ($application.Reason -eq 'DryRun') {
        $answer.Candidates = @($application.Candidates)
        return (& $answerOnly 'DryRun' ("{0} The remaining steps need the application, so a dry run stops here." -f [string]$application.Message) $true)
    }

    $answer.ApplicationId = [string]$application.ApplicationId
    $answer.ClientId      = [string]$application.ClientId

    # --- 3. its service principal ---------------------------------------------------------
    $principal = Ensure-PDServicePrincipal -ClientId $application.ClientId -DryRun:$DryRun -Stage $Stage
    & $addStep 'ServicePrincipal' $principal.Success $principal.Message

    if (-not $principal.Success) {
        if ($DryRun -and ($principal.Reason -eq 'DryRun')) {
            return (& $answerOnly 'DryRun' ("{0} {1} Nothing was created." -f [string]$application.Message, [string]$principal.Message) $true)
        }
        return (& $answerOnly $principal.Reason $principal.Message $false)
    }

    $answer.ServicePrincipalId = [string]$principal.ServicePrincipalId

    # --- 4. the two Graph roles, by exact id ----------------------------------------------
    $graph = Get-PDGraphServicePrincipal -AppId ([string]$script:PDGraph.GraphServiceAppId) -WithAppRoles -Stage $Stage
    & $addStep 'GraphServicePrincipal' $graph.Found $graph.Message
    if (-not $graph.Found) {
        return (& $answerOnly 'GraphServicePrincipal' $graph.Message $false)
    }

    $resolved = Resolve-PDEntraApplicationRole -AppRoles $graph.Principal.AppRoles -RequiredRoles @($script:PDGraph.RequiredAppRoles)

    $rolesResolved = (@($resolved.Missing).Count -eq 0)
    $rolesMessage  = ("Resolved {0} application role id(s) on the Microsoft Graph service principal." -f @($resolved.RoleIds.Keys).Count)
    if (-not $rolesResolved) {
        $rolesMessage = ("Microsoft Graph does not offer these as application permissions: {0}" -f (@($resolved.Missing) -join ', '))
    }
    & $addStep 'ResolveRoles' $rolesResolved $rolesMessage

    if (-not $rolesResolved) {
        return (& $answerOnly 'RoleResolution' ("Microsoft Graph does not offer {0} as an application permission on this tenant, so nothing was granted. Role names are matched exactly and never approximated." -f (@($resolved.Missing) -join ', ')) $false)
    }

    # --- 5. requested permissions (not consent) -------------------------------------------
    $permissions = Set-PDEntraRequiredResourceAccess -ApplicationId $application.ApplicationId -RoleIds $resolved.RoleIds -DryRun:$DryRun -Stage $Stage
    & $addStep 'RequestedPermissions' $true $permissions.Message

    # --- 6. the grants themselves, missing ones only ---------------------------------------
    $grants = Ensure-PDAppRoleAssignments -UploadServicePrincipalId $principal.ServicePrincipalId `
                                          -GraphServicePrincipalId $graph.Principal.ServicePrincipalId `
                                          -RoleIds $resolved.RoleIds -DryRun:$DryRun -Stage $Stage
    & $addStep 'Grants' $grants.Success $grants.Message
    if (-not $grants.Success) {
        return (& $answerOnly 'Grants' $grants.Message $false)
    }

    if ($DryRun) {
        $answer.Candidates = @()
        return (& $answerOnly 'DryRun' ("Dry run. {0} It would then create a secret for this workstation, test it, and save it locally; nothing was created, granted, or saved." -f $grants.Message) $true)
    }

    # --- 7. the secret ---------------------------------------------------------------------
    $secretLabel = Get-PDGraphTrimmedText -Value $Label
    if ([string]::IsNullOrWhiteSpace($secretLabel)) { $secretLabel = New-PDGraphSecretLabel }

    $created = Add-PDAppSecret -ApplicationId $application.ApplicationId -LifetimeDays $SecretLifetimeDays -Label $secretLabel -Stage $Stage
    & $addStep 'Secret' $created.Success $created.Message

    foreach ($warning in @($created.Warnings)) {
        if (-not [string]::IsNullOrWhiteSpace($warning)) { $answer.Warnings += [string]$warning }
    }

    if (-not $created.Success) {
        return (& $answerOnly $created.Outcome ("The application is configured but no secret could be created, so nothing was saved locally. {0}" -f [string]$created.Message) $false)
    }

    $answer.SecretKeyId     = [string]$created.KeyId
    $answer.SecretExpiresOn = $created.ExpiresOn

    $candidate = New-PDGraphCredentialObject -TenantId ([string]$verdict.TenantId) -ClientId ([string]$application.ClientId) `
                    -ClientSecret $created.Secret -SecretExpiresOn $created.ExpiresOn -SecretKeyId $created.KeyId `
                    -AppObjectId $application.ApplicationId -ServicePrincipalId $principal.ServicePrincipalId `
                    -AppDisplayName ([string]$script:PDGraph.AppDisplayName)

    # --- 8. prove it, then save; a secret that cannot upload is not worth keeping ----------
    $test = Wait-PDGraphUploadSecretReady -Credential $candidate -SecretJustCreated -Stage $Stage
    & $addStep 'Test' $test.Ready $test.Message

    if (-not $test.Ready) {
        $note = 'The new secret was left in place so it can be found and revoked in Entra (its key id is not known).'
        if (-not [string]::IsNullOrWhiteSpace($created.KeyId)) {
            $revoked = Remove-PDAppSecret -ApplicationId $application.ApplicationId -KeyId $created.KeyId -Description 'new secret (test failed)' -Stage $Stage
            $note    = [string]$revoked.Message
        }
        return (& $answerOnly 'TestFailed' ("The application is configured, but the new secret did not become usable, so it was not saved. {0} {1}" -f [string]$test.Message, $note) $false)
    }

    $saved = $null
    try {
        $saved = Save-PDGraphCredential -Credential $candidate -Path $CredentialPath
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        & $addStep 'Save' $false $info.Message
        return (& $answerOnly 'SaveFailed' ("The secret works but could not be stored: {0} Its key id is {1}; revoke it in Entra if this workstation should not keep using it." -f [string]$info.Message, [string]$created.KeyId) $false)
    }

    & $addStep 'Save' $true ("Stored at {0}, expiring {1}." -f [string]$saved.Path, $saved.SecretExpiresOn.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture))

    $expiryText = $saved.SecretExpiresOn.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)

    # The ids are already in the step lines above; the summary only says what the operator needs.
    # (Setup prints the Multi-Admin Approval next step itself, so it is not repeated here.)
    $answer.Message = ("'{0}' is ready. This PC's secret is saved and expires {1}. If your tenant has Multi-Admin Approval enabled, set up its exclusion next (MAA Exclusions - Setup/Config)." -f [string]$script:PDGraph.AppDisplayName, $expiryText)

    return (& $answerOnly 'Provisioned' $answer.Message $true)
}

function Test-PDGraphUploadCandidateCredential {
    <#
        .SYNOPSIS
        Checks a hand-entered credential against the tenant BEFORE it replaces the stored one
        (spec 7.2, manual entry).

        .DESCRIPTION
        A typo in a secret would otherwise look like a broken upload hours later. Nothing is saved
        here and the existing local configuration is never touched: this only answers "would this
        work", plus which roles the tenant actually grants.
    #>
    param(
        [AllowNull()][string]$TenantId,
        [AllowNull()][string]$ClientId,
        [AllowNull()][object]$ClientSecret,
        [AllowNull()][object]$SecretExpiresOn,
        [AllowNull()][string]$SecretKeyId,
        [AllowNull()][string]$AppObjectId,
        [AllowNull()][string]$ServicePrincipalId,
        [AllowNull()][string]$AppDisplayName,
        [switch]$SkipRoleCheck,
        [string]$Stage = 'Credential'
    )

    $credential = $null
    try {
        $name = Get-PDGraphTrimmedText -Value $AppDisplayName
        if ([string]::IsNullOrWhiteSpace($name)) { $name = [string]$script:PDGraph.AppDisplayName }

        $credential = New-PDGraphCredentialObject -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret `
                        -SecretExpiresOn $SecretExpiresOn -SecretKeyId $SecretKeyId -AppObjectId $AppObjectId `
                        -ServicePrincipalId $ServicePrincipalId -AppDisplayName $name
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        return @{ Valid = $false; Reason = 'InvalidInput'; Credential = $null; Roles = @(); MissingRoles = @(); Warnings = @()
                  Message = $info.Message }
    }

    $warnings = @()

    if ($credential.SecretExpiresOn -le [System.DateTimeOffset]::UtcNow) {
        $shown = $credential.SecretExpiresOn.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
        return @{ Valid = $false; Reason = 'Expired'; Credential = $credential; Roles = @(); MissingRoles = @(); Warnings = $warnings
                  Message = ("That secret expired on {0}, so it was not saved. Enter the current secret or create a new one in Entra." -f $shown) }
    }

    if ([string]::IsNullOrWhiteSpace([string]$credential.SecretKeyId)) {
        $warnings += 'No secret key id was entered, so rotation will save a replacement but cannot revoke this secret; it will report the key for manual cleanup.'
    }

    $token = $null
    try {
        $token = Get-PDGraphToken -Credential (Get-PDGraphCredentialProbe -Credential $credential) -Force
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        return @{ Valid = $false; Reason = 'TokenFailed'; Credential = $credential; Roles = @(); MissingRoles = @(); Warnings = $warnings
                  Message = ("The token endpoint refused those credentials, so they were not saved: {0}" -f [string]$info.Message) }
    }

    $held = @()
    try { $held = @($token.Roles) } catch { $held = @() }

    $missing = @()
    if (-not $SkipRoleCheck) {
        foreach ($role in @($script:PDGraph.RequiredAppRoles)) {
            $found = $false
            foreach ($grant in $held) {
                if (([string]$grant).Trim() -eq ([string]$role).Trim()) { $found = $true; break }
            }
            if (-not $found) { $missing += [string]$role }
        }
    }

    if (@($missing).Count -gt 0) {
        return @{ Valid = $false; Reason = 'MissingRoles'; Credential = $credential; Roles = @($held); MissingRoles = @($missing); Warnings = $warnings
                  Message = ("Those credentials work but the application is not granted {0}. Grant the missing application role(s) in Entra ('Azure App Registration - Setup/Config', Automatic, does it), then save again. Nothing was replaced." -f (($missing | ForEach-Object { "'$_'" }) -join ', ')) }
    }

    if (@($held).Count -eq 0) {
        $warnings += 'The token carried no readable application roles, so permissions could not be confirmed from it.'
    }

    return @{ Valid = $true; Reason = 'Valid'; Credential = $credential; Roles = @($held); MissingRoles = @(); Warnings = $warnings
              Message = ("Those credentials work: the token carries {0} application role(s) and expires {1}." -f @($held).Count, $credential.SecretExpiresOn.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)) }
}

function Test-PDGraphUploadConnection {
    <#
        .SYNOPSIS
        The menu's 'Test the saved connection': token, roles, and one small Intune read
        (spec 7.2).

        .DESCRIPTION
        Deliberately modest, and says so: a successful read does not prove the application is
        excluded from Multi-Admin Approval, because MAA blocks writes and this performs none. The
        token is requested with -Force so a revoked secret cannot hide behind this process's cache.
    #>
    param(
        [AllowNull()][string]$CredentialPath,
        [AllowNull()][string]$ReadPath,
        [switch]$SkipIntuneRead,
        [string]$Stage = 'Credential'
    )

    $credential = Get-PDGraphCredential -Path $CredentialPath

    $warnings = @()
    foreach ($warning in @($credential.Warnings)) {
        if (-not [string]::IsNullOrWhiteSpace($warning)) { $warnings += [string]$warning }
    }

    $token = $null
    try {
        $token = Get-PDGraphToken -Credential $credential -Force
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        return @{ Success = $false; Reason = 'TokenFailed'; Message = $info.Message; Roles = @(); MissingRoles = @()
                  SecretExpiresOn = $credential.SecretExpiresOn; DaysUntilExpiry = $credential.DaysUntilExpiry
                  Warnings = $warnings }
    }

    $held    = @()
    try { $held = @($token.Roles) } catch { $held = @() }

    $missing = @()
    foreach ($role in @($script:PDGraph.RequiredAppRoles)) {
        $found = $false
        foreach ($grant in $held) {
            if (([string]$grant).Trim() -eq ([string]$role).Trim()) { $found = $true; break }
        }
        if (-not $found) { $missing += [string]$role }
    }

    if (@($missing).Count -gt 0) {
        return @{ Success = $false; Reason = 'MissingRoles'
                  Message = ("The secret works but the application is not granted {0}. Run the create/configure option to grant them." -f (($missing | ForEach-Object { "'$_'" }) -join ', '))
                  Roles = @($held); MissingRoles = @($missing)
                  SecretExpiresOn = $credential.SecretExpiresOn; DaysUntilExpiry = $credential.DaysUntilExpiry
                  Warnings = $warnings }
    }

    $read = $null
    if (-not $SkipIntuneRead) {
        $path = Get-PDGraphTrimmedText -Value $ReadPath
        if ([string]::IsNullOrWhiteSpace($path)) { $path = [string]$script:PDGraph.ConnectionTestPath }

        try {
            $read = Invoke-PDGraphRequest -Method Get -Uri $path -AuthContext @{ Credential = $credential } -RetryMode 'Read' -Stage $Stage -Description 'connection test read'
        } catch {
            $info = Get-PDGraphErrorInfo -ErrorRecord $_
            return @{ Success = $false; Reason = 'ReadFailed'; Message = $info.Message; Roles = @($held); MissingRoles = @()
                      SecretExpiresOn = $credential.SecretExpiresOn; DaysUntilExpiry = $credential.DaysUntilExpiry
                      Warnings = $warnings }
        }
    }

    $warnings += 'This test only reads, so it cannot tell whether the Multi-Admin Approval (MAA) exclusion is in place. Your first automatic upload will.'

    $readNote = 'no Intune read was requested'
    if (-not $SkipIntuneRead) { $readNote = 'the small Intune read succeeded' }

    return @{
        Success         = $true
        Reason          = 'Connected'
        Message         = ("The stored credential works: token issued, both application roles present, {0}. The secret expires {1}." -f $readNote, $credential.SecretExpiresOn.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture))
        Roles           = @($held)
        MissingRoles    = @()
        TokenExpiresOn  = $token.ExpiresOn
        IntuneRead      = $read
        SecretExpiresOn = $credential.SecretExpiresOn
        DaysUntilExpiry = $credential.DaysUntilExpiry
        Warnings        = $warnings
    }
}

function Get-PDGraphUploadMaaGuidance {
    <#
        .SYNOPSIS
        The Multi-Admin Approval exclusion instructions (spec 7.5). Pure text.

        .DESCRIPTION
        Reads nothing and writes nothing: no Graph calls at all, because the menu that shows this
        must work when the tenant connection is the thing that is broken. What the exclusion covers
        and what it does not cover is stated plainly, because "it is in MAA" is the most common
        reason a configured application still cannot publish.
    #>
    param(
        [AllowNull()][string]$AppDisplayName,
        [AllowNull()][string]$ClientId,
        [AllowNull()][string]$CredentialPath
    )

    $name = Get-PDGraphTrimmedText -Value $AppDisplayName
    $id   = Get-PDGraphTrimmedText -Value $ClientId

    if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($id)) {
        $summary = Get-PDGraphCredentialSummary -CredentialPath $CredentialPath
        if ($summary.Usable) {
            if ([string]::IsNullOrWhiteSpace($name)) { $name = [string]$summary.AppDisplayName }
            if ([string]::IsNullOrWhiteSpace($id))   { $id   = [string]$summary.ClientId }
        }
    }

    if ([string]::IsNullOrWhiteSpace($name)) { $name = [string]$script:PDGraph.AppDisplayName }
    if ([string]::IsNullOrWhiteSpace($id))   { $id   = 'not configured on this workstation yet' }

    $steps = @(
        'Intune -> Tenant administration -> Multi Admin Approval -> Access policies',
        '-> Apps policy -> Exclusions -> Add enterprise applications',
        ('-> select {0} (Intune lists app registrations here as enterprise applications) -> submit a justification' -f $name),
        '-> another authorized administrator approves',
        '-> requester selects Complete'
    )

    $notes = @(
        'Why: with Multi-Admin Approval on, every change to Intune apps waits for a second admin to approve it. The exclusion lets uploads made by the PowerDeploy Azure App Registration go through without that wait.',
        'It only covers the app-registration (application-only) uploads PowerDeploy makes. Changes you make yourself in the Intune portal still need approval as before.',
        'You only do this once. Rotating this PC''s secret does not undo it, because the exclusion belongs to the app registration, not the secret.',
        'Without the exclusion, Intune refuses automatic uploads. The wizard tells you that and switches to the guided manual setup.',
        '"Test config" cannot tell whether the exclusion is in place (it only reads). Your first automatic upload will.'
    )

    return @{
        AppDisplayName = $name
        ClientId       = $id
        Steps          = @($steps)
        Notes          = @($notes)
        Message        = ('Add "{0}" to the exclusions of your Multi-Admin Approval apps policy.' -f $name)
    }
}
