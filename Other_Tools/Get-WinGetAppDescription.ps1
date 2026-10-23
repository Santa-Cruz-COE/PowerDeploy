<#

.SYNOPSIS
    Bounded, read-only WinGet description lookup for PowerDeploy's optional Intune upload path.

.DESCRIPTION
    DOT-SOURCE THIS FILE. It defines functions only.

    Importing this file runs nothing, writes nothing, emits no output, and never replaces a
    caller's Write-Log. Setup.ps1 dot-sources it to fill an Intune app's Description when the
    app JSON has none.

    Provides:
      - Get-WinGetAppDescription: runs 'winget show' for one exact ID against the msstore
        source, then the winget source, in a hidden, time-bounded child process, and returns
        exactly one result object. It never prompts, never installs or repairs WinGet, and
        never throws for operational failures.
      - ConvertFrom-PDWinGetShowOutput: the pure text parser behind it, tested against
        captured fixtures in Tests/Fixtures/WinGet.

    WinGet show output is plain console text with no machine-readable switch. The parser only
    accepts the English labels it has fixtures for; anything else is UnrecognizedOutput rather
    than a guess. Retrieval failure is expected and harmless: the caller falls back to 'N/A'.

    Windows PowerShell 5.1 and PowerShell 7 compatible. Source is ASCII-only.

.LINK
    .claude/plans/intune-graph-upload.md - section 6 (WinGet description lookup)

#>

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

function Test-PDWinGetId {
    <#
        .SYNOPSIS
        True when the value is a plausible WinGet package ID (community or Store product ID).

        .DESCRIPTION
        Strict allow-list: letters, digits, '.', '_', '-', '+', starting with a letter or digit,
        at most 128 characters. Anything else is refused before an argument string is built,
        so no raw input ever reaches the child process command line. Never throws.
    #>
    param( [AllowNull()][object]$Value )

    if ($null -eq $Value) { return $false }
    return ([string]$Value) -cmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
}

function Get-PDWinGetTopLevelLabels {
    <#
        .SYNOPSIS
        The English top-level 'winget show' field labels the parser recognizes.

        .DESCRIPTION
        Every label here appears in a captured fixture under Tests/Fixtures/WinGet. Add a label
        only together with a fixture that shows it.
    #>
    return @(
        'Version', 'Publisher', 'Publisher Url', 'Publisher Support Url', 'Author', 'Moniker',
        'Description', 'Homepage', 'License', 'License Url', 'Privacy Url', 'Copyright',
        'Release Notes', 'Release Notes Url', 'Documentation', 'Tags', 'Agreements', 'Installer'
    )
}

function New-PDWinGetDescriptionResult {
    <#
        .SYNOPSIS
        Builds the single result object Get-WinGetAppDescription returns.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Found', 'NotFound', 'Unavailable', 'Timeout', 'UnrecognizedOutput')][string]$Status,
        [string]$Message = '',
        # Untyped on purpose: a [string] parameter would turn $null into ''.
        [AllowNull()]$Description = $null,
        [AllowNull()]$Source = $null,
        [AllowNull()]$PackageId = $null,
        # Kept even when no description was found: the publisher alone is still useful.
        [AllowNull()]$Publisher = $null,
        # Links, kept like the publisher even when no description was found.
        [AllowNull()]$Homepage = $null,
        [AllowNull()]$PrivacyUrl = $null
    )

    if ([string]::IsNullOrWhiteSpace([string]$Publisher)) { $Publisher = $null } else { $Publisher = ([string]$Publisher).Trim() }
    if ([string]::IsNullOrWhiteSpace([string]$Homepage))  { $Homepage  = $null } else { $Homepage  = ([string]$Homepage).Trim() }
    if ([string]::IsNullOrWhiteSpace([string]$PrivacyUrl)) { $PrivacyUrl = $null } else { $PrivacyUrl = ([string]$PrivacyUrl).Trim() }

    if ($Status -eq 'Found') {
        $Description = [string]$Description
        $Source      = [string]$Source
        $PackageId   = [string]$PackageId
    } else {
        $Description = $null
        $Source      = $null
        $PackageId   = $null
    }

    return [pscustomobject]@{
        Found       = ($Status -eq 'Found')
        Description = $Description
        Source      = $Source
        PackageId   = $PackageId
        Publisher   = $Publisher
        Homepage    = $Homepage
        PrivacyUrl  = $PrivacyUrl
        Status      = $Status
        Message     = $Message
    }
}

function Resolve-PDWinGetPath {
    <#
        .SYNOPSIS
        Returns the path of an existing winget.exe, or $null. Never installs or repairs WinGet.

        .DESCRIPTION
        An explicit -WinGetPath is used as-is and must exist. Otherwise: Get-Command winget,
        then the per-user WindowsApps app execution alias.
    #>
    param( [AllowNull()][string]$WinGetPath )

    if (-not [string]::IsNullOrWhiteSpace($WinGetPath)) {
        if (Test-Path -LiteralPath $WinGetPath -PathType Leaf) { return $WinGetPath }
        return $null
    }

    try {
        $command = Get-Command -Name 'winget.exe' -CommandType Application -ErrorAction Stop | Select-Object -First 1
        if ($command -and $command.Source -and (Test-Path -LiteralPath $command.Source)) { return $command.Source }
    } catch { }

    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $alias = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
        if (Test-Path -LiteralPath $alias) { return $alias }
    }

    return $null
}

function Invoke-PDWinGetProcess {
    <#
        .SYNOPSIS
        Runs one hidden, time-bounded winget process and captures stdout and stderr separately.

        .DESCRIPTION
        UseShellExecute is off and no window is created. Both streams are read concurrently so a
        full pipe cannot deadlock the child. On timeout only the process started here is killed.
        Returns { Started; TimedOut; ExitCode; StdOut; StdErr; ElapsedMs; Error }. Never throws.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $result = [pscustomobject]@{
        Started   = $false
        TimedOut  = $false
        ExitCode  = $null
        StdOut    = ''
        StdErr    = ''
        ElapsedMs = 0
        Error     = $null
    }

    $process = $null
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName               = $FilePath
        $startInfo.Arguments              = $Arguments
        $startInfo.UseShellExecute        = $false
        $startInfo.CreateNoWindow         = $true
        $startInfo.WindowStyle            = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $startInfo.RedirectStandardInput  = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError  = $true
        $startInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $startInfo.StandardErrorEncoding  = [System.Text.Encoding]::UTF8

        $process = [System.Diagnostics.Process]::Start($startInfo)
        $result.Started = $true

        # Nothing is ever typed into winget; closing stdin turns any stray prompt into EOF.
        try { $process.StandardInput.Close() } catch { }

        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()

        $timeoutMs = [Math]::Max(1, $TimeoutSeconds) * 1000
        if (-not $process.WaitForExit($timeoutMs)) {
            $result.TimedOut = $true
            try { $process.Kill() } catch { }
            $null = $process.WaitForExit(5000)
        } else {
            $result.ExitCode = $process.ExitCode
        }

        # The pipes close when the child exits; the bound only matters if a grandchild kept one open.
        if ($stdoutTask.Wait(5000)) { $result.StdOut = [string]$stdoutTask.Result }
        if ($stderrTask.Wait(5000)) { $result.StdErr = [string]$stderrTask.Result }
    } catch {
        $result.Error = $_.Exception.Message
    } finally {
        $timer.Stop()
        $result.ElapsedMs = [int]$timer.ElapsedMilliseconds
        if ($process) { try { $process.Dispose() } catch { } }
    }

    return $result
}

function Get-PDWinGetShortText {
    <#
        .SYNOPSIS
        First non-empty line of a text, trimmed to a short length, for operator messages.
    #>
    param( [AllowNull()][string]$Text, [int]$MaxLength = 160 )

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $line = @($Text -split "[`r`n]+" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    if ($line.Count -eq 0) { return '' }
    $short = ([string]$line[0]).Trim()
    if ($short.Length -gt $MaxLength) { $short = $short.Substring(0, $MaxLength) + '...' }
    return $short
}

# ---------------------------------------------------------------------------
# Pure parser
# ---------------------------------------------------------------------------

function ConvertFrom-PDWinGetShowOutput {
    <#
        .SYNOPSIS
        Extracts the Description field from 'winget show' stdout for one exact package ID.

        .DESCRIPTION
        Pure: no I/O. Strips ANSI escape sequences and carriage-return progress/spinner
        overwrites, normalizes line endings, then requires the header 'Found <Name> [<Id>]'
        with an ID equal to -ExpectedId (case-insensitive). The description is the value on the
        'Description:' line plus its indented continuation lines, ending at the next top-level
        field. Only stdout should be passed in; stderr is never a description.

        Returns { Status; Description; PackageId; Publisher; Homepage; PrivacyUrl; Message } where Status is Found, NotFound,
        or UnrecognizedOutput. Unknown or localized labels, or an unrecognized field boundary,
        are UnrecognizedOutput - never a guess.

        .PARAMETER Text
        Raw stdout of 'winget show'.

        .PARAMETER ExpectedId
        The exact ID that was requested.
    #>
    param(
        [AllowNull()][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][string]$ExpectedId
    )

    $fail = {
        param([string]$Status, [string]$Message, $Publisher = $null, $Homepage = $null, $PrivacyUrl = $null)
        [pscustomobject]@{ Status = $Status; Description = $null; PackageId = $null; Publisher = $Publisher; Homepage = $Homepage; PrivacyUrl = $PrivacyUrl; Message = $Message }
    }

    if ([string]::IsNullOrWhiteSpace($Text)) { return (& $fail 'UnrecognizedOutput' 'winget produced no output.') }

    # --- clean: ANSI (CSI and OSC sequences, then any stray ESC pair), CR overwrites, line endings ---
    $clean = $Text
    $clean = [regex]::Replace($clean, '\x1B\][^\x07\x1B]*(\x07|\x1B\\)', '')
    $clean = [regex]::Replace($clean, '\x1B\[[0-?]*[ -/]*[@-~]', '')
    $clean = [regex]::Replace($clean, '\x1B[@-_]', '')
    $clean = [regex]::Replace($clean, '\r+\n', "`n")
    while ($clean -match '[^\n\x08]\x08') { $clean = [regex]::Replace($clean, '[^\n\x08]\x08', '') }
    $clean = $clean.Replace([string][char]8, '')

    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($raw in ($clean -split "`n")) {
        # A bare CR returns the cursor to column 0: what remains visible is the text after the last one.
        $visible = $raw
        $lastCr = $visible.LastIndexOf([char]13)
        if ($lastCr -ge 0) { $visible = $visible.Substring($lastCr + 1) }
        $lines.Add($visible.TrimEnd())
    }

    # --- header ---
    $headerIndex = -1
    $headerId = $null
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $match = [regex]::Match($lines[$i], '^Found (?<name>.+) \[(?<id>[^\[\]]+)\]$')
        if ($match.Success) {
            $headerIndex = $i
            $headerId = $match.Groups['id'].Value
            break
        }
    }

    if ($headerIndex -lt 0) {
        foreach ($line in $lines) {
            if ($line.Trim() -eq 'No package found matching input criteria.') {
                return (& $fail 'NotFound' 'No package found matching input criteria.')
            }
        }
        return (& $fail 'UnrecognizedOutput' 'winget output has no recognized package header.')
    }

    if (-not [string]::Equals($headerId, $ExpectedId, [System.StringComparison]::OrdinalIgnoreCase)) {
        return (& $fail 'NotFound' ("winget matched a different package ID '{0}'." -f $headerId))
    }

    # --- fields ---
    $known = Get-PDWinGetTopLevelLabels
    $labelPattern = '^(?<label>[^\s:][^:]*):(?:\s(?<value>.*))?$'

    $descriptionLines = $null
    $publisher = $null
    $homepage = $null
    $publisherUrl = $null
    $privacyUrl = $null
    $afterDescription = $false
    $sawKnownLabel = $false
    $i = $headerIndex + 1
    while ($i -lt $lines.Count) {
        $line = $lines[$i]

        # Indented lines belong to the previous field; blank lines carry no structure.
        if (($line.Length -eq 0) -or ($line[0] -eq ' ') -or ($line[0] -eq "`t")) { $i++; continue }

        $field = [regex]::Match($line, $labelPattern)
        if ((-not $field.Success) -or ($known -notcontains $field.Groups['label'].Value)) {
            # Past the description only the link fields are read, so an unfamiliar label there
            # (a newer winget) is skipped instead of failing a lookup that already succeeded.
            if ($afterDescription) { $i++; continue }
            return (& $fail 'UnrecognizedOutput' ("Unrecognized winget field line: '{0}'." -f (Get-PDWinGetShortText -Text $line -MaxLength 60)))
        }
        $sawKnownLabel = $true

        # One-line link fields (Homepage and Privacy Url are listed after the description).
        $linkValue = ([string]$field.Groups['value'].Value).Trim()
        if (-not [string]::IsNullOrWhiteSpace($linkValue)) {
            switch -CaseSensitive ($field.Groups['label'].Value) {
                'Homepage'      { if ($null -eq $homepage)     { $homepage = $linkValue } }
                'Publisher Url' { if ($null -eq $publisherUrl) { $publisherUrl = $linkValue } }
                'Privacy Url'   { if ($null -eq $privacyUrl)   { $privacyUrl = $linkValue } }
            }
        }
        if ($afterDescription) { $i++; continue }

        # Publisher is a one-line field listed before Description in every captured output.
        if ($field.Groups['label'].Value -ceq 'Publisher') {
            $value = $field.Groups['value'].Value
            if (-not [string]::IsNullOrWhiteSpace($value)) { $publisher = $value.Trim() }
        }

        if ($field.Groups['label'].Value -ceq 'Description') {
            $descriptionLines = New-Object System.Collections.Generic.List[string]
            $inline = $field.Groups['value'].Value
            if (-not [string]::IsNullOrWhiteSpace($inline)) { $descriptionLines.Add($inline.Trim()) }

            $continuation = New-Object System.Collections.Generic.List[string]
            $j = $i + 1
            while (($j -lt $lines.Count) -and (($lines[$j].Length -eq 0) -or ($lines[$j][0] -eq ' ') -or ($lines[$j][0] -eq "`t"))) {
                $continuation.Add($lines[$j])
                $j++
            }

            # The next top-level line must be a field we know, or the boundary is a guess.
            if ($j -lt $lines.Count) {
                $next = [regex]::Match($lines[$j], $labelPattern)
                if ((-not $next.Success) -or ($known -notcontains $next.Groups['label'].Value)) {
                    return (& $fail 'UnrecognizedOutput' ("Unrecognized field after Description: '{0}'." -f (Get-PDWinGetShortText -Text $lines[$j] -MaxLength 60)))
                }
            }

            # Remove the common indent winget adds, keep the author's own structure.
            $indent = [int]::MaxValue
            foreach ($c in $continuation) {
                if ($c.Trim().Length -eq 0) { continue }
                $lead = $c.Length - $c.TrimStart().Length
                if ($lead -lt $indent) { $indent = $lead }
            }
            foreach ($c in $continuation) {
                if ($c.Trim().Length -eq 0) { $descriptionLines.Add(''); continue }
                $descriptionLines.Add($c.Substring($indent))
            }
            # Keep reading the remaining top-level fields for the links.
            $afterDescription = $true
            $i = $j
            continue
        }
        $i++
    }

    # Information link: the package homepage, else the publisher's site.
    if ($null -eq $homepage) { $homepage = $publisherUrl }

    if ($null -eq $descriptionLines) {
        if ($sawKnownLabel) { return (& $fail 'NotFound' 'The package has no Description field.' $publisher $homepage $privacyUrl) }
        return (& $fail 'UnrecognizedOutput' 'winget output has no recognized fields.')
    }

    $description = ($descriptionLines -join "`n").Trim()
    if ($description.Length -eq 0) { return (& $fail 'NotFound' 'The package Description is empty.' $publisher $homepage $privacyUrl) }

    return [pscustomobject]@{
        Status      = 'Found'
        Description = $description
        PackageId   = $headerId
        Publisher   = $publisher
        Homepage    = $homepage
        PrivacyUrl  = $privacyUrl
        Message     = 'Description found.'
    }
}

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

function Get-WinGetAppDescription {
    <#
        .SYNOPSIS
        Looks up a WinGet package's description by exact ID. Read-only, bounded, never throws.

        .DESCRIPTION
        Queries the msstore source first, then the winget source, with the exact same ID:
            winget show --id <ID> --exact --source <src> --disable-interactivity --accept-source-agreements
        Each query runs in a hidden child process bounded by -TimeoutSeconds. Display-name
        matching is never used. WinGet is never installed or repaired; if it is absent the
        result is Unavailable.

        Returns exactly one object:
            Found (bool), Description (string or null), Source ('msstore', 'winget', or null),
            PackageId (exact matched ID or null),
            Publisher (the package's Publisher field, or null; kept even when no description was found),
            Homepage (Homepage, else Publisher Url, or null) and PrivacyUrl (Privacy Url, or null), kept the same way,
            Status (Found | NotFound | Unavailable | Timeout | UnrecognizedOutput),
            Message (short operator-readable text)

        .PARAMETER WinGetId
        Exact WinGet package ID (community ID such as 7zip.7zip, or a Store product ID).

        .PARAMETER TimeoutSeconds
        Bound for each source query. Default 30.

        .PARAMETER WinGetPath
        Optional explicit path to winget.exe. Must exist, or the result is Unavailable.

        .EXAMPLE
        $lookup = Get-WinGetAppDescription -WinGetId '7zip.7zip'
        if ($lookup.Found) { $description = $lookup.Description } else { $description = 'N/A' }
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$WinGetId,
        [int]$TimeoutSeconds = 30,
        [string]$WinGetPath
    )

    try {
        if (-not (Test-PDWinGetId -Value $WinGetId)) {
            return (New-PDWinGetDescriptionResult -Status 'NotFound' -Message 'Not a valid WinGet ID; lookup skipped.')
        }
        if ($TimeoutSeconds -lt 1) { $TimeoutSeconds = 1 }

        $exe = Resolve-PDWinGetPath -WinGetPath $WinGetPath
        if (-not $exe) {
            return (New-PDWinGetDescriptionResult -Status 'Unavailable' -Message 'winget.exe was not found on this machine.')
        }

        $attempts = @()
        $firstPublisher = $null
        $firstHomepage = $null
        $firstPrivacyUrl = $null
        foreach ($source in @('msstore', 'winget')) {
            $arguments = 'show --id {0} --exact --source {1} --disable-interactivity --accept-source-agreements' -f $WinGetId, $source
            Write-Verbose ("Get-WinGetAppDescription: {0} {1}" -f $exe, $arguments)

            $run = Invoke-PDWinGetProcess -FilePath $exe -Arguments $arguments -TimeoutSeconds $TimeoutSeconds
            Write-Verbose ("Get-WinGetAppDescription: {0} exit={1} timedOut={2} elapsedMs={3}" -f $source, $run.ExitCode, $run.TimedOut, $run.ElapsedMs)

            if (-not $run.Started) {
                return (New-PDWinGetDescriptionResult -Status 'Unavailable' -Message ("winget could not be started: {0}" -f (Get-PDWinGetShortText -Text $run.Error)))
            }

            if ($run.TimedOut) {
                $attempts += [pscustomobject]@{ Source = $source; Status = 'Timeout'; Message = ("no answer within {0}s" -f $TimeoutSeconds) }
                continue
            }

            $parsed = ConvertFrom-PDWinGetShowOutput -Text $run.StdOut -ExpectedId $WinGetId
            if (($null -eq $firstPublisher) -and -not [string]::IsNullOrWhiteSpace([string]$parsed.Publisher)) { $firstPublisher = [string]$parsed.Publisher }
            if (($null -eq $firstHomepage) -and -not [string]::IsNullOrWhiteSpace([string]$parsed.Homepage)) { $firstHomepage = [string]$parsed.Homepage }
            if (($null -eq $firstPrivacyUrl) -and -not [string]::IsNullOrWhiteSpace([string]$parsed.PrivacyUrl)) { $firstPrivacyUrl = [string]$parsed.PrivacyUrl }
            if ($parsed.Status -eq 'Found') {
                $foundPublisher = $parsed.Publisher
                if ([string]::IsNullOrWhiteSpace([string]$foundPublisher)) { $foundPublisher = $firstPublisher }
                $foundHomepage = $parsed.Homepage
                if ([string]::IsNullOrWhiteSpace([string]$foundHomepage)) { $foundHomepage = $firstHomepage }
                $foundPrivacy = $parsed.PrivacyUrl
                if ([string]::IsNullOrWhiteSpace([string]$foundPrivacy)) { $foundPrivacy = $firstPrivacyUrl }
                return (New-PDWinGetDescriptionResult -Status 'Found' -Description $parsed.Description -Source $source -PackageId $parsed.PackageId -Publisher $foundPublisher -Homepage $foundHomepage -PrivacyUrl $foundPrivacy -Message ("Description found in the {0} source." -f $source))
            }

            $detail = $parsed.Message
            if (($parsed.Status -eq 'UnrecognizedOutput') -and [string]::IsNullOrWhiteSpace($run.StdOut) -and -not [string]::IsNullOrWhiteSpace($run.StdErr)) {
                $detail = 'winget error: ' + (Get-PDWinGetShortText -Text $run.StdErr)
            }
            $attempts += [pscustomobject]@{ Source = $source; Status = $parsed.Status; Message = $detail }
        }

        # Report the first attempt that was not a plain miss; a miss everywhere is NotFound.
        $status = 'NotFound'
        foreach ($attempt in $attempts) {
            if ($attempt.Status -ne 'NotFound') { $status = $attempt.Status; break }
        }
        $summary = ($attempts | ForEach-Object { '{0}: {1}' -f $_.Source, $_.Message }) -join ' '
        return (New-PDWinGetDescriptionResult -Status $status -Message $summary -Publisher $firstPublisher -Homepage $firstHomepage -PrivacyUrl $firstPrivacyUrl)
    } catch {
        return (New-PDWinGetDescriptionResult -Status 'Unavailable' -Message ("Description lookup failed: {0}" -f (Get-PDWinGetShortText -Text $_.Exception.Message)))
    }
}
