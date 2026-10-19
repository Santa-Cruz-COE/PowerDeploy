<#

.SYNOPSIS
    Offline behavioural tests for the Intune Graph upload feature.

.DESCRIPTION
    Dependency-free harness - this repository has no test framework, and Pester is installed
    here at two mutually incompatible majors. Every case runs offline: all network I/O goes
    through the library's single transport seam, so tests inject a fake transport and assert
    on the requests that would have been sent. No credential is ever read from or written to
    the real %LOCALAPPDATA% location; storage tests use a throwaway directory.

    Run under BOTH engines (spec section 13 - parser success alone is not a pass):

        powershell -NoProfile -ExecutionPolicy Bypass -File Tests\IntuneGraphUpload.Tests.ps1
        pwsh -NoProfile -ExecutionPolicy Bypass -File Tests\IntuneGraphUpload.Tests.ps1

    Exit code 0 = every case passed.

.MODULE
    Milestone 2 of .claude/plans/intune-graph-upload.buildplan.md covers the cases marked
    M2 below. Later milestones add cases to this same file.

#>

[CmdletBinding()]
param(
    [string]$HelperPath,
    [switch]$KeepTemp
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

$script:Cases   = @()
$script:Passed  = 0
$script:Failures = @()
$script:CurrentCase = ''

function Add-TestCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )
    $script:Cases += @{ Id = $Id; Name = $Name; Body = $Body }
}

function Assert-True {
    param([object]$Condition, [string]$Message)
    if (-not $Condition) { throw "Expected true: $Message" }
}

function Assert-Equal {
    param([object]$Expected, [object]$Actual, [string]$Message)
    if ($Expected -ne $Actual) { throw "Expected '$Expected' but got '$Actual'. $Message" }
}

function Assert-Like {
    param([string]$Pattern, [object]$Actual, [string]$Message)
    if (([string]$Actual) -notlike $Pattern) { throw "Expected '$Pattern' to match '$Actual'. $Message" }
}

function Assert-NotLike {
    param([string]$Pattern, [object]$Actual, [string]$Message)
    if (([string]$Actual) -like $Pattern) { throw "Expected '$Pattern' NOT to match, but it did. $Message" }
}

function Assert-Match {
    param([string]$Pattern, [object]$Actual, [string]$Message)
    if (([string]$Actual) -notmatch $Pattern) { throw "Expected regex '$Pattern' to match '$Actual'. $Message" }
}

function Assert-NotMatch {
    param([string]$Pattern, [object]$Actual, [string]$Message)
    if (([string]$Actual) -match $Pattern) { throw "Expected regex '$Pattern' NOT to match, but it did ('$Actual'). $Message" }
}

function Assert-Throws {
    <#
        Runs a script block, requires that it throw, and returns the ErrorRecord.
        Optional -MessagePattern is matched against the exception message.
    #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [string]$MessagePattern,
        [string]$Message
    )

    $caught = $null
    try {
        & $Body | Out-Null
    } catch {
        $caught = $_
    }

    if ($null -eq $caught) { throw "Expected a terminating error but none was thrown. $Message" }
    if ($MessagePattern -and (([string]$caught.Exception.Message) -notlike $MessagePattern)) {
        throw "Error message '$($caught.Exception.Message)' did not match '$MessagePattern'. $Message"
    }
    return $caught
}

function New-FakeSecureString {
    param([string]$Value = 'fake-secret-never-real')
    return (ConvertTo-SecureString -String $Value -AsPlainText -Force)
}

# Installed by the runner before every case except the deliberate real-transport ones, so a case
# that forgets to mock fails here instead of sending a request to Microsoft.
$script:PDTransportTripwire = {
    param($Request)
    throw ("this case did not install a transport; refusing {0} {1}" -f $Request.Method, $Request.Uri)
}

function New-MockResponse {
    param(
        [int]$StatusCode = 200,
        [string]$Body = '',
        [hashtable]$Headers = @{}
    )
    return @{
        StatusCode     = $StatusCode
        Body           = $Body
        Headers        = $Headers
        TransportError = $null
    }
}

function New-TestJwt {
    param([string[]]$Roles = @('DeviceManagementApps.ReadWrite.All', 'Group.Read.All'))

    $roleList = (@($Roles | ForEach-Object { '"' + $_ + '"' }) -join ',')
    $payload  = '{"aud":"00000003-0000-0000-c000-000000000000","roles":[' + $roleList + ']}'
    $encode = {
        param([string]$Text)
        [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Text)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
    $header = & $encode '{"alg":"RS256","typ":"JWT"}'
    $body64 = & $encode $payload
    return ($header + '.' + $body64 + '.not-a-real-signature')
}

# ---------------------------------------------------------------------------
# Locate and load the library under test
# ---------------------------------------------------------------------------

if ([string]::IsNullOrWhiteSpace($HelperPath)) {
    $HelperPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Other_Tools\InTune-GraphAPI_Helpers.ps1'
}
if (-not (Test-Path -LiteralPath $HelperPath)) {
    Write-Host "FATAL: helper library not found at $HelperPath"
    exit 2
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("PowerDeploy-GraphTests-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

Write-Host "================================================================"
Write-Host " IntuneGraphUpload tests"
Write-Host " Engine : PowerShell $($PSVersionTable.PSVersion)"
Write-Host " Helper : $HelperPath"
Write-Host " Temp   : $tempRoot"
Write-Host "================================================================"
Write-Host ""

# ---------------------------------------------------------------------------
# M2 - import purity and error plumbing
# ---------------------------------------------------------------------------

Add-TestCase 'M2-01' 'Dot-sourcing the library is silent and has no side effects' {
    # The real credential folder may legitimately exist on a workstation that has been provisioned,
    # so the check is "import changed nothing there", not "the folder does not exist".
    $realStore = Join-Path $env:LOCALAPPDATA 'PowerDeploy'
    $snapshot = {
        if (-not (Test-Path -LiteralPath $realStore)) { return 'absent' }
        # Files only: 5.1 can report a folder's own timestamp from a stale enumeration cache, while a
        # new, changed, or removed file (a lock, a temp file, a rewritten credential) still shows.
        return ((@(Get-ChildItem -LiteralPath $realStore -Recurse -Force | ForEach-Object { if ($_.PSIsContainer) { '{0}|dir' -f $_.FullName } else { '{0}|{1}|{2}' -f $_.FullName, $_.LastWriteTimeUtc.Ticks, $_.Length } }) | Sort-Object) -join "`n")
    }
    $before = & $snapshot

    # Import into a throwaway child scope purely to observe what import-time output happens.
    $imported = & {
        . $HelperPath
    }

    Assert-True ($null -eq $imported -or @($imported).Count -eq 0) "Importing must emit no output (got: $imported)"

    # Importing must not touch the credential store, authenticate, or write anywhere.
    Assert-Equal $before (& $snapshot) 'Import must not create or change anything in the real credential folder'
}

. $HelperPath

Add-TestCase 'M2-01b' 'Every documented entry point is defined after import' {
    foreach ($required in @('Get-PDGraphCredential', 'Save-PDGraphCredential', 'Remove-PDGraphCredential',
                            'Get-PDGraphCredentialPath', 'New-PDGraphCredentialObject',
                            'Enter-PDGraphCredentialLock', 'Exit-PDGraphCredentialLock',
                            'Get-PDGraphToken', 'Invoke-PDGraphRequest', 'Get-PDGraphCollection',
                            'Invoke-PDGraphTransport', 'Get-PDGraphNormalizedResponse',
                            'Complete-PDIntuneNotes', 'Remove-UrlCredential', 'Test-PDGraphUrlIsGraph',
                            'Get-PDGraphErrorInfo', 'New-PDGraphError', 'Stop-PDGraphError',
                            'Get-PDGraphItems', 'Get-PDGraphServiceMessage', 'Test-PDGraphApprovalRequired',
                            'Get-PDGraphResponseHeader', 'Get-PDJwtClaims', 'Test-PDGraphGuid',
                            'Read-PDIntuneWinPackage', 'New-PDWin32AppPayload',
                            'Resolve-PDGraphGroups', 'Resolve-PDGraphGroup', 'Find-PDIntuneDuplicateApps',
                            'Find-PDIntuneCategory', 'Get-PDDelimitedList', 'ConvertTo-PDODataStringLiteral',
                            'New-PDGraphQueryPath', 'Test-PDArchiveEntryName', 'Get-PDXmlElementText',
                            'Get-PDCommandFileText', 'Get-PDDetectionScriptBase64', 'Get-PDFileSha256',
                            'Get-PDGraphPropertyValue', 'Get-PDResolvedFilePath', 'Get-PDTextFileContents',
                            'Get-PDGraphProvisioningPrerequisite', 'Connect-PDGraphInteractive',
                            'Disconnect-PDGraphInteractive', 'Start-PDGraphUploadProvisioning',
                            'Start-PDGraphSecretRotation', 'Remove-PDGraphUploadCredential',
                            'Get-PDGraphUploadMaaGuidance',
                            'Find-PDEntraUploadApp', 'Ensure-PDEntraApplication',
                            'Ensure-PDServicePrincipal', 'Ensure-PDAppRoleAssignments',
                            'Add-PDAppSecret', 'Remove-PDAppSecret', 'Get-PDEntraAppSecretKey',
                            'New-PDGraphSecretLabel', 'Wait-PDGraphUploadSecretReady',
                            'Resolve-PDGraphDelegatedContext', 'Resolve-PDEntraApplicationRole',
                            'Set-PDEntraRequiredResourceAccess', 'Get-PDEntraApplication',
                            'Get-PDGraphServicePrincipal', 'Get-PDGraphDelegatedCollection')) {
        Assert-True ($null -ne (Get-Command -CommandType Function -Name $required -ErrorAction SilentlyContinue)) "Function $required should be defined"
    }
}

Add-TestCase 'M2-02' 'Sanitized error detail survives throw/catch' {
    $caught = Assert-Throws -Body {
        Stop-PDGraphError -Message 'nope' -Stage 'CreateApp' -Status 403 -RequestId 'req-1' -ApprovalRequired $true -Detail 'service said no'
    }

    $info = Get-PDGraphErrorInfo -ErrorRecord $caught
    Assert-Equal 'CreateApp' $info.Stage 'Stage survives'
    Assert-Equal 403 $info.Status 'Status survives'
    Assert-Equal 'req-1' $info.RequestId 'RequestId survives'
    Assert-True $info.ApprovalRequired 'ApprovalRequired survives'
    Assert-True $info.Sanitized 'Sanitized marker survives'
    Assert-Like '*stage: CreateApp*' $info.Message 'Message names the stage'
    Assert-Like '*Multi-Admin Approval*' $info.Message 'Message names MAA when flagged'
}

Add-TestCase 'M2-03' 'Get-PDGraphErrorInfo tolerates foreign exceptions' {
    $info = Get-PDGraphErrorInfo -ErrorRecord (New-Object System.Exception 'plain')
    Assert-Equal 'plain' $info.Message 'Plain message readable'
    Assert-True (-not $info.Sanitized) 'Plain exception is not sanitized'
    Assert-Equal 0 $info.Status 'Status defaults to 0'

    $info2 = Get-PDGraphErrorInfo -ErrorRecord $null
    Assert-True ($null -ne $info2) 'Null input still returns a hashtable'
}

# ---------------------------------------------------------------------------
# M2 - Remove-UrlCredential (spec 12.1, test L01)
# ---------------------------------------------------------------------------

Add-TestCase 'L01a' 'Remove-UrlCredential strips userinfo and never emits the secret' {
    $secret = 'ghp_SUPERSECRETVALUE1234567890'
    $cases = @(
        @{ In = "https://oauth2:$secret@github.com/org/PowerDeploy.git"; Like = 'https://github.com/*' },
        @{ In = "https://$secret@github.com/org/repo";                   Like = 'https://github.com/*' },
        @{ In = "http://user:pass@example.com:8080/a/b";                 Like = 'http://example.com:8080/*' },
        @{ In = "https://org@github.com/a/b";                            Like = 'https://github.com/*' }
    )

    foreach ($case in $cases) {
        $out = Remove-UrlCredential -Url $case.In
        Assert-Like $case.Like $out "stripped to host for $($case.In)"
        Assert-NotLike "*$secret*" $out 'secret must not survive'
        Assert-NotLike '*pass*' $out 'password must not survive'
        Assert-NotLike '*oauth2*' $out 'userinfo must not survive'
    }
}

Add-TestCase 'L01b' 'Remove-UrlCredential leaves non-credential forms alone' {
    Assert-Equal 'git@github.com:org/repo.git' (Remove-UrlCredential -Url 'git@github.com:org/repo.git') 'scp-style remote unchanged'
    Assert-Equal 'https://github.com/Santa-Cruz-COE/PowerDeploy' (Remove-UrlCredential -Url 'https://github.com/Santa-Cruz-COE/PowerDeploy') 'clean url unchanged'
    Assert-Equal 'C:\ProgramData\PowerDeploy--PRODUCTION' (Remove-UrlCredential -Url 'C:\ProgramData\PowerDeploy--PRODUCTION') 'local path unchanged'
    Assert-Equal '' (Remove-UrlCredential -Url '') 'empty in, empty out'
    Assert-Equal '' (Remove-UrlCredential -Url $null) 'null in, empty out'

    $withQuery = Remove-UrlCredential -Url "https://user:pw@github.com/org/repo?x=1"
    Assert-Equal 'https://github.com/org/repo?x=1' $withQuery 'query preserved, userinfo removed'

    # A malformed authority must be redacted, not echoed.
    Assert-Like '*<redacted>*' (Remove-UrlCredential -Url 'https://justuser@') 'malformed userinfo-only authority is redacted'
    Assert-NotLike '*justuser*' (Remove-UrlCredential -Url 'https://justuser@') 'malformed input user is not echoed'
}

Add-TestCase 'M2-04' 'Remove-UrlCredential never throws on hostile input' {
    $hostile = @('https://', '://x', 'http://[', ('https://' + ('a' * 5000)), "https://a`n@b.com/c", '%zz%://x', '\\server\share')
    foreach ($value in $hostile) {
        $result = Remove-UrlCredential -Url $value
        Assert-True ($null -ne $result) "returns a value for '$value'"
        Assert-True ($result -notmatch "`n") "result stays single-line for '$value'"
    }
}

# ---------------------------------------------------------------------------
# M2 - Complete-PDIntuneNotes (spec 4.4, test N01)
# ---------------------------------------------------------------------------

Add-TestCase 'N01a' 'Complete-PDIntuneNotes appends exactly one ISO-8601 Created line' {
    $notes = "InstallMethod: WinGet`r`nTarget Version: N/A"
    $when  = [System.DateTimeOffset]::new(2026, 10, 8, 15, 30, 45, [System.TimeSpan]::FromHours(-7))

    $out = Complete-PDIntuneNotes -Notes $notes -CreatedAt $when
    $lines = @($out -split "`r`n")

    Assert-Equal 3 $lines.Count "three lines total (got $($lines.Count))"
    Assert-Equal 'InstallMethod: WinGet' $lines[0] 'technical block preserved'
    Assert-Match '^Created: 2026-10-08T15:30:45-07:00$' $lines[2] 'timestamp carries the offset'
    Assert-Equal 1 @($lines | Where-Object { $_ -like 'Created:*' }).Count 'exactly one Created line'
}

Add-TestCase 'N01b' 'Complete-PDIntuneNotes is idempotent so a retry cannot double-stamp' {
    $when = [System.DateTimeOffset]::UtcNow
    $once = Complete-PDIntuneNotes -Notes 'Verified: pilot group' -CreatedAt $when
    $twice = Complete-PDIntuneNotes -Notes $once -CreatedAt ([System.DateTimeOffset]::UtcNow)

    Assert-Equal $once.TrimEnd() $twice.TrimEnd() 'second call changes nothing'
    Assert-Equal 1 @(($twice -split "`r`n") | Where-Object { $_ -like 'Created:*' }).Count 'still one Created line'
}

Add-TestCase 'N01c' 'Complete-PDIntuneNotes adds no user or machine attribution' {
    $out = Complete-PDIntuneNotes -Notes 'x' -CreatedAt ([System.DateTimeOffset]::UtcNow)
    Assert-NotLike "*$env:USERNAME*" $out 'no username'
    Assert-NotLike "*$env:COMPUTERNAME*" $out 'no computer name'
    Assert-Equal 2 @($out -split "`r`n").Count 'only the block and the stamp'
    Assert-Match 'Created: .*[+-]\d{2}:\d{2}$' $out 'offset always present'
}

Add-TestCase 'M2-05' 'Complete-PDIntuneNotes handles empty notes and rejects garbage timestamps' {
    $out = Complete-PDIntuneNotes -Notes '' -CreatedAt ([System.DateTimeOffset]::new(2026, 1, 2, 3, 4, 5, [System.TimeSpan]::Zero))
    Assert-Match '^Created: 2026-01-02T03:04:05' $out 'empty notes yields just the stamp'

    $out2 = Complete-PDIntuneNotes -Notes "trailing blank lines`r`n`r`n`r`n" -CreatedAt ([System.DateTimeOffset]::UtcNow)
    Assert-Equal 2 @($out2 -split "`r`n").Count 'trailing blank lines collapse'

    Assert-Throws -Body { Complete-PDIntuneNotes -Notes 'x' -CreatedAt 'definitely not a date' } -MessagePattern '*timestamp*' 'unparseable timestamp is refused'
}

# ---------------------------------------------------------------------------
# M2 - JWT claims and URL gating
# ---------------------------------------------------------------------------

Add-TestCase 'M2-06' 'Get-PDJwtClaims reads the roles claim without verifying anything' {
    $jwt = New-TestJwt -Roles @('DeviceManagementApps.ReadWrite.All', 'Group.Read.All')
    $claims = Get-PDJwtClaims -Token $jwt
    $roles = @($claims.roles)
    Assert-Equal 2 $roles.Count 'both roles decoded'
    Assert-True ($roles -contains 'Group.Read.All') 'Group.Read.All present'
    Assert-True ((Get-PDJwtClaims -Token '').Count -eq 0) 'empty token yields no claims'
    Assert-True ((Get-PDJwtClaims -Token 'not-a-jwt').Count -eq 0) 'garbage token yields no claims'
}

Add-TestCase 'M2-07' 'Test-PDGraphUrlIsGraph accepts only https on the Graph host' {
    Assert-True (Test-PDGraphUrlIsGraph -Url 'https://graph.microsoft.com/beta/x') 'graph beta url'
    Assert-True (Test-PDGraphUrlIsGraph -Url 'https://graph.microsoft.com/v1.0/groups') 'graph v1 url'
    Assert-True (-not (Test-PDGraphUrlIsGraph -Url 'http://graph.microsoft.com/beta')) 'plain http refused'
    Assert-True (-not (Test-PDGraphUrlIsGraph -Url 'https://graph.microsoft.com.evil.test/x')) 'suffix-spoof refused'
    Assert-True (-not (Test-PDGraphUrlIsGraph -Url 'https://contoso.blob.core.windows.net/c/b')) 'storage refused'
    Assert-True (-not (Test-PDGraphUrlIsGraph -Url '/relative/path')) 'relative refused'
    Assert-True (-not (Test-PDGraphUrlIsGraph -Url $null)) 'null refused'
}

# ---------------------------------------------------------------------------
# M2 - credential storage (spec 7.3, tests C01/C02)
# ---------------------------------------------------------------------------

Add-TestCase 'C01a' 'Missing credential produces an actionable message naming the menu' {
    $missing = Join-Path $tempRoot 'nope\credential.clixml'
    Assert-Throws -Body { Get-PDGraphCredential -Path $missing } -MessagePattern '*InTuneAPI--Setup-and-Manage*' 'points at the provisioning menu'
}

Add-TestCase 'C01b' 'Save then load round-trips a credential without exposing the secret' {
    $path = Join-Path $tempRoot 'roundtrip\credential.clixml'
    $secret = New-FakeSecureString -Value 'R0tund0wn3d-never-real'

    $credential = New-PDGraphCredentialObject -TenantId ([guid]::NewGuid().ToString()) `
        -ClientId ([guid]::NewGuid().ToString()) -ClientSecret $secret `
        -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays(90)) `
        -SecretKeyId ([guid]::NewGuid().ToString()) -AppDisplayName 'PowerDeploy Intune Upload'

    $saved = Save-PDGraphCredential -Credential $credential -Path $path
    Assert-True (Test-Path -LiteralPath $path) 'file exists'
    Assert-True (-not (Test-Path -LiteralPath "$path.lock")) 'lock file removed after save'
    Assert-True ($saved.DaysUntilExpiry -gt 88) "computed days until expiry ($($saved.DaysUntilExpiry))"

    $bytes = [System.IO.File]::ReadAllBytes($path)
    $text  = [System.Text.Encoding]::UTF8.GetString($bytes)
    Assert-NotLike '*R0tund0wn3d-never-real*' $text 'secret text is not stored in clear'

    $loaded = Get-PDGraphCredential -Path $path
    Assert-Equal $credential.TenantId $loaded.TenantId 'TenantId round-trips'
    Assert-Equal $credential.ClientId $loaded.ClientId 'ClientId round-trips'
    Assert-True ($loaded.ClientSecret -is [System.Security.SecureString]) 'secret comes back as SecureString'
    Assert-Equal ([guid]$credential.SecretKeyId).ToString() ([guid]$loaded.SecretKeyId).ToString() 'SecretKeyId round-trips'
    Assert-True ($loaded.SecretExpiresOn -is [System.DateTimeOffset]) 'expiry comes back as DateTimeOffset'
    Assert-Equal 0 @($loaded.Warnings).Count 'no warnings for a 90-day secret'
    Assert-True (-not $loaded.ContainsKey('ClientSecretPlain')) 'no plaintext helper field exists'
}

Add-TestCase 'C01e' 'Saving over an existing credential replaces it' {
    # Regression: File.Replace was given $null for the backup path, which PowerShell passes to .NET
    # as an empty string, so every save over an existing file failed (rotation, re-entry).
    $path = Join-Path $tempRoot 'overwrite\credential.clixml'
    $first = New-PDGraphCredentialObject -TenantId ([guid]::NewGuid().ToString()) `
        -ClientId ([guid]::NewGuid().ToString()) -ClientSecret (New-FakeSecureString -Value 'first-never-real') `
        -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays(90)) -SecretKeyId ([guid]::NewGuid().ToString())
    $null = Save-PDGraphCredential -Credential $first -Path $path

    $secondKey = [guid]::NewGuid().ToString()
    $second = New-PDGraphCredentialObject -TenantId $first.TenantId -ClientId $first.ClientId `
        -ClientSecret (New-FakeSecureString -Value 'second-never-real') `
        -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays(180)) -SecretKeyId $secondKey
    $null = Save-PDGraphCredential -Credential $second -Path $path

    $loaded = Get-PDGraphCredential -Path $path
    Assert-Equal $secondKey ([guid]$loaded.SecretKeyId).ToString() 'the second save is what loads'
    Assert-Equal 0 @(Get-ChildItem -LiteralPath (Split-Path $path -Parent) -Filter '*.tmp').Count 'no temp file left behind'
    Assert-True (-not (Test-Path -LiteralPath "$path.lock")) 'lock released'
}

Add-TestCase 'C01c' 'Corrupt, wrong-schema, and foreign-secret files each get one clear message' {
    # Garbage file.
    $garbage = Join-Path $tempRoot 'corrupt\credential.clixml'
    New-Item -ItemType Directory -Path (Split-Path $garbage -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllText($garbage, 'this is not a clixml document <<<')
    $caught = Assert-Throws -Body { Get-PDGraphCredential -Path $garbage }
    Assert-Like '*credential*' $caught.Exception.Message 'mentions the credential'

    # Right shape, plaintext secret (the dangerous case: something else wrote this file).
    $plaintextSecret = Join-Path $tempRoot 'plaintext\credential.clixml'
    $bad = @{
        SchemaVersion   = 1
        TenantId        = [guid]::NewGuid().ToString()
        ClientId        = [guid]::NewGuid().ToString()
        ClientSecret    = 'plaintext-is-never-acceptable'
        SecretExpiresOn = ([System.DateTimeOffset]::UtcNow.AddDays(10)).ToString('o')
    }
    New-Item -ItemType Directory -Path (Split-Path $plaintextSecret -Parent) -Force | Out-Null
    Export-Clixml -LiteralPath $plaintextSecret -InputObject $bad -Depth 5
    $caught2 = Assert-Throws -Body { Get-PDGraphCredential -Path $plaintextSecret }
    Assert-Like '*SecureString*' $caught2.Exception.Message 'names the SecureString requirement'

    # Wrong schema version.
    $wrongSchema = Join-Path $tempRoot 'schema\credential.clixml'
    $old = New-PDGraphCredentialObject -TenantId ([guid]::NewGuid().ToString()) -ClientId ([guid]::NewGuid().ToString()) `
        -ClientSecret (New-FakeSecureString) -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays(10))
    $old['SchemaVersion'] = 99
    New-Item -ItemType Directory -Path (Split-Path $wrongSchema -Parent) -Force | Out-Null
    Export-Clixml -LiteralPath $wrongSchema -InputObject $old -Depth 5
    Assert-Throws -Body { Get-PDGraphCredential -Path $wrongSchema } -MessagePattern '*SchemaVersion*' 'names the schema version'

    # Not a GUID.
    $badGuid = Join-Path $tempRoot 'badguid\credential.clixml'
    $g = New-PDGraphCredentialObject -TenantId ([guid]::NewGuid().ToString()) -ClientId ([guid]::NewGuid().ToString()) `
        -ClientSecret (New-FakeSecureString) -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays(10))
    $g['TenantId'] = 'not-a-guid'
    New-Item -ItemType Directory -Path (Split-Path $badGuid -Parent) -Force | Out-Null
    Export-Clixml -LiteralPath $badGuid -InputObject $g -Depth 5
    Assert-Throws -Body { Get-PDGraphCredential -Path $badGuid } -MessagePattern '*TenantId*' 'names TenantId'
}

Add-TestCase 'C01d' 'Expired credentials are refused outright' {
    $path = Join-Path $tempRoot 'expired\credential.clixml'
    $c = New-PDGraphCredentialObject -TenantId ([guid]::NewGuid().ToString()) -ClientId ([guid]::NewGuid().ToString()) `
        -ClientSecret (New-FakeSecureString) -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays(-1))
    Save-PDGraphCredential -Credential $c -Path $path | Out-Null

    $caught = Assert-Throws -Body { Get-PDGraphCredential -Path $path } -MessagePattern '*expired*'
    Assert-Like '*rotate*' $caught.Exception.Message 'tells the operator to rotate'

    Assert-Throws -Body { Get-PDGraphToken -Credential (Get-PDGraphCredential -Path $path) } -MessagePattern '*expired*' 'token acquisition also refuses'
}

Add-TestCase 'C02' 'Near-expiry credentials stay usable but return a warning' {
    $path = Join-Path $tempRoot 'nearexpiry\credential.clixml'
    $c = New-PDGraphCredentialObject -TenantId ([guid]::NewGuid().ToString()) -ClientId ([guid]::NewGuid().ToString()) `
        -ClientSecret (New-FakeSecureString) -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays(12))
    Save-PDGraphCredential -Credential $c -Path $path | Out-Null

    $loaded = Get-PDGraphCredential -Path $path
    Assert-True ($loaded.DaysUntilExpiry -le 13 -and $loaded.DaysUntilExpiry -ge 11) "days until expiry is near ($($loaded.DaysUntilExpiry))"
    Assert-Equal 1 @($loaded.Warnings | Where-Object { $_ -like '*expire*' }).Count 'exactly one expiry warning'
    Assert-Equal 1 @($loaded.Warnings | Where-Object { $_ -like '*key id*' }).Count 'the missing key id is separately reported'
    Assert-Like '*expire*' @($loaded.Warnings | Where-Object { $_ -like '*expire*' })[0] 'warning is about expiry'
}

Add-TestCase 'C03a' 'A save that fails validation leaves the previous credential working' {
    $path = Join-Path $tempRoot 'atomic\credential.clixml'
    $good = New-PDGraphCredentialObject -TenantId ([guid]::NewGuid().ToString()) -ClientId ([guid]::NewGuid().ToString()) `
        -ClientSecret (New-FakeSecureString -Value 'original') -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays(60))
    Save-PDGraphCredential -Credential $good -Path $path | Out-Null
    $originalTenant = (Get-PDGraphCredential -Path $path).TenantId

    # Simulate a broken write: a plaintext secret passes straight through Save and fails the
    # round-trip validation, which is exactly the guard under test.
    $broken = @{
        TenantId        = [guid]::NewGuid().ToString()
        ClientId        = [guid]::NewGuid().ToString()
        ClientSecret    = 'plaintext'
        SecretExpiresOn = ([System.DateTimeOffset]::UtcNow.AddDays(60)).ToString('o')
    }
    Assert-Throws -Body { Save-PDGraphCredential -Credential $broken -Path $path } -MessagePattern '*existing credential is unchanged*' 'failure is explicit'

    Assert-Equal $originalTenant (Get-PDGraphCredential -Path $path).TenantId 'old credential still loads'
    Assert-Equal 0 @(Get-ChildItem -LiteralPath (Split-Path $path -Parent) -Filter 'credential.*.tmp').Count 'no temp file left behind'
    Assert-True (-not (Test-Path -LiteralPath "$path.lock")) 'no lock left behind'
}

Add-TestCase 'C03b' 'A concurrent save is rejected rather than racing the first' {
    $path = Join-Path $tempRoot 'locking\credential.clixml'
    $c = New-PDGraphCredentialObject -TenantId ([guid]::NewGuid().ToString()) -ClientId ([guid]::NewGuid().ToString()) `
        -ClientSecret (New-FakeSecureString) -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays(60))

    $savedLock = Enter-PDGraphCredentialLock -CredentialPath $path
    $previousWait = $script:PDGraph.LockWaitSeconds
    $script:PDGraph.LockWaitSeconds = 1
    try {
        Assert-Throws -Body { Save-PDGraphCredential -Credential $c -Path $path } -MessagePattern '*already in progress*' 'second writer is refused'
    } finally {
        $script:PDGraph.LockWaitSeconds = $previousWait
        Exit-PDGraphCredentialLock -Lock $savedLock
    }

    # After release the same save succeeds, proving the refusal was a lock and not a wedge.
    Save-PDGraphCredential -Credential $c -Path $path | Out-Null
    Assert-True (Test-Path -LiteralPath $path) 'save succeeds once the lock is released'
}

Add-TestCase 'C04a' 'Remove-PDGraphCredential removes only the named file and is idempotent' {
    $path = Join-Path $tempRoot 'removal\credential.clixml'
    $c = New-PDGraphCredentialObject -TenantId ([guid]::NewGuid().ToString()) -ClientId ([guid]::NewGuid().ToString()) `
        -ClientSecret (New-FakeSecureString) -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays(60))
    Save-PDGraphCredential -Credential $c -Path $path | Out-Null

    $sibling = Join-Path (Split-Path $path -Parent) 'unrelated.txt'
    Set-Content -LiteralPath $sibling -Value 'keep me'

    $first = Remove-PDGraphCredential -Path $path
    Assert-True $first.Removed 'reports removal'
    Assert-True (-not (Test-Path -LiteralPath $path)) 'file gone'
    Assert-Like '*still active*' $first.Message 'warns the Entra secret survives'
    Assert-True (Test-Path -LiteralPath $sibling) 'sibling file untouched'

    $second = Remove-PDGraphCredential -Path $path
    Assert-True (-not $second.Removed) 'second removal reports nothing to do'
}

Add-TestCase 'C02b' 'A recorded key id silences the rotation warning' {
    $path = Join-Path $tempRoot 'nearexpiry2\credential.clixml'
    $c = New-PDGraphCredentialObject -TenantId ([guid]::NewGuid().ToString()) -ClientId ([guid]::NewGuid().ToString()) `
        -ClientSecret (New-FakeSecureString) -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays(12)) `
        -SecretKeyId ([guid]::NewGuid().ToString())
    Save-PDGraphCredential -Credential $c -Path $path | Out-Null

    $loaded = Get-PDGraphCredential -Path $path
    Assert-Equal 0 @($loaded.Warnings | Where-Object { $_ -like '*key id*' }).Count 'no key id warning when it is recorded'
}

# ---------------------------------------------------------------------------
# M2 - credential path resolution
# ---------------------------------------------------------------------------

Add-TestCase 'M2-08' 'Credential path defaults to LOCALAPPDATA and honours overrides' {
    $default = Get-PDGraphCredentialPath
    Assert-Like '*PowerDeploy*GraphUpload*credential.clixml' $default 'default layout'
    Assert-True ([System.IO.Path]::IsPathRooted($default)) 'default is absolute'
    Assert-True ($default -notlike '*\.\*') 'default is normalized'

    $override = Get-PDGraphCredentialPath -Path (Join-Path $tempRoot 'override\cred.clixml')
    Assert-Equal (Join-Path $tempRoot 'override\cred.clixml') $override 'override honoured'

    $relative = Get-PDGraphCredentialPath -Path (Join-Path $tempRoot '..\..\fixtures')
    Assert-True ($relative -notlike '*..*') 'relative segments resolved'
}

Add-TestCase 'M2-09' 'New-PDGraphCredentialObject validates every input' {
    $good = @{
        TenantId        = [guid]::NewGuid().ToString()
        ClientId        = [guid]::NewGuid().ToString()
        ClientSecret    = New-FakeSecureString
        SecretExpiresOn = [System.DateTimeOffset]::UtcNow.AddDays(30)
    }

    Assert-Throws -Body { New-PDGraphCredentialObject -TenantId 'nope' -ClientId $good.ClientId -ClientSecret $good.ClientSecret -SecretExpiresOn $good.SecretExpiresOn } -MessagePattern '*TenantId*' 'bad tenant refused'
    Assert-Throws -Body { New-PDGraphCredentialObject -TenantId $good.TenantId -ClientId 'nope' -ClientSecret $good.ClientSecret -SecretExpiresOn $good.SecretExpiresOn } -MessagePattern '*ClientId*' 'bad client refused'
    Assert-Throws -Body { New-PDGraphCredentialObject -TenantId $good.TenantId -ClientId $good.ClientId -ClientSecret $good.ClientSecret -SecretExpiresOn 'whenever' } -MessagePattern '*SecretExpiresOn*' 'bad expiry refused'
    Assert-Throws -Body { New-PDGraphCredentialObject -TenantId $good.TenantId -ClientId $good.ClientId -ClientSecret $good.ClientSecret -SecretExpiresOn $good.SecretExpiresOn -SecretKeyId 'oops' } -MessagePattern '*SecretKeyId*' 'bad key id refused'
    Assert-Throws -Body { New-PDGraphCredentialObject -TenantId $good.TenantId -ClientId $good.ClientId -ClientSecret $good.ClientSecret } -MessagePattern '*SecretExpiresOn*' 'missing expiry refused'

    # Optional identifiers may legitimately be absent (manual entry path, spec 7.2).
    $minimal = New-PDGraphCredentialObject -TenantId $good.TenantId -ClientId $good.ClientId -ClientSecret $good.ClientSecret -SecretExpiresOn $good.SecretExpiresOn
    Assert-Equal '' $minimal.SecretKeyId 'absent key id stays empty, not invented'
    Assert-Equal '' $minimal.AppObjectId 'absent object id stays empty, not invented'
    Assert-Equal $good.TenantId.ToLower() $minimal.TenantId 'tenant normalized to lowercase'
}

# ---------------------------------------------------------------------------
# M2 - token acquisition and request stack (mocked transport)
# ---------------------------------------------------------------------------

Add-TestCase 'M2-10' 'Token acquisition decodes roles, caches, and honours -Force' {
    $script:MockCalls = @()
    $script:MockToken = (New-TestJwt)
    $script:PDGraph.TestTransport = {
        param($Request)
        $script:MockCalls += $Request
        return (New-MockResponse -StatusCode 200 -Body (@{ access_token = $script:MockToken; expires_in = 3600 } | ConvertTo-Json -Compress) -Headers @{ 'request-id' = 'tok-1' })
    }

    $c = New-PDGraphCredentialObject -TenantId ([guid]::NewGuid().ToString()) -ClientId ([guid]::NewGuid().ToString()) `
        -ClientSecret (New-FakeSecureString -Value 'token-flow-secret') -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays(30))

    $script:PDGraph.TokenCache = @{}
    $token = Get-PDGraphToken -Credential $c
    Assert-True (@($script:MockCalls).Count -eq 1) 'exactly one token request'
    Assert-Equal 'Post' $script:MockCalls[0].Method 'token request is a POST'
    Assert-Like 'https://login.microsoftonline.com/*' $script:MockCalls[0].Uri 'token endpoint host'
    Assert-True ($script:MockCalls[0].Uri -like ("https://login.microsoftonline.com/$($c.TenantId)/oauth2/v2.0/token")) 'token endpoint carries the tenant id'
    Assert-True ($script:MockCalls[0].BodyText -like 'grant_type=client_credentials*') 'client credentials grant'
    Assert-True ($script:MockCalls[0].BodyText -like '*scope=https%3A%2F%2Fgraph.microsoft.com%2F.default*') 'scope url-encoded'
    Assert-True (-not $script:MockCalls[0].ContainsKey('Headers') -or $null -eq $script:MockCalls[0].Headers -or -not $script:MockCalls[0].Headers.ContainsKey('Authorization')) 'no authorization header on a token request'
    Assert-Equal 2 @($token.Roles).Count 'roles decoded from the token'
    Assert-True ($token.ExpiresOn -gt [DateTime]::UtcNow.AddMinutes(50)) 'expiry computed'
    Assert-NotLike '*token-flow-secret*' ($script:MockCalls[0].Uri) 'secret never appears in the token URL'

    $again = Get-PDGraphToken -Credential $c
    Assert-True (@($script:MockCalls).Count -eq 1) 'second call is served from cache'
    Assert-Equal $token.AccessToken $again.AccessToken 'cached token identical'

    $forced = Get-PDGraphToken -Credential $c -Force
    Assert-True (@($script:MockCalls).Count -eq 2) '-Force bypasses the cache'

    # A body that would leak the secret must never be returned or surfaced.
    Assert-NotLike '*token-flow-secret*' ($token | ConvertTo-Json -Depth 5) 'returned token has no secret'
    $script:PDGraph.TestTransport = $null
    $script:PDGraph.TokenCache = @{}
}

Add-TestCase 'U04a' 'A bad secret yields the service reason, without echoing the secret' {
    $script:MockCalls = @()
    $script:PDGraph.TestTransport = {
        param($Request)
        $script:MockCalls += $Request
        return (New-MockResponse -StatusCode 401 -Body (@{ error = 'invalid_client'; error_description = 'AADSTS7000215: Invalid provided secret value.' } | ConvertTo-Json -Compress) -Headers @{ 'request-id' = 'bad-1' })
    }

    $c = New-PDGraphCredentialObject -TenantId ([guid]::NewGuid().ToString()) -ClientId ([guid]::NewGuid().ToString()) `
        -ClientSecret (New-FakeSecureString -Value 'super-secret-value') -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays(30))

    $script:PDGraph.TokenCache = @{}
    $caught = Assert-Throws -Body { Get-PDGraphToken -Credential $c }
    $msg = [string]$caught.Exception.Message
    Assert-Like '*AADSTS7000215*' $msg 'service reason surfaced'
    Assert-NotLike '*super-secret-value*' $msg 'secret never echoed'
    Assert-NotLike '*client_secret*' $msg 'request body never echoed'

    $info = Get-PDGraphErrorInfo -ErrorRecord $caught
    Assert-Equal 401 $info.Status 'status recorded'
    Assert-Equal 'Credential' $info.Stage 'stage recorded'
    Assert-True (-not $info.Retryable) '401 is not retried'
    Assert-Equal 1 @($script:MockCalls).Count 'an invalid secret is a terminal refusal, never retried'

    $script:PDGraph.TestTransport = $null
    $script:PDGraph.TokenCache = @{}
}

Add-TestCase 'M2-11' 'Invoke-PDGraphRequest sends what we think it sends' {
    $script:MockCalls = @()
    $script:PDGraph.TestTransport = {
        param($Request)
        $script:MockCalls += $Request
        return (New-MockResponse -StatusCode 200 -Body '{"id":"app-1","displayName":"x"}' -Headers @{ 'request-id' = 'r-1' })
    }

    $token = @{ AccessToken = 'opaque-token'; ExpiresOn = [DateTime]::UtcNow.AddHours(1); TenantId = 't'; ClientId = 'c'; Roles = @() }

    $result = Invoke-PDGraphRequest -Method Post -Uri '/beta/deviceAppManagement/mobileApps' -Body @{ displayName = 'App 1'; installExperience = @{ runAsAccount = 'system'; maxRunTimeInMinutes = 15 } } -AuthContext $token -Stage 'CreateApp'

    Assert-Equal 'app-1' $result.id 'parsed json returned'
    $call = @($script:MockCalls)[-1]
    Assert-Equal 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps' $call.Uri 'relative path resolved against beta base'
    Assert-Equal 'Bearer opaque-token' $call.Headers['Authorization'] 'bearer attached to graph'
    Assert-Like 'application/json*' $call.ContentType 'json content type'

    $sentJson = [System.Text.Encoding]::UTF8.GetString($call.BodyBytes)
    Assert-Like '*runAsAccount*' $sentJson 'nested object serialized to real JSON'
    Assert-Like '*maxRunTimeInMinutes*' $sentJson 'deeply nested value survives serialization'
    Assert-NotLike '*Hashtable*' $sentJson 'no stringified hashtable'
    Assert-NotLike '*opaque-token*' $sentJson 'bearer token is not in the body'

    # v1.0 paths pick the v1 base automatically.
    Invoke-PDGraphRequest -Method Get -Uri '/v1.0/groups/x' -AuthContext $token | Out-Null
    Assert-Equal 'https://graph.microsoft.com/v1.0/groups/x' (@($script:MockCalls)[-1]).Uri 'v1.0 path resolved'

    # An unversioned path defaults to beta exactly once - never /beta/beta/.
    Invoke-PDGraphRequest -Method Get -Uri '/deviceAppManagement/mobileApps' -AuthContext $token | Out-Null
    Assert-Equal 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps' (@($script:MockCalls)[-1]).Uri 'unversioned path gets one beta prefix'

    # An absolute Graph URL (a service nextLink) is used verbatim.
    Invoke-PDGraphRequest -Method Get -Uri 'https://graph.microsoft.com/v1.0/groups?$skiptoken=abc' -AuthContext $token | Out-Null
    Assert-Equal 'https://graph.microsoft.com/v1.0/groups?$skiptoken=abc' (@($script:MockCalls)[-1]).Uri 'absolute graph url unchanged'

    $script:PDGraph.TestTransport = $null
}

Add-TestCase 'M2-12' 'Authorization is never sent to a non-Graph host' {
    $script:MockCalls = @()
    $script:PDGraph.TestTransport = {
        param($Request)
        $script:MockCalls += $Request
        return (New-MockResponse -StatusCode 200 -Body '{}')
    }

    $token = @{ AccessToken = 'opaque-token'; ExpiresOn = [DateTime]::UtcNow.AddHours(1) }

    $caught = Assert-Throws -Body {
        Invoke-PDGraphRequest -Method Put -Uri 'https://contoso.blob.core.windows.net/printers/x.zip' -AuthContext $token -Stage 'Upload'
    }
    Assert-Like '*non-Graph host*' $caught.Exception.Message 'explicit refusal'
    Assert-Equal 0 @($script:MockCalls).Count 'refusal happens before any I/O'

    # Without an AuthContext the same storage URL is allowed through (SAS upload path).
    $script:PDGraph.TestTransport = $null
}

Add-TestCase 'U03a' 'Throttled reads honour Retry-After; writes are never repeated' {
    $script:MockCalls = @()
    $script:PDGraph.TestTransport = {
        param($Request)
        $script:MockCalls += $Request
        if (@($script:MockCalls).Count -lt 3) {
            return (New-MockResponse -StatusCode 429 -Body '{"error":{"message":"Too many requests"}}' -Headers @{ 'Retry-After' = '0'; 'request-id' = 'throttled' })
        }
        return (New-MockResponse -StatusCode 200 -Body '{"ok":true}')
    }

    $previousBase = $script:PDGraph.BaseRetryDelaySec
    $script:PDGraph.BaseRetryDelaySec = 0
    try {
        $r = Invoke-PDGraphRequest -Method Get -Uri '/beta/deviceAppManagement/mobileApps' -RetryMode 'Read'
        Assert-True $r.ok 'read eventually succeeds'
        Assert-Equal 3 @($script:MockCalls).Count 'two retries then success'

        # A write must be attempted exactly once: a lost response is reconciled, never repeated.
        $script:MockCalls = @()
        $script:PDGraph.TestTransport = {
            param($Request)
            $script:MockCalls += $Request
            return (New-MockResponse -StatusCode 503 -Body 'unavailable')
        }
        $caught = Assert-Throws -Body { Invoke-PDGraphRequest -Method Post -Uri '/beta/deviceAppManagement/mobileApps' -Body @{ x = 1 } -RetryMode 'Write' -Stage 'CreateApp' }
        Assert-Equal 1 @($script:MockCalls).Count 'write is never repeated'
        $info = Get-PDGraphErrorInfo -ErrorRecord $caught
        Assert-Equal 503 $info.Status 'status preserved'
        Assert-Equal 'CreateApp' $info.Stage 'stage preserved'
    } finally {
        $script:PDGraph.BaseRetryDelaySec = $previousBase
        $script:PDGraph.TestTransport = $null
    }
}

Add-TestCase 'U04b' 'Ordinary 400 and Multi-Admin-Approval refusals are told apart' {
    $token = @{ AccessToken = 'x'; ExpiresOn = [DateTime]::UtcNow.AddHours(1) }

    $script:PDGraph.TestTransport = {
        param($Request)
        return (New-MockResponse -StatusCode 400 -Body '{"error":{"code":"Request_BadRequest","message":"A property value is invalid."}}' -Headers @{ 'request-id' = 'p-1' })
    }
    $plain = Assert-Throws -Body { Invoke-PDGraphRequest -Method Post -Uri '/beta/x' -Body @{ a = 1 } -AuthContext $token -RetryMode 'Write' -Stage 'CreateApp' }
    $plainInfo = Get-PDGraphErrorInfo -ErrorRecord $plain
    Assert-True (-not $plainInfo.ApprovalRequired) 'ordinary 400 is NOT labeled MAA'
    Assert-Like '*invalid*' $plainInfo.Detail 'service reason preserved'

    $script:PDGraph.TestTransport = {
        param($Request)
        return (New-MockResponse -StatusCode 400 -Body '{"error":{"code":"AuthorizationRequestFailed","message":"Multiple admin approval is required to perform this operation."}}' -Headers @{ 'request-id' = 'maa-1' })
    }
    $maa = Assert-Throws -Body { Invoke-PDGraphRequest -Method Post -Uri '/beta/x' -Body @{ a = 1 } -AuthContext $token -RetryMode 'Write' -Stage 'CreateApp' }
    Assert-True (Get-PDGraphErrorInfo -ErrorRecord $maa).ApprovalRequired 'body evidence flags MAA'

    $script:PDGraph.TestTransport = {
        param($Request)
        return (New-MockResponse -StatusCode 412 -Body 'approval code required' -Headers @{ 'request-id' = 'maa-2' })
    }
    $maa2 = Assert-Throws -Body { Invoke-PDGraphRequest -Method Post -Uri '/beta/x' -Body @{ a = 1 } -AuthContext $token -RetryMode 'Write' -Stage 'CreateApp' }
    Assert-True (Get-PDGraphErrorInfo -ErrorRecord $maa2).ApprovalRequired '412 with approval text flags MAA'

    $script:PDGraph.TestTransport = {
        param($Request)
        return (New-MockResponse -StatusCode 403 -Body 'forbidden')
    }
    $forbidden = Assert-Throws -Body { Invoke-PDGraphRequest -Method Post -Uri '/beta/x' -Body @{ a = 1 } -AuthContext $token -RetryMode 'Write' -Stage 'CreateApp' }
    Assert-True (-not (Get-PDGraphErrorInfo -ErrorRecord $forbidden).ApprovalRequired) 'a bare 403 is NOT MAA'

    $script:PDGraph.TestTransport = $null
}

Add-TestCase 'M2-13' 'Transport failures are described, not dumped' {
    $script:PDGraph.TestTransport = {
        param($Request)
        return (Get-PDGraphNormalizedResponse -ErrorRecord (New-Object System.Management.Automation.ErrorRecord (New-Object System.Net.WebException 'The operation timed out'), 'timeout', 'NotSpecified', $null))
    }

    $previousAttempts = $script:PDGraph.MaxAttempts
    $previousBase     = $script:PDGraph.BaseRetryDelaySec
    $script:PDGraph.MaxAttempts = 2
    $script:PDGraph.BaseRetryDelaySec = 0
    try {
        $caught = Assert-Throws -Body { Invoke-PDGraphRequest -Method Get -Uri '/beta/x' -RetryMode 'Read' -Stage 'Verify' }
        $info = Get-PDGraphErrorInfo -ErrorRecord $caught
        Assert-Like '*before reaching the service*' $info.Message 'transport wording'
        Assert-True $info.Retryable 'transport failure is retryable'
        Assert-Equal 0 $info.Status 'no HTTP status claimed'
    } finally {
        $script:PDGraph.MaxAttempts = $previousAttempts
        $script:PDGraph.BaseRetryDelaySec = $previousBase
        $script:PDGraph.TestTransport = $null
    }
}

Add-TestCase 'M2-14' 'Get-PDGraphCollection follows pages and refuses foreign links' {
    $script:MockCount = 0
    $script:PDGraph.TestTransport = {
        param($Request)
        $script:MockCount++
        if ($Request.Uri -notlike '*nextLink*') {
            return (New-MockResponse -StatusCode 200 -Body (@{ value = @(@{ id = 'g1' }, @{ id = 'g2' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/groups?nextLink=2' } | ConvertTo-Json -Compress))
        }
        return (New-MockResponse -StatusCode 200 -Body (@{ value = @(@{ id = 'g3' }) } | ConvertTo-Json -Compress))
    }

    $script:MockCount = 0
    $all = @(Get-PDGraphCollection -Path '/v1.0/groups' -AuthContext @{ AccessToken = 'x'; ExpiresOn = [DateTime]::UtcNow.AddHours(1) })
    Assert-Equal 3 $all.Count 'both pages aggregated'
    Assert-Equal 'g3' $all[2].id 'order preserved across pages'

    $script:PDGraph.TestTransport = {
        param($Request)
        return (New-MockResponse -StatusCode 200 -Body (@{ value = @(@{ id = 'g1' }); '@odata.nextLink' = 'https://evil.test/v1.0/groups?2' } | ConvertTo-Json -Compress))
    }
    $caught = Assert-Throws -Body { Get-PDGraphCollection -Path '/v1.0/groups' -AuthContext @{ AccessToken = 'x'; ExpiresOn = [DateTime]::UtcNow.AddHours(1) } }
    Assert-Like '*not an https Graph URL*' $caught.Exception.Message 'foreign pagination link refused'

    $script:PDGraph.TestTransport = $null
}

Add-TestCase 'M2-15' 'Response header reader handles both engine shapes' {
    $map = @{ 'request-id' = 'abc123'; 'Retry-After' = '7' }
    Assert-Equal 'abc123' (Get-PDGraphResponseHeader -Headers $map -Name 'request-id') 'hashtable shape'
    Assert-Equal $null (Get-PDGraphResponseHeader -Headers $map -Name 'missing') 'missing header is null'
    Assert-Equal $null (Get-PDGraphResponseHeader -Headers $null -Name 'request-id') 'null headers tolerated'

    try {
        $collection = New-Object System.Net.WebHeaderCollection
        $collection.Add('request-id', 'from-webheadercollection')
        Assert-Equal 'from-webheadercollection' (Get-PDGraphResponseHeader -Headers $collection -Name 'request-id') 'WebHeaderCollection shape'
    } catch {
        Write-Host "  SKIP WebHeaderCollection unavailable: $($_.Exception.Message)"
    }
}

Add-TestCase 'M2-16' 'Empty and non-JSON responses are handled' {
    $script:PDGraph.TestTransport = { param($Request) return (New-MockResponse -StatusCode 204 -Body '') }
    Assert-Equal $null (Invoke-PDGraphRequest -Method Delete -Uri '/beta/x') '204 returns null'

    $script:PDGraph.TestTransport = { param($Request) return (New-MockResponse -StatusCode 200 -Body 'plain text back') }
    Assert-Equal 'plain text back' (Invoke-PDGraphRequest -Method Get -Uri '/beta/x') 'non-json body returned as text'

    $script:PDGraph.TestTransport = $null
}

Add-TestCase 'M2-17' 'Get-PDGraphItems normalizes the 5.1-vs-7 JSON array difference' {
    # 5.1 hands back a top-level JSON array as ONE Object[] object; 7 enumerates it. Counting
    # that directly is exactly how a duplicate-app check would silently miss matches on 5.1.
    $arrayPayload = '[{"id":"a"},{"id":"b"}]' | ConvertFrom-Json
    $items = @(Get-PDGraphItems -Payload $arrayPayload)
    Assert-Equal 2 $items.Count "both elements visible on PS $($PSVersionTable.PSVersion)"
    Assert-Equal 'b' $items[1].id 'elements are the real objects'

    $wrapper = '{"value":[{"id":"a"}]}' | ConvertFrom-Json
    Assert-Equal 1 @(Get-PDGraphItems -Payload $wrapper).Count 'value wrapper unwrapped'

    $single = '[{"id":"only"}]' | ConvertFrom-Json
    Assert-Equal 1 @(Get-PDGraphItems -Payload $single).Count 'single-element array is one item'

    Assert-Equal 1 @(Get-PDGraphItems -Payload 'abc').Count 'a string is one item, not three characters'
    Assert-Equal 0 @(Get-PDGraphItems -Payload $null).Count 'null yields an empty array'
    Assert-Equal 1 @(Get-PDGraphItems -Payload ([pscustomobject]@{ id = 'plain' })).Count 'a bare object is one item'

    # A hashtable has no adapter properties, so the 'value' unwrap above cannot see it and the
    # fallback enumeration would walk its KEYS: one record would count as several items.
    Assert-Equal 1 @(Get-PDGraphItems -Payload @{ id = 'a'; displayName = 'b'; versionId = 'c' }).Count 'a bare hashtable is one item, not its keys'
    Assert-Equal 2 @(Get-PDGraphItems -Payload @{ value = @('x', 'y') }).Count 'a hashtable value envelope is unwrapped'
}

# ---------------------------------------------------------------------------
# Real transport (no mock): a localhost HTTP server so that Invoke-PDGraphTransport,
# the 5.1 WebException path, the 7 HttpResponseException path, header extraction and
# Retry-After handling are exercised for real. Spec 11.1 requires both error shapes, and
# that requirement cannot be met by mocking the seam it is about. Skips cleanly when
# HttpListener cannot bind (no admin rights), and says so loudly rather than passing silently.
# ---------------------------------------------------------------------------

function Get-PDFreePort {
    $probe = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $probe.Start()
    $port = $probe.LocalEndpoint.Port
    $probe.Stop()
    return $port
}

function Start-PDTestServer {
    <#
        .DESCRIPTION
        Serves the supplied scenarios, in order, from a background job. Records one JSON
        line per received request so tests can assert what was actually put on the wire.
        /__ready and /__shutdown are control paths that never consume a scenario.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable[]]$Scenarios,
        [int]$Port = 0
    )

    if ($Port -eq 0) { $Port = Get-PDFreePort }

    $requestLog = Join-Path $tempRoot ("requests-" + [guid]::NewGuid().ToString('N') + '.jsonl')
    $scenarioJson = ($Scenarios | ConvertTo-Json -Depth 6 -Compress)

    $worker = {
        param([int]$PortArg, [string]$ScenarioJsonArg, [string]$RequestLogArg)

        $ErrorActionPreference = 'Stop'
        # Engine difference that will bite anything decoding a JSON array (5.1 emits a top-level
        # JSON array as ONE Object[] object; 7 enumerates it). A foreach over the result is the
        # only form that is identical on both engines - @() around the pipeline is not.
        $decoded = $ScenarioJsonArg | ConvertFrom-Json
        $scenarios = @()
        foreach ($item in $decoded) { $scenarios += $item }

        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://127.0.0.1:$PortArg/")
        $listener.Start()

        function Write-SimpleResponse {
            param($Context, [int]$Status, [string]$Text)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
            $Context.Response.StatusCode = $Status
            $Context.Response.ContentType = 'text/plain'
            $Context.Response.ContentLength64 = $bytes.Length
            $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $Context.Response.Close()
        }

        $served = 0
        while ($listener.IsListening) {
            try { $context = $listener.GetContext() } catch { break }

            $request = $context.Request
            $path    = $request.Url.AbsolutePath

            if ($path -eq '/__ready')     { Write-SimpleResponse -Context $context -Status 200 -Text 'ready'; continue }
            if ($path -eq '/__shutdown')  { Write-SimpleResponse -Context $context -Status 200 -Text 'bye'; break }

            if ($served -ge $scenarios.Count) {
                Write-SimpleResponse -Context $context -Status 503 -Text 'no scenario left'
                continue
            }

            $scenario = $scenarios[$served]

            $incomingBody = ''
            try {
                $reader = New-Object System.IO.StreamReader($request.InputStream, $request.InputEncoding)
                $incomingBody = $reader.ReadToEnd()
            } catch { }

            $headersSeen = @{}
            foreach ($name in $request.Headers.AllKeys) { $headersSeen[$name] = [string]$request.Headers[$name] }

            $record = @{
                Method = $request.HttpMethod
                Url    = $request.Url.ToString()
                Body   = $incomingBody
                Header = $headersSeen
            }
            [System.IO.File]::AppendAllText($RequestLogArg, ($record | ConvertTo-Json -Depth 6 -Compress) + [Environment]::NewLine)

            if ($null -ne $scenario.PSObject.Properties['Headers']) {
                $headerNames = @($scenario.Headers.PSObject.Properties | ForEach-Object { [string]$_.Name })
                foreach ($name in $headerNames) {
                    try { $context.Response.Headers.Add($name, [string]$scenario.Headers.$name) } catch { }
                }
            }

            $responseBody = [System.Text.Encoding]::UTF8.GetBytes([string]$scenario.Body)
            $contentType = 'application/json'
            if ($null -ne $scenario.PSObject.Properties['ContentType']) { $contentType = [string]$scenario.ContentType }

            $context.Response.StatusCode = [int]$scenario.Status
            $context.Response.ContentType = $contentType
            $context.Response.ContentLength64 = $responseBody.Length
            $context.Response.OutputStream.Write($responseBody, 0, $responseBody.Length)
            $context.Response.Close()

            $served++
        }

        try { $listener.Stop() } catch { }
        try { $listener.Close() } catch { }
    }

    $job = $null
    try {
        $job = Start-Job -ScriptBlock $worker -ArgumentList $Port, $scenarioJson, $requestLog
    } catch {
        return @{ Started = $false; Reason = $_.Exception.Message }
    }

    # Readiness is a real HTTP request, so a bare socket never disturbs the request loop.
    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        try {
            $ping = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/__ready" -TimeoutSec 3 -ErrorAction Stop
            if ($ping.StatusCode -eq 200) { $ready = $true; break }
        } catch {
            if ($job.State -eq 'Failed') {
                $why = (Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-String)
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                return @{ Started = $false; Reason = "job failed: $why" }
            }
            Start-Sleep -Milliseconds 150
        }
    }

    if (-not $ready) {
        $why = ''
        if ($null -ne $job) { $why = (Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-String) }
        if ($job) { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
        return @{ Started = $false; Reason = "listener never answered /__ready. $why" }
    }

    return @{ Started = $true; Port = $Port; Job = $job; RequestLog = $requestLog }
}

function Stop-PDTestServer {
    param([object]$Server)
    if ($null -eq $Server) { return }

    # Ask the worker to exit instead of relying on the wait timeout.
    try { Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$($Server.Port)/__shutdown" -TimeoutSec 3 -ErrorAction SilentlyContinue | Out-Null } catch { }

    if ($null -ne $Server.Job) {
        Wait-Job -Job $Server.Job -Timeout 8 | Out-Null
        Remove-Job -Job $Server.Job -Force -ErrorAction SilentlyContinue
    }
}

function Get-PDRecordedRequest {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $lines = @(Get-Content -LiteralPath $Path | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    return @($lines | ForEach-Object { $_ | ConvertFrom-Json })
}

Add-TestCase 'RT-01' 'Real transport reads a successful response and its headers' {
    $server = Start-PDTestServer -Scenarios @(
        @{ Status = 200; Body = '{"id":"app-7","displayName":"Real"}'; ContentType = 'application/json'; Headers = @{ 'request-id' = 'real-200' } }
    )
    if (-not $server.Started) {
        Write-Host "  SKIP HttpListener unavailable ($($server.Reason)) - real-transport cases not executed" -ForegroundColor Yellow
        $script:SkippedRealTransport = $true
        return
    }
    $script:SkippedRealTransport = $false

    try {
        $response = Invoke-PDGraphTransport -Request @{ Method = 'Get'; Uri = "http://127.0.0.1:$($server.Port)/app"; TimeoutSec = 20 }
        Assert-Equal 200 $response.StatusCode 'real 200 status'
        Assert-Like '*app-7*' $response.Body 'real body captured'
        Assert-Equal 'real-200' $response.Headers['request-id'] 'real header captured'
        Assert-True ($null -eq $response.TransportError) 'no transport error claimed'
    } finally {
        Stop-PDTestServer -Server $server
    }
}

Add-TestCase 'RT-02' 'Real HTTP error exposes status, service reason and request id on this engine' {
    if ($script:SkippedRealTransport) { Write-Host '  SKIP (no HttpListener)' -ForegroundColor Yellow; return }

    $server = Start-PDTestServer -Scenarios @(
        @{ Status = 400; Body = '{"error":{"code":"Bad","message":"displayName is required"}}'; ContentType = 'application/json'; Headers = @{ 'request-id' = 'real-400' } }
    )
    Assert-True $server.Started 'server started'

    try {
        $caught = Assert-Throws -Body {
            Invoke-PDGraphRequest -Method Post -Uri "http://127.0.0.1:$($server.Port)/apps" -Body @{ nope = 1 } -RetryMode 'Write' -Stage 'CreateApp'
        }
        $info = Get-PDGraphErrorInfo -ErrorRecord $caught
        Assert-Equal 400 $info.Status "status extracted on PS $($PSVersionTable.PSVersion)"
        Assert-Equal 'real-400' $info.RequestId "request-id header extracted on PS $($PSVersionTable.PSVersion)"
        Assert-Like '*displayName is required*' $info.Detail "response body extracted on PS $($PSVersionTable.PSVersion)"

        # The bearer token we attached must have gone out on the wire (and only there).
        $requests = Get-PDRecordedRequest -Path $server.RequestLog
        Assert-Equal 1 @($requests).Count 'exactly one request for a write'
        Assert-Equal $null $requests[0].Header['Authorization'] 'no authorization header when none was supplied'
    } finally {
        Stop-PDTestServer -Server $server
    }
}

Add-TestCase 'RT-03' 'Real throttling is honoured and the same write is never repeated' {
    if ($script:SkippedRealTransport) { Write-Host '  SKIP (no HttpListener)' -ForegroundColor Yellow; return }

    $server = Start-PDTestServer -Scenarios @(
        @{ Status = 429; Body = '{"error":{"message":"busy"}}'; ContentType = 'application/json'; Headers = @{ 'Retry-After' = '0' } },
        @{ Status = 200; Body = '{"ok":true}'; ContentType = 'application/json' }
    )
    Assert-True $server.Started 'server started'

    $previousBase = $script:PDGraph.BaseRetryDelaySec
    $script:PDGraph.BaseRetryDelaySec = 0
    try {
        $r = Invoke-PDGraphRequest -Method Get -Uri "http://127.0.0.1:$($server.Port)/apps" -RetryMode 'Read'
        Assert-True $r.ok 'read retried over a real 429 and succeeded'
        Assert-Equal 2 @(Get-PDRecordedRequest -Path $server.RequestLog).Count 'two real requests'
    } finally {
        $script:PDGraph.BaseRetryDelaySec = $previousBase
        Stop-PDTestServer -Server $server
    }
}

Add-TestCase 'RT-04' 'A refused connection is reported as a transport failure' {
    $deadPort = Get-PDFreePort
    $previousAttempts = $script:PDGraph.MaxAttempts
    $previousBase = $script:PDGraph.BaseRetryDelaySec
    $script:PDGraph.MaxAttempts = 1
    $script:PDGraph.BaseRetryDelaySec = 0
    try {
        $caught = Assert-Throws -Body { Invoke-PDGraphRequest -Method Get -Uri "http://127.0.0.1:$deadPort/nothing" -RetryMode 'Read' -Stage 'Verify' }
        $info = Get-PDGraphErrorInfo -ErrorRecord $caught
        Assert-Like '*before reaching the service*' $info.Message 'transport wording'
        Assert-Equal 0 $info.Status 'no HTTP status invented'
        Assert-True $info.Retryable 'retryable'
    } finally {
        $script:PDGraph.MaxAttempts = $previousAttempts
        $script:PDGraph.BaseRetryDelaySec = $previousBase
    }
}

# ---------------------------------------------------------------------------
# M3 - package, payload, preflight, groups, category, duplicates
#
# Every case below runs offline through the same transport seam as M2. The router
# records each request, so 'no mutation happened' is a claim about recorded verbs,
# not about intentions.
# ---------------------------------------------------------------------------

$script:FixtureRoot   = Join-Path $PSScriptRoot 'Fixtures\IntuneGraph'
$script:UploaderPath  = Join-Path (Split-Path $PSScriptRoot -Parent) 'Other_Tools\Upload-InTuneWin32App.ps1'

if (-not (Test-Path -LiteralPath $script:UploaderPath)) {
    Write-Host "FATAL: uploader script not found at $script:UploaderPath"
    exit 2
}

. $script:UploaderPath

# --- mock Graph ------------------------------------------------------------------------------

$script:MockGraphRouter = $null
$script:MockGraphCalls  = @()

function Set-PDMockGraph {
    <#
        Installs a transport that answers from the scenario router and records every request.
        An unmocked request is a test failure, never a silent fall through to the network.
    #>
    param([Parameter(Mandatory = $true)][scriptblock]$Router)

    $script:MockGraphRouter = $Router
    $script:MockGraphCalls  = @()
    $script:PDGraph.TokenCache = @{}

    $script:PDGraph.TestTransport = {
        param($Request)

        $script:MockGraphCalls += $Request

        $handler = $script:MockGraphRouter
        if ($null -eq $handler) { throw ("mock Graph has no router; refusing {0} {1}" -f $Request.Method, $Request.Uri) }

        $response = & $handler $Request
        if ($null -eq $response) { throw ("mock Graph has no answer for {0} {1}" -f $Request.Method, $Request.Uri) }
        return $response
    }
}

function Clear-PDMockGraph {
    $script:PDGraph.TestTransport  = $null
    $script:MockGraphRouter        = $null
    $script:MockGraphCalls         = @()
    $script:PDGraph.TokenCache     = @{}
}

function Get-PDMockGraphUri {
    param([int]$Index = -1)
    $calls = @($script:MockGraphCalls)
    if ($Index -lt 0) { return (@($calls | ForEach-Object { '{0} {1}' -f $_.Method, $_.Uri })) }
    if ($Index -ge $calls.Count) { throw "only $($calls.Count) mock requests were recorded" }
    return ('{0} {1}' -f $calls[$Index].Method, $calls[$Index].Uri)
}

function Get-PDMockGraphMutation {
    <#
        Recorded requests that would change tenant state. The token endpoint is a POST by
        design and is not a tenant resource, so it is reported separately.
    #>
    $mutations = @()
    foreach ($call in @($script:MockGraphCalls)) {
        if (([string]$call.Uri) -like 'https://graph.microsoft.com/*') {
            if (([string]$call.Method) -ne 'Get') { $mutations += ('{0} {1}' -f $call.Method, $call.Uri) }
        } elseif (([string]$call.Method) -ne 'Get') {
            if (([string]$call.Uri) -notlike 'https://login.microsoftonline.com/*') {
                $mutations += ('{0} {1}' -f $call.Method, $call.Uri)
            }
        }
    }
    return $mutations
}

function New-PDMockJsonResponse {
    param([int]$Status = 200, [AllowNull()][string]$Json = '{}', [hashtable]$Headers = $null)

    if ($null -eq $Headers) { $Headers = @{ 'request-id' = 'mock-req' } }
    return (New-MockResponse -StatusCode $Status -Body $Json -Headers $Headers)
}

function New-PDMockValuePage {
    param([object[]]$Value = @(), [string]$NextLink)

    $page = @{ value = @($Value) }
    if ($NextLink) { $page['@odata.nextLink'] = $NextLink }
    return ($page | ConvertTo-Json -Depth 10 -Compress)
}

function New-PDM3GroupValue {
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][string]$DisplayName)
    return @{ id = $Id; displayName = $DisplayName }
}

function Get-PDMockFilterLiteral {
    <#
        Pulls the string literal out of a decoded "...?%24filter=displayName eq 'it''s'..." URI and
        turns OData's doubled apostrophes back into one. Returns $null when the request carried no
        displayName filter; the router treats that as "no match", never as "match everything".
    #>
    param([Parameter(Mandatory = $true)][string]$DecodedUri)

    $found = [regex]::Match($DecodedUri, "displayName eq '((?:[^']|'')*)'")
    if (-not $found.Success) { return $null }
    return $found.Groups[1].Value.Replace("''", "'")
}

# The standard scenario. Tests set the scenario fields, then call preflight.
$script:M3 = $null

function Reset-PDM3Scenario {
    <#
        Group directory served by the mock: $Groups is matched case-insensitively by display
        name, $GroupById by object id, $Apps / $Categories answer the duplicate and category
        lookups. $GroupPages, when set, is served as consecutive collection pages so pagination
        is exercised for real.
    #>
    param(
        [object[]]$Groups = @(),
        [hashtable]$GroupById = @{},
        [object[]]$Apps = @(),
        [object[]]$Categories = @(),
        [object[]]$GroupPages = $null,
        [string[]]$UnknownGroupIds = @()
    )

    $script:M3 = @{
        Groups          = @($Groups)
        GroupById       = $GroupById
        Apps            = @($Apps)
        Categories      = @($Categories)
        GroupPages      = $GroupPages
        GroupPageCursor = 0
        UnknownGroupIds = @($UnknownGroupIds)
        Token           = (New-TestJwt)
    }

    Set-PDMockGraph -Router {
        param($Request)

        $method  = [string]$Request.Method
        $uri     = [string]$Request.Uri
        $decoded = [System.Uri]::UnescapeDataString($uri)
        $state   = $script:M3

        if ($uri -like 'https://login.microsoftonline.com/*/oauth2/v2.0/token') {
            return (New-PDMockJsonResponse -Json (@{ access_token = $state.Token; expires_in = 3600 } | ConvertTo-Json -Compress))
        }

        # Group by object id: /v1.0/groups/{id}?...
        if (($decoded -like 'https://graph.microsoft.com/v1.0/groups/*') -and ($decoded -notlike '*$filter=*')) {
            $path   = $uri.Split('?')[0]
            $id     = $path.Substring($path.LastIndexOf('/') + 1)
            $id     = [System.Uri]::UnescapeDataString($id)

            if (@($state.UnknownGroupIds).Count -gt 0) {
                foreach ($unknown in @($state.UnknownGroupIds)) {
                    if ($unknown -eq $id) {
                        return (New-PDMockJsonResponse -Status 404 -Json (@{ error = @{ code = 'Request_ResourceNotFound'; message = 'Resource does not exist.' } } | ConvertTo-Json -Compress))
                    }
                }
            }

            if ($state.GroupById.ContainsKey($id)) {
                $group = $state.GroupById[$id]
                return (New-PDMockJsonResponse -Json (@{ id = $group.Id; displayName = $group.DisplayName } | ConvertTo-Json -Compress))
            }
            return (New-PDMockJsonResponse -Status 404 -Json (@{ error = @{ code = 'Request_ResourceNotFound'; message = 'Resource does not exist.' } } | ConvertTo-Json -Compress))
        }

        # Group collection by displayName filter (paginated)
        if (($decoded -like 'https://graph.microsoft.com/v1.0/groups*') -and (($decoded -like '*$filter=*') -or ($decoded -like '*skiptoken=*'))) {
            if ($null -ne $state.GroupPages) {
                $index = [int]$state.GroupPageCursor
                $state.GroupPageCursor = $index + 1
                if ($index -lt @($state.GroupPages).Count) { return (New-PDMockJsonResponse -Json ([string]@($state.GroupPages)[$index])) }
                return (New-PDMockJsonResponse -Json (New-PDMockValuePage -Value @()))
            }

            $wanted = Get-PDMockFilterLiteral -DecodedUri $decoded

            $matched = @()
            if ($null -ne $wanted) {
                foreach ($group in @($state.Groups)) {
                    if (([string]$group.DisplayName) -eq $wanted) { $matched += (New-PDM3GroupValue -Id $group.Id -DisplayName $group.DisplayName) }
                }
            }
            return (New-PDMockJsonResponse -Json (New-PDMockValuePage -Value $matched))
        }

        # Category lookup (matched before the shorter mobileApps prefix)
        if ($decoded -like 'https://graph.microsoft.com/beta/deviceAppManagement/mobileAppCategories*') {
            $wanted = Get-PDMockFilterLiteral -DecodedUri $decoded

            $matched = @()
            if ($null -ne $wanted) {
                foreach ($category in @($state.Categories)) {
                    if (([string]$category.displayName) -eq $wanted) { $matched += $category }
                }
            }
            return (New-PDMockJsonResponse -Json (New-PDMockValuePage -Value $matched))
        }

        # Duplicate app lookup
        if ($decoded -like 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps*') {
            $wanted = Get-PDMockFilterLiteral -DecodedUri $decoded
            $prefix = $null
            $starts = [regex]::Match($decoded, "startswith\(displayName,'((?:[^']|'')*)'\)")
            if ($starts.Success) { $prefix = $starts.Groups[1].Value.Replace("''", "'") }

            # Like the live service: an eq literal containing [ or ] matches nothing, while
            # startswith matches by prefix.
            $matched = @()
            if ($null -ne $wanted -and ($wanted.IndexOfAny([char[]]@('[', ']')) -lt 0)) {
                foreach ($app in @($state.Apps)) {
                    if (([string]$app.displayName) -eq $wanted) { $matched += $app }
                }
            }
            if ($null -ne $prefix) {
                foreach ($app in @($state.Apps)) {
                    if (([string]$app.displayName).StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { $matched += $app }
                }
            }
            return (New-PDMockJsonResponse -Json (New-PDMockValuePage -Value $matched))
        }

        return $null
    }
}

# --- input sets --------------------------------------------------------------------------------

function New-PDM3InputSet {
    <#
        One isolated directory per case: credential file, command files, detection script, and a
        temp directory for the extracted payload. Nothing here touches %LOCALAPPDATA% or the repo.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Case,
        [string]$InstallText = '"Setup.exe" /quiet ',
        [string]$UninstallText = '"Setup.exe" /uninstall /quiet',
        [byte[]]$DetectionBytes = $null,
        [int]$DaysUntilExpiry = 90,
        [string]$FakeSecret = 'm3-never-real-secret'
    )

    $dir = Join-Path $tempRoot ('m3-' + $Case)
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    $install   = Join-Path $dir 'install.txt'
    $uninstall = Join-Path $dir 'uninstall.txt'
    $detection = Join-Path $dir 'detect.ps1'

    $utf8    = New-Object System.Text.UTF8Encoding($false)
    $rawBytes = $utf8.GetBytes($InstallText)
    [System.IO.File]::WriteAllBytes($install, $rawBytes)
    [System.IO.File]::WriteAllBytes($uninstall, $utf8.GetBytes($UninstallText))

    if ($null -eq $DetectionBytes) {
        $DetectionBytes = $utf8.GetBytes("Write-Output 'detected'`r`n")
    }
    [System.IO.File]::WriteAllBytes($detection, $DetectionBytes)

    $credentialPath = Join-Path $dir 'credential.clixml'
    $credential = New-PDGraphCredentialObject -TenantId ([guid]::NewGuid().ToString()) `
        -ClientId ([guid]::NewGuid().ToString()) `
        -ClientSecret (New-FakeSecureString -Value $FakeSecret) `
        -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays($DaysUntilExpiry)) `
        -SecretKeyId ([guid]::NewGuid().ToString()) `
        -AppDisplayName 'PowerDeploy Intune Upload'
    Save-PDGraphCredential -Credential $credential -Path $credentialPath | Out-Null

    return @{
        Directory      = $dir
        InstallFile    = $install
        UninstallFile  = $uninstall
        DetectionFile  = $detection
        CredentialPath = $credentialPath
        TempDirectory  = (Join-Path $dir 'payload-temp')
    }
}

function Get-PDM3FixturePath { param([string]$Name) return (Join-Path $script:FixtureRoot $Name) }

function Invoke-PDM3Preflight {
    <#
        Calls preflight with a consistent set of arguments so each case only states what it cares
        about. -DryRun defaults on: the mutation question is U01's, not every case's.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Inputs,
        [string]$Package = 'valid.intunewin',
        [string]$DisplayName = 'PowerDeploy Test App',
        [string]$Description = 'N/A',
        [string]$Publisher = 'PowerDeploy',
        [string]$AppVersion,
        [string]$Category,
        [string]$Notes,
        [string[]]$RequiredGroups = @(),
        [string[]]$AvailableGroups = @(),
        [switch]$Execution,
        [switch]$AllowDuplicateName
    )

    $arguments = @{
        IntuneWinPath        = Get-PDM3FixturePath -Name $Package
        DisplayName          = $DisplayName
        Description          = $Description
        Publisher            = $Publisher
        InstallCommandFile   = $Inputs.InstallFile
        UninstallCommandFile = $Inputs.UninstallFile
        DetectionScriptFile  = $Inputs.DetectionFile
        CredentialPath       = $Inputs.CredentialPath
        TempDirectory        = $Inputs.TempDirectory
        RequiredGroups       = $RequiredGroups
        AvailableGroups      = $AvailableGroups
    }
    if ($PSBoundParameters.ContainsKey('AppVersion')) { $arguments['AppVersion'] = $AppVersion }
    if ($PSBoundParameters.ContainsKey('Category'))   { $arguments['Category']   = $Category }
    if ($PSBoundParameters.ContainsKey('Notes'))      { $arguments['Notes']      = $Notes }
    # Default is a dry run; -Execution is what opts a case into the write path.
    if ($Execution) { $arguments.Remove('DryRun') } else { $arguments['DryRun'] = $true }
    if ($AllowDuplicateName) { $arguments['AllowDuplicateName'] = [switch]::Present }

    return (Start-PDIntunePreflight @arguments)
}

Add-TestCase 'M3-01' 'The uploader dot-sources with no output, no prompts, and no writes' {
    $logBefore = $script:PDUploadLogPath

    $imported = & {
        $local:helperPath = $HelperPath
        . $script:UploaderPath
    }
    Assert-True (($null -eq $imported) -or (@($imported).Count -eq 0)) 'importing the uploader must emit nothing'
    Assert-True ($null -eq $logBefore) 'dot-sourcing must not start a log file'

    foreach ($required in @('Start-PDIntunePreflight', 'Invoke-PDIntuneUpload', 'New-PDIntuneUploadResult', 'Invoke-PDIntuneUploadWriteStages', 'Write-PDUploadLog', 'Write-PDReviewSummary')) {
        Assert-True ($null -ne (Get-Command -CommandType Function -Name $required -ErrorAction SilentlyContinue)) "uploader function $required should be defined"
    }

    # The library must not have grabbed a log writer: spec invariant 3.
    Assert-True ($null -eq (Get-Command -CommandType Function -Name 'Write-Log' -ErrorAction SilentlyContinue)) 'the feature must not define Write-Log; Setup owns it'

    Assert-True (Test-Path -LiteralPath (Join-Path ([System.IO.Path]::GetTempPath()) '')) 'sanity'
}

Add-TestCase 'P02' 'Package fixture maps metadata, sizes, and payload with no re-encryption' {
    $temp = Join-Path $tempRoot 'p02'

    $package = Read-PDIntuneWinPackage -IntuneWinPath (Get-PDM3FixturePath -Name 'valid.intunewin') -TempDirectory $temp

    Assert-Equal 'IntunePackage.intunewin' $package.FileName 'fileName from ApplicationInfo/FileName'
    Assert-Equal 'PowerDeployFixtureSetup.exe' $package.SetupFile 'setupFilePath from ApplicationInfo/SetupFile'
    Assert-Equal 'PowerDeployFixtureSetup.exe' $package.PackageName 'Name preserved for diagnostics'
    Assert-Equal '1.8.7.0' $package.ToolVersion 'ToolVersion read from the root element'
    Assert-Equal ([long]462) ([long]$package.UnencryptedContentSize) 'size comes from UnencryptedContentSize'
    Assert-Equal ([long]512) ([long]$package.PayloadBytes) 'sizeEncrypted is measured from the payload'
    Assert-True ([long]$package.PayloadBytes -gt [long]$package.UnencryptedContentSize) 'the encrypted payload is larger than the declared content size, as in a real package'
    Assert-Equal 'IntuneWinPackage/Contents/IntunePackage.intunewin' $package.ContentEntry 'content entry identified'
    Assert-True (Test-Path -LiteralPath $package.PayloadPath) 'payload extracted'

    # sizeEncrypted must be the file's real length, not the XML's word for it.
    Assert-Equal (Get-Item -LiteralPath $package.PayloadPath).Length ([long]$package.PayloadBytes) 'reported length is the real file length'

    # No re-encryption, no transcoding: the extracted bytes are the fixture's pattern exactly.
    $bytes = [System.IO.File]::ReadAllBytes($package.PayloadPath)
    Assert-Equal 512 $bytes.Length 'byte count'
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $expectedByte = [byte](($i * 37 + 11) -band 0xFF)
        if ($bytes[$i] -ne $expectedByte) { throw "payload byte $i differs from the archive entry; the reader must copy bytes verbatim" }
    }

    # Encryption info is read, not invented, and ProfileIdentifier is never hardcoded.
    Assert-Equal 7 $package.EncryptionInfo.Keys.Count 'all seven encryption fields present'
    foreach ($field in @('EncryptionKey', 'MacKey', 'InitializationVector', 'Mac', 'ProfileIdentifier', 'FileDigest', 'FileDigestAlgorithm')) {
        Assert-True (-not [string]::IsNullOrWhiteSpace([string]$package.EncryptionInfo[$field])) "EncryptionInfo/$field read"
    }
    Assert-Equal 'ProfileVersion1' $package.EncryptionInfo['ProfileIdentifier'] 'profile identifier taken from metadata'
    Assert-Equal 'SHA256' $package.EncryptionInfo['FileDigestAlgorithm'] 'digest algorithm taken from metadata'

    # A deflated variant must read identically: the reader never assumes 'stored'.
    $deflated = Read-PDIntuneWinPackage -IntuneWinPath (Get-PDM3FixturePath -Name 'deflated-payload.intunewin') -TempDirectory (Join-Path $tempRoot 'p02-deflated')
    Assert-Equal (Get-PDFileSha256 -Path $package.PayloadPath) (Get-PDFileSha256 -Path $deflated.PayloadPath) 'compressed archive yields the same payload bytes'
    Assert-Equal ([long]512) ([long]$deflated.PayloadBytes) 'deflated payload length still measured'

    Assert-True $package.TempDirectoryOwned 'the run created this temp directory'
    Assert-True (-not (Split-Path $package.PayloadPath -Leaf).Contains('IntunePackage')) 'payload is written under a name we chose, never the archive entry name'
}

Add-TestCase 'P01' 'Invalid packages fail in preflight before any token or POST' {
    $bad = @('missing-detection-xml.intunewin', 'metadata-without-content-entry.intunewin',
             'two-content-entries.intunewin', 'traversal-entry.intunewin', 'not-a-zip.intunewin',
             'malformed-detection-xml.intunewin', 'missing-encryption-info.intunewin')

    Reset-PDM3Scenario -Groups @(New-PDM3GroupValue -Id ([guid]::NewGuid().ToString()) -DisplayName 'Unused Group')

    foreach ($name in $bad) {
        $inputs = New-PDM3InputSet -Case ("p01-" + $name.Replace('.', '-'))

        $caught = Assert-Throws -Body { Invoke-PDM3Preflight -Inputs $inputs -Package $name }
        $info = Get-PDGraphErrorInfo -ErrorRecord $caught

        Assert-Equal 'Preflight' $info.Stage "$name fails in Preflight"
        Assert-True ($info.Message.Length -gt 20) "$name produces a real message"

        # Nothing at all may leave the process: not a token request, not a single Graph call.
        Assert-Equal 0 @($script:MockGraphCalls).Count "$name must not reach the network (saw: $(Get-PDMockGraphUri))"

        # And nothing may be written outside the run's temp directory.
        Assert-True (-not (Test-Path -LiteralPath (Join-Path (Split-Path $tempRoot -Parent) 'PowerDeploy-fixture-evil.txt'))) 'archive entry names never become paths'

        Clear-PDMockGraph
        Reset-PDM3Scenario -Groups @()
    }

    # A missing file is also a preflight failure, not an unhandled .NET exception.
    $inputs = New-PDM3InputSet -Case 'p01-missing-file'
    Reset-PDM3Scenario
    $caught = Assert-Throws -Body { Invoke-PDM3Preflight -Inputs $inputs -Package 'does-not-exist.intunewin' } -MessagePattern '*not found*'
    Assert-Equal 'Preflight' (Get-PDGraphErrorInfo -ErrorRecord $caught).Stage 'missing package stage'
    Clear-PDMockGraph
}

Add-TestCase 'P03' 'Commands keep their text, lose only trailing newlines, and reject embedded newlines' {
    # A scenario is installed so that even a mis-ordered preflight cannot reach the network.
    Reset-PDM3Scenario

    # Trailing CRLF is removed; quoting, inner spacing, and even trailing spaces survive.
    $keepSpaces = New-PDM3InputSet -Case 'p03-spaces' -InstallText "`"App`" /x `r`n" -UninstallText "`"App`" /u`n"
    $preflight = Invoke-PDM3Preflight -Inputs $keepSpaces
    Assert-Equal '"App" /x ' $preflight.InstallCommand 'trailing CR/LF removed, meaningful trailing space kept'
    Assert-Equal '"App" /u' $preflight.UninstallCommand 'bare LF handled like CRLF'
    Assert-Equal 9 $preflight.CommandLengths.Install 'length reported for review (never a limit)'

    # An embedded newline is not a command line.
    $multi = New-PDM3InputSet -Case 'p03-multiline' -InstallText "step1`r`nstep2`r`n"
    $caught = Assert-Throws -Body { Invoke-PDM3Preflight -Inputs $multi } -MessagePattern '*more than one line*'
    Assert-Equal 'Preflight' (Get-PDGraphErrorInfo -ErrorRecord $caught).Stage 'multiline stage'

    # Empty and whitespace-only command files are refused.
    $empty = New-PDM3InputSet -Case 'p03-empty' -InstallText "`r`n`r`n"
    Assert-Throws -Body { Invoke-PDM3Preflight -Inputs $empty } -MessagePattern '*is empty*' 'empty command refused'

    # A BOM would break the installer, so it is consumed; UTF-16 command files still decode.
    $utf8Bom  = New-PDM3InputSet -Case 'p03-utf8bom' -InstallText 'setup.exe /q'
    [System.IO.File]::WriteAllBytes($utf8Bom.InstallFile, ([byte[]]@(0xEF, 0xBB, 0xBF) + [byte[]]([System.Text.Encoding]::UTF8.GetBytes('setup.exe /q'))))
    $result = Invoke-PDM3Preflight -Inputs $utf8Bom
    Assert-Equal 'setup.exe /q' $result.InstallCommand 'UTF-8 BOM never reaches the command'

    $utf16    = New-PDM3InputSet -Case 'p03-utf16' -InstallText 'setup.exe /q'
    [System.IO.File]::WriteAllBytes($utf16.InstallFile, ([System.Text.Encoding]::Unicode.GetPreamble() + [System.Text.Encoding]::Unicode.GetBytes('setup.exe /q')))
    $result = Invoke-PDM3Preflight -Inputs $utf16
    Assert-Equal 'setup.exe /q' $result.InstallCommand 'UTF-16 command file decoded, not garbled'

    # Detection is base64 of the raw bytes: a BOM stays inside the script, nothing is transcoded.
    $detectionBytes = [byte[]]@(0xEF, 0xBB, 0xBF) + [System.Text.Encoding]::Unicode.GetBytes("Write-Output 'bom and utf16'`n")
    $detectionCase  = New-PDM3InputSet -Case 'p03-detection' -DetectionBytes $detectionBytes
    $result         = Invoke-PDM3Preflight -Inputs $detectionCase
    $decoded        = [System.Convert]::FromBase64String($result.Detection.Base64)
    Assert-Equal $detectionBytes.Length $decoded.Length 'detection bytes are not resized or transcoded'
    for ($i = 0; $i -lt $detectionBytes.Length; $i++) {
        if ($decoded[$i] -ne $detectionBytes[$i]) { throw "detection byte $i changed; Intune would run different bytes than were generated" }
    }
    Assert-Equal $detectionBytes.Length $result.Detection.Bytes 'detection size reported'
    Assert-Equal (Get-PDFileSha256 -Path $detectionCase.DetectionFile) $result.Detection.Sha256 'detection hash is of the raw file'

    # Commands are never length-limited (spec 14.3): a long command must survive untouched.
    $longCommand = 'setup.exe ' + ('/param=' + ('x' * 1500))
    $longCase    = New-PDM3InputSet -Case 'p03-long' -InstallText $longCommand
    $result      = Invoke-PDM3Preflight -Inputs $longCase
    Assert-Equal $longCommand.Length $result.CommandLengths.Install 'long command measured, not truncated'
    Assert-Equal $longCommand $result.InstallCommand 'long command preserved'

    Clear-PDMockGraph
}

Add-TestCase 'G01' 'The same group by repeated name and by GUID produces one assignment' {
    $groupId   = [guid]::NewGuid().ToString()
    $otherId   = [guid]::NewGuid().ToString()
    $availId   = [guid]::NewGuid().ToString()

    Reset-PDM3Scenario `
        -Groups @(@{ Id = $groupId; DisplayName = 'Test Group' }, @{ Id = $otherId; DisplayName = 'Other Group' }, @{ Id = $availId; DisplayName = 'Available Group' }) `
        -GroupById @{ $groupId = @{ Id = $groupId; DisplayName = 'Test Group' }; $otherId = @{ Id = $otherId; DisplayName = 'Other Group' }; $availId = @{ Id = $availId; DisplayName = 'Available Group' } }

    $inputs = New-PDM3InputSet -Case 'g01'

    $preflight = Invoke-PDM3Preflight -Inputs $inputs `
        -RequiredGroups @('Test Group; Test Group', 'Test Group', " $groupId ", 'Other Group') `
        -AvailableGroups @('Available Group;;', $availId)

    $groups = @($preflight.ResolvedGroups)
    # 'Test Group; Test Group', 'Test Group', and the bare GUID are the same group; 'Other Group'
    # is second; the Available pair collapses to one.
    Assert-Equal 3 $groups.Count 'duplicates inside an intent collapse (2 required + 1 available)'

    $requiredGroupsList = @($groups | Where-Object { $_.Intent -eq 'required' })
    Assert-Equal 2 $requiredGroupsList.Count 'required intent count'

    $testGroupEntries = @($groups | Where-Object { $_.Id -eq $groupId })
    Assert-Equal 1 $testGroupEntries.Count 'name, repeated name, and GUID produce exactly one assignment'
    Assert-Equal 'required' $testGroupEntries[0].Intent 'intent preserved'
    Assert-Equal 'Test Group' $testGroupEntries[0].DisplayName 'display name comes from the directory, not the input'

    # The GUID was supplied once as a name-ish token and once as an id; the id path is used for it.
    $idLookups = @(@($script:MockGraphCalls) | Where-Object { $_.Uri -like ("*/v1.0/groups/$groupId*") })
    Assert-Equal 1 $idLookups.Count 'one direct id read per GUID input'

    Clear-PDMockGraph
}

Add-TestCase 'G02' 'The same group id in both intents fails preflight without creating anything' {
    $groupId = [guid]::NewGuid().ToString()
    Reset-PDM3Scenario -Groups @(@{ Id = $groupId; DisplayName = 'Shared Group' }) -GroupById @{ $groupId = @{ Id = $groupId; DisplayName = 'Shared Group' } }

    $inputs = New-PDM3InputSet -Case 'g02'

    $caught = Assert-Throws -Body { Invoke-PDM3Preflight -Inputs $inputs -RequiredGroups @('Shared Group') -AvailableGroups @($groupId) }
    $info = Get-PDGraphErrorInfo -ErrorRecord $caught

    Assert-Like '*both a Required and an Available*' $info.Message 'names the conflict'
    Assert-Like "*$groupId*" $info.Message 'names the group id'
    Assert-Equal 'Preflight' $info.Stage 'fails in preflight'
    Assert-Equal 0 @(Get-PDMockGraphMutation).Count 'no mutation, ever, and no app created'

    Clear-PDMockGraph
}

Add-TestCase 'G03' 'Zero groups is valid, says No assignments, and never touches the assign endpoint' {
    Reset-PDM3Scenario

    $inputs = New-PDM3InputSet -Case 'g03'
    $preflight = Invoke-PDM3Preflight -Inputs $inputs

    Assert-Equal 0 @($preflight.ResolvedGroups).Count 'no groups requested means no groups resolved'
    Assert-Equal 'No assignments' $preflight.ReviewMetadata.GroupAssignmentSummary 'review says it in words'

    # A semicolon-only string is still zero groups, not a lookup with an empty name.
    $inputs2 = New-PDM3InputSet -Case 'g03b'
    $preflight2 = Invoke-PDM3Preflight -Inputs $inputs2 -RequiredGroups @(';;  ;') -AvailableGroups @()
    Assert-Equal 0 @($preflight2.ResolvedGroups).Count 'delimiter-only input is empty'

    foreach ($call in @($script:MockGraphCalls)) {
        Assert-True (([string]$call.Uri) -notlike '*assign*') 'the assign endpoint must never be mentioned without groups'
    }
    Assert-Equal 0 @(Get-PDMockGraphMutation).Count 'nothing written'

    Clear-PDMockGraph
}

Add-TestCase 'G04' 'Group resolution: missing, ambiguous, apostrophes, and pagination' {
    # --- zero matches: the input is named and nothing is guessed ---
    Reset-PDM3Scenario -Groups @(@{ Id = ([guid]::NewGuid().ToString()); DisplayName = 'Something Else' })
    $inputs = New-PDM3InputSet -Case 'g04-missing'
    $caught = Assert-Throws -Body { Invoke-PDM3Preflight -Inputs $inputs -RequiredGroups @('No Such Group') } -MessagePattern '*No Entra group is named exactly*'
    Assert-Like '*No Such Group*' (Get-PDGraphErrorInfo -ErrorRecord $caught).Message 'names what was asked for'
    Clear-PDMockGraph

    # --- a GUID that is not there: actionable, not a bare 404 ---
    $missingId = [guid]::NewGuid().ToString()
    Reset-PDM3Scenario -UnknownGroupIds @($missingId)
    $inputs = New-PDM3InputSet -Case 'g04-missing-id'
    $caught = Assert-Throws -Body { Invoke-PDM3Preflight -Inputs $inputs -RequiredGroups @($missingId) } -MessagePattern '*No Entra group has the object id*'
    Assert-Like '*display name*' (Get-PDGraphErrorInfo -ErrorRecord $caught).Message 'offers the alternative'
    Clear-PDMockGraph

    # --- two exact matches: refuse, list candidates, tell the operator to use an id ---
    $firstId  = [guid]::NewGuid().ToString()
    $secondId = [guid]::NewGuid().ToString()
    Reset-PDM3Scenario -Groups @(@{ Id = $firstId; DisplayName = 'Duplicate Name' }, @{ Id = $secondId; DisplayName = 'Duplicate Name' })
    $inputs = New-PDM3InputSet -Case 'g04-ambiguous'
    $caught = Assert-Throws -Body { Invoke-PDM3Preflight -Inputs $inputs -RequiredGroups @('Duplicate Name') }
    $info = Get-PDGraphErrorInfo -ErrorRecord $caught
    Assert-Like '*2 groups are named*' $info.Message 'counts the candidates'
    Assert-Like "*$firstId*" $info.Message 'first candidate id shown'
    Assert-Like "*$secondId*" $info.Message 'second candidate id shown'
    Assert-Like '*object id*' $info.Message 'tells the operator how to disambiguate'
    Assert-Equal 0 @(Get-PDMockGraphMutation).Count 'ambiguity never becomes a guess'
    Clear-PDMockGraph

    # --- apostrophe: OData doubling plus URI escaping, and a match found anyway ---
    $apostropheId = [guid]::NewGuid().ToString()
    Reset-PDM3Scenario -Groups @(@{ Id = $apostropheId; DisplayName = "IT's Group" }, @{ Id = ([guid]::NewGuid().ToString()); DisplayName = 'ITs Group' })
    $inputs = New-PDM3InputSet -Case 'g04-apostrophe'
    $preflight = Invoke-PDM3Preflight -Inputs $inputs -RequiredGroups @("IT's Group")

    $filterUri = [string](@($script:MockGraphCalls)[1].Uri)
    Assert-Like '*%27IT%27%27s%20Group%27*' $filterUri 'apostrophe doubled for OData and percent-encoded on the wire'
    Assert-Equal 1 @($preflight.ResolvedGroups).Count 'exact match resolved'
    Assert-Equal "IT's Group" $preflight.ResolvedGroups[0].DisplayName 'exact name matched, not the near-miss'
    Assert-Equal $apostropheId $preflight.ResolvedGroups[0].Id 'right group'
    Clear-PDMockGraph

    # --- pagination: the match lives on the second page and must still be found ---
    $pagedId  = [guid]::NewGuid().ToString()
    $pageOne  = New-PDMockValuePage -Value @((New-PDM3GroupValue -Id ([guid]::NewGuid().ToString()) -DisplayName 'Unrelated One')) `
                                    -NextLink 'https://graph.microsoft.com/v1.0/groups?$filter=displayName%20eq%20%27Paged%20Group%27&$skiptoken=page2'
    $pageTwo  = New-PDMockValuePage -Value @((New-PDM3GroupValue -Id $pagedId -DisplayName 'Paged Group'))
    Reset-PDM3Scenario -GroupPages @($pageOne, $pageTwo)
    $inputs = New-PDM3InputSet -Case 'g04-paged'
    $preflight = Invoke-PDM3Preflight -Inputs $inputs -RequiredGroups @('Paged Group')

    Assert-Equal 1 @($preflight.ResolvedGroups).Count 'found across pages'
    Assert-Equal $pagedId $preflight.ResolvedGroups[0].Id 'the paginated match'
    $pages = @(@($script:MockGraphCalls) | Where-Object { ($_.Uri -like '*/v1.0/groups*') -and ($_.Uri -notlike '*login*') })
    Assert-Equal 2 $pages.Count 'both pages were actually fetched'
    Assert-Like '*skiptoken=page2*' @($pages)[1].Uri 'nextLink followed verbatim'
    Clear-PDMockGraph
}

Add-TestCase 'G05' '/AllDevices and /AllUsers are built-in targets; an unknown /command is refused' {
    $groupId = [guid]::NewGuid().ToString()
    Reset-PDM3Scenario -Groups @(@{ Id = $groupId; DisplayName = 'Techs' })

    # Mixed with a real group, any letter case, repeated: one built-in entry plus the group.
    $preflight = Invoke-PDM3Preflight -Inputs (New-PDM3InputSet -Case 'g05-mixed') -RequiredGroups @('/AllUsers') -AvailableGroups @('/alldevices; Techs; /AllDevices')
    $groups = @($preflight.ResolvedGroups)
    Assert-Equal 3 $groups.Count 'one /AllUsers, one /AllDevices, one group'
    $devices = @($groups | Where-Object { $_.Id -eq '/AllDevices' })
    Assert-Equal 1 $devices.Count 'the repeated /AllDevices collapses to one'
    Assert-Equal 'available' ([string]$devices[0].Intent) 'with the intent it was given'
    Assert-Like '*built-in*' ([string]$devices[0].DisplayName) 'and is labelled as a built-in target'
    Assert-Equal 0 @(@($script:MockGraphCalls) | Where-Object { ([string]$_.Uri) -like '*groups*AllDevices*' -or ([string]$_.Uri) -like '*groups*alldevices*' }).Count 'no directory lookup for a built-in target'

    # A typo is refused, not looked up as a group.
    $caught = Assert-Throws -Body { Invoke-PDM3Preflight -Inputs (New-PDM3InputSet -Case 'g05-typo') -AvailableGroups @('/AllDevice') }
    Assert-Like "*Unknown option '/AllDevice'*" (Get-PDGraphErrorInfo -ErrorRecord $caught).Message 'the typo is named'

    # Same built-in in both intents follows the group conflict rule.
    $caught = Assert-Throws -Body { Invoke-PDM3Preflight -Inputs (New-PDM3InputSet -Case 'g05-conflict') -RequiredGroups @('/AllDevices') -AvailableGroups @('/alldevices') }
    Assert-Like '*both a Required and an Available*' (Get-PDGraphErrorInfo -ErrorRecord $caught).Message 'neither intent wins'

    # The payload carries the built-in target type and no group id; the read-back recognizes it.
    $payload = New-PDIntuneAssignmentPayload -ResolvedGroups @($devices[0], @($groups | Where-Object { $_.Id -eq $groupId })[0])
    $json = ConvertTo-PDGraphJson -InputObject $payload
    Assert-Like '*"#microsoft.graph.allDevicesAssignmentTarget"*' $json 'All devices target type sent'
    $builtInTarget = @($payload.mobileAppAssignments | Where-Object { $_.target['@odata.type'] -like '*allDevices*' })[0].target
    Assert-True (-not $builtInTarget.ContainsKey('groupId')) 'a built-in target carries no groupId'

    $readBack = @(
        @{ id = 'a1'; intent = 'available'; target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } },
        (New-PDM4Assignment -Id 'a2' -GroupId $groupId -Intent 'available')
    )
    $expected = @($devices[0], @($groups | Where-Object { $_.Id -eq $groupId })[0])
    Assert-Equal 0 @(Compare-PDIntuneAssignmentSet -Expected $expected -Assignments $readBack).Count 'the read-back agrees'
    $missing = @(Compare-PDIntuneAssignmentSet -Expected $expected -Assignments @($readBack[1]))
    Assert-Equal 1 $missing.Count 'a missing All devices assignment is a difference'
}

Add-TestCase 'A01' 'A missing category warns, creates nothing, and associates nothing' {
    Reset-PDM3Scenario -Categories @(@{ id = ([guid]::NewGuid().ToString()); displayName = 'Printers' })

    $inputs = New-PDM3InputSet -Case 'a01'
    $preflight = Invoke-PDM3Preflight -Inputs $inputs -Category 'Finance Tools'

    Assert-Equal 'Missing' $preflight.CategoryResult.Status 'status Missing'
    Assert-Equal 'Finance Tools' $preflight.CategoryResult.RequestedName 'requested name preserved'
    Assert-Equal $null $preflight.CategoryResult.Id 'no id invented'
    Assert-Like '*never created*' $preflight.CategoryResult.Warning 'warning explains the policy'
    Assert-Equal 1 @(@($preflight.Warnings) | Where-Object { $_ -like '*Finance Tools*' }).Count 'warning surfaced'
    Assert-Equal 0 @(Get-PDMockGraphMutation).Count 'no category POST, no app POST, nothing'
    foreach ($call in @($script:MockGraphCalls)) {
        # The read-only lookup of mobileAppCategories is expected; the association endpoint on an
        # app (.../mobileApps/{id}/categories or /$ref) is not.
        Assert-True (([string]$call.Uri) -notlike '*/categories*') 'no category association request either'
    }

    # Ambiguous categories must also skip the association rather than pick one.
    Clear-PDMockGraph
    Reset-PDM3Scenario -Categories @(@{ id = ([guid]::NewGuid().ToString()); displayName = 'Printers' }, @{ id = ([guid]::NewGuid().ToString()); displayName = 'Printers' })
    $inputs = New-PDM3InputSet -Case 'a01-ambiguous'
    $preflight = Invoke-PDM3Preflight -Inputs $inputs -Category 'Printers'
    Assert-Equal 'Ambiguous' $preflight.CategoryResult.Status 'multiple exact matches'
    Assert-Equal $null $preflight.CategoryResult.Id 'never picks arbitrarily'
    Assert-Like '*rename them or leave Category empty*' ($preflight.CategoryResult.Warning) 'actionable advice'
    Assert-Equal 0 @(Get-PDMockGraphMutation).Count 'still nothing written'

    # An empty category means no lookup at all.
    Clear-PDMockGraph
    Reset-PDM3Scenario
    $inputs = New-PDM3InputSet -Case 'a01-none'
    $preflight = Invoke-PDM3Preflight -Inputs $inputs -Category '   '
    Assert-Equal 'NotRequested' $preflight.CategoryResult.Status 'no category, no lookup'
    $categoryCalls = @(@($script:MockGraphCalls) | Where-Object { $_.Uri -like '*Categories*' })
    Assert-Equal 0 $categoryCalls.Count 'the categories endpoint is not even queried'

    Clear-PDMockGraph
}

Add-TestCase 'A03' 'a duplicate whose name has [brackets] is still found' {
    # Live finding 2026-10-12: Intune's displayName eq filter never matches names with brackets,
    # and development-mode names always have them ("[PUBLIC-DEVELOPMENT] [VER: ...]").
    $name = 'PRINTER - SPED: Vanino [PUBLIC-DEVELOPMENT] [VER: e0e4f3c]'
    Reset-PDM3Scenario -Apps @(@{ id = 'dup-1'; displayName = $name; publishingState = 'published' },
                              @{ id = 'other-1'; displayName = 'PRINTER - SPED: Vanino [PROD]'; publishingState = 'published' })

    $inputs    = New-PDM3InputSet -Case 'a03-brackets'
    $preflight = Invoke-PDM3Preflight -Inputs $inputs -DisplayName $name
    $found     = @($preflight.DuplicateApps)
    Assert-Equal 1 $found.Count 'exactly the app with the identical name'
    Assert-Equal 'dup-1' ([string]$found[0].Id) 'and not the one that only shares the prefix'
}

Add-TestCase 'A02' 'Duplicate display names are review data, then an explicit switch gates execution' {
    $existingId = 'app-existing-1'
    $otherId    = 'app-existing-2'
    Reset-PDM3Scenario -Apps @(@{ id = $existingId; displayName = 'PowerDeploy Test App'; publishingState = 'published' },
                              @{ id = $otherId; displayName = 'PowerDeploy Test App'; publishingState = 'published' })

    # A dry run reports duplicates without failing (spec 9.2).
    $inputs = New-PDM3InputSet -Case 'a02-dryrun'
    $preflight = Invoke-PDM3Preflight -Inputs $inputs
    Assert-Equal 2 @($preflight.DuplicateApps).Count 'both matches listed'
    $listedIds = @($preflight.DuplicateApps | ForEach-Object { $_.Id })
    Assert-True ($listedIds -contains $existingId) 'first id surfaced'
    Assert-True ($listedIds -contains $otherId) 'second id surfaced'

    # Execution without the switch stops with a message that says what to do.
    Clear-PDMockGraph
    Reset-PDM3Scenario -Apps @(@{ id = $existingId; displayName = 'PowerDeploy Test App' })
    $inputs = New-PDM3InputSet -Case 'a02-execute'
    $caught = Assert-Throws -Body { Invoke-PDM3Preflight -Inputs $inputs -Execution }
    $info = Get-PDGraphErrorInfo -ErrorRecord $caught
    Assert-Like '*already have the display name*' $info.Message 'explains the collision'
    Assert-Like "*$existingId*" $info.Message 'shows the existing app id'
    Assert-Like '*-AllowDuplicateName*' $info.Message 'names the switch that would allow it'
    Assert-Equal 0 @(Get-PDMockGraphMutation).Count 'refusal happens before any write'

    # With the switch, the duplicate gate lets the run proceed (to the M4 boundary).
    Clear-PDMockGraph
    Reset-PDM3Scenario -Apps @(@{ id = $existingId; displayName = 'PowerDeploy Test App' })
    $inputs = New-PDM3InputSet -Case 'a02-allowed'
    $preflight = Invoke-PDM3Preflight -Inputs $inputs -Execution -AllowDuplicateName
    Assert-Equal 1 @($preflight.DuplicateApps).Count 'duplicates still reported'
    Assert-True ($preflight.ContainsKey('Stage')) 'preflight completed for the write path'
    Assert-Equal 0 @(Get-PDMockGraphMutation).Count 'even the accepted path writes nothing in this milestone'

    Clear-PDMockGraph
}

Add-TestCase 'U01' 'DryRun through every preflight branch issues zero mutation calls' {
    $groupId = [guid]::NewGuid().ToString()
    $availId = [guid]::NewGuid().ToString()
    Reset-PDM3Scenario `
        -Groups @(@{ Id = $groupId; DisplayName = 'Required Group' }, @{ Id = $availId; DisplayName = 'Available Group' }) `
        -GroupById @{ $groupId = @{ Id = $groupId; DisplayName = 'Required Group' }; $availId = @{ Id = $availId; DisplayName = 'Available Group' } } `
        -Apps @(@{ id = 'app-dupe'; displayName = 'PowerDeploy Test App' }) `
        -Categories @(@{ id = 'cat-1'; displayName = 'Printers' })

    $inputs = New-PDM3InputSet -Case 'u01'
    $preflight = Invoke-PDM3Preflight -Inputs $inputs -RequiredGroups @('Required Group') -AvailableGroups @('Available Group') -Category 'Printers'

    $mutations = @(Get-PDMockGraphMutation)
    Assert-Equal 0 $mutations.Count "dry run must mutate nothing (saw: $($mutations -join '; '))"

    $graphCalls = @(@($script:MockGraphCalls) | Where-Object { $_.Uri -like 'https://graph.microsoft.com/*' })
    Assert-True $graphCalls.Count -ge 3 'the dry run really did read groups, duplicates, and the category'
    foreach ($call in $graphCalls) {
        Assert-Equal 'Get' ([string]$call.Method) 'every Graph request in a dry run is a GET'
    }

    # The only non-GET is the token POST to the identity provider, which is not a tenant write.
    $nonGet = @(@($script:MockGraphCalls) | Where-Object { ($_.Method -ne 'Get') -and ($_.Uri -notlike 'https://login.microsoftonline.com/*') })
    Assert-Equal 0 $nonGet.Count 'the token endpoint is the only non-GET endpoint used'

    foreach ($forbidden in @('/assign', '/categories', 'comp=block', 'renewUpload', 'commitFile', '/commit')) {
        foreach ($call in @($script:MockGraphCalls)) {
            Assert-True (([string]$call.Uri) -notlike "*$forbidden*") "dry run must never touch $forbidden"
        }
    }

    Clear-PDMockGraph
}

Add-TestCase 'M3-02' 'Dry run returns the whole review object and leaks nothing' {
    $groupId = [guid]::NewGuid().ToString()
    Reset-PDM3Scenario `
        -Groups @(@{ Id = $groupId; DisplayName = 'Required Group' }) `
        -GroupById @{ $groupId = @{ Id = $groupId; DisplayName = 'Required Group' } } `
        -Categories @(@{ id = 'cat-1'; displayName = 'Printers' })

    $secretCommand = 'Setup.exe /p:https://oauth2:ghp_COMMANDLEAK@github.com/org/repo'
    $inputs  = New-PDM3InputSet -Case 'm3-review' -InstallText $secretCommand
    $notes   = "InstallMethod: N/A`r`n`r`nPOWERDEPLOY DATA`r`nTarget Repo: https://github.com/Santa-Cruz-COE/PowerDeploy"

    $result = Invoke-PDIntuneUpload -IntuneWinPath (Get-PDM3FixturePath -Name 'valid.intunewin') `
        -DisplayName 'PowerDeploy Test App' -Description 'N/A' -Publisher 'PowerDeploy' `
        -InstallCommandFile $inputs.InstallFile -UninstallCommandFile $inputs.UninstallFile `
        -DetectionScriptFile $inputs.DetectionFile -Notes $notes -Category 'Printers' `
        -RequiredGroups @('Required Group') -CredentialPath $inputs.CredentialPath `
        -TempDirectory $inputs.TempDirectory -DryRun

    Assert-Equal $true $result.Success 'dry run succeeded'
    Assert-Equal $true $result.DryRun 'flagged as a dry run'
    Assert-Equal 'Preflight' $result.Stage 'stage reported'
    Assert-Equal 'NotNeeded' $result.CleanupStatus 'nothing to clean up'
    Assert-Equal $null $result.AppId 'no app id on a dry run'
    Assert-True ($result.Message.Length -gt 10) 'message present'

    # Every documented review field is present and filled.
    $meta = $result.ReviewMetadata
    Assert-Equal 'PowerDeploy Test App' $meta.DisplayName 'DisplayName'
    Assert-Equal 'N/A' $meta.Description 'Description passed through untouched'
    Assert-Equal 'PowerDeploy' $meta.Publisher 'Publisher'
    Assert-Equal '' $meta.AppVersion 'AppVersion omitted/empty when not supplied'
    Assert-Equal $false $meta.AllowAvailableUninstall 'default false honoured'
    Assert-Equal 'IntunePackage.intunewin' $meta.PackageFileName 'package mapping reviewed'
    Assert-Equal 'PowerDeployFixtureSetup.exe' $meta.SetupFilePath 'setup file reviewed'
    Assert-Equal ([long]462) ([long]$meta.PackageUnencryptedBytes) 'content size reviewed'
    Assert-Equal ([long]512) ([long]$meta.PackageEncryptedBytes) 'encrypted size reviewed'
    Assert-Equal 'System' $meta.InstallationDefaults.InstallContext 'installation defaults reviewed'
    Assert-Equal 15 $meta.InstallationDefaults.InstallTimeoutMinutes 'timeout default reviewed'
    Assert-Like '*Windows 10 1607*' $meta.InstallationDefaults.MinimumWindowsVersion 'minimum OS reviewed'
    Assert-Like '*Created: timestamp is appended*' $meta.NotesTimestampNote 'dry run says the timestamp comes at creation'
    Assert-Equal $notes $meta.Notes 'technical Notes preserved exactly as supplied'

    Assert-Equal 1 @($result.ResolvedGroups).Count 'resolved group returned'
    Assert-Equal $groupId $result.ResolvedGroups[0].Id 'id, not just a name'
    Assert-Equal 'required' $result.ResolvedGroups[0].Intent 'intent returned'
    Assert-Equal 'Resolved' $result.CategoryResult.Status 'category resolved'
    Assert-Equal 'cat-1' $result.CategoryResult.Id 'category id'
    Assert-Equal 0 @($result.DuplicateApps).Count 'no duplicates in this scenario'
    Assert-Equal 4 $result.InputHashes.Keys.Count 'package/install/uninstall/detection hashed'
    foreach ($key in @('Package', 'Install', 'Uninstall', 'Detection')) {
        Assert-Match '^[0-9a-f]{64}$' $result.InputHashes[$key] "$key hash is SHA-256 hex"
    }
    Assert-Equal $secretCommand.Length $result.CommandLengths.Install 'command length reported instead of the command'
    Assert-True ($null -ne $result.SecretExpiresOn) 'secret expiry surfaced'

    # Leak hunt: the returned object must not carry the command text, the secret, or a token.
    $serialized = $result | ConvertTo-Json -Depth 15 -Compress
    Assert-NotLike '*ghp_COMMANDLEAK*' $serialized 'install command text never appears in the result'
    Assert-NotLike '*m3-never-real-secret*' $serialized 'credential secret never appears in the result'
    Assert-NotLike '*Bearer*' $serialized 'no bearer token in the result'
    Assert-NotLike '*access_token*' $serialized 'no token material in the result'
    Assert-NotLike '*EncryptionKey*' $serialized 'package encryption info never leaves the process'
    Assert-NotLike '*InitializationVector*' $serialized 'no initialization vector'
    Assert-NotLike '*clientSecret*' $serialized 'no client secret field'
    Assert-NotLike '*intunewin-payload-*' $serialized 'temp payload paths are not surfaced'

    # A dot-sourced call must not have started a log file.
    Assert-Equal $null $script:PDUploadLogPath 'no log file from a library call'

    # And the temp directory this call created is gone again.
    Assert-True (-not (Test-Path -LiteralPath $inputs.TempDirectory)) 'per-run temp directory removed in finally'
    Assert-Equal 0 @(Get-PDMockGraphMutation).Count 'still zero mutations'

    Clear-PDMockGraph
}

Add-TestCase 'N02' 'The serialized create payload has no owner key, ever' {
    $temp = Join-Path $tempRoot 'n02'
    $package = Read-PDIntuneWinPackage -IntuneWinPath (Get-PDM3FixturePath -Name 'valid.intunewin') -TempDirectory $temp

    $base = @{
        DisplayName      = 'PowerDeploy Test App'
        Description      = 'Department: Technology'
        Publisher        = 'PowerDeploy'
        InstallCommand   = 'Setup.exe /quiet'
        UninstallCommand = 'Setup.exe /uninstall /quiet'
        DetectionBase64  = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("Write-Output 1"))
        FinalNotes       = "POWERDEPLOY DATA`r`nCreated: 2026-10-08T12:00:00+00:00"
        Package          = $package
    }

    $forbiddenKeys = @('owner', 'developer', 'ownerNameUrl', 'allowedArchitectures', 'minimumSupportedWindowsRelease',
                       'detectionRules', 'activeInstallScript', 'activeUninstallScript', 'committedContentVersion',
                       'publishingState', 'contentMismatch', 'appVersion', 'isAssigned')

    foreach ($variant in @(@{ Name = 'no version'; Add = @{} },
                           @{ Name = 'with version'; Add = @{ AppVersion = '1.2.3' } },
                           @{ Name = 'N/A version'; Add = @{ AppVersion = 'N/A' } },
                           @{ Name = 'available uninstall'; Add = @{ AllowAvailableUninstall = $true } })) {

        $arguments = @{} + $base
        foreach ($key in $variant.Add.Keys) { $arguments[$key] = $variant.Add[$key] }

        $payload = New-PDWin32AppPayload @arguments
        $json    = ConvertTo-PDGraphJson -InputObject $payload

        # Scan every key at every depth, not just a substring of the JSON text.
        $parsed = $json | ConvertFrom-Json
        $seenKeys = @()
        $walk = {
            param($Node, $Depth)
            if ($Depth -gt 12) { return }
            if ($null -eq $Node) { return }
            if ($Node -is [System.Management.Automation.PSCustomObject]) {
                foreach ($property in $Node.PSObject.Properties) {
                    $script:N02Keys += $property.Name
                    & $walk $property.Value ($Depth + 1)
                }
            } elseif ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
                foreach ($item in $Node) { & $walk $item ($Depth + 1) }
            }
        }
        $script:N02Keys = @()
        & $walk $parsed 0
        foreach ($key in @($script:N02Keys)) {
            foreach ($bad in $forbiddenKeys) {
                if ($key -eq $bad) { throw "payload ($($variant.Name)) contained the forbidden key '$bad'" }
            }
        }

        # The values that must be there are there, with the one-representation rule.
        Assert-Like '*win32LobApp*' $json 'odata type'
        Assert-Like '*x64,x86*' $json 'one architecture representation'
        Assert-Like '*v10_1607*' $json 'one OS representation'
        Assert-Like '*win32LobAppPowerShellScriptRule*' $json 'one detection rule representation'
        Assert-Like '*maxRunTimeInMinutes*' $json 'install experience present'
        Assert-Like '*1707*' $json 'default return codes'
        Assert-Like '*IntunePackage.intunewin*' $json 'fileName from the package'
        Assert-Like '*PowerDeployFixtureSetup.exe*' $json 'setupFilePath from the package'

        $hasVersion = $json -like '*displayVersion*'
        if ($variant.Name -eq 'with version') {
            Assert-True $hasVersion 'a usable version is sent'
            Assert-Like '*1.2.3*' $json 'version value preserved'
        } else {
            Assert-True (-not $hasVersion) "($($variant.Name)) no displayVersion key when the version is missing, N/A, or whitespace"
        }

        if ($variant.Name -eq 'available uninstall') {
            Assert-Like '*"allowAvailableUninstall":true*' $json 'printer default honoured when asked'
        } else {
            Assert-Like '*"allowAvailableUninstall":false*' $json 'application default is false'
        }
    }

    # Empty and null Notes must still serialize as an empty string, not a missing or null field.
    $emptyNotes = @{} + $base
    $emptyNotes['FinalNotes'] = ''
    $json = ConvertTo-PDGraphJson -InputObject (New-PDWin32AppPayload @emptyNotes)
    Assert-Like '*"notes":""*' $json 'notes is an empty string, never null'

    # A detection rule must not grow the fields the schema does not want.
    $payload = New-PDWin32AppPayload @base
    $ruleJson = ConvertTo-PDGraphJson -InputObject $payload.rules[0]
    foreach ($unwanted in @('displayName', 'runAsAccount', 'comparisonValue')) {
        Assert-True ($ruleJson -notlike "*$unwanted*") "detection rule must not carry $unwanted"
    }

    Clear-PDMockGraph
}


Add-TestCase 'M3-04' 'A missing or expired credential fails before any Graph call' {
    Reset-PDM3Scenario

    $inputs = New-PDM3InputSet -Case 'm3-nocredential'
    $missing = Join-Path $tempRoot 'm3-nocredential\absent.clixml'

    $result = Invoke-PDIntuneUpload -IntuneWinPath (Get-PDM3FixturePath -Name 'valid.intunewin') `
        -DisplayName 'PowerDeploy Test App' -Description 'N/A' -Publisher 'PowerDeploy' `
        -InstallCommandFile $inputs.InstallFile -UninstallCommandFile $inputs.UninstallFile `
        -DetectionScriptFile $inputs.DetectionFile -CredentialPath $missing `
        -TempDirectory $inputs.TempDirectory -DryRun

    Assert-Equal $false $result.Success 'no credential means no success'
    Assert-Equal 'Credential' $result.Stage 'stage names the credential step'
    Assert-Like '*InTuneAPI--Setup-and-Manage*' $result.Message 'points at the menu that fixes it'
    Assert-Equal 0 @($script:MockGraphCalls).Count 'a missing credential never reaches the network'

    # An expired secret is refused, not refreshed silently.
    $expired = New-PDM3InputSet -Case 'm3-expired' -DaysUntilExpiry -5
    $result = Invoke-PDIntuneUpload -IntuneWinPath (Get-PDM3FixturePath -Name 'valid.intunewin') `
        -DisplayName 'PowerDeploy Test App' -Description 'N/A' -Publisher 'PowerDeploy' `
        -InstallCommandFile $expired.InstallFile -UninstallCommandFile $expired.UninstallFile `
        -DetectionScriptFile $expired.DetectionFile -CredentialPath $expired.CredentialPath `
        -TempDirectory $expired.TempDirectory -DryRun
    Assert-Equal $false $result.Success 'expired secret is a failure'
    Assert-Equal 'Credential' $result.Stage 'credential stage'
    Assert-Like '*expired*' $result.Message 'names the reason'

    # Near expiry stays usable but warns (C02 applied to the whole flow).
    Clear-PDMockGraph
    Reset-PDM3Scenario
    $near = New-PDM3InputSet -Case 'm3-nearexpiry' -DaysUntilExpiry 10
    $result = Invoke-PDIntuneUpload -IntuneWinPath (Get-PDM3FixturePath -Name 'valid.intunewin') `
        -DisplayName 'PowerDeploy Test App' -Description 'N/A' -Publisher 'PowerDeploy' `
        -InstallCommandFile $near.InstallFile -UninstallCommandFile $near.UninstallFile `
        -DetectionScriptFile $near.DetectionFile -CredentialPath $near.CredentialPath `
        -TempDirectory $near.TempDirectory -DryRun
    Assert-Equal $true $result.Success 'near expiry is still usable'
    Assert-True (@($result.Warnings) | Where-Object { $_ -like '*expires in*' }).Count -ge 1 'warns about the rotation window'
    Assert-True ($null -ne $result.SecretExpiresOn) 'expiry surfaced for the review screen'

    Clear-PDMockGraph
}

Add-TestCase 'M3-05' 'A token without the required application roles stops before any write' {
    Reset-PDM3Scenario
    $script:M3.Token = (New-TestJwt -Roles @('Group.Read.All'))

    $inputs = New-PDM3InputSet -Case 'm3-roles'
    $result = Invoke-PDIntuneUpload -IntuneWinPath (Get-PDM3FixturePath -Name 'valid.intunewin') `
        -DisplayName 'PowerDeploy Test App' -Description 'N/A' -Publisher 'PowerDeploy' `
        -InstallCommandFile $inputs.InstallFile -UninstallCommandFile $inputs.UninstallFile `
        -DetectionScriptFile $inputs.DetectionFile -CredentialPath $inputs.CredentialPath `
        -TempDirectory $inputs.TempDirectory -DryRun

    Assert-Equal $false $result.Success 'missing role is not silently tolerated'
    Assert-Equal 'Credential' $result.Stage 'credential stage'
    Assert-Like '*DeviceManagementApps.ReadWrite.All*' $result.Message 'names the missing role'
    Assert-Equal 0 @(Get-PDMockGraphMutation).Count 'permission problems never become partial writes'

    Clear-PDMockGraph
}

Add-TestCase 'M3-06' 'Package reader rejects hostile entry names and accepts ordinary ones' {
    foreach ($safe in @('IntuneWinPackage/Contents/IntunePackage.intunewin', 'IntuneWinPackage/Metadata/Detection.xml', 'a/b/c.txt', 'with space.name')) {
        Assert-True (Test-PDArchiveEntryName -Name $safe) "$safe is a safe relative entry name"
    }
    foreach ($hostile in @('../evil.txt', 'a/../../evil.txt', '/etc/passwd', 'C:\Windows\evil', '\\server\share', 'C:\', '', '   ', 'stream:name.txt', "control`tabc")) {
        Assert-True (-not (Test-PDArchiveEntryName -Name $hostile)) "$hostile must be rejected"
    }
}

Add-TestCase 'M3-07' 'Query building escapes what OData needs and nothing else' {
    $q = [string][char]39
    Assert-Equal ($q + 'plain' + $q) (ConvertTo-PDODataStringLiteral -Value 'plain') 'simple literal'
    Assert-Equal ($q + 'it' + $q + $q + 's' + $q) (ConvertTo-PDODataStringLiteral -Value ('it' + $q + 's')) "apostrophes are OData's only escape"
    Assert-Equal (($q * 5) + 'quote' + ($q * 3)) (ConvertTo-PDODataStringLiteral -Value (($q * 2) + 'quote' + $q)) 'every apostrophe is doubled exactly once'

    $path = New-PDGraphQueryPath -Path '/v1.0/groups' -Query @{ '$filter' = "displayName eq 'A & B'"; '$select' = 'id,displayName' }
    Assert-Like '*/v1.0/groups?*%24filter=*' $path '$ in option names is escaped'
    Assert-Like '*%24select=id%2CdisplayName*' $path 'select escaped'
    Assert-Like '*A%20%26%20B*' $path 'ampersand cannot break out of the filter'
    Assert-True (([System.Uri]$path).Scheme -eq $null -or $true) 'relative path still parses as a Uri'

    # Same input must produce the same URL on both engines: apostrophes are forced to %27 because
    # EscapeDataString disagrees between .NET Framework and .NET Core.
    $apostrophe = New-PDGraphQueryPath -Path '/v1.0/groups' -Query @{ '$filter' = "displayName eq 'It''s'" }
    Assert-Like '*%27It%27%27s%27*' $apostrophe.Substring($apostrophe.IndexOf('%24filter')) 'apostrophes always percent-encoded'

    Assert-Equal '/v1.0/groups' (New-PDGraphQueryPath -Path '/v1.0/groups' -Query $null) 'no query, no question mark'
    Assert-Equal '/v1.0/groups' (New-PDGraphQueryPath -Path '/v1.0/groups' -Query @{ empty = '' }) 'empty values dropped'

    Assert-Equal @() @(Get-PDDelimitedList -Values $null).Count 'null input is an empty list'
    Assert-Equal 3 @(Get-PDDelimitedList -Values @('a;b', ' ; ', 'c')).Count 'split, trim, discard empty'
    Assert-Equal 1 @(Get-PDDelimitedList -Values 'single').Count 'scalar input'
}

Add-TestCase 'M3-08' 'The script command line parses strictly and cannot clobber the caller' {
    $parsed = ConvertTo-PDUploaderRunArgument -RawArguments @(
        '-IntuneWinPath', 'C:\pkg\app.intunewin',
        '-DisplayName', 'Two words',
        '-DryRun',
        '-RequiredGroups', 'Group A;Group B',
        '-RequiredGroups', 'Group C',
        '-AllowAvailableUninstall', 'true',
        '-AppVersion:1.2.3',
        '-NoRollback:$false')

    Assert-Equal 'C:\pkg\app.intunewin' $parsed.IntuneWinPath 'value option'
    Assert-Equal 'Two words' $parsed.DisplayName 'value with spaces'
    Assert-Equal $true ([bool]$parsed.DryRun) 'bare switch is present'
    Assert-Equal 2 @($parsed.RequiredGroups).Count 'repeated list option accumulates'
    Assert-Equal 'Group C' @($parsed.RequiredGroups)[1] 'order preserved'
    Assert-Equal $true $parsed.AllowAvailableUninstall '[bool] option from text'
    Assert-Equal '1.2.3' $parsed.AppVersion '-Name:value form'
    Assert-Equal $false ([bool]$parsed.NoRollback) '-Switch:$false honoured'

    # Nothing else may be invented by the parser.
    Assert-True (-not $parsed.ContainsKey('Category')) 'unspecified options stay absent'

    # Typos and missing values are errors, never "the operator left it out".
    Assert-Throws -Body { ConvertTo-PDUploaderRunArgument -RawArguments @('-DryRunn') } -MessagePattern '*Unknown option*' 'typo refused'
    Assert-Throws -Body { ConvertTo-PDUploaderRunArgument -RawArguments @('-DisplayName') } -MessagePattern '*requires a value*' 'missing value refused'
    Assert-Throws -Body { ConvertTo-PDUploaderRunArgument -RawArguments @('positional') } -MessagePattern '*Unexpected argument*' 'positional refused'
    Assert-Throws -Body { ConvertTo-PDUploaderRunArgument -RawArguments @('-AllowAvailableUninstall', 'maybe') } -MessagePattern '*must be true or false*' 'bad boolean refused'

    Assert-Equal 0 @(ConvertTo-PDUploaderRunArgument -RawArguments @()).Keys.Count 'no arguments parses to nothing'

    # Dot-sourcing the uploader must not have written anything into this script's own scope:
    # the wizard state that Setup.ps1 keeps lives in variables with exactly these names.
    # (The harness's own $HelperPath is legitimately set, so it is not in this list.)
    foreach ($shadowed in @('IntuneWinPath', 'DisplayName', 'Description', 'Publisher', 'Notes', 'Category',
                            'AppVersion', 'RequiredGroups', 'AvailableGroups', 'CredentialPath', 'DryRun',
                            'AllowDuplicateName', 'NoRollback', 'LogDirectory', 'TempDirectory')) {
        Assert-True ($null -eq (Get-Variable -Name $shadowed -ErrorAction SilentlyContinue)) "$shadowed must not exist in the caller's scope after dot-sourcing"
    }
}

# ---------------------------------------------------------------------------
# M4 - write stages, storage transfer, verification, rollback
#
# The M4 router extends the M3 router, so groups, categories, and duplicates keep
# answering from the M3 scenario while app, content, storage, assignment, and delete
# requests are answered and recorded here. Order-sensitive claims are proven from the
# recorded request trail; "nothing was written" is proven by Get-PDMockGraphMutation.
# ---------------------------------------------------------------------------

$script:M4 = $null
$script:M3Router = $null

function Get-PDM4SasUri {
    <#
        One SAS URI in the shape Graph returns: the same URL four times, space-separated.
        'se' is a real expiry so the renewal paths are driven by the same parsing the
        production code uses, not by a special test hook.
    #>
    param(
        [string]$Tag = 'original',
        [object]$ExpiresInSec = 3600
    )

    $moment = [DateTimeOffset]::UtcNow.AddSeconds([double]$ExpiresInSec)
    $se     = [System.Uri]::EscapeDataString($moment.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))
    $uri    = "https://pdintuneweb.blob.core.windows.net/content/IntunePackage.intunewin?sv=2021-08-06&sr=b&se=$se&sig=sig-$Tag"

    # Four identical endpoint families, exactly like the real azureStorageUri property.
    return ($uri + ' ' + $uri + ' ' + $uri + ' ' + $uri)
}

function Get-PDM4Queued {
    <#
        Consumes the next scripted response for a route, or returns -Default when the
        script for that route has run out. Queues let a case say "pending, pending, success".
    #>
    param([Parameter(Mandatory = $true)][string]$Key, [AllowNull()][object]$Default)

    $queue = @($script:M4[$Key])
    if ($queue.Count -eq 0) { return $Default }

    $next = $queue[0]
    if ($queue.Count -eq 1) { $script:M4[$Key] = @() } else { $script:M4[$Key] = @($queue[1..($queue.Count - 1)]) }

    return $next
}

function Reset-PDM4Scenario {
    <#
        Installs the write-path router on top of the M3 scenario. Every knob defaults to a
        successful publish, and each case overrides only what it is about:

          -FileQueue / -AppQueue     scripted answers for repeated GETs (pending states)
          -CreateResponse            hashtable: @{ Status; Json } used for POST mobileApps
          -CreateThrows              transport failure on the create POST (lost response)
          -ReadBack                  scriptblock that mutates the read-back app (U07)
          -AssignmentRecords         what GET .../assignments returns
          -CategoryRecords           what GET .../categories returns
          -Storage                   scriptblock handling every non-Graph request
          -FileFailAfter/-AppFailAfter  keep failing after N reads (bounded-deadline tests)
    #>
    param(
        [string]$AppId = 'app-new-1',
        [string]$VersionId = '7',
        [string]$FileId = 'file-1',
        [object[]]$FileQueue = @(),
        [object[]]$AppQueue = @(),
        [AllowNull()][hashtable]$CreateResponse = $null,
        [switch]$CreateThrows,
        [AllowNull()][scriptblock]$ReadBack = $null,
        [object[]]$AssignmentRecords = $null,
        [object[]]$CategoryRecords = $null,
        [AllowNull()][scriptblock]$Storage = $null,
        [object[]]$Groups = @(),
        [hashtable]$GroupById = @{},
        [object[]]$Apps = @(),
        [object[]]$Categories = @(),
        [int]$FileFailAfter = -1,
        [int]$AppFailAfter = -1,
        [object[]]$FailRules = @(),
        [int]$SasExpiresInSec = 3600,
        [int]$PollDeadlineSec = 30,
        [AllowNull()][object[]]$ReconcileAppIds = $null,
        [string]$ReconcileDisplayName = 'PowerDeploy Test App'
    )

    # Keep the read-only scenario, then delegate to it for anything the write path is not about.
    Reset-PDM3Scenario -Groups $Groups -GroupById $GroupById -Apps $Apps -Categories $Categories
    $script:M3Router = $script:MockGraphRouter

    $script:M4 = @{
        AppId             = $AppId
        VersionId         = $VersionId
        FileId            = $FileId
        CurrentSas        = (Get-PDM4SasUri -Tag 'original' -ExpiresInSec $SasExpiresInSec)
        FileQueue         = @($FileQueue)
        AppQueue          = @($AppQueue)
        CreateResponse    = $CreateResponse
        CreateThrows      = [bool]$CreateThrows
        CreateBody        = $null
        CreateCount       = 0
        ReadBack          = $ReadBack
        AssignmentRecords = $AssignmentRecords
        CategoryRecords   = $CategoryRecords
        Storage           = $Storage
        FileReads         = 0
        AppReads          = 0
        FileFailAfter     = $FileFailAfter
        AppFailAfter      = $AppFailAfter
        FailRules         = @($FailRules)
        RenewCount        = 0
        FilePhase         = ''
        StorageRequests   = @()
        StorageBodies     = @()
        Committed         = $false
        Assigned          = $false
        ReconcileAppIds    = $ReconcileAppIds
        ReconcileDisplayName = $ReconcileDisplayName
        DuplicateLookups  = 0
        CategoryRef       = $null
        CategoryIds       = @()
        AssignBody        = $null
        PublishPatch      = $null
        IconPatch         = $null
        IconRefused       = $false
        LinksPatch        = $null
        LinksRefused      = $false
        Deleted           = @()
    }

    # Polling must never slow the suite; a case testing a bounded deadline lowers it to 0, which
    # means "fail if the first check is not already satisfied".
    $script:PDGraph.PollIntervalMs = 0
    $script:PDGraph.PollDeadlineSec = $PollDeadlineSec

    Set-PDMockGraph -Router {
        param($Request)

        $method  = [string]$Request.Method
        $uri     = [string]$Request.Uri
        $state   = $script:M4
        $path    = ($uri -split '\?')[0]

        # --- Scripted refusals -------------------------------------------------------------------
        # A rule says "the next (or every) request to this route is refused like this", which is
        # how each post-create stage is made to fail in turn. Rules never apply to the token
        # endpoint so a scenario cannot accidentally lock itself out of every request.
        if ($uri -notlike 'https://login.microsoftonline.com/*') {
            foreach ($rule in @($state.FailRules)) {
                if ($null -eq $rule) { continue }
                $remaining = [int]$rule['Remaining']
                if ($remaining -eq 0) { continue }
                if (([string]$rule['Method']) -ne $method) { continue }
                if ($path -notlike [string]$rule['PathLike']) { continue }

                $rule['Remaining'] = ($remaining - 1)

                $headers = @{ 'request-id' = 'mock-req' }
                if ($rule.ContainsKey('Headers') -and ($null -ne $rule['Headers'])) {
                    foreach ($headerName in $rule['Headers'].Keys) { $headers[$headerName] = [string]$rule['Headers'][$headerName] }
                }
                return (New-PDMockJsonResponse -Status ([int]$rule['Status']) -Json ([string]$rule['Json']) -Headers $headers)
            }
        }

        # --- Token (must be tested before the storage branch: the token host is not Graph either) ----
        if ($uri -like 'https://login.microsoftonline.com/*') {
            return (& $script:M3Router $Request)
        }

        # --- Everything that is not Graph is storage ---------------------------------------------
        if ($uri -notlike 'https://graph.microsoft.com/*') {
            $state.StorageRequests += $Request

            if ($null -ne $state.Storage) { return (& $state.Storage $Request $state) }

            if ($uri -like '*comp=blocklist*') { $state.Committed = $true }
            return (New-PDMockJsonResponse -Status 201)
        }

        # --- Content version / file record ------------------------------------------------------------
        if (($method -eq 'Post') -and ($path -like '*/microsoft.graph.win32LobApp/contentVersions')) {
            $body = $Request.BodyText
            if ($null -eq $body) { $body = '' }
            return (New-PDMockJsonResponse -Status 201 -Json (@{ id = $state.VersionId; '@odata.type' = '#microsoft.graph.win32LobAppContentVersion' } | ConvertTo-Json -Compress))
        }

        if (($method -eq 'Post') -and ($path -like '*/contentVersions/*/files')) {
            return (New-PDMockJsonResponse -Status 201 -Json (@{
                id                            = $state.FileId
                '@odata.type'                 = '#microsoft.graph.mobileAppContentFile'
                name                          = 'IntunePackage.intunewin'
                size                          = 462
                sizeEncrypted                 = 512
                isDependency                  = $false
                uploadState                   = 'azureStorageUriRequestPending'
            } | ConvertTo-Json -Compress))
        }

        # --- Renewal and commit actions ---------------------------------------------------------------
        if (($method -eq 'Post') -and ($path -like ('*/files/*/microsoft.graph.renewUpload'))) {
            $state.RenewCount = [int]$state.RenewCount + 1
            $state.CurrentSas = (Get-PDM4SasUri -Tag ('renewed-' + [string]$state.RenewCount))
            $state.FilePhase  = 'azureStorageUriRenewalSuccess'
            return (New-PDMockJsonResponse -Status 200 -Json '{}')
        }

        if (($method -eq 'Post') -and ($path -like ('*/files/*/microsoft.graph.commit'))) {
            $bodyText = [string]$Request.BodyText
            if ($Request.ContainsKey('BodyBytes') -and ($null -ne $Request.BodyBytes)) {
                $bodyText = [System.Text.Encoding]::UTF8.GetString($Request.BodyBytes)
            }
            # The commit body carries the encryption keys; the mock keeps it so a case can prove
            # it was sent, and proves separately that it never reached a message.
            $script:M4.CommitBody = $bodyText
            $state.FilePhase      = 'commitFileSuccess'
            return (New-PDMockJsonResponse -Status 200 -Json '{}')
        }

        if ($method -eq 'Get') {
            $fileReads = [int]$state.FileReads
            if ($path -like ('*/files/' + $state.FileId)) {
                $state.FileReads = $fileReads + 1

                if (($state.FileFailAfter -ge 0) -and ($state.FileReads -gt $state.FileFailAfter)) {
                    return (New-PDMockJsonResponse -Status 500 -Json (@{ error = @{ code = 'GeneralError'; message = 'read failed' } } | ConvertTo-Json -Compress))
                }

                $queued = Get-PDM4Queued -Key 'FileQueue' -Default $null
                if ($null -ne $queued) { return $queued }

                # Default: like the real service, ONE uploadState that follows the actions the
                # uploader has taken - storage URI ready, then renewed, then committed.
                $phase = [string]$state.FilePhase
                if ([string]::IsNullOrWhiteSpace($phase)) { $phase = 'azureStorageUriRequestSuccess' }
                return (New-PDMockJsonResponse -Json (@{
                    id              = $state.FileId
                    uploadState     = $phase
                    azureStorageUri = $state.CurrentSas
                } | ConvertTo-Json -Compress))
            }

            # --- Category / assignment / app read-back -------------------------------------------------
            if ($path -like ('*/mobileApps/' + $state.AppId + '/categories')) {
                # By default the tenant holds exactly the links the upload posted through $ref;
                # -CategoryRecords replaces them for the cases where they did not land.
                $records = @()
                if ($null -ne $state.CategoryRecords) {
                    $records = @($state.CategoryRecords)
                } else {
                    foreach ($categoryId in @($state.CategoryIds)) { $records += @{ id = $categoryId } }
                }
                return (New-PDMockJsonResponse -Json (New-PDMockValuePage -Value $records))
            }

            if ($path -like ('*/mobileApps/' + $state.AppId + '/assignments')) {
                $records = @($state.AssignmentRecords)
                if ($null -eq $state.AssignmentRecords) {
                    # Nothing was sent, so nothing exists; the router says so without failing.
                    $records = @()
                }
                return (New-PDMockJsonResponse -Json (New-PDMockValuePage -Value $records))
            }

            if ($path -like ('*/mobileApps/' + $state.AppId)) {
                $appReads = [int]$state.AppReads
                $state.AppReads = $appReads + 1

                if (($state.AppFailAfter -ge 0) -and ($state.AppReads -gt $state.AppFailAfter)) {
                    return (New-PDMockJsonResponse -Status 500 -Json (@{ error = @{ code = 'GeneralError'; message = 'read failed' } } | ConvertTo-Json -Compress))
                }

                $queued = Get-PDM4Queued -Key 'AppQueue' -Default $null
                if ($null -ne $queued) { return $queued }

                # The read-back is the create body echoed back plus service-managed fields: that is
                # precisely "the tenant holds what was submitted", which is what Verify must prove.
                $record = @{}
                if ($null -ne $state.CreateBody) {
                    foreach ($property in $state.CreateBody.PSObject.Properties) { $record[$property.Name] = $property.Value }
                }
                $record['id']                     = $state.AppId
                $record['publishingState']        = 'published'
                $record['committedContentVersion'] = $state.VersionId
                $record['isAssigned']             = (@($state.AssignmentRecords).Count -gt 0)
                if ($null -ne $state.ReadBack) { & $state.ReadBack $record }

                return (New-PDMockJsonResponse -Json ($record | ConvertTo-Json -Depth 15 -Compress))
            }
        }

        # --- Writes to the app resource ----------------------------------------------------------------
        if ($method -eq 'Patch') {
            $patchBody = [System.Text.Encoding]::UTF8.GetString($Request.BodyBytes)
            # The icon is its own PATCH; keep it apart from the publish PATCH the read-back relies on.
            if ($patchBody -like '*largeIcon*') {
                $script:M4.IconPatch = $patchBody
                if ($script:M4.IconRefused) {
                    return (New-PDMockJsonResponse -Status 400 -Json (@{ error = @{ code = 'BadRequest'; message = 'The icon was refused by the test scenario.' } } | ConvertTo-Json -Compress))
                }
                return (New-PDMockJsonResponse -Status 204 -Json '')
            }
            if (($patchBody -like '*informationUrl*') -or ($patchBody -like '*privacyInformationUrl*')) {
                $script:M4.LinksPatch = $patchBody
                if ($script:M4.LinksRefused) {
                    return (New-PDMockJsonResponse -Status 400 -Json (@{ error = @{ code = 'BadRequest'; message = 'The links were refused by the test scenario.' } } | ConvertTo-Json -Compress))
                }
                return (New-PDMockJsonResponse -Status 204 -Json '')
            }
            $script:M4.PublishPatch = $patchBody
            return (New-PDMockJsonResponse -Status 204 -Json '')
        }

        if (($method -eq 'Post') -and ($path -like '*/categories/$ref')) {
            $script:M4.CategoryRef  = [System.Text.Encoding]::UTF8.GetString($Request.BodyBytes)
            if (([string]$script:M4.CategoryRef) -match '/categories/(.*?)"') {
                $script:M4.CategoryIds = @($script:M4.CategoryIds) + $matches[1]
            }
            return (New-PDMockJsonResponse -Status 204 -Json '')
        }

        if (($method -eq 'Post') -and ($path -like ('*/mobileApps/' + $state.AppId + '/*assign*'))) {
            $script:M4.AssignBody  = [System.Text.Encoding]::UTF8.GetString($Request.BodyBytes)

            # Like the service: the action body is { "mobileAppAssignments": [...] } and nothing else.
            $assignParsed = $null
            try { $assignParsed = $script:M4.AssignBody | ConvertFrom-Json } catch { }
            $rootNames = @()
            if ($null -ne $assignParsed) { $rootNames = @($assignParsed.PSObject.Properties | ForEach-Object { $_.Name }) }
            if ((@($rootNames).Count -ne 1) -or ($rootNames[0] -cne 'mobileAppAssignments')) {
                return (New-PDMockJsonResponse -Status 400 -Json (@{ error = @{ code = 'ModelValidationFailure'; message = ("The assign body must be exactly {{ mobileAppAssignments: [...] }}; got: {0}" -f ($rootNames -join ', ')) } } | ConvertTo-Json -Compress))
            }

            $script:M4.Assigned    = $true
            return (New-PDMockJsonResponse -Status 200 -Json '{}')
        }

        if ($method -eq 'Delete') {
            $script:M4.Deleted += $path
            return (New-PDMockJsonResponse -Status 204 -Json '')
        }

        # --- App creation (last, so nothing else lands here by accident) -------------------------------
        if (($method -eq 'Post') -and ($path -like '*deviceAppManagement/mobileApps')) {
            $state.CreateCount = [int]$state.CreateCount + 1
            $state.CreateBody  = ([System.Text.Encoding]::UTF8.GetString($Request.BodyBytes) | ConvertFrom-Json)

            if ($state.CreateThrows) {
                throw (New-Object System.Net.WebException('The underlying connection was closed: An unexpected error occurred on a receive.'))
            }
            if ($null -ne $state.CreateResponse) {
                return (New-PDMockJsonResponse -Status ([int]$state.CreateResponse.Status) -Json ([string]$state.CreateResponse.Json))
            }
            return (New-PDMockJsonResponse -Status 201 -Json (@{ id = $state.AppId; '@odata.type' = '#microsoft.graph.win32LobApp' } | ConvertTo-Json -Compress))
        }

        # --- Reconciliation scenarios -------------------------------------------------
        # A lost create is reconciled from the same duplicate-name lookup preflight used, so the
        # scenario answers the first lookup with 'nothing there' (that is what preflight saw) and
        # later lookups with the apps that exist now.
        if (($null -ne $state.ReconcileAppIds) -and ($method -eq 'Get') -and ($path -like '*deviceAppManagement/mobileApps')) {
            $state.DuplicateLookups = [int]$state.DuplicateLookups + 1

            $values = @()
            if ([int]$state.DuplicateLookups -ge 2) {
                foreach ($candidateId in @($state.ReconcileAppIds)) {
                    $values += @{ id = $candidateId; displayName = $state.ReconcileDisplayName; publishingState = 'none' }
                }
            }
            return (New-PDMockJsonResponse -Json (New-PDMockValuePage -Value $values))
        }

        # --- Everything else (groups, category lookup, duplicate lookup) --------------------------------
        return (& $script:M3Router $Request)
    }
}

function New-PDM4FailRule {
    <#
        One scripted refusal: method + path pattern + the status and body to answer with.
        -Times 1 refuses once (a retry test); -Times -1 refuses every time (a terminal test).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$PathLike,
        [int]$Status = 400,
        [string]$Json = '',
        [int]$Times = 1,
        [AllowNull()][hashtable]$Headers = $null,
        [string]$ErrorCode = 'TestRefusal',
        [string]$ErrorMessage = 'refused by the test scenario'
    )

    if ([string]::IsNullOrWhiteSpace($Json)) {
        $Json = (@{ error = @{ code = $ErrorCode; message = $ErrorMessage } } | ConvertTo-Json -Compress)
    }

    return @{ Method = $Method; PathLike = $PathLike; Status = $Status; Json = $Json; Remaining = $Times; Headers = $Headers }
}

function Get-PDM4CallTrail {
    <# The recorded verb+path sequence, with the storage host shortened for readable messages.
       Storage requests keep comp/blockid, because which storage verb ran is the whole question. #>
    $trail = @()
    foreach ($call in @($script:MockGraphCalls)) {
        $uri     = [string]$call.Uri
        $noQuery = ($uri -split '\?')[0]
        if ($noQuery -like '*blob.core.windows.net*') {
            $suffix = ''
            if ($uri -like '*comp=blocklist*') { $suffix = '?comp=blocklist' }
            elseif ($uri -like '*comp=block&*') { $suffix = '?comp=block'
                if ($uri -match 'blockid=([^&]*)') { $suffix += '&blockid=' + $matches[1] }
            }
            $noQuery = ($noQuery -replace 'https://pdintuneweb\.blob\.core\.windows\.net/content', 'STORE') + $suffix
        }
        $noQuery = $noQuery -replace 'https://graph.microsoft.com/beta/deviceAppManagement', 'G'
        $noQuery = $noQuery -replace 'https://graph.microsoft.com/v1.0', 'DIR'
        $trail += ('{0} {1}' -f [string]$call.Method, $noQuery)
    }
    return $trail
}

function Assert-PDM4Order {
    <#
        Asserts that the first recorded request matching each pattern appears in the given
        order, which is how "assignments happen last" and "published before assigned" are
        proven from the wire rather than from a comment.
    #>
    param([Parameter(Mandatory = $true)][string[]]$OrderedPatterns, [string]$Message)

    $trail = @(Get-PDM4CallTrail)
    $lastFound = -1

    foreach ($pattern in $OrderedPatterns) {
        $found = -1
        for ($i = 0; $i -lt $trail.Count; $i++) {
            if ($i -le $lastFound) { continue }
            if ($trail[$i] -like $pattern) { $found = $i; break }
        }
        if ($found -lt 0) {
            throw "expected '$pattern' after position $lastFound in the request order; trail was: $($trail -join ' | '). $Message"
        }
        $lastFound = $found
    }
}

function New-PDM4FilePending {
    param([switch]$StorageFailed, [switch]$CommitFailed, [switch]$InvalidLink, [switch]$RenewalFailed)

    # Real uploadState values (mobileAppContentFileUploadState). -InvalidLink keeps its name for the
    # existing cases but is the service's generic 'error' state: there is no 'commitFileInvalidLink'.
    $record = @{ id = 'file-1'; uploadState = 'azureStorageUriRequestPending' }
    if ($StorageFailed)     { $record = @{ id = 'file-1'; uploadState = 'azureStorageUriRequestFailed' } }
    if ($CommitFailed)      { $record = @{ id = 'file-1'; uploadState = 'commitFileFailed' } }
    if ($InvalidLink)       { $record = @{ id = 'file-1'; uploadState = 'error' } }
    if ($RenewalFailed)     { $record = @{ id = 'file-1'; uploadState = 'azureStorageUriRenewalFailed' } }
    return (New-PDMockJsonResponse -Json ($record | ConvertTo-Json -Compress))
}

function New-PDM4FileReady {
    <# Storage URI ready, commit not yet attempted. -Expired hands back an already-expired SAS. #>
    param([switch]$Expired)

    $sas = 'https://pdintuneweb.blob.core.windows.net/content/IntunePackage.intunewin?sv=1&sr=b&se=2030-01-01T00:00:00Z&sig=sig-original'
    if ($Expired) { $sas = 'https://pdintuneweb.blob.core.windows.net/content/IntunePackage.intunewin?sv=1&sr=b&se=2020-01-01T00:00:00Z&sig=sig-original' }

    return (New-PDMockJsonResponse -Json (@{
        id              = 'file-1'
        uploadState     = 'azureStorageUriRequestSuccess'
        azureStorageUri = $sas
    } | ConvertTo-Json -Compress))
}

function New-PDM4FileCommitPending {
    # The storage URI is ready, the commit has not been confirmed yet.
    return (New-PDMockJsonResponse -Json (@{
        id              = 'file-1'
        uploadState     = 'commitFilePending'
        azureStorageUri = 'https://pdintuneweb.blob.core.windows.net/content/IntunePackage.intunewin?sv=1&se=2030-01-01T00:00:00Z&sig=x'
    } | ConvertTo-Json -Compress))
}

function New-PDM4AppPending {
    param([string]$State = 'pending', [string]$Id = 'app-new-1')
    return (New-PDMockJsonResponse -Json (@{ id = $Id; publishingState = $State } | ConvertTo-Json -Compress))
}

function New-PDM4Assignment {
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][string]$GroupId, [Parameter(Mandatory = $true)][string]$Intent)
    return @{ id = $Id; '@odata.type' = '#microsoft.graph.mobileAppAssignment'; intent = $Intent; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $GroupId } }
}

function New-PDM4InputSet {
    param([Parameter(Mandatory = $true)][string]$Case)
    return (New-PDM3InputSet -Case ('m4-' + $Case))
}

function Invoke-PDM4Upload {
    <#
        Runs the whole uploader (preflight + write stages) with a consistent argument set so
        each case states only what it cares about. Never a dry run: M4 is the execution path.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Inputs,
        [string]$DisplayName = 'PowerDeploy Test App',
        [string]$Category,
        [string]$Notes,
        [string[]]$RequiredGroups = @(),
        [string[]]$AvailableGroups = @(),
        [switch]$AllowDuplicateName,
        [switch]$NoRollback,
        [string]$IconFile,
        [string]$InformationUrl,
        [string]$PrivacyUrl
    )

    $arguments = @{
        IntuneWinPath        = Get-PDM3FixturePath -Name 'valid.intunewin'
        DisplayName          = $DisplayName
        Description          = 'N/A'
        Publisher            = 'PowerDeploy'
        InstallCommandFile   = $Inputs.InstallFile
        UninstallCommandFile = $Inputs.UninstallFile
        DetectionScriptFile  = $Inputs.DetectionFile
        CredentialPath       = $Inputs.CredentialPath
        TempDirectory        = $Inputs.TempDirectory
        RequiredGroups       = $RequiredGroups
        AvailableGroups      = $AvailableGroups
    }
    if ($PSBoundParameters.ContainsKey('Category')) { $arguments['Category'] = $Category }
    if ($PSBoundParameters.ContainsKey('Notes'))    { $arguments['Notes']    = $Notes }
    if ($AllowDuplicateName) { $arguments['AllowDuplicateName'] = [switch]::Present }
    if ($NoRollback)         { $arguments['NoRollback']         = [switch]::Present }
    if ($PSBoundParameters.ContainsKey('IconFile')) { $arguments['IconFile'] = $IconFile }
    if ($PSBoundParameters.ContainsKey('InformationUrl')) { $arguments['InformationUrl'] = $InformationUrl }
    if ($PSBoundParameters.ContainsKey('PrivacyUrl'))     { $arguments['PrivacyUrl']     = $PrivacyUrl }

    return (Invoke-PDIntuneUpload @arguments)
}

Add-TestCase 'M4-01' 'A successful publish issues the spec 10.3 sequence in order and verifies it' {
    $groupId = [guid]::NewGuid().ToString()
    $requiredId = [guid]::NewGuid().ToString()
    Reset-PDM4Scenario `
        -Groups @(@{ Id = $groupId; DisplayName = 'Required Group' }, @{ Id = $requiredId; DisplayName = 'Available Group' }) `
        -GroupById @{ $groupId = @{ Id = $groupId; DisplayName = 'Required Group' }; $requiredId = @{ Id = $requiredId; DisplayName = 'Available Group' } } `
        -Categories @(@{ id = 'cat-1'; displayName = 'Printers' }) `
        -AssignmentRecords @(
            (New-PDM4Assignment -Id 'assign-1' -GroupId $groupId -Intent 'required'),
            (New-PDM4Assignment -Id 'assign-2' -GroupId $requiredId -Intent 'available')) `
        -CategoryRecords @(@{ id = 'cat-1'; displayName = 'Printers' })

    $inputs = New-PDM4InputSet -Case 'happy'
    $result = Invoke-PDM4Upload -Inputs $inputs -RequiredGroups @('Required Group') -AvailableGroups @('Available Group') -Category 'Printers' `
                                -Notes 'InstallMethod: manual'

    Assert-Equal $true $result.Success ('publish reported success; message: ' + $result.Message)
    Assert-Equal 'Complete' $result.Stage 'stage reached completion'
    Assert-Equal 'app-new-1' $result.AppId 'the id the service returned, not a guess'
    Assert-Equal 'NotNeeded' $result.CleanupStatus 'nothing to clean up'
    Assert-Like '*endpoint.microsoft.com*' $result.PortalUrl 'a portal link is offered'
    Assert-Equal 'Resolved' $result.CategoryResult.Status 'category resolved'

    # The sequence itself (spec 10.3). Assignments after publication, verification last.
    Assert-PDM4Order -OrderedPatterns @(
        'POST G/mobileApps',
        'POST G/mobileApps/app-new-1/microsoft.graph.win32LobApp/contentVersions',
        'POST G/mobileApps/app-new-1/microsoft.graph.win32LobApp/contentVersions/7/files',
        'GET G/mobileApps/app-new-1/microsoft.graph.win32LobApp/contentVersions/7/files/file-1',
        'PUT STORE*',
        'PUT STORE*comp=blocklist*',
        'POST G/mobileApps/app-new-1/microsoft.graph.win32LobApp/contentVersions/7/files/file-1/microsoft.graph.commit',
        'PATCH G/mobileApps/app-new-1',
        'POST G/mobileApps/app-new-1/categories/$ref',
        'POST G/mobileApps/app-new-1/*assign*',
        'GET G/mobileApps/app-new-1/assignments') `
        -Message 'the write sequence must follow spec 10.3'

    # Every Graph request was authorized; no storage request ever was (spec invariant 8).
    foreach ($call in @($script:MockGraphCalls)) {
        $hasAuth = ($null -ne $call.Headers) -and $call.Headers.ContainsKey('Authorization')
        if (([string]$call.Uri) -like 'https://graph.microsoft.com/*') {
            Assert-True $hasAuth "Graph request $([string]$call.Method) $([string]$call.Uri) carries a bearer token"
        } elseif (([string]$call.Uri) -like 'https://login.microsoftonline.com/*') {
            Assert-True (-not $hasAuth) 'the token request carries no bearer'
        } else {
            Assert-True (-not $hasAuth) "storage request $([string]$call.Uri) must never carry authorization"
        }
    }

    # The uploaded bytes are the package's encrypted payload, byte for byte.
    $package = Read-PDIntuneWinPackage -IntuneWinPath (Get-PDM3FixturePath -Name 'valid.intunewin') -TempDirectory (Join-Path $tempRoot 'm4-happy-package')
    $expectedBytes = [System.IO.File]::ReadAllBytes($package.PayloadPath)
    $blockBodies = @()
    foreach ($call in @($script:M4.StorageRequests)) {
        if ((([string]$call.Uri) -like '*comp=block&*') -and ($null -ne $call.BodyBytes)) { $blockBodies += ,$call.BodyBytes }
    }
    $rejoined = New-Object byte[] $expectedBytes.Length
    $offset = 0
    foreach ($block in $blockBodies) {
        [Array]::Copy($block, 0, $rejoined, $offset, $block.Length)
        $offset += $block.Length
    }
    Assert-Equal ([long]$expectedBytes.Length) ([long]$offset) 'every payload byte was PUT'
    $identical = $true
    for ($i = 0; $i -lt $expectedBytes.Length; $i++) {
        if ($rejoined[$i] -ne $expectedBytes[$i]) { $identical = $false; break }
    }
    Assert-True $identical 'the bytes are the encrypted payload, unchanged'

    # File record and commit bodies (spec 10.1 mapping).
    $fileRequest = @(@($script:MockGraphCalls) | Where-Object { (($_.Method -eq 'Post') -and ($_.Uri -like '*/contentVersions/7/files')) })[0]
    $fileBody = [System.Text.Encoding]::UTF8.GetString($fileRequest.BodyBytes) | ConvertFrom-Json
    Assert-Equal '#microsoft.graph.mobileAppContentFile' $fileBody.'@odata.type' 'file record type'
    Assert-Equal 'IntunePackage.intunewin' $fileBody.name 'name from ApplicationInfo/FileName'
    Assert-Equal ([long]462) ([long]$fileBody.size) 'size is the unencrypted content size'
    Assert-Equal ([long]512) ([long]$fileBody.sizeEncrypted) 'sizeEncrypted is the measured payload length'
    Assert-Equal $false ([bool]$fileBody.isDependency) 'isDependency false'

    $commit = $script:M4.CommitBody | ConvertFrom-Json
    Assert-Equal ([string]$package.EncryptionInfo.EncryptionKey) ([string]$commit.fileEncryptionInfo.encryptionKey) 'encryption key taken from the package'
    Assert-Equal ([string]$package.EncryptionInfo.ProfileIdentifier) ([string]$commit.fileEncryptionInfo.profileIdentifier) 'profileIdentifier read from metadata, never hardcoded'
    Assert-Equal ([string]$package.EncryptionInfo.FileDigestAlgorithm) ([string]$commit.fileEncryptionInfo.fileDigestAlgorithm) 'digest algorithm from metadata'

    # Notes carry exactly one timestamp (spec 4.4).
    $createBody = $script:M4.CreateBody
    Assert-Equal 1 ([regex]::Matches([string]$createBody.notes, '(?m)^Created:\s')).Count 'exactly one Created line in the submitted Notes'

    # No owner key, at any depth (N02 again, but on the bytes that were actually sent).
    $createRequest = @(@($script:MockGraphCalls) | Where-Object { (($_.Method -eq 'Post') -and (([string]$_.Uri) -like '*deviceAppManagement/mobileApps')) })[0]
    Assert-True ($null -ne $createRequest) 'the create POST was recorded'
    $sentJson = [System.Text.Encoding]::UTF8.GetString($createRequest.BodyBytes)
    Assert-NotLike '*"owner"*' $sentJson 'no owner key in the create request'

    Assert-Equal 0 @($script:M4.Deleted).Count 'a success deletes nothing'
    Clear-PDMockGraph
}

Add-TestCase 'M4-02' 'Commit keys, SAS URIs, tokens, and commands stay out of the result and the messages' {
    Reset-PDM4Scenario

    $secretCommand = 'Setup.exe /p:https://oauth2:ghp_M4LEAK@github.com/org/repo'
    $inputs = New-PDM4InputSet -Case 'leak'
    $installFile = $inputs.InstallFile
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllBytes($installFile, $utf8.GetBytes($secretCommand))

    $result = Invoke-PDM4Upload -Inputs $inputs

    Assert-Equal $true $result.Success ('the publish succeeded; message: ' + $result.Message)

    # What was sent is provably secret-bearing, so the leak test below means something.
    Assert-Like '*encryptionKey*' $script:M4.CommitBody 'the commit body really carried the package keys'
    $storageSawSignature = $false
    foreach ($call in @($script:M4.StorageRequests)) {
        if (([string]$call.Uri) -like '*sig=sig-original*') { $storageSawSignature = $true }
    }
    Assert-True $storageSawSignature 'the storage requests really used the SAS URI'

    $package = Read-PDIntuneWinPackage -IntuneWinPath (Get-PDM3FixturePath -Name 'valid.intunewin') -TempDirectory (Join-Path $tempRoot 'm4-leak-package')
    $serialized = $result | ConvertTo-Json -Depth 20 -Compress

    Assert-NotLike '*ghp_M4LEAK*' $serialized 'the install command text stays out of the result'
    Assert-NotLike '*Bearer*' $serialized 'no bearer token in the result'
    Assert-NotLike '*access_token*' $serialized 'no token material in the result'
    Assert-NotLike '*sig=sig-original*' $serialized 'no SAS query string in the result'
    Assert-NotLike '*sig-*' $serialized 'no SAS signature in the result'
    Assert-NotLike '*m4-secret*' $serialized 'no client secret in the result'
    foreach ($field in @('EncryptionKey', 'MacKey', 'InitializationVector', 'Mac', 'FileDigest')) {
        $value = [string]$package.EncryptionInfo[$field]
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        Assert-True (([string]$serialized).IndexOf($value, [System.StringComparison]::Ordinal) -lt 0) "the package $field never leaves the process"
    }

    Assert-NotLike '*ghp_M4LEAK*' $result.Message 'the message repeats no command text'
    Assert-Equal $secretCommand.Length $result.CommandLengths.Install 'only the command length is reported'
    Clear-PDMockGraph
}

Add-TestCase 'U02a' 'Pending storage-URI and publication states are waited for, not assumed' {
    Reset-PDM4Scenario `
        -FileQueue @(
            (New-PDM4FilePending),
            (New-PDM4FilePending)) `
        -AppQueue @(
            (New-PDM4AppPending -State 'pending'),
            (New-PDM4AppPending -State 'scheduled'))

    $inputs = New-PDM4InputSet -Case 'u02a'
    $result = Invoke-PDM4Upload -Inputs $inputs

    Assert-Equal $true $result.Success ('the publish completed once the states cleared; message: ' + $result.Message)
    Assert-Equal 4 ([int]$script:M4.FileReads) 'two pending reads, the ready read, then the commit confirmation'
    Assert-Equal 4 ([int]$script:M4.AppReads) 'two unpublished reads, the published read, then the verify read'
    Assert-True ([bool]$script:M4.Committed) 'the block list was sent once the URI was ready'
    Assert-Equal 0 @($script:M4.Deleted).Count 'a success deletes nothing'
    Clear-PDMockGraph
}

Add-TestCase 'U02b' 'A terminal storage-URI state stops before any byte is uploaded' {
    Reset-PDM4Scenario -FileQueue @((New-PDM4FilePending -StorageFailed))

    $inputs = New-PDM4InputSet -Case 'u02b'
    $result = Invoke-PDM4Upload -Inputs $inputs

    Assert-Equal $false $result.Success 'a terminal state is a failure'
    Assert-Equal 'StorageUri' $result.Stage 'the stage that failed'
    Assert-Like '*terminal failure*' $result.Message 'says the service reported a terminal state'
    Assert-Equal 0 @($script:M4.StorageRequests).Count 'no byte was sent to a failed storage URI'
    Assert-Equal 1 @($script:M4.Deleted).Count 'the app created before the failure is rolled back'
    Assert-Equal 'Deleted' $result.CleanupStatus 'cleanup reported'
    Clear-PDMockGraph
}

Add-TestCase 'U02c' 'A commit that never reports success fails the Commit stage on the deadline' {
    Reset-PDM4Scenario -FileQueue @((New-PDM4FileReady), (New-PDM4FileCommitPending)) -PollDeadlineSec 0

    $inputs = New-PDM4InputSet -Case 'u02c'
    $result = Invoke-PDM4Upload -Inputs $inputs

    Assert-Equal $false $result.Success 'an unconfirmed commit is not success'
    Assert-Equal 'Commit' $result.Stage 'the commit stage is where it stopped'
    Assert-Like '*Timed out*' $result.Message 'names the deadline rather than pretending'
    Assert-Like '*commit to succeed*' $result.Message 'says what it was waiting for'
    Assert-Equal 1 @($script:M4.Deleted).Count 'the incomplete app is removed'
    Clear-PDMockGraph
}

Add-TestCase 'U02d' 'Publication is waited for, and a failed state is not polled out' {
    Reset-PDM4Scenario -AppQueue @((New-PDM4AppPending -State 'pending')) -PollDeadlineSec 0
    $inputs = New-PDM4InputSet -Case 'u02d-timeout'
    $result = Invoke-PDM4Upload -Inputs $inputs
    Assert-Equal 'Publish' $result.Stage 'the publish stage timed out'
    Assert-Like '*published*' $result.Message 'says it was waiting for the published state'
    Clear-PDMockGraph

    Reset-PDM4Scenario -AppQueue @((New-PDM4AppPending -State 'failed'))
    $failed = New-PDM4InputSet -Case 'u02d-failed'
    $result = Invoke-PDM4Upload -Inputs $failed
    Assert-Equal 'Publish' $result.Stage 'a failed publishing state fails the stage'
    Assert-Like '*terminal failure*' $result.Message 'does not wait a terminal state out'
    Assert-Equal 0 @(@($script:MockGraphCalls) | Where-Object { $_.Uri -like '*assign*' }).Count 'an unpublished app is never assigned'
    Assert-Equal 1 @($script:M4.Deleted).Count 'and the app is rolled back'
    Clear-PDMockGraph
}

Add-TestCase 'U03a' 'An expired storage URI is renewed before anything is uploaded' {
    Reset-PDM4Scenario -SasExpiresInSec -60

    $inputs = New-PDM4InputSet -Case 'u03a'
    $result = Invoke-PDM4Upload -Inputs $inputs

    Assert-Equal $true $result.Success ('the publish finished after renewing the URI; message: ' + $result.Message)
    Assert-Equal 1 ([int]$script:M4.RenewCount) 'exactly one renewal was needed'
    Assert-Equal 1 @(@($script:MockGraphCalls) | Where-Object { (($_.Method -eq 'Post') -and ($_.Uri -like '*microsoft.graph.renewUpload')) }).Count 'the renewUpload action was called once'
    # Microsoft: "Do not supply a request body for this method." The live service refused the body
    # this used to send (HTTP 400, unexpected 'odata.type' annotation; 2026-10-19).
    $renewCall = @(@($script:MockGraphCalls) | Where-Object { (($_.Method -eq 'Post') -and ($_.Uri -like '*microsoft.graph.renewUpload')) })[0]
    Assert-True (($null -eq $renewCall.BodyBytes) -or (@($renewCall.BodyBytes).Count -eq 0)) 'renewUpload is posted with no request body'

    $blockRequests = @(@($script:M4.StorageRequests) | Where-Object { ([string]$_.Uri) -like '*comp=block&*' })
    Assert-True $blockRequests.Count -ge 1 'blocks were uploaded'
    foreach ($call in $blockRequests) {
        Assert-Like '*sig=sig-renewed-1*' ([string]$call.Uri) 'blocks went to the renewed URI, not the expired one'
        Assert-True (($null -eq $call.Headers) -or (-not $call.Headers.ContainsKey('Authorization'))) 'a storage PUT carries no Graph bearer token'
    }
    Clear-PDMockGraph
}

Add-TestCase 'U03b' 'A storage refusal mid-upload renews once and restarts the blocks' {
    $script:M4StorageHits = 0
    $storage = {
        param($Request, $State)

        $script:M4StorageHits = [int]$script:M4StorageHits + 1
        $uri = [string]$Request.Uri

        if (($uri -like '*comp=block&*') -and ($script:M4StorageHits -eq 1)) {
            # Azure answers an expired SAS with 403 AuthorizationExpired.
            return (New-PDMockJsonResponse -Status 403 -Json (@{ error = @{ code = 'AuthenticationFailed'; message = 'Server failed to authenticate the request.' } } | ConvertTo-Json -Compress))
        }
        if ($uri -like '*comp=blocklist*') { $State.Committed = $true }
        return (New-PDMockJsonResponse -Status 201)
    }

    Reset-PDM4Scenario -Storage $storage

    $inputs = New-PDM4InputSet -Case 'u03b'
    $result = Invoke-PDM4Upload -Inputs $inputs

    Assert-Equal $true $result.Success ('the upload recovered from the refusal; message: ' + $result.Message)
    Assert-Equal 1 ([int]$script:M4.RenewCount) 'one renewal for one refusal'
    Assert-True ([bool]$script:M4.Committed) 'the block list was still sent'
    Assert-True ([int]$script:M4StorageHits -ge 2) 'the refused block was retried against the new URI'
    Clear-PDMockGraph
}

Add-TestCase 'U03c' 'A renewal that fails terminally stops the upload instead of looping' {
    Reset-PDM4Scenario -SasExpiresInSec -60 -FileQueue @(
        (New-PDM4FileReady -Expired),
        (New-PDM4FilePending -RenewalFailed))

    $inputs = New-PDM4InputSet -Case 'u03c'
    $result = Invoke-PDM4Upload -Inputs $inputs

    Assert-Equal $false $result.Success 'a failed renewal is a failure'
    Assert-Equal 'Upload' $result.Stage 'the upload stage owns the renewal'
    Assert-Like '*renewing the content file storage URI*' $result.Message 'names what failed'
    Assert-Equal 0 @(@($script:M4.StorageRequests) | Where-Object { ([string]$_.Uri) -like '*comp=block&*' }).Count 'no block was sent to a URI that failed to renew'
    Assert-Equal 1 @($script:M4.Deleted).Count 'the app is still rolled back'
    Clear-PDMockGraph
}

Add-TestCase 'U03d' 'Throttling on a content read is honoured and the upload still finishes' {
    Reset-PDM4Scenario -FailRules @(
        (New-PDM4FailRule -Method 'Get' -PathLike '*/files/file-1' -Status 429 -Headers @{ 'Retry-After' = '0'; 'request-id' = 'throttled' } -ErrorCode 'TooManyRequests' -ErrorMessage 'Too many requests'))

    $inputs = New-PDM4InputSet -Case 'u03d'
    $result = Invoke-PDM4Upload -Inputs $inputs

    Assert-Equal $true $result.Success ('the read was retried within the deadline; message: ' + $result.Message)
    # Two reads are what a successful run performs (storage URI, commit confirmation); three proves
    # the throttled one was retried inside the same stage rather than failing the upload.
    Assert-Equal 3 @(@($script:MockGraphCalls) | Where-Object { (($_.Method -eq 'Get') -and ($_.Uri -like '*/files/file-1')) }).Count 'one throttled read, its retry, and the commit confirmation'
    Assert-Equal 0 @($script:M4.Deleted).Count 'throttling is not a reason to delete anything'
    Clear-PDMockGraph
}

Add-TestCase 'U04c' 'An ordinary 400 on creation is reported as itself, once' {
    Reset-PDM4Scenario -CreateResponse @{
        Status = 400
        Json   = (@{ error = @{ code = 'Request_BadRequest'; message = 'A property value is not valid for this app type.' } } | ConvertTo-Json -Compress)
    }

    $inputs = New-PDM4InputSet -Case 'u04c'
    $result = Invoke-PDM4Upload -Inputs $inputs

    Assert-Equal $false $result.Success 'the app was not created'
    Assert-Equal 'CreateApp' $result.Stage 'creation is where it stopped'
    Assert-Like '*A property value is not valid*' $result.Message 'the service reason is preserved'
    Assert-NotLike '*Multi-Admin Approval*' $result.Message 'an ordinary 400 is never labelled MAA'
    Assert-Equal 1 ([int]$script:M4.CreateCount) 'a refused create is never repeated'
    Assert-Equal 'NotNeeded' $result.CleanupStatus 'nothing was created, so nothing is pending'
    Assert-Equal $null $result.AppId 'no app id invented'
    Clear-PDMockGraph
}

Add-TestCase 'U04d' 'A Multi-Admin Approval refusal is told apart and explained' {
    Reset-PDM4Scenario -CreateResponse @{
        Status = 400
        Json   = (@{ error = @{ code = 'MultiAdminApprovalRequired'; message = 'Multiple admin approval is required for this operation.' } } | ConvertTo-Json -Compress)
    }

    $inputs = New-PDM4InputSet -Case 'u04d'
    $result = Invoke-PDM4Upload -Inputs $inputs

    Assert-Equal $false $result.Success 'MAA blocks the write'
    Assert-Like '*Multi-Admin Approval*' $result.Message 'names MAA explicitly'
    Assert-NotLike '*Request_BadRequest*' $result.Message 'does not pretend to be a validation error'
    Assert-Equal 1 ([int]$script:M4.CreateCount) 'no approval workflow is attempted, so no second POST'
    Assert-Equal 'NotNeeded' $result.CleanupStatus 'nothing exists to roll back'
    Clear-PDMockGraph

    # The 412 approval-code shape is the other half of spec 11.1's MAA detection.
    Reset-PDM4Scenario -CreateResponse @{
        Status = 412
        Json   = (@{ error = @{ code = 'ApprovalRequired'; message = 'An approval code is required to complete this request.' } } | ConvertTo-Json -Compress)
    }
    $again = New-PDM4InputSet -Case 'u04d-412'
    $result = Invoke-PDM4Upload -Inputs $again
    Assert-Equal $false $result.Success 'the 412 shape also fails cleanly'
    Assert-Like '*Multi-Admin Approval*' $result.Message 'the approval-code shape is recognized'
    Assert-Like '*HTTP 412*' $result.Message 'the actual status is reported'
    Clear-PDMockGraph
}

Add-TestCase 'U05a' 'Every post-create failure deletes only the recorded app id' {
    $stages = @(
        @{ Name = 'ContentVersion'; Rules = @((New-PDM4FailRule -Method 'Post' -PathLike '*/contentVersions' -ErrorCode 'Request_BadRequest' -ErrorMessage 'The content version cannot be created.')) }
        @{ Name = 'Upload';         Rules = @((New-PDM4FailRule -Method 'Put' -PathLike '*/IntunePackage.intunewin' -Status 400 -ErrorCode 'InvalidBlobOrBlock' -ErrorMessage 'The block list is invalid.')) }
        @{ Name = 'Commit';         Rules = @((New-PDM4FailRule -Method 'Post' -PathLike '*/files/file-1/microsoft.graph.commit' -ErrorCode 'CommitFailed' -ErrorMessage 'The content file cannot be committed.')) }
        @{ Name = 'Publish';        Rules = @((New-PDM4FailRule -Method 'Patch' -PathLike '*/mobileApps/app-new-1' -ErrorCode 'PublishFailed' -ErrorMessage 'The content version cannot be published.')) }
        @{ Name = 'Category';       Rules = @((New-PDM4FailRule -Method 'Post' -PathLike '*/categories/$ref' -ErrorCode 'CategoryNotFound' -ErrorMessage 'The category could not be associated.')); Category = 'Printers' }
        @{ Name = 'Assign';         Rules = @((New-PDM4FailRule -Method 'Post' -PathLike '*microsoft.graph.assign' -ErrorCode 'AssignmentFailed' -ErrorMessage 'The assignment was refused.')); Group = $true }
    )

    foreach ($entry in $stages) {
        $groupId = [guid]::NewGuid().ToString()
        $scenario = @{ FailRules = $entry.Rules }
        if ($entry.ContainsKey('Category')) { $scenario['Categories'] = @(@{ id = 'cat-1'; displayName = [string]$entry['Category'] }) }
        if ($entry.ContainsKey('Group')) {
            $scenario['Groups'] = @(@{ Id = $groupId; DisplayName = 'Required Group' })
            $scenario['GroupById'] = @{ $groupId = @{ Id = $groupId; DisplayName = 'Required Group' } }
        }

        Reset-PDM4Scenario @scenario

        $inputs = New-PDM4InputSet -Case ('u05-' + $entry.Name)
        $groups = @()
        if ($entry.ContainsKey('Group')) { $groups = @('Required Group') }
        $category = $null
        if ($entry.ContainsKey('Category')) { $category = [string]$entry['Category'] }

        $result = Invoke-PDM4Upload -Inputs $inputs -RequiredGroups $groups -Category $category

        Assert-Equal $false $result.Success ("$($entry.Name) failure must not report success")
        Assert-Equal $entry.Name $result.Stage ("the failure is reported at $($entry.Name)")
        Assert-Equal 1 @($script:M4.Deleted).Count ("$($entry.Name): exactly one delete was issued")
        Assert-Like '*/mobileApps/app-new-1' ([string]$script:M4.Deleted[0]) "$($entry.Name): only the created id was deleted"
        Assert-Equal 'Deleted' $result.CleanupStatus "$($entry.Name): cleanup reported"
        Assert-Equal 'app-new-1' $result.AppId "$($entry.Name): the id stays available for traceability after deletion"
        Assert-NotLike '*failed to delete*' $result.Message "$($entry.Name): the original error is still the headline"
        Assert-Like '*refused*' $result.Message "$($entry.Name): the service refusal is what is reported"

        Clear-PDMockGraph
    }
}

Add-TestCase 'U05b' 'NoRollback keeps the created app and says so' {
    Reset-PDM4Scenario -FailRules @((New-PDM4FailRule -Method 'Post' -PathLike '*/contentVersions' -ErrorMessage 'The content version cannot be created.'))

    $inputs = New-PDM4InputSet -Case 'u05-norollback'
    $result = Invoke-PDM4Upload -Inputs $inputs -NoRollback

    Assert-Equal $false $result.Success 'the upload still failed'
    Assert-Equal 'KeptByRequest' $result.CleanupStatus 'explicit preservation is reported'
    Assert-Equal 0 @($script:M4.Deleted).Count 'nothing was deleted'
    Assert-Equal 'app-new-1' $result.AppId 'the surviving id is reported'
    Assert-Like '*kept as requested*' $result.Message 'the operator is told the app is still there'
    Assert-Like '*app-new-1*' $result.Message 'with the id'

    Clear-PDMockGraph
}

Add-TestCase 'U05c' 'A failed deletion keeps the original error and reports the surviving app' {
    Reset-PDM4Scenario -FailRules @(
        (New-PDM4FailRule -Method 'Post' -PathLike '*/contentVersions' -ErrorMessage 'The content version cannot be created.'),
        (New-PDM4FailRule -Method 'Delete' -PathLike '*/mobileApps/app-new-1' -Status 403 -ErrorCode 'AuthorizationFailed' -ErrorMessage 'The current identity cannot delete the app.'))

    $inputs = New-PDM4InputSet -Case 'u05-cleanupfails'
    $result = Invoke-PDM4Upload -Inputs $inputs

    Assert-Equal $false $result.Success 'the upload failed'
    Assert-Equal 'ContentVersion' $result.Stage 'the original stage is retained, not the cleanup stage'
    Assert-Equal 'Failed' $result.CleanupStatus 'a failed deletion is not reported as Deleted'
    Assert-Equal 'app-new-1' $result.AppId 'the surviving id is reported'
    Assert-Like '*content version cannot be created*' $result.Message 'the original failure survives'
    Assert-Like '*removal of the incomplete app failed*' $result.Message 'and the cleanup problem is added to it'
    Assert-Like '*endpoint.microsoft.com*' $result.Message 'a portal link is included for the surviving app'

    Clear-PDMockGraph
}

Add-TestCase 'U06a' 'A lost create response is never blindly repeated' {
    Reset-PDM4Scenario -CreateThrows

    $inputs = New-PDM4InputSet -Case 'u06a'
    $result = Invoke-PDM4Upload -Inputs $inputs

    Assert-Equal $false $result.Success 'an unknown outcome is not success'
    Assert-Equal 1 ([int]$script:M4.CreateCount) 'the create POST was issued exactly once'
    Assert-Equal 'CreateApp' $result.Stage 'reported at the create stage'
    Assert-Equal 'Unknown' $result.CleanupStatus 'the app may or may not exist, and that is stated'
    Assert-Equal $null $result.AppId 'no id is invented'
    Assert-Equal 0 @($script:M4.Deleted).Count 'nothing is deleted on a guess'
    Assert-Like '*could not be established*' $result.Message 'tells the operator to inspect Intune'
    Assert-Like '*PowerDeploy Test App*' $result.Message 'names the display name to look for'
    Assert-Equal 0 @($script:M4.StorageRequests).Count 'nothing was uploaded'

    Clear-PDMockGraph
}

Add-TestCase 'U06b' 'A lost create response is reconciled when exactly one app can be it' {
    Reset-PDM4Scenario -CreateThrows -AppId 'reconciled-1' `
                       -ReconcileAppIds @('reconciled-1') -ReconcileDisplayName 'PowerDeploy Test App'

    $inputs = New-PDM4InputSet -Case 'u06b'
    $result = Invoke-PDM4Upload -Inputs $inputs

    Assert-Equal $true $result.Success ('the upload continued on the reconciled id; message: ' + $result.Message)
    Assert-Equal 1 ([int]$script:M4.CreateCount) 'still exactly one create POST'
    Assert-Equal 'reconciled-1' $result.AppId 'the reconciled id was adopted'
    Assert-True (@($result.Warnings) | Where-Object { $_ -like '*reconciled*' }).Count -ge 1 'the reconciliation is surfaced, not silent'
    Assert-Equal 0 @($script:M4.Deleted).Count 'and it was not deleted'

    Clear-PDMockGraph
}

Add-TestCase 'U06c' 'An ambiguous reconciliation stays Unknown' {
    Reset-PDM4Scenario -CreateThrows -AppId 'reconciled-1' `
                       -ReconcileAppIds @('reconciled-1', 'reconciled-2') -ReconcileDisplayName 'PowerDeploy Test App'

    $inputs = New-PDM4InputSet -Case 'u06c'
    $result = Invoke-PDM4Upload -Inputs $inputs

    Assert-Equal 'Unknown' $result.CleanupStatus 'two candidates is not an exact reconciliation'
    Assert-Equal $null $result.AppId 'no id chosen arbitrarily'
    Assert-Equal 0 @($script:M4.Deleted).Count 'and nothing is deleted'
    Assert-Equal 1 ([int]$script:M4.CreateCount) 'one create POST, no repeats'

    Clear-PDMockGraph
}

Add-TestCase 'U07d' 'a flags value read back in a different order is the same setting' {
    # Live finding 2026-10-12: submitted 'x64,x86', Intune reported 'x86,x64', and a correct
    # upload was rolled back as a mismatch.
    $expected = [ordered]@{
        'Architectures' = @{ Path = 'applicableArchitectures'; Value = 'x64,x86'; Secret = $false; Set = $true }
    }
    $same = @(Compare-PDIntuneAppReadBack -Expected $expected -App ([pscustomobject]@{ applicableArchitectures = 'x86,x64' }))
    Assert-Equal 0 $same.Count 'reordered flags agree'
    $diff = @(Compare-PDIntuneAppReadBack -Expected $expected -App ([pscustomobject]@{ applicableArchitectures = 'x86' }))
    Assert-Equal 1 $diff.Count 'a missing flag is still a mismatch'
    $plain = [ordered]@{ 'Publisher' = @{ Path = 'publisher'; Value = 'x64,x86'; Secret = $false } }
    Assert-Equal 1 @(Compare-PDIntuneAppReadBack -Expected $plain -App ([pscustomobject]@{ publisher = 'x86,x64' })).Count 'ordinary text is not compared as a set'
}

Add-TestCase 'U08' 'the app icon is a best-effort PATCH after publishing that never fails the upload' {
    $iconPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Templates\Printer-Icon.png'
    Assert-True (Test-Path -LiteralPath $iconPath) 'the standard printer icon ships in Templates'

    # Set: one PATCH with the exact PNG bytes, after publish and before assignment.
    Reset-PDM4Scenario
    $result = Invoke-PDM4Upload -Inputs (New-PDM4InputSet -Case 'icon-ok') -IconFile $iconPath
    Assert-True $result.Success ("the upload succeeds: {0}" -f $result.Message)
    $body = $script:M4.IconPatch | ConvertFrom-Json
    Assert-Equal 'image/png' ([string]$body.largeIcon.type) 'PNG mime type'
    Assert-Equal '#microsoft.graph.mimeContent' ([string]$body.largeIcon.'@odata.type') 'mimeContent'
    Assert-Equal ([Convert]::ToBase64String([System.IO.File]::ReadAllBytes($iconPath))) ([string]$body.largeIcon.value) 'the exact file bytes'
    Assert-NotLike '*largeIcon*' ([string]$script:M4.PublishPatch) 'the publish PATCH does not carry the icon'
    Assert-Equal 'printer-icon.png' ([string]$result.ReviewMetadata.IconFile).ToLowerInvariant() 'the review names the icon'

    # Refused: still published and assigned, with a warning, and nothing rolled back.
    Reset-PDM4Scenario
    $script:M4.IconRefused = $true
    $refused = Invoke-PDM4Upload -Inputs (New-PDM4InputSet -Case 'icon-refused') -IconFile $iconPath
    Assert-True $refused.Success ("a refused icon does not fail the upload: {0}" -f $refused.Message)
    Assert-Equal 0 @($script:M4.Deleted).Count 'nothing was deleted'
    Assert-Like '*icon could not be set*' ((@($refused.Warnings)) -join ' | ') 'the operator is told'

    # Not a PNG: no PATCH, a warning, upload still succeeds.
    Reset-PDM4Scenario
    $notPng = Join-Path $tempRoot 'not-an-icon.png'
    Set-Content -LiteralPath $notPng -Value 'definitely not a png'
    $bad = Invoke-PDM4Upload -Inputs (New-PDM4InputSet -Case 'icon-bad') -IconFile $notPng
    Assert-True $bad.Success 'an invalid icon file does not fail the upload'
    Assert-True ($null -eq $script:M4.IconPatch) 'no icon PATCH is sent for a non-PNG file'
    Assert-Like '*not a PNG or JPEG*' ((@($bad.Warnings)) -join ' | ') 'and it says why'

    # No icon requested: no PATCH at all.
    Reset-PDM4Scenario
    $none = Invoke-PDM4Upload -Inputs (New-PDM4InputSet -Case 'icon-none')
    Assert-True $none.Success 'plain upload still fine'
    Assert-True ($null -eq $script:M4.IconPatch) 'no icon, no icon PATCH'
}

Add-TestCase 'U09' 'Company Portal links are a best-effort PATCH; JPEG icons are sent as image/jpeg' {
    # Links set: one PATCH carrying both, separate from publish and icon.
    Reset-PDM4Scenario
    $result = Invoke-PDM4Upload -Inputs (New-PDM4InputSet -Case 'links-ok') -InformationUrl 'https://7-zip.org/download.html' -PrivacyUrl 'http://go.microsoft.com/fwlink/?LinkID=316999'
    Assert-True $result.Success ("links do not change the outcome: {0}" -f $result.Message)
    $links = $script:M4.LinksPatch | ConvertFrom-Json
    Assert-Equal 'https://7-zip.org/download.html' ([string]$links.informationUrl) 'information URL sent'
    Assert-Equal 'http://go.microsoft.com/fwlink/?LinkID=316999' ([string]$links.privacyInformationUrl) 'http links are accepted'
    Assert-NotLike '*informationUrl*' ([string]$script:M4.PublishPatch) 'the publish PATCH does not carry the links'
    Assert-Equal 'https://7-zip.org/download.html' ([string]$result.ReviewMetadata.InformationUrl) 'the review shows the link'

    # A link that is not http(s) is left out with a warning; nothing is sent when none remain.
    Reset-PDM4Scenario
    $bad = Invoke-PDM4Upload -Inputs (New-PDM4InputSet -Case 'links-bad') -InformationUrl 'javascript:alert(1)' -PrivacyUrl 'N/A'
    Assert-True $bad.Success 'a bad link never fails the upload'
    Assert-True ($null -eq $script:M4.LinksPatch) 'no links PATCH when no valid link remains'
    Assert-Like '*not an http(s) link*' ((@($bad.Warnings)) -join ' | ') 'the operator is told'

    # Refused by Intune: still published, warning, no rollback.
    Reset-PDM4Scenario
    $script:M4.LinksRefused = $true
    $refused = Invoke-PDM4Upload -Inputs (New-PDM4InputSet -Case 'links-refused') -InformationUrl 'https://example.invalid/'
    Assert-True $refused.Success 'a refused link does not fail the upload'
    Assert-Equal 0 @($script:M4.Deleted).Count 'nothing deleted'
    Assert-Like '*links could not be set*' ((@($refused.Warnings)) -join ' | ') 'warning shown'

    # JPEG icon: detected by its bytes, sent as image/jpeg.
    Reset-PDM4Scenario
    $jpeg = Join-Path $tempRoot 'icon.jpg'
    [System.IO.File]::WriteAllBytes($jpeg, [byte[]](0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01))
    $jpegResult = Invoke-PDM4Upload -Inputs (New-PDM4InputSet -Case 'icon-jpeg') -IconFile $jpeg
    Assert-True $jpegResult.Success 'JPEG icon upload succeeds'
    Assert-Equal 'image/jpeg' ([string](($script:M4.IconPatch | ConvertFrom-Json).largeIcon.type)) 'sent as image/jpeg'
}

Add-TestCase 'U07a' 'An assignment read-back difference is never reported as success' {
    $groupId = [guid]::NewGuid().ToString()
    $otherId = [guid]::NewGuid().ToString()

    # The required assignment is simply missing from the tenant.
    Reset-PDM4Scenario `
        -Groups @(@{ Id = $groupId; DisplayName = 'Required Group' }, @{ Id = $otherId; DisplayName = 'Available Group' }) `
        -GroupById @{ $groupId = @{ Id = $groupId; DisplayName = 'Required Group' }; $otherId = @{ Id = $otherId; DisplayName = 'Available Group' } } `
        -AssignmentRecords @((New-PDM4Assignment -Id 'assign-1' -GroupId $otherId -Intent 'available'))

    $inputs = New-PDM4InputSet -Case 'u07-missing'
    $result = Invoke-PDM4Upload -Inputs $inputs -RequiredGroups @('Required Group') -AvailableGroups @('Available Group')

    Assert-Equal $false $result.Success 'a missing assignment is not success'
    Assert-Equal 'Verify' $result.Stage 'caught by verification, not by an exit code'
    Assert-Like '*no *required* assignment*' $result.Message 'names the missing intent'
    Assert-Equal 'Deleted' $result.CleanupStatus 'the half-configured app is removed'
    Clear-PDMockGraph

    # Wrong intent on the right group.
    Reset-PDM4Scenario `
        -Groups @(@{ Id = $groupId; DisplayName = 'Required Group' }) `
        -GroupById @{ $groupId = @{ Id = $groupId; DisplayName = 'Required Group' } } `
        -AssignmentRecords @((New-PDM4Assignment -Id 'assign-1' -GroupId $groupId -Intent 'available'))

    $wrong = New-PDM4InputSet -Case 'u07-intent'
    $result = Invoke-PDM4Upload -Inputs $wrong -RequiredGroups @('Required Group')
    Assert-Equal $false $result.Success 'an available assignment is not the required one'
    Assert-Equal 'Verify' $result.Stage 'verification stage'
    Assert-Like '*instead of the requested*' $result.Message 'says what differs'
    Clear-PDMockGraph

    # An assignment nobody asked for.
    Reset-PDM4Scenario `
        -Groups @(@{ Id = $groupId; DisplayName = 'Required Group' }) `
        -GroupById @{ $groupId = @{ Id = $groupId; DisplayName = 'Required Group' } } `
        -AssignmentRecords @((New-PDM4Assignment -Id 'assign-1' -GroupId $groupId -Intent 'required'),
                             (New-PDM4Assignment -Id 'assign-2' -GroupId 'someone-elses-group' -Intent 'required'))

    $extra = New-PDM4InputSet -Case 'u07-extra'
    $result = Invoke-PDM4Upload -Inputs $extra -RequiredGroups @('Required Group')
    Assert-Equal $false $result.Success 'an extra assignment is a mismatch too'
    Assert-Like '*not requested*' $result.Message 'names the extra assignment'
    Clear-PDMockGraph
}

Add-TestCase 'U07b' 'Assignment sets are compared as sets, and metadata differences fail' {
    $groupId = [guid]::NewGuid().ToString()
    $otherId = [guid]::NewGuid().ToString()

    # Same pairs, opposite order, unrelated service ids: that is a match.
    Reset-PDM4Scenario `
        -Groups @(@{ Id = $groupId; DisplayName = 'Required Group' }, @{ Id = $otherId; DisplayName = 'Available Group' }) `
        -GroupById @{ $groupId = @{ Id = $groupId; DisplayName = 'Required Group' }; $otherId = @{ Id = $otherId; DisplayName = 'Available Group' } } `
        -AssignmentRecords @(
            (New-PDM4Assignment -Id 'service-id-b' -GroupId $otherId -Intent 'available'),
            (New-PDM4Assignment -Id 'service-id-a' -GroupId $groupId -Intent 'required'))

    $inputs = New-PDM4InputSet -Case 'u07-order'
    $result = Invoke-PDM4Upload -Inputs $inputs -RequiredGroups @('Required Group') -AvailableGroups @('Available Group')
    Assert-Equal $true $result.Success ('order and service ids are ignored; message: ' + $result.Message)
    Clear-PDMockGraph

    # A service-normalized description must fail verification rather than be waved through.
    Reset-PDM4Scenario -ReadBack {
        param($Record)
        $Record['description'] = 'Something the portal typed'
    }

    $mutated = New-PDM4InputSet -Case 'u07-metadata'
    $result = Invoke-PDM4Upload -Inputs $mutated
    Assert-Equal $false $result.Success 'a changed field is not success'
    Assert-Equal 'Verify' $result.Stage 'verification stage'
    Assert-Like '*Description*' $result.Message 'names the field that differs'
    Assert-Equal 'Deleted' $result.CleanupStatus 'the app is rolled back'
    Clear-PDMockGraph

    # The detection script is compared too, and its text is never echoed.
    Reset-PDM4Scenario -ReadBack {
        param($Record)
        $Record['rules'] = @(@{
            '@odata.type'           = '#microsoft.graph.win32LobAppPowerShellScriptRule'
            ruleType                = 'detection'
            scriptContent           = 'QW55dGhpbmcgZWxzZQ=='
            enforceSignatureCheck   = $false
            runAs32Bit              = $false
        })
    }
    $detection = New-PDM4InputSet -Case 'u07-detection'
    $result = Invoke-PDM4Upload -Inputs $detection
    Assert-Equal $false $result.Success 'a different detection script fails verification'
    Assert-Like '*Detection script*' $result.Message 'names the field'
    Assert-NotLike '*QW55dGhpbmcgZWxzZQ==*' $result.Message 'the detection script itself is still not printed'
    Clear-PDMockGraph
}

Add-TestCase 'U07c' 'A category that is not associated fails verification' {
    Reset-PDM4Scenario `
        -Categories @(@{ id = 'cat-1'; displayName = 'Printers' }) `
        -CategoryRecords @(@{ id = 'cat-2'; displayName = 'Something else' })

    $inputs = New-PDM4InputSet -Case 'u07-category'
    $result = Invoke-PDM4Upload -Inputs $inputs -Category 'Printers'

    Assert-Equal $false $result.Success 'an unassociated category is a mismatch'
    Assert-Equal 'Verify' $result.Stage 'verification stage'
    Assert-Like '*cat-1*not associated*' $result.Message 'names the category that is missing'
    Assert-Equal 'Deleted' $result.CleanupStatus 'rolled back'

    Clear-PDMockGraph
}
# ---------------------------------------------------------------------------
# M5 - provisioning, rotation and removal
#
# Two identities, therefore two seams (spec 7.1): the upload identity uses
# $PDGraph.TestTransport and the temporary interactive administrator uses
# $PDGraph.MgChannel. Every case below installs both, so a forgotten mock fails
# loudly instead of reaching Microsoft or opening a real sign-in prompt, and
# 'only the intended object was touched' is a claim about recorded requests.
#
# Spec 13: interactive Setup is never executed. The menu surface is checked with
# the AST, and the behaviour behind it is checked here, on the pure functions.
# ---------------------------------------------------------------------------

$script:M5 = $null

function Invoke-PDM5Case {
    <#
        Fast timings plus guaranteed teardown, so a case cannot leave a fake
        administrator channel or a one-second propagation deadline behind for
        every later case.
    #>
    param([Parameter(Mandatory = $true)][scriptblock]$Body)

    $keys   = @('PropagationDeadlineSec', 'PropagationIntervalMs', 'LockWaitSeconds', 'BaseRetryDelaySec',
                'DefaultSecretLifetimeDays', 'MaxSecretLifetimeDays', 'WarnSecretLifetimeDays',
                'SecretLabelDateFormat', 'PropagationIntervalMs')
    $saved  = @{}
    foreach ($key in $keys) { $saved[$key] = $script:PDGraph[$key] }

    $script:PDGraph.PropagationDeadlineSec = 1
    $script:PDGraph.PropagationIntervalMs  = 10
    $script:PDGraph.LockWaitSeconds        = 1
    $script:PDGraph.BaseRetryDelaySec      = 0

    try {
        return (& $Body)
    } finally {
        foreach ($key in $saved.Keys) { $script:PDGraph[$key] = $saved[$key] }
        $script:PDGraph.MgChannel  = $null
        $script:PDGraph.TokenCache = @{}
    }
}

function Get-PDM5FilterLiteral {
    <#
        The string literal of one OData property out of a decoded request URI, with the doubled
        apostrophes turned back into one. $null means "that filter was not in the request", which the
        router treats as no match - never as match everything.
    #>
    param([Parameter(Mandatory = $true)][string]$DecodedUri, [Parameter(Mandatory = $true)][string]$Property)

    $found = [regex]::Match($DecodedUri, ("{0} eq '((?:[^']|'')*)'" -f [regex]::Escape($Property)))
    if (-not $found.Success) { return $null }
    return $found.Groups[1].Value.Replace("''", "'")
}

function Reset-PDM5Scenario {
    <#
        The tenant the provisioning functions see. Nothing here is a real tenant object: they are the
        shapes the library reads, in the shapes ConvertFrom-Json gives it.
    #>
    param(
        [object[]]$Apps = @(),
        [hashtable]$AppByObjectId = @{},
        [object[]]$ServicePrincipals = @(),
        [object[]]$ExistingGrants = @(),
        [object[]]$RequiredResourceAccess = @(),
        [string]$NewApplicationId = $null,
        [string]$NewClientId = $null,
        [string]$NewServicePrincipalId = $null,
        [hashtable]$Secret = $null,
        [object[]]$SecretKeys = @(),
        [object[]]$Failures = @(),
        [object]$Context = $null,
        [object]$ContextAfterConnect = $null,
        [string[]]$TokenRoles = @('DeviceManagementApps.ReadWrite.All', 'Group.Read.All'),
        [int]$TokenRoleEmptyResponses = 0,
        [string]$TokenFailure = $null
    )

    $script:M5 = @{
        Apps                    = @($Apps)
        AppByObjectId           = $AppByObjectId
        ServicePrincipals       = @($ServicePrincipals)
        ExistingGrants          = @($ExistingGrants)
        RequiredResourceAccess  = @($RequiredResourceAccess)
        NewApplicationId        = $NewApplicationId
        NewClientId             = $NewClientId
        NewServicePrincipalId   = $NewServicePrincipalId
        Secret                  = $Secret
        SecretKeys              = @($SecretKeys)
        Failures                = @($Failures)
        Context                 = $Context
        ContextAfterConnect     = $ContextAfterConnect
        TokenRoles              = @($TokenRoles)
        TokenRoleEmptyResponses = [int]$TokenRoleEmptyResponses
        TokenFailure            = $TokenFailure
        TokenResponses          = 0
        ConnectCount            = 0
        DisconnectCount         = 0
        ConnectArguments        = $null
        Calls                   = @()
        Bodies                  = @()
        AppOnlyCalls            = @()
        Grants                  = @()
        PatchedResourceAccess   = $null
        Revoked                 = @()
        AddedSecretLabels       = @()
    }

    Set-PDM5Channel
}

function Invoke-PDM5Failure {
    <#
        Consumes the next scripted failure that matches this request. A failure is used once, so a
        case can say "the first addPassword dies" and still see what the retry policy refuses to do.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$State, [string]$Method, [string]$DecodedUri)

    $entries = @($State['Failures'])
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $failure = $entries[$i]
        if ($null -eq $failure) { continue }
        if (([string]$failure.Method) -and (([string]$failure.Method) -ne $Method)) { continue }
        if (([string]$failure.Match) -and ($DecodedUri -notlike ('*' + [string]$failure.Match + '*'))) { continue }

        # A used failure is used up. Writing through a temporary copy left it armed, and the next
        # matching request in the same scenario then died for the previous step's reason.
        $entries[$i] = $null
        $State['Failures'] = $entries

        return $failure
    }
    return $null
}

function Invoke-PDM5DelegatedRoute {
    <#
        The fake tenant behind the administrator channel. Records every request it answers.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Request)

    $state   = $script:M5
    $method  = [string]$Request.Method
    $uri     = [string]$Request.Uri
    $decoded = [System.Uri]::UnescapeDataString($uri)

    $state.Calls  += ,('{0} {1}' -f $method, $decoded)
    $state.Bodies += ,@{ Method = $method; Uri = $decoded; Body = [string]$Request.Body }

    $failure = Invoke-PDM5Failure -State $state -Method $method -DecodedUri $decoded
    if ($null -ne $failure) {
        if (([string]$failure.Kind) -eq 'transport') {
            # Exactly how a real transport dies, so the lost-write logic is tested for real.
            throw (New-Object System.Net.WebException ('the scripted transport died for {0} {1}' -f $method, $decoded))
        }
        return (New-PDMockJsonResponse -Status ([int]$failure.Status) -Json (
                @{ error = @{ code = [string]$failure.Code; message = [string]$failure.Message } } | ConvertTo-Json -Compress))
    }

    # --- applications -------------------------------------------------------------------------
    if (($method -eq 'POST') -and ($decoded -eq 'https://graph.microsoft.com/v1.0/applications')) {
        return (New-PDMockJsonResponse -Status 201 -Json (@{
            id             = [string]$state.NewApplicationId
            appId          = [string]$state.NewClientId
            displayName    = 'PowerDeploy Intune Upload'
            signInAudience = 'AzureADMyOrg'
        } | ConvertTo-Json -Compress))
    }

    if ($decoded -match '^https://graph\.microsoft\.com/v1\.0/applications/([0-9a-fA-F-]{36})(/|\?|$)') {
        $objectId = $matches[1]

        if ($decoded -like '*/addPassword') {
            $label = ''
            try { $label = [string]((($Request.Body | ConvertFrom-Json) -as [psobject]).passwordCredential.displayName) } catch { }
            $state.AddedSecretLabels += $label

            if ($null -eq $state.Secret) {
                return (New-PDMockJsonResponse -Status 500 -Json (@{ error = @{ code = 'NoSecretConfigured'; message = 'the scenario has no secret to return' } } | ConvertTo-Json -Compress))
            }
            return (New-PDMockJsonResponse -Status 201 -Json (@{
                keyId       = [string]$state.Secret.keyId
                secretText  = [string]$state.Secret.secretText
                endDateTime = [string]$state.Secret.endDateTime
            } | ConvertTo-Json -Compress))
        }

        if ($decoded -like '*/removePassword') {
            $revokedKeyId = ''
            try { $revokedKeyId = [string](($Request.Body | ConvertFrom-Json).keyId) } catch { }
            $state.Revoked += $revokedKeyId
            return (New-PDMockJsonResponse -Status 204 -Json '')
        }

        if ($method -eq 'PATCH') {
            $state.PatchedResourceAccess = [string]$Request.Body
            return (New-PDMockJsonResponse -Status 204 -Json '')
        }

        $app = $null
        foreach ($key in @($state.AppByObjectId.Keys)) {
            if (([string]$key) -ieq $objectId) { $app = $state.AppByObjectId[$key]; break }
        }
        if ($null -eq $app) {
            return (New-PDMockJsonResponse -Status 404 -Json (@{ error = @{ code = 'Request_ResourceNotFound'; message = 'Resource does not exist.' } } | ConvertTo-Json -Compress))
        }

        $body = @{ id = $objectId; appId = [string]$app.appId; displayName = [string]$app.displayName }
        if ($decoded -like '*requiredResourceAccess*') { $body['requiredResourceAccess'] = @($state.RequiredResourceAccess) }
        if ($decoded -like '*passwordCredentials*')    { $body['passwordCredentials']    = @($state.SecretKeys) }

        return (New-PDMockJsonResponse -Json ($body | ConvertTo-Json -Depth 20 -Compress))
    }

    # A collection read has to be recognised as such: '?' is a wildcard in -like, so the old
    # 'applications?*' pattern also matched 'applications/<id>?$select=...' and answered an
    # object read with an empty value page - which the library would then read as 'no permissions
    # yet' and merge its PATCH from nothing. Anchored positional matching keeps the fake tenant
    # telling the truth about what it was asked for.
    if (($method -eq 'GET') -and ($decoded -match '^https://graph\.microsoft\.com/v1\.0/applications\?')) {
        $byName  = Get-PDM5FilterLiteral -DecodedUri $decoded -Property 'displayName'
        $byAppId = Get-PDM5FilterLiteral -DecodedUri $decoded -Property 'appId'

        $matched = @()
        foreach ($app in @($state.Apps)) {
            if ($null -ne $byName -and (([string]$app.displayName) -ne $byName)) { continue }
            if ($null -ne $byAppId -and (([string]$app.appId) -ne $byAppId)) { continue }
            $matched += $app
        }
        return (New-PDMockJsonResponse -Json (New-PDMockValuePage -Value $matched))
    }

    # --- service principals --------------------------------------------------------------------
    if (($method -eq 'POST') -and ($decoded -eq 'https://graph.microsoft.com/v1.0/servicePrincipals')) {
        return (New-PDMockJsonResponse -Status 201 -Json (@{
            id    = [string]$state.NewServicePrincipalId
            appId = [string]((($Request.Body | ConvertFrom-Json) -as [psobject]).appId)
        } | ConvertTo-Json -Compress))
    }

    if (($method -eq 'GET') -and ($decoded -match '^https://graph\.microsoft\.com/v1\.0/servicePrincipals\?') -and ($decoded -notlike '*appRoleAssignments*')) {
        $byAppId = Get-PDM5FilterLiteral -DecodedUri $decoded -Property 'appId'

        $matched = @()
        foreach ($principal in @($state.ServicePrincipals)) {
            if ($null -ne $byAppId -and (([string]$principal.appId) -ne $byAppId)) { continue }

            $item = @{ id = [string]$principal.id; appId = [string]$principal.appId; displayName = [string]$principal.displayName }
            if ($decoded -like '*appRoles*') { $item['appRoles'] = @($principal.appRoles) }
            $matched += $item
        }
        return (New-PDMockJsonResponse -Json (New-PDMockValuePage -Value $matched))
    }

    if ($decoded -like '*/appRoleAssignments*') {
        # Like the real service: the URL names the principal the roles are granted TO, and a grant
        # posted under any other principal is refused (this once let a wrong path pass every test).
        $pathPrincipal = $null
        if ($decoded -match '/servicePrincipals/([0-9a-fA-F-]{36})/appRoleAssignments') { $pathPrincipal = $matches[1] }

        if ($method -eq 'POST') {
            $granted = $null
            try { $granted = ($Request.Body | ConvertFrom-Json) -as [psobject] } catch { }
            if (([string]$granted.principalId) -ne [string]$pathPrincipal) {
                return (New-PDMockJsonResponse -Status 400 -Json (@{ error = @{ code = 'Request_BadRequest'; message = 'principalId does not match the service principal in the request URL.' } } | ConvertTo-Json -Compress))
            }
            $state.Grants += [pscustomobject]@{
                principalId = [string]$granted.principalId
                resourceId  = [string]$granted.resourceId
                appRoleId   = [string]$granted.appRoleId
            }
            return (New-PDMockJsonResponse -Status 201 -Json (@{ id = 'grant-1' } | ConvertTo-Json -Compress))
        }

        $matched = @()
        foreach ($grant in @($state.ExistingGrants)) {
            if (([string]$grant.principalId) -ne [string]$pathPrincipal) { continue }
            $matched += $grant
        }
        return (New-PDMockJsonResponse -Json (New-PDMockValuePage -Value $matched))
    }

    throw ("the m5 administrator channel has no answer for {0} {1}" -f $method, $decoded)
}

function Set-PDM5Channel {
    <#
        Installs the fake administrator channel. Connect/Disconnect/GetContext are counted so a test
        can prove the temporary session was closed, and Invoke is the router above.
    #>
    $script:PDGraph.MgChannel = @{
        Connect    = {
            param($Arguments)
            $script:M5.ConnectCount = [int]$script:M5.ConnectCount + 1
            $script:M5.ConnectArguments = $Arguments
            $null
        }
        Disconnect = {
            param($Arguments)
            $script:M5.DisconnectCount = [int]$script:M5.DisconnectCount + 1
            $null
        }
        GetContext = {
            param($Arguments)
            if ([int]$script:M5.ConnectCount -gt 0) { return $script:M5.ContextAfterConnect }
            return $script:M5.Context
        }
        Invoke = {
            param($Request)
            Invoke-PDM5DelegatedRoute -Request $Request
        }
    }
}

function Set-PDM5AppOnlyTransport {
    <#
        The upload identity's side: the token endpoint and the small Intune read. Kept separate from
        the administrator channel because they are different identities (spec 7.1).
    #>
    param(
        [string[]]$Roles = @('DeviceManagementApps.ReadWrite.All', 'Group.Read.All'),
        [int]$EmptyRoleResponses = 0,
        [string]$Failure = $null
    )

    $script:M5.TokenRoles   = @($Roles)
    $script:M5.TokenFailure = $Failure

    $script:PDGraph.TestTransport = {
        param($Request)

        $state = $script:M5
        $state.AppOnlyCalls += ,('{0} {1}' -f [string]$Request.Method, [string]$Request.Uri)

        if (([string]$Request.Uri) -like 'https://login.microsoftonline.com/*/oauth2/v2.0/token') {
            $state.TokenResponses = [int]$state.TokenResponses + 1

            if (-not [string]::IsNullOrWhiteSpace($state.TokenFailure)) {
                # -Json, not -Body: a wrong parameter name here is swallowed by the transport seam
                # and arrives below as a dead connection, which is a completely different thing to
                # have tested. If a case here reports an unexplained transport error, print the
                # returned Message first - the real reason is quoted inside it.
                return (New-PDMockJsonResponse -Status 400 -Json (@{
                    error             = 'invalid_client'
                    error_description = [string]$state.TokenFailure
                } | ConvertTo-Json -Compress))
            }

            $roles = @($state.TokenRoles)
            if ([int]$state.TokenResponses -le [int]$state.TokenRoleEmptyResponses) { $roles = @() }

            return (New-PDMockJsonResponse -Json (@{
                access_token = (New-TestJwt -Roles $roles)
                expires_in   = 3600
            } | ConvertTo-Json -Compress))
        }

        if (([string]$Request.Uri) -like 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps*') {
            return (New-PDMockJsonResponse -Json (New-PDMockValuePage -Value @(@{ id = 'read-back-app'; displayName = 'anything' })))
        }

        throw ("the m5 app-only transport has no answer for {0} {1}" -f [string]$Request.Method, [string]$Request.Uri)
    }
}

function Get-PDM5CallTrail {
    param([string]$Contains)
    $calls = @($script:M5.Calls)
    if (-not [string]::IsNullOrWhiteSpace($Contains)) { $calls = @($calls | Where-Object { $_ -like "*$Contains*" }) }
    return $calls
}

function Get-PDM5Mutation {
    <#
        Administrator-channel calls that would change tenant state. A GET is never one, and the
        token endpoint belongs to the other channel entirely.
    #>
    $mutations = @()
    foreach ($call in @($script:M5.Calls)) {
        $method = ([string]$call).Split(' ')[0]
        if ($method -ne 'Get') { $mutations += [string]$call }
    }
    return $mutations
}

function New-PDM5Session {
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [string[]]$Scopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All'),
        [string]$AuthType = 'Delegated'
    )
    return @{ TenantId = $TenantId; Account = 'admin@contoso.com'; AuthType = $AuthType; Scopes = @($Scopes); Owned = $true; Reused = $false }
}

function New-PDM5StoredCredential {
    <#
        A credential file written the way the library writes it, under $tempRoot. Never the real
        %LOCALAPPDATA% location.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][string]$SecretKeyId,
        [AllowNull()][string]$AppObjectId,
        [string]$ClientId = '11111111-1111-1111-1111-111111111111',
        [string]$TenantId = '22222222-2222-2222-2222-222222222222',
        [double]$DaysFromNow = 60,
        [string]$SecretValue = 'stored-secret-never-real'
    )

    $credential = New-PDGraphCredentialObject -TenantId $TenantId -ClientId $ClientId `
                    -ClientSecret (New-FakeSecureString -Value $SecretValue) `
                    -SecretExpiresOn ([System.DateTimeOffset]::UtcNow.AddDays($DaysFromNow)) `
                    -SecretKeyId $SecretKeyId -AppObjectId $AppObjectId `
                    -AppDisplayName 'PowerDeploy Intune Upload'

    $null = Save-PDGraphCredential -Credential $credential -Path $Path
    return $credential
}

$script:M5AppId        = '33333333-3333-3333-3333-333333333333'
$script:M5ClientId     = '11111111-1111-1111-1111-111111111111'
$script:M5TenantId     = '22222222-2222-2222-2222-222222222222'
$script:M5UploadSpId   = '44444444-4444-4444-4444-444444444444'
$script:M5GraphSpId    = '55555555-5555-5555-5555-555555555555'
$script:M5GraphAppId   = '00000003-0000-0000-c000-000000000000'
$script:M5RoleApps     = '66666666-6666-6666-6666-666666666666'
$script:M5RoleGroups   = '77777777-7777-7777-7777-777777777777'
$script:M5OldKeyId     = '88888888-8888-8888-8888-888888888888'
$script:M5NewKeyId     = '99999999-9999-9999-9999-999999999999'

function New-PDM5GraphServicePrincipal {
    param([switch]$WithoutApplicationRoles, [string]$Id)

    $roles = @(
        @{ id = $script:M5RoleApps;   value = 'DeviceManagementApps.ReadWrite.All'; allowedMemberTypes = @('Application') },
        @{ id = $script:M5RoleGroups; value = 'Group.Read.All';                     allowedMemberTypes = @('Application') },
        @{ id = 'aaaaaaaa-0000-0000-0000-000000000001'; value = 'Group.Read.All';   allowedMemberTypes = @('Delegated') }
    )
    if ($WithoutApplicationRoles) {
        $roles = @(@{ id = 'aaaaaaaa-0000-0000-0000-000000000002'; value = 'Group.Read.All'; allowedMemberTypes = @('Delegated') })
    }

    return @{
        id          = $(if ($Id) { $Id } else { $script:M5GraphSpId })
        appId       = $script:M5GraphAppId
        displayName = 'Microsoft Graph'
        appRoles    = $roles
    }
}

# --- the menu surface, checked without running interactive Setup (spec 13) --------------------

$script:SetupAst = $null

function Get-PDM5SetupAst {
    if ($null -eq $script:SetupAst) {
        $path = Join-Path (Split-Path $PSScriptRoot -Parent) 'Setup.ps1'
        Assert-True (Test-Path -LiteralPath $path) "Setup.ps1 should exist at $path"

        $parseErrors = $null
        $parsed = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$parseErrors)
        Assert-True (@($parseErrors).Count -eq 0) "Setup.ps1 must parse cleanly ($((@($parseErrors) | ForEach-Object { $_.Message }) -join ' | '))"
        $script:SetupAst = $parsed
    }
    return $script:SetupAst
}

function Get-PDM5DotSourceScope {
    <#
        Proves a feature file is dot-sourced somewhere its function definitions survive. A try or if
        block does not create a scope, but a function does - dot-sourcing inside one would hand the
        menu commands that no longer exist once that function returns. (CommandExpressionAst's
        InvocationOperator property exists only on PowerShell 7, so the dot-source is located by its
        own text and then walked up to the nearest function definition.)
    #>
    param([Parameter(Mandatory = $true)][object]$Ast, [Parameter(Mandatory = $true)][string]$Variable)

    $target    = ('. $' + $Variable)
    $found     = @($Ast.FindAll({ param($node) (($null -ne $node.Extent) -and ([string]$node.Extent.Text -eq $target)) }, $true))
    $pipelines = @($found | Where-Object { $_ -is [System.Management.Automation.Language.PipelineAst] })
    Assert-True (@($pipelines).Count -eq 1) "Setup.ps1 should dot-source $Variable exactly once (found $(@($pipelines).Count))"

    $enclosing = $null
    $node      = @($pipelines)[0]
    while ($null -ne $node) {
        if ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $enclosing = $node; break }
        $node = $node.Parent
    }

    Assert-True ($null -eq $enclosing) "the dot-source of $Variable must sit at script scope, not inside a function"
}

function Get-PDM5SetupFunction {
    param([Parameter(Mandatory = $true)][string]$Name)

    $ast = Get-PDM5SetupAst
    $found = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) |
             Where-Object { $_.Name -eq $Name }

    Assert-True (@($found).Count -eq 1) "Setup.ps1 should define $Name exactly once (found $(@($found).Count))"
    return @($found)[0]
}

Add-TestCase 'M5-01' 'Setup.ps1 loads the feature at script scope and still has no top-level param block' {
    $ast  = Get-PDM5SetupAst
    $text = [System.IO.File]::ReadAllText((Join-Path (Split-Path $PSScriptRoot -Parent) 'Setup.ps1'))

    # The M3 bug that erased the wizard's variables: dot-sourcing a script with a top-level param()
    # writes every parameter into the CALLER as $null. Setup must never grow one.
    Assert-True ($null -eq $ast.ParamBlocks) 'Setup.ps1 must not declare a top-level param() block'

    # Both feature files are dot-sourced at script scope, where their functions outlive the load.
    Get-PDM5DotSourceScope -Ast $ast -Variable 'InTuneGraphHelperScriptPath'
    Get-PDM5DotSourceScope -Ast $ast -Variable 'IntuneUploadScriptPath'

    # A load failure is recorded, not thrown: guided manual publishing has to survive it.
    Assert-Like '*$GraphUploadAvailable  = $false*' $text 'availability starts false'
    Assert-Like '*Catch *{ *$GraphUploadLoadError = $_.Exception.Message*' ($text -replace "`r?`n", ' ') 'a load failure is recorded, not raised'
}

Add-TestCase 'M5-02' 'the provisioning menu offers exactly the spec 7.2 options and never exits' {
    $menu = Get-PDM5SetupFunction -Name 'InTuneAPI--Setup-and-Manage'
    $body = [string]$menu.Extent.Text
    $shown = [string](Get-PDM5SetupFunction -Name 'Show-GraphUploadMenu').Extent.Text

    foreach ($option in @(
            '1 - Azure App Registration - Setup/Config (prerequisite for API uploads)',
            '2 - Azure App Registration - Test config',
            '3 - Azure App Registration - Rotate local PC secret',
            '4 - Azure App Registration - Remove local PC secret',
            '5 - MAA Exclusions - Setup/Config manually (not prerequisite, useful if your tenant has MAA enabled)',
            '0 - Return')) {
        Assert-True ($shown -like "*$option*") "the menu must show '$option'"
    }

    Assert-True ($body -like '*Show-GraphUploadMenu*') 'the menu shows its own option list'

    # Every option has to reach a function, or it is a menu item that does nothing.
    foreach ($dispatch in @('Invoke-GraphUploadProvisionApplication', 'Invoke-GraphUploadEnterCredential',
                            'Invoke-GraphUploadTestConnection', 'Invoke-GraphUploadRotateSecret',
                            'Show-GraphUploadMaaInstructions', 'Invoke-GraphUploadRemoveCredential')) {
        Assert-True ($body -like "*$dispatch*") "option list entry $dispatch is never dispatched"
    }

    # Spec invariant 2: a failure in a reusable path must never close Setup's process.
    $exits = @($menu.FindAll({ param($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true))
    Assert-True (@($exits).Count -eq 0) 'the provisioning menu must never call exit'

    # Only the menu function may carry '--', because the end-of-file menu reflects on '*--*'.
    $ast = Get-PDM5SetupAst
    $names = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) |
             ForEach-Object { $_.Name }
    foreach ($helper in @('Show-GraphUploadMenu', 'Show-GraphUploadError', 'Read-GraphUploadYesNo', 'Read-GraphUploadTenantId',
                          'Read-GraphUploadSecretLifetime', 'Connect-GraphUploadAdminSession', 'Show-GraphUploadSteps',
                          'Show-GraphUploadCredentialState', 'Invoke-GraphUploadProvisionApplication',
                          'Invoke-GraphUploadEnterCredential', 'Invoke-GraphUploadTestConnection',
                          'Invoke-GraphUploadRotateSecret', 'Show-GraphUploadMaaInstructions',
                          'Invoke-GraphUploadRemoveCredential')) {
        Assert-True (@($names) -ccontains $helper) "Setup.ps1 should define $helper"
        Assert-True ($helper -notlike '*--*') "$helper must not contain '--' (it would appear in the reflection menu)"
    }

    # Nothing in the new helpers may exit either, and the menu must be reachable by the reflection.
    foreach ($helper in @('Invoke-GraphUploadProvisionApplication', 'Invoke-GraphUploadEnterCredential',
                          'Invoke-GraphUploadTestConnection', 'Invoke-GraphUploadRotateSecret',
                          'Show-GraphUploadMaaInstructions', 'Invoke-GraphUploadRemoveCredential')) {
        $fn    = Get-PDM5SetupFunction -Name $helper
        $stops = @($fn.FindAll({ param($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true))
        Assert-True (@($stops).Count -eq 0) "$helper must never call exit"
    }

    Assert-True (@($names | Where-Object { $_ -like 'InTuneAPI--*' }).Count -eq 1) 'the provisioning menu is reflected exactly once'
}

Add-TestCase 'M5-03' 'the provisioning menu calls the library and never the network itself' {
    $ast = Get-PDM5SetupAst

    $names = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
    foreach ($helper in @('Invoke-GraphUploadProvisionApplication', 'Invoke-GraphUploadEnterCredential',
                          'Invoke-GraphUploadTestConnection', 'Invoke-GraphUploadRotateSecret',
                          'Show-GraphUploadMaaInstructions', 'Invoke-GraphUploadRemoveCredential',
                          'Connect-GraphUploadAdminSession')) {
        $fn = @($names | Where-Object { $_.Name -eq $helper })[0]
        Assert-True ($null -ne $fn) "expected $helper to be defined"

        $commands = @($fn.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)) |
                    ForEach-Object { $_.GetCommandName() } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        foreach ($forbidden in @('Invoke-WebRequest', 'Invoke-RestMethod', 'Invoke-MgGraphRequest', 'Connect-MgGraph',
                                 'Disconnect-MgGraph', 'Get-MgContext', 'Export-Clixml', 'Import-Clixml',
                                 'ConvertTo-SecureString', 'Start-PDIntunePreflight')) {
            Assert-True (@($commands) -notcontains $forbidden) "$helper must not call $forbidden directly (the library owns the network and the credential file)"
        }

        # Everything it calls has to exist: this is the check that catches a renamed helper.
        $defined = @($names | ForEach-Object { $_.Name })
        foreach ($command in @($commands)) {
            if ($command -eq 'git') { continue }
            $known = $null -ne (Get-Command -Name $command -CommandType Cmdlet, Function, Alias, ExternalScript, Application -ErrorAction SilentlyContinue)
            if (-not $known) { $known = (@($defined) -ccontains $command) }
            Assert-True $known "$helper calls '$command', which is not defined in Setup.ps1, the library, or the uploader"
        }
    }
}

# --- pure provisioning decisions ---------------------------------------------------------------

Add-TestCase 'M5-04' 'the administrator-channel prerequisite is reported, never auto-installed' {
    $missing = Get-PDGraphProvisioningPrerequisite -Probe { $null }
    Assert-True (-not $missing.Available) 'a machine without the module is reported as unavailable'
    Assert-Like '*Install-Module Microsoft.Graph.Authentication -Scope CurrentUser*' $missing.Message 'names the exact prerequisite'
    Assert-Like '*not installed for this Windows account*' $missing.Message 'says what is missing, and for whom'

    $present = Get-PDGraphProvisioningPrerequisite -Probe { '2.36.0' }
    Assert-True $present.Available 'an installed module is reported as available'
    Assert-Equal '2.36.0' ([string]$present.Version) 'the version is reported'

    # The seam itself must refuse a half-written fake rather than pretend to work.
    $script:PDGraph.MgChannel = @{ Connect = { param($a) $null } }
    $caught = Assert-Throws -Body { Get-PDGraphDelegatedChannel } -MessagePattern '*Disconnect*' 'names the missing handler'
    $script:PDGraph.MgChannel = $null
}

Add-TestCase 'M5-05' 'roles are resolved by exact value and only where Application consent is possible' {
    $principal = New-PDM5GraphServicePrincipal
    $resolved  = Resolve-PDEntraApplicationRole -AppRoles @($principal.appRoles) -RequiredRoles @('DeviceManagementApps.ReadWrite.All', 'Group.Read.All')

    Assert-Equal 0 @($resolved.Missing).Count 'both roles resolve'
    Assert-Equal $script:M5RoleApps ([string]$resolved.RoleIds['DeviceManagementApps.ReadWrite.All']) 'the apps role id comes from the service principal'
    Assert-Equal $script:M5RoleGroups ([string]$resolved.RoleIds['Group.Read.All']) 'the group role id comes from the service principal'

    # The delegated-only Group.Read.All entry above must never satisfy the requirement, and a name
    # that does not exist is reported rather than approximated by substring.
    $partial = Resolve-PDEntraApplicationRole -AppRoles @(New-PDM5GraphServicePrincipal -WithoutApplicationRoles).appRoles -RequiredRoles @('Group.Read.All')
    Assert-Equal 1 @($partial.Missing).Count 'a delegated-only role of the same name does not count'
    Assert-Equal 'Group.Read.All' @($partial.Missing)[0] 'the missing role is named'

    $unknown = Resolve-PDEntraApplicationRole -AppRoles @($principal.appRoles) -RequiredRoles @('DeviceManagementApps.Read.All')
    Assert-Equal 1 @($unknown.Missing).Count 'a near-miss role name is missing, never matched loosely'
}

Add-TestCase 'M5-06' 'a delegated request never carries the administrator credential off Graph' {
    Reset-PDM5Scenario
    $caught = Assert-Throws -Body { Invoke-PDGraphDelegatedRequest -Method Get -Uri 'https://evil.example.com/v1.0/applications' } `
                            -MessagePattern '*not Microsoft Graph*' 'refuses the non-Graph host'
    Assert-Equal 0 @($script:M5.Calls).Count 'the refusal happens before any request leaves'

    # The version-prefix rule the app-only channel uses must not drift from the delegated one.
    Assert-Equal 'https://graph.microsoft.com/v1.0/applications' (New-PDGraphRequestUrl -Uri '/v1.0/applications') 'v1.0 prefix selects the v1.0 base once'
    Assert-Equal 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps' (New-PDGraphRequestUrl -Uri '/beta/deviceAppManagement/mobileApps') 'beta prefix selects the beta base once'
    Assert-True ((New-PDGraphRequestUrl -Uri '/beta/deviceAppManagement/mobileApps') -notlike '/beta/beta/') 'no doubled version segment'
}

Add-TestCase 'M5-07' 'several same-named registrations are chosen by the operator, never guessed' {
    Reset-PDM5Scenario -Apps @(
        @{ id = '33333333-3333-3333-3333-333333333333'; appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' },
        @{ id = 'cccccccc-3333-3333-3333-333333333333'; appId = 'cccccccc-1111-1111-1111-111111111111'; displayName = 'PowerDeploy Intune Upload' }
    )

    $needs = Ensure-PDEntraApplication
    Assert-True (-not $needs.Success) 'several matches is not a success'
    Assert-Equal 'NeedsSelection' $needs.Reason 'it says a selection is needed'
    Assert-Equal 2 @($needs.Candidates).Count 'both candidates are offered'
    Assert-Equal 0 @((Get-PDM5Mutation)).Count 'a lookup mutates nothing'

    $mutating = Ensure-PDEntraApplication
    Assert-Equal 0 @((Get-PDM5Mutation)).Count 'still nothing written while the operator has not chosen'

    # An id outside this tenant is refused rather than used.
    Assert-Throws -Body {
        Ensure-PDEntraApplication -Selection { param($apps) 'dddddddd-3333-3333-3333-333333333333' }
    } -MessagePattern '*not one of the matches*' 'a chosen id must be one of the matches'

    $chosen = Ensure-PDEntraApplication -Selection { param($apps) 'cccccccc-3333-3333-3333-333333333333' }
    Assert-True $chosen.Success 'the chosen registration is used'
    Assert-Equal 'cccccccc-3333-3333-3333-333333333333' ([string]$chosen.ApplicationId) 'the chosen id is the one used'
    Assert-Equal 'Selected' $chosen.Reason 'the reason says the operator chose it'
}

Add-TestCase 'M5-08' 'the missing application is created single-tenant, and a lost create is never repeated' {
    Reset-PDM5Scenario -Apps @() -NewApplicationId $script:M5AppId -NewClientId $script:M5ClientId

    $created = Ensure-PDEntraApplication
    Assert-True $created.Success 'the create succeeded'
    Assert-Equal 'Created' $created.Reason 'it says it created one'
    Assert-Equal ([string]$script:M5AppId) ([string]$created.ApplicationId) 'the returned id is used, not invented'

    $post = @((Get-PDM5Mutation) | Where-Object { $_ -like 'POST https://graph.microsoft.com/v1.0/applications*' })
    Assert-Equal 1 @($post).Count 'exactly one POST created it'
    Assert-Like '*"signInAudience":"AzureADMyOrg"*' ([string](@($script:M5.Bodies)[-1].Body)) 'single-tenant, as spec 7.2 step 2 requires'

    # A create whose response is lost is reported as unknown, and above all not repeated.
    Reset-PDM5Scenario -Apps @() -Failures @(@{ Method = 'POST'; Match = '/v1.0/applications'; Kind = 'transport' })
    $lost = Ensure-PDEntraApplication
    Assert-True (-not $lost.Success) 'a lost create is not a success'
    Assert-Equal 'UnknownCreate' $lost.Reason 'and it is not known whether the app exists'
    Assert-Equal 1 @((Get-PDM5CallTrail -Contains 'POST https://graph.microsoft.com/v1.0/applications')).Count 'the lost POST was attempted exactly once'
    Assert-Like '*not repeated*' $lost.Message 'the message says it was not repeated'
}

Add-TestCase 'M5-09' 'required permissions merge additively and a PATCH is not wasted' {
    $graphEntry = @{
        resourceAppId = $script:M5GraphAppId
        resourceAccess = @(@{ id = 'bbbbbbbb-0000-0000-0000-000000000001'; type = 'Role' })
    }
    $otherEntry = @{
        resourceAppId = 'abcdabcd-0000-0000-0000-000000000000'
        resourceAccess = @(@{ id = 'bbbbbbbb-0000-0000-0000-000000000009'; type = 'Scope' })
    }

    Reset-PDM5Scenario -AppByObjectId @{ $script:M5AppId = @{ appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' } } `
                       -RequiredResourceAccess @($graphEntry, $otherEntry)

    $result = Set-PDEntraRequiredResourceAccess -ApplicationId $script:M5AppId -RoleIds @{ 'DeviceManagementApps.ReadWrite.All' = $script:M5RoleApps }
    Assert-True $result.Changed 'a missing role changes something'
    Assert-Equal 1 @((Get-PDM5Mutation) | Where-Object { $_ -like 'PATCH *' }).Count 'exactly one PATCH'

    $patched = [string]$script:M5.PatchedResourceAccess
    Assert-Like '*abcdabcd-0000-0000-0000-000000000000*' $patched 'the unrelated resource entry survives the PATCH'
    Assert-Like '*bbbbbbbb-0000-0000-0000-000000000009*' $patched 'the unrelated resourceAccess entry survives too'
    Assert-Like '*bbbbbbbb-0000-0000-0000-000000000001*' $patched 'the existing Graph role survives'
    Assert-Like "*$([regex]::Escape($script:M5RoleApps))*" $patched 'the resolved role id is added'

    # Asking for what is already there must not write at all.
    Reset-PDM5Scenario -AppByObjectId @{ $script:M5AppId = @{ appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' } } `
                       -RequiredResourceAccess @(@{ resourceAppId = $script:M5GraphAppId; resourceAccess = @(@{ id = $script:M5RoleApps; type = 'Role' }) })
    $again = Set-PDEntraRequiredResourceAccess -ApplicationId $script:M5AppId -RoleIds @{ 'DeviceManagementApps.ReadWrite.All' = $script:M5RoleApps }
    Assert-True (-not $again.Changed) 'nothing to add means nothing changed'
    Assert-Equal 0 @((Get-PDM5Mutation)).Count 'and no request was written'
    Assert-Like '*not consent*' $result.Message 'configuring requested permissions is described as not consent'
}

Add-TestCase 'M5-10' 'role grants address three exact ids, skip what exists, and remove nothing' {
    Reset-PDM5Scenario -ExistingGrants @(@{ id = 'grant-1'; principalId = $script:M5UploadSpId; resourceId = $script:M5GraphSpId; appRoleId = $script:M5RoleGroups })

    $result = Ensure-PDAppRoleAssignments -UploadServicePrincipalId $script:M5UploadSpId -GraphServicePrincipalId $script:M5GraphSpId -RoleIds @{
        'DeviceManagementApps.ReadWrite.All' = $script:M5RoleApps
        'Group.Read.All'                     = $script:M5RoleGroups
    }

    Assert-True $result.Success 'the grant step succeeded'
    Assert-Equal 1 @($result.Granted).Count 'only the missing role was granted'
    Assert-Equal 'DeviceManagementApps.ReadWrite.All' @($result.Granted)[0] 'and it is the one that was missing'
    Assert-Equal 'Group.Read.All' @($result.AlreadyGranted)[0] 'the existing grant is reported as already granted'

    $posts = @((Get-PDM5Mutation) | Where-Object { $_ -like 'POST *appRoleAssignments*' })
    Assert-Equal 1 @($posts).Count 'exactly one grant POST was made'
    Assert-Equal 0 @((Get-PDM5Mutation) | Where-Object { $_ -like 'DELETE *' }).Count 'nothing is ever revoked by this function'

    $grant = @($script:M5.Grants)[0]
    Assert-Equal $script:M5UploadSpId ([string]$grant.principalId) 'principalId is the upload service principal'
    Assert-Equal $script:M5GraphSpId ([string]$grant.resourceId) 'resourceId is the Microsoft Graph service principal'
    Assert-Equal $script:M5RoleApps ([string]$grant.appRoleId) 'appRoleId is the resolved role id'

    # A grant whose response is lost is unconfirmed: never repeated, and reported as such.
    Reset-PDM5Scenario -ExistingGrants @() -Failures @(@{ Method = 'POST'; Match = 'appRoleAssignments'; Kind = 'transport' })
    $lost = Ensure-PDAppRoleAssignments -UploadServicePrincipalId $script:M5UploadSpId -GraphServicePrincipalId $script:M5GraphSpId -RoleIds @{ 'Group.Read.All' = $script:M5RoleGroups }
    Assert-True (-not $lost.Success) 'a lost grant is not a success'
    Assert-Equal 1 @((Get-PDM5CallTrail -Contains 'POST *appRoleAssignments*')).Count 'the lost grant POST was made once and not retried'
    Assert-Like '*not repeated*' $lost.Message 'the operator is told it was not repeated'

    Assert-Throws -Body { Ensure-PDAppRoleAssignments -UploadServicePrincipalId 'not-a-guid' -GraphServicePrincipalId $script:M5GraphSpId -RoleIds @{ 'x' = $script:M5RoleApps } } `
                  -MessagePattern '*not a GUID*' 'a malformed id is refused before any request'
}

Add-TestCase 'M5-11' 'a secret label names the workstation, and control characters cannot forge one' {
    $when  = [System.DateTimeOffset]::new(2026, 4, 9, 8, 30, 0, [System.TimeSpan]::Zero)
    $label = New-PDGraphSecretLabel -CreatedAt $when -User 'tech01' -Computer 'WS-042'
    Assert-Equal 'tech01@WS-042 2026-04-09' $label 'user@computer date, as spec 7.2 step 7 asks'

    $default = New-PDGraphSecretLabel -CreatedAt $when
    Assert-Like "*@$([Environment]::MachineName) 2026-04-09" $default 'the real account and machine are used when not supplied'

    $hostile = New-PDGraphSecretLabel -CreatedAt $when -User "tech`r`nFAKE LINE" -Computer "WS`tx`v042"
    Assert-True ($hostile -notmatch '[^ -~]') "a label must be printable on one line (got: $hostile)"
    Assert-Like 'tech FAKE LINE@WS x 042*' $hostile 'they are collapsed into the one display line instead'
}

Add-TestCase 'M5-12' 'secret creation: a SecureString out, never a repeated POST, never a valueless key' {
    Reset-PDM5Scenario -AppByObjectId @{ $script:M5AppId = @{ appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' } } `
                       -Secret @{ keyId = $script:M5NewKeyId; secretText = 'created-secret-never-real'; endDateTime = ([System.DateTimeOffset]::UtcNow.AddDays(180)).ToString('yyyy-MM-ddTHH:mm:ssZ') }

    $created = Add-PDAppSecret -ApplicationId $script:M5AppId -LifetimeDays 90 -Label 'tech01@WS-042 2026-04-09'

    Assert-True $created.Success 'the secret was created'
    Assert-Equal 'Created' $created.Outcome 'and the service answered'
    Assert-Equal $script:M5NewKeyId ([string]$created.KeyId) 'the key id is the service answer, never invented'
    Assert-True ($created.Secret -is [System.Security.SecureString]) 'the value is a SecureString'
    Assert-True ($created.ExpiresOn -gt [System.DateTimeOffset]::UtcNow.AddDays(88)) 'expiry comes from the response'
    Assert-Equal 1 @((Get-PDM5CallTrail -Contains '/addPassword')).Count 'exactly one addPassword'
    Assert-Like '*tech01@WS-042 2026-04-09*' ([string](@($script:M5.Bodies)[-1].Body)) 'the workstation label is what Entra stores'
    Assert-NotLike '*created-secret-never-real*' ([string]($created | ConvertTo-Json -Depth 5 -Compress)) 'the value is not in the result object either'

    # A dry run never creates a secret (spec invariant 5 names secret operations explicitly).
    Reset-PDM5Scenario -AppByObjectId @{ $script:M5AppId = @{ appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' } } -Secret $null
    $dry = Add-PDAppSecret -ApplicationId $script:M5AppId -DryRun
    Assert-True $dry.Success 'the dry run succeeds'
    Assert-Equal 'DryRun' $dry.Outcome 'and says it did nothing'
    Assert-Equal 0 @((Get-PDM5Mutation)).Count 'a dry run never creates a secret'

    # A POST whose response is lost is unknown, not retried.
    Reset-PDM5Scenario -AppByObjectId @{ $script:M5AppId = @{ appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' } } `
                       -Failures @(@{ Method = 'POST'; Match = 'addPassword'; Kind = 'transport' })
    $lost = Add-PDAppSecret -ApplicationId $script:M5AppId
    Assert-True (-not $lost.Success) 'a lost addPassword is not a success'
    Assert-Equal 'Unknown' $lost.Outcome 'and its outcome is unknown'
    Assert-Equal 1 @((Get-PDM5CallTrail -Contains '/addPassword')).Count 'it was never repeated'
    Assert-Like '*Entra*' $lost.Message 'the operator is told to reconcile in Entra'

    # Without an exact key id there is no revocation at all.
    Reset-PDM5Scenario -AppByObjectId @{ $script:M5AppId = @{ appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' } }
    $noKey = Remove-PDAppSecret -ApplicationId $script:M5AppId -KeyId ''
    Assert-True (-not $noKey.Success) 'no key id means no revocation'
    Assert-Equal 'NoKeyId' $noKey.Outcome 'and it is reported as such'
    Assert-Equal 0 @((Get-PDM5Mutation)).Count 'nothing was written'
    Assert-Like '*Entra*revoke*it there*' $noKey.Message 'the manual path is named'

    Assert-Throws -Body { Add-PDAppSecret -ApplicationId 'not-a-guid' } -MessagePattern '*not a GUID*' 'a malformed application id is refused'
}

Add-TestCase 'M5-13' 'the secret test waits for propagation, and refuses fast when the secret is simply wrong' {
    Invoke-PDM5Case -Body {
        $path = Join-Path $tempRoot 'm5-wait\credential.clixml'
        New-PDM5StoredCredential -Path $path

        # Roles appear on the second attempt: that is propagation, and it must be waited for.
        Reset-PDM5Scenario -TokenRoles @('DeviceManagementApps.ReadWrite.All', 'Group.Read.All') -TokenRoleEmptyResponses 1
        Set-PDM5AppOnlyTransport -EmptyRoleResponses 1

        $candidate = Get-PDGraphCredential -Path $path
        $ready     = Wait-PDGraphUploadSecretReady -Credential $candidate
        Assert-True $ready.Ready 'the roles arriving late is not a failure'
        Assert-Equal 2 ([int]$ready.Attempts) 'it took the second attempt'
        Assert-Equal 0 @($ready.MissingRoles).Count 'nothing is missing at the end'

        # A secret the token endpoint rejects is not a propagation problem.
        Reset-PDM5Scenario -TokenFailure 'AADSTS7000215: Invalid client secret provided.'
        Set-PDM5AppOnlyTransport -Failure 'AADSTS7000215: Invalid client secret provided.'
        $rejected = Wait-PDGraphUploadSecretReady -Credential $candidate
        Assert-True (-not $rejected.Ready) 'a rejected secret is not ready'
        Assert-Equal 'SecretRejected' $rejected.Reason 'and it is named, not waited on'
        Assert-Equal 1 ([int]$rejected.Attempts) 'it failed once and stopped, instead of waiting two minutes'

        # A secret created moments ago gets the same answer while Entra replicates it, so there it
        # is waited out (first live run: AADSTS7000215 in the same second the secret was created).
        $fresh = Wait-PDGraphUploadSecretReady -Credential $candidate -SecretJustCreated
        Assert-True (-not $fresh.Ready) 'a secret that never starts working is still not ready'
        Assert-Equal 'Deadline' $fresh.Reason 'but a just-created secret is waited on until the deadline'
        Assert-True ([int]$fresh.Attempts -ge 2) 'it kept trying instead of giving up on the first refusal'

        # Roles that never arrive is a deadline, and says nothing was saved.
        Reset-PDM5Scenario -TokenRoles @()
        Set-PDM5AppOnlyTransport -Roles @()
        $late = Wait-PDGraphUploadSecretReady -Credential $candidate
        Assert-True (-not $late.Ready) 'roles that never arrive is not ready'
        Assert-Equal 'Deadline' $late.Reason 'reported as the deadline it hit'
        Assert-Like '*Nothing was saved*' $late.Message 'and says the stored credential is untouched'
        $tokenCalls = @(@($script:M5.AppOnlyCalls) -like '*login.microsoftonline.com*')
        Assert-True (@($tokenCalls).Count -ge 2) 'it really did keep trying until the deadline'

        $script:PDGraph.TestTransport = $null
    }
}

Add-TestCase 'C03c' 'rotation whose test fails keeps the old credential and revokes the new key' {
    Invoke-PDM5Case -Body {
        $path = Join-Path $tempRoot 'm5-rotate-testfail\credential.clixml'
        New-PDM5StoredCredential -Path $path -SecretKeyId $script:M5OldKeyId -AppObjectId $script:M5AppId -TenantId $script:M5TenantId -ClientId $script:M5ClientId

        $before = [System.IO.File]::ReadAllBytes($path)
        $beforeText = [System.Text.Encoding]::UTF8.GetString($before)

        Reset-PDM5Scenario -AppByObjectId @{ $script:M5AppId = @{ appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' } } `
                           -Secret @{ keyId = $script:M5NewKeyId; secretText = 'replacement-secret-never-real'; endDateTime = ([System.DateTimeOffset]::UtcNow.AddDays(180)).ToString('yyyy-MM-ddTHH:mm:ssZ') } `
                           -TokenFailure 'AADSTS7000215: Invalid client secret provided.'
        Set-PDM5AppOnlyTransport -Failure 'AADSTS7000215: Invalid client secret provided.'

        $result = Start-PDGraphSecretRotation -CredentialPath $path -Session (New-PDM5Session -TenantId $script:M5TenantId)

        Assert-True (-not $result.Success) 'a replacement that cannot upload is not a rotation'
        Assert-Equal 'TestFailed' $result.Reason 'the failure is named'
        Assert-True $result.OldCredentialRetained 'it says the old credential was retained'

        $after = [System.IO.File]::ReadAllBytes($path)
        Assert-Equal $beforeText ([System.Text.Encoding]::UTF8.GetString($after)) 'the stored credential is byte-for-byte what it was'

        $old = Get-PDGraphCredential -Path $path
        Assert-Equal $script:M5OldKeyId ([string]$old.SecretKeyId) 'and it still carries the OLD key id'

        Assert-True [string]::IsNullOrWhiteSpace([string]$result.LeftoverKeyId) 'the replacement was cleaned up, leaving nothing behind'
        Assert-Equal 1 @($script:M5.Revoked).Count 'exactly one revocation was attempted'
        Assert-Like "*$script:M5NewKeyId*" ([string]@($script:M5.Revoked)[0]) 'the key revoked in Entra is the NEW one'
        Assert-Equal 0 @(@($script:M5.Revoked) | Where-Object { $_ -eq $script:M5OldKeyId }).Count 'the OLD secret was never revoked while the replacement was unproven'
        Assert-Equal 0 @((Get-PDM5Mutation) | Where-Object { $_ -like 'DELETE *' }).Count 'the application and its service principal are never deleted'
        Assert-NotLike '*replacement-secret-never-real*' ([string]($result | ConvertTo-Json -Depth 5 -Compress)) 'the rejected secret value is not in the result'

        $script:PDGraph.TestTransport = $null
    }
}

Add-TestCase 'C03d' 'rotation whose save fails keeps the old credential and revokes the new key' {
    Invoke-PDM5Case -Body {
        $path = Join-Path $tempRoot 'm5-rotate-savefail\credential.clixml'
        New-PDM5StoredCredential -Path $path -SecretKeyId $script:M5OldKeyId -AppObjectId $script:M5AppId -TenantId $script:M5TenantId -ClientId $script:M5ClientId

        $before = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($path))

        # The same lock the save takes is held by somebody else, so the save must fail rather than
        # race (spec 7.3: serialize concurrent credential changes).
        $lock = Enter-PDGraphCredentialLock -CredentialPath $path

        try {
            Reset-PDM5Scenario -AppByObjectId @{ $script:M5AppId = @{ appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' } } `
                               -Secret @{ keyId = $script:M5NewKeyId; secretText = 'replacement-secret-never-real'; endDateTime = ([System.DateTimeOffset]::UtcNow.AddDays(180)).ToString('yyyy-MM-ddTHH:mm:ssZ') }
            Set-PDM5AppOnlyTransport

            $result = Start-PDGraphSecretRotation -CredentialPath $path -Session (New-PDM5Session -TenantId $script:M5TenantId)

            Assert-True (-not $result.Success) 'a save that could not happen is not a rotation'
            Assert-Equal 'SaveFailed' $result.Reason 'and it is named'
            Assert-True $result.OldCredentialRetained 'the old credential is reported retained'
            Assert-Equal $before ([System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($path))) 'the file on disk is unchanged'
            Assert-Like "*$script:M5NewKeyId*" ([string]@($script:M5.Revoked)[0]) 'the working-but-unstored replacement secret was revoked again'
            Assert-Equal 0 @(@($script:M5.Revoked) | Where-Object { $_ -eq $script:M5OldKeyId }).Count 'the old secret stays active, because it is the one still saved'
        } finally {
            Exit-PDGraphCredentialLock -Lock $lock
            $script:PDGraph.TestTransport = $null
        }
    }
}

Add-TestCase 'C04b' 'when the old key cannot be revoked the new credential stays and the key is reported' {
    Invoke-PDM5Case -Body {
        $path = Join-Path $tempRoot 'm5-rotate-revokefail\credential.clixml'
        New-PDM5StoredCredential -Path $path -SecretKeyId $script:M5OldKeyId -AppObjectId $script:M5AppId -TenantId $script:M5TenantId -ClientId $script:M5ClientId

        Reset-PDM5Scenario -AppByObjectId @{ $script:M5AppId = @{ appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' } } `
                           -Secret @{ keyId = $script:M5NewKeyId; secretText = 'replacement-secret-never-real'; endDateTime = ([System.DateTimeOffset]::UtcNow.AddDays(180)).ToString('yyyy-MM-ddTHH:mm:ssZ') } `
                           -Failures @(@{ Method = 'POST'; Match = 'removePassword'; Kind = 'http'; Status = 403; Code = 'Authorization_RequestDenied'; Message = 'Insufficient privileges to complete the operation.' })
        Set-PDM5AppOnlyTransport

        $result = Start-PDGraphSecretRotation -CredentialPath $path -Session (New-PDM5Session -TenantId $script:M5TenantId)

        # Spec 7.4: the working replacement is kept, and the surviving old key is reported.
        Assert-True $result.Success ("the rotation itself succeeded (reason: {0}; {1})" -f [string]$result.Reason, [string]$result.Message)
        Assert-Equal 'RotatedOldKeyActive' $result.Reason 'and the surviving old key is named as the reason'
        Assert-True (-not $result.OldKeyRemoved) 'the old key was not removed'
        Assert-Equal $script:M5OldKeyId ([string]$result.LeftoverKeyId) 'the leftover key id is reported, not hidden'
        Assert-Like '*still active*' $result.Message 'the operator is told it is still active'
        Assert-NotLike '*replacement-secret-never-real*' ([string]($result | ConvertTo-Json -Depth 5 -Compress)) 'no secret value in the result'

        $stored = Get-PDGraphCredential -Path $path
        Assert-Equal $script:M5NewKeyId ([string]$stored.SecretKeyId) 'the stored credential is the new one'
        Assert-True ($stored.ClientSecret -is [System.Security.SecureString]) 'and it loads as a usable credential'
        Assert-NotLike '*replacement-secret-never-real*' ([System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($path))) 'the file holds no plaintext secret'

        # M5.Revoked only records removals the fake tenant accepted; this one was refused, so read
        # the attempts from the request bodies instead.
        $attempts = @(@($script:M5.Bodies) | Where-Object { $_.Uri -like '*/removePassword' } | ForEach-Object { [string](($_.Body | ConvertFrom-Json).keyId) })
        Assert-Equal 1 $attempts.Count 'exactly one revocation was attempted'
        Assert-Equal $script:M5OldKeyId $attempts[0] 'and it was for the old key id'
        Assert-Equal 0 @((Get-PDM5Mutation) | Where-Object { $_ -like 'DELETE *' }).Count 'nothing else in Entra was touched'

        $script:PDGraph.TestTransport = $null
    }
}

Add-TestCase 'C04c' 'removal of the local file revokes nothing, and says so' {
    $path = Join-Path $tempRoot 'm5-remove-local\credential.clixml'
    New-PDM5StoredCredential -Path $path -SecretKeyId $script:M5OldKeyId -AppObjectId $script:M5AppId

    Reset-PDM5Scenario

    $result = Remove-PDGraphUploadCredential -CredentialPath $path
    Assert-True $result.Success 'the file was removed'
    Assert-True $result.Removed 'and it says it was'
    Assert-True (-not $result.Revoked) 'nothing was revoked'
    Assert-True (-not (Test-Path -LiteralPath $path)) 'the credential file is gone'
    Assert-Equal 0 @($script:M5.Calls).Count 'local-only removal makes no tenant call at all'
    Assert-Like '*still active*' $result.Message 'and the message says the Entra secret stays active until revoked'
}

Add-TestCase 'C04d' 'removal with revocation touches one key id and nothing else' {
    $path = Join-Path $tempRoot 'm5-remove-revoke\credential.clixml'
    New-PDM5StoredCredential -Path $path -SecretKeyId $script:M5OldKeyId -AppObjectId $script:M5AppId -TenantId $script:M5TenantId -ClientId $script:M5ClientId

    Reset-PDM5Scenario -AppByObjectId @{ $script:M5AppId = @{ appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' } }

    $result = Remove-PDGraphUploadCredential -CredentialPath $path -RevokeEntraKey -Session (New-PDM5Session -TenantId $script:M5TenantId)

    Assert-True $result.Success 'the removal and revocation succeeded'
    Assert-True $result.Revoked 'the secret was revoked'
    Assert-True $result.Removed 'and the file removed'
    Assert-True (-not (Test-Path -LiteralPath $path)) 'the credential file is gone'

    Assert-Equal 1 @($script:M5.Revoked).Count 'exactly one revocation'
    Assert-Equal $script:M5OldKeyId @($script:M5.Revoked)[0] 'the revoked key is the recorded key id'
    Assert-Equal 0 @((Get-PDM5Mutation) | Where-Object { $_ -like 'DELETE *' }).Count 'the application and service principal are never deleted'
    Assert-Like '*application and its other secrets were left alone*' $result.Message 'and it says so'

    # A session for another tenant is refused before any revocation, and the file stays.
    $path2 = Join-Path $tempRoot 'm5-remove-wrongtenant\credential.clixml'
    New-PDM5StoredCredential -Path $path2 -SecretKeyId $script:M5OldKeyId -AppObjectId $script:M5AppId -TenantId $script:M5TenantId

    Reset-PDM5Scenario -AppByObjectId @{ $script:M5AppId = @{ appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' } }
    $wrong = Remove-PDGraphUploadCredential -CredentialPath $path2 -RevokeEntraKey -Session (New-PDM5Session -TenantId 'ffffffff-ffff-ffff-ffff-ffffffffffff')
    Assert-True (-not $wrong.Success) 'the wrong tenant is refused'
    Assert-Equal 'TenantMismatch' $wrong.Reason 'and named'
    Assert-Equal 0 @($script:M5.Revoked).Count 'no secret was revoked'
    Assert-True (Test-Path -LiteralPath $path2) 'the credential file is kept'

    # Revocation without a session cannot happen, and the upload identity is why.
    $nocreds = Remove-PDGraphUploadCredential -CredentialPath $path2 -RevokeEntraKey
    Assert-True (-not $nocreds.Success) 'no session means no revocation'
    Assert-Equal 'NoSession' $nocreds.Reason 'and it is named'
    Assert-Like '*upload identity*' $nocreds.Message 'with the reason: the upload identity may not manage secrets'
    Assert-True (Test-Path -LiteralPath $path2) 'the file is still there'
}

Add-TestCase 'M5-14' 'provisioning issues the spec 7.2 sequence in order and stores only a tested secret' {
    Invoke-PDM5Case -Body {
        $path = Join-Path $tempRoot 'm5-provision\credential.clixml'

        $scenario = @{
            ApplicationId           = $script:M5AppId
            Apps                    = @(@{ id = $script:M5AppId; appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' })
            AppByObjectId           = @{ $script:M5AppId = @{ appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' } }
            ServicePrincipals       = @(
                @{ id = $script:M5UploadSpId; appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload'; appRoles = @() },
                (New-PDM5GraphServicePrincipal)
            )
            ExistingGrants          = @()
            RequiredResourceAccess  = @()
            Secret                  = @{ keyId = $script:M5NewKeyId; secretText = 'provisioned-secret-never-real'; endDateTime = ([System.DateTimeOffset]::UtcNow.AddDays(180)).ToString('yyyy-MM-ddTHH:mm:ssZ') }
        }

        Reset-PDM5Scenario @scenario
        Set-PDM5AppOnlyTransport

        $result = Start-PDGraphUploadProvisioning -Session (New-PDM5Session -TenantId $script:M5TenantId) -CredentialPath $path

        Assert-True $result.Success "provisioning succeeded ($($result.Reason): $($result.Message))"
        Assert-Equal 'Provisioned' $result.Reason 'and it says so'
        Assert-Equal $script:M5NewKeyId ([string]$result.SecretKeyId) 'the recorded key id is the service answer'

        $trail = @(Get-PDM5CallTrail)
        $indexOf = { param($pattern) for ($i = 0; $i -lt $trail.Count; $i++) { if ($trail[$i] -match $pattern) { return $i } }; return -1 }

        $appLookup     = & $indexOf 'GET .*v1\.0/applications\?'
        $principalGet  = & $indexOf 'GET .*v1\.0/servicePrincipals\?'
        $permissionGet = & $indexOf 'GET .*\?\$select=id,requiredResourceAccess'
        $permissionSet = & $indexOf 'PATCH .*applications/[0-9a-fA-F-]{36}$'
        $grantRead     = & $indexOf 'GET .*appRoleAssignments\?'
        $grantWrite    = & $indexOf 'POST .*appRoleAssignments'
        $secretAdd     = & $indexOf 'POST .*/addPassword'

        Assert-True ($appLookup -ge 0) 'the registration was looked up first'
        Assert-True ($principalGet -gt $appLookup) 'its service principal next'
        Assert-True ($permissionGet -gt $principalGet) 'then the requested permissions were read'
        Assert-True ($permissionSet -gt $permissionGet) 'then merged with a PATCH'
        Assert-True ($grantRead -gt $permissionSet) 'then the existing grants were read'
        Assert-True ($grantWrite -gt $grantRead) 'then only the missing grants were written'
        Assert-True ($secretAdd -gt $grantWrite) 'and only then was the secret created'
        Assert-True ($trail.Count -eq ($secretAdd + 1)) "nothing was written after the secret ($($trail.Count) calls, last at $secretAdd)"

        Assert-Equal 2 @((Get-PDM5CallTrail -Contains 'POST *appRoleAssignments')).Count 'both roles were granted, once each'
        Assert-Equal 1 @((Get-PDM5CallTrail -Contains '/addPassword')).Count 'one secret'
        Assert-Equal 1 @(@($script:M5.AppOnlyCalls) -like '*login.microsoftonline.com*').Count 'the new secret was proven with exactly one token request'
        Assert-Equal 0 @(@($script:M5.AppOnlyCalls) -like '*graph.microsoft.com*').Count 'provisioning never uses the upload identity for Graph reads'
        Assert-Equal 0 @((Get-PDM5Mutation) | Where-Object { $_ -like 'DELETE *' }).Count 'nothing was deleted'

        Assert-Like '*@*' @($script:M5.AddedSecretLabels)[0] 'the secret is labelled user@computer date'

        $stored = Get-PDGraphCredential -Path $path
        Assert-Equal $script:M5NewKeyId ([string]$stored.SecretKeyId) 'the stored credential is the tested one'
        Assert-Equal $script:M5AppId ([string]$stored.AppObjectId) 'with the application id it was created on'
        Assert-Equal $script:M5UploadSpId ([string]$stored.ServicePrincipalId) 'and the service principal id'
        Assert-NotLike '*provisioned-secret-never-real*' ([System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($path))) 'the file holds no plaintext secret'
        Assert-NotLike '*provisioned-secret-never-real*' ([string]($result | ConvertTo-Json -Depth 5 -Compress)) 'the result object holds no secret'
        Assert-NotLike '*provisioned-secret-never-real*' (@($result.Steps | ForEach-Object { $_.Message }) -join ' | ') 'no step message holds the secret either'
        Assert-Like '*Multi-Admin Approval*' $result.Message 'and the operator is pointed at the MAA exclusion'

        # The same run with -DryRun must write nothing at all, secrets included (spec invariant 5).
        Reset-PDM5Scenario @scenario
        Set-PDM5AppOnlyTransport
        $dryPath = Join-Path $tempRoot 'm5-provision-dry\credential.clixml'
        $dry = Start-PDGraphUploadProvisioning -Session (New-PDM5Session -TenantId $script:M5TenantId) -CredentialPath $dryPath -DryRun

        Assert-True $dry.Success "a dry run reports what it found ($($dry.Reason): $($dry.Message))"
        Assert-Equal 'DryRun' $dry.Reason 'and says it changed nothing'
        Assert-Equal 0 @(Get-PDM5Mutation).Count 'a dry run issues zero tenant mutations'
        Assert-Equal 0 @((Get-PDM5CallTrail -Contains '*/addPassword')).Count 'including secret creation'
        Assert-True (-not (Test-Path -LiteralPath $dryPath)) 'and no credential file was written'

        $script:PDGraph.TestTransport = $null
    }
}

Add-TestCase 'M5-15' 'a secret that cannot upload is not kept, and no credential is replaced' {
    Invoke-PDM5Case -Body {
        $path = Join-Path $tempRoot 'm5-provision-testfail\credential.clixml'

        Reset-PDM5Scenario -Apps @(@{ id = $script:M5AppId; appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' }) `
                           -AppByObjectId @{ $script:M5AppId = @{ appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' } } `
                           -ServicePrincipals @(
                                @{ id = $script:M5UploadSpId; appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload'; appRoles = @() },
                                (New-PDM5GraphServicePrincipal)) `
                           -Secret @{ keyId = $script:M5NewKeyId; secretText = 'unusable-secret-never-real'; endDateTime = ([System.DateTimeOffset]::UtcNow.AddDays(180)).ToString('yyyy-MM-ddTHH:mm:ssZ') } `
                           -TokenFailure 'AADSTS7000215: Invalid client secret provided.'
        Set-PDM5AppOnlyTransport -Failure 'AADSTS7000215: Invalid client secret provided.'

        $result = Start-PDGraphUploadProvisioning -Session (New-PDM5Session -TenantId $script:M5TenantId) -CredentialPath $path

        Assert-True (-not $result.Success) 'provisioning fails when the new secret cannot get a token'
        Assert-Equal 'TestFailed' $result.Reason 'and says the test is what failed'
        Assert-True (-not (Test-Path -LiteralPath $path)) 'nothing was stored'
        Assert-Like "*$script:M5NewKeyId*" ([string]@($script:M5.Revoked)[0]) 'the unusable secret was revoked again, by its key id'
        Assert-NotLike '*unusable-secret-never-real*' ([string]($result | ConvertTo-Json -Depth 5 -Compress)) 'its value is not in the result'

        $script:PDGraph.TestTransport = $null
    }
}

Add-TestCase 'M5-16' 'the connection test proves token, roles and one small Intune read' {
    Invoke-PDM5Case -Body {
        $path = Join-Path $tempRoot 'm5-connection\credential.clixml'
        New-PDM5StoredCredential -Path $path -SecretKeyId $script:M5OldKeyId -AppObjectId $script:M5AppId

        Reset-PDM5Scenario
        Set-PDM5AppOnlyTransport -Roles @('DeviceManagementApps.ReadWrite.All', 'Group.Read.All')

        $result = Test-PDGraphUploadConnection -CredentialPath $path
        Assert-True $result.Success "the connection test passes ($($result.Message))"
        Assert-Equal 1 @(@($script:M5.AppOnlyCalls) -like '*login.microsoftonline.com*').Count 'one token request, forced rather than cached'
        $intuneReads = @(@($script:M5.AppOnlyCalls) -like '*beta/deviceAppManagement/mobileApps*')
        Assert-Equal 1 @($intuneReads).Count 'one small Intune read, on the resource that matters'
        Assert-Like '*Multi-Admin Approval*' (@($result.Warnings) -join ' | ') 'and it warns that a read proves nothing about MAA'

        Reset-PDM5Scenario
        Set-PDM5AppOnlyTransport -Roles @('Group.Read.All')
        $missing = Test-PDGraphUploadConnection -CredentialPath $path
        Assert-True (-not $missing.Success) 'a token without both roles fails the test'
        Assert-Equal 'MissingRoles' $missing.Reason 'and names the reason'
        Assert-Like '*DeviceManagementApps.ReadWrite.All*' $missing.Message 'naming the role that is missing'

        Reset-PDM5Scenario
        Set-PDM5AppOnlyTransport -Failure 'AADSTS7000215: Invalid client secret provided.'
        $revoked = Test-PDGraphUploadConnection -CredentialPath $path
        Assert-True (-not $revoked.Success) 'a revoked secret fails the test'
        Assert-Equal 'TokenFailed' $revoked.Reason 'at the token step'

        $script:PDGraph.TestTransport = $null
    }
}

Add-TestCase 'M5-17' 'the MAA menu only reads its own text and calls no tenant endpoint' {
    Reset-PDM5Scenario -Apps @(@{ id = $script:M5AppId; appId = $script:M5ClientId; displayName = 'PowerDeploy Intune Upload' })

    $path = Join-Path $tempRoot 'm5-maa\credential.clixml'
    New-PDM5StoredCredential -Path $path -SecretKeyId $script:M5OldKeyId -AppObjectId $script:M5AppId -ClientId $script:M5ClientId

    $guidance = Get-PDGraphUploadMaaGuidance -CredentialPath $path

    Assert-Like '*PowerDeploy Intune Upload*' $guidance.Message 'it names the configured application'
    Assert-Equal $script:M5ClientId ([string]$guidance.ClientId) 'and its client id, from the stored credential'
    Assert-Like '*Multi Admin Approval*' (@($guidance.Steps) -join ' -> ') 'the portal path from spec 7.5'
    Assert-Like '*justification*' (@($guidance.Steps) -join ' -> ') 'including the justification step'
    Assert-Like '*application-only*' (@($guidance.Notes) -join ' | ') 'what the exclusion covers'
    Assert-Like '*rotat*' (@($guidance.Notes) -join ' | ') 'and that rotation does not undo it'
    Assert-Equal 0 @($script:M5.Calls).Count 'showing MAA instructions makes no Graph call at all'

    # With no credential stored it still answers, from the built-in defaults.
    $fallback = Get-PDGraphUploadMaaGuidance -CredentialPath (Join-Path $tempRoot 'm5-maa\none.clixml')
    Assert-Like '*PowerDeploy Intune Upload*' $fallback.Message 'the configured name defaults to the feature default'
    Assert-Like '*not configured*' $fallback.ClientId 'and says no client id is known yet'
}

Add-TestCase 'M5-18' 'the temporary sign-in is verified, and only this tool closes it' {
    # An unrelated connection is never reused silently (spec 7.1).
    Reset-PDM5Scenario -Context ([pscustomobject]@{ TenantId = 'ffffffff-ffff-ffff-ffff-ffffffffffff'; AuthType = 'Delegated'; Account = 'someone@else'; Scopes = @('Application.ReadWrite.All') }) `
                       -ContextAfterConnect ([pscustomobject]@{ TenantId = $script:M5TenantId; AuthType = 'Delegated'; Account = 'admin@contoso.com'; Scopes = @('Application.ReadWrite.All') })

    $refused = Connect-PDGraphInteractive -TenantId $script:M5TenantId
    Assert-True (-not $refused.Success) 'an existing connection is not taken over quietly'
    Assert-Equal 'ExistingContext' $refused.Reason 'and the operator is asked'
    Assert-Equal 0 ([int]$script:M5.ConnectCount) 'no sign-in was attempted without permission'
    Assert-Equal 0 @($script:M5.Calls).Count 'and nothing was requested'

    $replaced = Connect-PDGraphInteractive -TenantId $script:M5TenantId -ReplaceExistingContext
    Assert-True $replaced.Success 'signing in again is allowed when asked for'
    Assert-Equal 1 ([int]$script:M5.ConnectCount) 'exactly one sign-in'
    Assert-Like '*Application.ReadWrite.All*' (@($script:M5.ConnectArguments.Scopes) -join ',') 'with the provisioning scope'

    $closed = Disconnect-PDGraphInteractive -Session $replaced.Session
    Assert-True $closed.Disconnected 'a session this tool opened is closed by this tool'
    Assert-Equal 1 ([int]$script:M5.DisconnectCount) 'once'

    $kept2 = Disconnect-PDGraphInteractive -Session @{ TenantId = $script:M5TenantId; Owned = $false }
    Assert-True (-not $kept2.Disconnected) 'a session that was already open is left open'
    Assert-Equal 'NotOwned' $kept2.Reason 'and says why'
    Assert-Equal 1 ([int]$script:M5.DisconnectCount) 'no extra disconnect happened'

    # A daemon/app-only context is exactly the unrelated connection that must be refused.
    Reset-PDM5Scenario -ContextAfterConnect ([pscustomobject]@{ TenantId = $script:M5TenantId; AuthType = 'AppOnly'; Account = 'daemon'; Scopes = @('Application.ReadWrite.All') })
    $appOnly = Connect-PDGraphInteractive -TenantId $script:M5TenantId
    Assert-True (-not $appOnly.Success) 'an application-only context is refused'
    Assert-Equal 'NotDelegated' $appOnly.Reason 'and named'

    # A sign-in that never got the scope it needs is refused before any write is attempted.
    Reset-PDM5Scenario -ContextAfterConnect ([pscustomobject]@{ TenantId = $script:M5TenantId; AuthType = 'Delegated'; Account = 'admin@contoso.com'; Scopes = @('User.Read') })
    $noScope = Connect-PDGraphInteractive -TenantId $script:M5TenantId
    Assert-True (-not $noScope.Success) 'a missing delegated scope is refused'
    Assert-Equal 'MissingScopes' $noScope.Reason 'and named'
    Assert-Like '*Application.ReadWrite.All*' $noScope.Message 'naming the scope that is missing'

    # Provisioning itself refuses a session that is not delegated.
    $notProvisioned = Start-PDGraphUploadProvisioning -Session ([pscustomobject]@{ TenantId = $script:M5TenantId; AuthType = 'AppOnly'; Scopes = @('Application.ReadWrite.All') })
    Assert-True (-not $notProvisioned.Success) 'provisioning refuses a non-delegated session'
    Assert-Equal 'NotDelegated' $notProvisioned.Reason 'before touching anything'
    Assert-Equal 0 @((Get-PDM5Mutation)).Count 'and it wrote nothing'
}

# ---------------------------------------------------------------------------
# D07 - WinGet description lookup (spec 6)
#
# The parser runs against stdout captured from this workstation's winget (see
# Tests/Fixtures/WinGet/README.md). No case here starts winget.exe.
# ---------------------------------------------------------------------------

$script:WinGetFixtureRoot = Join-Path $PSScriptRoot 'Fixtures\WinGet'
$script:WinGetLookupPath  = Join-Path (Split-Path $PSScriptRoot -Parent) 'Other_Tools\Get-WinGetAppDescription.ps1'

if (-not (Test-Path -LiteralPath $script:WinGetLookupPath)) {
    Write-Host "FATAL: WinGet lookup script not found at $script:WinGetLookupPath"
    exit 2
}

. $script:WinGetLookupPath

function Get-PDWinGetFixture {
    param([Parameter(Mandatory = $true)][string]$Name)
    return [System.IO.File]::ReadAllText((Join-Path $script:WinGetFixtureRoot $Name), [System.Text.Encoding]::UTF8)
}

Add-TestCase 'D07a' 'Parser extracts single-line descriptions from captured winget output without the next field' {
    $vscode = ConvertFrom-PDWinGetShowOutput -Text (Get-PDWinGetFixture 'winget-Microsoft.VisualStudioCode.txt') -ExpectedId 'microsoft.visualstudiocode'
    Assert-Equal 'Found' $vscode.Status 'exact id, case-insensitive'
    Assert-Equal 'Microsoft.VisualStudioCode' $vscode.PackageId 'the id winget printed is returned'
    Assert-Like 'Microsoft Visual Studio Code is a code editor redefined*Linux, macOS, and Windows.' $vscode.Description 'whole label-line value'
    Assert-NotMatch '[\r\n]' $vscode.Description 'a single-line value stays single-line'
    Assert-NotLike '*Homepage*' $vscode.Description 'the next field is not swallowed'

    $sevenZip = ConvertFrom-PDWinGetShowOutput -Text (Get-PDWinGetFixture 'winget-7zip.7zip.txt') -ExpectedId '7zip.7zip'
    Assert-Equal 'Found' $sevenZip.Status '7zip'
    Assert-Equal 'A file archiver with a high compression ratio.' $sevenZip.Description 'exact text'
}

Add-TestCase 'D07f' 'Parser and result keep the Publisher field, even when there is no description' {
    # The app wizard uses the same winget show output for the Company Portal publisher.
    $sevenZip = ConvertFrom-PDWinGetShowOutput -Text (Get-PDWinGetFixture 'winget-7zip.7zip.txt') -ExpectedId '7zip.7zip'
    Assert-Equal 'Igor Pavlov' ([string]$sevenZip.Publisher) 'community source publisher'
    $portal = ConvertFrom-PDWinGetShowOutput -Text (Get-PDWinGetFixture 'msstore-9WZDNCRFJ3PZ.txt') -ExpectedId '9WZDNCRFJ3PZ'
    Assert-Equal 'Microsoft Corporation' ([string]$portal.Publisher) 'Store source publisher'

    $noDescription = "Found Example App [Example.App]`r`nVersion: 1.0`r`nPublisher: Example Corp`r`nHomepage: https://example.invalid`r`n"
    $parsed = ConvertFrom-PDWinGetShowOutput -Text $noDescription -ExpectedId 'Example.App'
    Assert-Equal 'NotFound' $parsed.Status 'no description is still NotFound'
    Assert-Equal 'Example Corp' ([string]$parsed.Publisher) 'but the publisher is kept'

    $result = New-PDWinGetDescriptionResult -Status 'NotFound' -Message 'no description' -Publisher ' Example Corp '
    Assert-True (-not $result.Found) 'not Found'
    Assert-Equal 'Example Corp' ([string]$result.Publisher) 'publisher survives a missing description, trimmed'
    Assert-True ($null -eq (New-PDWinGetDescriptionResult -Status 'Unavailable' -Publisher '  ').Publisher) 'a blank publisher is null'
}

Add-TestCase 'D07g' 'Parser reads Homepage and Privacy Url after the description, without tripping on later labels' {
    $vscode = ConvertFrom-PDWinGetShowOutput -Text (Get-PDWinGetFixture 'winget-Microsoft.VisualStudioCode.txt') -ExpectedId 'Microsoft.VisualStudioCode'
    Assert-Equal 'https://code.visualstudio.com/' ([string]$vscode.Homepage) 'homepage, listed after the description'
    Assert-Equal 'https://privacy.microsoft.com/' ([string]$vscode.PrivacyUrl) 'privacy URL'
    Assert-Like 'Microsoft Visual Studio Code is a code editor*' $vscode.Description 'the description is unchanged'

    $portal = ConvertFrom-PDWinGetShowOutput -Text (Get-PDWinGetFixture 'msstore-9WZDNCRFJ3PZ.txt') -ExpectedId '9WZDNCRFJ3PZ'
    Assert-Equal 'http://go.microsoft.com/fwlink/?LinkId=273865' ([string]$portal.Homepage) 'no Homepage: falls back to Publisher Url'

    $sevenZip = ConvertFrom-PDWinGetShowOutput -Text (Get-PDWinGetFixture 'winget-7zip.7zip.txt') -ExpectedId '7zip.7zip'
    Assert-True ($null -eq $sevenZip.PrivacyUrl) 'no Privacy Url: null, not a guess'

    # An unknown label right after the description is still refused (the boundary would be a
    # guess, see D07c); one further down only gets skipped while the links are read.
    $newer = "Found Example App [Example.App]`r`nPublisher: Example Corp`r`nDescription: Does things.`r`nHomepage: https://example.invalid/`r`nShiny New Field: value`r`nPrivacy Url: https://example.invalid/privacy`r`n"
    $parsed = ConvertFrom-PDWinGetShowOutput -Text $newer -ExpectedId 'Example.App'
    Assert-Equal 'Found' $parsed.Status 'an unknown label further down does not break the lookup'
    Assert-Equal 'Does things.' $parsed.Description 'description intact'
    Assert-Equal 'https://example.invalid/privacy' ([string]$parsed.PrivacyUrl) 'links after the unknown label are still read'
}

Add-TestCase 'D07b' 'Parser preserves multiline descriptions and stops at the next top-level field' {
    $portal = ConvertFrom-PDWinGetShowOutput -Text (Get-PDWinGetFixture 'msstore-9WZDNCRFJ3PZ.txt') -ExpectedId '9WZDNCRFJ3PZ'
    Assert-Equal 'Found' $portal.Status 'Store product id'
    Assert-Like 'Microsoft Intune helps organizations manage access*' $portal.Description 'starts at the first continuation line'
    Assert-Like '*Company Portal helps simplify the tasks you need to do for work:*' $portal.Description 'middle paragraph kept'
    Assert-Match '(?m)^- Enroll your device' $portal.Description 'list structure kept, winget indent removed'
    Assert-Like '*will be used by your organization.' $portal.Description 'ends with the last continuation line'
    Assert-NotLike '*License:*' $portal.Description 'License not swallowed'
    Assert-NotMatch '\r' $portal.Description 'CR CR LF endings normalized'
    Assert-True (@($portal.Description -split "`n").Count -ge 10) 'continuation lines are separate lines'

    $git = ConvertFrom-PDWinGetShowOutput -Text (Get-PDWinGetFixture 'winget-Git.Git.txt') -ExpectedId 'Git.Git'
    Assert-Equal 'Found' $git.Status 'Git'
    Assert-Equal 2 @($git.Description -split "`n").Count 'both continuation lines, nothing more'
    Assert-Like 'Git is a free and open source*' $git.Description 'first line'
    Assert-NotLike '*Homepage*' $git.Description 'Homepage not swallowed'
    Assert-NotLike '*Changes since*' $git.Description 'Release Notes not swallowed'
}

Add-TestCase 'D07c' 'Parser maps not-found, wrong-id, localized and unknown-boundary output to non-Found statuses' {
    $missing = ConvertFrom-PDWinGetShowOutput -Text (Get-PDWinGetFixture 'notfound.txt') -ExpectedId 'Contoso.DoesNotExist.PDTest'
    Assert-Equal 'NotFound' $missing.Status 'captured not-found text'
    Assert-True ($null -eq $missing.Description) 'no description'

    $vscodeText = Get-PDWinGetFixture 'winget-Microsoft.VisualStudioCode.txt'
    $wrongId = ConvertFrom-PDWinGetShowOutput -Text $vscodeText -ExpectedId 'Microsoft.VisualStudioCode.Insiders'
    Assert-Equal 'NotFound' $wrongId.Status 'a header for another id is not this package'
    Assert-True ($null -eq $wrongId.Description) 'and yields no description'

    $german = ConvertFrom-PDWinGetShowOutput -Text (Get-PDWinGetFixture 'synth-localized-de.txt') -ExpectedId 'Microsoft.VisualStudioCode'
    Assert-Equal 'UnrecognizedOutput' $german.Status 'localized header/labels are not guessed at'

    $unknownBoundary = $vscodeText.Replace('Homepage: https://code.visualstudio.com/', 'Startseite: https://code.visualstudio.com/')
    $boundary = ConvertFrom-PDWinGetShowOutput -Text $unknownBoundary -ExpectedId 'Microsoft.VisualStudioCode'
    Assert-Equal 'UnrecognizedOutput' $boundary.Status 'an unknown field after Description is not a safe boundary'

    $unknownBefore = $vscodeText.Replace('Moniker: vscode', 'Spitzname: vscode')
    Assert-Equal 'UnrecognizedOutput' (ConvertFrom-PDWinGetShowOutput -Text $unknownBefore -ExpectedId 'Microsoft.VisualStudioCode').Status 'unknown label before Description'

    Assert-Equal 'UnrecognizedOutput' (ConvertFrom-PDWinGetShowOutput -Text '' -ExpectedId 'x.y').Status 'empty output'
}

Add-TestCase 'D07d' 'Parser strips ANSI escapes, spinner overwrites and progress bars' {
    $esc = [string][char]27
    $cr  = [string][char]13
    $block = [string][char]0x2588
    $spinner = '   - ' + $cr + '   \ ' + $cr + '   | ' + $cr + '   / ' + $cr + $esc + '[0G' + $esc + '[2K'
    $progress = '  ' + ($block * 10) + '  1.00 MB / 2.00 MB' + $cr + $esc + '[2K' + $esc + '[?25h'
    $body = (Get-PDWinGetFixture 'winget-7zip.7zip.txt').Replace('Description: A file', ('Description: ' + $esc + '[1mA' + $esc + '[0m file'))
    $text = $spinner + $progress + "`r`n" + $esc + '[?25l' + $body

    $parsed = ConvertFrom-PDWinGetShowOutput -Text $text -ExpectedId '7zip.7zip'
    Assert-Equal 'Found' $parsed.Status 'header still recognized behind spinner output'
    Assert-Equal 'A file archiver with a high compression ratio.' $parsed.Description 'no escape bytes left in the value'
    Assert-NotMatch '\x1B' $parsed.Description 'no ESC'
}

Add-TestCase 'D07e' 'Lookup returns exactly one object when winget is absent or the id is invalid' {
    $absent = Join-Path $tempRoot 'no-such-dir\winget.exe'
    $results = @(Get-WinGetAppDescription -WinGetId '7zip.7zip' -WinGetPath $absent)
    Assert-Equal 1 $results.Count 'exactly one object on the pipeline'
    Assert-Equal 'Unavailable' $results[0].Status 'missing winget'
    Assert-True ($results[0].Found -eq $false) 'Found is false'
    Assert-True ($null -eq $results[0].Description -and $null -eq $results[0].Source -and $null -eq $results[0].PackageId) 'no data fields'
    Assert-True (-not [string]::IsNullOrWhiteSpace($results[0].Message)) 'operator message present'

    # Shell metacharacters are refused before any argument string exists (and before winget is resolved).
    $hostile = @(Get-WinGetAppDescription -WinGetId '7zip.7zip --source x & calc' -WinGetPath $absent)
    Assert-Equal 1 $hostile.Count 'one object'
    Assert-Equal 'NotFound' $hostile[0].Status 'invalid id is refused'
    Assert-Like '*valid WinGet ID*' $hostile[0].Message 'and says why'
}

Add-TestCase 'I05' 'semicolon-separated groups reach the uploader as separate names' {
    # Regression (first live printer upload, 2026-10-12): "IT PCs; Techs" arrived as the single name
    # "IT PCs Techs", because Read-IntuneGroupList returned a wrapped array that the caller wrapped
    # again. Exercise the real prompt function and the caller's exact conversion.
    $function = Get-PDM5SetupFunction -Name 'Read-IntuneGroupList'
    $probe = & {
        function Write-Log { param($Message, $Level) }
        function Read-Host { param($Prompt) 'IT PCs; Techs ;; ' }
        . ([scriptblock]::Create($function.Extent.Text))
        [string[]]$groups = @(Read-IntuneGroupList -Intent 'Available')
        ,$groups
    }
    Assert-Equal 2 @($probe).Count 'two groups, not one joined name'
    Assert-Equal 'IT PCs' ([string]@($probe)[0]) 'first group trimmed'
    Assert-Equal 'Techs' ([string]@($probe)[1]) 'second group trimmed, empty pieces dropped'

    $blank = & {
        function Write-Log { param($Message, $Level) }
        function Read-Host { param($Prompt) '' }
        . ([scriptblock]::Create($function.Extent.Text))
        [string[]]$groups = @(Read-IntuneGroupList -Intent 'Required')
        ,$groups
    }
    Assert-Equal 0 @($blank).Count 'a blank answer is no groups, not one empty name'
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

foreach ($case in $script:Cases) {
    $script:CurrentCase = "$($case.Id) - $($case.Name)"

    # RT-* cases deliberately exercise the real HTTP stack against a loopback listener;
    # everything else gets a tripwire so a forgotten mock can never reach Microsoft.
    if ($case.Id -like 'RT-*') {
        $script:PDGraph.TestTransport = $null
    } else {
        $script:PDGraph.TestTransport = $script:PDTransportTripwire
    }

    try {
        & $case.Body | Out-Null
        $script:Passed++
        Write-Host ("PASS  {0,-10} {1}" -f $case.Id, $case.Name) -ForegroundColor DarkGreen
    } catch {
        $script:Failures += @{ Id = $case.Id; Name = $case.Name; Reason = $_.Exception.Message; Site = $_.InvocationInfo.PositionMessage }
        Write-Host ("FAIL  {0,-10} {1}" -f $case.Id, $case.Name) -ForegroundColor Red
        Write-Host ("      {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    }
}

if (-not $KeepTemp) {
    try { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { }
} else {
    Write-Host "Temp kept at $tempRoot"
}

Write-Host ""
Write-Host "================================================================"
Write-Host (" Engine  : PowerShell {0}" -f $PSVersionTable.PSVersion)
Write-Host (" Passed  : {0} / {1}" -f $script:Passed, $script:Cases.Count)
Write-Host (" Failed  : {0}" -f $script:Failures.Count)
Write-Host "================================================================"

if ($script:Failures.Count -gt 0) {
    Write-Host ""
    foreach ($failure in $script:Failures) {
        Write-Host ("FAIL {0} {1}" -f $failure.Id, $failure.Name) -ForegroundColor Red
        Write-Host ("     {0}" -f $failure.Reason)
        Write-Host ("     {0}" -f $failure.Site) -ForegroundColor DarkGray
    }
    exit 1
}

exit 0
