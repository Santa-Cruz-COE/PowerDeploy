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
    # Import into a throwaway child scope purely to observe what import-time output happens.
    $imported = & {
        . $HelperPath
    }

    Assert-True ($null -eq $imported -or @($imported).Count -eq 0) "Importing must emit no output (got: $imported)"

    # Importing must not touch the credential store, authenticate, or write anywhere.
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'PowerDeploy'))) 'Import must not create the real credential folder'
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
                            'Get-PDGraphResponseHeader', 'Get-PDJwtClaims', 'Test-PDGraphGuid')) {
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
    Assert-Throws -Body { Get-PDGraphCredential -Path $missing } -MessagePattern '*Graph_API_Upload--InTune-Setup*' 'points at the provisioning menu'
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
# Run
# ---------------------------------------------------------------------------

foreach ($case in $script:Cases) {
    $script:CurrentCase = "$($case.Id) - $($case.Name)"
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
