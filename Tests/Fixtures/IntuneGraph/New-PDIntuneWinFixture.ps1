<#

.SYNOPSIS
    Regenerates the tiny .intunewin fixtures used by Tests/IntuneGraphUpload.Tests.ps1.

.DESCRIPTION
    Every fixture here is SYNTHESIZED. None contains vendor content, vendor names, or real
    key material. The metadata element names, element order, and the outer archive layout were
    read from a real IntuneWinAppUtil 1.8.7.0 package produced on this workstation (see README.md
    in this folder) so the parser is exercised against observed structure rather than assumed
    structure.

    Each fixture is a few hundred bytes. Content is deterministic: the pseudo-encrypted payload is
    a fixed arithmetic pattern and entry timestamps are pinned, so re-running this script on the
    same engine reproduces the same files.

    USE PWSH 7 TO REGENERATE. .NET Framework's ZipArchive deflates entries even when asked for
    NoCompression, while .NET Core honours it; the committed fixtures are stored (like real
    IntuneWinAppUtil output) and were produced with pwsh 7. The script reports the drift loudly
    rather than letting it be committed silently.

    Usage:
        pwsh       -NoProfile -ExecutionPolicy Bypass -File Tests\Fixtures\IntuneGraph\New-PDIntuneWinFixture.ps1
        powershell -NoProfile -ExecutionPolicy Bypass -File Tests\Fixtures\IntuneGraph\New-PDIntuneWinFixture.ps1
        ... -Verify    re-reads each fixture and prints a table without writing anything

.LINK
    .claude/plans/intune-graph-upload.md sections 10.1 and 13 (P01, P02)

#>

[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [switch]$Verify,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = $PSScriptRoot }

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# --- Shared, deliberately fake fixture material ---------------------------------------------

$script:ToolVersion       = '1.8.7.0'
$script:MetadataEntryName  = 'IntuneWinPackage/Metadata/Detection.xml'
$script:ContentFolder      = 'IntuneWinPackage/Contents/'
$script:PackageFileName    = 'IntunePackage.intunewin'
$script:SetupFileName      = 'PowerDeployFixtureSetup.exe'
$script:UnencryptedSize    = 462   # ApplicationInfo/UnencryptedContentSize
$script:EncryptedSize      = 512   # a real package's payload is slightly LARGER than this

# A fixed pattern keeps fixture bytes reproducible. Not random, not encrypted, not secret.
function Get-PDFixturePayload {
    param([int]$Length)

    $bytes = New-Object byte[] $Length
    for ($i = 0; $i -lt $Length; $i++) {
        $bytes[$i] = [byte](($i * 37 + 11) -band 0xFF)
    }
    return ,$bytes
}

# base64 of a fixed pattern. These are NOT keys and never were.
function Get-PDFixtureKeyMaterial {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [int]$ByteLength = 32
    )

    $bytes = New-Object byte[] $ByteLength
    # Deterministic seed from the label's characters: String.GetHashCode() is randomized per
    # process in .NET Core, so it must not be involved if regenerated fixtures are to match.
    $seed = 17
    foreach ($char in $Label.ToCharArray()) { $seed = (($seed * 31) + [int]$char) -band 0x7FFFFFFF }

    for ($i = 0; $i -lt $ByteLength; $i++) {
        $seed = ([long]$seed * 1103515245 + 12345) -band 0x7FFFFFFF
        $bytes[$i] = [byte](($seed -shr 8) -band 0xFF)
    }
    return [System.Convert]::ToBase64String($bytes)
}

function New-PDFixtureDetectionXml {
    <#
        Mirrors the element names and order observed in a real 1.8.7.0 Detection.xml.
        -OmitEncryptionInfo drops the whole EncryptionInfo element.
        -Malformed leaves the document unparseable.
    #>
    param(
        [string]$FileName  = $script:PackageFileName,
        [string]$SetupFile = $script:SetupFileName,
        [string]$Name      = $script:SetupFileName,
        [long]$UnencryptedContentSize = $script:UnencryptedSize,
        [switch]$OmitEncryptionInfo,
        [switch]$Malformed
    )

    $encryption = @()
    if (-not $OmitEncryptionInfo) {
        $encryption = @(
            '  <EncryptionInfo>'
            ('    <EncryptionKey>{0}</EncryptionKey>'                 -f (Get-PDFixtureKeyMaterial -Label 'EncryptionKey'))
            ('    <MacKey>{0}</MacKey>'                               -f (Get-PDFixtureKeyMaterial -Label 'MacKey'))
            ('    <InitializationVector>{0}</InitializationVector>'   -f (Get-PDFixtureKeyMaterial -Label 'InitializationVector' -ByteLength 16))
            ('    <Mac>{0}</Mac>'                                     -f (Get-PDFixtureKeyMaterial -Label 'Mac' -ByteLength 16))
            '    <ProfileIdentifier>ProfileVersion1</ProfileIdentifier>'
            ('    <FileDigest>{0}</FileDigest>'                       -f (Get-PDFixtureKeyMaterial -Label 'FileDigest' -ByteLength 32))
            '    <FileDigestAlgorithm>SHA256</FileDigestAlgorithm>'
            '  </EncryptionInfo>'
        )
    }

    $xml = (@(
        '<?xml version="1.0" encoding="utf-8"?>'
        ('<ApplicationInfo xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ToolVersion="{0}">' -f $script:ToolVersion)
        ('  <Name>{0}</Name>'          -f $Name)
        ('  <UnencryptedContentSize>{0}</UnencryptedContentSize>' -f $UnencryptedContentSize)
        ('  <FileName>{0}</FileName>'  -f $FileName)
        ('  <SetupFile>{0}</SetupFile>' -f $SetupFile)
    ) + $encryption + @('</ApplicationInfo>')) -join "`r`n"

    if ($Malformed) {
        # Cut the document open so [xml] cannot parse it.
        $xml = $xml -replace '</ApplicationInfo>', ''
    }
    return $xml
}

function New-PDZipPackage {
    <#
        Writes one outer .intunewin. -Entries is an ordered list of @{ Name = <entry path>; Bytes = <byte[]> }.
        Real IntuneWinAppUtil packages store their entries uncompressed, which is the default here.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object[]]$Entries,
        [ValidateSet('NoCompression', 'Optimal')][string]$CompressionLevel = 'NoCompression'
    )

    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }

    $level = [System.IO.Compression.CompressionLevel]::NoCompression
    if ($CompressionLevel -eq 'Optimal') { $level = [System.IO.Compression.CompressionLevel]::Optimal }

    $fs  = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite)
    $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($entry in $Entries) {
            $created = $zip.CreateEntry([string]$entry.Name, $level)
            # Pin the timestamp. 5.1 exposes LastWriteTime as DateTime and .NET Core as
            # DateTimeOffset, so hand the setter an unspecified-kind local DateTime either way.
            try {
                $created.LastWriteTime = New-Object System.DateTime(2026, 10, 8, 12, 0, 0, [System.DateTimeKind]::Unspecified)
            } catch { }

            $stream = $created.Open()
            try {
                $bytes = [byte[]]$entry.Bytes
                $stream.Write($bytes, 0, $bytes.Length)
            } finally { $stream.Dispose() }
        }
    } finally {
        $zip.Dispose()
        $fs.Dispose()
    }
    return (Get-Item -LiteralPath $Path)
}

# --- The fixtures -----------------------------------------------------------------------------

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
function Get-PDBytes { param([string]$Text) return $utf8NoBom.GetBytes($Text) }

$script:Fixtures = [ordered]@{}

# 1. The good one: metadata + exactly one content entry, both stored.
$script:Fixtures['valid.intunewin'] = @{
    Expect  = 'readable'
    Reason  = 'Well-formed package: Detection.xml + exactly one content entry'
    Entries = @(
        @{ Name = $script:MetadataEntryName; Bytes = (Get-PDBytes (New-PDFixtureDetectionXml)) },
        @{ Name = ($script:ContentFolder + $script:PackageFileName); Bytes = (Get-PDFixturePayload -Length $script:EncryptedSize) }
    )
}

# 2. No metadata at all.
$script:Fixtures['missing-detection-xml.intunewin'] = @{
    Expect  = 'reject'
    Reason  = 'Outer ZIP has no IntuneWinPackage/Metadata/Detection.xml'
    Entries = @(
        @{ Name = ($script:ContentFolder + $script:PackageFileName); Bytes = (Get-PDFixturePayload -Length $script:EncryptedSize) }
    )
}

# 3. Metadata names a payload that is not in the archive; an unrelated entry is.
$script:Fixtures['metadata-without-content-entry.intunewin'] = @{
    Expect  = 'reject'
    Reason  = 'Detection.xml says IntunePackage.intunewin but the only content entry is RenamedPackage.intunewin'
    Entries = @(
        @{ Name = $script:MetadataEntryName; Bytes = (Get-PDBytes (New-PDFixtureDetectionXml)) },
        @{ Name = ($script:ContentFolder + 'RenamedPackage.intunewin'); Bytes = (Get-PDFixturePayload -Length $script:EncryptedSize) }
    )
}

# 4. Two content entries - the metadata/payload pairing is not unambiguous.
$script:Fixtures['two-content-entries.intunewin'] = @{
    Expect  = 'reject'
    Reason  = 'Two entries under IntuneWinPackage/Contents/; the parser must not pick one'
    Entries = @(
        @{ Name = $script:MetadataEntryName; Bytes = (Get-PDBytes (New-PDFixtureDetectionXml)) },
        @{ Name = ($script:ContentFolder + $script:PackageFileName); Bytes = (Get-PDFixturePayload -Length $script:EncryptedSize) },
        @{ Name = ($script:ContentFolder + 'SecondContent.intunewin'); Bytes = (Get-PDFixturePayload -Length 64) }
    )
}

# 5. An entry whose name escapes the archive root.
$script:Fixtures['traversal-entry.intunewin'] = @{
    Expect  = 'reject'
    Reason  = 'Contains an entry named with ../ segments; nothing may ever be written outside the temp directory'
    Entries = @(
        @{ Name = $script:MetadataEntryName; Bytes = (Get-PDBytes (New-PDFixtureDetectionXml)) },
        @{ Name = 'IntuneWinPackage/Contents/../../../../PowerDeploy-fixture-evil.txt'; Bytes = (Get-PDBytes 'evil') },
        @{ Name = ($script:ContentFolder + $script:PackageFileName); Bytes = (Get-PDFixturePayload -Length $script:EncryptedSize) }
    )
}

# 6. Not a ZIP at all.
$script:Fixtures['not-a-zip.intunewin'] = @{
    Expect   = 'reject'
    Reason   = 'Arbitrary bytes with no ZIP header'
    Entries  = @()
    RawBytes = (Get-PDFixturePayload -Length 96)
}

# 7. Metadata is not parseable XML.
$script:Fixtures['malformed-detection-xml.intunewin'] = @{
    Expect  = 'reject'
    Reason  = 'Detection.xml is truncated mid-document'
    Entries = @(
        @{ Name = $script:MetadataEntryName; Bytes = (Get-PDBytes (New-PDFixtureDetectionXml -Malformed)) },
        @{ Name = ($script:ContentFolder + $script:PackageFileName); Bytes = (Get-PDFixturePayload -Length $script:EncryptedSize) }
    )
}

# 8. Valid package whose metadata can never support a commit.
$script:Fixtures['missing-encryption-info.intunewin'] = @{
    Expect  = 'reject'
    Reason  = 'No EncryptionInfo element, so no commit fileEncryptionInfo can be built'
    Entries = @(
        @{ Name = $script:MetadataEntryName; Bytes = (Get-PDBytes (New-PDFixtureDetectionXml -OmitEncryptionInfo)) },
        @{ Name = ($script:ContentFolder + $script:PackageFileName); Bytes = (Get-PDFixturePayload -Length $script:EncryptedSize) }
    )
}

# 9. Payload present but DEFLATED, unlike real IntuneWinAppUtil output. The parser must read
#    through the archive API and never assume entries are stored.
$script:Fixtures['deflated-payload.intunewin'] = @{
    Expect      = 'readable'
    Reason      = 'Same content as valid.intunewin but compressed'
    Compression = 'Optimal'
    Entries = @(
        @{ Name = $script:MetadataEntryName; Bytes = (Get-PDBytes (New-PDFixtureDetectionXml)) },
        @{ Name = ($script:ContentFolder + $script:PackageFileName); Bytes = (Get-PDFixturePayload -Length $script:EncryptedSize) }
    )
}

# --- Generate or verify -----------------------------------------------------------------------

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

function Test-PDZipHonoursNoCompression {
    <#
        Probes whether this engine's ZipArchive really stores an entry when asked for
        NoCompression. .NET Framework deflates anyway, which would silently rewrite every
        fixture with different bytes, so the probe runs BEFORE anything is written.
    #>
    $probe = Join-Path ([System.IO.Path]::GetTempPath()) ('pd-fixture-probe-' + [guid]::NewGuid().ToString('N') + '.zip')
    try {
        New-PDZipPackage -Path $probe -Entries @(@{ Name = 'probe.bin'; Bytes = (Get-PDFixturePayload -Length 512) }) | Out-Null

        $fs  = [System.IO.File]::Open($probe, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Read)
        try {
            foreach ($entry in $zip.Entries) {
                # 5.1 leaves CompressedMethod unset, so equal lengths is the stored signal there.
                $method   = [string]$entry.CompressedMethod
                $isStored = ($method -eq 'Stored') -or (($method -eq 'None' -or $method -eq '') -and ($entry.CompressedLength -eq $entry.Length))
                if (-not $isStored) { return $false }
            }
        } finally { $zip.Dispose(); $fs.Dispose() }
        return $true
    } finally {
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    }
}

if (-not $Verify) {
    if (-not (Test-PDZipHonoursNoCompression)) {
        if ($Force) {
            Write-Warning 'This engine deflates entries despite NoCompression; writing anyway because -Force was given.'
        } else {
            Write-Warning "This engine's ZipArchive deflates entries even when asked to store them, which would rewrite every fixture with different bytes."
            Write-Warning "The committed fixtures are stored, as IntuneWinAppUtil writes them. Regenerate with pwsh 7, or pass -Force to write this variant on purpose."
            exit 3
        }
    }
}

function Get-PDEntryNames {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fs  = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Read)
    try {
        return @(foreach ($entry in $zip.Entries) {
            '{0} [{1}/{2}]' -f $entry.FullName, $entry.CompressedLength, $entry.Length
        })
    } finally { $zip.Dispose(); $fs.Dispose() }
}

foreach ($name in $script:Fixtures.Keys) {
    $fixture = $script:Fixtures[$name]
    $path    = Join-Path $OutputDirectory $name

    if ($Verify) {
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Host ("{0,-40} MISSING" -f $name) -ForegroundColor Red
            continue
        }
        '{0,-38} {1,8} bytes  expects {2}' -f $name, (Get-Item -LiteralPath $path).Length, $fixture.Expect
        '    {0}' -f $fixture.Reason
        if (-not $fixture.ContainsKey('RawBytes')) {
            foreach ($entryName in (Get-PDEntryNames -Path $path)) { "      $entryName" }
        }
        continue
    }

    if ($fixture.ContainsKey('RawBytes')) {
        [System.IO.File]::WriteAllBytes($path, [byte[]]$fixture.RawBytes)
    } else {
        $level = 'NoCompression'
        if ($fixture.ContainsKey('Compression')) { $level = $fixture.Compression }
        New-PDZipPackage -Path $path -Entries $fixture.Entries -CompressionLevel $level | Out-Null
    }
    '{0,-40} {1,8} bytes' -f $name, (Get-Item -LiteralPath $path).Length
}

if ($Verify) { return }

Write-Host ("`nFixtures written to {0}" -f $OutputDirectory)
