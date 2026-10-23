<#

.SYNOPSIS
    Compatibility gate for the Intune Graph upload feature: AST parse + ASCII-only on both
    engines, without running the behavioural suite.

.DESCRIPTION
    Spec section 13 requires parser compatibility to be checked on Windows PowerShell 5.1 AND
    PowerShell 7, and warns that parser success alone is not a pass - run
    Tests/IntuneGraphUpload.Tests.ps1 as well. This script exists because those two checks were
    being done from throwaway scripts in %TEMP%, which no future session has.

    ASCII-only matters: 5.1 misreads BOM-less UTF-8 that contains non-ASCII bytes, and it reports
    the failure as a mysterious syntax error far from the real cause. Fixture packages are binary
    and are intentionally not scanned.

    Line endings are checked in the same pass. Every file here is CRLF in the working tree (which
    is what the engines read) and git normalizes to LF in the index, so a file written with bare
    LFs is the one case where the working tree silently diverges from the rest of the repo.

    Usage (run under BOTH engines; exit code 0 means clean):
        powershell -NoProfile -ExecutionPolicy Bypass -File Tests\Check-PDCompatibility.ps1
        pwsh       -NoProfile -ExecutionPolicy Bypass -File Tests\Check-PDCompatibility.ps1

.LINK
    .claude/plans/intune-graph-upload.progress.md

#>

[CmdletBinding()]
param(
    [switch]$SkipAscii,
    [string]$RepoRoot
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}

# Every file this feature owns, plus the pre-existing files it changes. Setup.ps1 joined this strict
# list in M5, when the provisioning menu landed in it: from that point its bytes are the feature's
# responsibility, so a BOM, a non-ASCII byte, or a bare LF fails the gate instead of warning.
$featureFiles = @(
    'Other_Tools\InTune-GraphAPI_Helpers.ps1',
    'Other_Tools\Upload-InTuneWin32App.ps1',
    'Other_Tools\Get-WinGetAppDescription.ps1',
    'Tests\IntuneGraphUpload.Tests.ps1',
    'Tests\Check-PDCompatibility.ps1',
    'Tests\Fixtures\IntuneGraph\New-PDIntuneWinFixture.ps1',
    'Setup.ps1',
    # Bulk printer tools (printer-bulk-tools.buildplan.md)
    'Other_Tools\Printer-Intune_Helpers.ps1',
    'Other_Tools\Printer-IntuneBulk.ps1',
    'Other_Tools\CsvGrid-Editor_Helpers.ps1',
    'Tests\PrinterIntuneBulk.Tests.ps1'
)

# Joined by M7 (duplicate-printer guard); until then its pre-existing bytes warn instead of failing.
$preExistingFiles = @(
    'Installers\General_IP-Printer_Installer.ps1'
)

Write-Host ("Engine : PowerShell {0}" -f $PSVersionTable.PSVersion)
Write-Host ("Root   : {0}" -f $RepoRoot)
Write-Host ''

$failures = @()
$warnings = @()

function Get-PDFileBytes {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $buffer = New-Object byte[] $stream.Length
        $offset = 0
        while ($offset -lt $buffer.Length) {
            $read = $stream.Read($buffer, $offset, ($buffer.Length - $offset))
            if ($read -le 0) { break }
            $offset += $read
        }
        return ,$buffer
    } finally { $stream.Dispose() }
}

foreach ($relative in ($featureFiles + $preExistingFiles)) {
    $path = Join-Path $RepoRoot $relative
    $isFeature = ($featureFiles -ccontains $relative)

    if (-not (Test-Path -LiteralPath $path)) {
        $failures += ("{0}: file is missing" -f $relative)
        continue
    }

    # --- parse ---
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$parseErrors)
    foreach ($parseError in @($parseErrors)) {
        $failures += ('{0}:{1}: parse: {2}' -f $relative, $parseError.Extent.StartLineNumber, $parseError.Message)
    }

    if ($SkipAscii) { continue }

    # --- ASCII / BOM ---
    $bytes = Get-PDFileBytes -Path $path

    if (($bytes.Length -ge 3) -and ($bytes[0] -eq 0xEF) -and ($bytes[1] -eq 0xBB) -and ($bytes[2] -eq 0xBF)) {
        $message = "$relative`: UTF-8 BOM present"
        if ($isFeature) { $failures += $message } else { $warnings += $message }
    }

        $lineNumber          = 1
    $firstOffendingLine  = 0
    $bareLineFeeds       = 0
    $bareCarriageReturns = 0

    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -eq 10) {
            $lineNumber++
            if (($i -eq 0) -or ($bytes[$i - 1] -ne 13)) { $bareLineFeeds++ }
        }
        if ($bytes[$i] -gt 127) {
            if ($firstOffendingLine -eq 0) { $firstOffendingLine = $lineNumber }
        }
        if (($bytes[$i] -eq 13) -and (($i + 1) -ge $bytes.Length -or $bytes[$i + 1] -ne 10)) {
            $bareCarriageReturns++
        }
    }

    if ($firstOffendingLine -gt 0) {
        $message = ('{0}:{1}: non-ASCII byte in a source file (5.1 can misread BOM-less UTF-8)' -f $relative, $firstOffendingLine)
        if ($isFeature) { $failures += $message } else { $warnings += $message }
    }

    if (($bareLineFeeds -gt 0) -or ($bareCarriageReturns -gt 0)) {
        $message = ('{0}: {1} bare LF and {2} bare CR byte(s); this repo keeps CRLF line endings in the working tree' -f $relative, $bareLineFeeds, $bareCarriageReturns)
        if ($isFeature) { $failures += $message } else { $warnings += $message }
    }
}

foreach ($warning in $warnings) { Write-Host ("WARN  {0}" -f $warning) -ForegroundColor Yellow }

if (@($failures).Count -gt 0) {
    foreach ($failure in $failures) { Write-Host ("FAIL  {0}" -f $failure) -ForegroundColor Red }
    Write-Host ''
    Write-Host ("FAILED: {0} problem(s)" -f @($failures).Count)
    exit 1
}

Write-Host ("Checked {0} file(s): parse clean, ASCII-only where required." -f @($featureFiles + $preExistingFiles).Count)
Write-Host 'Reminder: this is not the behavioural suite. Run Tests\IntuneGraphUpload.Tests.ps1 too.'
exit 0
