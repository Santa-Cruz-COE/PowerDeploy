<#
NOTE: This script was primarily written by Claude Opus 5.0 + 5.5. It was tested and manually adjusted before publication.

INSTRUCTIONS:
Ingests a manufacturer's printer driver pack and turns it into a PowerDeploy-ready
DriverZip plus the matching "drivers" JSON entry.

Accepts any of:
  - a vendor .zip            (e.g. UNIV_5.1076.4.0_PCL6_x64.zip)
  - a self-extracting .exe   (e.g. upd-pcl6-x64-7.9.0.26347.exe)  [needs 7-Zip]
  - an already-extracted folder

WHAT IT DOES AND WHY

Vendor packs are not laid out consistently. Observed in the wild:
  - HP ships its INFs one level down, in "64bit\"
  - KONICA MINOLTA ships the SAME INF filename under both
    Driver\PCL\Driver\Win_x64\ and ...\Win_x86\
So you cannot assume the INF is at the root, and you cannot pick by path depth.

Instead this script reads the INFs themselves, which is authoritative:

  1. PRIMARY FILTER - does the INF declare any printer driver names?
     Only real printer INFs have model entries. In a fresh HP UPD pack, exactly
     1 of 12 INFs declares driver names; the other 11 are bus/port/scan/fax
     components. This single test does most of the work.

  2. ARCHITECTURE - read from the [Manufacturer] decoration ("NTamd64",
     "NTarm64", "NTx86") and shown next to each INF. It is reported, not
     filtered: x64, ARM64 and x86 are all valid targets, so the choice is yours.
     The decoration is a Microsoft INF requirement, not a vendor convention.
     INF files are case-insensitive by spec, so matching is case-insensitive
     (HP writes "NTAMD64", KM writes "NTamd64", others write "ntamd64.6.0.3").

  3. TIE-BREAK - if a DriverName is supplied, keep only INFs declaring it.
     Anything still ambiguous is put to you as a pick-list, in the order the
     INFs were found; nothing is guessed.

PACKAGING RULE
The zip is made from the directory the chosen INF lives in. Verified against
both HP ("64bit\") and KM ("Driver\PCL\Driver\Win_x64\") - in both cases that
folder is self-contained, holding the INF plus all of its payload files.

USAGE
  .\Convert-VendorPack-ToDriverZip.ps1 -PackPath "C:\Downloads\upd-pcl6-x64.exe"
  .\Convert-VendorPack-ToDriverZip.ps1 -PackPath "C:\Downloads\KM_Universal" -DriverName "KONICA MINOLTA Universal PCL"
  .\Convert-VendorPack-ToDriverZip.ps1 -PackPath ".\pack.zip" -PresetDriver "KM_UPD4_PCL6_WIN_X64" -Analyze

#>

param(
    [Parameter(Mandatory=$true)]
    [string]$PackPath,

    # If you already know the exact driver name (e.g. from Get-PrinterDriver on
    # the print server), pass it to remove all ambiguity.
    [string]$DriverName,

    # The PresetDriver code used to link printers[] -> drivers[] in the JSON.
    [string]$PresetDriver,

    # Prefix used to build the DriverZip blob path in the emitted JSON.
    [string]$BlobPathPrefix = "printers/Drivers",

    [string]$OutputDirectory,

    # Report what is in the pack and exit, without building a zip.
    [switch]$Analyze
)

# Resolve our own folder even when run via paste/selection, where $PSScriptRoot is empty.
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $ScriptDir) { $ScriptDir = (Get-Location).Path }

$RepoRoot = Split-Path $ScriptDir -Parent
$WorkingDirectory = Split-Path $RepoRoot -Parent
if (!(Test-Path "$WorkingDirectory\TEMP")) { $WorkingDirectory = $ScriptDir }

$ThisFileName = $MyInvocation.MyCommand.Name
$LogRoot = "$WorkingDirectory\Logs\Other_Logs"
$LogPath = "$LogRoot\$ThisFileName._Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = "$WorkingDirectory\TEMP\DriverPacks"
}


# --- Helpers --------------------------------------------------------------

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "DRYRUN"  { Write-Host $logEntry -ForegroundColor Cyan }
        default   { Write-Host $logEntry }
    }

    # Ensure log directory exists
    $logDir = Split-Path $LogPath -Parent
    if (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    # Resilient log write: retry an atomic append so a transient AV/EDR file lock
    # (Defender, CrowdStrike, etc.) cannot throw "Stream was not readable" and spam the
    # console. Encoding::Default (system ANSI) matches the prior Add-Content behavior.
    for ($logAttempt = 1; $logAttempt -le 5; $logAttempt++) {
        try {
            [System.IO.File]::AppendAllText($LogPath, $logEntry + [Environment]::NewLine, [System.Text.Encoding]::Default)
            break
        } catch {
            if ($logAttempt -eq 5) { break }   # give up quietly after ~160ms of retries
            Start-Sleep -Milliseconds 40
        }
    }
}

function Find-SevenZip {
    # Needed only for self-extracting .exe packs.
    $Candidates = @(
        "$env:ProgramFiles\7-Zip\7z.exe",
        "${env:ProgramFiles(x86)}\7-Zip\7z.exe",
        "$env:ProgramW6432\7-Zip\7z.exe"
    )
    foreach ($c in $Candidates) { if ($c -and (Test-Path $c)) { return $c } }
    $cmd = Get-Command 7z.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Get-VendorFolder {
    <#
      Maps a driver name to the manufacturer folder in the blob layout:
          printers/Drivers/<VendorFolder>/<file>.zip
      Returns "Other" when no manufacturer can be identified from the name
      (e.g. "DTC1250e Card Printer", "Generic / Text Only").

      Deliberately an ORDERED ARRAY, not a hashtable: PowerShell does not
      guarantee hashtable key order, and the more specific patterns have to be
      tested before the shorter ones.

      Keep this list in sync with Export-PrinterServer-Drivers.ps1 and
      Convert-PrinterCSV-ToJSON.ps1 - these scripts are intentionally standalone
      (Script A has to run on the print server on its own), so the helper is
      duplicated rather than shared.
    #>
    param([string]$DriverName)

    if ([string]::IsNullOrWhiteSpace($DriverName)) { return 'Other' }

    $map = @(
        @{ Pattern = 'KONICA\s*MINOLTA';     Folder = 'KonicaMinolta' }
        @{ Pattern = 'Hewlett[-\s]?Packard'; Folder = 'HP' }
        @{ Pattern = '\bHP\b';               Folder = 'HP' }
        @{ Pattern = '\bCanon\b';            Folder = 'Canon' }
        @{ Pattern = '\bXerox\b';            Folder = 'Xerox' }
        @{ Pattern = '\bRicoh\b';            Folder = 'Ricoh' }
        @{ Pattern = '\bBrother\b';          Folder = 'Brother' }
        @{ Pattern = '\bLexmark\b';          Folder = 'Lexmark' }
        @{ Pattern = '\bEpson\b';            Folder = 'Epson' }
        @{ Pattern = '\bKyocera\b';          Folder = 'Kyocera' }
        @{ Pattern = '\bSharp\b';            Folder = 'Sharp' }
        @{ Pattern = '\bToshiba\b';          Folder = 'Toshiba' }
        @{ Pattern = '\bOKI\b';              Folder = 'OKI' }
        @{ Pattern = '\bZebra\b';            Folder = 'Zebra' }
        @{ Pattern = '\bDymo\b';             Folder = 'Dymo' }
        @{ Pattern = '\bEvolis\b';           Folder = 'Evolis' }
        @{ Pattern = '\bFargo\b';            Folder = 'Fargo' }
        @{ Pattern = '\bSamsung\b';          Folder = 'Samsung' }
        @{ Pattern = '\bDell\b';             Folder = 'Dell' }
        @{ Pattern = '\bAdobe\b';            Folder = 'Adobe' }
        @{ Pattern = '\bMicrosoft\b';        Folder = 'Microsoft' }
    )

    foreach ($e in $map) {
        if ($DriverName -imatch $e.Pattern) { return $e.Folder }
    }
    return 'Other'
}

function Get-INFDriverInfo {
    <#
      Parses one INF the way Windows does:
        [Manufacturer] lists  %Var%=SectionBase,decoration1,decoration2...
        Model sections are    [SectionBase] and [SectionBase.decoration]
        Model entries look like   "Driver Name" = InstallSection,HardwareID
                             or   %Token% = InstallSection,HardwareID  (resolved via [Strings])
      Returns the declared driver names plus the architectures declared.
    #>
    param([string]$Path)

    $Result = [PSCustomObject][ordered]@{
        Path          = $Path
        DriverNames   = @()
        Decorations   = @()
        SupportsAmd64 = $false
        SupportsArm64 = $false
        Supportsx86   = $false
    }

    try { $Lines = Get-Content -LiteralPath $Path -ErrorAction Stop } catch { return $Result }

    # Walk the file once, recording section boundaries.
    $Sections = @{}
    $Current = $null
    foreach ($raw in $Lines) {
        $line = $raw.Trim()
        if ($line -match '^\[(.+?)\]') {
            $Current = $Matches[1].Trim()
            if (-not $Sections.ContainsKey($Current)) { $Sections[$Current] = New-Object System.Collections.ArrayList }
        } elseif ($Current -ne $null -and $line -ne '' -and -not $line.StartsWith(';')) {
            [void]$Sections[$Current].Add($line)
        }
    }

    # [Manufacturer] - find it case-insensitively (HP writes [MANUFACTURER]).
    $MfgKey = $Sections.Keys | Where-Object { $_ -ieq 'Manufacturer' } | Select-Object -First 1
    if (-not $MfgKey) { return $Result }

    $ModelSectionNames = New-Object System.Collections.ArrayList
    foreach ($entry in $Sections[$MfgKey]) {
        # e.g.  %HP%=HP,NTAMD64      or   %KM%=KONICA MINOLTA, NTamd64, NTamd64.6.0
        $eq = $entry.IndexOf('=')
        if ($eq -lt 0) { continue }
        $rhs   = $entry.Substring($eq + 1)
        $parts = $rhs.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        if ($parts.Count -eq 0) { continue }

        $Base = $parts[0]
        [void]$ModelSectionNames.Add($Base)

        if ($parts.Count -gt 1) {
            foreach ($dec in $parts[1..($parts.Count - 1)]) {
                $Result.Decorations += $dec
                [void]$ModelSectionNames.Add("$Base.$dec")
                # Decorations are the authoritative architecture marker.
                if ($dec -imatch 'amd64') { $Result.SupportsAmd64 = $true }
                if ($dec -imatch 'arm64') { $Result.SupportsArm64 = $true }
                if ($dec -imatch 'x86')   { $Result.Supportsx86   = $true }
            }
        }
    }

    # [Strings] - model entries may name the driver via a %Token% instead of a
    # literal (HP device packs write  %PRINTER1% = INSTALL_SECTION,...). Only the
    # base section is read; localized [Strings.xxxx] copies would override it.
    $Strings = @{}
    $StrKey = $Sections.Keys | Where-Object { $_ -ieq 'Strings' } | Select-Object -First 1
    if ($StrKey) {
        foreach ($s in $Sections[$StrKey]) {
            if ($s -match '^\s*([^=]+?)\s*=\s*"?(.*?)"?\s*$') { $Strings[$Matches[1]] = $Matches[2] }
        }
    }

    # Collect declared driver names from every model section.
    $Names = New-Object System.Collections.ArrayList
    foreach ($sName in ($ModelSectionNames | Select-Object -Unique)) {
        $key = $Sections.Keys | Where-Object { $_ -ieq $sName } | Select-Object -First 1
        if (-not $key) { continue }
        foreach ($entry in $Sections[$key]) {
            # The driver name on the left of '=' is either quoted or a %Token%.
            $n = $null
            if ($entry -match '^\s*"([^"]+)"\s*=') {
                $n = $Matches[1].Trim()
            } elseif ($entry -match '^\s*%([^%]+)%\s*=' -and $Strings.ContainsKey($Matches[1].Trim())) {
                $n = $Strings[$Matches[1].Trim()].Trim()
            }
            if ($n -and -not $Names.Contains($n)) { [void]$Names.Add($n) }
        }
    }

    $Result.DriverNames = @($Names)
    # An INF with no decorations at all is undecorated/legacy - treat as usable.
    if ($Result.Decorations.Count -eq 0) { $Result.SupportsAmd64 = $true }
    return $Result
}

function Get-INFArchList {
    # Architectures an INF declares, as short labels: x64, arm64, x86.
    param($Info)
    $arch = @()
    if ($Info.SupportsAmd64) { $arch += 'x64' }
    if ($Info.SupportsArm64) { $arch += 'arm64' }
    if ($Info.Supportsx86)   { $arch += 'x86' }
    return ,$arch
}

function Read-ChoiceIndex {
    # Prompts until a valid index 0..(Count-1) is entered. No default: blank or
    # out-of-range input is rejected and asked again.
    param([int]$Count)
    while ($true) {
        $raw = Read-Host "Enter number (0-$($Count - 1))"
        if ($null -eq $raw) { throw "No input available for selection." }   # stdin closed
        $n = 0
        if ([int]::TryParse($raw.Trim(), [ref]$n) -and $n -ge 0 -and $n -lt $Count) { return $n }
        Write-Log "Invalid choice '$raw'. Enter a number from 0 to $($Count - 1)." "WARNING"
    }
}


# --- Main -----------------------------------------------------------------

Try {

    Write-Log "Log file: $LogPath"

    if (!(Test-Path $PackPath)) { Write-Log "Pack not found: $PackPath" "ERROR"; return }

    $PackItem = Get-Item -LiteralPath $PackPath
    $PackLabel = [System.IO.Path]::GetFileNameWithoutExtension($PackItem.Name)
    if (!(Test-Path $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }

    # --- 1. Get an extracted folder to work from --------------------------
    if ($PackItem.PSIsContainer) {

        $ExtractRoot = $PackItem.FullName
        Write-Log "Using already-extracted folder: $ExtractRoot"

    } else {

        $ExtractRoot = Join-Path $OutputDirectory "$PackLabel-EXTRACTED"
        if (Test-Path $ExtractRoot) {
            Write-Log "Removing previous extraction: $ExtractRoot"
            Remove-Item -LiteralPath $ExtractRoot -Recurse -Force
        }
        New-Item -ItemType Directory -Path $ExtractRoot -Force | Out-Null

        switch ($PackItem.Extension.ToLower()) {

            '.zip' {
                Write-Log "Extracting zip..."
                Expand-Archive -LiteralPath $PackItem.FullName -DestinationPath $ExtractRoot -Force -ErrorAction Stop
            }

            '.exe' {
                $SevenZip = Find-SevenZip
                if (-not $SevenZip) {
                    Write-Log "This pack is a self-extracting .exe, which needs 7-Zip to unpack." "ERROR"
                    Write-Log "Install 7-Zip, or extract the .exe yourself and re-run against the folder." "ERROR"
                    return
                }
                Write-Log "Extracting self-extracting exe with 7-Zip..."
                & $SevenZip x $PackItem.FullName "-o$ExtractRoot" -y | Out-Null
                if ($LASTEXITCODE -ne 0) { Write-Log "7-Zip failed with exit code $LASTEXITCODE" "ERROR"; return }
            }

            default {
                Write-Log "Unsupported pack type '$($PackItem.Extension)'. Expected .zip, .exe, or a folder." "ERROR"
                return
            }
        }
    }

    # --- 2. Find and parse every INF --------------------------------------
    $AllINFs = @(Get-ChildItem -Path $ExtractRoot -Filter *.inf -Recurse -File -ErrorAction SilentlyContinue)
    if ($AllINFs.Count -eq 0) { Write-Log "No .inf files found anywhere in $ExtractRoot" "ERROR"; return }

    Write-Log "Found $($AllINFs.Count) INF file(s). Parsing..."
    $Parsed = foreach ($inf in $AllINFs) { Get-INFDriverInfo -Path $inf.FullName }

    # PRIMARY FILTER: only INFs that actually declare printer driver names.
    $PrinterINFs = @($Parsed | Where-Object { $_.DriverNames.Count -gt 0 })
    Write-Log ""
    Write-Log "=== PACK ANALYSIS ==="
    Write-Log ""
    Write-Log ("  INFs total                   : {0}" -f $AllINFs.Count)
    Write-Log ("  INFs declaring printer drivers: {0}" -f $PrinterINFs.Count)
    Write-Log ""
    foreach ($p in $PrinterINFs) {

        $rel = $p.Path.Substring($ExtractRoot.Length).TrimStart('\')
        Write-Log ("  {0}  [{1}]" -f $rel, ((Get-INFArchList $p) -join '/'))
        foreach ($n in $p.DriverNames) { Write-Log "      - $n" }
        Write-Log ""
    }

    if ($PrinterINFs.Count -eq 0) { Write-Log "No INF in this pack declares any printer driver. Nothing to package." "ERROR"; return }
    if ($Analyze) { Write-Log "-Analyze specified; stopping here."; return }

    # --- 3. Narrow to one INF ---------------------------------------------
    # Architecture is deliberately NOT filtered: x64, ARM64 and x86 are all valid
    # targets, and it is shown next to each INF in the analysis above.
    $Candidates = $PrinterINFs

    # TIE-BREAK: explicit driver name. This is the filter that actually does the
    # disambiguating - in a fresh HP UPD pack 5 of 12 INFs declare driver names,
    # so "declares a printer driver" alone is not enough to land on one.
    if (-not [string]::IsNullOrWhiteSpace($DriverName)) {

        # Exact match first - this is what Add-PrinterDriver -Name requires.
        $ByName = @($Candidates | Where-Object { $_.DriverNames -contains $DriverName })

        if ($ByName.Count -eq 0) {
            # Fall back to a contains-match. Packs ship versioned variants of the
            # same name (e.g. "HP Universal Printing PCL 6" alongside
            # "HP Universal Printing PCL 6 (v7.1.0)"), so a near-miss is common
            # and worth surfacing rather than hard-failing.
            $ByName = @($Candidates | Where-Object {
                $n = $_.DriverNames
                @($n | Where-Object { $_ -like "*$DriverName*" -or $DriverName -like "*$_*" }).Count -gt 0
            })
            if ($ByName.Count -ge 1) {
                Write-Log "No EXACT match for '$DriverName'. Found partial match(es) instead." "WARNING"
                Write-Log "Confirm the exact name below - it must match Add-PrinterDriver exactly." "WARNING"
            }
        }

        if ($ByName.Count -ge 1) {
            $Candidates = $ByName
        } else {
            Write-Log "No INF declares a driver matching '$DriverName'." "ERROR"
            Write-Log "Names that ARE available are listed above - copy one of them exactly." "ERROR"
            return
        }

    } else {
        Write-Log "No -DriverName supplied. Selection will be interactive." "WARNING"
    }

    Write-Log ""

    # No ranking: the analysis above lists each INF's driver names, so the pick
    # is left to you, in the same order the INFs were found. Note the zip is
    # built from the chosen INF's folder, so where a pack ships the same INF in
    # several places (e.g. a flattened root copy AND Driver\...\Win_x64\), the
    # arch-specific folder makes a much smaller zip.
    if ($Candidates.Count -gt 1) {
        Write-Log "Multiple INFs match. Choose one:"
        Write-Log ""
        for ($i = 0; $i -lt $Candidates.Count; $i++) {
            Write-Log ("  [{0}] {1}  [{2}]" -f $i, $Candidates[$i].Path.Substring($ExtractRoot.Length).TrimStart('\'), ((Get-INFArchList $Candidates[$i]) -join '/'))
        }
        $Chosen = $Candidates[(Read-ChoiceIndex -Count $Candidates.Count)]
    } else {
        $Chosen = $Candidates[0]
    }

    # Pick the driver name to record.
    $FinalDriverName = $DriverName
    if ([string]::IsNullOrWhiteSpace($FinalDriverName)) {
        if ($Chosen.DriverNames.Count -eq 1) {
            $FinalDriverName = $Chosen.DriverNames[0]
        } else {
            Write-Log "This INF declares several driver names. Which one do your printers use?"
            Write-Log ""
            for ($i = 0; $i -lt $Chosen.DriverNames.Count; $i++) { Write-Log ("  [{0}] {1}" -f $i, $Chosen.DriverNames[$i]) }
            $FinalDriverName = $Chosen.DriverNames[(Read-ChoiceIndex -Count $Chosen.DriverNames.Count)]
        }
    }

    $ChosenINF = Get-Item -LiteralPath $Chosen.Path
    $DriverFolder = $ChosenINF.Directory.FullName

    # --- 4. Build the zip from the INF's own folder ------------------------
    # Validated on HP ("64bit\") and KM ("Driver\PCL\Driver\Win_x64\"): the folder
    # holding the INF also holds all of its payload files.
    # Name the zip after the architecture(s) the chosen INF declares.
    $ArchLabel = (Get-INFArchList $Chosen) -join '-'
    $ZipName = "$PackLabel-$ArchLabel.zip"
    $ZipPath = Join-Path $OutputDirectory $ZipName
    if (Test-Path $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }

    Write-Log "Packaging driver folder: $DriverFolder"
    Compress-Archive -Path (Join-Path $DriverFolder '*') -DestinationPath $ZipPath -Force -ErrorAction Stop

    $ZipSizeMB = [math]::Round((Get-Item $ZipPath).Length / 1MB, 2)

    # --- 5. Emit the JSON drivers[] entry ---------------------------------
    if ([string]::IsNullOrWhiteSpace($PresetDriver)) {
        $PresetDriver = (($FinalDriverName -replace '[^A-Za-z0-9]+', '_').Trim('_').ToUpper()) + "_WIN_" + ($ArchLabel -replace '-', '_').ToUpper()
    }

    # Group by manufacturer so the blob layout stays navigable:
    #   printers/Drivers/KonicaMinolta/<zip>   not   printers/Drivers/<zip>
    $VendorFolder = Get-VendorFolder -DriverName $FinalDriverName
    $BlobPath = "$($BlobPathPrefix.TrimEnd('/'))/$VendorFolder/$ZipName"

    # TODO: auto-fill KnownModels when the INF actually declares real model names.
    #
    # Whether this is possible depends entirely on the driver type:
    #
    #  - MODEL-SPECIFIC INFs DO carry readable model names, as the left-hand side
    #    of their model entries. We already parse these into $Chosen.DriverNames,
    #    e.g. the HP UPD pack yields real strings like
    #        "HP LaserJet Enterprise 500 color M551 (DOT4USB)"
    #    For this class, KnownModels could be populated for free from that list.
    #
    #  - UNIVERSAL drivers DO NOT contain them, anywhere in the package. Verified
    #    against the KONICA MINOLTA Universal PCL pack: its only model hints are
    #    truncated USB hardware IDs of the form
    #        USBPRINT\KONICA_MINOLTAbizhub7925
    #    where the trailing 4 chars are a hash, not a model number - the model
    #    portion is truncated away. The real supported-model list lives in the
    #    vendor's compatibility matrix / release notes, NOT in the driver package.
    #    No amount of INF parsing recovers it.
    #
    # So this can only ever be partial, which is why it is left as a placeholder
    # for now - populating it for some entries and not others was judged more
    # confusing than leaving it consistently manual. Revisit if the inconsistency
    # turns out to be acceptable.
    $Entry = [PSCustomObject][ordered]@{
        PresetDriver = $PresetDriver
        DriverName   = $FinalDriverName
        INFFile      = $ChosenINF.Name
        DriverZip    = $BlobPath
        KnownModels  = "FILL_IN_MODELS_THIS_COVERS"
    }

    $JsonPath = Join-Path $OutputDirectory "$PackLabel.driver-entry.json"
    $Entry | ConvertTo-Json -Depth 4 | Out-File -FilePath $JsonPath -Encoding UTF8 -Force

    # --- 6. Report ---------------------------------------------------------
    Write-Log ""
    Write-Log "=== DONE ===" "SUCCESS"
    Write-Log ""
    Write-Log ("  Chosen INF   : {0}" -f $ChosenINF.Name)
    Write-Log ("  Driver name  : {0}" -f $FinalDriverName)
    Write-Log ("  Zip          : {0}  ({1} MB)" -f $ZipPath, $ZipSizeMB)
    Write-Log ("  JSON entry   : {0}" -f $JsonPath)
    Write-Log ""
    Write-Log "NEXT STEPS:"
    Write-Log ""
    Write-Log "  1. Upload the zip to your blob so it lands at: $BlobPath"
    Write-Log "  2. Paste the JSON entry into the 'drivers' array of your printer JSON."
    Write-Log "  3. Fill in KnownModels."
    Write-Log ""
    Write-Log "JSON output:"
    Write-Host (Get-Content $JsonPath -Raw)

} Catch {
    Write-Log "Failed: $_" "ERROR"
}

Write-Log ""
Write-Log "Finished"
