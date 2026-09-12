<#

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

  2. SECONDARY FILTER - architecture, read from the [Manufacturer] decoration
     ("NTamd64" vs "NTx86"). This is a Microsoft INF requirement, not a vendor
     convention, so it is the same for every manufacturer. INF files are
     case-insensitive by spec, so matching is case-insensitive
     (HP writes "NTAMD64", KM writes "NTamd64", others write "ntamd64.6.0.3").

  3. TIE-BREAK - if a DriverName is supplied, keep only INFs declaring it.
     Anything still ambiguous is put to you as a pick-list; nothing is guessed.

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

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = "$WorkingDirectory\TEMP\DriverPacks"
}


# --- Helpers --------------------------------------------------------------

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

function Get-INFDriverInfo {
    <#
      Parses one INF the way Windows does:
        [Manufacturer] lists  %Var%=SectionBase,decoration1,decoration2...
        Model sections are    [SectionBase] and [SectionBase.decoration]
        Model entries look like   "Driver Name" = InstallSection,HardwareID
      Returns the declared driver names plus the architectures declared.
    #>
    param([string]$Path)

    $Result = [PSCustomObject][ordered]@{
        Path          = $Path
        DriverNames   = @()
        Decorations   = @()
        SupportsAmd64 = $false
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
                if ($dec -imatch 'x86')   { $Result.Supportsx86   = $true }
            }
        }
    }

    # Collect declared driver names from every model section.
    $Names = New-Object System.Collections.ArrayList
    foreach ($sName in ($ModelSectionNames | Select-Object -Unique)) {
        $key = $Sections.Keys | Where-Object { $_ -ieq $sName } | Select-Object -First 1
        if (-not $key) { continue }
        foreach ($entry in $Sections[$key]) {
            # Model entries always quote the driver name on the left of '='.
            if ($entry -match '^\s*"([^"]+)"\s*=') {
                $n = $Matches[1].Trim()
                if ($n -ne '' -and -not $Names.Contains($n)) { [void]$Names.Add($n) }
            }
        }
    }

    $Result.DriverNames = @($Names)
    # An INF with no decorations at all is undecorated/legacy - treat as usable.
    if ($Result.Decorations.Count -eq 0) { $Result.SupportsAmd64 = $true }
    return $Result
}


# --- Main -----------------------------------------------------------------

Try {

    if (!(Test-Path $PackPath)) { Write-Warning "Pack not found: $PackPath"; return }

    $PackItem = Get-Item -LiteralPath $PackPath
    $PackLabel = [System.IO.Path]::GetFileNameWithoutExtension($PackItem.Name)
    if (!(Test-Path $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }

    # --- 1. Get an extracted folder to work from --------------------------
    if ($PackItem.PSIsContainer) {

        $ExtractRoot = $PackItem.FullName
        Write-Host "Using already-extracted folder: $ExtractRoot"

    } else {

        $ExtractRoot = Join-Path $OutputDirectory "$PackLabel-EXTRACTED"
        if (Test-Path $ExtractRoot) {
            Write-Host "Removing previous extraction: $ExtractRoot"
            Remove-Item -LiteralPath $ExtractRoot -Recurse -Force
        }
        New-Item -ItemType Directory -Path $ExtractRoot -Force | Out-Null

        switch ($PackItem.Extension.ToLower()) {

            '.zip' {
                Write-Host "Extracting zip..."
                Expand-Archive -LiteralPath $PackItem.FullName -DestinationPath $ExtractRoot -Force -ErrorAction Stop
            }

            '.exe' {
                $SevenZip = Find-SevenZip
                if (-not $SevenZip) {
                    Write-Warning "This pack is a self-extracting .exe, which needs 7-Zip to unpack."
                    Write-Warning "Install 7-Zip, or extract the .exe yourself and re-run against the folder."
                    return
                }
                Write-Host "Extracting self-extracting exe with 7-Zip..."
                & $SevenZip x $PackItem.FullName "-o$ExtractRoot" -y | Out-Null
                if ($LASTEXITCODE -ne 0) { Write-Warning "7-Zip failed with exit code $LASTEXITCODE"; return }
            }

            default {
                Write-Warning "Unsupported pack type '$($PackItem.Extension)'. Expected .zip, .exe, or a folder."
                return
            }
        }
    }

    # --- 2. Find and parse every INF --------------------------------------
    $AllINFs = @(Get-ChildItem -Path $ExtractRoot -Filter *.inf -Recurse -File -ErrorAction SilentlyContinue)
    if ($AllINFs.Count -eq 0) { Write-Warning "No .inf files found anywhere in $ExtractRoot"; return }

    Write-Host ""
    Write-Host "Found $($AllINFs.Count) INF file(s). Parsing..."
    $Parsed = foreach ($inf in $AllINFs) { Get-INFDriverInfo -Path $inf.FullName }

    # PRIMARY FILTER: only INFs that actually declare printer driver names.
    $PrinterINFs = @($Parsed | Where-Object { $_.DriverNames.Count -gt 0 })

    Write-Host ""
    Write-Host "=== PACK ANALYSIS ===" -ForegroundColor Cyan
    Write-Host ("  INFs total                   : {0}" -f $AllINFs.Count)
    Write-Host ("  INFs declaring printer drivers: {0}" -f $PrinterINFs.Count)
    foreach ($p in $PrinterINFs) {
        $rel = $p.Path.Substring($ExtractRoot.Length).TrimStart('\')
        $arch = @(); if ($p.SupportsAmd64) { $arch += 'x64' }; if ($p.Supportsx86) { $arch += 'x86' }
        Write-Host ""
        Write-Host ("  {0}  [{1}]" -f $rel, ($arch -join '/')) -ForegroundColor Yellow
        foreach ($n in $p.DriverNames) { Write-Host "      - $n" }
    }

    if ($PrinterINFs.Count -eq 0) { Write-Warning "No INF in this pack declares any printer driver. Nothing to package."; return }
    if ($Analyze) { Write-Host ""; Write-Host "-Analyze specified; stopping here."; return }

    # --- 3. Narrow to one INF ---------------------------------------------
    $Candidates = $PrinterINFs

    # SECONDARY FILTER: architecture.
    $Wanted = @($Candidates | Where-Object { $_.SupportsAmd64 })
    if ($Wanted.Count -ge 1) { $Candidates = $Wanted } else { Write-Host "No x64-capable INF found; keeping all candidates." -ForegroundColor Yellow }

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
                Write-Host ""
                Write-Warning "No EXACT match for '$DriverName'. Found partial match(es) instead."
                Write-Warning "Confirm the exact name below - it must match Add-PrinterDriver exactly."
            }
        }

        if ($ByName.Count -ge 1) {
            $Candidates = $ByName
        } else {
            Write-Warning "No INF declares a driver matching '$DriverName'."
            Write-Warning "Names that ARE available are listed above - copy one of them exactly."
            return
        }

    } else {
        Write-Host ""
        Write-Warning "No -DriverName supplied. Selection will be interactive."
        Write-Warning "Tip: the DriverName column from Export-PrinterServer-CSV.ps1 is exactly what goes here."
    }

    # Prefer a SELF-CONTAINED folder. Because the zip is built from the INF's
    # directory, an INF sitting in a folder that also nests OTHER driver variants
    # would drag all of them in. Real example: a KM pack with a flattened copy at
    # the root produced a 91 MB zip (the root also holds the whole Driver\ tree),
    # versus ~31 MB when packaging the arch-specific Win_x64 folder instead.
    # So rank candidates whose folder contains no other printer INF first.
    if ($Candidates.Count -gt 1) {
        $Ranked = $Candidates | ForEach-Object {
            $cand = $_          # capture: $_ rebinds inside the nested Where-Object
            $dir = (Split-Path $cand.Path -Parent).TrimEnd('\') + '\'
            $nested = @($PrinterINFs | Where-Object {
                $_.Path -ne $cand.Path -and $_.Path.StartsWith($dir, [StringComparison]::OrdinalIgnoreCase)
            }).Count
            [PSCustomObject]@{ Info = $cand; Nested = $nested; Depth = $cand.Path.Split([char]'\').Count }
        }
        # Fewest nested variants first, then shallowest, for a deterministic order.
        $Candidates = @($Ranked | Sort-Object Nested, Depth | ForEach-Object { $_.Info })

        $SelfContained = @($Ranked | Where-Object { $_.Nested -eq 0 })
        if ($SelfContained.Count -ge 1 -and $SelfContained.Count -lt $Ranked.Count) {
            Write-Host ""
            Write-Host "Note: preferring self-contained driver folder(s) to avoid over-packaging." -ForegroundColor Yellow
        }
    }

    if ($Candidates.Count -gt 1) {
        Write-Host ""
        Write-Host "Multiple INFs still match. Choose one (best first):" -ForegroundColor Yellow
        for ($i = 0; $i -lt $Candidates.Count; $i++) {
            Write-Host ("  [{0}] {1}" -f $i, $Candidates[$i].Path.Substring($ExtractRoot.Length).TrimStart('\'))
        }
        $pick = Read-Host "Enter number (blank = 0)"
        if ([string]::IsNullOrWhiteSpace($pick)) { $pick = 0 }
        $Chosen = $Candidates[[int]$pick]
    } else {
        $Chosen = $Candidates[0]
    }

    # Pick the driver name to record.
    $FinalDriverName = $DriverName
    if ([string]::IsNullOrWhiteSpace($FinalDriverName)) {
        if ($Chosen.DriverNames.Count -eq 1) {
            $FinalDriverName = $Chosen.DriverNames[0]
        } else {
            Write-Host ""
            Write-Host "This INF declares several driver names. Which one do your printers use?" -ForegroundColor Yellow
            for ($i = 0; $i -lt $Chosen.DriverNames.Count; $i++) { Write-Host ("  [{0}] {1}" -f $i, $Chosen.DriverNames[$i]) }
            $pick = Read-Host "Enter number (blank = 0)"
            if ([string]::IsNullOrWhiteSpace($pick)) { $pick = 0 }
            $FinalDriverName = $Chosen.DriverNames[[int]$pick]
        }
    }

    $ChosenINF = Get-Item -LiteralPath $Chosen.Path
    $DriverFolder = $ChosenINF.Directory.FullName

    # --- 4. Build the zip from the INF's own folder ------------------------
    # Validated on HP ("64bit\") and KM ("Driver\PCL\Driver\Win_x64\"): the folder
    # holding the INF also holds all of its payload files.
    $ZipName = "$PackLabel-x64.zip"
    $ZipPath = Join-Path $OutputDirectory $ZipName
    if (Test-Path $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }

    Write-Host ""
    Write-Host "Packaging driver folder: $DriverFolder"
    Compress-Archive -Path (Join-Path $DriverFolder '*') -DestinationPath $ZipPath -Force -ErrorAction Stop

    $ZipSizeMB = [math]::Round((Get-Item $ZipPath).Length / 1MB, 2)

    # --- 5. Emit the JSON drivers[] entry ---------------------------------
    if ([string]::IsNullOrWhiteSpace($PresetDriver)) {
        $PresetDriver = (($FinalDriverName -replace '[^A-Za-z0-9]+', '_').Trim('_').ToUpper()) + "_WIN_X64"
    }

    $BlobPath = "$($BlobPathPrefix.TrimEnd('/'))/$ZipName"

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
    Write-Host ""
    Write-Host "=== DONE ===" -ForegroundColor Green
    Write-Host ("  Chosen INF   : {0}" -f $ChosenINF.Name)
    Write-Host ("  Driver name  : {0}" -f $FinalDriverName)
    Write-Host ("  Zip          : {0}  ({1} MB)" -f $ZipPath, $ZipSizeMB)
    Write-Host ("  JSON entry   : {0}" -f $JsonPath)
    Write-Host ""
    Write-Host "NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "  1. Upload the zip to your blob so it lands at: $BlobPath"
    Write-Host "  2. Paste the JSON entry into the 'drivers' array of your printer JSON."
    Write-Host "  3. Fill in KnownModels."
    Write-Host ""
    Write-Host (Get-Content $JsonPath -Raw)

} Catch {
    Write-Warning "Failed: $_"
}

Write-Host "Finished"
