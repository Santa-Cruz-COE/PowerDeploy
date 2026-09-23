<#

INSTRUCTIONS:
Companion to Export-PrinterServer-CSV.ps1.

Run this AFTER you have exported printers to CSV and reviewed the CSV
(confirmed PrinterName / PortName, and set the PresetDriver code for each row).

This script will:
- Read the reviewed CSV
- Build the "printers" section (one entry per row)
- Build the "drivers" section by de-duplicating on PresetDriver
  (a print server with many printers usually has only a handful of drivers)
- Write a standalone printer JSON file for you to review and merge into your
  private printer JSON

It does NOT touch your existing printer JSON - output is written to TEMP so
you can review it and merge deliberately.

DriverZip cannot be known from the print server (it points at YOUR storage),
so it is emitted as a "PASTE_DRIVERZIP_PATH_HERE" placeholder - fill it once per driver.

USAGE:
  .\Convert-PrinterCSV-ToJSON.ps1                 # prompts you to pick a CSV
  .\Convert-PrinterCSV-ToJSON.ps1 -CsvPath "C:\path\to\Export.csv"

#>

param(
    [string]$CsvPath,
    [string]$OutputPath
)

$RepoRoot = (Split-Path $PSScriptRoot -Parent)
$WorkingDirectory = (Split-Path $RepoRoot -Parent)

if (!(Test-Path "$WorkingDirectory\TEMP")) {
    $WorkingDirectory = $PSScriptRoot
}

$ExportDir = "$WorkingDirectory\TEMP\PrintServer_Exports"


# --- Helpers --------------------------------------------------------------

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
      Convert-VendorPack-ToDriverZip.ps1 - these scripts are intentionally
      standalone, so the helper is duplicated rather than shared.
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


Try {

    # --- Locate the CSV ---------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($CsvPath)) {

        if (!(Test-Path $ExportDir)) {
            Write-Warning "No CSV specified and no export folder found at: $ExportDir"
            Write-Warning "Run Export-PrinterServer-CSV.ps1 first, or pass -CsvPath."
            return
        }

        $csvFiles = Get-ChildItem -Path $ExportDir -Filter *.csv | Sort-Object LastWriteTime -Descending

        if ($csvFiles.Count -eq 0) {
            Write-Warning "No CSV files found in $ExportDir. Run Export-PrinterServer-CSV.ps1 first, or pass -CsvPath."
            return
        }

        Write-Host "Available exported CSV files (newest first):"
        for ($i = 0; $i -lt $csvFiles.Count; $i++) {
            Write-Host ("  [{0}] {1}  ({2})" -f $i, $csvFiles[$i].Name, $csvFiles[$i].LastWriteTime)
        }

        $choice = Read-Host "Enter the number of the CSV to convert (blank = 0, newest)"
        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = 0 }
        $CsvPath = $csvFiles[[int]$choice].FullName
    }

    if (!(Test-Path $CsvPath)) {
        Write-Warning "CSV not found at: $CsvPath"
        return
    }

    Write-Host "Reading CSV: $CsvPath"
    $rows = Import-Csv -Path $CsvPath

    if (-not $rows -or @($rows).Count -eq 0) {
        Write-Warning "CSV contained no rows. Nothing to convert."
        return
    }

    # --- Validate required columns ---------------------------------------
    $required = @('PrinterName', 'PortName', 'PrinterIP', 'PresetDriver', 'DriverName', 'INFFile')
    $have = $rows[0].PSObject.Properties.Name
    $missing = $required | Where-Object { $_ -notin $have }
    if ($missing.Count -gt 0) {
        Write-Warning ("CSV is missing required column(s): {0}" -f ($missing -join ', '))
        Write-Warning "Expected columns: $($required -join ', ')"
        return
    }

    # --- Work out which extra columns to carry into printers[] ------------
    #
    # Column rules:
    #   - Columns ending in _EXCLUDED are reference-only; never exported.
    #   - The six mapped columns below are handled explicitly.
    #   - EVERY other column the user adds (Model, Location, Asset, Department,
    #     or anything they invent) is carried through onto each printer object.
    #   - A column that is completely empty across all rows is dropped entirely,
    #     so unused sample columns never clutter the JSON.
    #   - Within a kept column, blank cells are omitted from that one object.
    $mapped = @('PrinterName','PortName','PrinterIP','PresetDriver','DriverName','INFFile')
    $allColumns = $rows[0].PSObject.Properties.Name

    $extraColumns = @($allColumns | Where-Object {
        $_ -notmatch '_EXCLUDED$' -and $mapped -notcontains $_
    } | Where-Object {
        # Keep only columns where at least one row has a value.
        $col = $_
        @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.$col) }).Count -gt 0
    })

    $droppedEmpty = @($allColumns | Where-Object {
        $_ -notmatch '_EXCLUDED$' -and $mapped -notcontains $_ -and $extraColumns -notcontains $_
    })
    $excludedCols = @($allColumns | Where-Object { $_ -match '_EXCLUDED$' })

    # --- Resolve PresetDriver collisions ----------------------------------
    #
    # PresetDriver is the key into drivers[], so one code must mean exactly one
    # INF. Because the code is slugged from DriverName, two printers with the
    # SAME driver name always land on the same code - and if their INFFile
    # differs, that is real version drift (e.g. "HP Universal Printing PCL 6"
    # ships as hpcu240u.inf in one UPD release and hpcu345u.inf in another).
    # Those are different drivers needing different zips, so they must not be
    # silently merged into one entry.
    #
    # Note the INVERSE case needs no special handling and already works: one INF
    # serving several driver names (KM's kobkaj__.inf declares both
    # "KONICA MINOLTA 4020i PCL" and "...5020i PCL") produces different codes,
    # so those become separate entries that can point at the SAME DriverZip.
    #
    # When a code does cover more than one INF, every member of that group gets
    # the INF's base name appended. Deriving the suffix from the data rather
    # than from row order keeps it deterministic and self-documenting, and
    # suffixing all members avoids an arbitrary "first one wins".
    $infsByPreset = @{}
    foreach ($row in $rows) {
        $p = ($row.PresetDriver).Trim()
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $raw = ($row.INFFile).Trim()
        $leaf = if ($raw) { Split-Path $raw -Leaf } else { "" }
        if (-not $infsByPreset.ContainsKey($p)) { $infsByPreset[$p] = New-Object System.Collections.ArrayList }
        if (-not $infsByPreset[$p].Contains($leaf)) { [void]$infsByPreset[$p].Add($leaf) }
    }

    $splitPresets = @($infsByPreset.Keys | Where-Object { $infsByPreset[$_].Count -gt 1 })

    function Resolve-PresetCode {
        param($BaseCode, $INFLeaf)
        if ([string]::IsNullOrWhiteSpace($BaseCode)) { return $BaseCode }
        if ($infsByPreset.ContainsKey($BaseCode) -and $infsByPreset[$BaseCode].Count -gt 1) {
            $suffix = ([System.IO.Path]::GetFileNameWithoutExtension($INFLeaf) -replace '[^A-Za-z0-9]+','_').Trim('_').ToUpper()
            if ($suffix) { return "$BaseCode`__$suffix" }
        }
        return $BaseCode
    }

    # --- Build printers[] and de-duplicated drivers[] --------------------
    $printers = @()
    $driverMap = @{}   # PresetDriver -> driver object (first seen)
    $conflicts = @()
    $rowNum = 1

    foreach ($row in $rows) {
        $rowNum++  # header is line 1

        $printerName = ($row.PrinterName).Trim()
        if ([string]::IsNullOrWhiteSpace($printerName)) {
            Write-Warning "Row $rowNum has a blank PrinterName - skipping."
            continue
        }

        $preset = ($row.PresetDriver).Trim()
        if ([string]::IsNullOrWhiteSpace($preset)) {
            Write-Warning "Printer '$printerName' has a blank PresetDriver - it will have no driver link in the JSON."
        }

        # Reduce INFFile to its bare filename. The installer builds
        # "$ExtractRoot\$INFFile" to locate the INF inside the DriverZip, so a
        # full path breaks it. Older CSVs (and anything built from
        # Get-PrinterDriver output) carry the full DriverStore InfPath, which
        # would otherwise land in the JSON as
        # "C:\\Windows\\System32\\DriverStore\\FileRepository\\...".
        # Split-Path -Leaf is a no-op on a value that is already bare.
        $infRaw  = ($row.INFFile).Trim()
        $infLeaf = if ($infRaw) { Split-Path $infRaw -Leaf } else { "" }

        # If this code covers more than one INF, both the printer and its driver
        # entry use the disambiguated form so they still join correctly.
        $presetBase  = $preset
        $preset      = Resolve-PresetCode -BaseCode $presetBase -INFLeaf $infLeaf
        $wasSplit    = ($presetBase -ne $preset)

        $printerObj = [ordered]@{
            PrinterName  = $printerName
            PortName     = ($row.PortName).Trim()
            PrinterIP    = ($row.PrinterIP).Trim()
            PresetDriver = $preset
        }

        # Carry through any user-added columns that have a value on this row.
        foreach ($col in $extraColumns) {
            $val = $row.$col
            if (-not [string]::IsNullOrWhiteSpace($val)) { $printerObj[$col] = $val.Trim() }
        }

        $printers += [PSCustomObject]$printerObj

        if (-not [string]::IsNullOrWhiteSpace($preset)) {
            if (-not $driverMap.ContainsKey($preset)) {
                $driverMap[$preset] = [PSCustomObject][ordered]@{
                    PresetDriver = $preset
                    DriverName   = ($row.DriverName).Trim()
                    INFFile      = $infLeaf
                    # This script does not build a zip, so it cannot know the
                    # filename - but it DOES know the manufacturer, so emit the
                    # correct folder shape and leave only the filename to fill.
                    #
                    # For a split (version-drift) entry the placeholder is made
                    # distinct per INF. Both halves need DIFFERENT zips, and an
                    # identical placeholder on both is an easy way to end up
                    # pointing them at the same file by accident.
                    DriverZip    = if ($wasSplit) {
                                       "printers/Drivers/$(Get-VendorFolder -DriverName ($row.DriverName).Trim())/PASTE_ZIP_FOR_$($infLeaf)_HERE.zip"
                                   } else {
                                       "printers/Drivers/$(Get-VendorFolder -DriverName ($row.DriverName).Trim())/PASTE_ZIP_FILENAME_HERE.zip"
                                   }
                }
            } else {
                # Anything still colliding after disambiguation is a genuine data
                # problem. Report the field that ACTUALLY differs with both
                # values - the old message only ever printed DriverName, so an
                # INF-only conflict rendered as "'X' vs 'X'", which told you
                # nothing about the real mismatch.
                $existing = $driverMap[$preset]
                $rowDriverName = ($row.DriverName).Trim()

                if ($existing.DriverName -ne $rowDriverName) {
                    $conflicts += "PresetDriver '$preset' has two DriverName values: '$($existing.DriverName)' vs '$rowDriverName' (row $rowNum). Give them different PresetDriver codes."
                }
                if ($existing.INFFile -ne $infLeaf) {
                    $conflicts += "PresetDriver '$preset' has two INFFile values: '$($existing.INFFile)' vs '$infLeaf' (row $rowNum). Only '$($existing.INFFile)' was kept."
                }
            }
        }
    }

    $drivers = @($driverMap.Values | Sort-Object PresetDriver)

    # --- Assemble and write JSON -----------------------------------------
    $jsonObject = [PSCustomObject][ordered]@{
        printers = $printers
        drivers  = $drivers
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($CsvPath)
        $OutputDir = "$WorkingDirectory\TEMP\PrintServer_Exports"
        if (!(Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
        $OutputPath = "$OutputDir\$baseName.PrinterData.json"
    }

    $jsonObject | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

    # --- Report -----------------------------------------------------------
    Write-Host ""
    Write-Host "Conversion complete." -ForegroundColor Green
    Write-Host ("  Printers written : {0}" -f $printers.Count)
    Write-Host ("  Distinct drivers : {0}" -f $drivers.Count)

    if ($extraColumns.Count -gt 0) {
        Write-Host ("  Extra columns carried into each printer: {0}" -f ($extraColumns -join ', '))
    }
    if ($droppedEmpty.Count -gt 0) {
        Write-Host ("  Columns dropped (empty in every row)   : {0}" -f ($droppedEmpty -join ', '))
    }
    if ($excludedCols.Count -gt 0) {
        Write-Host ("  Columns skipped (_EXCLUDED)            : {0}" -f ($excludedCols -join ', '))
    }

    if ($splitPresets.Count -gt 0) {
        Write-Host ""
        Write-Host "DRIVER VERSION SPLIT DETECTED" -ForegroundColor Yellow
        foreach ($sp in $splitPresets) {
            Write-Host ("  '{0}' covers {1} different INF files, so it was split into:" -f $sp, $infsByPreset[$sp].Count)
            foreach ($i in $infsByPreset[$sp]) {
                Write-Host ("     {0}   (INF: {1})" -f (Resolve-PresetCode -BaseCode $sp -INFLeaf $i), $i)
            }
        }
        Write-Host "  These are separate driver versions and need SEPARATE DriverZips." -ForegroundColor Yellow
    }
    Write-Host ("  Output JSON      : {0}" -f $OutputPath)

    if ($conflicts.Count -gt 0) {
        Write-Host ""
        Write-Warning "Driver mapping conflicts detected - fix these in the CSV and re-run:"
        $conflicts | ForEach-Object { Write-Warning "  $_" }
    }

    $needFill = $drivers | Where-Object { $_.DriverZip -like "*PASTE_ZIP_FILENAME_HERE*" }
    if ($needFill.Count -gt 0) {
        Write-Host ""
        Write-Host "NEXT STEP: set the DriverZip path for each of these drivers in the JSON:" -ForegroundColor Yellow
        $needFill | ForEach-Object { Write-Host ("  - {0}" -f $_.PresetDriver) }
    }

    Write-Host ""
    Write-Host "Review the output, then merge the printers[] and drivers[] entries into your private printer JSON."

} Catch {
    Write-Warning "Conversion failed: $_"
}

Write-Host "Finished"
