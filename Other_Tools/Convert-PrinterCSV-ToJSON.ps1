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

        $printers += [PSCustomObject][ordered]@{
            PrinterName  = $printerName
            PortName     = ($row.PortName).Trim()
            PrinterIP    = ($row.PrinterIP).Trim()
            PresetDriver = $preset
        }

        if (-not [string]::IsNullOrWhiteSpace($preset)) {
            if (-not $driverMap.ContainsKey($preset)) {
                $driverMap[$preset] = [PSCustomObject][ordered]@{
                    PresetDriver = $preset
                    DriverName   = ($row.DriverName).Trim()
                    INFFile      = ($row.INFFile).Trim()
                    DriverZip    = "PASTE_DRIVERZIP_PATH_HERE"
                }
            } else {
                # Same PresetDriver code but different DriverName/INFFile = likely
                # a naming mistake in the CSV. Flag it so the user can fix it.
                $existing = $driverMap[$preset]
                if ($existing.DriverName -ne ($row.DriverName).Trim() -or
                    $existing.INFFile   -ne ($row.INFFile).Trim()) {
                    $conflicts += "PresetDriver '$preset' maps to more than one driver: '$($existing.DriverName)' vs '$($row.DriverName)' (row $rowNum)."
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
    Write-Host ("  Output JSON      : {0}" -f $OutputPath)

    if ($conflicts.Count -gt 0) {
        Write-Host ""
        Write-Warning "Driver mapping conflicts detected - fix these in the CSV and re-run:"
        $conflicts | ForEach-Object { Write-Warning "  $_" }
    }

    $needFill = $drivers | Where-Object { $_.DriverZip -eq "PASTE_DRIVERZIP_PATH_HERE" }
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
