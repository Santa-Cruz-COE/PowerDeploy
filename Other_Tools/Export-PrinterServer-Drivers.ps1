<#

INSTRUCTIONS:
Run this ON the print server (same as Export-PrinterServer-CSV.ps1).
Administrator rights are NOT required for the normal path.

WHAT IT DOES AND WHY

This is the backfill counterpart to Convert-VendorPack-ToDriverZip.ps1:
instead of ingesting a manufacturer's pack, it harvests the drivers your print
server is ALREADY using, and emits blob-ready zips plus the matching
"drivers" JSON entries.

The key insight is that you do not have to guess which files a driver needs.
When a printer driver is installed, Windows stages a flattened, complete,
minimal copy of it into the Driver Store:

    C:\Windows\System32\DriverStore\FileRepository\<inf>_<arch>_<hash>\

Windows has already resolved exactly which files that INF references. That
folder IS the "gutted" driver package you would otherwise hand-build - and
Get-PrinterDriver hands you the path to it directly via its InfPath property,
so no elevation and no pnputil call is needed to read it.

Even better, these are the exact driver VERSIONS currently working in
production on the print server, rather than whatever is newest on a vendor site.

Falls back to `pnputil /export-driver` (which DOES need admin) only for the
unusual case where a driver's InfPath is not inside the Driver Store.

USAGE
  .\Export-PrinterServer-Drivers.ps1 -Analyze     # list what would be exported
  .\Export-PrinterServer-Drivers.ps1              # export every in-use driver
  .\Export-PrinterServer-Drivers.ps1 -DriverName "KONICA MINOLTA Universal PCL"

#>

param(
    # Export only this driver. Default: every driver actually used by a printer.
    [string]$DriverName,

    # Include Microsoft in-box drivers (Print to PDF, XPS, IPP class...).
    # Off by default - they ship with Windows and do not need deploying.
    [switch]$IncludeMicrosoft,

    # Export every installed printer driver, not just those in use by a printer.
    [switch]$AllInstalled,

    [string]$BlobPathPrefix = "printers/Drivers",

    [string]$OutputDirectory,

    # Report only; build nothing.
    [switch]$Analyze
)

# Resolve our own folder even when run via paste/selection, where $PSScriptRoot is empty.
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $ScriptDir) { $ScriptDir = (Get-Location).Path }

$RepoRoot = Split-Path $ScriptDir -Parent
$WorkingDirectory = Split-Path $RepoRoot -Parent
if (!(Test-Path "$WorkingDirectory\TEMP")) { $WorkingDirectory = $ScriptDir }

$PrintServerName = $env:COMPUTERNAME
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = "$WorkingDirectory\TEMP\PrintServer_Drivers"
}


# --- Helpers --------------------------------------------------------------

function Get-PresetDriverCode {
    # Same slug convention as Export-PrinterServer-CSV.ps1 so the two tools agree.
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return "" }
    $vendorMap = @{
        'HP'='HP'; 'Hewlett'='HP'; 'KONICA MINOLTA'='KM'; 'Konica'='KM'; 'Canon'='CANON'
        'Xerox'='XEROX'; 'Ricoh'='RICOH'; 'Brother'='BROTHER'; 'Lexmark'='LEXMARK'
        'Epson'='EPSON'; 'Kyocera'='KYOCERA'; 'Sharp'='SHARP'; 'Toshiba'='TOSHIBA'
    }
    $prefix = $null
    foreach ($k in $vendorMap.Keys) { if ($Name -match [regex]::Escape($k)) { $prefix = $vendorMap[$k]; break } }
    $slug = ($Name -replace '[^A-Za-z0-9]+','_').Trim('_').ToUpper()
    if ($prefix -and $slug -notmatch "^$prefix`_") { $slug = "$prefix`_$slug" }
    return "$slug`_WIN_X64"
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

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}


# --- Main -----------------------------------------------------------------

Try {

    Write-Host "Print server: $PrintServerName"

    # --- 1. Decide which drivers we care about ----------------------------
    if ($AllInstalled) {
        $TargetNames = @(Get-PrinterDriver -ErrorAction Stop | Select-Object -ExpandProperty Name -Unique)
        Write-Host "Scope: ALL installed printer drivers"
    } else {
        # Only drivers actually bound to a printer - mirrors the CSV export's intent.
        $TargetNames = @(Get-Printer -ErrorAction Stop | Select-Object -ExpandProperty DriverName -Unique)
        Write-Host "Scope: drivers in use by printers on this server"
    }

    if (-not $IncludeMicrosoft) {
        $TargetNames = @($TargetNames | Where-Object {
            $_ -notmatch '^Microsoft' -and $_ -notmatch 'Universal Print Class' -and $_ -notmatch '^Remote Desktop'
        })
    }

    if (-not [string]::IsNullOrWhiteSpace($DriverName)) {
        $TargetNames = @($TargetNames | Where-Object { $_ -eq $DriverName })
        if ($TargetNames.Count -eq 0) { Write-Warning "No driver named '$DriverName' is present. Run with -Analyze to list them."; return }
    }

    if ($TargetNames.Count -eq 0) { Write-Warning "Nothing to export."; return }

    # --- 2. Resolve each driver to its Driver Store package ---------------
    $Resolved = foreach ($name in ($TargetNames | Sort-Object)) {

        $drv = Get-PrinterDriver -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $drv) {
            Write-Warning "Could not read driver details for '$name' - skipping."
            continue
        }

        $inStore = ($drv.InfPath -like '*\DriverStore\FileRepository\*')
        $pkgDir  = if ($drv.InfPath) { Split-Path $drv.InfPath -Parent } else { $null }
        $files   = 0
        $sizeMB  = 0

        if ($inStore -and $pkgDir -and (Test-Path $pkgDir)) {
            $fi = @(Get-ChildItem -LiteralPath $pkgDir -Recurse -File -ErrorAction SilentlyContinue)
            $files  = $fi.Count
            $sizeMB = [math]::Round((($fi | Measure-Object Length -Sum).Sum) / 1MB, 2)
        }

        [PSCustomObject][ordered]@{
            DriverName   = $drv.Name
            INFFile      = if ($drv.InfPath) { Split-Path $drv.InfPath -Leaf } else { "" }
            InfPath      = $drv.InfPath
            PackageDir   = $pkgDir
            InDriverStore= $inStore
            FileCount    = $files
            SizeMB       = $sizeMB
        }
    }

    $Resolved = @($Resolved)

    # --- 3. Report --------------------------------------------------------
    Write-Host ""
    Write-Host "=== DRIVERS FOUND ($($Resolved.Count)) ===" -ForegroundColor Cyan
    foreach ($r in $Resolved) {
        Write-Host ""
        Write-Host ("  {0}" -f $r.DriverName) -ForegroundColor Yellow
        Write-Host ("      INF        : {0}" -f $r.INFFile)
        if ($r.InDriverStore) {
            Write-Host ("      Package    : {0}" -f $r.PackageDir)
            Write-Host ("      Contents   : {0} files, {1} MB" -f $r.FileCount, $r.SizeMB)
        } else {
            Write-Host ("      NOT in Driver Store - will need pnputil /export-driver (admin)") -ForegroundColor Magenta
            Write-Host ("      InfPath    : {0}" -f $r.InfPath)
        }
    }

    if ($Analyze) {
        Write-Host ""
        Write-Host "-Analyze specified; nothing was exported."
        return
    }

    if (!(Test-Path $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }

    # --- 4. Package each driver ------------------------------------------
    $Entries = New-Object System.Collections.ArrayList
    $IsAdmin = Test-IsAdmin

    foreach ($r in $Resolved) {

        $SafeName = ($r.DriverName -replace '[^A-Za-z0-9]+','_').Trim('_')
        $ZipName  = "$SafeName-x64.zip"
        $ZipPath  = Join-Path $OutputDirectory $ZipName
        $SourceDir = $null

        if ($r.InDriverStore -and (Test-Path $r.PackageDir)) {

            # Normal path: Windows already flattened and resolved this for us.
            $SourceDir = $r.PackageDir

        } else {

            # Fallback: ask Windows to export it. Requires elevation.
            if (-not $IsAdmin) {
                Write-Warning "'$($r.DriverName)' is not in the Driver Store and needs admin to export. Skipping - re-run elevated."
                continue
            }
            $ExportDir = Join-Path $OutputDirectory "$SafeName-EXPORT"
            if (Test-Path $ExportDir) { Remove-Item -LiteralPath $ExportDir -Recurse -Force }
            New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null

            $published = Split-Path $r.InfPath -Leaf
            Write-Host "Exporting '$($r.DriverName)' via pnputil ($published)..."
            & "$env:WINDIR\System32\pnputil.exe" /export-driver $published $ExportDir | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Warning "pnputil export failed for '$($r.DriverName)' (exit $LASTEXITCODE). Skipping."; continue }
            $SourceDir = $ExportDir
        }

        Write-Host "Packaging '$($r.DriverName)' from: $SourceDir"
        if (Test-Path $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
        Compress-Archive -Path (Join-Path $SourceDir '*') -DestinationPath $ZipPath -Force -ErrorAction Stop

        $ZipMB = [math]::Round((Get-Item $ZipPath).Length / 1MB, 2)
        Write-Host ("   -> {0} ({1} MB)" -f $ZipName, $ZipMB) -ForegroundColor Green

        # TODO: record which printers were OBSERVED using this driver.
        #
        # Running here on the print server, we can see exactly which queues are
        # bound to each driver - Get-Printer returns DriverName per printer, so
        # grouping by it costs nothing and needs no network calls. That is real
        # evidence from this environment, and arguably more useful than a
        # vendor's theoretical list of every model a universal driver supports.
        #
        # Two caveats to settle before building it:
        #
        #  1. This yields QUEUE NAMES, not models. Nothing on the port exposes a
        #     model - Description is just "Standard TCP/IP Port" and SNMPEnabled
        #     is commonly False. True model strings require an SNMP query to the
        #     device (OID 1.3.6.1.2.1.25.3.2.1.3.1 - which is what HP's own UPD
        #     does; see hpcu3456SPS.xml inside their pack). That is separate work.
        #     Queue names only help if your naming convention embeds the model.
        #
        #  2. It should go in its OWN field (e.g. ObservedOn), not KnownModels.
        #     KnownModels is hand-curated truth; writing machine output into it
        #     means a re-run silently clobbers notes someone wrote by hand.
        #
        # Deferred deliberately - not blocking, and the field is documentation
        # only (the installer never reads KnownModels).
        [void]$Entries.Add([PSCustomObject][ordered]@{
            PresetDriver = Get-PresetDriverCode -Name $r.DriverName
            DriverName   = $r.DriverName
            INFFile      = $r.INFFile
            DriverZip    = "$($BlobPathPrefix.TrimEnd('/'))/$(Get-VendorFolder -DriverName $r.DriverName)/$ZipName"
            KnownModels  = "FILL_IN_MODELS_THIS_COVERS"
        })
    }

    if ($Entries.Count -eq 0) { Write-Warning "No drivers were packaged."; return }

    # --- 5. Emit the drivers[] JSON ---------------------------------------
    $JsonPath = Join-Path $OutputDirectory "$PrintServerName.drivers.json"
    ([PSCustomObject]@{ drivers = @($Entries) }) | ConvertTo-Json -Depth 5 |
        Out-File -FilePath $JsonPath -Encoding UTF8 -Force

    Write-Host ""
    Write-Host "=== DONE ===" -ForegroundColor Green
    Write-Host ("  Drivers packaged : {0}" -f $Entries.Count)
    Write-Host ("  Output folder    : {0}" -f $OutputDirectory)
    Write-Host ("  JSON entries     : {0}" -f $JsonPath)
    Write-Host ""
    Write-Host "NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "  1. Upload each zip to the exact path in its DriverZip field."
    Write-Host "     These are grouped by manufacturer, e.g:"
    foreach ($e in ($Entries | Select-Object -First 3)) { Write-Host ("       {0}" -f $e.DriverZip) }
    Write-Host "     Anything whose manufacturer could not be identified goes under /Other."
    Write-Host "  2. Merge the 'drivers' array into your printer JSON."
    Write-Host "  3. Fill in KnownModels for each entry."
    Write-Host "  4. The PresetDriver codes here match Export-PrinterServer-CSV.ps1,"
    Write-Host "     so printers[] and drivers[] should line up."

} Catch {
    Write-Warning "Failed: $_"
}

Write-Host "Finished"
