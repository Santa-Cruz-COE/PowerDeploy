<#

.SYNOPSIS
    Bulk printer tools for Intune: create every printer in PrinterData.json from one CSV, and delete
    many printer apps from one CSV.

.DESCRIPTION
    The logic behind two Setup.ps1 menu entries:

      Printer--InTune-BulkCreate  PrinterData.json -> draft CSV (Include / groups editable) -> stage
                                  (groups resolved, existing printers found) -> confirm -> create.
                                  A printer that already exists (same PrinterName AND same deploy
                                  mode) is overridden by creating the new app FIRST and deleting the
                                  old one only after the new one was created and verified. The old
                                  app is backed up to JSON before it is deleted.
      Printer--InTune-BulkDelete  every PowerDeploy printer app -> CSV (mark rows) -> confirm ->
                                  back up -> delete. Intune cleanup only: devices keep the printer.

    No prompts live here; Setup.ps1 owns every question. Everything is reachable offline through
    the Graph helper library's TestTransport seam, which is how Tests\PrinterIntuneBulk.Tests.ps1
    runs it.

    This file may be dot-sourced: functions only, no top-level param() block, no output, no side
    effects at import. It needs Other_Tools\InTune-GraphAPI_Helpers.ps1, Upload-InTuneWin32App.ps1
    (bulk create only) and Printer-Intune_Helpers.ps1 to be loaded first; Setup.ps1 loads all three.

.LINK
    .claude/plans/printer-bulk-tools.buildplan.md

#>

# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------

$script:PDBulk = @{
    # Bulk create. Include, RequiredGroups and AvailableGroups are the operator's; the rest is context.
    # A draft is these columns, then ReferenceColumns, then any other printer field the JSON uses
    # (Get-PDPrinterBulkDraftColumns).
    DraftColumns   = @('Include', 'PrinterName', 'IntuneDisplayName', 'RequiredGroups', 'AvailableGroups', 'Problem')
    # PrinterData.json fields shown for reference only: printer details always come from the JSON,
    # and an edit to one of these in the sheet is reported as ignored. Driver columns show what the
    # installer will use (the PresetDriver's values when one is set).
    ReferenceColumns = @('Department', 'Location', 'Model', 'Asset', 'PrinterIP', 'PortName', 'PresetDriver', 'DriverName', 'INFFile', 'DriverZip', 'Verified', 'Publisher')
    StagedColumns  = @('Include', 'PrinterName', 'IntuneDisplayName', 'RequiredGroups', 'AvailableGroups', 'Department', 'Location', 'PrinterIP', 'Problem', 'Action', 'ExistingAppIds', 'ExistingDisplayNames')
    ResultColumns  = @('Include', 'PrinterName', 'IntuneDisplayName', 'RequiredGroups', 'AvailableGroups', 'Department', 'Location', 'PrinterIP', 'Problem', 'Action', 'Result', 'NewAppId', 'DeletedAppIds', 'BackupFiles', 'Error')

    # Bulk delete. Only Delete is the operator's; rows are matched by AppId alone.
    DeleteColumns       = @('Delete', 'DisplayName', 'PrinterName', 'DeployMode', 'Version', 'Created', 'AppId')
    DeleteResultColumns = @('DisplayName', 'PrinterName', 'DeployMode', 'AppId', 'Result', 'BackupFile', 'Error')

    # Every printer app Setup creates starts with this (see Get-PDPrinterIntuneDisplayName).
    DisplayNamePrefix = 'PRINTER'
    Category          = 'Printers'
}

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

function Test-PDBulkYes {
    <# True for the ways a person marks a spreadsheet cell "yes": Y, Yes, X, TRUE, 1 (any case, trimmed). #>
    param([AllowNull()][object]$Value)

    $text = ([string]$Value).Trim().ToLowerInvariant()
    return (@('y', 'yes', 'x', 'true', '1') -contains $text)
}

function Get-PDBulkCell {
    <# One trimmed cell from a CSV row (or any object), '' when the column is absent. Never throws. #>
    param([AllowNull()][object]$Row, [Parameter(Mandatory = $true)][string]$Name)

    if ($null -eq $Row) { return '' }
    $property = $Row.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return '' }
    return ([string]$property.Value).Trim()
}

function Get-PDBulkRecordValue {
    <# One property of a PrinterData.json record, $null when absent (so 'not supplied' stays $null, as in the wizard). #>
    param([AllowNull()][object]$Record, [Parameter(Mandatory = $true)][string]$Name)

    if ($null -eq $Record) { return $null }
    $property = $Record.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-PDBulkGroupTerms {
    <# A CSV group cell split on ';' (the uploader's own rule), trimmed, empties dropped. #>
    param([AllowNull()][string]$Cell)
    return @(Get-PDDelimitedList -Values @($Cell))
}

# ---------------------------------------------------------------------------
# CSV in and out
# ---------------------------------------------------------------------------

function Write-PDBulkCsv {
    <#
        .SYNOPSIS
        Writes rows with exactly these columns, in this order, as UTF-8 WITH a BOM on both engines
        (Excel reads a BOM-less UTF-8 CSV as ANSI and mangles non-ASCII names).
    #>
    param(
        [AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory = $true)][string[]]$Columns,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $folder = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($folder) -and -not (Test-Path -LiteralPath $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }

    $shaped = @()
    foreach ($row in @($Rows)) {
        $out = [ordered]@{}
        foreach ($column in $Columns) { $out[$column] = Get-PDBulkCell -Row $row -Name $column }
        $shaped += [pscustomobject]$out
    }

    if (@($shaped).Count -eq 0) {
        $lines = @(($Columns | ForEach-Object { '"' + $_ + '"' }) -join ',')
    } else {
        $lines = @($shaped | ConvertTo-Csv -NoTypeInformation)
    }

    [System.IO.File]::WriteAllLines($Path, [string[]]$lines, (New-Object System.Text.UTF8Encoding($true)))
}

function Read-PDBulkCsv {
    <#
        .SYNOPSIS
        Reads an operator-edited CSV. Tolerates a BOM, Excel's blank trailing rows, extra columns,
        and stray spaces. Throws only when the file cannot be read or a required column is gone.

        .OUTPUTS
        Array of PSCustomObject rows; each gains a RowNumber (the spreadsheet row, header = 1).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$RequiredColumns
    )

    if (-not (Test-Path -LiteralPath $Path)) { throw "The CSV was not found: $Path" }

    try {
        $text = [System.IO.File]::ReadAllText($Path)
    } catch {
        throw ("The CSV could not be read ({0}). If it is open in Excel, save and close it, then try again." -f $_.Exception.Message)
    }

    $raw = @()
    if (-not [string]::IsNullOrWhiteSpace($text)) { $raw = @($text | ConvertFrom-Csv) }

    $headerLine = ($text -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    $present = @()
    if ($headerLine) { $present = @(($headerLine | ConvertFrom-Csv -Header (1..200 | ForEach-Object { "c$_" })).PSObject.Properties | Where-Object { $null -ne $_.Value } | ForEach-Object { ([string]$_.Value).Trim() }) }

    $missing = @($RequiredColumns | Where-Object { $present -notcontains $_ })
    if ($missing.Count -gt 0) {
        throw ("The CSV is missing column(s): {0}. Columns can be added but not renamed or removed." -f ($missing -join ', '))
    }

    $rows = @()
    $rowNumber = 1
    foreach ($row in $raw) {
        $rowNumber++
        $hasText = $false
        foreach ($property in $row.PSObject.Properties) {
            if (-not [string]::IsNullOrWhiteSpace([string]$property.Value)) { $hasText = $true; break }
        }
        if (-not $hasText) { continue }

        $clean = [ordered]@{ RowNumber = $rowNumber }
        foreach ($property in $row.PSObject.Properties) {
            $name = ([string]$property.Name).Trim()
            if ([string]::IsNullOrWhiteSpace($name) -or $clean.Contains($name)) { continue }
            $clean[$name] = ([string]$property.Value).Trim()
        }
        $rows += [pscustomobject]$clean
    }

    return $rows
}

# ---------------------------------------------------------------------------
# PrinterData.json
# ---------------------------------------------------------------------------

function Get-PDPrinterJsonCatalog {
    <#
        .SYNOPSIS
        Reads PrinterData.json and checks every printer the way the installer will.

        .OUTPUTS
        { Printers = records sorted by PrinterName; ByName = name -> record;
          Problems = name -> why this printer would fail to install;
          Errors = problems with the whole file (any one stops the bulk run) }

        .NOTES
        A PrinterName used twice is a whole-file error: the wizard and the installer both refuse it
        (Setup.ps1 Select-PrinterFromJSON), and there is no safe way to choose one.
        Per-printer rules mirror General_IP-Printer_Installer.ps1: PortName and PrinterIP are
        required; the driver comes from a PresetDriver that exists in "drivers", or, without one,
        from the record's own DriverName, INFFile and DriverZip.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $catalog = @{ Printers = @(); ByName = @{}; Problems = @{}; Errors = @(); Presets = @{}; ExtraFields = @() }

    if (-not (Test-Path -LiteralPath $Path)) { $catalog.Errors += "PrinterData.json was not found: $Path"; return $catalog }

    try {
        $data = (Get-Content -LiteralPath $Path -Raw -Encoding UTF8) | ConvertFrom-Json -ErrorAction Stop
    } catch {
        $catalog.Errors += ("PrinterData.json is not valid JSON: {0}" -f $_.Exception.Message)
        return $catalog
    }

    $printers = @(Get-PDBulkRecordValue -Record $data -Name 'printers')
    $drivers  = @(Get-PDBulkRecordValue -Record $data -Name 'drivers')
    if ($printers.Count -eq 0 -or $null -eq $printers[0]) { $catalog.Errors += 'PrinterData.json has no "printers" entries.'; return $catalog }

    $presets = @{}
    foreach ($driver in $drivers) {
        $preset = [string](Get-PDBulkRecordValue -Record $driver -Name 'PresetDriver')
        if (-not [string]::IsNullOrWhiteSpace($preset)) { $presets[$preset.Trim()] = $driver }
    }

    $counts = @{}
    $index = 0
    foreach ($printer in $printers) {
        $index++
        $name = ([string](Get-PDBulkRecordValue -Record $printer -Name 'PrinterName')).Trim()
        if ([string]::IsNullOrWhiteSpace($name)) { $catalog.Errors += "Printer entry #$index has no PrinterName."; continue }
        $key = $name.ToLowerInvariant()
        if ($counts.ContainsKey($key)) { $counts[$key]++ } else { $counts[$key] = 1 }
        if ($counts[$key] -gt 1) { continue }

        $catalog.ByName[$key] = $printer
        $catalog.Printers += $printer

        $problems = @()
        foreach ($field in @('PortName', 'PrinterIP')) {
            if ([string]::IsNullOrWhiteSpace([string](Get-PDBulkRecordValue -Record $printer -Name $field))) { $problems += "no $field" }
        }
        $preset = ([string](Get-PDBulkRecordValue -Record $printer -Name 'PresetDriver')).Trim()
        if (-not [string]::IsNullOrWhiteSpace($preset)) {
            if (-not $presets.ContainsKey($preset)) { $problems += "PresetDriver '$preset' is not in drivers" }
        } else {
            foreach ($field in @('DriverName', 'INFFile', 'DriverZip')) {
                if ([string]::IsNullOrWhiteSpace([string](Get-PDBulkRecordValue -Record $printer -Name $field))) { $problems += "no PresetDriver and no $field" }
            }
        }
        if ($problems.Count -gt 0) { $catalog.Problems[$key] = ($problems -join '; ') }
    }

    foreach ($key in @($counts.Keys | Sort-Object)) {
        if ($counts[$key] -gt 1) {
            $shown = [string](Get-PDBulkRecordValue -Record $catalog.ByName[$key] -Name 'PrinterName')
            $catalog.Errors += ("'{0}' appears {1} times in PrinterData.json; printer names must be unique." -f $shown, $counts[$key])
        }
    }

    $catalog.Printers = @($catalog.Printers | Sort-Object { [string](Get-PDBulkRecordValue -Record $_ -Name 'PrinterName') })
    $catalog.Presets  = $presets

    # Any printer field beyond the known ones still gets a reference column, in first-seen order.
    $known = @('PrinterName') + @($script:PDBulk.ReferenceColumns)
    foreach ($printer in @($catalog.Printers)) {
        foreach ($property in $printer.PSObject.Properties) {
            if ($known -notcontains $property.Name -and $catalog.ExtraFields -notcontains $property.Name) { $catalog.ExtraFields += $property.Name }
        }
    }

    return $catalog
}

function Get-PDPrinterBulkDraftColumns {
    <# The draft's columns for this catalog: the operator's columns, the reference columns, then any extra JSON fields. #>
    param([Parameter(Mandatory = $true)][hashtable]$Catalog)
    return @(@($script:PDBulk.DraftColumns) + @($script:PDBulk.ReferenceColumns) + @($Catalog.ExtraFields))
}

function Get-PDPrinterReferenceValues {
    <#
        .SYNOPSIS
        One printer's reference column values as text, exactly as the sheet shows them.
        DriverName / INFFile / DriverZip are what the installer will use: the PresetDriver's values
        when the printer names a preset that exists (General_IP-Printer_Installer.ps1 prefers it),
        otherwise the printer's own.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Catalog, [Parameter(Mandatory = $true)][object]$Record)

    $values = [ordered]@{}
    foreach ($column in @(@($script:PDBulk.ReferenceColumns) + @($Catalog.ExtraFields))) {
        $value = Get-PDBulkRecordValue -Record $Record -Name $column
        if ($null -eq $value) { $values[$column] = '' }
        elseif ($value -is [string]) { $values[$column] = $value.Trim() }
        elseif ($value -is [System.Array] -or $value -is [System.Management.Automation.PSCustomObject]) { $values[$column] = ($value | ConvertTo-Json -Compress -Depth 5) }
        else { $values[$column] = [string]$value }
    }

    $preset = ([string](Get-PDBulkRecordValue -Record $Record -Name 'PresetDriver')).Trim()
    if (-not [string]::IsNullOrWhiteSpace($preset) -and $Catalog.Presets.ContainsKey($preset)) {
        foreach ($field in @('DriverName', 'INFFile', 'DriverZip')) {
            $values[$field] = ([string](Get-PDBulkRecordValue -Record $Catalog.Presets[$preset] -Name $field)).Trim()
        }
    }

    return $values
}

# ---------------------------------------------------------------------------
# Intune: list, back up, delete
# ---------------------------------------------------------------------------

function Get-PDIntunePrinterApps {
    <#
        .SYNOPSIS
        Every Intune app whose display name is one Setup would give a printer, all deploy modes.

        .DESCRIPTION
        startswith() is the query Find-PDIntuneDuplicateApps already relies on for bracketed
        development names (an eq filter never matches a name containing [ or ]). The parse below,
        not the query, decides what counts as a printer.

        .OUTPUTS
        { AppId; DisplayName; PrinterName; Department; DeployMode; Version; Created } sorted by
        PrinterName, then DeployMode.
    #>
    param(
        [AllowNull()][object]$AuthContext,
        [string]$Stage = 'ListPrinters'
    )

    $query = @{
        '$filter' = 'startswith(displayName,' + (ConvertTo-PDODataStringLiteral -Value $script:PDBulk.DisplayNamePrefix) + ')'
        '$select' = 'id,displayName,createdDateTime'
    }
    $path  = New-PDGraphQueryPath -Path ([string]$script:PDGraph.MobileAppsPath) -Query $query
    $items = Get-PDGraphCollection -Path $path -AuthContext $AuthContext -Stage $Stage -Description 'printer app list'

    $apps = @()
    foreach ($item in (Get-PDGraphItems -Payload $items)) {
        $id   = [string](Get-PDGraphPropertyValue -Object $item -Name 'id')
        $name = [string](Get-PDGraphPropertyValue -Object $item -Name 'displayName')
        if ([string]::IsNullOrWhiteSpace($id)) { continue }

        $parsed = ConvertFrom-PDPrinterIntuneDisplayName -DisplayName $name
        if (-not $parsed.IsPrinter) { continue }

        $created = Get-PDGraphPropertyValue -Object $item -Name 'createdDateTime'
        $createdText = ''
        if ($null -ne $created -and -not [string]::IsNullOrWhiteSpace([string]$created)) {
            $parsedDate = [System.DateTimeOffset]::MinValue
            if ($created -is [DateTime]) { $createdText = $created.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) }
            elseif ([System.DateTimeOffset]::TryParse([string]$created, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsedDate)) {
                $createdText = $parsedDate.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
            } else { $createdText = [string]$created }
        }

        $apps += [pscustomobject]@{
            AppId       = $id
            DisplayName = $name
            PrinterName = $parsed.PrinterName
            Department  = $parsed.Department
            DeployMode  = $parsed.DeployMode
            Version     = $parsed.Version
            Created     = $createdText
        }
    }

    return @($apps | Sort-Object PrinterName, DeployMode, DisplayName)
}

function Backup-PDIntuneApp {
    <#
        .SYNOPSIS
        Saves an app and its assignments to <Folder>\<AppId>.json before it is deleted. Throws when
        either read fails, and the callers never delete an app whose backup did not succeed.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$AppId,
        [Parameter(Mandatory = $true)][string]$Folder,
        [AllowNull()][object]$AuthContext,
        [string]$Stage = 'Backup'
    )

    $appPath = [string]$script:PDGraph.MobileAppsPath + '/' + [System.Uri]::EscapeDataString($AppId)
    $app         = Invoke-PDGraphRequest -Method Get -Uri $appPath -AuthContext $AuthContext -RetryMode 'Read' -Stage $Stage -Description ('read app ' + $AppId)
    $assignments = Get-PDGraphCollection -Path ($appPath + '/assignments') -AuthContext $AuthContext -Stage $Stage -Description ('read assignments of ' + $AppId)

    if (-not (Test-Path -LiteralPath $Folder)) { New-Item -ItemType Directory -Path $Folder -Force | Out-Null }

    $backup = [ordered]@{
        BackedUpAt  = [System.DateTimeOffset]::Now.ToString('yyyy-MM-ddTHH:mm:sszzz', [System.Globalization.CultureInfo]::InvariantCulture)
        AppId       = $AppId
        App         = $app
        Assignments = @($assignments)
    }

    $file = Join-Path $Folder ($AppId + '.json')
    [System.IO.File]::WriteAllText($file, ($backup | ConvertTo-Json -Depth 40), (New-Object System.Text.UTF8Encoding($false)))
    return $file
}

function Remove-PDIntuneApp {
    <#
        .SYNOPSIS
        Deletes one app. An app that is already gone (404) counts as deleted.
        .OUTPUTS
        'Deleted' or 'AlreadyGone'. Throws on any other failure.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$AppId,
        [AllowNull()][object]$AuthContext,
        [string]$Stage = 'Delete'
    )

    $appPath = [string]$script:PDGraph.MobileAppsPath + '/' + [System.Uri]::EscapeDataString($AppId)
    try {
        $null = Invoke-PDGraphRequest -Method Delete -Uri $appPath -AuthContext $AuthContext -RetryMode 'Write' -Stage $Stage -Description ('delete app ' + $AppId)
        return 'Deleted'
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        if ($info.Status -eq 404) { return 'AlreadyGone' }
        throw
    }
}

function Remove-PDIntuneAppWithBackup {
    <#
        .SYNOPSIS
        Backup, then delete. Never throws.
        .OUTPUTS
        { Result = Deleted | AlreadyGone | BackupFailed | DeleteFailed; BackupFile; Error }
    #>
    param(
        [Parameter(Mandatory = $true)][string]$AppId,
        [Parameter(Mandatory = $true)][string]$BackupFolder,
        [AllowNull()][object]$AuthContext
    )

    $outcome = [pscustomobject]@{ Result = ''; BackupFile = ''; Error = '' }

    try {
        $outcome.BackupFile = Backup-PDIntuneApp -AppId $AppId -Folder $BackupFolder -AuthContext $AuthContext
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        if ($info.Status -eq 404) { $outcome.Result = 'AlreadyGone'; return $outcome }
        $outcome.Result = 'BackupFailed'
        $outcome.Error  = ('Backup failed, so the app was NOT deleted: {0}' -f $info.Message)
        return $outcome
    }

    try {
        $outcome.Result = Remove-PDIntuneApp -AppId $AppId -AuthContext $AuthContext
    } catch {
        $info = Get-PDGraphErrorInfo -ErrorRecord $_
        $outcome.Result = 'DeleteFailed'
        $outcome.Error  = ('Delete failed: {0}' -f $info.Message)
    }

    return $outcome
}

# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

function Resolve-PDBulkGroups {
    <#
        .SYNOPSIS
        Resolves every distinct group term in the included rows ONCE, and reports every problem at
        once instead of stopping at the first (a 150-row sheet should need one round of fixes).

        .OUTPUTS
        { Map = lower-cased term -> { Id; DisplayName }; Errors = @() }
    #>
    param(
        [AllowEmptyCollection()][object[]]$Rows,
        [AllowNull()][object]$AuthContext,
        [string]$Stage = 'Groups'
    )

    $result = @{ Map = @{}; Errors = @() }
    $usedBy = [ordered]@{}

    foreach ($row in @($Rows)) {
        foreach ($column in @('RequiredGroups', 'AvailableGroups')) {
            foreach ($term in (Get-PDBulkGroupTerms -Cell (Get-PDBulkCell -Row $row -Name $column))) {
                $key = $term.ToLowerInvariant()
                if (-not $usedBy.Contains($key)) { $usedBy[$key] = @{ Term = $term; Rows = @() } }
                # Row number for Excel users, printer name for the built-in editor (which has no row numbers).
                $where = [string](Get-PDBulkCell -Row $row -Name 'RowNumber')
                $printerName = Get-PDBulkCell -Row $row -Name 'PrinterName'
                if (-not [string]::IsNullOrWhiteSpace($printerName)) { $where = ('{0}: {1}' -f $where, $printerName) }
                $usedBy[$key].Rows += $where
            }
        }
    }

    foreach ($key in @($usedBy.Keys)) {
        $term = [string]$usedBy[$key].Term
        try {
            $builtIn = Get-PDBuiltInAssignmentTarget -Term $term -Stage $Stage
            if ($null -ne $builtIn) {
                $result.Map[$key] = [pscustomobject]@{ Id = [string]$builtIn.Id; DisplayName = [string]$builtIn.DisplayName }
            } else {
                $group = Resolve-PDGraphGroup -Query $term -AuthContext $AuthContext -Stage $Stage
                $result.Map[$key] = [pscustomobject]@{ Id = [string]$group.Id; DisplayName = [string]$group.DisplayName }
            }
        } catch {
            $info = Get-PDGraphErrorInfo -ErrorRecord $_
            $where = @($usedBy[$key].Rows | Select-Object -Unique)
            $rowsText = (@($where | Select-Object -First 5) -join ', ')
            if ($where.Count -gt 5) { $rowsText += (' and {0} more' -f ($where.Count - 5)) }
            $label = 'row'
            if ($where.Count -gt 1) { $label = 'rows' }
            $result.Errors += ("Group '{0}' (CSV {1} {2}): {3}" -f $term, $label, $rowsText, $info.Message)
        }
    }

    return $result
}

function Get-PDBulkRowGroupIds {
    <#
        .SYNOPSIS
        One row's resolved Required/Available ids. The same group under both intents is an error,
        exactly as the uploader would report it (Resolve-PDGraphGroups).
        .OUTPUTS
        { Required = string[]; Available = string[]; Error = '' }
    #>
    param([Parameter(Mandatory = $true)][object]$Row, [Parameter(Mandatory = $true)][hashtable]$GroupMap)

    $out = [pscustomobject]@{ Required = @(); Available = @(); Error = '' }
    $seen = @{}

    foreach ($pair in @(@{ Column = 'RequiredGroups'; Intent = 'Required' }, @{ Column = 'AvailableGroups'; Intent = 'Available' })) {
        $ids = @()
        foreach ($term in (Get-PDBulkGroupTerms -Cell (Get-PDBulkCell -Row $Row -Name $pair.Column))) {
            $entry = $GroupMap[$term.ToLowerInvariant()]
            if ($null -eq $entry) { continue }
            $idKey = ([string]$entry.Id).ToLowerInvariant()
            if ($seen.ContainsKey($idKey) -and $seen[$idKey] -ne $pair.Intent) {
                $out.Error = ("'{0}' is in both RequiredGroups and AvailableGroups. Choose one." -f $entry.DisplayName)
            }
            $seen[$idKey] = $pair.Intent
            if ($ids -notcontains [string]$entry.Id) { $ids += [string]$entry.Id }
        }
        if ($pair.Intent -eq 'Required') { $out.Required = $ids } else { $out.Available = $ids }
    }

    return $out
}

# ---------------------------------------------------------------------------
# Bulk create
# ---------------------------------------------------------------------------

function New-PDPrinterBulkDraft {
    <#
        .SYNOPSIS
        One draft row per printer in the catalog, with every PrinterData.json field as a reference
        column (Get-PDPrinterBulkDraftColumns). Printers that would fail to install always start with
        Include = N and say why in Problem; the rest start ticked, or all unticked with
        -IncludeByDefault $false (handy for picking a few printers out of many).
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Catalog,
        [AllowNull()][string]$DeployMode,
        [AllowNull()][string]$SourceCommit,
        [AllowEmptyCollection()][string[]]$DefaultRequiredGroups = @(),
        [AllowEmptyCollection()][string[]]$DefaultAvailableGroups = @(),
        [bool]$IncludeByDefault = $true
    )

    $rows = @()
    foreach ($record in @($Catalog.Printers)) {
        $name    = ([string](Get-PDBulkRecordValue -Record $record -Name 'PrinterName')).Trim()
        $problem = [string]$Catalog.Problems[$name.ToLowerInvariant()]
        $dept    = Get-PDBulkRecordValue -Record $record -Name 'Department'

        $row = [ordered]@{
            Include           = $(if ([string]::IsNullOrWhiteSpace($problem) -and $IncludeByDefault) { 'Y' } else { 'N' })
            PrinterName       = $name
            IntuneDisplayName = (Get-PDPrinterIntuneDisplayName -PrinterName $name -Department $dept -DeployMode $DeployMode -SourceCommit $SourceCommit)
            RequiredGroups    = (@($DefaultRequiredGroups) -join '; ')
            AvailableGroups   = (@($DefaultAvailableGroups) -join '; ')
            Problem           = $problem
        }
        $reference = Get-PDPrinterReferenceValues -Catalog $Catalog -Record $record
        foreach ($column in $reference.Keys) { $row[$column] = $reference[$column] }

        $rows += [pscustomobject]$row
    }
    return $rows
}

function Resolve-PDPrinterBulkStage {
    <#
        .SYNOPSIS
        Checks the edited draft and finds the printers that already exist.

        .DESCRIPTION
        Only rows marked Include are staged. Everything is checked against the CATALOG, never the
        CSV's own context columns: PrinterName is the key and is not editable, and a printer the
        draft flagged (Problem) cannot be forced in by changing Include.

        "Already exists" = an Intune printer app with the same PrinterName (case-insensitive) AND
        the same deploy mode (decision D1). Same-name apps in other modes are listed only as
        information and are never touched.

        .OUTPUTS
        { Rows = staged rows (Action Create or Conflict, Matches, OtherModeMatches, GroupIds);
          Errors = problems that must be fixed in the CSV before anything runs; Excluded = count;
          Warnings = reference cells edited in the sheet (ignored: details come from the JSON) }
    #>
    param(
        [AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory = $true)][hashtable]$Catalog,
        [AllowEmptyCollection()][object[]]$ExistingApps,
        [Parameter(Mandatory = $true)][hashtable]$GroupMap,
        [AllowNull()][string]$DeployMode,
        [AllowNull()][string]$SourceCommit
    )

    $stage = @{ Rows = @(); Errors = @(); Excluded = 0; Warnings = @() }
    $seenNames = @{}

    foreach ($row in @($Rows)) {
        $rowNumber = Get-PDBulkCell -Row $row -Name 'RowNumber'
        $name      = Get-PDBulkCell -Row $row -Name 'PrinterName'

        if (-not (Test-PDBulkYes -Value (Get-PDBulkCell -Row $row -Name 'Include'))) { $stage.Excluded++; continue }

        if ([string]::IsNullOrWhiteSpace($name)) { $stage.Errors += "Row ${rowNumber}: Include is set but PrinterName is empty."; continue }

        $key = $name.ToLowerInvariant()
        if ($seenNames.ContainsKey($key)) { $stage.Errors += ("Row {0}: '{1}' is already on row {2}." -f $rowNumber, $name, $seenNames[$key]); continue }
        $seenNames[$key] = $rowNumber

        $record = $Catalog.ByName[$key]
        if ($null -eq $record) { $stage.Errors += ("Row {0}: '{1}' is not in PrinterData.json. PrinterName cannot be edited in the CSV." -f $rowNumber, $name); continue }

        $problem = [string]$Catalog.Problems[$key]
        if (-not [string]::IsNullOrWhiteSpace($problem)) { $stage.Errors += ("Row {0}: '{1}' would fail to install ({2}). Fix PrinterData.json or set Include to N." -f $rowNumber, $name, $problem); continue }

        $groupIds = Get-PDBulkRowGroupIds -Row $row -GroupMap $GroupMap
        if (-not [string]::IsNullOrWhiteSpace($groupIds.Error)) { $stage.Errors += ("Row {0}: {1}" -f $rowNumber, $groupIds.Error); continue }

        $canonicalName = ([string](Get-PDBulkRecordValue -Record $record -Name 'PrinterName')).Trim()
        $sameName  = @(@($ExistingApps) | Where-Object { ([string]$_.PrinterName) -ieq $canonicalName })
        $sameMode  = @($sameName | Where-Object { ([string]$_.DeployMode) -ieq $DeployMode })
        $otherMode = @($sameName | Where-Object { ([string]$_.DeployMode) -ine $DeployMode })

        $dept = Get-PDBulkRecordValue -Record $record -Name 'Department'

        # A reference cell that no longer matches the JSON was edited (by hand, or reformatted by a
        # spreadsheet program). It changes nothing; say so, so nobody thinks an IP was changed here.
        $reference = Get-PDPrinterReferenceValues -Catalog $Catalog -Record $record
        foreach ($column in $reference.Keys) {
            if ($null -eq $row.PSObject.Properties[$column]) { continue }
            $sheetValue = Get-PDBulkCell -Row $row -Name $column
            if ($sheetValue -cne [string]$reference[$column]) {
                $stage.Warnings += ("Row {0} ({1}): {2} is '{3}' in the sheet but '{4}' in PrinterData.json." -f $rowNumber, $canonicalName, $column, $sheetValue, $reference[$column])
            }
        }

        $stage.Rows += [pscustomobject]@{
            RowNumber            = $rowNumber
            Include              = 'Y'
            PrinterName          = $canonicalName
            IntuneDisplayName    = (Get-PDPrinterIntuneDisplayName -PrinterName $canonicalName -Department $dept -DeployMode $DeployMode -SourceCommit $SourceCommit)
            RequiredGroups       = (Get-PDBulkCell -Row $row -Name 'RequiredGroups')
            AvailableGroups      = (Get-PDBulkCell -Row $row -Name 'AvailableGroups')
            Department           = [string]$reference['Department']
            Location             = [string]$reference['Location']
            PrinterIP            = [string]$reference['PrinterIP']
            Problem              = ''
            Action               = $(if ($sameMode.Count -gt 0) { 'Conflict' } else { 'Create' })
            ExistingAppIds       = (@($sameMode | ForEach-Object { $_.AppId }) -join '; ')
            ExistingDisplayNames = (@($sameMode | ForEach-Object { $_.DisplayName }) -join '; ')
            Matches              = $sameMode
            OtherModeMatches     = $otherMode
            RequiredIds          = @($groupIds.Required)
            AvailableIds         = @($groupIds.Available)
        }
    }

    return $stage
}

function Invoke-PDPrinterBulkCreate {
    <#
        .SYNOPSIS
        Creates every staged printer whose Action is Create or Override, one at a time. Never throws;
        one printer failing never stops the batch.

        .DESCRIPTION
        Per printer:
          1. New-PDPrinterIntuneMetadata (the same builder the wizard uses).
          2. Invoke-PDIntuneUpload with the group ids resolved at staging. -AllowDuplicateName only
             for Override rows, whose old app may carry the same name.
          3. Override rows only, and ONLY after step 2 reported Success: back up, then delete, each
             old app. If the create failed, the old app is never touched.

        .PARAMETER Context
        Hashtable: RepoUrl, RepoNickName, RepoBranch, TargetWorkingDirectory, DeployMode, RepoRoot,
        IconPath, GenerateInstallCommandPath, IntuneWinPath, BackupFolder, CredentialPath.

        .PARAMETER OnProgress
        Called as (Index, Total, StagedRow, ResultRow) after each printer.

        .OUTPUTS
        Result rows (columns $script:PDBulk.ResultColumns). Include is N for printers that are done
        and Y for the ones that are not, so the results CSV can be fed straight back in as a retry.
    #>
    param(
        [AllowEmptyCollection()][object[]]$StagedRows,
        [Parameter(Mandatory = $true)][hashtable]$Catalog,
        [Parameter(Mandatory = $true)][hashtable]$Context,
        [AllowNull()][object]$AuthContext,
        [AllowNull()][scriptblock]$OnProgress,
        [AllowNull()][scriptblock]$Log
    )

    $results = @()
    $work = @(@($StagedRows) | Where-Object { @('Create', 'Override') -contains [string]$_.Action })
    $total = $work.Count
    $index = 0

    foreach ($row in @($StagedRows)) {
        $result = [ordered]@{}
        foreach ($column in $script:PDBulk.ResultColumns) { $result[$column] = Get-PDBulkCell -Row $row -Name $column }
        $result['Action'] = [string]$row.Action

        if (@('Create', 'Override') -notcontains [string]$row.Action) {
            $result['Include'] = 'N'
            $result['Result']  = 'Skipped'
            $results += [pscustomobject]$result
            continue
        }

        $index++
        $result['Include'] = 'Y'
        $record = $Catalog.ByName[([string]$row.PrinterName).ToLowerInvariant()]

        try {
            # 6>$null: the generator narrates every step with Write-Host, which would bury the
            # one progress line per printer. Its own log files still get every line.
            $build = New-PDPrinterIntuneMetadata -PrinterName ([string]$row.PrinterName) `
                -Department (Get-PDBulkRecordValue -Record $record -Name 'Department') `
                -Location   (Get-PDBulkRecordValue -Record $record -Name 'Location') `
                -Model      (Get-PDBulkRecordValue -Record $record -Name 'Model') `
                -Asset      (Get-PDBulkRecordValue -Record $record -Name 'Asset') `
                -PrinterIP  (Get-PDBulkRecordValue -Record $record -Name 'PrinterIP') `
                -Verified   (Get-PDBulkRecordValue -Record $record -Name 'Verified') `
                -Publisher  (Get-PDBulkRecordValue -Record $record -Name 'Publisher') `
                -IntuneWinPath ([string]$Context.IntuneWinPath) -RepoUrl ([string]$Context.RepoUrl) `
                -RepoNickName ([string]$Context.RepoNickName) -RepoBranch ([string]$Context.RepoBranch) `
                -TargetWorkingDirectory ([string]$Context.TargetWorkingDirectory) -DeployMode ([string]$Context.DeployMode) `
                -RepoRoot ([string]$Context.RepoRoot) -IconPath ([string]$Context.IconPath) `
                -GenerateInstallCommandPath ([string]$Context.GenerateInstallCommandPath) -Log $Log 6>$null
        } catch {
            $result['Result'] = 'Failed'
            $result['Error']  = ('Building the commands failed: {0}' -f $_.Exception.Message)
            $results += [pscustomobject]$result
            if ($null -ne $OnProgress) { $null = & $OnProgress $index $total $row ([pscustomobject]$result) }
            continue
        }

        $meta = $build.Metadata
        $result['IntuneDisplayName'] = [string]$meta.DisplayName

        $upload = $null
        try {
            $upload = Invoke-PDIntuneUpload -IntuneWinPath ([string]$meta.IntuneWinPath) -DisplayName ([string]$meta.DisplayName) `
                -Description ([string]$meta.Description) -Publisher ([string]$meta.Publisher) `
                -InstallCommandFile ([string]$meta.InstallCommandFile) -UninstallCommandFile ([string]$meta.UninstallCommandFile) `
                -DetectionScriptFile ([string]$meta.DetectionScriptFile) -AppVersion ([string]$meta.AppVersion) `
                -Category ([string]$meta.Category) -Notes ([string]$meta.Notes) `
                -AllowAvailableUninstall ([bool]$meta.AllowAvailableUninstall) -IconFile ([string]$meta.IconFile) `
                -RequiredGroups ([string[]]@($row.RequiredIds)) -AvailableGroups ([string[]]@($row.AvailableIds)) `
                -CredentialPath ([string]$Context.CredentialPath) `
                -AllowDuplicateName:([string]$row.Action -eq 'Override')
        } catch {
            $upload = [pscustomobject]@{ Success = $false; Stage = 'Upload'; Message = $_.Exception.Message; CleanupStatus = 'Unknown'; AppId = $null }
        }

        if ($null -eq $upload -or -not $upload.Success) {
            $message = '(the uploader returned nothing; check Intune for this printer before retrying)'
            if ($null -ne $upload) {
                $message = ('stage {0}: {1}' -f $upload.Stage, $upload.Message)
                $cleanup = [string]$upload.CleanupStatus
                if ($cleanup -ne 'Deleted' -and $cleanup -ne 'NotNeeded' -and -not [string]::IsNullOrWhiteSpace([string]$upload.AppId)) {
                    $message += (' An incomplete app was left in Intune: {0}.' -f $upload.AppId)
                }
            }
            if ([string]$row.Action -eq 'Override') { $message += ' The existing app was not touched.' }
            $result['Result'] = 'Failed'
            $result['Error']  = $message
            $results += [pscustomobject]$result
            if ($null -ne $OnProgress) { $null = & $OnProgress $index $total $row ([pscustomobject]$result) }
            continue
        }

        $result['NewAppId'] = [string]$upload.AppId
        $result['Result']   = 'Created'
        $result['Include']  = 'N'

        if ([string]$row.Action -eq 'Override') {
            $deleted = @(); $backups = @(); $problems = @()
            foreach ($old in @($row.Matches)) {
                $oldId = [string]$old.AppId
                if ([string]::IsNullOrWhiteSpace($oldId) -or $oldId -eq [string]$upload.AppId) { continue }
                $outcome = Remove-PDIntuneAppWithBackup -AppId $oldId -BackupFolder ([string]$Context.BackupFolder) -AuthContext $AuthContext
                if ($outcome.BackupFile) { $backups += $outcome.BackupFile }
                if (@('Deleted', 'AlreadyGone') -contains $outcome.Result) { $deleted += $oldId }
                else { $problems += ('{0}: {1}' -f $oldId, $outcome.Error) }
            }
            $result['DeletedAppIds'] = ($deleted -join '; ')
            $result['BackupFiles']   = ($backups -join '; ')
            if ($problems.Count -gt 0) {
                # The new printer exists; only the cleanup of the old one is left (the delete tool can finish it).
                $result['Result'] = 'CreatedOldNotDeleted'
                $result['Error']  = ('The new app was created, but the old app was not removed: ' + ($problems -join ' | '))
            } else {
                $result['Result'] = 'Overridden'
            }
        }

        $results += [pscustomobject]$result
        if ($null -ne $OnProgress) { $null = & $OnProgress $index $total $row ([pscustomobject]$result) }
    }

    return $results
}

# ---------------------------------------------------------------------------
# Bulk delete
# ---------------------------------------------------------------------------

function New-PDPrinterDeleteSheet {
    <# One row per printer app, Delete blank. #>
    param([AllowEmptyCollection()][object[]]$Apps)

    $rows = @()
    foreach ($app in @($Apps)) {
        $rows += [pscustomobject]@{
            Delete      = ''
            DisplayName = [string]$app.DisplayName
            PrinterName = [string]$app.PrinterName
            DeployMode  = [string]$app.DeployMode
            Version     = [string]$app.Version
            Created     = [string]$app.Created
            AppId       = [string]$app.AppId
        }
    }
    return $rows
}

function Resolve-PDPrinterDeleteSelection {
    <#
        .SYNOPSIS
        The rows marked Delete, matched to a FRESH list of printer apps by AppId only (never by name:
        two apps can share a name, and a name in the sheet may have been edited).

        .OUTPUTS
        { Selected = current app objects to delete; Gone = marked AppIds no longer in Intune;
          Errors = marked rows without a usable AppId }
    #>
    param(
        [AllowEmptyCollection()][object[]]$Rows,
        [AllowEmptyCollection()][object[]]$CurrentApps
    )

    $byId = @{}
    foreach ($app in @($CurrentApps)) { $byId[([string]$app.AppId).ToLowerInvariant()] = $app }

    $selection = @{ Selected = @(); Gone = @(); Errors = @() }
    $seen = @{}

    foreach ($row in @($Rows)) {
        if (-not (Test-PDBulkYes -Value (Get-PDBulkCell -Row $row -Name 'Delete'))) { continue }
        $id = Get-PDBulkCell -Row $row -Name 'AppId'
        $rowNumber = Get-PDBulkCell -Row $row -Name 'RowNumber'
        if ([string]::IsNullOrWhiteSpace($id)) { $selection.Errors += "Row ${rowNumber}: marked for deletion but AppId is empty."; continue }

        $key = $id.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        if ($byId.ContainsKey($key)) { $selection.Selected += $byId[$key] }
        else { $selection.Gone += [pscustomobject]@{ AppId = $id; DisplayName = (Get-PDBulkCell -Row $row -Name 'DisplayName') } }
    }

    return $selection
}

function Invoke-PDPrinterBulkDelete {
    <#
        .SYNOPSIS
        Backs up and deletes each selected app. Never throws; a failure on one app never stops the rest.
        .OUTPUTS
        Result rows (columns $script:PDBulk.DeleteResultColumns).
    #>
    param(
        [AllowEmptyCollection()][object[]]$Apps,
        [Parameter(Mandatory = $true)][string]$BackupFolder,
        [AllowNull()][object]$AuthContext,
        [AllowNull()][scriptblock]$OnProgress
    )

    $results = @()
    $total = @($Apps).Count
    $index = 0

    foreach ($app in @($Apps)) {
        $index++
        $outcome = Remove-PDIntuneAppWithBackup -AppId ([string]$app.AppId) -BackupFolder $BackupFolder -AuthContext $AuthContext

        $row = [pscustomobject]@{
            DisplayName = [string]$app.DisplayName
            PrinterName = [string]$app.PrinterName
            DeployMode  = [string]$app.DeployMode
            AppId       = [string]$app.AppId
            Result      = [string]$outcome.Result
            BackupFile  = [string]$outcome.BackupFile
            Error       = [string]$outcome.Error
        }
        $results += $row
        if ($null -ne $OnProgress) { $null = & $OnProgress $index $total $row }
    }

    return $results
}
