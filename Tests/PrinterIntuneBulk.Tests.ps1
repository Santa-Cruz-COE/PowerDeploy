<#

.SYNOPSIS
    Offline behavioural tests for the bulk printer tools and the shared printer builders.

.DESCRIPTION
    Same dependency-free harness as Tests\IntuneGraphUpload.Tests.ps1. Every Graph call goes through
    the helper library's TestTransport seam, so nothing here reaches Microsoft; the uploader and the
    command generator are replaced by recording stubs where a case needs them.

        powershell -NoProfile -ExecutionPolicy Bypass -File Tests\PrinterIntuneBulk.Tests.ps1
        pwsh       -NoProfile -ExecutionPolicy Bypass -File Tests\PrinterIntuneBulk.Tests.ps1

    Exit code 0 = every case passed.

    The old-vs-new equivalence proof for moving the builders out of Setup.ps1 (plan 6.1 items 1-2)
    ran once against HEAD c63243c and is recorded in the build plan; it needs a HEAD copy of
    Setup.ps1 and generates real command files, so it is not part of this offline suite.

.LINK
    .claude/plans/printer-bulk-tools.buildplan.md section 6.1

#>

[CmdletBinding()]
param([switch]$KeepTemp)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

$script:Cases    = @()
$script:Passed   = 0
$script:Failures = @()

function Add-TestCase {
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][scriptblock]$Body)
    $script:Cases += @{ Id = $Id; Name = $Name; Body = $Body }
}

function Assert-True {
    param([object]$Condition, [string]$Message)
    if (-not $Condition) { throw "Expected true: $Message" }
}

function Assert-Equal {
    param([object]$Expected, [object]$Actual, [string]$Message)
    if ($Expected -cne $Actual) { throw "Expected '$Expected' but got '$Actual'. $Message" }
}

function Assert-Like {
    param([string]$Pattern, [object]$Actual, [string]$Message)
    if (([string]$Actual) -notlike $Pattern) { throw "Expected '$Pattern' to match '$Actual'. $Message" }
}

function Assert-Throws {
    param([Parameter(Mandatory = $true)][scriptblock]$Body, [string]$MessagePattern, [string]$Message)
    $caught = $null
    try { & $Body | Out-Null } catch { $caught = $_ }
    if ($null -eq $caught) { throw "Expected a terminating error but none was thrown. $Message" }
    if ($MessagePattern -and (([string]$caught.Exception.Message) -notlike $MessagePattern)) {
        throw "Error message '$($caught.Exception.Message)' did not match '$MessagePattern'. $Message"
    }
    return $caught
}

# ---------------------------------------------------------------------------
# Load the code under test (same order as Setup.ps1)
# ---------------------------------------------------------------------------

$repoRoot     = Split-Path $PSScriptRoot -Parent
$graphPath    = Join-Path $repoRoot 'Other_Tools\InTune-GraphAPI_Helpers.ps1'
$uploaderPath = Join-Path $repoRoot 'Other_Tools\Upload-InTuneWin32App.ps1'
$printerPath  = Join-Path $repoRoot 'Other_Tools\Printer-Intune_Helpers.ps1'
$bulkPath     = Join-Path $repoRoot 'Other_Tools\Printer-IntuneBulk.ps1'
$gridPath     = Join-Path $repoRoot 'Other_Tools\CsvGrid-Editor_Helpers.ps1'
$setupPath    = Join-Path $repoRoot 'Setup.ps1'

foreach ($path in @($graphPath, $uploaderPath, $printerPath, $bulkPath, $gridPath, $setupPath)) {
    if (-not (Test-Path -LiteralPath $path)) { Write-Host "FATAL: $path not found"; exit 2 }
}

$script:TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('PowerDeploy-BulkTests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null

Write-Host "================================================================"
Write-Host " PrinterIntuneBulk tests"
Write-Host " Engine : PowerShell $($PSVersionTable.PSVersion)"
Write-Host " Temp   : $script:TempRoot"
Write-Host "================================================================"
Write-Host ""

# Import purity is checked before the real import, in a throwaway scope.
$script:ImportOutput = & {
    . $graphPath
    . $printerPath
    . $bulkPath
    . $gridPath
}

. $graphPath
. $uploaderPath
. $printerPath
. $bulkPath
. $gridPath

# A read that fails must fail once, not sleep through five retries.
$script:PDGraph.MaxAttempts = 1

$script:FakeAuth = @{ AccessToken = 'fake-token-never-real' }

# ---------------------------------------------------------------------------
# Mock Graph
# ---------------------------------------------------------------------------

$script:Calls  = @()
$script:Router = $null

$script:Tripwire = {
    param($Request)
    throw ("this case did not install a mock; refusing {0} {1}" -f $Request.Method, $Request.Uri)
}

function New-MockResponse {
    param([int]$Status = 200, [AllowNull()][object]$Body = $null)
    $text = ''
    if ($null -ne $Body) { if ($Body -is [string]) { $text = $Body } else { $text = ($Body | ConvertTo-Json -Depth 20 -Compress) } }
    return @{ StatusCode = $Status; Body = $text; Headers = @{ 'request-id' = 'mock-req' }; TransportError = $null }
}

function Set-MockGraph {
    param([Parameter(Mandatory = $true)][scriptblock]$Router)
    $script:Router = $Router
    $script:Calls  = @()
    $script:PDGraph.TestTransport = {
        param($Request)
        $decoded = [System.Uri]::UnescapeDataString([string]$Request.Uri)
        $script:Calls += [pscustomobject]@{ Method = [string]$Request.Method; Uri = $decoded }
        $answer = & $script:Router $Request.Method $decoded
        if ($null -eq $answer) { throw ("mock has no answer for {0} {1}" -f $Request.Method, $decoded) }
        return $answer
    }
}

function Get-MockCalls { param([string]$Method) return @($script:Calls | Where-Object { -not $Method -or $_.Method -eq $Method }) }

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

function New-TestJsonFile {
    param([Parameter(Mandatory = $true)][string]$Json, [string]$Name = 'PrinterData.json')
    $path = Join-Path $script:TempRoot ([guid]::NewGuid().ToString('N') + '-' + $Name)
    [System.IO.File]::WriteAllText($path, $Json, (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

$script:GoodJson = @'
{
  "printers": [
    { "PrinterName": "Zulu-Copier", "PortName": "010.000.000.009", "PrinterIP": "10.0.0.9", "PresetDriver": "HP", "Floor": "2" },
    { "PrinterName": "Alpha-Lobby", "PortName": "010.000.000.001", "PrinterIP": "10.0.0.1", "PresetDriver": "HP", "Department": "Facilities", "Location": "Bldg A" },
    { "PrinterName": "Bravo-Old",   "PortName": "010.000.000.002", "PrinterIP": "10.0.0.2", "PresetDriver": "GONE" },
    { "PrinterName": "Charlie-Own", "PortName": "010.000.000.003", "PrinterIP": "10.0.0.3", "DriverName": "Own", "INFFile": "own.inf", "DriverZip": "printers/Drivers/own.zip" },
    { "PrinterName": "Delta-NoIP",  "PortName": "010.000.000.004", "PresetDriver": "HP" }
  ],
  "drivers": [
    { "PresetDriver": "HP", "DriverName": "HP Universal Printing PCL 6", "INFFile": "hpcu345u.inf", "DriverZip": "printers/Drivers/HP/upd.zip" }
  ]
}
'@

function New-StageRow {
    param([string]$Include = 'Y', [string]$Name, [string]$Required = '', [string]$Available = '', [int]$Row = 2)
    return [pscustomobject]@{ RowNumber = $Row; Include = $Include; PrinterName = $Name; RequiredGroups = $Required; AvailableGroups = $Available }
}

function New-ExistingApp {
    param([string]$Id, [string]$Name, [string]$Mode = 'PRODUCTION', [string]$Dept = '')
    $display = Get-PDPrinterIntuneDisplayName -PrinterName $Name -Department $Dept -DeployMode $Mode -SourceCommit 'abc1234'
    $parsed  = ConvertFrom-PDPrinterIntuneDisplayName -DisplayName $display
    return [pscustomobject]@{ AppId = $Id; DisplayName = $display; PrinterName = $parsed.PrinterName; Department = $parsed.Department; DeployMode = $parsed.DeployMode; Version = $parsed.Version; Created = '' }
}

# ---------------------------------------------------------------------------
# Import and Setup.ps1 structure
# ---------------------------------------------------------------------------

Add-TestCase 'B01' 'dot-sourcing the printer helpers and the bulk tools is silent' {
    Assert-True ($null -eq $script:ImportOutput -or @($script:ImportOutput).Count -eq 0) "import must emit nothing (got: $script:ImportOutput)"
    foreach ($name in @('Test-IntuneFieldMissing', 'ConvertTo-IntuneFieldText', 'Get-IntuneDisplayUrl', 'New-IntunePrinterDescription',
                        'New-IntuneTechnicalNotes', 'Get-PDPrinterSourceCommit', 'Get-PDPrinterIntuneDisplayName',
                        'ConvertFrom-PDPrinterIntuneDisplayName', 'New-PDPrinterIntuneMetadata',
                        'Get-PDPrinterJsonCatalog', 'New-PDPrinterBulkDraft', 'Resolve-PDPrinterBulkStage', 'Invoke-PDPrinterBulkCreate',
                        'Get-PDIntunePrinterApps', 'Resolve-PDPrinterDeleteSelection', 'Invoke-PDPrinterBulkDelete',
                        'Read-PDBulkCsv', 'Write-PDBulkCsv', 'Resolve-PDBulkGroups', 'Backup-PDIntuneApp', 'Remove-PDIntuneApp',
                        'Get-PDCsvAssociatedProgram', 'Test-PDGridEditorAvailable', 'ConvertTo-PDGridTable', 'ConvertFrom-PDGridTable',
                        'ConvertTo-PDGridRowFilter', 'Show-PDCsvGridEditor')) {
        Assert-True ($null -ne (Get-Command -CommandType Function -Name $name -ErrorAction SilentlyContinue)) "$name should be defined"
    }
}

$script:SetupAst = [System.Management.Automation.Language.Parser]::ParseFile($setupPath, [ref]$null, [ref]$null)
$script:SetupFunctions = @($script:SetupAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))

Add-TestCase 'B02' 'Setup.ps1 loads both new files at script scope and no longer defines the moved functions' {
    foreach ($variable in @('PrinterIntuneHelpersScriptPath', 'PrinterIntuneBulkScriptPath', 'CsvGridEditorScriptPath')) {
        $target = '. $' + $variable
        $found = @($script:SetupAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.PipelineAst] -and [string]$n.Extent.Text -eq $target }, $true))
        Assert-Equal 1 $found.Count "Setup.ps1 should dot-source $variable exactly once"
        $node = $found[0]; $inFunction = $false
        while ($null -ne $node) { if ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $inFunction = $true; break }; $node = $node.Parent }
        Assert-True (-not $inFunction) "the dot-source of $variable must be at script scope"
    }

    $helperAst = [System.Management.Automation.Language.Parser]::ParseFile($printerPath, [ref]$null, [ref]$null)
    foreach ($moved in @('Test-IntuneFieldMissing', 'ConvertTo-IntuneFieldText', 'Get-IntuneDisplayUrl', 'New-IntunePrinterDescription', 'New-IntuneTechnicalNotes')) {
        Assert-Equal 0 @($script:SetupFunctions | Where-Object { $_.Name -eq $moved }).Count "$moved must not be defined in Setup.ps1 any more (one copy only)"
        Assert-Equal 1 @($helperAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $moved }, $true)).Count "$moved is defined once in the helper"
    }
}

Add-TestCase 'B03' 'the wizard builds through the shared builder, and the bulk menu entries never exit' {
    $wizard = @($script:SetupFunctions | Where-Object { $_.Name -eq 'Printer--InTune-Setup' })
    Assert-Equal 1 $wizard.Count 'the printer wizard exists once'
    $commands = @($wizard[0].FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
    Assert-True ($commands -contains 'New-PDPrinterIntuneMetadata') 'the wizard calls New-PDPrinterIntuneMetadata'
    Assert-True ($commands -notcontains 'New-IntunePrinterDescription') 'the wizard no longer builds the Description inline'

    foreach ($entry in @('Printer--InTune-BulkCreate', 'Printer--InTune-BulkDelete')) {
        $fn = @($script:SetupFunctions | Where-Object { $_.Name -eq $entry })
        Assert-Equal 1 $fn.Count "$entry is defined once (the menu reflects on '*--*')"
        Assert-Equal 0 @($fn[0].FindAll({ param($n) $n -is [System.Management.Automation.Language.ExitStatementAst] }, $true)).Count "$entry must never call exit"
    }
    foreach ($helper in @('Test-PrinterBulkReady', 'Open-PrinterBulkSheet', 'Wait-PrinterBulkSheet', 'Edit-PrinterBulkSheet', 'Get-PrinterBulkJsonPath')) {
        $fn = @($script:SetupFunctions | Where-Object { $_.Name -eq $helper })
        Assert-Equal 1 $fn.Count "$helper is defined once"
        Assert-True ($helper -notlike '*--*') "$helper must not contain '--' (it would appear in the menu)"
        Assert-Equal 0 @($fn[0].FindAll({ param($n) $n -is [System.Management.Automation.Language.ExitStatementAst] }, $true)).Count "$helper must never call exit"
    }
}

# ---------------------------------------------------------------------------
# Display name: builder and parser as a pair
# ---------------------------------------------------------------------------

Add-TestCase 'B10' 'every display name Setup builds parses back to the same printer, department and mode' {
    $modes = @('PUBLIC-DEVELOPMENT', 'PUBLIC-TESTING', 'PRIVATE-DEVELOPMENT', 'PRODUCTION')
    $names = @('Lobby', 'HR-2F-HP', 'Room 101 Copier', 'Lab [2]', 'O''Brien Office', 'Bldg-A: West')
    $depts = @($null, '', 'Facilities', 'Public Works - Roads')
    foreach ($mode in $modes) {
        foreach ($name in $names) {
            foreach ($dept in $depts) {
                if ($name -like '*: *' -and $dept) { continue }   # documented ambiguity, see B11
                $display = Get-PDPrinterIntuneDisplayName -PrinterName $name -Department $dept -DeployMode $mode -SourceCommit 'f9068c8.UnstagedChanges'
                $parsed  = ConvertFrom-PDPrinterIntuneDisplayName -DisplayName $display
                Assert-True $parsed.IsPrinter "'$display' is a printer"
                Assert-Equal $name $parsed.PrinterName "PrinterName from '$display'"
                Assert-Equal ([string]$dept) $parsed.Department "Department from '$display'"
                Assert-Equal $mode $parsed.DeployMode "DeployMode from '$display'"
                if ($mode -ne 'PRODUCTION') { Assert-Equal 'f9068c8.UnstagedChanges' $parsed.Version "Version from '$display'" }
            }
        }
    }
}

Add-TestCase 'B12' 'without git the source commit is "unknown" and nothing throws (as when the wizard did this inline)' {
    $result = & {
        function git { throw (New-Object System.Management.Automation.CommandNotFoundException 'git is not installed') }
        try { Get-PDPrinterSourceCommit -RepoRoot $repoRoot } catch { 'THREW: ' + $_.Exception.Message }
    }
    Assert-Equal 'unknown' $result 'a missing git gives unknown, never a thrown error'
    Assert-Like '*' (Get-PDPrinterSourceCommit -RepoRoot $repoRoot) 'the real lookup still works'
}

Add-TestCase 'B11' 'names Setup would never build are not printers, and the edge cases are pinned' {
    foreach ($other in @($null, '', '   ', '7-Zip', 'PRINTERS Admin Tool', 'Printer: Lobby', 'PRINTER:Lobby', 'PRINTER - : ', 'PRINTER: ', 'My PRINTER: Lobby')) {
        Assert-True (-not (ConvertFrom-PDPrinterIntuneDisplayName -DisplayName $other).IsPrinter) "'$other' is not a printer"
    }

    $renamed = ConvertFrom-PDPrinterIntuneDisplayName -DisplayName 'PRINTER: Lobby [OLD - f9068c8]'
    Assert-Equal 'Lobby [OLD - f9068c8]' $renamed.PrinterName 'a hand-renamed app keeps its tag in the name, so it never matches the JSON'
    Assert-Equal 'PRODUCTION' $renamed.DeployMode 'no mode tail means PRODUCTION'

    $colon = ConvertFrom-PDPrinterIntuneDisplayName -DisplayName 'PRINTER - Ops: Bldg-A: West'
    Assert-Equal 'Ops' $colon.Department 'the first ": " ends the department'
    Assert-Equal 'Bldg-A: West' $colon.PrinterName 'the rest is the printer name'
}

# ---------------------------------------------------------------------------
# PrinterData.json and the draft
# ---------------------------------------------------------------------------

Add-TestCase 'B20' 'the catalog applies the installer''s rules per printer and sorts by name' {
    $catalog = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json $script:GoodJson)
    Assert-Equal 0 @($catalog.Errors).Count 'no whole-file errors'
    Assert-Equal 5 @($catalog.Printers).Count 'every printer is listed'
    Assert-Equal 'Alpha-Lobby' ([string]$catalog.Printers[0].PrinterName) 'sorted by PrinterName'
    Assert-Like "*PresetDriver 'GONE' is not in drivers*" $catalog.Problems['bravo-old'] 'a missing preset is a problem'
    Assert-Like '*no PrinterIP*' $catalog.Problems['delta-noip'] 'a missing IP is a problem'
    Assert-True (-not $catalog.Problems.ContainsKey('charlie-own')) 'a printer with its own driver fields and no preset is fine'
    Assert-True (-not $catalog.Problems.ContainsKey('alpha-lobby')) 'a complete printer has no problem'
}

Add-TestCase 'B21' 'whole-file problems: duplicate names, missing names, broken JSON, no printers' {
    $dup = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json '{"printers":[{"PrinterName":"A","PortName":"p","PrinterIP":"1","DriverName":"d","INFFile":"i","DriverZip":"z"},{"PrinterName":"a ","PortName":"p","PrinterIP":"2"}],"drivers":[]}')
    Assert-Like "*appears 2 times*" (@($dup.Errors) -join ' ') 'a duplicate PrinterName (case and spaces ignored) stops the run'

    $noName = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json '{"printers":[{"PortName":"p"}]}')
    Assert-Like '*#1 has no PrinterName*' (@($noName.Errors) -join ' ') 'a nameless entry is reported by position'

    $broken = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json '{"printers": [')
    Assert-Like '*not valid JSON*' (@($broken.Errors) -join ' ') 'broken JSON is reported, not thrown'

    $empty = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json '{"drivers": []}')
    Assert-Like '*no "printers" entries*' (@($empty.Errors) -join ' ') 'no printers is reported'

    $missing = Get-PDPrinterJsonCatalog -Path (Join-Path $script:TempRoot 'nope.json')
    Assert-Like '*was not found*' (@($missing.Errors) -join ' ') 'a missing file is reported'
}

Add-TestCase 'B22' 'the draft marks printers that would fail, pre-fills default groups, and previews the name' {
    $catalog = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json $script:GoodJson)
    $draft = @(New-PDPrinterBulkDraft -Catalog $catalog -DeployMode 'PRIVATE-DEVELOPMENT' -SourceCommit 'abc1234' -DefaultRequiredGroups @('IT PCs', 'Techs') -DefaultAvailableGroups @())

    Assert-Equal 5 $draft.Count 'one row per printer'
    $alpha = $draft | Where-Object { $_.PrinterName -eq 'Alpha-Lobby' }
    Assert-Equal 'Y' $alpha.Include 'a good printer starts included'
    Assert-Equal 'IT PCs; Techs' $alpha.RequiredGroups 'default Required groups are pre-filled'
    Assert-Equal '' $alpha.AvailableGroups 'blank defaults stay blank (D4 skip)'
    Assert-Equal 'PRINTER - Facilities: Alpha-Lobby [PRIVATE-DEVELOPMENT] [VER: abc1234]' $alpha.IntuneDisplayName 'the name preview is the real name'
    Assert-Equal 'Bldg A' $alpha.Location 'context columns come from the JSON'

    $bravo = $draft | Where-Object { $_.PrinterName -eq 'Bravo-Old' }
    Assert-Equal 'N' $bravo.Include 'a printer that would fail starts excluded'
    Assert-Like '*GONE*' $bravo.Problem 'and says why'

    $none = @(New-PDPrinterBulkDraft -Catalog $catalog -DeployMode 'PRODUCTION' -SourceCommit 'x')
    Assert-Equal '' ($none | Where-Object { $_.PrinterName -eq 'Alpha-Lobby' }).RequiredGroups 'no defaults given means empty group cells'

    $unticked = @(New-PDPrinterBulkDraft -Catalog $catalog -DeployMode 'PRODUCTION' -SourceCommit 'x' -IncludeByDefault $false)
    Assert-Equal 'N,N,N,N,N' (($unticked | ForEach-Object Include) -join ',') 'IncludeByDefault $false starts every printer unticked'
}

Add-TestCase 'B23' 'the draft carries every PrinterData.json field, with the driver the installer will really use' {
    $catalog = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json $script:GoodJson)
    $columns = @(Get-PDPrinterBulkDraftColumns -Catalog $catalog)
    $expected = @($script:PDBulk.DraftColumns) + @($script:PDBulk.ReferenceColumns) + @('Floor')
    Assert-Equal ($expected -join ',') ($columns -join ',') 'operator columns, then reference columns, then the extra JSON field'
    foreach ($field in @('Asset', 'Model', 'PortName', 'PresetDriver', 'Verified', 'DriverName', 'INFFile', 'DriverZip')) {
        Assert-True ($columns -contains $field) "$field is a column"
    }

    $draft = @(New-PDPrinterBulkDraft -Catalog $catalog -DeployMode 'PRODUCTION' -SourceCommit 'x')
    $alpha = $draft | Where-Object { $_.PrinterName -eq 'Alpha-Lobby' }
    Assert-Equal '010.000.000.001' $alpha.PortName 'PortName copied as text'
    Assert-Equal 'HP Universal Printing PCL 6' $alpha.DriverName 'a PresetDriver printer shows the preset''s driver'
    Assert-Equal 'printers/Drivers/HP/upd.zip' $alpha.DriverZip 'and the preset''s zip'
    $charlie = $draft | Where-Object { $_.PrinterName -eq 'Charlie-Own' }
    Assert-Equal 'own.inf' $charlie.INFFile 'a printer without a preset shows its own driver fields'
    Assert-Equal '2' ($draft | Where-Object { $_.PrinterName -eq 'Zulu-Copier' }).Floor 'an extra JSON field is carried'
    Assert-Equal '' $alpha.Floor 'and is empty for printers without it'
}

# ---------------------------------------------------------------------------
# CSV in and out
# ---------------------------------------------------------------------------

Add-TestCase 'B30' 'the CSV is written with a BOM and the exact columns, and reads back' {
    $path = Join-Path $script:TempRoot 'roundtrip.csv'
    $rows = @([pscustomobject]@{ PrinterName = 'A'; Include = 'Y'; Extra = 'ignored' }, [pscustomobject]@{ PrinterName = 'B, "quoted"'; Include = 'N' })
    Write-PDBulkCsv -Rows $rows -Columns @('Include', 'PrinterName', 'RequiredGroups') -Path $path

    $bytes = [System.IO.File]::ReadAllBytes($path)
    Assert-True ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) 'UTF-8 BOM so Excel reads it as UTF-8'
    $header = ([System.IO.File]::ReadAllLines($path))[0]
    Assert-Equal '"Include","PrinterName","RequiredGroups"' $header 'exactly the requested columns, in order'

    $back = @(Read-PDBulkCsv -Path $path -RequiredColumns @('Include', 'PrinterName'))
    Assert-Equal 2 $back.Count 'both rows'
    Assert-Equal 'B, "quoted"' $back[1].PrinterName 'commas and quotes survive'
    Assert-Equal 3 ([int]$back[1].RowNumber) 'RowNumber is the spreadsheet row (header is row 1)'

    $empty = Join-Path $script:TempRoot 'empty.csv'
    Write-PDBulkCsv -Rows @() -Columns @('Delete', 'AppId') -Path $empty
    Assert-Equal 0 @(Read-PDBulkCsv -Path $empty -RequiredColumns @('Delete', 'AppId')).Count 'an empty sheet is valid and has no rows'
}

Add-TestCase 'B31' 'an Excel-saved sheet with blank rows, spaces and an added column still reads' {
    $path = Join-Path $script:TempRoot 'excel.csv'
    $text = "Include,PrinterName,RequiredGroups,AvailableGroups,My Notes`r`n yes , Alpha-Lobby ,IT PCs;Techs,,call Bob`r`nn,Zulu-Copier,,,`r`n,,,,`r`n,,,,`r`n"
    [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($true)))

    $rows = @(Read-PDBulkCsv -Path $path -RequiredColumns @('Include', 'PrinterName', 'RequiredGroups', 'AvailableGroups'))
    Assert-Equal 2 $rows.Count 'blank trailing rows are ignored'
    Assert-Equal 'Alpha-Lobby' $rows[0].PrinterName 'cells are trimmed'
    Assert-True (Test-PDBulkYes -Value $rows[0].Include) "' yes ' counts as yes"
    Assert-True (-not (Test-PDBulkYes -Value $rows[1].Include)) "'n' is no"

    $renamed = Join-Path $script:TempRoot 'renamed.csv'
    [System.IO.File]::WriteAllText($renamed, "Include,Printer,RequiredGroups,AvailableGroups`r`nY,A,,`r`n", (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws -Body { Read-PDBulkCsv -Path $renamed -RequiredColumns @('Include', 'PrinterName', 'RequiredGroups', 'AvailableGroups') } -MessagePattern '*missing column(s): PrinterName*' | Out-Null

    foreach ($yes in @('Y', 'y', 'Yes', 'YES', 'x', 'TRUE', '1')) { Assert-True (Test-PDBulkYes -Value $yes) "'$yes' is yes" }
    foreach ($no in @('', 'N', 'no', '0', 'false', 'maybe', $null)) { Assert-True (-not (Test-PDBulkYes -Value $no)) "'$no' is not yes" }
}

# ---------------------------------------------------------------------------
# Groups and staging
# ---------------------------------------------------------------------------

function Set-GroupDirectory {
    param([hashtable]$Groups)   # lower-case name -> @(ids)
    Set-MockGraph -Router {
        param($Method, $Uri)
        $found = [regex]::Match($Uri, "displayName eq '((?:[^']|'')*)'")
        if ($Method -eq 'Get' -and $Uri -like '*/groups?*' -and $found.Success) {
            $name = $found.Groups[1].Value.Replace("''", "'")
            $ids = @($script:GroupDirectory[$name.ToLowerInvariant()])
            $value = @($ids | Where-Object { $_ } | ForEach-Object { @{ id = $_; displayName = $name } })
            return (New-MockResponse -Body @{ value = $value })
        }
        return $null
    }
    $script:GroupDirectory = $Groups
}

Add-TestCase 'B40' 'every distinct group is looked up once, and every problem is reported at once' {
    Set-GroupDirectory -Groups @{ 'it pcs' = @('11111111-1111-1111-1111-111111111111'); 'techs' = @('22222222-2222-2222-2222-222222222222'); 'twins' = @('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444444') }

    $rows = @(
        (New-StageRow -Name 'A' -Required 'IT PCs; Techs' -Row 2),
        (New-StageRow -Name 'B' -Required 'it pcs' -Available '/AllUsers' -Row 3),
        (New-StageRow -Name 'C' -Required 'IT PCs;Nobody' -Available 'Twins' -Row 4)
    )
    $result = Resolve-PDBulkGroups -Rows $rows -AuthContext $script:FakeAuth

    Assert-Equal 1 @(Get-MockCalls -Method Get | Where-Object { $_.Uri -like "*'IT PCs'*" -or $_.Uri -like "*'it pcs'*" }).Count 'IT PCs looked up once although three rows use it'
    Assert-Equal '11111111-1111-1111-1111-111111111111' ([string]$result.Map['it pcs'].Id) 'names resolve case-insensitively to one id'
    Assert-Equal '/AllUsers' ([string]$result.Map['/allusers'].Id) 'built-in targets need no lookup'
    Assert-Equal 2 @($result.Errors).Count 'both problems are reported together'
    Assert-Like "*Group 'Nobody' (CSV row 4: C)*" (@($result.Errors) -join ' | ') 'an unknown group names its row and printer'
    Assert-Like "*Group 'Twins' (CSV row 4: C)*2 groups are named*" (@($result.Errors) -join ' | ') 'an ambiguous group is an error, never a guess'

    $many = @(1..7 | ForEach-Object { New-StageRow -Name ("P$_") -Required 'Nobody' -Row ($_ + 1) })
    $manyErrors = (Resolve-PDBulkGroups -Rows $many -AuthContext $script:FakeAuth).Errors -join ' | '
    Assert-Like "*(CSV rows 2: P1, 3: P2, 4: P3, 5: P4, 6: P5 and 2 more)*" $manyErrors 'a group used on many rows lists the first five and a count'
}

Add-TestCase 'B41' 'staging checks every row against the JSON and finds same-mode printers only' {
    $catalog = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json $script:GoodJson)
    $map = @{ 'it pcs' = [pscustomobject]@{ Id = 'g1'; DisplayName = 'IT PCs' }; 'techs' = [pscustomobject]@{ Id = 'g2'; DisplayName = 'Techs' } }
    $existing = @(
        (New-ExistingApp -Id 'old-1' -Name 'Alpha-Lobby' -Mode 'PRIVATE-DEVELOPMENT' -Dept 'Facilities'),
        (New-ExistingApp -Id 'old-2' -Name 'alpha-lobby' -Mode 'PRIVATE-DEVELOPMENT'),
        (New-ExistingApp -Id 'prod-1' -Name 'Alpha-Lobby' -Mode 'PRODUCTION'),
        (New-ExistingApp -Id 'prod-2' -Name 'Zulu-Copier' -Mode 'PRODUCTION')
    )
    $rows = @(
        (New-StageRow -Name 'Alpha-Lobby' -Required 'IT PCs' -Row 2),
        (New-StageRow -Name 'Zulu-Copier' -Available 'Techs' -Row 3),
        (New-StageRow -Name 'Charlie-Own' -Row 4),
        (New-StageRow -Include 'N' -Name 'Bravo-Old' -Row 5)
    )
    $stage = Resolve-PDPrinterBulkStage -Rows $rows -Catalog $catalog -ExistingApps $existing -GroupMap $map -DeployMode 'PRIVATE-DEVELOPMENT' -SourceCommit 'abc1234'

    Assert-Equal 0 @($stage.Errors).Count ("clean sheet: " + (@($stage.Errors) -join ' | '))
    Assert-Equal 1 $stage.Excluded 'Include = N is left out, even for a flagged printer'
    $alpha = $stage.Rows | Where-Object { $_.PrinterName -eq 'Alpha-Lobby' }
    Assert-Equal 'Conflict' $alpha.Action 'same name and same mode is a conflict'
    Assert-Equal 'old-1; old-2' $alpha.ExistingAppIds 'both same-mode copies (any department, any case) are found'
    Assert-Equal 1 @($alpha.OtherModeMatches).Count 'the PRODUCTION copy is information only'
    Assert-Equal 'g1' (@($alpha.RequiredIds) -join ',') 'resolved Required ids travel with the row'

    $zulu = $stage.Rows | Where-Object { $_.PrinterName -eq 'Zulu-Copier' }
    Assert-Equal 'Create' $zulu.Action 'a printer that exists only in another mode is created'
    Assert-Equal 'g2' (@($zulu.AvailableIds) -join ',') 'resolved Available ids travel with the row'
}

Add-TestCase 'B42' 'staging refuses edited names, flagged printers, duplicates, and a group in both intents' {
    $catalog = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json $script:GoodJson)
    $map = @{ 'it pcs' = [pscustomobject]@{ Id = 'g1'; DisplayName = 'IT PCs' }; 'it-pcs-by-id' = [pscustomobject]@{ Id = 'G1'; DisplayName = 'IT PCs' } }
    $rows = @(
        (New-StageRow -Name 'Alpha-Lobby-RENAMED' -Row 2),
        (New-StageRow -Name 'Bravo-Old' -Row 3),
        (New-StageRow -Name 'Zulu-Copier' -Row 4),
        (New-StageRow -Name 'zulu-copier' -Row 5),
        (New-StageRow -Name 'Charlie-Own' -Required 'IT PCs' -Available 'it-pcs-by-id' -Row 6),
        (New-StageRow -Name '' -Row 7)
    )
    $stage = Resolve-PDPrinterBulkStage -Rows $rows -Catalog $catalog -ExistingApps @() -GroupMap $map -DeployMode 'PRODUCTION' -SourceCommit 'x'
    $text = @($stage.Errors) -join ' | '

    Assert-Like "*Row 2: 'Alpha-Lobby-RENAMED' is not in PrinterData.json*" $text 'an edited PrinterName is refused'
    Assert-Like "*Row 3: 'Bravo-Old' would fail to install*" $text 'a flagged printer cannot be forced in'
    Assert-Like "*Row 5: 'zulu-copier' is already on row 4*" $text 'a duplicate row is refused'
    Assert-Like "*Row 6:*both RequiredGroups and AvailableGroups*" $text 'one group under both intents is refused'
    Assert-Like "*Row 7: Include is set but PrinterName is empty*" $text 'an empty name is refused'
    Assert-Equal 1 @($stage.Rows).Count 'only the clean row is staged'
}

Add-TestCase 'B43' 'an edited reference cell is reported as ignored; a sheet without reference columns warns about nothing' {
    $catalog = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json $script:GoodJson)
    $draft = @(New-PDPrinterBulkDraft -Catalog $catalog -DeployMode 'PRODUCTION' -SourceCommit 'x')
    $alpha = $draft | Where-Object { $_.PrinterName -eq 'Alpha-Lobby' }
    $alpha | Add-Member -NotePropertyName RowNumber -NotePropertyValue 2 -Force
    $alpha.PrinterIP = '10.0.0.250'
    $alpha.Location  = 'Bldg A'
    $zulu = $draft | Where-Object { $_.PrinterName -eq 'Zulu-Copier' }
    $zulu | Add-Member -NotePropertyName RowNumber -NotePropertyValue 3 -Force

    $stage = Resolve-PDPrinterBulkStage -Rows @($alpha, $zulu) -Catalog $catalog -ExistingApps @() -GroupMap @{} -DeployMode 'PRODUCTION' -SourceCommit 'x'
    Assert-Equal 0 @($stage.Errors).Count 'an edited reference cell is not an error'
    Assert-Equal 1 @($stage.Warnings).Count 'exactly the one edited cell is reported'
    Assert-Like "*Row 2 (Alpha-Lobby): PrinterIP is '10.0.0.250' in the sheet but '10.0.0.1' in PrinterData.json*" (@($stage.Warnings)[0]) 'with both values'
    Assert-Equal '10.0.0.1' ($stage.Rows | Where-Object { $_.PrinterName -eq 'Alpha-Lobby' }).PrinterIP 'the staged row uses the JSON value'

    $resumed = @((New-StageRow -Name 'Alpha-Lobby' -Row 2))
    $quiet = Resolve-PDPrinterBulkStage -Rows $resumed -Catalog $catalog -ExistingApps @() -GroupMap @{} -DeployMode 'PRODUCTION' -SourceCommit 'x'
    Assert-Equal 0 @($quiet.Warnings).Count 'columns the sheet does not have are never compared'
}

# ---------------------------------------------------------------------------
# Listing printer apps
# ---------------------------------------------------------------------------

Add-TestCase 'B50' 'the printer list follows pages, keeps only real printer names, and asks with startswith' {
    Set-MockGraph -Router {
        param($Method, $Uri)
        if ($Method -eq 'Get' -and $Uri -like '*/deviceAppManagement/mobileApps?*' -and $Uri -notlike '*page=2*') {
            return (New-MockResponse -Body @{
                value = @(
                    @{ id = 'a1'; displayName = 'PRINTER: Zulu-Copier'; createdDateTime = '2026-10-01T12:30:00Z' },
                    @{ id = 'a2'; displayName = 'PRINTERS Admin Tool'; createdDateTime = '2026-10-01T12:30:00Z' }
                )
                '@odata.nextLink' = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?page=2'
            })
        }
        if ($Method -eq 'Get' -and $Uri -like '*page=2*') {
            return (New-MockResponse -Body @{ value = @(@{ id = 'a3'; displayName = 'PRINTER - HR: Alpha [PRIVATE-DEVELOPMENT] [VER: abc]' }) })
        }
        return $null
    }

    $apps = @(Get-PDIntunePrinterApps -AuthContext $script:FakeAuth)
    Assert-Like "*startswith(displayName,'PRINTER')*" (Get-MockCalls)[0].Uri 'the list asks with startswith (eq never matches bracketed names)'
    Assert-Equal 2 $apps.Count 'the second page is followed and the non-printer is dropped'
    Assert-Equal 'Alpha' $apps[0].PrinterName 'sorted by PrinterName'
    Assert-Equal 'PRIVATE-DEVELOPMENT' $apps[0].DeployMode 'mode parsed'
    Assert-Equal 'HR' $apps[0].Department 'department parsed'
    Assert-Equal '2026-10-01' ($apps[1].Created.Substring(0, 10)) 'created date shown as a date'
}

# ---------------------------------------------------------------------------
# Bulk create: ordering and isolation
# ---------------------------------------------------------------------------

$script:Uploads = @()
$script:UploadPlan = @{}

$script:RealBuilder  = (Get-Command -CommandType Function -Name 'New-PDPrinterIntuneMetadata').ScriptBlock
$script:RealUploader = (Get-Command -CommandType Function -Name 'Invoke-PDIntuneUpload').ScriptBlock

function Install-BulkCreateStubs {
    # Replace the builder and the uploader with recording stubs for this case only.
    $script:Uploads = @()
    Set-Item -Path function:global:New-PDPrinterIntuneMetadata -Value {
        param([string]$PrinterName, $Department, $Location, $Model, $Asset, $PrinterIP, $Verified, $Publisher, $IntuneWinPath,
              $RepoUrl, $RepoNickName, $RepoBranch, $TargetWorkingDirectory, $DeployMode, $RepoRoot, $IconPath, $GenerateInstallCommandPath, $Log)
        if ($PrinterName -eq 'Charlie-Own') { throw 'No data returned!' }
        return @{ Metadata = @{ DisplayName = ('PRINTER: ' + $PrinterName); IntuneWinPath = $IntuneWinPath; Description = 'd'; Publisher = 'PowerDeploy';
                                InstallCommandFile = 'i.txt'; UninstallCommandFile = 'u.txt'; DetectionScriptFile = 'd.ps1'; AppVersion = 'v';
                                Category = 'Printers'; Notes = 'n'; AllowAvailableUninstall = $true; IconFile = '' } }
    }
    Set-Item -Path function:global:Invoke-PDIntuneUpload -Value {
        param($IntuneWinPath, $DisplayName, $Description, $Publisher, $InstallCommandFile, $UninstallCommandFile, $DetectionScriptFile,
              $AppVersion, $Category, $Notes, [string[]]$RequiredGroups, [string[]]$AvailableGroups, $AllowAvailableUninstall,
              $CredentialPath, [switch]$DryRun, [switch]$AllowDuplicateName, [switch]$NoRollback, $TempDirectory, $IconFile, $InformationUrl, $PrivacyUrl)
        $script:Uploads += [pscustomobject]@{ DisplayName = $DisplayName; AllowDuplicateName = [bool]$AllowDuplicateName; Required = @($RequiredGroups); Available = @($AvailableGroups); At = @($script:Calls).Count }
        $plan = $script:UploadPlan[$DisplayName]
        if ($plan -eq 'fail') { return [pscustomobject]@{ Success = $false; Stage = 'CreateApp'; Message = 'refused'; CleanupStatus = 'NotNeeded'; AppId = $null } }
        return [pscustomobject]@{ Success = $true; Stage = 'Done'; Message = 'ok'; CleanupStatus = 'NotNeeded'; AppId = ('new-' + $DisplayName.Substring(9)) }
    }
}

function Remove-BulkCreateStubs {
    # Put the real definitions back where the stubs went (re-importing here would define them only
    # inside this function, and they would vanish when it returns).
    Set-Item -Path function:global:New-PDPrinterIntuneMetadata -Value $script:RealBuilder
    Set-Item -Path function:global:Invoke-PDIntuneUpload -Value $script:RealUploader
}

function Set-AppStoreMock {
    param([hashtable]$Behaviour)   # app id -> 'ok' | 'delete-fails' | 'read-fails' | 'gone'
    $script:AppBehaviour = $Behaviour
    Set-MockGraph -Router {
        param($Method, $Uri)
        $m = [regex]::Match($Uri, '/mobileApps/([^/?]+)(/assignments)?')
        if (-not $m.Success) { return $null }
        $id = $m.Groups[1].Value
        $how = [string]$script:AppBehaviour[$id]
        if ($how -eq 'gone') { return (New-MockResponse -Status 404 -Body @{ error = @{ code = 'NotFound'; message = 'gone' } }) }
        if ($Method -eq 'Get' -and $how -eq 'read-fails') { return (New-MockResponse -Status 403 -Body @{ error = @{ code = 'Forbidden'; message = 'no' } }) }
        if ($Method -eq 'Get' -and $m.Groups[2].Success) { return (New-MockResponse -Body @{ value = @(@{ id = 'as1'; intent = 'required'; target = @{ groupId = 'g1' } }) }) }
        if ($Method -eq 'Get') { return (New-MockResponse -Body @{ id = $id; displayName = "PRINTER: $id" }) }
        if ($Method -eq 'Delete' -and $how -eq 'delete-fails') { return (New-MockResponse -Status 400 -Body @{ error = @{ code = 'BadRequest'; message = 'cannot' } }) }
        if ($Method -eq 'Delete') { return (New-MockResponse -Status 204) }
        return $null
    }
}

function New-CreateRow {
    param([string]$Name, [string]$Action, [string[]]$OldIds = @())
    return [pscustomobject]@{
        RowNumber = 2; Include = 'Y'; PrinterName = $Name; IntuneDisplayName = "PRINTER: $Name"; RequiredGroups = 'IT PCs'; AvailableGroups = ''
        Department = ''; Location = ''; PrinterIP = ''; Problem = ''; Action = $Action
        ExistingAppIds = ($OldIds -join '; '); ExistingDisplayNames = ''
        Matches = @($OldIds | ForEach-Object { [pscustomobject]@{ AppId = $_; DisplayName = "PRINTER: $Name" } })
        OtherModeMatches = @(); RequiredIds = @('g1'); AvailableIds = @()
    }
}

Add-TestCase 'B60' 'override deletes the old app only after the new one exists, and backs it up first' {
    $catalog = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json $script:GoodJson)
    $backups = Join-Path $script:TempRoot ('b60-' + [guid]::NewGuid().ToString('N'))
    Install-BulkCreateStubs
    try {
        $script:UploadPlan = @{ 'PRINTER: Zulu-Copier' = 'fail' }
        Set-AppStoreMock -Behaviour @{ 'old-alpha' = 'ok'; 'old-zulu' = 'ok' }

        $rows = @(
            (New-CreateRow -Name 'Alpha-Lobby' -Action 'Override' -OldIds @('old-alpha')),
            (New-CreateRow -Name 'Zulu-Copier' -Action 'Override' -OldIds @('old-zulu'))
        )
        $results = @(Invoke-PDPrinterBulkCreate -StagedRows $rows -Catalog $catalog -AuthContext $script:FakeAuth -Context @{ BackupFolder = $backups; IntuneWinPath = 'x.intunewin'; RetryDelaySeconds = 0 })

        $alpha = $results | Where-Object { $_.PrinterName -eq 'Alpha-Lobby' }
        Assert-Equal 'Overridden' $alpha.Result 'the override completed'
        Assert-Equal 'new-Alpha-Lobby' $alpha.NewAppId 'the new app id is recorded'
        Assert-Equal 'old-alpha' $alpha.DeletedAppIds 'the old app id is recorded as deleted'
        Assert-Equal 'N' $alpha.Include 'a finished printer is not retried'

        $calls = @(Get-MockCalls | ForEach-Object { '{0} {1}' -f $_.Method, ($_.Uri -replace '^https://graph.microsoft.com/beta/deviceAppManagement', '') })
        Assert-Equal 'Get /mobileApps/old-alpha|Get /mobileApps/old-alpha/assignments|Delete /mobileApps/old-alpha' ($calls -join '|') 'backup reads happen before the delete, and nothing else is touched'
        Assert-Equal 0 ([int]$script:Uploads[0].At) 'the new app was created before any call about the old app'

        $backupFile = Join-Path $backups 'old-alpha.json'
        Assert-True (Test-Path -LiteralPath $backupFile) 'the backup file exists'
        $saved = Get-Content -LiteralPath $backupFile -Raw | ConvertFrom-Json
        Assert-Equal 'old-alpha' ([string]$saved.App.id) 'the backup holds the app'
        Assert-Equal 'g1' ([string]$saved.Assignments[0].target.groupId) 'the backup holds its assignments'

        $zulu = $results | Where-Object { $_.PrinterName -eq 'Zulu-Copier' }
        Assert-Equal 'Failed' $zulu.Result 'a failed create is reported'
        Assert-Like '*existing app was not touched*' $zulu.Error 'and says the old app is safe'
        Assert-Equal 'Y' $zulu.Include 'a failed printer is marked for retry'
        Assert-Equal 0 @(Get-MockCalls | Where-Object { $_.Uri -like '*old-zulu*' }).Count 'a failed create never touches the old app'

        Assert-True (@($script:Uploads | ForEach-Object { $_.AllowDuplicateName }) -notcontains $false) 'override rows may share the old name'
    } finally {
        Remove-BulkCreateStubs
    }
}

Add-TestCase 'B61' 'one printer failing never stops the batch; skips and creates are handled' {
    $catalog = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json $script:GoodJson)
    Install-BulkCreateStubs
    try {
        $script:UploadPlan = @{}
        Set-AppStoreMock -Behaviour @{ 'old-alpha' = 'delete-fails' }
        $progress = @()

        $rows = @(
            (New-CreateRow -Name 'Alpha-Lobby' -Action 'Override' -OldIds @('old-alpha')),
            (New-CreateRow -Name 'Charlie-Own' -Action 'Create'),
            (New-CreateRow -Name 'Delta-NoIP' -Action 'Skip' -OldIds @('old-delta')),
            (New-CreateRow -Name 'Zulu-Copier' -Action 'Create')
        )
        $results = @(Invoke-PDPrinterBulkCreate -StagedRows $rows -Catalog $catalog -AuthContext $script:FakeAuth `
                        -Context @{ BackupFolder = (Join-Path $script:TempRoot 'b61'); IntuneWinPath = 'x.intunewin'; RetryDelaySeconds = 0 } `
                        -OnProgress { param($Index, $Total, $Row, $Result) $script:B61Progress += ('{0}/{1} {2}' -f $Index, $Total, $Result.Result) })

        Assert-Equal 4 $results.Count 'one result per staged row'
        Assert-Equal 'CreatedOldNotDeleted' ($results[0]).Result 'a failed old-app delete keeps the new app and says so'
        Assert-Like '*old-alpha: Delete failed*' ($results[0]).Error 'the old app id and reason are given'
        Assert-Equal 'N' ($results[0]).Include 'the new printer exists, so it is not retried'
        Assert-Equal 'Failed' ($results[1]).Result 'a build failure is reported'
        Assert-Like '*No data returned!*' ($results[1]).Error 'with the builder message'
        Assert-Equal 'Skipped' ($results[2]).Result 'a skipped row does nothing'
        Assert-Equal 0 @(Get-MockCalls | Where-Object { $_.Uri -like '*old-delta*' }).Count 'a skipped row never touches its existing app'
        Assert-Equal 'Created' ($results[3]).Result 'the batch carried on after the failures'
        Assert-Equal 2 $script:Uploads.Count 'only Create/Override rows that built reach the uploader'
        Assert-Equal $false ($script:Uploads | Where-Object { $_.DisplayName -eq 'PRINTER: Zulu-Copier' }).AllowDuplicateName 'a plain create never allows a duplicate name'
        Assert-Equal 'g1' (@(($script:Uploads | Where-Object { $_.DisplayName -eq 'PRINTER: Zulu-Copier' }).Required) -join ',') 'resolved group ids reach the uploader'
        Assert-Equal '1/3 CreatedOldNotDeleted|2/3 Failed|3/3 Created' (@($script:B61Progress) -join '|') 'progress counts only the printers being created'
    } finally {
        Remove-BulkCreateStubs
        $script:B61Progress = @()
    }
}
$script:B61Progress = @()

Add-TestCase 'B62' 'an old app whose backup cannot be read is never deleted' {
    $catalog = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json $script:GoodJson)
    Install-BulkCreateStubs
    try {
        $script:UploadPlan = @{}
        Set-AppStoreMock -Behaviour @{ 'old-alpha' = 'read-fails' }
        $results = @(Invoke-PDPrinterBulkCreate -StagedRows @(New-CreateRow -Name 'Alpha-Lobby' -Action 'Override' -OldIds @('old-alpha')) `
                        -Catalog $catalog -AuthContext $script:FakeAuth -Context @{ BackupFolder = (Join-Path $script:TempRoot 'b62'); IntuneWinPath = 'x'; RetryDelaySeconds = 0 })
        Assert-Equal 'CreatedOldNotDeleted' $results[0].Result 'reported as needing attention'
        Assert-Like '*Backup failed, so the app was NOT deleted*' $results[0].Error 'and why'
        Assert-Equal 0 @(Get-MockCalls -Method Delete).Count 'no DELETE without a backup'
    } finally {
        Remove-BulkCreateStubs
    }
}

Add-TestCase 'B64' 'a failed upload that left nothing behind is retried; preflight failures and leftovers are not' {
    $catalog = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json $script:GoodJson)
    Install-BulkCreateStubs
    try {
        # Per display name: a list of outcomes, one per attempt (the last repeats).
        $script:AttemptPlan = @{
            'PRINTER: Alpha-Lobby' = @('content', 'ok')
            'PRINTER: Zulu-Copier' = @('preflight')
            'PRINTER: Delta-NoIP'  = @('leftover')
            'PRINTER: Bravo-Old'   = @('content')
        }
        $script:AttemptCount = @{}
        Set-Item -Path function:global:Invoke-PDIntuneUpload -Value {
            param($IntuneWinPath, $DisplayName, $Description, $Publisher, $InstallCommandFile, $UninstallCommandFile, $DetectionScriptFile,
                  $AppVersion, $Category, $Notes, [string[]]$RequiredGroups, [string[]]$AvailableGroups, $AllowAvailableUninstall,
                  $CredentialPath, [switch]$DryRun, [switch]$AllowDuplicateName, [switch]$NoRollback, $TempDirectory, $IconFile, $InformationUrl, $PrivacyUrl)
            $n = 1 + [int]$script:AttemptCount[$DisplayName]; $script:AttemptCount[$DisplayName] = $n
            $script:Uploads += [pscustomobject]@{ DisplayName = $DisplayName; AllowDuplicateName = [bool]$AllowDuplicateName; Attempt = $n }
            $plan = @($script:AttemptPlan[$DisplayName]); $outcome = $plan[[math]::Min($n, $plan.Count) - 1]
            switch ($outcome) {
                'ok'        { return [pscustomobject]@{ Success = $true;  Stage = 'Done';          Message = 'ok';    CleanupStatus = 'NotNeeded'; AppId = 'new-' + $n; StorageRenewals = 1; StorageAccessWaits = 2 } }
                'content'   { return [pscustomobject]@{ Success = $false; Stage = 'CommitFile';    Message = 'commitFileFailed'; CleanupStatus = 'Deleted'; AppId = 'tmp' } }
                'preflight' { return [pscustomobject]@{ Success = $false; Stage = 'Preflight';     Message = 'bad group'; CleanupStatus = 'NotNeeded'; AppId = $null } }
                'leftover'  { return [pscustomobject]@{ Success = $false; Stage = 'ContentUpload'; Message = 'boom';  CleanupStatus = 'Failed'; AppId = 'left-1' } }
            }
        }

        $rows = @((New-CreateRow -Name 'Alpha-Lobby' -Action 'Create'), (New-CreateRow -Name 'Zulu-Copier' -Action 'Create'),
                  (New-CreateRow -Name 'Delta-NoIP' -Action 'Create'), (New-CreateRow -Name 'Bravo-Old' -Action 'Create'))
        $results = @(Invoke-PDPrinterBulkCreate -StagedRows $rows -Catalog $catalog -AuthContext $script:FakeAuth `
                        -Context @{ BackupFolder = (Join-Path $script:TempRoot 'b64'); IntuneWinPath = 'x'; RetryDelaySeconds = 0 })
        $by = @{}; foreach ($r in $results) { $by[$r.PrinterName] = $r }

        Assert-Equal 'Created' $by['Alpha-Lobby'].Result 'a transient content failure is retried and succeeds'
        Assert-Equal '2' $by['Alpha-Lobby'].Attempts 'on the second attempt'
        Assert-Equal '1' $by['Alpha-Lobby'].StorageRenewals 'the final attempt''s storage renewals reach the results'
        Assert-Equal '2' $by['Alpha-Lobby'].StorageWaits 'and its storage waits'
        Assert-Equal '0' $by['Zulu-Copier'].StorageRenewals 'an upload that never reported counts shows 0'
        Assert-Like '*Succeeded on attempt 2 after: attempt 1: stage CommitFile: commitFileFailed*' $by['Alpha-Lobby'].Error 'the earlier failure is kept for the record'
        Assert-Equal 'False,True' ((@($script:Uploads | Where-Object { $_.DisplayName -eq 'PRINTER: Alpha-Lobby' }) | ForEach-Object { $_.AllowDuplicateName }) -join ',') 'only the retry may share the deleted attempt''s name'

        Assert-Equal '1' $by['Zulu-Copier'].Attempts 'a preflight failure is not retried'
        Assert-Equal '1' $by['Delta-NoIP'].Attempts 'a failure that may have left an app is never retried'
        Assert-Like '*incomplete app was left in Intune: left-1*' $by['Delta-NoIP'].Error 'and the leftover is reported'
        Assert-Equal '3' $by['Bravo-Old'].Attempts 'a printer that keeps failing stops after three attempts'
        Assert-Like '3 attempts failed. Last: stage CommitFile*' $by['Bravo-Old'].Error 'and says so'
        Assert-Equal 'Y' $by['Bravo-Old'].Include 'and stays marked for the next retry run'
    } finally {
        Remove-BulkCreateStubs
    }
}

Add-TestCase 'B63' 'the stubs are gone afterwards: the real builder and uploader are back' {
    $builder  = (Get-Command -CommandType Function -Name 'New-PDPrinterIntuneMetadata').ScriptBlock.ToString()
    $uploader = (Get-Command -CommandType Function -Name 'Invoke-PDIntuneUpload').ScriptBlock.ToString()
    Assert-Like '*& $GenerateInstallCommandPath -DesiredFunction "InstallPrinterByIP"*' $builder 'the real builder runs the generator'
    Assert-Like '*Start-PDIntunePreflight*' $uploader 'the real uploader runs preflight'
}

# ---------------------------------------------------------------------------
# Bulk delete
# ---------------------------------------------------------------------------

Add-TestCase 'B70' 'the delete sheet is matched by AppId only, against a fresh list' {
    $current = @((New-ExistingApp -Id 'a1' -Name 'Lobby'), (New-ExistingApp -Id 'a2' -Name 'Lobby'), (New-ExistingApp -Id 'a3' -Name 'HR'))
    $sheet = @(New-PDPrinterDeleteSheet -Apps $current)
    Assert-Equal '' $sheet[0].Delete 'nothing is pre-marked'

    $rows = @(
        [pscustomobject]@{ RowNumber = 2; Delete = 'Y'; AppId = 'A1'; DisplayName = 'renamed in the sheet' },
        [pscustomobject]@{ RowNumber = 3; Delete = ''; AppId = 'a2'; DisplayName = 'PRINTER: Lobby' },
        [pscustomobject]@{ RowNumber = 4; Delete = 'x'; AppId = 'gone-1'; DisplayName = 'PRINTER: Old' },
        [pscustomobject]@{ RowNumber = 5; Delete = 'yes'; AppId = 'a1'; DisplayName = 'dup' },
        [pscustomobject]@{ RowNumber = 6; Delete = 'Y'; AppId = ''; DisplayName = 'PRINTER: HR' }
    )
    $selection = Resolve-PDPrinterDeleteSelection -Rows $rows -CurrentApps $current
    Assert-Equal 'a1' (@($selection.Selected | ForEach-Object AppId) -join ',') 'only the marked id, once, matched case-insensitively; the same-name twin is untouched'
    Assert-Equal 'gone-1' (@($selection.Gone | ForEach-Object AppId) -join ',') 'an id no longer in Intune is reported, not deleted'
    Assert-Like '*Row 6: marked for deletion but AppId is empty*' (@($selection.Errors) -join ' ') 'a marked row without an id is an error'
}

Add-TestCase 'B71' 'bulk delete backs up each app first and carries on past failures' {
    $backups = Join-Path $script:TempRoot ('b71-' + [guid]::NewGuid().ToString('N'))
    Set-AppStoreMock -Behaviour @{ 'a1' = 'ok'; 'a2' = 'delete-fails'; 'a3' = 'gone'; 'a4' = 'ok' }
    $apps = @((New-ExistingApp -Id 'a1' -Name 'One'), (New-ExistingApp -Id 'a2' -Name 'Two'), (New-ExistingApp -Id 'a3' -Name 'Three'), (New-ExistingApp -Id 'a4' -Name 'Four'))

    $results = @(Invoke-PDPrinterBulkDelete -Apps $apps -BackupFolder $backups -AuthContext $script:FakeAuth)

    Assert-Equal 'Deleted|DeleteFailed|AlreadyGone|Deleted' (@($results | ForEach-Object Result) -join '|') 'one outcome per app, in order'
    Assert-Like '*Delete failed*' $results[1].Error 'the failure is explained'
    Assert-True (Test-Path -LiteralPath (Join-Path $backups 'a2.json')) 'the app that failed to delete was still backed up'
    foreach ($id in @('a1', 'a4')) {
        $order = @(Get-MockCalls | Where-Object { $_.Uri -like "*/mobileApps/$id*" } | ForEach-Object { $_.Method })
        Assert-Equal 'Get|Get|Delete' ($order -join '|') "$id was read (app, assignments) before it was deleted"
    }
}

# ---------------------------------------------------------------------------
# Built-in sheet editor
# ---------------------------------------------------------------------------

Add-TestCase 'B80' 'the .csv association lookup never throws and never reports the Open With picker' {
    $program = Get-PDCsvAssociatedProgram
    Assert-True (($null -eq $program) -or (Test-Path -LiteralPath $program)) "either no program, or a real file (got '$program')"
    if ($null -ne $program) { Assert-True ((Split-Path -Leaf $program) -ine 'OpenWith.exe') 'the picker is not a program' }
    Assert-Equal $null (Get-PDCsvAssociatedProgram -Extension '.pd-no-such-extension-zz') 'an unknown extension has no program'
}

Add-TestCase 'B85' 'LibreOffice is found where it is installed, and opened with no import dialog and every column as text' {
    $fakeRoot = Join-Path $script:TempRoot ('lo-' + [guid]::NewGuid().ToString('N'))
    $fake = Join-Path $fakeRoot 'LibreOffice\program\soffice.exe'
    New-Item -ItemType Directory -Path (Split-Path $fake -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllText($fake, '')

    Assert-Equal $fake (Find-PDLibreOffice -Candidates @((Join-Path $fakeRoot 'missing.exe'), $fake)) 'the first existing candidate wins'
    Assert-Equal $null (Find-PDLibreOffice -Candidates @((Join-Path $fakeRoot 'missing.exe'), '', $null)) 'nothing installed means $null'
    $real = Find-PDLibreOffice
    Assert-True (($null -eq $real) -or (Test-Path -LiteralPath $real)) 'the standard lookup never invents a path'

    $arguments = Get-PDLibreOfficeCsvArguments -Path 'C:\Run Folder\draft.csv' -ColumnCount 3
    Assert-Equal '--calc --infilter="CSV:44,34,76,1,1/2/2/2/3/2" "C:\Run Folder\draft.csv"' $arguments 'comma, double quote, UTF-8, line 1, every column Text, quoted path'
    Assert-Like '*30/2"*' (Get-PDLibreOfficeCsvArguments -Path 'x.csv') 'enough columns for every sheet the tools write'
}

Add-TestCase 'B86' 'LibreOffice is installed as a catalog app: the entry exists and Setup installs it through the JSON app installer' {
    $catalog = Get-Content -LiteralPath (Join-Path $repoRoot 'Templates\ApplicationData_TEMPLATE.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $entry = @($catalog.Applications | Where-Object { $_.ApplicationName -eq 'LibreOffice' })
    Assert-Equal 1 $entry.Count 'exactly one LibreOffice entry in the public catalog'
    Assert-Equal 'WinGet' ([string]$entry[0].InstallMethod) 'installed through the WinGet engine'
    Assert-Equal 'TheDocumentFoundation.LibreOffice' ([string]$entry[0].WinGetID) 'with the official package id'

    $edit = @($script:SetupFunctions | Where-Object { $_.Name -eq 'Edit-PrinterBulkSheet' })[0]
    $calls = @($edit.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.Extent.Text })
    Assert-True (@($calls | Where-Object { $_ -like '& $JSONAppInstaller_ScriptPath -TargetAppName ''LibreOffice''*' }).Count -eq 1) 'Setup installs the catalog entry through the JSON app installer'
    Assert-True (@($calls | Where-Object { $_ -like '*WinGetInstallerScript*' }).Count -eq 0) 'and never calls the WinGet engine directly'
}

Add-TestCase 'B81' 'sheet <-> grid table: tick boxes become Y/N, text is trimmed, columns and order survive' {
    $rows = @(
        [pscustomobject]@{ Include = 'yes'; PrinterName = 'A'; RequiredGroups = ' IT PCs ; Techs '; Extra = 'kept' },
        [pscustomobject]@{ Include = '';    PrinterName = 'B'; RequiredGroups = '' },
        [pscustomobject]@{ Include = 'x';   PrinterName = 'C' }
    )
    $columns = @('Include', 'PrinterName', 'RequiredGroups', 'Extra')
    $table = ConvertTo-PDGridTable -Rows $rows -Columns $columns -FlagColumns @('Include')

    Assert-True ($table -is [System.Data.DataTable]) 'a DataTable comes back (not its rows)'
    Assert-Equal 'Include,PrinterName,RequiredGroups,Extra' ((@($table.Columns) | ForEach-Object ColumnName) -join ',') 'column order kept'
    Assert-True ($table.Columns['Include'].DataType -eq [bool]) 'the flag column is a tick box'
    Assert-Equal 'True,False,True' ((@($table.Rows) | ForEach-Object { $_['Include'] }) -join ',') 'Y/yes/x tick, blank does not'

    $table.Rows[1]['Include'] = $true
    $back = @(ConvertFrom-PDGridTable -Table $table -FlagColumns @('Include'))
    Assert-Equal 'Y,Y,Y' (($back | ForEach-Object Include) -join ',') 'ticks are saved as Y'
    Assert-Equal 'IT PCs ; Techs' $back[0].RequiredGroups 'text is trimmed at the ends only'
    Assert-Equal 'kept' $back[0].Extra 'an extra column survives'
    Assert-Equal '' $back[2].RequiredGroups 'a cell the row never had is empty, not null'

    $table.Rows[0]['Include'] = $false
    Assert-Equal 'N' (@(ConvertFrom-PDGridTable -Table $table -FlagColumns @('Include')))[0].Include 'an untick is saved as N'
}

Add-TestCase 'B82' 'the Find box filters across text columns and treats special characters literally' {
    $table = ConvertTo-PDGridTable -Rows @(
        [pscustomobject]@{ PrinterName = 'Lab [2]';     Location = 'Bldg A' },
        [pscustomobject]@{ PrinterName = 'O''Brien';    Location = '100% recycled' },
        [pscustomobject]@{ PrinterName = 'Lobby*Front'; Location = 'Bldg B' },
        [pscustomobject]@{ PrinterName = 'HR';          Location = 'bldg a annex' }
    ) -Columns @('PrinterName', 'Location')
    $view = New-Object System.Data.DataView ($table)
    $find = {
        param([string]$Text)
        $view.RowFilter = ConvertTo-PDGridRowFilter -Text $Text -TextColumns @('PrinterName', 'Location')
        return ((@($view) | ForEach-Object { $_['PrinterName'] }) -join '|')
    }

    Assert-Equal '' (ConvertTo-PDGridRowFilter -Text '  ' -TextColumns @('PrinterName')) 'blank search means no filter'
    Assert-Equal 'Lab [2]|HR' (& $find 'bldg a') 'case-insensitive, across every text column'
    Assert-Equal 'Lab [2]' (& $find '[2]') 'brackets are literal'
    Assert-Equal "O'Brien" (& $find "o'b") 'an apostrophe is literal'
    Assert-Equal "O'Brien" (& $find '100%') 'a percent sign is literal'
    Assert-Equal 'Lobby*Front' (& $find 'y*f') 'an asterisk is literal'
}

$script:GridReady = Test-PDGridEditorAvailable

function Invoke-GridEditorCase {
    # Runs the real window with a hook; any failure inside the hook is rethrown here instead of
    # leaving a dialog open.
    param([string]$Path, [string[]]$Messages = @(), [string[]]$Editable, [string[]]$Flags, [scriptblock]$Drive)
    $script:HookError = $null
    $hook = {
        param($ui)
        try { & $Drive $ui } catch { $script:HookError = $_ } finally { if ($ui.Form.Visible) { $ui.Cancel.PerformClick() } }
    }
    $result = Show-PDCsvGridEditor -Path $Path -Title 'test' -Instructions 'test' -EditableColumns $Editable -FlagColumns $Flags -Messages $Messages -TestHook $hook
    if ($null -ne $script:HookError) { throw $script:HookError }
    return $result
}

Add-TestCase 'B83' 'the editor window: fill groups, untick, find + tick shown, read-only columns stay put, Save writes the sheet' {
    if (-not $script:GridReady.Available) { Write-Host "      (skipped: $($script:GridReady.Reason))"; return }

    $catalog = Get-PDPrinterJsonCatalog -Path (New-TestJsonFile -Json $script:GoodJson)
    $sheet = Join-Path $script:TempRoot ('grid-' + [guid]::NewGuid().ToString('N') + '.csv')
    Write-PDBulkCsv -Rows (New-PDPrinterBulkDraft -Catalog $catalog -DeployMode 'PRODUCTION' -SourceCommit 'x') -Columns $script:PDBulk.DraftColumns -Path $sheet

    $result = Invoke-GridEditorCase -Path $sheet -Messages @('Row 3: problem one', 'Row 4: problem two') -Editable @('RequiredGroups', 'AvailableGroups') -Flags @('Include') -Drive {
        param($ui)
        $grid = $ui.Grid
        Assert-True $ui.Problems.Visible 'the previous problems are shown above the grid'
        Assert-Like '*Row 3: problem one*' $ui.Problems.Text 'with their text'
        Assert-True $grid.Columns['PrinterName'].ReadOnly 'PrinterName is locked'
        Assert-True (-not $grid.Columns['RequiredGroups'].ReadOnly) 'RequiredGroups is editable'

        # Rows are sorted by name: Alpha, Bravo, Charlie, Delta, Zulu. Select RequiredGroups for
        # Alpha and Charlie plus Alpha's PrinterName, and set them all to one value.
        $grid.ClearSelection()
        $required = $grid.Columns['RequiredGroups'].Index
        $grid.Rows[0].Cells[$required].Selected = $true
        $grid.Rows[2].Cells[$required].Selected = $true
        $grid.Rows[0].Cells[$grid.Columns['PrinterName'].Index].Selected = $true
        $ui.SetValue.Text = '  IT PCs; Techs  '
        $ui.SetApply.PerformClick()

        # Untick Zulu directly, then filter to "Delta" and tick everything shown.
        $ui.View[4]['Include'] = $false
        $ui.Find.Text = 'delta'
        Assert-Equal 1 $ui.View.Count 'Find narrows to one row'
        $ui.TickAll.PerformClick()
        $ui.Find.Text = ''
        Assert-Equal 5 $ui.View.Count 'clearing Find shows every row again'

        $ui.Save.PerformClick()
    }

    Assert-Equal 'Saved' $result.Result 'Save and continue reports Saved'
    $saved = @(Read-PDBulkCsv -Path $sheet -RequiredColumns $script:PDBulk.DraftColumns)
    Assert-Equal ($script:PDBulk.DraftColumns -join ',') ((@($saved[0].PSObject.Properties | Where-Object { $_.Name -ne 'RowNumber' }) | ForEach-Object Name) -join ',') 'the saved sheet keeps the exact columns'
    $by = @{}; foreach ($row in $saved) { $by[$row.PrinterName] = $row }
    Assert-Equal 'IT PCs; Techs' $by['Alpha-Lobby'].RequiredGroups 'Set selected cells filled Alpha (trimmed)'
    Assert-Equal 'IT PCs; Techs' $by['Charlie-Own'].RequiredGroups 'and Charlie'
    Assert-Equal '' $by['Bravo-Old'].RequiredGroups 'an unselected row is unchanged'
    Assert-True ($by.ContainsKey('Alpha-Lobby')) 'the selected read-only PrinterName was not overwritten'
    Assert-Equal 'N' $by['Zulu-Copier'].Include 'the untick was saved as N'
    Assert-Equal 'Y' $by['Delta-NoIP'].Include 'Tick all shown ticked the filtered row'
    Assert-Equal 'N' $by['Bravo-Old'].Include 'a row hidden by Find was not ticked'
}

Add-TestCase 'B84' 'closing the editor with Cancel leaves the sheet exactly as it was' {
    if (-not $script:GridReady.Available) { Write-Host "      (skipped: $($script:GridReady.Reason))"; return }

    $apps = @((New-ExistingApp -Id 'a1' -Name 'One'), (New-ExistingApp -Id 'a2' -Name 'Two'))
    $sheet = Join-Path $script:TempRoot ('grid-del-' + [guid]::NewGuid().ToString('N') + '.csv')
    Write-PDBulkCsv -Rows (New-PDPrinterDeleteSheet -Apps $apps) -Columns $script:PDBulk.DeleteColumns -Path $sheet
    $before = [System.IO.File]::ReadAllBytes($sheet)

    $result = Invoke-GridEditorCase -Path $sheet -Editable @() -Flags @('Delete') -Drive {
        param($ui)
        Assert-True (-not $ui.Problems.Visible) 'no problems panel on a first open'
        Assert-True $ui.Grid.Columns['AppId'].ReadOnly 'AppId is locked'
        $ui.TickAll.PerformClick()
        Assert-Like '*2 ticked (Delete)*' $ui.Status.Text 'the status line counts ticks'
        $ui.Cancel.PerformClick()
    }

    Assert-Equal 'Cancelled' $result.Result 'Cancel reports Cancelled'
    Assert-Equal ([Convert]::ToBase64String($before)) ([Convert]::ToBase64String([System.IO.File]::ReadAllBytes($sheet))) 'the file was not touched'
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

foreach ($case in $script:Cases) {
    $script:PDGraph.TestTransport = $script:Tripwire
    $script:Calls = @()
    try {
        & $case.Body | Out-Null
        $script:Passed++
        Write-Host ("PASS  {0,-6} {1}" -f $case.Id, $case.Name) -ForegroundColor DarkGreen
    } catch {
        $script:Failures += @{ Id = $case.Id; Name = $case.Name; Reason = $_.Exception.Message; Site = $_.InvocationInfo.PositionMessage }
        Write-Host ("FAIL  {0,-6} {1}" -f $case.Id, $case.Name) -ForegroundColor Red
        Write-Host ("      {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    }
}
$script:PDGraph.TestTransport = $null

if (-not $KeepTemp) {
    try { Remove-Item -LiteralPath $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { }
} else {
    Write-Host "Temp kept at $script:TempRoot"
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
