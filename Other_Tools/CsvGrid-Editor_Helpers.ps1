<#

.SYNOPSIS
    How the bulk printer CSVs get edited on a PC with no program for .csv files (common on admin VMs
    without Office): finding / launching LibreOffice Calc, and a small built-in spreadsheet window used
    when LibreOffice is declined.

.DESCRIPTION
    Built on WinForms (DataGridView), which ships with Windows and .NET Framework, so nothing is
    downloaded or installed. The window:
      - shows every column, with only the editable ones unlocked (the rest are grey);
      - shows yes/no columns (Include, Delete) as tick boxes, saved back as Y / N;
      - has Find (filters rows across all columns), Tick all / Untick all for the rows shown, and
        "Set selected cells to" for filling many group cells at once;
      - pastes a block copied from Excel or Notepad (Ctrl+V) into the editable cells from the
        current cell down/right;
      - writes the CSV with Write-PDBulkCsv (same format the rest of the tool reads) only when
        "Save and continue" is pressed.

    The data conversion (ConvertTo-PDGridTable / ConvertFrom-PDGridTable) has no UI and is tested
    offline; the window itself has a test hook that drives it without a person.

    This file may be dot-sourced: functions only, no top-level param() block, no output, no side
    effects at import. WinForms is loaded only when a window is actually shown. Needs
    Other_Tools\Printer-IntuneBulk.ps1 (Read-PDBulkCsv / Write-PDBulkCsv / Test-PDBulkYes).

.LINK
    .claude/plans/printer-bulk-tools.buildplan.md

#>

function Get-PDCsvAssociatedProgram {
    <#
        .SYNOPSIS
        The program Windows would open a .csv file with, or $null when there is none. Never throws.

        .DESCRIPTION
        Asks the shell itself (AssocQueryString) rather than reading the registry, because the shell
        is what Start-Process uses. ASSOCF_INIT_IGNOREUNKNOWN keeps the "How do you want to open
        this file?" picker (OpenWith.exe) from counting as a program.
    #>
    param([string]$Extension = '.csv')

    try {
        if (-not ('PowerDeploy.ShellAssoc' -as [type])) {
            Add-Type -Namespace 'PowerDeploy' -Name 'ShellAssoc' -MemberDefinition @'
[DllImport("shlwapi.dll", CharSet = CharSet.Unicode)]
public static extern uint AssocQueryString(uint flags, uint str, string pszAssoc, string pszExtra, System.Text.StringBuilder pszOut, ref uint pcchOut);
'@
        }

        $ASSOCF_INIT_IGNOREUNKNOWN = 0x400
        $ASSOCSTR_EXECUTABLE       = 2
        $size = [uint32]1024
        $buffer = New-Object System.Text.StringBuilder ([int]$size)
        $hr = [PowerDeploy.ShellAssoc]::AssocQueryString($ASSOCF_INIT_IGNOREUNKNOWN, $ASSOCSTR_EXECUTABLE, $Extension, $null, $buffer, [ref]$size)
        if ($hr -ne 0) { return $null }

        $exe = $buffer.ToString()
        if ([string]::IsNullOrWhiteSpace($exe)) { return $null }
        if ((Split-Path -Leaf $exe) -ieq 'OpenWith.exe') { return $null }
        return $exe
    } catch {
        return $null
    }
}

function Find-PDLibreOffice {
    <#
        .SYNOPSIS
        Path to LibreOffice's soffice.exe, or $null when it is not installed. Never throws.

        .DESCRIPTION
        The bulk tools offer LibreOffice Calc (WinGet: TheDocumentFoundation.LibreOffice) when this PC
        has no program for .csv files. -Candidates replaces the standard locations (tests).
    #>
    param([AllowNull()][string[]]$Candidates)

    try {
        if ($null -eq $Candidates) {
            $Candidates = @()
            foreach ($root in @($env:ProgramFiles, $env:ProgramW6432, ${env:ProgramFiles(x86)})) {
                if (-not [string]::IsNullOrWhiteSpace($root)) { $Candidates += (Join-Path $root 'LibreOffice\program\soffice.exe') }
            }
            try {
                $registered = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\soffice.exe' -ErrorAction Stop).'(default)'
                if (-not [string]::IsNullOrWhiteSpace($registered)) { $Candidates += $registered.Trim().Trim('"') }
            } catch { }
        }

        foreach ($candidate in @($Candidates)) {
            if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $candidate }
        }
    } catch { }

    return $null
}

function Get-PDLibreOfficeCsvArguments {
    <#
        .SYNOPSIS
        The soffice.exe command line that opens a sheet straight into Calc with no import dialog.

        .DESCRIPTION
        --infilter "CSV:44,34,76,1,<formats>": comma separated (44), double-quoted text (34), UTF-8
        (76), starting at line 1, and every column imported as Text (n/2), so Calc never reformats a
        value - an IP, a leading zero, or a group named like a number or a date stays exactly as
        written. Saving keeps the same options.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateRange(1, 200)][int]$ColumnCount = 30
    )

    $formats = (1..$ColumnCount | ForEach-Object { '{0}/2' -f $_ }) -join '/'
    return ('--calc --infilter="CSV:44,34,76,1,{0}" "{1}"' -f $formats, $Path)
}

function Test-PDGridEditorAvailable {
    <#
        .SYNOPSIS
        Whether a WinForms window can be shown in this session. Returns { Available; Reason }.
        WinForms needs a single-threaded apartment (Windows PowerShell 5.1's console is STA by
        default) and the Windows desktop (absent on Server Core).
    #>
    $state = [System.Threading.Thread]::CurrentThread.GetApartmentState()
    if ($state -ne [System.Threading.ApartmentState]::STA) {
        return [pscustomobject]@{ Available = $false; Reason = "this PowerShell session runs in $state mode; the editor window needs STA (run Setup with Windows PowerShell 5.1 or pwsh -STA)" }
    }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    } catch {
        return [pscustomobject]@{ Available = $false; Reason = ("Windows Forms is not available here ({0})" -f $_.Exception.Message) }
    }
    if (-not [System.Windows.Forms.SystemInformation]::UserInteractive) {
        return [pscustomobject]@{ Available = $false; Reason = 'this session has no interactive desktop' }
    }
    return [pscustomobject]@{ Available = $true; Reason = '' }
}

function ConvertTo-PDGridTable {
    <#
        .SYNOPSIS
        CSV rows -> System.Data.DataTable for the grid. Flag columns become booleans (tick boxes);
        everything else is text. Columns keep the given order; a column a row lacks is empty.
    #>
    param(
        [AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory = $true)][string[]]$Columns,
        [AllowEmptyCollection()][string[]]$FlagColumns = @()
    )

    $table = New-Object System.Data.DataTable 'Sheet'
    foreach ($column in $Columns) {
        $type = [string]
        if ($FlagColumns -contains $column) { $type = [bool] }
        $null = $table.Columns.Add($column, $type)
    }

    foreach ($row in @($Rows)) {
        $dataRow = $table.NewRow()
        foreach ($column in $Columns) {
            $value = Get-PDBulkCell -Row $row -Name $column
            if ($FlagColumns -contains $column) { $dataRow[$column] = [bool](Test-PDBulkYes -Value $value) }
            else { $dataRow[$column] = [string]$value }
        }
        $table.Rows.Add($dataRow)
    }

    $table.AcceptChanges()
    return ,$table
}

function ConvertFrom-PDGridTable {
    <#
        .SYNOPSIS
        DataTable -> CSV rows (PSCustomObject, columns in order). Ticked flags become 'Y', unticked
        become 'N'; text is trimmed. Rows the grid has marked deleted are left out.
    #>
    param(
        [Parameter(Mandatory = $true)][System.Data.DataTable]$Table,
        [AllowEmptyCollection()][string[]]$FlagColumns = @()
    )

    $rows = @()
    foreach ($dataRow in $Table.Rows) {
        if ($dataRow.RowState -eq [System.Data.DataRowState]::Deleted) { continue }
        $out = [ordered]@{}
        foreach ($column in $Table.Columns) {
            $name  = $column.ColumnName
            $value = $dataRow[$name]
            if ($FlagColumns -contains $name) {
                $out[$name] = $(if (($value -isnot [System.DBNull]) -and [bool]$value) { 'Y' } else { 'N' })
            } elseif ($value -is [System.DBNull] -or $null -eq $value) {
                $out[$name] = ''
            } else {
                $out[$name] = ([string]$value).Trim()
            }
        }
        $rows += [pscustomobject]$out
    }
    return $rows
}

function ConvertTo-PDGridRowFilter {
    <#
        .SYNOPSIS
        A DataView RowFilter matching rows where any text column contains the search text
        (case-insensitive), with the filter language's special characters escaped. '' for no filter.
    #>
    param([AllowNull()][string]$Text, [Parameter(Mandatory = $true)][string[]]$TextColumns)

    if ([string]::IsNullOrWhiteSpace($Text) -or @($TextColumns).Count -eq 0) { return '' }

    $escaped = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.Trim().ToCharArray()) {
        if ('*%[]'.IndexOf($ch) -ge 0) { $null = $escaped.Append('[').Append($ch).Append(']') }
        elseif ($ch -eq "'") { $null = $escaped.Append("''") }
        else { $null = $escaped.Append($ch) }
    }
    $pattern = $escaped.ToString()

    $parts = foreach ($column in $TextColumns) { "[{0}] LIKE '*{1}*'" -f $column.Replace(']', '\]'), $pattern }
    return ($parts -join ' OR ')
}

function Show-PDCsvGridEditor {
    <#
        .SYNOPSIS
        Opens the sheet in the built-in editor window and waits for it to close.

        .PARAMETER EditableColumns
        Columns the operator may change. Every other column is read-only (grey).

        .PARAMETER FlagColumns
        Yes/no columns shown as tick boxes and saved as Y / N. Implicitly editable.

        .PARAMETER Messages
        Problems from the previous check, shown in red above the grid so they can be fixed in place.

        .PARAMETER TestHook
        Tests only: called with a hashtable of the window's controls once it is shown, to drive it without a
        person. The hook is responsible for closing the window.

        .OUTPUTS
        { Result = Saved | Cancelled | Unavailable; Reason }
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Title = 'PowerDeploy - edit sheet',
        [string]$Instructions = '',
        [AllowEmptyCollection()][string[]]$EditableColumns = @(),
        [AllowEmptyCollection()][string[]]$FlagColumns = @(),
        [AllowEmptyCollection()][string[]]$Messages = @(),
        # A read-only column worth reading (shown in red, next to the editable ones), e.g. Problem.
        [string]$HighlightColumn = 'Problem',
        [AllowNull()][scriptblock]$TestHook
    )

    $outcome = [pscustomobject]@{ Result = 'Cancelled'; Reason = '' }

    $ready = Test-PDGridEditorAvailable
    if (-not $ready.Available) { $outcome.Result = 'Unavailable'; $outcome.Reason = $ready.Reason; return $outcome }

    # --- data ---------------------------------------------------------------------------------
    $text = [System.IO.File]::ReadAllText($Path)
    $headerLine = ($text -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    if (-not $headerLine) { $outcome.Result = 'Unavailable'; $outcome.Reason = 'the sheet is empty'; return $outcome }
    $columns = @(($headerLine | ConvertFrom-Csv -Header (1..200 | ForEach-Object { "c$_" })).PSObject.Properties |
                 Where-Object { $null -ne $_.Value -and -not [string]::IsNullOrWhiteSpace([string]$_.Value) } |
                 ForEach-Object { ([string]$_.Value).Trim() } | Select-Object -Unique)

    $rows = @(Read-PDBulkCsv -Path $Path -RequiredColumns @($columns[0]))
    $flags = @($FlagColumns | Where-Object { $columns -contains $_ })
    $table = ConvertTo-PDGridTable -Rows $rows -Columns $columns -FlagColumns $flags
    $view  = New-Object System.Data.DataView ($table)
    $textColumns = @($columns | Where-Object { $flags -notcontains $_ })
    $editable = @(@($EditableColumns) + @($flags) | Where-Object { $columns -contains $_ } | Select-Object -Unique)

    # --- window -------------------------------------------------------------------------------
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Size = New-Object System.Drawing.Size(1200, 760)
    $form.MinimumSize = New-Object System.Drawing.Size(700, 400)
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form.KeyPreview = $true

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'
    $layout.ColumnCount = 1
    $layout.RowCount = 5
    $layout.Padding = New-Object System.Windows.Forms.Padding(8)
    foreach ($style in @('AutoSize', 'AutoSize', 'AutoSize', 'Percent', 'AutoSize')) {
        if ($style -eq 'Percent') { $null = $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) }
        else { $null = $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) }
    }
    $form.Controls.Add($layout)

    $help = New-Object System.Windows.Forms.Label
    $help.AutoSize = $true
    $help.MaximumSize = New-Object System.Drawing.Size(1150, 0)
    $help.Text = $Instructions
    $help.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
    $layout.Controls.Add($help, 0, 0)

    $problems = New-Object System.Windows.Forms.Label
    $problems.AutoSize = $true
    $problems.MaximumSize = New-Object System.Drawing.Size(1150, 0)
    $problems.ForeColor = [System.Drawing.Color]::Firebrick
    $problems.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
    $shownMessages = @($Messages | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($shownMessages.Count -gt 0) {
        $listed = @($shownMessages | Select-Object -First 12 | ForEach-Object { '- ' + $_ })
        if ($shownMessages.Count -gt 12) { $listed += ('...and {0} more (see the console)' -f ($shownMessages.Count - 12)) }
        $problems.Text = ("Fix these, then press Save and continue:`r`n" + ($listed -join "`r`n"))
    } else {
        $problems.Visible = $false
    }
    $layout.Controls.Add($problems, 0, 1)

    $tools = New-Object System.Windows.Forms.FlowLayoutPanel
    $tools.AutoSize = $true
    $tools.WrapContents = $true
    $tools.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 4)
    $layout.Controls.Add($tools, 0, 2)

    $newLabel = {
        param([string]$Caption)
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $Caption
        $label.AutoSize = $true
        $label.Margin = New-Object System.Windows.Forms.Padding(0, 7, 4, 0)
        return $label
    }

    $tools.Controls.Add((& $newLabel 'Find:'))
    $find = New-Object System.Windows.Forms.TextBox
    $find.Width = 220
    $tools.Controls.Add($find)

    $tickAll = New-Object System.Windows.Forms.Button
    $tickAll.AutoSize = $true
    $untickAll = New-Object System.Windows.Forms.Button
    $untickAll.AutoSize = $true
    if ($flags.Count -gt 0) {
        $tickAll.Text   = ('Tick all shown ({0})' -f $flags[0])
        $untickAll.Text = ('Untick all shown ({0})' -f $flags[0])
        $tickAll.Margin = New-Object System.Windows.Forms.Padding(16, 3, 3, 3)
        $tools.Controls.Add($tickAll)
        $tools.Controls.Add($untickAll)
    }

    $setValue = New-Object System.Windows.Forms.TextBox
    $setValue.Width = 260
    $setApply = New-Object System.Windows.Forms.Button
    $setApply.Text = 'Apply'
    $setApply.AutoSize = $true
    if (@($editable | Where-Object { $flags -notcontains $_ }).Count -gt 0) {
        $setLabel = & $newLabel 'Set selected cells to:'
        $setLabel.Margin = New-Object System.Windows.Forms.Padding(16, 7, 4, 0)
        $tools.Controls.Add($setLabel)
        $tools.Controls.Add($setValue)
        $tools.Controls.Add($setApply)
    }

    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AllowUserToOrderColumns = $false
    $grid.SelectionMode = 'CellSelect'
    $grid.MultiSelect = $true
    $grid.RowHeadersWidth = 28
    $grid.AutoSizeColumnsMode = 'None'
    $grid.ClipboardCopyMode = 'EnableWithoutHeaderText'
    $grid.EditMode = 'EditOnKeystrokeOrF2'
    $grid.DataSource = $view
    $layout.Controls.Add($grid, 0, 3)

    $bottom = New-Object System.Windows.Forms.FlowLayoutPanel
    $bottom.AutoSize = $true
    $bottom.Dock = 'Fill'
    $bottom.FlowDirection = 'RightToLeft'
    $layout.Controls.Add($bottom, 0, 4)

    $save = New-Object System.Windows.Forms.Button
    $save.Text = 'Save and continue'
    $save.AutoSize = $true
    $save.Padding = New-Object System.Windows.Forms.Padding(8, 2, 8, 2)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'
    $cancel.AutoSize = $true
    $status = New-Object System.Windows.Forms.Label
    $status.AutoSize = $true
    $status.Margin = New-Object System.Windows.Forms.Padding(0, 8, 24, 0)
    $bottom.Controls.Add($save)
    $bottom.Controls.Add($cancel)
    $bottom.Controls.Add($status)

    # --- behaviour ----------------------------------------------------------------------------
    $state = @{ Saved = $false; Columns = $columns; Flags = $flags; Editable = $editable }

    $updateStatus = {
        $shown = $view.Count
        $text = '{0} row(s)' -f $table.Rows.Count
        if ($shown -ne $table.Rows.Count) { $text += (', {0} shown' -f $shown) }
        if ($state.Flags.Count -gt 0) {
            $ticked = @($table.Rows | Where-Object { ($_[$state.Flags[0]] -isnot [System.DBNull]) -and [bool]$_[$state.Flags[0]] }).Count
            $text += (', {0} ticked ({1})' -f $ticked, $state.Flags[0])
        }
        $status.Text = $text
    }

    # On screen (the saved file keeps its own order): tick boxes, then the key column, then the
    # editable columns, then the highlight column, then the rest - so what the operator changes,
    # and why a row was unticked, are visible without scrolling right.
    $displayOrder = @()
    $displayOrder += @($columns | Where-Object { $flags -contains $_ })
    $displayOrder += @($columns | Where-Object { $flags -notcontains $_ } | Select-Object -First 1)
    $displayOrder += @($columns | Where-Object { $editable -contains $_ -and $displayOrder -notcontains $_ })
    if ($columns -contains $HighlightColumn -and $displayOrder -notcontains $HighlightColumn) { $displayOrder += $HighlightColumn }
    $displayOrder += @($columns | Where-Object { $displayOrder -notcontains $_ })
    $state.DisplayOrder = $displayOrder
    $state.Highlight = $HighlightColumn

    $styleColumns = {
        foreach ($gridColumn in $grid.Columns) {
            $name = $gridColumn.DataPropertyName
            $gridColumn.SortMode = 'Automatic'
            $gridColumn.DisplayIndex = [array]::IndexOf([object[]]$state.DisplayOrder, $name)
            if ($state.Editable -contains $name) {
                $gridColumn.ReadOnly = $false
                $gridColumn.HeaderCell.Style.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
            } else {
                $gridColumn.ReadOnly = $true
                $gridColumn.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
                $gridColumn.DefaultCellStyle.ForeColor = [System.Drawing.Color]::FromArgb(70, 70, 70)
            }
            if ($name -eq $state.Highlight) { $gridColumn.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Firebrick }
            if ($state.Flags -contains $name) { $gridColumn.Width = 70 }
            elseif ($state.Editable -contains $name) { $gridColumn.Width = 240 }
            else {
                # Fit the content, but never so wide that one long column pushes the rest off screen.
                $gridColumn.Width = [math]::Max(60, [math]::Min(320, $gridColumn.GetPreferredWidth([System.Windows.Forms.DataGridViewAutoSizeColumnMode]::AllCells, $true)))
            }
        }
    }

    $setCell = {
        param($DataRowView, [string]$Column, [string]$Value)
        if ($state.Editable -notcontains $Column) { return $false }
        if ($state.Flags -contains $Column) { $DataRowView[$Column] = [bool](Test-PDBulkYes -Value $Value) }
        else { $DataRowView[$Column] = $Value.Trim() }
        return $true
    }

    $grid.Add_DataBindingComplete({ & $styleColumns; & $updateStatus })

    # Tick boxes commit at once, so the ticked count and filters see the change immediately.
    $grid.Add_CurrentCellDirtyStateChanged({
        if ($grid.IsCurrentCellDirty -and ($grid.CurrentCell -is [System.Windows.Forms.DataGridViewCheckBoxCell])) {
            $null = $grid.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit)
        }
    })
    $grid.Add_CellValueChanged({ & $updateStatus })
    $grid.Add_DataError({ param($sender, $e) $e.ThrowException = $false })

    $find.Add_TextChanged({
        $null = $grid.EndEdit()
        $view.RowFilter = ConvertTo-PDGridRowFilter -Text $find.Text -TextColumns $textColumns
        & $updateStatus
    })

    $markShown = {
        param([bool]$Value)
        $null = $grid.EndEdit()
        foreach ($rowView in @($view)) { $rowView[$state.Flags[0]] = $Value }
        $grid.Refresh()
        & $updateStatus
    }
    $tickAll.Add_Click({ & $markShown $true })
    $untickAll.Add_Click({ & $markShown $false })

    $setApply.Add_Click({
        $null = $grid.EndEdit()
        $changed = 0; $skipped = 0
        foreach ($cell in @($grid.SelectedCells)) {
            $column = $grid.Columns[$cell.ColumnIndex].DataPropertyName
            if (& $setCell $view[$cell.RowIndex] $column $setValue.Text) { $changed++ } else { $skipped++ }
        }
        $grid.Refresh()
        & $updateStatus
        if ($changed -eq 0) {
            [void][System.Windows.Forms.MessageBox]::Show($form, 'Select one or more cells in an editable (white) column first.', 'Set selected cells', 'OK', 'Information')
        }
    })

    # Ctrl+V outside a cell edit pastes a block (tab-separated columns, one line per row) from the
    # current cell, into editable cells only.
    $grid.Add_KeyDown({
        param($sender, $e)
        if (-not ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::V)) { return }
        if ($grid.IsCurrentCellInEditMode -or $null -eq $grid.CurrentCell) { return }
        $clip = [System.Windows.Forms.Clipboard]::GetText()
        if ([string]::IsNullOrEmpty($clip)) { return }
        $lines = @($clip -split "`r?`n")
        if ($lines.Count -gt 1 -and $lines[-1] -eq '') { $lines = $lines[0..($lines.Count - 2)] }
        $startRow = $grid.CurrentCell.RowIndex
        $startCol = $grid.CurrentCell.ColumnIndex
        for ($r = 0; $r -lt $lines.Count -and ($startRow + $r) -lt $view.Count; $r++) {
            $cells = $lines[$r] -split "`t"
            for ($c = 0; $c -lt $cells.Count -and ($startCol + $c) -lt $grid.Columns.Count; $c++) {
                $null = & $setCell $view[$startRow + $r] $grid.Columns[$startCol + $c].DataPropertyName $cells[$c]
            }
        }
        $grid.Refresh()
        & $updateStatus
        $e.Handled = $true
    })

    $save.Add_Click({
        $null = $grid.EndEdit()
        $form.BindingContext[$view].EndCurrentEdit()
        try {
            $out = ConvertFrom-PDGridTable -Table $table -FlagColumns $state.Flags
            Write-PDBulkCsv -Rows $out -Columns $state.Columns -Path $Path
            $state.Saved = $true
            $form.Close()
        } catch {
            [void][System.Windows.Forms.MessageBox]::Show($form, ("The sheet could not be saved: {0}`r`n`r`nIf it is open in another program, close it and press Save again." -f $_.Exception.Message), 'Save failed', 'OK', 'Error')
        }
    })

    $cancel.Add_Click({ $form.Close() })

    $form.Add_FormClosing({
        param($sender, $e)
        if ($state.Saved -or $state.ContainsKey('Testing')) { return }
        if ($null -eq $table.GetChanges()) { return }
        $answer = [System.Windows.Forms.MessageBox]::Show($form, 'Close without saving your changes?', 'Unsaved changes', 'YesNo', 'Warning')
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { $e.Cancel = $true }
    })

    # Bring the window in front of the console it was started from.
    $form.Add_Shown({
        $form.TopMost = $true
        $form.Activate()
        $form.TopMost = $false
        if ($null -ne $TestHook) {
            $state['Testing'] = $true
            & $TestHook @{ Form = $form; Grid = $grid; Table = $table; View = $view; Save = $save; Cancel = $cancel; Find = $find; SetValue = $setValue; SetApply = $setApply; TickAll = $tickAll; UntickAll = $untickAll; Problems = $problems; Status = $status }
        }
    })

    try {
        [void]$form.ShowDialog()
    } finally {
        $form.Dispose()
    }

    if ($state.Saved) { $outcome.Result = 'Saved' }
    return $outcome
}
