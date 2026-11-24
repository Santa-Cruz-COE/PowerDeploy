<#

.SYNOPSIS
    Behavioural tests for the organization registry Intune Platform Script: the generator
    (Generate_Install-Command.ps1 OrgRegistryPlatformScript), the template
    (Templates\OrgRegistry-PlatformScript_TEMPLATE.ps1) and the shared naming helpers
    (Other_Tools\OrgRegistry-Intune_Helpers.ps1).

.DESCRIPTION
    Same dependency-free harness as Tests\IntuneGraphUpload.Tests.ps1 / Tests\PrinterIntuneBulk.Tests.ps1.
    No Graph, Entra or network call is made.

        powershell -NoProfile -ExecutionPolicy Bypass -File Tests\OrgRegistryPlatformScript.Tests.ps1
        pwsh       -NoProfile -ExecutionPolicy Bypass -File Tests\OrgRegistryPlatformScript.Tests.ps1

    Exit code 0 = every case that ran passed. A SKIPPED case is reported as skipped, never as passed.

    Registry use:
      - HKCU\SOFTWARE\PowerDeploy-Test-<guid>... keys (any user) exercise the template's ACL and value
        functions; they are deleted in finally blocks.
      - The end-to-end case runs ONLY when elevated: it stamps HKLM\SOFTWARE\PowerDeploy-Test-<guid>,
        runs the generated script in 64-bit Windows PowerShell, checks values, exit code and ACLs, and
        deletes the test key in finally. Not elevated = SKIPPED.
      - The real HKLM\SOFTWARE\PowerDeploy is never opened for writing; the generator refuses any
        root other than it or SOFTWARE\PowerDeploy-Test-<guid>, and every script this suite runs is
        stamped with a test root.

    The generator writes its usual log under <repo parent>\Logs\Generator_Logs (a handful of small
    files per run, containing only the fake values below).

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
$script:Skipped  = @()
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

# A case calls this to report SKIPPED (counted separately, never as passed).
function Skip-TestCase {
    param([string]$Reason)
    throw "PDTEST-SKIP: $Reason"
}

# ---------------------------------------------------------------------------
# Paths and fixtures
# ---------------------------------------------------------------------------

$repoRoot      = Split-Path $PSScriptRoot -Parent
$generatorPath = Join-Path $repoRoot 'Other_Tools\Generate_Install-Command.ps1'
$helpersPath   = Join-Path $repoRoot 'Other_Tools\OrgRegistry-Intune_Helpers.ps1'
$templatePath  = Join-Path $repoRoot 'Templates\OrgRegistry-PlatformScript_TEMPLATE.ps1'
$configRegPath = Join-Path $repoRoot 'Configurators\Configure-Registry.ps1'

foreach ($path in @($generatorPath, $helpersPath, $templatePath, $configRegPath)) {
    if (-not (Test-Path -LiteralPath $path)) { Write-Host "FATAL: $path not found"; exit 2 }
}

$script:TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('PowerDeploy-OrgRegTests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null

$script:IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# 64-bit Windows PowerShell 5.1: the host Intune runs the platform script in.
$script:WinPS64 = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not [Environment]::Is64BitProcess) { $script:WinPS64 = "$env:SystemRoot\Sysnative\WindowsPowerShell\v1.0\powershell.exe" }

Write-Host "================================================================"
Write-Host " OrgRegistryPlatformScript tests"
Write-Host " Engine   : PowerShell $($PSVersionTable.PSVersion)"
Write-Host " Elevated : $script:IsElevated"
Write-Host " Temp     : $script:TempRoot"
Write-Host "================================================================"
Write-Host ""

# Import purity is checked before the real import, in a throwaway scope.
$script:ImportOutput = @(& { . $helpersPath })
$script:FunctionsBefore = @(Get-ChildItem function: | ForEach-Object Name)
. $helpersPath
$script:HelperFunctions = @(Get-ChildItem function: | ForEach-Object Name | Where-Object { $script:FunctionsBefore -notcontains $_ })

# Distinctive fake values (at least 10 characters each) so "does this value appear anywhere?" has
# no false positives. Every awkward character class the embedding must survive is here.
$script:TrickyValues = [ordered]@{
    StorageAccountName         = 'acct' + [char]0x00E9 + 'Tst_9q7Z'
    PrinterDataJSONpath        = 'prn/' + "it's" + '$(Get-Date)`n_Pq3.json'
    PrinterContainerSASkey     = 'sv=2024&sig=AbC+/=' + [char]0x2018 + 'x' + [char]0x2019 + [char]0x201A + [char]0x201B + "'" + '"$env:X`"_K1'
    ApplicationDataJSONpath    = 'app/[bracket]"dq"' + [char]0x00FC + 'Zz8.json'
    ApplicationContainerSASkey = '$null;exit 0;#x' + "`r`n" + 'line2 ``tab' + "`t" + '_K2' + [char]0x4E2D
    CustomRepoURL              = 'https://user@host/o' + "''" + 'r/$x`y_U7'
    CustomRepoToken            = ''
}

$script:Generated = @{}

# Runs the generator exactly as Setup.ps1 does, with the test-only output folder (and root when given).
function Invoke-PDGenerator {
    param(
        [Parameter(Mandatory = $true)][hashtable]$FunctionParams,
        [string]$WorkingDirectory = (Join-Path $script:TempRoot 'wd')
    )
    $ErrorActionPreference = 'Continue'
    $outDir = Join-Path $script:TempRoot ('out-' + [guid]::NewGuid().ToString('N'))
    $params = @{} + $FunctionParams
    if (-not $params.ContainsKey('OutputDirectory')) { $params['OutputDirectory'] = $outDir }
    $global:LASTEXITCODE = 0
    $all = @(& $generatorPath -DesiredFunction 'OrgRegistryPlatformScript' -RepoURL 'github.com/example/none' -RepoNickName 'PowerDeploy-Repo' -RepoBranch 'dev' -TargetWorkingDirectory $WorkingDirectory -FunctionParams $params *>&1)
    $exit = $global:LASTEXITCODE
    $result = $all | Where-Object { $_ -is [hashtable] } | Select-Object -Last 1
    $text = @($all | Where-Object { $_ -isnot [hashtable] } | ForEach-Object { [string]$_ })
    return @{ Exit = $exit; Result = $result; Text = $text; OutDir = $params['OutputDirectory'] }
}

function New-PDTestRoot { return ('SOFTWARE\PowerDeploy-Test-' + [guid]::NewGuid().ToString()) }

# The text between the stamp markers of a generated script.
function Get-PDStampBlock {
    param([Parameter(Mandatory = $true)][string]$Content)
    $begin = $Content.IndexOf('#__PD_STAMP_BEGIN__', [System.StringComparison]::Ordinal)
    $end   = $Content.IndexOf('#__PD_STAMP_END__', [System.StringComparison]::Ordinal)
    if (($begin -lt 0) -or ($end -le $begin)) { throw 'stamp markers not found' }
    return $Content.Substring($begin, $end - $begin)
}

# Template functions, loaded from the template's own AST so the tests exercise the shipped code.
$script:TemplateAst = [System.Management.Automation.Language.Parser]::ParseFile($templatePath, [ref]$null, [ref]$null)
foreach ($fn in @('New-PDStrictRegistrySecurity', 'Test-PDStrictRegistrySecurity', 'Test-PDStrictKeyAcl', 'Set-PDStrictKey', 'Set-PDOrgValue', 'Test-PDOrgValue')) {
    $def = @($script:TemplateAst.FindAll({ param($n) ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and ($n.Name -ceq $fn) }, $true))
    if ($def.Count -ne 1) { Write-Host "FATAL: template function $fn not found exactly once"; exit 2 }
    . ([scriptblock]::Create($def[0].Extent.Text))
}

# Configure-Registry.ps1's own Set-StrictRegAcl (with Get-RegistryKeyWithView) to make reference keys,
# and the RegistrySecurity its Set-StrictRegAcl builds.
$script:ConfigAst = [System.Management.Automation.Language.Parser]::ParseFile($configRegPath, [ref]$null, [ref]$null)
foreach ($fn in @('Get-RegistryKeyWithView', 'Set-StrictRegAcl')) {
    $def = @($script:ConfigAst.FindAll({ param($n) ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and ($n.Name -ceq $fn) }, $true))
    if ($def.Count -ne 1) { Write-Host "FATAL: Configure-Registry function $fn not found exactly once"; exit 2 }
    . ([scriptblock]::Create($def[0].Extent.Text))
}
$setStrictText = @($script:ConfigAst.FindAll({ param($n) ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and ($n.Name -ceq 'Set-StrictRegAcl') }, $true))[0].Extent.Text
$sbStart = $setStrictText.IndexOf('$regSec = New-Object System.Security.AccessControl.RegistrySecurity', [System.StringComparison]::Ordinal)
$sbEnd   = $setStrictText.IndexOf('$subKey.SetAccessControl($regSec)', [System.StringComparison]::Ordinal)
if (($sbStart -lt 0) -or ($sbEnd -le $sbStart)) { Write-Host "FATAL: could not find the ACL construction in Set-StrictRegAcl"; exit 2 }
$script:SetStrictRegAclBuilder = [scriptblock]::Create($setStrictText.Substring($sbStart, $sbEnd - $sbStart) + "`n" + '$regSec')

# One stub Write-Log for every extracted function.
$script:LogLines = @()
function Write-Log { param([string]$Message, [string]$Level = 'INFO') $script:LogLines += "[$Level] $Message" }

# Configure-Registry.ps1's Test-StrictRegAcl, run in Windows PowerShell 5.1: the engine Git-Runner and
# Security Manager run it in. (Under PowerShell 7 its $acl.Access is empty for a RegistrySecurity, so
# it can never pass there; calling it in-process from pwsh would test the wrong thing.)
# Returns one bool per key path, in order.
function Invoke-PDTestStrictRegAcl51 {
    param([Parameter(Mandatory = $true)][string[]]$KeyPaths)
    $runner = Join-Path $script:TempRoot 'Run-TestStrictRegAcl.ps1'
    if (-not (Test-Path -LiteralPath $runner)) {
        $code = @(
            'param([string]$ConfigRegPath, [string]$KeyPathList)'
            '$ast = [System.Management.Automation.Language.Parser]::ParseFile($ConfigRegPath, [ref]$null, [ref]$null)'
            'foreach ($fn in @(''Get-RegistryKeyWithView'', ''Test-StrictRegAcl'')) {'
            '    $def = @($ast.FindAll({ param($n) ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and ($n.Name -ceq $fn) }, $true))'
            '    . ([scriptblock]::Create($def[0].Extent.Text))'
            '}'
            'function Write-Log { param([string]$Message, [string]$Level) }'
            'foreach ($KeyPath in ($KeyPathList -split ''\|'')) { ''RESULT:'' + [string](Test-StrictRegAcl) }'
        ) -join "`r`n"
        [System.IO.File]::WriteAllText($runner, $code, (New-Object System.Text.UTF8Encoding($false)))
    }
    $out = @(& $script:WinPS64 -NoProfile -ExecutionPolicy Bypass -File $runner -ConfigRegPath $configRegPath -KeyPathList ($KeyPaths -join '|') 2>&1 | ForEach-Object { [string]$_ })
    $results = @($out | Where-Object { $_ -like 'RESULT:*' } | ForEach-Object { $_.Substring(7) -eq 'True' })
    if ($results.Count -ne $KeyPaths.Count) { throw ("Test-StrictRegAcl runner returned {0} result(s) for {1} key(s): {2}" -f $results.Count, $KeyPaths.Count, ($out -join ' | ')) }
    return ,$results
}

# HKCU test keys: make deletable again (the strict ACL may exclude this user), then delete.
function Remove-PDTestKey {
    param([Parameter(Mandatory = $true)][Microsoft.Win32.RegistryKey]$BaseKey, [Parameter(Mandatory = $true)][string]$SubKeyPath)
    try {
        $k = $BaseKey.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        if ($k) {
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $open = New-Object System.Security.AccessControl.RegistrySecurity
            $open.SetAccessRuleProtection($true, $false)
            $open.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($me, [System.Security.AccessControl.RegistryRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)))
            $k.SetAccessControl($open)
            $k.Dispose()
        }
    } catch { }
    try { $BaseKey.DeleteSubKeyTree($SubKeyPath, $false) } catch { Write-Host "  WARNING: could not delete test key $SubKeyPath : $($_.Exception.Message)" -ForegroundColor Yellow }
}

# ---------------------------------------------------------------------------
# Naming helpers
# ---------------------------------------------------------------------------

Add-TestCase 'N1' 'helpers: dot-sourcing prints nothing and defines no "--" function' {
    Assert-Equal 0 $script:ImportOutput.Count 'dot-sourcing produced output'
    Assert-True ($script:HelperFunctions.Count -ge 6) "expected the helper functions, got: $($script:HelperFunctions -join ', ')"
    foreach ($fn in $script:HelperFunctions) { Assert-True ($fn -notlike '*--*') "function $fn contains -- and would appear in the Setup menu" }
    foreach ($fn in @('Get-PDOrgRegistryIntuneDisplayName', 'ConvertFrom-PDOrgRegistryIntuneDisplayName', 'Get-PDOrgRegistryIntuneDescription', 'Get-PDOrgRegistryPlatformScriptFileName', 'Get-PDOrgRegistrySourceCommit', 'Test-PDOrgRegistryIntuneNameMatch')) {
        Assert-True ($script:HelperFunctions -contains $fn) "$fn is defined"
    }
}

Add-TestCase 'N2' 'display names: exact PRODUCTION and app-style non-production names' {
    Assert-Equal 'POWERDEPLOY ORG REGISTRY: Platform Script' (Get-PDOrgRegistryIntuneDisplayName -Type PlatformScript -DeployMode 'PRODUCTION' -SourceCommit 'abc1234') 'production platform script'
    Assert-Equal 'POWERDEPLOY ORG REGISTRY: Remediation' (Get-PDOrgRegistryIntuneDisplayName -Type Remediation -DeployMode 'PRODUCTION' -SourceCommit 'abc1234') 'production remediation'
    Assert-Equal 'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC-TESTING] [VER: abc1234]' (Get-PDOrgRegistryIntuneDisplayName -Type PlatformScript -DeployMode 'PUBLIC-TESTING' -SourceCommit 'abc1234') 'non-production platform script'
    Assert-Equal 'POWERDEPLOY ORG REGISTRY: Remediation [MODE: PRIVATE-DEVELOPMENT] [VER: abc1234.UnstagedChanges]' (Get-PDOrgRegistryIntuneDisplayName -Type Remediation -DeployMode 'PRIVATE-DEVELOPMENT' -SourceCommit 'abc1234.UnstagedChanges') 'non-production remediation'
}

Add-TestCase 'N3' 'display names: round trip for every mode and type' {
    foreach ($mode in @('PUBLIC-DEVELOPMENT', 'PUBLIC-TESTING', 'PRIVATE-DEVELOPMENT', 'PRODUCTION')) {
        foreach ($type in @('PlatformScript', 'Remediation')) {
            $name = Get-PDOrgRegistryIntuneDisplayName -Type $type -DeployMode $mode -SourceCommit '0f1e2d3.UnstagedChanges'
            $parsed = ConvertFrom-PDOrgRegistryIntuneDisplayName -DisplayName $name
            Assert-True $parsed.IsOrgRegistry "$name parses"
            Assert-Equal $type $parsed.Type "$name type"
            Assert-Equal $mode $parsed.DeployMode "$name mode"
            if ($mode -eq 'PRODUCTION') { Assert-Equal '' $parsed.Version "$name has no version" } else { Assert-Equal '0f1e2d3.UnstagedChanges' $parsed.Version "$name version" }
        }
    }
}

Add-TestCase 'N4' 'matching: VER is ignored, mode and type are not' {
    $old = Get-PDOrgRegistryIntuneDisplayName -Type PlatformScript -DeployMode 'PUBLIC-TESTING' -SourceCommit 'aaaaaaa'
    Assert-True (Test-PDOrgRegistryIntuneNameMatch -DisplayName $old -Type PlatformScript -DeployMode 'PUBLIC-TESTING') 'an older VER still matches'
    Assert-True (Test-PDOrgRegistryIntuneNameMatch -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC-TESTING] [VER: ]' -Type PlatformScript -DeployMode 'PUBLIC-TESTING') 'an empty VER still matches'
    Assert-True (-not (Test-PDOrgRegistryIntuneNameMatch -DisplayName $old -Type PlatformScript -DeployMode 'PUBLIC-DEVELOPMENT')) 'another mode does not match'
    Assert-True (-not (Test-PDOrgRegistryIntuneNameMatch -DisplayName $old -Type Remediation -DeployMode 'PUBLIC-TESTING')) 'the other type does not match'
    Assert-True (-not (Test-PDOrgRegistryIntuneNameMatch -DisplayName $old -Type PlatformScript -DeployMode 'PRODUCTION')) 'production does not match a non-production name'
    Assert-True (Test-PDOrgRegistryIntuneNameMatch -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' -Type Remediation -DeployMode 'PRODUCTION') 'production matches the plain name'
    Assert-True (-not (Test-PDOrgRegistryIntuneNameMatch -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' -Type Remediation -DeployMode 'PUBLIC-TESTING')) 'a non-production mode does not match the production name'
}

Add-TestCase 'N5' 'parser: foreign names are rejected and nothing throws' {
    $foreign = @(
        $null, '', '   ',
        'PRINTER: Lobby',
        'APP: Zoom [MODE: PUBLIC-TESTING] [VER: abc]',
        'PowerDeploy Registry Update',
        'powerdeploy org registry: Remediation',
        'POWERDEPLOY ORG REGISTRY: Remediation extra',
        'POWERDEPLOY ORG REGISTRY: Platform Script [PUBLIC-TESTING] [VER: abc]',
        'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: ] [VER: abc]',
        'POWERDEPLOY ORG REGISTRY: Scripts',
        'X POWERDEPLOY ORG REGISTRY: Remediation',
        "POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC-TESTING`n] [VER: abc]"
    )
    # Surrounding whitespace is trimmed (as the printer parser does), so a trailing newline is the same name.
    Assert-True (ConvertFrom-PDOrgRegistryIntuneDisplayName -DisplayName "POWERDEPLOY ORG REGISTRY: Remediation`r`n").IsOrgRegistry 'surrounding whitespace is trimmed'
    # Non-string input must bind and come back as "not ours", never throw.
    $odd = @(
        ,@('POWERDEPLOY ORG REGISTRY: Remediation'),
        ,@('POWERDEPLOY ORG REGISTRY: Remediation', 'POWERDEPLOY ORG REGISTRY: Platform Script'),
        @{ displayName = 'POWERDEPLOY ORG REGISTRY: Remediation' },
        42,
        [pscustomobject]@{ displayName = 'POWERDEPLOY ORG REGISTRY: Remediation' }
    )
    foreach ($item in $odd) {
        $parsed = ConvertFrom-PDOrgRegistryIntuneDisplayName -DisplayName $item
        Assert-True (-not $parsed.IsOrgRegistry) "a $($item.GetType().Name) must not parse"
        Assert-True (-not (Test-PDOrgRegistryIntuneNameMatch -DisplayName $item -Type Remediation -DeployMode 'PRODUCTION')) "a $($item.GetType().Name) never matches"
    }
    Assert-True (-not (Test-PDOrgRegistryIntuneNameMatch -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' -Type Remediation -DeployMode @('PRODUCTION'))) 'an array deploy mode never matches'
    foreach ($name in $foreign) {
        $parsed = ConvertFrom-PDOrgRegistryIntuneDisplayName -DisplayName $name
        Assert-True (-not $parsed.IsOrgRegistry) "'$name' must not parse"
        Assert-Equal '' $parsed.Type "'$name' type empty"
        Assert-Equal '' $parsed.DeployMode "'$name' mode empty"
        Assert-True (-not (Test-PDOrgRegistryIntuneNameMatch -DisplayName $name -Type Remediation -DeployMode 'PRODUCTION')) "'$name' never matches"
    }
}

Add-TestCase 'N6' 'description and Intune file name' {
    $d = Get-PDOrgRegistryIntuneDescription -Type PlatformScript -DeployMode 'PUBLIC-TESTING' -SourceCommit 'abc1234' -GeneratedAt ([datetime]'2026-11-05T09:08:07')
    Assert-Like '*Deploy mode: PUBLIC-TESTING*' $d 'mode'
    Assert-Like '*Source commit: abc1234*' $d 'commit'
    Assert-Like '*Generated: 2026-11-05 09:08:07*' $d 'generated time'
    Assert-Like '*Generated by PowerDeploy Setup*' $d 'generator line'
    $r = Get-PDOrgRegistryIntuneDescription -Type Remediation -DeployMode 'PRODUCTION' -SourceCommit 'abc1234' -GeneratedAt '2026-11-05 09:08:07'
    Assert-Like '*hourly*' $r 'the remediation description says hourly'
    Assert-Equal 'PowerDeploy-OrgRegistry_abc1234.ps1' (Get-PDOrgRegistryPlatformScriptFileName -SourceCommit 'abc1234') 'file name'
    Assert-Equal 'PowerDeploy-OrgRegistry_abc1234.UnstagedChanges.ps1' (Get-PDOrgRegistryPlatformScriptFileName -SourceCommit 'abc1234.UnstagedChanges') 'file name with marker'
    Assert-Equal 'PowerDeploy-OrgRegistry_unknown.ps1' (Get-PDOrgRegistryPlatformScriptFileName -SourceCommit '') 'blank commit'
}

# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

Add-TestCase 'G1' 'generator: awkward values embed exactly and the script parses' {
    $run = Invoke-PDGenerator -FunctionParams (@{ DeployMode = 'PUBLIC-DEVELOPMENT' } + [hashtable]$script:TrickyValues)
    Assert-Equal 0 $run.Exit 'generator exit code'
    Assert-True ($run.Result -is [hashtable]) 'a hashtable comes back'
    $path = $run.Result.PlatformScript
    Assert-True (Test-Path -LiteralPath $path) 'the script file exists'
    $script:Generated['Tricky'] = $run

    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$parseErrors)
    Assert-Equal 0 @($parseErrors).Count 'the generated script parses'

    # Run only the stamp block, then compare every value exactly.
    $content = [System.IO.File]::ReadAllText($path)
    $block = Get-PDStampBlock -Content $content
    $values = & ([scriptblock]::Create($block + "`n" + 'return ,@($PDOrgValues)'))
    Assert-Equal 7 @($values).Count 'seven entries'
    $expectedOrder = @('General\StorageAccountName', 'General\CustomRepoURL', 'General\CustomRepoToken', 'Printers\PrinterDataJSONpath', 'Printers\PrinterContainerSASkey', 'Applications\ApplicationDataJSONpath', 'Applications\ApplicationContainerSASkey')
    for ($i = 0; $i -lt 7; $i++) {
        Assert-Equal $expectedOrder[$i] ("{0}\{1}" -f $values[$i].SubKey, $values[$i].Name) "entry $i order"
        Assert-True ($values[$i].Value -is [string]) "entry $i is a string"
        Assert-True ($values[$i].Value -ceq [string]$script:TrickyValues[$values[$i].Name]) "$($values[$i].Name) round-trips exactly"
    }
}

Add-TestCase 'G2' 'generator: file name, UTF-8 BOM, size, commit marker, header' {
    $run = $script:Generated['Tricky']; if (-not $run) { throw 'G1 did not produce a script' }
    $path = $run.Result.PlatformScript
    $leaf = Split-Path $path -Leaf
    $commit = $run.Result.PlatformScriptSourceCommit
    Assert-Equal (Get-PDOrgRegistrySourceCommit -RepoRoot $repoRoot) $commit 'commit string matches the helper'
    Assert-True ($commit -cmatch '^([0-9a-f]{4,40}|unknown)(\.UnstagedChanges)?$') "commit shape: $commit"
    $porcelain = @(git -C $repoRoot status --porcelain -- 'Templates/OrgRegistry-PlatformScript_TEMPLATE.ps1' 2>$null)
    Assert-Equal ([bool]($porcelain.Count -gt 0)) ($commit -like '*.UnstagedChanges') 'the marker follows the template''s uncommitted edits'
    Assert-True ($leaf -cmatch ('^PowerDeploy-OrgRegistry_' + [regex]::Escape($commit) + '_\d{8}_\d{6}\.ps1$')) "file name: $leaf"
    $bytes = [System.IO.File]::ReadAllBytes($path)
    Assert-True (($bytes[0] -eq 0xEF) -and ($bytes[1] -eq 0xBB) -and ($bytes[2] -eq 0xBF)) 'UTF-8 BOM'
    Assert-True ($bytes.Length -lt 200KB) "smaller than 200 KB ($($bytes.Length))"
    $content = [System.IO.File]::ReadAllText($path)
    Assert-Like '*# Deploy mode   : PUBLIC-DEVELOPMENT*' $content 'header deploy mode'
    Assert-Like "*# Source commit : $commit*" $content 'header commit'
    Assert-Like "*# Generated     : $($run.Result.PlatformScriptGeneratedAt)*" $content 'header generated time'
    Assert-Equal 'PUBLIC-DEVELOPMENT' $run.Result.PlatformScriptDeployMode 'deploy mode returned'
    Assert-True ($content -notlike '*#__PD_STAMP_HEADER__*') 'header marker replaced'
    Assert-True (-not ($content -cmatch '\$PDStamped\s*=\s*\$false')) 'stamped flag set'
    Assert-True ($content -cmatch "(?m)^\`$PDRegistryRoot\s*=\s*'SOFTWARE\\PowerDeploy'\r?$") 'default root is the real one'
    Assert-True ($content.Contains("`r`n") -and -not ($content -match '(?<!\r)\n')) 'CRLF line endings'
}

Add-TestCase 'G3' 'generator: no value in any comment, outside the values literal, or in its own output' {
    $run = $script:Generated['Tricky']; if (-not $run) { throw 'G1 did not produce a script' }
    $path = $run.Result.PlatformScript
    $content = [System.IO.File]::ReadAllText($path)
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$tokens, [ref]$parseErrors)
    $comments = @($tokens | Where-Object { $_.Kind -eq [System.Management.Automation.Language.TokenKind]::Comment } | ForEach-Object Text)
    $assign = @($ast.FindAll({ param($n) ($n -is [System.Management.Automation.Language.AssignmentStatementAst]) -and ($n.Left.Extent.Text -ceq '$PDOrgValues') }, $true))
    Assert-Equal 1 $assign.Count 'one values assignment'
    $outside = $content.Remove($assign[0].Extent.StartOffset, $assign[0].Extent.EndOffset - $assign[0].Extent.StartOffset)
    foreach ($name in $script:TrickyValues.Keys) {
        $value = [string]$script:TrickyValues[$name]
        if ($value.Length -lt 10) { continue }
        foreach ($comment in $comments) { Assert-True (-not $comment.Contains($value)) "$name appears in a comment" }
        Assert-True (-not $outside.Contains($value)) "$name appears outside the values literal"
        # Also the escaped form, as it sits in the file.
        $escaped = [System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($value)
        Assert-True (-not $outside.Contains($escaped)) "$name (escaped) appears outside the values literal"
        # The generator function's own lines (between its START and END) never show a value.
        $inFunction = $false
        foreach ($line in $run.Text) {
            if ($line -like '*FUNCTION: OrgRegistryPlatformScript | START*') { $inFunction = $true }
            if ($inFunction) { Assert-True (-not $line.Contains($value)) "$name appears in the generator function's output" }
            if ($line -like '*FUNCTION: OrgRegistryPlatformScript | END*') { $inFunction = $false }
        }
    }
}

Add-TestCase 'G4' 'template: no Write-* call can print a value' {
    $writers = @('Write-Log', 'Write-Host', 'Write-Output', 'Write-Information', 'Write-Verbose', 'Write-Warning', 'Write-Error', 'Write-Debug', 'Out-Host', 'Out-File', 'Add-Content', 'Set-Content')
    $valueVariables = @('PDOrgValues', 'PDEntries', 'ExpectedData', 'CurrentData', 'ReadData')
    $calls = @($script:TemplateAst.FindAll({ param($n) ($n -is [System.Management.Automation.Language.CommandAst]) -and ($writers -contains $n.GetCommandName()) }, $true))
    Assert-True ($calls.Count -gt 10) 'found the logging calls'
    foreach ($call in $calls) {
        foreach ($v in @($call.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true))) {
            Assert-True ($valueVariables -notcontains $v.VariablePath.UserPath) ("line {0} logs `${1}" -f $call.Extent.StartLineNumber, $v.VariablePath.UserPath)
        }
        foreach ($m in @($call.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] }, $true))) {
            Assert-True ($m.Member.Extent.Text -cne 'Value') ("line {0} logs a .Value member" -f $call.Extent.StartLineNumber)
        }
    }
    # A value only ever leaves an entry as the -ExpectedData argument of Set-PDOrgValue / Test-PDOrgValue.
    $uses = @($script:TemplateAst.FindAll({ param($n) ($n -is [System.Management.Automation.Language.MemberExpressionAst]) -and ($n.Member.Extent.Text -ceq 'Value') -and ($n.Expression -is [System.Management.Automation.Language.VariableExpressionAst]) -and ($n.Expression.VariablePath.UserPath -eq 'Entry') }, $true))
    Assert-Equal 2 $uses.Count 'two uses of $Entry.Value'
    foreach ($use in $uses) {
        Assert-True (($use.Parent -is [System.Management.Automation.Language.CommandAst]) -and (@('Set-PDOrgValue', 'Test-PDOrgValue') -contains $use.Parent.GetCommandName())) ("line {0}: `$Entry.Value used outside Set-PDOrgValue / Test-PDOrgValue" -f $use.Extent.StartLineNumber)
    }
}

Add-TestCase 'G5' 'generator: Setup-shaped input uses the shared defaults; blanks stay blank' {
    $run = Invoke-PDGenerator -FunctionParams @{ DeployMode = 'PRODUCTION'; CustomRepoURL = 'https://example.invalid/r'; CustomRepoToken = ''; PrinterContainerSASkey = ''; ApplicationContainerSASkey = 'sv=1' }
    Assert-Equal 0 $run.Exit 'generator exit code'
    $content = [System.IO.File]::ReadAllText($run.Result.PlatformScript)
    $values = & ([scriptblock]::Create((Get-PDStampBlock -Content $content) + "`n" + 'return ,@($PDOrgValues)'))
    $byName = @{}; foreach ($v in $values) { $byName[$v.Name] = $v.Value }
    Assert-Equal 'powerdeploy' $byName['StorageAccountName'] 'StorageAccountName default'
    Assert-Equal 'printers/PrinterData.json' $byName['PrinterDataJSONpath'] 'PrinterDataJSONpath default'
    Assert-Equal 'applications/ApplicationData.json' $byName['ApplicationDataJSONpath'] 'ApplicationDataJSONpath default'
    Assert-Equal '' $byName['CustomRepoToken'] 'blank token stays an empty string'
    Assert-Equal '' $byName['PrinterContainerSASkey'] 'blank SAS key stays an empty string'
    Assert-True ($byName['PrinterContainerSASkey'] -is [string]) 'blank is a string, not null'
    Assert-Equal 7 @($values).Count 'all seven are written, blanks included'
}

Add-TestCase 'G6' 'generator: refuses bad deploy mode, a foreign root, NUL, and 200 KB' {
    $cases = @(
        @{ Why = 'blank mode';        Params = @{ DeployMode = '' } },
        @{ Why = 'mode with newline'; Params = @{ DeployMode = "PRODUCTION`r`n# x" } },
        @{ Why = 'foreign root';      Params = @{ DeployMode = 'PUBLIC-TESTING'; RegistryRoot = 'SOFTWARE\Microsoft' } },
        @{ Why = 'near-miss root';    Params = @{ DeployMode = 'PUBLIC-TESTING'; RegistryRoot = 'SOFTWARE\PowerDeploy-Test-notaguid' } },
        @{ Why = 'NUL in a value';    Params = @{ DeployMode = 'PUBLIC-TESTING'; CustomRepoToken = "a$([char]0)b" } },
        @{ Why = '200 KB';            Params = @{ DeployMode = 'PUBLIC-TESTING'; CustomRepoToken = ('x' * (200 * 1024)) } },
        @{ Why = 'real root + LF';    Params = @{ DeployMode = 'PUBLIC-TESTING'; RegistryRoot = "SOFTWARE\PowerDeploy`n" }; Expect = '*RegistryRoot must be*' },
        @{ Why = 'real root + CRLF';  Params = @{ DeployMode = 'PUBLIC-TESTING'; RegistryRoot = "SOFTWARE\PowerDeploy`r`n" }; Expect = '*RegistryRoot must be*' },
        @{ Why = 'test root + LF';    Params = @{ DeployMode = 'PUBLIC-TESTING'; RegistryRoot = ((New-PDTestRoot) + "`n") }; Expect = '*RegistryRoot must be*' },
        @{ Why = 'mode + LF';         Params = @{ DeployMode = "PRODUCTION`n" }; Expect = '*DeployMode is missing or has unexpected characters*' },
        @{ Why = 'working dir + LF';  Params = @{ DeployMode = 'PUBLIC-TESTING' }; WorkingDirectory = ((Join-Path $script:TempRoot 'wd') + "`n"); Expect = '*TargetWorkingDirectory must be*' },
        @{ Why = 'lone surrogate';    Params = @{ DeployMode = 'PUBLIC-TESTING'; CustomRepoToken = ('abc' + [char]0xD800 + 'def') }; Expect = '*cannot be encoded as UTF-8*' },
        @{ Why = 'reversed surrogates'; Params = @{ DeployMode = 'PUBLIC-TESTING'; PrinterContainerSASkey = ('abc' + [char]0xDC00 + [char]0xD800 + 'def') }; Expect = '*cannot be encoded as UTF-8*' }
    )
    foreach ($case in $cases) {
        if ($case.WorkingDirectory) {
            $run = Invoke-PDGenerator -FunctionParams $case.Params -WorkingDirectory $case.WorkingDirectory
        } else {
            $run = Invoke-PDGenerator -FunctionParams $case.Params
        }
        Assert-Equal 1 $run.Exit "$($case.Why): exit code"
        if ($case.Expect) { Assert-True (@($run.Text | Where-Object { $_ -like $case.Expect }).Count -ge 1) "$($case.Why): refused for the right reason ($($case.Expect))" }
        Assert-True ($null -eq $run.Result) "$($case.Why): nothing returned"
        Assert-True (-not (Test-Path -LiteralPath $run.OutDir) -or @(Get-ChildItem -LiteralPath $run.OutDir).Count -eq 0) "$($case.Why): no file saved"
    }
}

Add-TestCase 'G7' 'refactor: OrgRegistryChangesString returns the same bracketed string' {
    $ErrorActionPreference = 'Continue'
    $out = @(& $generatorPath -DesiredFunction 'OrgRegistryChangesString' -TargetWorkingDirectory (Join-Path $script:TempRoot 'wd') -FunctionParams @{ CustomRepoURL = 'https://h/r'; PrinterContainerSASkey = 'sv=P'; ApplicationContainerSASkey = 'sv=A' } 6>$null)
    $actual = [string]($out | Select-Object -Last 1)
    $expected = '[-KeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\General" -ValueName "StorageAccountName" -ValueType "String" -Value "powerdeploy"],' +
                '[-KeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\General" -ValueName "CustomRepoURL" -ValueType "String" -Value "https://h/r"],' +
                '[-KeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\General" -ValueName "CustomRepoToken" -ValueType "String" -Value ""],' +
                '[-KeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\Printers" -ValueName "PrinterDataJSONpath" -ValueType "String" -Value "printers/PrinterData.json"],' +
                '[-KeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\Printers" -ValueName "PrinterContainerSASkey" -ValueType "String" -Value "sv=P"],' +
                '[-KeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\Applications" -ValueName "ApplicationDataJSONpath" -ValueType "String" -Value "applications/ApplicationData.json"],' +
                '[-KeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy\Applications" -ValueName "ApplicationContainerSASkey" -ValueType "String" -Value "sv=A"]'
    Assert-Equal $expected $actual 'bracketed string'
}

# ---------------------------------------------------------------------------
# Template (offline and HKCU)
# ---------------------------------------------------------------------------

Add-TestCase 'T1' 'ACL: the template builds exactly what Set-StrictRegAcl builds' {
    $mine = New-PDStrictRegistrySecurity
    $theirs = & $script:SetStrictRegAclBuilder
    Assert-Equal ($theirs.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)) ($mine.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)) 'DACL SDDL'
    Assert-True (Test-PDStrictRegistrySecurity -Security $mine) 'the template accepts its own ACL'
    Assert-True (Test-PDStrictRegistrySecurity -Security $theirs) 'the template accepts the Set-StrictRegAcl ACL'
}

Add-TestCase 'T2' 'ACL: the template check rejects anything that is not exactly strict' {
    $fc = [System.Security.AccessControl.RegistryRights]::FullControl
    $ci = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $np = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $users = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-545'

    $unprotected = New-PDStrictRegistrySecurity; $unprotected.SetAccessRuleProtection($false, $true)
    Assert-True (-not (Test-PDStrictRegistrySecurity -Security $unprotected)) 'inheritance not protected'

    $extra = New-PDStrictRegistrySecurity
    $extra.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($users, [System.Security.AccessControl.RegistryRights]::ReadKey, $ci, $np, $allow)))
    Assert-True (-not (Test-PDStrictRegistrySecurity -Security $extra)) 'an extra principal'

    $noAdmins = New-Object System.Security.AccessControl.RegistrySecurity; $noAdmins.SetAccessRuleProtection($true, $false)
    $noAdmins.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule((New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'), $fc, $ci, $np, $allow)))
    Assert-True (-not (Test-PDStrictRegistrySecurity -Security $noAdmins)) 'Administrators missing'

    $noInherit = New-Object System.Security.AccessControl.RegistrySecurity; $noInherit.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) { $noInherit.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule((New-Object System.Security.Principal.SecurityIdentifier $sid), $fc, [System.Security.AccessControl.InheritanceFlags]::None, $np, $allow))) }
    Assert-True (-not (Test-PDStrictRegistrySecurity -Security $noInherit)) 'no ContainerInherit'

    $readOnly = New-Object System.Security.AccessControl.RegistrySecurity; $readOnly.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) { $readOnly.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule((New-Object System.Security.Principal.SecurityIdentifier $sid), [System.Security.AccessControl.RegistryRights]::ReadKey, $ci, $np, $allow))) }
    Assert-True (-not (Test-PDStrictRegistrySecurity -Security $readOnly)) 'not FullControl'

    Assert-True (-not (Test-PDStrictRegistrySecurity -Security $null)) 'null'
}

Add-TestCase 'T3' 'ACL on a real key (HKCU): applied, verified, and accepted by Test-StrictRegAcl' {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64)
    $fresh = New-PDTestRoot
    $existing = New-PDTestRoot
    $reference = New-PDTestRoot
    try {
        # A key the template creates (strict at creation, then the Set-StrictRegAcl call).
        $script:LogLines = @()
        Assert-True (Set-PDStrictKey -BaseKey $base -SubKeyPath $fresh) 'Set-PDStrictKey on a new key'
        Assert-True (@($script:LogLines | Where-Object { $_ -like '*key created*' }).Count -eq 1) 'it was created'
        Assert-True (@($script:LogLines | Where-Object { $_ -like '*ACL set to strict*' }).Count -eq 1) 'and locked down'
        Assert-True (Test-PDStrictKeyAcl -BaseKey $base -SubKeyPath $fresh) 'and is strict'
        $script:LogLines = @()
        Assert-True (Set-PDStrictKey -BaseKey $base -SubKeyPath $fresh) 'a second run on the created key'
        Assert-True (@($script:LogLines | Where-Object { $_ -like '*ACL already strict*' }).Count -eq 1) 'finds nothing to change on the created key'

        # A key that already exists with the ordinary inherited ACL.
        $base.CreateSubKey($existing).Dispose()
        Assert-True (-not (Test-PDStrictKeyAcl -BaseKey $base -SubKeyPath $existing)) 'an ordinary key is not strict'
        $script:LogLines = @()
        Assert-True (Set-PDStrictKey -BaseKey $base -SubKeyPath $existing) 'Set-PDStrictKey on an existing key'
        Assert-True (@($script:LogLines | Where-Object { $_ -like '*ACL set to strict*' }).Count -eq 1) 'it was changed'
        $script:LogLines = @()
        Assert-True (Set-PDStrictKey -BaseKey $base -SubKeyPath $existing) 'a second run'
        Assert-True (@($script:LogLines | Where-Object { $_ -like '*ACL already strict*' }).Count -eq 1) 'finds nothing to change'

        # Configure-Registry.ps1's own check (what Security Manager runs, in 5.1) accepts both.
        $accepted = Invoke-PDTestStrictRegAcl51 -KeyPaths @("HKCU:\$fresh", "HKCU:\$existing")
        Assert-True $accepted[0] "Test-StrictRegAcl accepts the created key"
        Assert-True $accepted[1] "Test-StrictRegAcl accepts the fixed key"

        # Byte-for-byte the same DACL as Set-StrictRegAcl itself writes.
        $base.CreateSubKey($reference).Dispose()
        $KeyPath = "HKCU:\$reference"
        Set-StrictRegAcl
        $read = {
            param($sub)
            $k = $base.OpenSubKey($sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
            try { $k.GetAccessControl().GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access) } finally { $k.Dispose() }
        }
        $want = & $read $reference
        Assert-Equal $want (& $read $fresh) 'created key DACL equals Set-StrictRegAcl'
        Assert-Equal $want (& $read $existing) 'fixed key DACL equals Set-StrictRegAcl'
    } finally {
        foreach ($sub in @($fresh, $existing, $reference)) { Remove-PDTestKey -BaseKey $base -SubKeyPath $sub }
        $base.Dispose()
    }
}

Add-TestCase 'T4' 'values on a real key (HKCU): write, already correct, fixes case and type, blank, read-back' {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64)
    $sub = New-PDTestRoot
    try {
        $base.CreateSubKey($sub).Dispose()
        $v = [string]$script:TrickyValues['PrinterContainerSASkey']
        Assert-Equal 'written' (Set-PDOrgValue -BaseKey $base -SubKeyPath $sub -Name 'PrinterContainerSASkey' -ExpectedData $v) 'first write'
        Assert-True (Test-PDOrgValue -BaseKey $base -SubKeyPath $sub -Name 'PrinterContainerSASkey' -ExpectedData $v) 'read back'
        Assert-Equal 'already correct' (Set-PDOrgValue -BaseKey $base -SubKeyPath $sub -Name 'PrinterContainerSASkey' -ExpectedData $v) 'second write'
        Assert-True (-not (Test-PDOrgValue -BaseKey $base -SubKeyPath $sub -Name 'PrinterContainerSASkey' -ExpectedData $v.ToUpperInvariant())) 'the read-back is case-sensitive'
        Assert-Equal 'written' (Set-PDOrgValue -BaseKey $base -SubKeyPath $sub -Name 'PrinterContainerSASkey' -ExpectedData $v.ToUpperInvariant()) 'a case change is written'

        Assert-Equal 'written' (Set-PDOrgValue -BaseKey $base -SubKeyPath $sub -Name 'CustomRepoToken' -ExpectedData '') 'blank write'
        $k = $base.OpenSubKey($sub)
        try {
            Assert-True (@($k.GetValueNames()) -contains 'CustomRepoToken') 'a blank value exists'
            Assert-Equal ([Microsoft.Win32.RegistryValueKind]::String) $k.GetValueKind('CustomRepoToken') 'as a String'
            Assert-Equal '' $k.GetValue('CustomRepoToken') 'with no data'
        } finally { $k.Dispose() }
        Assert-True (Test-PDOrgValue -BaseKey $base -SubKeyPath $sub -Name 'CustomRepoToken' -ExpectedData '') 'blank read back'
        Assert-True (-not (Test-PDOrgValue -BaseKey $base -SubKeyPath $sub -Name 'Missing' -ExpectedData '')) 'a missing value is not a blank value'

        $k = $base.OpenSubKey($sub, $true)
        try { $k.SetValue('StorageAccountName', 'same', [Microsoft.Win32.RegistryValueKind]::ExpandString) } finally { $k.Dispose() }
        Assert-True (-not (Test-PDOrgValue -BaseKey $base -SubKeyPath $sub -Name 'StorageAccountName' -ExpectedData 'same')) 'a wrong value type fails the read-back'
        Assert-Equal 'written' (Set-PDOrgValue -BaseKey $base -SubKeyPath $sub -Name 'StorageAccountName' -ExpectedData 'same') 'and is rewritten as String'
        Assert-True (Test-PDOrgValue -BaseKey $base -SubKeyPath $sub -Name 'StorageAccountName' -ExpectedData 'same') 'then reads back'

        Assert-Equal 'FAILED' (Set-PDOrgValue -BaseKey $base -SubKeyPath "$sub\NoSuchKey" -Name 'X' -ExpectedData 'y') 'a missing key fails'
    } finally {
        Remove-PDTestKey -BaseKey $base -SubKeyPath $sub
        $base.Dispose()
    }
}

Add-TestCase 'T5' 'template: the unstamped template changes nothing and exits 1' {
    $out = @(& $script:WinPS64 -NoProfile -ExecutionPolicy Bypass -File $templatePath 2>&1 | ForEach-Object { [string]$_ })
    Assert-Equal 1 $LASTEXITCODE 'exit code'
    Assert-True (@($out | Where-Object { $_ -like '*unstamped template*Nothing was changed*' }).Count -eq 1) ("message: " + ($out -join ' | '))
}

Add-TestCase 'T7' 'template: the root allow-list is anchored at the very end (no trailing newline)' {
    $assign = @($script:TemplateAst.FindAll({ param($n) ($n -is [System.Management.Automation.Language.AssignmentStatementAst]) -and ($n.Left.Extent.Text -ceq '$PDAllowedRootPattern') }, $true))
    Assert-Equal 1 $assign.Count 'one root pattern'
    $pattern = & ([scriptblock]::Create($assign[0].Extent.Text + "`n" + '$PDAllowedRootPattern'))
    $guidRoot = New-PDTestRoot
    Assert-True ('SOFTWARE\PowerDeploy' -cmatch $pattern) 'the real root is allowed'
    Assert-True ($guidRoot -cmatch $pattern) 'a test root is allowed'
    foreach ($bad in @("SOFTWARE\PowerDeploy`n", "SOFTWARE\PowerDeploy`r`n", "$guidRoot`n", 'SOFTWARE\PowerDeploy\General', 'software\powerdeploy', 'SOFTWARE\PowerDeployX')) {
        Assert-True (-not ($bad -cmatch $pattern)) ("'{0}' must be refused" -f ($bad -replace "`r", '\r' -replace "`n", '\n'))
    }

    # A generated (test-root) script hand-edited to a root with a trailing newline refuses before
    # touching the registry (the root check runs before the admin check).
    $wd = Join-Path $script:TempRoot ('wd-' + [guid]::NewGuid().ToString('N'))
    $run = Invoke-PDGenerator -WorkingDirectory $wd -FunctionParams @{ DeployMode = 'PUBLIC-TESTING'; RegistryRoot = $guidRoot }
    Assert-Equal 0 $run.Exit 'generator exit code'
    $path = $run.Result.PlatformScript
    $text = [System.IO.File]::ReadAllText($path)
    $edited = $text.Replace("`$PDRegistryRoot     = '$guidRoot'", "`$PDRegistryRoot     = '$guidRoot`r`n'")
    Assert-True ($edited -cne $text) 'the root line was edited'
    [System.IO.File]::WriteAllText($path, $edited, (New-Object System.Text.UTF8Encoding($true)))
    $out = @(& $script:WinPS64 -NoProfile -ExecutionPolicy Bypass -File $path 2>&1 | ForEach-Object { [string]$_ })
    Assert-Equal 1 $LASTEXITCODE 'exit code'
    Assert-True (@($out | Where-Object { $_ -like '*stamped registry root is not allowed*' }).Count -eq 1) ("message: " + ($out -join ' | '))
}

Add-TestCase 'T6' 'stamped script, not elevated: refuses, prints and logs no value' {
    if ($script:IsElevated) { Skip-TestCase 'elevated session: the end-to-end case E1 covers the stamped script' }
    $wd = Join-Path $script:TempRoot ('wd-' + [guid]::NewGuid().ToString('N'))
    $run = Invoke-PDGenerator -WorkingDirectory $wd -FunctionParams (@{ DeployMode = 'PUBLIC-TESTING'; RegistryRoot = (New-PDTestRoot) } + [hashtable]$script:TrickyValues)
    Assert-Equal 0 $run.Exit 'generator exit code'
    $out = @(& $script:WinPS64 -NoProfile -ExecutionPolicy Bypass -File $run.Result.PlatformScript 2>&1 | ForEach-Object { [string]$_ })
    Assert-Equal 1 $LASTEXITCODE 'exit code'
    Assert-True (@($out | Where-Object { $_ -like '*Administrator (or SYSTEM) rights are required*' }).Count -eq 1) ("message: " + ($out -join ' | '))
    $logs = @(Get-ChildItem -LiteralPath (Join-Path $wd 'Logs\Config_Logs') -Filter 'PowerDeploy-OrgRegistry_PlatformScript._Log_*.log')
    Assert-Equal 1 $logs.Count 'one log file in <working directory>\Logs\Config_Logs'
    $logText = [System.IO.File]::ReadAllText($logs[0].FullName)
    foreach ($name in $script:TrickyValues.Keys) {
        $value = [string]$script:TrickyValues[$name]
        if ($value.Length -lt 10) { continue }
        Assert-True (-not (($out -join "`n").Contains($value))) "$name in the output"
        Assert-True (-not $logText.Contains($value)) "$name in the log"
    }
}

# ---------------------------------------------------------------------------
# End to end (elevated only)
# ---------------------------------------------------------------------------

Add-TestCase 'E1' 'end to end (elevated): HKLM test root, 64-bit Windows PowerShell, values, exit code, ACLs' {
    if (-not $script:IsElevated) { Skip-TestCase 'not elevated: run this suite from an elevated prompt to execute the HKLM end-to-end case' }

    $root = New-PDTestRoot
    $refRoot = New-PDTestRoot
    $wd = Join-Path $script:TempRoot ('wd-' + [guid]::NewGuid().ToString('N'))
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $run = Invoke-PDGenerator -WorkingDirectory $wd -FunctionParams (@{ DeployMode = 'PUBLIC-TESTING'; RegistryRoot = $root } + [hashtable]$script:TrickyValues)
        Assert-Equal 0 $run.Exit 'generator exit code'
        $content = [System.IO.File]::ReadAllText($run.Result.PlatformScript)
        Assert-True ($content.Contains("'$root'")) 'the test root is stamped'

        $out = @(& $script:WinPS64 -NoProfile -ExecutionPolicy Bypass -File $run.Result.PlatformScript 2>&1 | ForEach-Object { [string]$_ })
        Assert-Equal 0 $LASTEXITCODE ("first run exit code: " + ($out -join ' | '))

        foreach ($name in $script:TrickyValues.Keys) {
            $sub = switch -Wildcard ($name) { 'Printer*' { 'Printers' } 'Application*' { 'Applications' } default { 'General' } }
            $k = $base.OpenSubKey("$root\$sub")
            try {
                Assert-True ($null -ne $k) "$root\$sub exists"
                Assert-True (@($k.GetValueNames()) -contains $name) "$sub\$name exists"
                Assert-Equal ([Microsoft.Win32.RegistryValueKind]::String) $k.GetValueKind($name) "$sub\$name is a String"
                Assert-True ($k.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -ceq [string]$script:TrickyValues[$name]) "$sub\$name value"
            } finally { if ($k) { $k.Dispose() } }
        }

        # ACLs: Configure-Registry's own check, and the same DACL as Set-StrictRegAcl writes.
        $base.CreateSubKey($refRoot).Dispose()
        $KeyPath = "HKLM:\$refRoot"
        Set-StrictRegAcl
        $read = {
            param($sub)
            $k = $base.OpenSubKey($sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
            try { $k.GetAccessControl().GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access) } finally { $k.Dispose() }
        }
        $want = & $read $refRoot
        $keys = @($root, "$root\General", "$root\Printers", "$root\Applications")
        $accepted = Invoke-PDTestStrictRegAcl51 -KeyPaths @($keys | ForEach-Object { "HKLM:\$_" })
        for ($i = 0; $i -lt $keys.Count; $i++) {
            Assert-True $accepted[$i] "Test-StrictRegAcl accepts $($keys[$i])"
            Assert-Equal $want (& $read $keys[$i]) "$($keys[$i]) DACL equals Set-StrictRegAcl"
        }

        # What Security Manager runs: Configure-Registry.ps1 -Function Lockdown must find nothing to change.
        $lock = @(& $script:WinPS64 -NoProfile -ExecutionPolicy Bypass -File $configRegPath -KeyOnly $true -KeyPath "HKLM:\$root" -Function Lockdown -WorkingDirectory $wd 2>&1 | ForEach-Object { [string]$_ })
        Assert-Equal 0 $LASTEXITCODE 'Lockdown exit code'
        Assert-True (@($lock | Where-Object { $_ -like '*Registry ACL already strict. No changes made.*' }).Count -ge 1) 'Security Manager would find nothing to change'

        # Second run: nothing to do, still exit 0.
        $out2 = @(& $script:WinPS64 -NoProfile -ExecutionPolicy Bypass -File $run.Result.PlatformScript 2>&1 | ForEach-Object { [string]$_ })
        Assert-Equal 0 $LASTEXITCODE 'second run exit code'
        Assert-Equal 7 @($out2 | Where-Object { $_ -like '* : already correct*' }).Count 'every value already correct'

        # No value in output or log.
        $logText = (@(Get-ChildItem -LiteralPath (Join-Path $wd 'Logs\Config_Logs') -Filter 'PowerDeploy-OrgRegistry_PlatformScript._Log_*.log') | ForEach-Object { [System.IO.File]::ReadAllText($_.FullName) }) -join "`n"
        Assert-True ($logText.Length -gt 0) 'a log was written'
        foreach ($name in $script:TrickyValues.Keys) {
            $value = [string]$script:TrickyValues[$name]
            if ($value.Length -lt 10) { continue }
            Assert-True (-not ((($out + $out2) -join "`n").Contains($value))) "$name in the output"
            Assert-True (-not $logText.Contains($value)) "$name in the log"
        }
    } finally {
        foreach ($sub in @($root, $refRoot)) {
            try { $base.DeleteSubKeyTree($sub, $false) } catch { Write-Host "  WARNING: could not delete HKLM\$sub : $($_.Exception.Message)" -ForegroundColor Yellow }
        }
        $base.Dispose()
    }
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

foreach ($case in $script:Cases) {
    try {
        & $case.Body | Out-Null
        $script:Passed++
        Write-Host ("PASS  {0,-6} {1}" -f $case.Id, $case.Name) -ForegroundColor DarkGreen
    } catch {
        if (([string]$_.Exception.Message) -like 'PDTEST-SKIP:*') {
            $reason = ([string]$_.Exception.Message).Substring('PDTEST-SKIP:'.Length).Trim()
            $script:Skipped += @{ Id = $case.Id; Name = $case.Name; Reason = $reason }
            Write-Host ("SKIP  {0,-6} {1}" -f $case.Id, $case.Name) -ForegroundColor Yellow
            Write-Host ("      SKIPPED (not passed): {0}" -f $reason) -ForegroundColor Yellow
            continue
        }
        $script:Failures += @{ Id = $case.Id; Name = $case.Name; Reason = $_.Exception.Message; Site = $_.InvocationInfo.PositionMessage }
        Write-Host ("FAIL  {0,-6} {1}" -f $case.Id, $case.Name) -ForegroundColor Red
        Write-Host ("      {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    }
}

if (-not $KeepTemp) {
    try { Remove-Item -LiteralPath $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { }
} else {
    Write-Host "Temp kept at $script:TempRoot"
}

Write-Host ""
Write-Host "================================================================"
Write-Host (" Engine  : PowerShell {0}" -f $PSVersionTable.PSVersion)
Write-Host (" Passed  : {0} / {1}" -f $script:Passed, $script:Cases.Count)
Write-Host (" Skipped : {0}{1}" -f $script:Skipped.Count, $(if ($script:Skipped.Count) { ' (' + (($script:Skipped | ForEach-Object { $_.Id }) -join ', ') + ') - NOT passed' } else { '' }))
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
