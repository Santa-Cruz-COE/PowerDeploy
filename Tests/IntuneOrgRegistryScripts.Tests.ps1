<#

.SYNOPSIS
    Offline behavioural tests for the org registry scripts API upload
    (Other_Tools\Upload-InTuneOrgRegistryScripts.ps1) and its Setup.ps1 wizard side.

.DESCRIPTION
    Same dependency-free harness as Tests\IntuneGraphUpload.Tests.ps1 / Tests\PrinterIntuneBulk.Tests.ps1.
    Every Graph call goes through the helper library's TestTransport seam into a small in-memory
    tenant (Intune Platform Scripts, Intune Remediations, their assignments, and groups), so nothing
    here reaches Microsoft. No registry key is touched and no generated script is run.

        powershell -NoProfile -ExecutionPolicy Bypass -File Tests\IntuneOrgRegistryScripts.Tests.ps1
        pwsh       -NoProfile -ExecutionPolicy Bypass -File Tests\IntuneOrgRegistryScripts.Tests.ps1

    Exit code 0 = every case passed.

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

$repoRoot    = Split-Path $PSScriptRoot -Parent
$graphPath   = Join-Path $repoRoot 'Other_Tools\InTune-GraphAPI_Helpers.ps1'
$namingPath  = Join-Path $repoRoot 'Other_Tools\OrgRegistry-Intune_Helpers.ps1'
$enginePath  = Join-Path $repoRoot 'Other_Tools\Upload-InTuneOrgRegistryScripts.ps1'
$setupPath   = Join-Path $repoRoot 'Setup.ps1'

foreach ($path in @($graphPath, $namingPath, $enginePath, $setupPath)) {
    if (-not (Test-Path -LiteralPath $path)) { Write-Host "FATAL: $path not found"; exit 2 }
}

$script:TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('PowerDeploy-OrgRegUploadTests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null

Write-Host "================================================================"
Write-Host " IntuneOrgRegistryScripts tests"
Write-Host " Engine : PowerShell $($PSVersionTable.PSVersion)"
Write-Host " Temp   : $script:TempRoot"
Write-Host "================================================================"
Write-Host ""

# Import purity, in a throwaway scope first.
$script:ImportOutput = @(& { . $graphPath; . $namingPath; . $enginePath })
$script:FunctionsBefore = @(Get-ChildItem function: | ForEach-Object Name)
. $graphPath
. $namingPath
. $enginePath
$script:EngineFunctions = @(Get-ChildItem function: | ForEach-Object Name | Where-Object { $script:FunctionsBefore -notcontains $_ })

# A read that fails must fail once, not sleep through retries.
$script:PDGraph.MaxAttempts = 1

$script:FakeAuth = @{ AccessToken = 'fake-token-never-real' }

# ---------------------------------------------------------------------------
# Fixtures: script files carrying distinctive fake secrets
# ---------------------------------------------------------------------------

$script:FakeSas   = 'sv=2024-11-04&ss=b&sig=FAKESASSIGNATUREq7Zp3Lw9XcVb2Nm4'
$script:FakeToken = 'ghp_FAKEREPOTOKENa8s7d6f5g4h3j2k1'

function New-ScriptFile {
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][string]$Text, [switch]$Bom)
    $path = Join-Path $script:TempRoot ([guid]::NewGuid().ToString('N') + '-' + $Name)
    [System.IO.File]::WriteAllText($path, $Text, (New-Object System.Text.UTF8Encoding([bool]$Bom)))
    return $path
}

$script:PlatformFile    = New-ScriptFile -Name 'PowerDeploy-OrgRegistry_abc1234.ps1' -Bom -Text ("# platform`r`n`$sas = '{0}'`r`n`$tok = '{1}'`r`nexit 0`r`n" -f $script:FakeSas, $script:FakeToken)
$script:DetectionFile   = New-ScriptFile -Name 'Detect.ps1' -Text ("# detect`r`n`$u = 'https://oauth2:{0}@github.com/x/y'`r`n" -f $script:FakeToken)
$script:RemediationFile = New-ScriptFile -Name 'Remediate.ps1' -Text ("# remediate`r`n`$s = '{0}'`r`n" -f $script:FakeSas)

$script:ContentBase64 = @(
    [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($script:PlatformFile)),
    [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($script:DetectionFile)),
    [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($script:RemediationFile))
)

function New-Content {
    return @{
        PlatformScript = @{ Script = (Get-PDOrgRegistryFileFingerprint -Path $script:PlatformFile) }
        Remediation    = @{ Detection = (Get-PDOrgRegistryFileFingerprint -Path $script:DetectionFile); Remediation = (Get-PDOrgRegistryFileFingerprint -Path $script:RemediationFile) }
    }
}

function New-Metadata {
    param([string]$Mode = 'PRODUCTION', [string]$Commit = 'abc1234')
    return @{
        PlatformScript = @{
            DisplayName = (Get-PDOrgRegistryIntuneDisplayName -Type PlatformScript -DeployMode $Mode -SourceCommit $Commit)
            Description = (Get-PDOrgRegistryIntuneDescription -Type PlatformScript -DeployMode $Mode -SourceCommit $Commit -GeneratedAt '2026-11-09 10:00:00')
            FileName    = (Get-PDOrgRegistryPlatformScriptFileName -SourceCommit $Commit)
        }
        Remediation = @{
            DisplayName = (Get-PDOrgRegistryIntuneDisplayName -Type Remediation -DeployMode $Mode -SourceCommit $Commit)
            Description = (Get-PDOrgRegistryIntuneDescription -Type Remediation -DeployMode $Mode -SourceCommit $Commit -GeneratedAt '2026-11-09 10:00:00')
        }
    }
}

$script:LogLines = @()
$script:TestLog = { param($Message, $Level) $script:LogLines += ('[{0}] {1}' -f $Level, $Message) }

# ---------------------------------------------------------------------------
# Mock tenant behind the TestTransport seam
# ---------------------------------------------------------------------------

$script:Collections = @{ PlatformScript = 'deviceManagementScripts'; Remediation = 'deviceHealthScripts' }
$script:AssignProperty = @{ PlatformScript = 'deviceManagementScriptAssignments'; Remediation = 'deviceHealthScriptAssignments' }

function New-MockResponse {
    param([int]$Status = 200, [AllowNull()][object]$Body = $null, [hashtable]$Headers = @{})
    $text = ''
    if ($null -ne $Body) { if ($Body -is [string]) { $text = $Body } else { $text = ($Body | ConvertTo-Json -Depth 30 -Compress) } }
    $all = @{ 'request-id' = 'mock-req' }
    foreach ($key in $Headers.Keys) { $all[$key] = $Headers[$key] }
    return @{ StatusCode = $Status; Body = $text; Headers = $all; TransportError = $null }
}

function New-TransportFailure {
    return @{ StatusCode = 0; Body = ''; Headers = @{}; TransportError = @{ TransportFailure = $true; Message = 'The connection was closed.' } }
}

function Reset-Tenant {
    param([int]$PageSize = 50)
    $script:Tenant = @{
        PlatformScript = New-Object System.Collections.ArrayList
        Remediation    = New-Object System.Collections.ArrayList
        Groups         = @{
            '11111111-1111-1111-1111-111111111111' = 'IT PCs'
            '22222222-2222-2222-2222-222222222222' = 'Autopilot Devices'
            '33333333-3333-3333-3333-333333333333' = 'Lab PCs'
        }
        PageSize       = $PageSize
        NextId         = 100
    }
    $script:Calls = @()
    $script:Hook = $null
    $script:LogLines = @()
    $script:PDGraph.TestTransport = { param($Request) return (Invoke-MockTenant -Request $Request) }
}

function New-TenantId {
    $script:Tenant.NextId++
    return ('aaaaaaaa-0000-0000-0000-{0:D12}' -f $script:Tenant.NextId)
}

function Add-TenantObject {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PlatformScript', 'Remediation')][string]$Type,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [string]$Description = '',
        [object[]]$Assignments = @(),
        [string]$Id
    )
    if (-not $Id) { $Id = New-TenantId }
    $object = @{ id = $Id; displayName = $DisplayName; description = $Description; lastModifiedDateTime = '2026-11-01T08:00:00Z'
                 runAsAccount = 'system'; enforceSignatureCheck = $false; runAs32Bit = $false; assignments = @() }
    if ($Type -eq 'PlatformScript') { $object['fileName'] = 'old.ps1'; $object['scriptContent'] = 'b2xk' }
    else { $object['publisher'] = 'Someone'; $object['detectionScriptContent'] = 'b2xk'; $object['remediationScriptContent'] = 'b2xk'; $object['version'] = '15' }
    $stored = @()
    foreach ($assignment in @($Assignments)) {
        $copy = ($assignment | ConvertTo-Json -Depth 20 -Compress) | ConvertFrom-Json
        if ($null -eq $copy.PSObject.Properties['id']) { $copy | Add-Member -NotePropertyName id -NotePropertyValue ($Id + ':' + [guid]::NewGuid().ToString()) }
        $stored += $copy
    }
    $object['assignments'] = $stored
    [void]$script:Tenant[$Type].Add($object)
    return $Id
}

function Get-TenantObject {
    param([string]$Type, [string]$Id)
    foreach ($object in $script:Tenant[$Type]) { if ($object.id -eq $Id) { return $object } }
    return $null
}

function New-GroupAssignment {
    param([string]$GroupId, [switch]$Remediation, [switch]$Daily)
    $assignment = [ordered]@{ target = [ordered]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $GroupId; deviceAndAppManagementAssignmentFilterId = '00000000-0000-0000-0000-000000000000'; deviceAndAppManagementAssignmentFilterType = 'none' } }
    if ($Remediation) {
        $assignment['runRemediationScript'] = $false
        if ($Daily) { $assignment['runSchedule'] = [ordered]@{ '@odata.type' = '#microsoft.graph.deviceHealthScriptDailySchedule'; interval = 1; time = '08:00:00'; useUtc = $false } }
        else { $assignment['runSchedule'] = [ordered]@{ '@odata.type' = '#microsoft.graph.deviceHealthScriptHourlySchedule'; interval = 1 } }
    }
    return [pscustomobject]$assignment
}

function New-AllDevicesAssignment {
    param([switch]$Remediation)
    # Exactly the shape the live tenant returned for the hand-made Intune Remediation (2026-11-09).
    $assignment = [ordered]@{ target = [ordered]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget'; deviceAndAppManagementAssignmentFilterId = '00000000-0000-0000-0000-000000000000'; deviceAndAppManagementAssignmentFilterType = 'none' } }
    if ($Remediation) {
        $assignment['runRemediationScript'] = $false
        $assignment['runSchedule'] = [ordered]@{ '@odata.type' = '#microsoft.graph.deviceHealthScriptHourlySchedule'; interval = 1 }
    }
    return [pscustomobject]$assignment
}

function Invoke-MockTenant {
    param([hashtable]$Request)

    $method = [string]$Request.Method
    $uri = [System.Uri]::UnescapeDataString([string]$Request.Uri)
    $bodyText = ''
    if ($null -ne $Request.BodyBytes) { $bodyText = [System.Text.Encoding]::UTF8.GetString([byte[]]$Request.BodyBytes) }
    $script:Calls += [pscustomobject]@{ Method = $method; Uri = $uri; Body = $bodyText }

    if ($null -ne $script:Hook) {
        $hooked = & $script:Hook $method $uri $bodyText
        if ($null -ne $hooked) { return $hooked }
    }

    $groups = [regex]::Match($uri, '^https://graph\.microsoft\.com/v1\.0/groups(?:/(?<id>[^/?]+))?(?:\?(?<q>.*))?$')
    if ($groups.Success) {
        if ($groups.Groups['id'].Success) {
            $gid = $groups.Groups['id'].Value
            if ($script:Tenant.Groups.ContainsKey($gid)) { return (New-MockResponse -Body @{ id = $gid; displayName = $script:Tenant.Groups[$gid] }) }
            return (New-MockResponse -Status 404 -Body @{ error = @{ code = 'Request_ResourceNotFound'; message = 'not found' } })
        }
        $name = [regex]::Match($groups.Groups['q'].Value, "displayName eq '(?<n>(?:[^']|'')*)'").Groups['n'].Value.Replace("''", "'")
        $found = @($script:Tenant.Groups.Keys | Where-Object { $script:Tenant.Groups[$_] -eq $name } | ForEach-Object { @{ id = $_; displayName = $script:Tenant.Groups[$_] } })
        return (New-MockResponse -Body @{ value = $found })
    }

    $m = [regex]::Match($uri, '^https://graph\.microsoft\.com/beta/deviceManagement/(?<coll>deviceManagementScripts|deviceHealthScripts)(?:/(?<id>[^/?]+))?(?:/(?<sub>assignments|assign))?(?:\?(?<q>.*))?$')
    if (-not $m.Success) { throw ("mock tenant has no route for {0} {1}" -f $method, $uri) }

    $type = 'PlatformScript'
    if ($m.Groups['coll'].Value -eq 'deviceHealthScripts') { $type = 'Remediation' }
    $id = $m.Groups['id'].Value
    $sub = $m.Groups['sub'].Value
    $query = $m.Groups['q'].Value

    if (-not $id) {
        if ($method -eq 'Get') {
            $skip = 0
            $skipMatch = [regex]::Match($query, '\$skiptoken=(?<n>\d+)')
            if ($skipMatch.Success) { $skip = [int]$skipMatch.Groups['n'].Value }
            $select = [regex]::Match($query, '\$select=(?<s>[^&]*)').Groups['s'].Value
            $fields = @('id', 'displayName')
            if ($select) { $fields = @($select -split ',') }
            $all = @($script:Tenant[$type])
            $page = @()
            for ($i = $skip; $i -lt [Math]::Min($all.Count, $skip + $script:Tenant.PageSize); $i++) {
                $item = @{}
                foreach ($field in $fields) { if ($all[$i].ContainsKey($field)) { $item[$field] = $all[$i][$field] } }
                $page += $item
            }
            $body = @{ value = $page }
            if (($skip + $script:Tenant.PageSize) -lt $all.Count) {
                $body['@odata.nextLink'] = ('https://graph.microsoft.com/beta/deviceManagement/{0}?$select={1}&$skiptoken={2}' -f $m.Groups['coll'].Value, ($fields -join ','), ($skip + $script:Tenant.PageSize))
            }
            return (New-MockResponse -Body $body)
        }
        if ($method -eq 'Post') {
            $parsed = $bodyText | ConvertFrom-Json
            $newId = New-TenantId
            $object = @{ id = $newId; lastModifiedDateTime = '2026-11-09T10:00:00Z'; assignments = @() }
            foreach ($property in $parsed.PSObject.Properties) { if ($property.Name -ne '@odata.type') { $object[$property.Name] = $property.Value } }
            [void]$script:Tenant[$type].Add($object)
            return (New-MockResponse -Status 201 -Body @{ id = $newId; displayName = $object.displayName })
        }
        throw ("mock tenant: unexpected {0} on the collection" -f $method)
    }

    $object = Get-TenantObject -Type $type -Id $id
    if ($null -eq $object) { return (New-MockResponse -Status 404 -Body @{ error = @{ code = 'ResourceNotFound'; message = 'not found' } }) }

    if ($sub -eq 'assignments') {
        if ($method -ne 'Get') { throw 'mock tenant: assignments is read-only' }
        return (New-MockResponse -Body @{ value = @($object.assignments) })
    }

    if ($sub -eq 'assign') {
        $parsed = $bodyText | ConvertFrom-Json
        $list = @()
        foreach ($assignment in @($parsed.($script:AssignProperty[$type]))) {
            if ($null -eq $assignment) { continue }
            $copy = ($assignment | ConvertTo-Json -Depth 20 -Compress) | ConvertFrom-Json
            if ($null -ne $copy.PSObject.Properties['@odata.type']) { $copy.PSObject.Properties.Remove('@odata.type') }
            if ($null -eq $copy.PSObject.Properties['id']) { $copy | Add-Member -NotePropertyName id -NotePropertyValue ($id + ':' + [guid]::NewGuid().ToString()) }
            $list += $copy
        }
        $object['assignments'] = $list
        return (New-MockResponse -Status 204)
    }

    switch ($method) {
        'Get' {
            $full = @{ '@odata.type' = '#microsoft.graph.x' }
            foreach ($key in $object.Keys) { if ($key -ne 'assignments') { $full[$key] = $object[$key] } }
            return (New-MockResponse -Body $full)
        }
        'Patch' {
            $parsed = $bodyText | ConvertFrom-Json
            foreach ($property in $parsed.PSObject.Properties) { if ($property.Name -ne '@odata.type') { $object[$property.Name] = $property.Value } }
            $object['lastModifiedDateTime'] = '2026-11-09T10:00:00Z'
            return (New-MockResponse -Status 204)
        }
        'Delete' {
            $script:Tenant[$type].Remove($object)
            return (New-MockResponse -Status 204)
        }
    }
    throw ("mock tenant: unexpected {0} {1}" -f $method, $uri)
}

function Get-Calls { param([string]$Method, [string]$Like = '*') return @($script:Calls | Where-Object { (-not $Method -or $_.Method -eq $Method) -and $_.Uri -like $Like }) }

function Invoke-TestUpload {
    param([string[]]$Types = @('Remediation', 'PlatformScript'), [string]$Mode = 'PRODUCTION', [object[]]$Targets, [switch]$Keep, [hashtable]$SelectedIds, [hashtable]$Metadata, [object[]]$RedactValues)
    $inventory = @(Get-PDOrgRegistryIntuneObjects -AuthContext $script:FakeAuth -Types @('PlatformScript', 'Remediation'))
    $plan = New-PDOrgRegistryUploadPlan -Inventory $inventory -Types $Types -DeployMode $Mode -SelectedIds $SelectedIds
    if (-not $Metadata) { $Metadata = New-Metadata -Mode $Mode }
    $arguments = @{ AuthContext = $script:FakeAuth; Plan = $plan; Metadata = $Metadata; Content = (New-Content); Log = $script:TestLog }
    if ($Keep) { $arguments['KeepAssignments'] = $true } else { $arguments['Targets'] = @($Targets) }
    if ($PSBoundParameters.ContainsKey('RedactValues')) { $arguments['RedactValues'] = @($RedactValues) }
    $script:Calls = @()
    return (Invoke-PDOrgRegistryUpload @arguments)
}

function Get-ByType {
    param([object[]]$List, [string]$Type)
    return @(@($List) | Where-Object { $_.Type -eq $Type })[0]
}

function Get-GroupTargets {
    param([string[]]$Terms)
    return @(ConvertTo-PDOrgRegistryTargets -ResolvedGroups @(Resolve-PDGraphGroups -RequiredGroups $Terms -AuthContext $script:FakeAuth))
}

# ---------------------------------------------------------------------------
# Import, Setup.ps1 structure, naming
# ---------------------------------------------------------------------------

$script:SetupAst = [System.Management.Automation.Language.Parser]::ParseFile($setupPath, [ref]$null, [ref]$null)
$script:SetupFunctions = @($script:SetupAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))

$script:WizardHelpers = @('Read-OrgRegistryMenuChoice', 'Read-OrgRegistryYesNo', 'Write-OrgRegistryDescriptionLines', 'Show-OrgRegistryGuidedRemediation',
                          'Show-OrgRegistryGuidedPlatformScript', 'Test-OrgRegistryApiReady', 'Connect-OrgRegistryApi', 'Show-OrgRegistryMaaGuidance',
                          'Get-OrgRegistryTypeList', 'Read-OrgRegistryCopyChoice', 'Read-OrgRegistryAssignment', 'Show-OrgRegistryUploadReview',
                          'Invoke-OrgRegistryIntuneDeletionList', 'Invoke-OrgRegistryIntuneDeletion', 'Invoke-OrgRegistryIntuneAutoUpload')

Add-TestCase 'O01' 'the engine imports silently, defines no "--" function, and Setup.ps1 loads it at script scope' {
    Assert-Equal 0 $script:ImportOutput.Count 'dot-sourcing produced output'
    foreach ($fn in $script:EngineFunctions) { Assert-True ($fn -notlike '*--*') "engine function $fn contains -- and would appear in the Setup menu" }
    foreach ($fn in @('Get-PDOrgRegistryAuthContext', 'Get-PDOrgRegistryIntuneObjects', 'New-PDOrgRegistryUploadPlan', 'Get-PDOrgRegistryKeepOption',
                      'ConvertTo-PDOrgRegistryTargets', 'Find-PDOrgRegistryAssignmentOverlap', 'Invoke-PDOrgRegistryUpload',
                      'Get-PDOrgRegistryDeletionList', 'ConvertFrom-PDOrgRegistryDeletionSelection', 'Remove-PDOrgRegistryIntuneObject')) {
        Assert-True ($null -ne (Get-Command -CommandType Function -Name $fn -ErrorAction SilentlyContinue)) "$fn is defined"
    }

    $target = '. $OrgRegistryUploadScriptPath'
    $found = @($script:SetupAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.PipelineAst] -and [string]$n.Extent.Text -eq $target }, $true))
    Assert-Equal 1 $found.Count 'Setup.ps1 dot-sources the engine exactly once'
    $node = $found[0]; $inFunction = $false
    while ($null -ne $node) { if ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $inFunction = $true; break }; $node = $node.Parent }
    Assert-True (-not $inFunction) 'the dot-source is at script scope'

    foreach ($helper in $script:WizardHelpers) {
        $fn = @($script:SetupFunctions | Where-Object { $_.Name -eq $helper })
        Assert-Equal 1 $fn.Count "$helper is defined once"
        Assert-True ($helper -notlike '*--*') "$helper must not contain '--'"
        Assert-Equal 0 @($fn[0].FindAll({ param($n) $n -is [System.Management.Automation.Language.ExitStatementAst] }, $true)).Count "$helper must never call exit"
    }
}

Add-TestCase 'O02' 'the MODE class is the printer parser''s: stray whitespace or lower case never matches' {
    foreach ($good in @('POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC-TESTING] [VER: abc]', 'POWERDEPLOY ORG REGISTRY: Remediation [MODE: PRIVATE-DEVELOPMENT] [VER: 1a2b3c4.UnstagedChanges]', 'POWERDEPLOY ORG REGISTRY: Remediation [MODE: X1] [VER: ]')) {
        Assert-True (ConvertFrom-PDOrgRegistryIntuneDisplayName -DisplayName $good).IsOrgRegistry "'$good' parses"
    }
    $nearCopies = @(
        'POWERDEPLOY ORG REGISTRY: Platform Script [MODE:  PUBLIC-TESTING] [VER: abc]',
        'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC-TESTING ] [VER: abc]',
        'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC TESTING] [VER: abc]',
        'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: public-testing] [VER: abc]',
        'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: -TESTING] [VER: abc]',
        'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: 1TEST] [VER: abc]',
        "POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC-TESTING`t] [VER: abc]",
        'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC_TESTING] [VER: abc]'
    )
    foreach ($name in $nearCopies) {
        Assert-True (-not (ConvertFrom-PDOrgRegistryIntuneDisplayName -DisplayName $name).IsOrgRegistry) "'$name' must not parse"
        Assert-True (-not (Test-PDOrgRegistryIntuneNameMatch -DisplayName $name -Type PlatformScript -DeployMode 'PUBLIC-TESTING')) "'$name' must not match PUBLIC-TESTING"
    }
}

# ---------------------------------------------------------------------------
# Inventory and plan
# ---------------------------------------------------------------------------

Add-TestCase 'O10' 'the listing follows every page, uses $select, never asks for content, and keeps only the prefix' {
    Reset-Tenant -PageSize 2
    Add-TenantObject -Type PlatformScript -DisplayName 'Some other script' | Out-Null
    Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script' -Description "x`nSource commit: 1234abc`ny" -Assignments @(New-GroupAssignment -GroupId '11111111-1111-1111-1111-111111111111') | Out-Null
    Add-TenantObject -Type PlatformScript -DisplayName 'Another script' | Out-Null
    Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC-TESTING] [VER: f00d123]' | Out-Null
    Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script [MODE:  PUBLIC-TESTING] [VER: f00d123]' | Out-Null
    Add-TenantObject -Type PlatformScript -DisplayName 'powerdeploy org registry: Platform Script' | Out-Null
    Add-TenantObject -Type Remediation -DisplayName 'PRODUCTION: PowerDeploy Registry Remediation Script' | Out-Null
    Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' -Assignments @(New-AllDevicesAssignment -Remediation) | Out-Null

    $inventory = @(Get-PDOrgRegistryIntuneObjects -AuthContext $script:FakeAuth)

    Assert-Equal 4 $inventory.Count 'three Intune Platform Scripts with the prefix (one a near-copy) and one Intune Remediation; the hand-made name and the lower-case one are not listed'
    $lists = @(Get-Calls -Method Get | Where-Object { $_.Uri -match '/(deviceManagementScripts|deviceHealthScripts)\?' })
    Assert-Equal 4 $lists.Count 'six Intune Platform Scripts in pages of two (3 pages), and one page of Intune Remediations'
    foreach ($call in @(Get-Calls -Method Get -Like '*/deviceManagement/*')) {
        Assert-True ($call.Uri -notmatch '(?i)scriptContent') "no listing or assignments read asks for content: $($call.Uri)"
    }
    foreach ($call in $lists) { Assert-Like '*$select=id,displayName,description,lastModifiedDateTime*' $call.Uri 'every page carries $select' }

    $prod = @($inventory | Where-Object { $_.DisplayName -eq 'POWERDEPLOY ORG REGISTRY: Platform Script' })[0]
    Assert-Equal 'PRODUCTION' $prod.DeployMode 'production parsed'
    Assert-Equal '1234abc' $prod.Commit 'a production commit comes from the description'
    Assert-Equal 'IT PCs (11111111-1111-1111-1111-111111111111)' $prod.AssignmentLines[0] 'group names are resolved for display'
    $test = @($inventory | Where-Object { $_.DeployMode -eq 'PUBLIC-TESTING' })[0]
    Assert-Equal 'f00d123' $test.Commit 'the VER part is the commit'
    $near = @($inventory | Where-Object { -not $_.IsRecognized })
    Assert-Equal 1 $near.Count 'the near-copy is listed but not recognized'
    $rem = @($inventory | Where-Object { $_.Type -eq 'Remediation' })[0]
    Assert-Equal 'All devices (built-in Intune target) - Hourly, every 1 hour' $rem.AssignmentLines[0] 'All devices and the schedule are shown'
    Assert-Equal 'Daily, every 2 days at 08:00:00' (Get-PDOrgRegistryScheduleText -Assignment ([pscustomobject]@{ runSchedule = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceHealthScriptDailySchedule'; interval = 2; time = '08:00:00' } })) 'plural schedule text'
}

Add-TestCase 'O11' 'plan: no match creates, one match updates, several need a choice, a choice updates only that one' {
    Reset-Tenant
    $plan = New-PDOrgRegistryUploadPlan -Inventory @() -Types @('PlatformScript', 'Remediation') -DeployMode 'PRODUCTION'
    Assert-Equal 'Create|Create' (@($plan.Entries | ForEach-Object Action) -join '|') 'nothing in Intune: both are created'

    $one = Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation'
    Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation [MODE: PUBLIC-TESTING] [VER: a]' | Out-Null
    $a = Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC-TESTING] [VER: a]'
    $b = Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC-TESTING] [VER: b]'
    $inventory = @(Get-PDOrgRegistryIntuneObjects -AuthContext $script:FakeAuth -SkipGroupNames)

    $plan = New-PDOrgRegistryUploadPlan -Inventory $inventory -Types @('Remediation') -DeployMode 'PRODUCTION'
    Assert-Equal 'Update' $plan.Entries[0].Action 'one production copy: update it'
    Assert-Equal $one $plan.Entries[0].Target.Id 'the production copy, not the PUBLIC-TESTING one'

    $plan = New-PDOrgRegistryUploadPlan -Inventory $inventory -Types @('PlatformScript', 'Remediation') -DeployMode 'PUBLIC-TESTING'
    $psEntry = @($plan.Entries | Where-Object { $_.Type -eq 'PlatformScript' })[0]
    Assert-Equal 'Remediation|PlatformScript' (@($plan.Entries | ForEach-Object Type) -join '|') 'the order of the menu: the Intune Remediation, then the Intune Platform Script'
    Assert-Equal 'Choose' $psEntry.Action 'two PUBLIC-TESTING Intune Platform Scripts: a choice'
    Assert-Equal 2 @($psEntry.Candidates).Count 'both are candidates, whatever their VER'
    Assert-True $plan.NeedsChoice 'the plan says so'

    $result = Invoke-PDOrgRegistryUpload -AuthContext $script:FakeAuth -Plan $plan -Metadata (New-Metadata -Mode 'PUBLIC-TESTING') -Content (New-Content) -Targets @(Get-GroupTargets -Terms @('IT PCs'))
    Assert-True (-not $result.Success) 'a plan that still needs a choice writes nothing'
    Assert-Equal 0 (@(Get-Calls -Method Post).Count + @(Get-Calls -Method Patch).Count) 'no write at all'

    $plan = New-PDOrgRegistryUploadPlan -Inventory $inventory -Types @('PlatformScript') -DeployMode 'PUBLIC-TESTING' -SelectedIds @{ PlatformScript = $b }
    Assert-Equal 'Update' $plan.Entries[0].Action 'chosen'
    Assert-Equal $b $plan.Entries[0].Target.Id 'the chosen copy'
    Assert-Throws { New-PDOrgRegistryUploadPlan -Inventory $inventory -Types @('PlatformScript') -DeployMode 'PUBLIC-TESTING' -SelectedIds @{ PlatformScript = $one } } -MessagePattern '*is not one of the existing*' | Out-Null
}

# ---------------------------------------------------------------------------
# Upload: create, update
# ---------------------------------------------------------------------------

Add-TestCase 'O20' 'create: exact bodies, hourly schedule on the new Intune Remediation assignment, verified, one POST each' {
    Reset-Tenant
    $result = Invoke-TestUpload -Targets @(Get-GroupTargets -Terms @('Autopilot Devices'))

    Assert-True $result.Success "both verified: $(@($result.Objects | ForEach-Object Message) -join ' | ')"
    Assert-Equal 'Verified|Verified' (@($result.Objects | ForEach-Object Status) -join '|') 'both verified'
    Assert-Equal 1 @(Get-Calls -Method Post -Like '*/deviceManagementScripts').Count 'one create of the Intune Platform Script'
    Assert-Equal 1 @(Get-Calls -Method Post -Like '*/deviceHealthScripts').Count 'one create of the Intune Remediation'

    $ps = (Get-Calls -Method Post -Like '*/deviceManagementScripts')[0].Body | ConvertFrom-Json
    Assert-Equal '#microsoft.graph.deviceManagementScript' $ps.'@odata.type' 'platform script type'
    Assert-Equal 'POWERDEPLOY ORG REGISTRY: Platform Script' $ps.displayName 'platform script name'
    Assert-Equal 'system' $ps.runAsAccount 'runs as system'
    Assert-True ($ps.enforceSignatureCheck -eq $false -and $ps.runAs32Bit -eq $false) 'signature check off, 64-bit'
    Assert-Equal 'PowerDeploy-OrgRegistry_abc1234.ps1' $ps.fileName 'file name'
    Assert-Equal $script:ContentBase64[0] $ps.scriptContent 'base64 of the file bytes as written, BOM included'
    Assert-True ([System.Convert]::FromBase64String($ps.scriptContent)[0] -eq 0xEF) 'the BOM is part of the content'

    $rem = (Get-Calls -Method Post -Like '*/deviceHealthScripts')[0].Body | ConvertFrom-Json
    Assert-Equal '#microsoft.graph.deviceHealthScript' $rem.'@odata.type' 'remediation type'
    Assert-Equal 'PowerDeploy' $rem.publisher 'publisher'
    Assert-Equal $script:ContentBase64[1] $rem.detectionScriptContent 'detection content'
    Assert-Equal $script:ContentBase64[2] $rem.remediationScriptContent 'remediation content'
    Assert-True ($null -eq $rem.PSObject.Properties['version']) 'the Intune-managed version is never sent'

    $psAssign = (Get-Calls -Method Post -Like '*/deviceManagementScripts/*/assign')[0].Body | ConvertFrom-Json
    Assert-Equal 1 @($psAssign.deviceManagementScriptAssignments).Count 'one platform script assignment'
    Assert-Equal '#microsoft.graph.deviceManagementScriptAssignment' $psAssign.deviceManagementScriptAssignments[0].'@odata.type' 'assignment type'
    Assert-Equal '22222222-2222-2222-2222-222222222222' $psAssign.deviceManagementScriptAssignments[0].target.groupId 'group target'

    $remAssign = (Get-Calls -Method Post -Like '*/deviceHealthScripts/*/assign')[0].Body | ConvertFrom-Json
    $first = $remAssign.deviceHealthScriptAssignments[0]
    Assert-True ($first.runRemediationScript -eq $true) 'new assignments send runRemediationScript = true'
    Assert-Equal '#microsoft.graph.deviceHealthScriptHourlySchedule' $first.runSchedule.'@odata.type' 'hourly'
    Assert-Equal 1 ([int]$first.runSchedule.interval) 'every hour'

    foreach ($object in @($result.Objects)) {
        Assert-True $object.Created 'created in this run'
        Assert-Like 'https://intune.microsoft.com/*' $object.PortalUrl 'Intune admin center link'
        Assert-Like ('*' + $object.Id + '*') $object.PortalUrl 'the link names the object'
    }
    Assert-Equal 0 @(Get-Calls -Method Delete).Count 'nothing deleted'
}

Add-TestCase 'O21' 'update: PATCH in place (no create), name and content replaced, the old version is not touched' {
    Reset-Tenant
    $old = Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation [MODE: PUBLIC-TESTING] [VER: 0000aaa]' -Assignments @(New-GroupAssignment -GroupId '33333333-3333-3333-3333-333333333333' -Remediation)
    $result = Invoke-TestUpload -Types @('Remediation') -Mode 'PUBLIC-TESTING' -Targets @(Get-GroupTargets -Terms @('Lab PCs'))

    Assert-True $result.Success "verified: $($result.Objects[0].Message)"
    Assert-Equal 'Update' $result.Objects[0].Action 'updated'
    Assert-Equal $old $result.Objects[0].Id 'the same object'
    Assert-Equal 0 @(Get-Calls -Method Post -Like '*/deviceHealthScripts').Count 'no create'
    Assert-Equal 1 @(Get-Calls -Method Patch).Count 'one PATCH'
    $stored = Get-TenantObject -Type Remediation -Id $old
    Assert-Equal 'POWERDEPLOY ORG REGISTRY: Remediation [MODE: PUBLIC-TESTING] [VER: abc1234]' $stored.displayName 'the new VER'
    Assert-Equal '15' $stored.version 'version is left to Intune'
    Assert-Equal $script:ContentBase64[2] $stored.remediationScriptContent 'content replaced'
    Assert-True (-not $result.Objects[0].Created) 'not created in this run'
}

# ---------------------------------------------------------------------------
# Assignments: keep vs replace
# ---------------------------------------------------------------------------

Add-TestCase 'O30' 'Enter keeps only when every object is an update with the same assignment set' {
    Reset-Tenant
    Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script' -Assignments @(New-AllDevicesAssignment) | Out-Null
    Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' -Assignments @(New-AllDevicesAssignment -Remediation) | Out-Null
    $inventory = @(Get-PDOrgRegistryIntuneObjects -AuthContext $script:FakeAuth -SkipGroupNames)

    $both = New-PDOrgRegistryUploadPlan -Inventory $inventory -Types @('PlatformScript', 'Remediation') -DeployMode 'PRODUCTION'
    Assert-True (Get-PDOrgRegistryKeepOption -Plan $both).Available 'same set (schedules aside): keep offered'

    $createOne = New-PDOrgRegistryUploadPlan -Inventory @($inventory | Where-Object { $_.Type -eq 'Remediation' }) -Types @('PlatformScript', 'Remediation') -DeployMode 'PRODUCTION'
    $option = Get-PDOrgRegistryKeepOption -Plan $createOne
    Assert-True (-not $option.Available) 'a run that creates an object needs groups'
    Assert-Like '*is new*' $option.Reason 'and says why'
    $script:Calls = @()
    $refused = Invoke-PDOrgRegistryUpload -AuthContext $script:FakeAuth -Plan $createOne -Metadata (New-Metadata) -Content (New-Content) -KeepAssignments
    Assert-Equal 'NotAttempted|NotAttempted' (@($refused.Objects | ForEach-Object Status) -join '|') 'the engine refuses to "keep" for a new object'
    Assert-Equal 0 @($script:Calls).Count 'and sends nothing'

    Reset-Tenant
    Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script' -Assignments @(New-GroupAssignment -GroupId '22222222-2222-2222-2222-222222222222') | Out-Null
    Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' -Assignments @(New-AllDevicesAssignment -Remediation) | Out-Null
    $inventory = @(Get-PDOrgRegistryIntuneObjects -AuthContext $script:FakeAuth -SkipGroupNames)
    $differ = New-PDOrgRegistryUploadPlan -Inventory $inventory -Types @('PlatformScript', 'Remediation') -DeployMode 'PRODUCTION'
    $option = Get-PDOrgRegistryKeepOption -Plan $differ
    Assert-True (-not $option.Available) 'different sets: groups must be entered'
    Assert-Like '*different groups*' $option.Reason 'and says why'
}

Add-TestCase 'O31' 'kept assignments are re-sent exactly as Intune returned them (id, runRemediationScript false, filter fields)' {
    Reset-Tenant
    $id = Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' -Assignments @(New-AllDevicesAssignment -Remediation)
    $before = (Get-TenantObject -Type Remediation -Id $id).assignments[0] | ConvertTo-Json -Depth 20 -Compress

    $result = Invoke-TestUpload -Types @('Remediation') -Keep
    Assert-True $result.Success "verified: $($result.Objects[0].Message)"

    $sent = (Get-Calls -Method Post -Like '*/assign')[0].Body | ConvertFrom-Json
    $sentJson = $sent.deviceHealthScriptAssignments[0] | ConvertTo-Json -Depth 20 -Compress
    Assert-Equal $before $sentJson 'the assignment object is sent unchanged'
    Assert-True ($sent.deviceHealthScriptAssignments[0].runRemediationScript -eq $false) 'the flag is not "fixed"'
    Assert-True ($null -ne $sent.deviceHealthScriptAssignments[0].PSObject.Properties['id']) 'the id is sent as returned'
}

Add-TestCase 'O32' 'kept assignments refused with HTTP 400 are sent once more without their read-only id' {
    Reset-Tenant
    Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' -Assignments @(New-GroupAssignment -GroupId '11111111-1111-1111-1111-111111111111' -Remediation -Daily) | Out-Null
    $script:AssignAttempts = 0
    $hook = {
        param($Method, $Uri, $Body)
        if ($Method -eq 'Post' -and $Uri -like '*/assign') {
            $script:AssignAttempts++
            if ($Body -match '"id"') { return (New-MockResponse -Status 400 -Body @{ error = @{ code = 'ModelValidationFailure'; message = 'The property id is read-only.' } }) }
        }
        return $null
    }
    $inventory = @(Get-PDOrgRegistryIntuneObjects -AuthContext $script:FakeAuth -SkipGroupNames)
    $plan = New-PDOrgRegistryUploadPlan -Inventory $inventory -Types @('Remediation') -DeployMode 'PRODUCTION'
    $script:Hook = $hook
    $script:Calls = @()
    $result = Invoke-PDOrgRegistryUpload -AuthContext $script:FakeAuth -Plan $plan -Metadata (New-Metadata) -Content (New-Content) -KeepAssignments -Log $script:TestLog

    Assert-True $result.Success "verified: $($result.Objects[0].Message)"
    Assert-Equal 2 $script:AssignAttempts 'the refused assign, then one more without ids'
    $second = (Get-Calls -Method Post -Like '*/assign')[1].Body | ConvertFrom-Json
    $assignment = $second.deviceHealthScriptAssignments[0]
    Assert-True ($null -eq $assignment.PSObject.Properties['id']) 'no id the second time'
    Assert-Equal '#microsoft.graph.deviceHealthScriptDailySchedule' $assignment.runSchedule.'@odata.type' 'the kept daily schedule is unchanged'
    Assert-Equal '08:00:00' $assignment.runSchedule.time 'with its time'
    Assert-True (@($script:LogLines | Where-Object { $_ -like '*without the read-only id*' }).Count -eq 1) 'the second attempt is logged'
}

Add-TestCase 'O33' 'replacing assignments: only the new targets are sent, each Intune Remediation one hourly' {
    Reset-Tenant
    $id = Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' -Assignments @(New-GroupAssignment -GroupId '11111111-1111-1111-1111-111111111111' -Remediation -Daily)
    $result = Invoke-TestUpload -Types @('Remediation') -Targets @(Get-GroupTargets -Terms @('Lab PCs', '/AllDevices'))
    Assert-True $result.Success "verified: $($result.Objects[0].Message)"
    $sent = @(((Get-Calls -Method Post -Like '*/assign')[0].Body | ConvertFrom-Json).deviceHealthScriptAssignments)
    Assert-Equal 2 $sent.Count 'two new assignments, the old one is not carried over'
    foreach ($assignment in $sent) {
        Assert-Equal '#microsoft.graph.deviceHealthScriptHourlySchedule' $assignment.runSchedule.'@odata.type' 'hourly'
        Assert-True ($assignment.runRemediationScript -eq $true) 'remediation runs'
    }
    Assert-Equal '#microsoft.graph.allDevicesAssignmentTarget' $sent[1].target.'@odata.type' 'All devices is the built-in target'
    $stored = @((Get-TenantObject -Type Remediation -Id $id).assignments)
    Assert-True (@($stored | Where-Object { $_.target.groupId -eq '11111111-1111-1111-1111-111111111111' }).Count -eq 0) 'the old group is gone (assign replaces the set)'
}

Add-TestCase 'O34' 'an assignment filter is part of the set: keep is not offered when only the filter differs, and read-back catches a filter change' {
    Reset-Tenant
    $filtered = New-GroupAssignment -GroupId '22222222-2222-2222-2222-222222222222' -Remediation
    $filtered.target.deviceAndAppManagementAssignmentFilterId = '44444444-4444-4444-4444-444444444444'
    $filtered.target.deviceAndAppManagementAssignmentFilterType = 'include'
    Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script' -Assignments @(New-GroupAssignment -GroupId '22222222-2222-2222-2222-222222222222') | Out-Null
    $remId = Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' -Assignments @($filtered)
    $inventory = @(Get-PDOrgRegistryIntuneObjects -AuthContext $script:FakeAuth -SkipGroupNames)

    $plan = New-PDOrgRegistryUploadPlan -Inventory $inventory -Types @('Remediation', 'PlatformScript') -DeployMode 'PRODUCTION'
    $option = Get-PDOrgRegistryKeepOption -Plan $plan
    Assert-True (-not $option.Available) 'same group, different filter: keep is not offered'
    Assert-Like '*different groups*' $option.Reason 'and says why'
    Assert-Like '*[[]assignment filter: include 44444444-*' ((Get-PDOrgRegistryAssignmentLines -Type Remediation -Assignments @(@($inventory | Where-Object { $_.Id -eq $remId })[0].Assignments) -AuthContext $script:FakeAuth) -join ' ') 'the filter is shown'

    # Kept as is, but Intune reads it back without the filter.
    $plan = New-PDOrgRegistryUploadPlan -Inventory $inventory -Types @('Remediation') -DeployMode 'PRODUCTION'
    $script:Hook = {
        param($Method, $Uri, $Body)
        if ($Method -eq 'Get' -and $Uri -like '*/deviceHealthScripts/*/assignments') {
            $plain = New-GroupAssignment -GroupId '22222222-2222-2222-2222-222222222222' -Remediation
            return (New-MockResponse -Body @{ value = @($plain) })
        }
        return $null
    }
    $script:Calls = @()
    $result = Invoke-PDOrgRegistryUpload -AuthContext $script:FakeAuth -Plan $plan -Metadata (New-Metadata) -Content (New-Content) -KeepAssignments
    Assert-Equal 'Failed' $result.Objects[0].Status 'a lost filter is a read-back mismatch'
    Assert-Like '*1 assignment(s) that were sent are missing*' $result.Objects[0].Message 'reported'
}

# ---------------------------------------------------------------------------
# Overlap check
# ---------------------------------------------------------------------------

Add-TestCase 'O40' 'overlap: other modes and types are reported; partners, updated objects and exclusions are not' {
    Reset-Tenant
    $prodRem = Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' -Assignments @(New-AllDevicesAssignment -Remediation)
    $testPs = Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC-TESTING] [VER: a]' -Assignments @(New-GroupAssignment -GroupId '11111111-1111-1111-1111-111111111111')
    $exclusion = [pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = '33333333-3333-3333-3333-333333333333' } }
    $devRem = Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation [MODE: PUBLIC-DEVELOPMENT] [VER: a]' -Assignments @($exclusion, (New-GroupAssignment -GroupId '22222222-2222-2222-2222-222222222222' -Remediation))
    $inventory = @(Get-PDOrgRegistryIntuneObjects -AuthContext $script:FakeAuth -SkipGroupNames)

    # PRODUCTION, both types: the PRODUCTION Intune Remediation is updated (and is the partner).
    $plan = New-PDOrgRegistryUploadPlan -Inventory $inventory -Types @('PlatformScript', 'Remediation') -DeployMode 'PRODUCTION'
    $targets = @(Get-GroupTargets -Terms @('/AllDevices', 'IT PCs', 'Lab PCs'))
    $overlaps = @(Find-PDOrgRegistryAssignmentOverlap -Inventory $inventory -Plan $plan -Targets $targets -AuthContext $script:FakeAuth)
    Assert-Equal $testPs (@($overlaps | ForEach-Object Id) -join ',') 'only the PUBLIC-TESTING Intune Platform Script shares a group (IT PCs); the updated partner and the exclusion are not overlaps'
    Assert-Like 'IT PCs (11111111-*' $overlaps[0].SharedTarget 'the shared group is named'

    # PRODUCTION, Intune Platform Script only: the single PRODUCTION Intune Remediation is its partner.
    $plan = New-PDOrgRegistryUploadPlan -Inventory $inventory -Types @('PlatformScript') -DeployMode 'PRODUCTION'
    Assert-Equal $prodRem (@($plan.PartnerIds['PlatformScript']) -join ',') 'the partner is the same-mode object of the other type'
    $overlaps = @(Find-PDOrgRegistryAssignmentOverlap -Inventory $inventory -Plan $plan -Targets @(Get-GroupTargets -Terms @('/AllDevices')) -AuthContext $script:FakeAuth)
    Assert-Equal 0 $overlaps.Count 'All devices on the partner is expected, not an overlap'

    # PUBLIC-TESTING, Intune Platform Script: All devices collides with the PRODUCTION Intune Remediation.
    $plan = New-PDOrgRegistryUploadPlan -Inventory $inventory -Types @('PlatformScript') -DeployMode 'PUBLIC-TESTING'
    $overlaps = @(Find-PDOrgRegistryAssignmentOverlap -Inventory $inventory -Plan $plan -Targets @(Get-GroupTargets -Terms @('/AllDevices', 'IT PCs')) -AuthContext $script:FakeAuth)
    Assert-Equal $prodRem (@($overlaps | ForEach-Object Id) -join ',') 'All devices compares as itself; the PUBLIC-TESTING copy being updated is excluded'
    Assert-Equal 'All devices (built-in Intune target)' $overlaps[0].SharedTarget 'named'

    # A group nobody else uses: no overlap.
    $overlaps = @(Find-PDOrgRegistryAssignmentOverlap -Inventory $inventory -Plan $plan -Targets @(Get-GroupTargets -Terms @('Lab PCs')) -AuthContext $script:FakeAuth)
    Assert-Equal 0 $overlaps.Count 'an excluded group is not an assignment to it'
}

# ---------------------------------------------------------------------------
# Failures: read-back, rollback, MAA, lost responses, changed files
# ---------------------------------------------------------------------------

Add-TestCase 'O50' 'read-back mismatch on a created object: it is deleted, by its id only' {
    Reset-Tenant
    $existing = Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' -Assignments @(New-AllDevicesAssignment -Remediation)
    $script:Hook = {
        param($Method, $Uri, $Body)
        if ($Method -eq 'Get' -and $Uri -match '/deviceManagementScripts/[^/?]+$') {
            return (New-MockResponse -Body @{ id = 'x'; displayName = 'POWERDEPLOY ORG REGISTRY: Platform Script'; scriptContent = 'b3RoZXI='; runAsAccount = 'system'; enforceSignatureCheck = $false; runAs32Bit = $false; fileName = 'PowerDeploy-OrgRegistry_abc1234.ps1'; description = 'wrong' })
        }
        return $null
    }
    $result = Invoke-TestUpload -Targets @(Get-GroupTargets -Terms @('IT PCs'))

    Assert-True (-not $result.Success) 'not a success'
    $rem = Get-ByType $result.Objects 'Remediation'
    $ps = Get-ByType $result.Objects 'PlatformScript'
    Assert-Equal 'Verified' $rem.Status 'the pre-existing Intune Remediation (written first) was updated and verified'
    Assert-Equal 'Failed' $ps.Status 'the Intune Platform Script failed'
    Assert-Like '*SHA256 differs*' $ps.Message 'the content hash is the reason'
    Assert-Like '*description differs*' $ps.Message 'and the description'
    Assert-Equal 'Deleted' $ps.CleanupStatus 'rolled back'
    Assert-Like '*created*and then deleted again*' $ps.Message 'says exactly what happened'
    $deletes = @(Get-Calls -Method Delete)
    Assert-Equal 1 $deletes.Count 'one delete'
    Assert-Like ('*/deviceManagementScripts/' + $ps.Id) $deletes[0].Uri 'the id created in this run'
    Assert-True ($null -ne (Get-TenantObject -Type Remediation -Id $existing)) 'the pre-existing Intune Remediation is never deleted'

    # The first object fails: the second is not attempted.
    Reset-Tenant
    $script:Hook = {
        param($Method, $Uri, $Body)
        if ($Method -eq 'Get' -and $Uri -match '/deviceHealthScripts/[^/?]+$') { return (New-MockResponse -Body @{ id = 'x'; displayName = 'other' }) }
        return $null
    }
    $result = Invoke-TestUpload -Targets @(Get-GroupTargets -Terms @('IT PCs'))
    Assert-Equal 'Deleted' (Get-ByType $result.Objects 'Remediation').CleanupStatus 'the new Intune Remediation was rolled back'
    Assert-Equal 'NotAttempted' (Get-ByType $result.Objects 'PlatformScript').Status 'the Intune Platform Script was not attempted'
    Assert-Like '*Nothing was changed*' (Get-ByType $result.Objects 'PlatformScript').Message 'and says so'
    Assert-Equal 0 $script:Tenant.PlatformScript.Count 'no Intune Platform Script was created'
}

Add-TestCase 'O51' 'a failure on a pre-existing object never deletes it, and says what was changed' {
    Reset-Tenant
    $existing = Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation'
    $script:Hook = {
        param($Method, $Uri, $Body)
        if ($Method -eq 'Post' -and $Uri -like '*/deviceHealthScripts/*/assign') { return (New-MockResponse -Status 403 -Body @{ error = @{ code = 'Forbidden'; message = 'no' } }) }
        return $null
    }
    $result = Invoke-TestUpload -Types @('Remediation') -Targets @(Get-GroupTargets -Terms @('IT PCs'))
    Assert-Equal 'Failed' $result.Objects[0].Status 'failed at assign'
    Assert-Like '*were updated. Its assignments were not changed.*' $result.Objects[0].Message 'exact account of the change'
    Assert-Equal 0 @(Get-Calls -Method Delete).Count 'never deleted'
    Assert-True ($null -ne (Get-TenantObject -Type Remediation -Id $existing)) 'still there'

    Reset-Tenant
    Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' | Out-Null
    $script:Hook = {
        param($Method, $Uri, $Body)
        if ($Method -eq 'Patch') { return (New-MockResponse -Status 400 -Body @{ error = @{ code = 'BadRequest'; message = 'refused' } }) }
        return $null
    }
    $result = Invoke-TestUpload -Types @('Remediation') -Targets @(Get-GroupTargets -Terms @('IT PCs'))
    Assert-Like '*Nothing was changed.*' $result.Objects[0].Message 'a refused PATCH changed nothing'
    Assert-Equal 0 @(Get-Calls -Method Post -Like '*/assign').Count 'and nothing was assigned'
}

Add-TestCase 'O52' 'Multi-Admin Approval: HTTP 412 with x-msft-approval-code is recognized and nothing is created' {
    Reset-Tenant
    $script:Hook = {
        param($Method, $Uri, $Body)
        if ($Method -eq 'Post' -and $Uri -like '*/deviceManagementScripts') { return (New-MockResponse -Status 412 -Headers @{ 'x-msft-approval-code' = 'abc' }) }
        return $null
    }
    $result = Invoke-TestUpload -Types @('PlatformScript') -Targets @(Get-GroupTargets -Terms @('IT PCs'))
    Assert-True $result.ApprovalRequired 'MAA is reported'
    Assert-Like '*Multi-Admin Approval*' $result.Objects[0].Message 'in the message'
    Assert-Like '*Nothing was created.*' $result.Objects[0].Message 'nothing was created'
    Assert-Equal 1 @(Get-Calls -Method Post).Count 'the write was not retried'
    Assert-Equal 0 $script:Tenant.PlatformScript.Count 'the tenant is unchanged'

    # A 400 whose body asks for an approval justification (app-only writes) is MAA too.
    Reset-Tenant
    Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' | Out-Null
    $script:Hook = {
        param($Method, $Uri, $Body)
        if ($Method -eq 'Patch') { return (New-MockResponse -Status 400 -Body @{ error = @{ code = 'BadRequest'; message = 'An approval justification is required for this request.' } }) }
        return $null
    }
    $result = Invoke-TestUpload -Types @('Remediation') -Targets @(Get-GroupTargets -Terms @('IT PCs'))
    Assert-True $result.ApprovalRequired '400 with approval justification text is MAA'
}

Add-TestCase 'O53' 'a lost create response is never repeated: reconciled by name, or reported as unknown' {
    Reset-Tenant
    $script:Hook = {
        param($Method, $Uri, $Body)
        if ($Method -eq 'Post' -and $Uri -like '*/deviceManagementScripts') {
            $script:Hook = $null
            $null = Invoke-MockTenant -Request @{ Method = 'Post'; Uri = $Uri; BodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body) }
            return (New-TransportFailure)
        }
        return $null
    }
    $result = Invoke-TestUpload -Types @('PlatformScript') -Targets @(Get-GroupTargets -Terms @('IT PCs'))
    Assert-Equal 'KeptForReview' $result.Objects[0].CleanupStatus 'found by its name: kept for review'
    Assert-Equal 0 @(Get-Calls -Method Post -Like '*/assign').Count 'and nothing more is written to it'
    Assert-Equal 1 $script:Tenant.PlatformScript.Count 'exactly one object exists'

    Reset-Tenant
    $script:Hook = { param($Method, $Uri, $Body) if ($Method -eq 'Post' -and $Uri -like '*/deviceManagementScripts') { return (New-TransportFailure) }; return $null }
    $result = Invoke-TestUpload -Types @('PlatformScript') -Targets @(Get-GroupTargets -Terms @('IT PCs'))
    Assert-Equal 'Unknown' $result.Objects[0].CleanupStatus 'the outcome is unknown'
    Assert-Like '*may or may not exist*' $result.Objects[0].Message 'and says to check'
    Assert-Equal 1 @(Get-Calls -Method Post -Like '*/deviceManagementScripts').Count 'the create was sent once'
}

Add-TestCase 'O54' 'a script file that changed after the review is not sent' {
    Reset-Tenant
    $inventory = @()
    $plan = New-PDOrgRegistryUploadPlan -Inventory $inventory -Types @('PlatformScript') -DeployMode 'PRODUCTION'
    $copy = New-ScriptFile -Name 'changed.ps1' -Text 'first'
    $content = @{ PlatformScript = @{ Script = (Get-PDOrgRegistryFileFingerprint -Path $copy) } }
    [System.IO.File]::WriteAllText($copy, 'second')
    $script:Calls = @()
    $result = Invoke-PDOrgRegistryUpload -AuthContext $script:FakeAuth -Plan $plan -Metadata (New-Metadata) -Content $content -Targets @(Get-GroupTargets -Terms @('IT PCs'))
    Assert-Like '*changed after the review*' $result.Objects[0].Message 'refused'
    Assert-Equal 0 @(Get-Calls -Method Post -Like '*/deviceManagementScripts').Count 'nothing was sent'
}

Add-TestCase 'O55' 'no content, SAS key or repository token reaches a log line, a result or a message' {
    Reset-Tenant
    Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' | Out-Null
    $result1 = Invoke-TestUpload -Targets @(Get-GroupTargets -Terms @('IT PCs'))
    Assert-True $result1.Success 'the happy path ran'
    $logs1 = @($script:LogLines)

    # A service error that echoes the request body back.
    Reset-Tenant
    $script:Hook = {
        param($Method, $Uri, $Body)
        if ($Method -eq 'Post' -and $Uri -like '*/deviceManagementScripts') {
            $echo = ($Body | ConvertFrom-Json).scriptContent
            return (New-MockResponse -Status 400 -Body @{ error = @{ code = 'ModelValidationFailure'; message = ("Cannot convert the literal '{0}' to the expected type." -f $echo) } })
        }
        return $null
    }
    $result2 = Invoke-TestUpload -Types @('PlatformScript') -Targets @(Get-GroupTargets -Terms @('IT PCs'))
    Assert-Like '*<redacted>*' $result2.Objects[0].Message 'the echoed content is redacted'

    $everything = (@($logs1) + @($script:LogLines) + @(($result1 | ConvertTo-Json -Depth 10), ($result2 | ConvertTo-Json -Depth 10))) -join "`n"
    foreach ($secret in @($script:FakeSas, $script:FakeToken, 'FAKESASSIGNATURE', 'FAKEREPOTOKEN')) {
        Assert-True (-not $everything.Contains($secret)) "'$secret' must not appear"
    }
    foreach ($encoded in $script:ContentBase64) {
        for ($i = 0; $i + 40 -le $encoded.Length; $i += 20) {
            Assert-True (-not $everything.Contains($encoded.Substring($i, 40))) 'no 40-character piece of the base64 content appears'
        }
    }
    Assert-Equal '' (Protect-PDOrgRegistryText -Text $null) 'null is empty'
    Assert-Equal 'id 3f2a-11 ok' (Protect-PDOrgRegistryText -Text 'id 3f2a-11 ok') 'ordinary text is untouched'
}

Add-TestCase 'O56' 'the scrubber: URL userinfo anywhere, sig= plain or encoded, token shapes, exact values in every form, truncation tails' {
    try {
        Set-PDOrgRegistryRedactValues -Values @()
        $userinfo = Protect-PDOrgRegistryText -Text 'Graph said: invalid value https://oauth2:ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/org/repo.git here'
        Assert-Like '*https://***@github.com/org/repo.git here*' $userinfo 'userinfo mid-text is removed'
        Assert-True (-not $userinfo.Contains('abcdefghijklmnop')) 'the token is gone'

        $sas = Protect-PDOrgRegistryText -Text 'blob?sv=2024-11-04&sp=r&sig=Ab12Cd34%2BEf56%3D&se=2026-12-01 failed'
        Assert-Like '*&sig=<redacted>&se=2026-12-01 failed*' $sas 'a plain sig value is removed, the next parameter kept'
        $encoded = Protect-PDOrgRegistryText -Text 'u=blob%3Fsv%3D2024%26sig%3DAb12Cd34%252BEf56%253D%26se%3D1'
        Assert-Like '*%26sig%3D<redacted>%26se%3D1' $encoded 'a URL-encoded sig value is removed'

        foreach ($token in @('gho_abcdefghij1234', 'ghs_ABCDEFGHIJ5678', 'ghu_abcdefghij9999', 'github_pat_11ABCDEFG0_abcdefghijklmn', 'glpat-abcDEF123456789xyz')) {
            $out = Protect-PDOrgRegistryText -Text ("token {0} rejected" -f $token)
            Assert-Equal 'token <redacted> rejected' $out "$token is a token shape"
        }

        $u = ([char]92) + 'u00'
        $secret = 'MyRepoToken-123!'
        $sasValue = "sv=2024&sp=r&sig=KeyValue+/=x"
        Set-PDOrgRegistryRedactValues -Values @($secret, $sasValue, 'abc', $null)
        foreach ($form in @($secret, [System.Uri]::EscapeDataString($secret), [regex]::Replace([System.Uri]::EscapeDataString($secret), '%[0-9A-F]{2}', { param($m) $m.Value.ToLowerInvariant() }),
                            $sasValue, [System.Uri]::EscapeDataString($sasValue), ($sasValue.Replace('&', $u + '26')))) {
            $out = Protect-PDOrgRegistryText -Text ("before {0} after" -f $form)
            Assert-Equal 'before <redacted> after' $out "the exact value in the form '$form' is removed"
        }
        Assert-Equal 'abc stays' (Protect-PDOrgRegistryText -Text 'abc stays') 'values under 8 characters are ignored'
        Assert-Equal 'cut <redacted>...' (Protect-PDOrgRegistryText -Text 'cut MyRepoTok...') 'the start of a known value cut off by a truncation is removed'
        Assert-Equal 'detail: <redacted>...' (Protect-PDOrgRegistryText -Text 'detail: QUJDREVGR0hJSktMTU5P...') 'a base64 tail of 16+ characters before ... is removed'
        Assert-Equal 'short QUJDREVG...' (Protect-PDOrgRegistryText -Text 'short QUJDREVG...') 'a short run before ... is ordinary text'
        $plain = 'Created the Intune Platform Script (aaaaaaaa-0000-0000-0000-000000000101): POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC-TESTING] [VER: abc1234.UnstagedChanges]'
        Assert-Equal $plain (Protect-PDOrgRegistryText -Text $plain) 'ordinary text is untouched'

        # Case, double URL-encoding, inserted line breaks.
        Assert-Equal 'x <redacted> y' (Protect-PDOrgRegistryText -Text ('x {0} y' -f $secret.ToUpperInvariant())) 'case is ignored'
        $double = [System.Uri]::EscapeDataString([System.Uri]::EscapeDataString($sasValue))
        Assert-Equal 'x <redacted> y' (Protect-PDOrgRegistryText -Text ('x {0} y' -f $double)) 'the double URL-encoded form is removed'
        foreach ($break in @("`n", "`r`n", "`r")) {
            $wrapped = $secret.Substring(0, 6) + $break + $secret.Substring(6)
            Assert-Equal 'x <redacted> y' (Protect-PDOrgRegistryText -Text ('x {0} y' -f $wrapped)) 'a value wrapped across lines is still removed'
        }
        Set-PDOrgRegistryRedactValues -Values @()
        Assert-Like '*u=x%253Fsig%253D<redacted>%2526se%253D1*' (Protect-PDOrgRegistryText -Text 'u=x%253Fsig%253DAb12%25252B%2526se%253D1') 'a double URL-encoded sig value is removed, the next parameter kept'

        # Long ordinary words before a truncation are not base64.
        Assert-Equal 'deviceManagementScriptAssignmentsCollectionResponse...' (Protect-PDOrgRegistryText -Text 'deviceManagementScriptAssignmentsCollectionResponse...') 'an ordinary word before ... is kept'

        # URL userinfo with no token shape: only the userinfo rule catches it.
        $noShape = Protect-PDOrgRegistryText -Text 'clone of https://user:Pa55wordNoShape@host/x failed'
        Assert-Equal 'clone of https://***@host/x failed' $noShape 'a password with no known shape is removed from the URL'

        # Input that cannot become text: a fixed message, plus its protected Message when it has one.
        $bad = New-Object psobject
        $bad | Add-Member -MemberType ScriptMethod -Name ToString -Value { throw 'boom' } -Force
        Assert-Equal 'The error details could not be shown safely.' (Protect-PDOrgRegistryText -Text $bad) 'no Message: the fixed message'
        $bad | Add-Member -MemberType NoteProperty -Name Message -Value 'clone of https://user:Pa55wordNoShape@host/x failed'
        Assert-Equal 'The error details could not be shown safely. clone of https://***@host/x failed' (Protect-PDOrgRegistryText -Text $bad) 'the protected Message is kept'
    } finally {
        Set-PDOrgRegistryRedactValues -Values @()
    }
    Assert-Equal 'MyRepoToken-123!' (Protect-PDOrgRegistryText -Text 'MyRepoToken-123!') 'an empty list clears the values'
}

Add-TestCase 'O57' 'end to end: a 400 that echoes the token, the SAS key and the repository URL leaks none of them' {
    $token = 'S3cretRepo-Token_Value!42'
    $sasKey = 'sv=2024-11-04&ss=b&srt=co&sp=rl&se=2027-01-01&sig=Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2%2BJi1Hg0%3D'
    $repoUrl = 'https://oauth2:' + $token + '@github.com/example/fork'
    $redact = @($token, $sasKey, $repoUrl)

    Reset-Tenant
    Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' | Out-Null
    $script:EchoText = ("invalid value {0} and {1} and {2} and {3}" -f $repoUrl, $sasKey, [System.Uri]::EscapeDataString($sasKey), $token)
    $script:Hook = { param($Method, $Uri, $Body) if ($Method -eq 'Patch') { return (New-MockResponse -Status 400 -Body @{ error = @{ code = 'BadRequest'; message = $script:EchoText } }) }; return $null }
    $result = Invoke-TestUpload -Types @('Remediation') -Targets @(Get-GroupTargets -Terms @('IT PCs')) -RedactValues $redact
    $seen = (@($script:LogLines) + @($result | ConvertTo-Json -Depth 10)) -join "`n"
    Assert-Like '*refused*' $result.Objects[0].Message 'the refusal is still reported'
    foreach ($piece in @($token, 'S3cretRepo', 'Zx9Yw8Vu7Ts6', [System.Uri]::EscapeDataString($sasKey), 'oauth2:')) {
        Assert-True (-not $seen.Contains($piece)) "'$piece' must not appear in the message or a log line"
    }

    # Graph error text is cut at MaxErrorBodyChars + '...': a secret or content cut in half is still removed.
    Reset-Tenant
    Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' | Out-Null
    $filler = (('ab, ' * 219) + 'ab')
    $script:EchoText = $filler + $token
    $script:Hook = { param($Method, $Uri, $Body) if ($Method -eq 'Patch') { return (New-MockResponse -Status 400 -Body @{ error = @{ code = 'BadRequest'; message = $script:EchoText } }) }; return $null }
    $result = Invoke-TestUpload -Types @('Remediation') -Targets @(Get-GroupTargets -Terms @('IT PCs')) -RedactValues $redact
    Assert-Like '*<redacted>...*' $result.Objects[0].Message 'the cut-off token start is removed'
    Assert-True (-not $result.Objects[0].Message.Contains('S3cretRe')) 'no piece of the token survives the truncation'

    Reset-Tenant
    $script:Hook = {
        param($Method, $Uri, $Body)
        if ($Method -eq 'Post' -and $Uri -like '*/deviceManagementScripts') {
            $echo = ($Body | ConvertFrom-Json).scriptContent
            return (New-MockResponse -Status 400 -Body @{ error = @{ code = 'ModelValidationFailure'; message = ((('ab, ' * 212) + 'ab, abc') + $echo) } })
        }
        return $null
    }
    $result = Invoke-TestUpload -Types @('PlatformScript') -Targets @(Get-GroupTargets -Terms @('IT PCs'))
    Assert-Like '*<redacted>...*' $result.Objects[0].Message 'a base64 tail shorter than 40 characters is removed'
    Assert-True (-not $result.Objects[0].Message.Contains($script:ContentBase64[0].Substring(0, 12))) 'no piece of the content survives'
    Assert-Equal 0 @($script:PDOrgRegistryRedact).Count 'the values are cleared when the call ends'
}

Add-TestCase 'O58' 'a lost create never adopts an object that existed before it, and an adopted object gets no write and no delete' {
    # P2: another admin makes a copy with the same name while this run waits at its prompts.
    Reset-Tenant
    $plan = New-PDOrgRegistryUploadPlan -Inventory @() -Types @('PlatformScript') -DeployMode 'PRODUCTION'
    $foreign = Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script'
    $script:Hook = { param($Method, $Uri, $Body) if ($Method -eq 'Post' -and $Uri -like '*/deviceManagementScripts') { return (New-TransportFailure) }; return $null }
    $script:Calls = @()
    $result = Invoke-PDOrgRegistryUpload -AuthContext $script:FakeAuth -Plan $plan -Metadata (New-Metadata) -Content (New-Content) -Targets @(Get-GroupTargets -Terms @('IT PCs')) -Log $script:TestLog
    Assert-Equal 'Unknown' $result.Objects[0].CleanupStatus 'the other copy is not adopted'
    Assert-Equal 0 @(Get-Calls -Method Delete).Count 'nothing deleted'
    Assert-Equal 0 @(Get-Calls -Method Post -Like '*/assign').Count 'nothing assigned'
    Assert-True ($null -ne (Get-TenantObject -Type PlatformScript -Id $foreign)) 'the other copy is untouched'

    # A new object appears after the create request: another admin's copy, or this run's own object
    # (identical content). Either way it is adopted only for review: no assign, no PATCH, no delete.
    foreach ($whose in @('another admin', 'this run')) {
        Reset-Tenant
        $script:Whose = $whose
        $script:Hook = {
            param($Method, $Uri, $Body)
            if ($Method -eq 'Post' -and $Uri -like '*/deviceManagementScripts') {
                $hook = $script:Hook; $script:Hook = $null
                if ($script:Whose -eq 'this run') { $null = Invoke-MockTenant -Request @{ Method = 'Post'; Uri = $Uri; BodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body) } }
                else { $null = Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script' }
                $script:Hook = $hook
                return (New-TransportFailure)
            }
            return $null
        }
        $result = Invoke-TestUpload -Types @('PlatformScript') -Targets @(Get-GroupTargets -Terms @('IT PCs'))
        $object = $result.Objects[0]
        $id = [string]$script:Tenant.PlatformScript[0].id
        Assert-True $object.Adopted "$whose : adopted"
        Assert-Equal 'KeptForReview' $object.CleanupStatus "$whose : kept for review"
        Assert-Equal 'Failed' $object.Status "$whose : not reported as verified"
        Assert-Equal ("An Intune Platform Script named POWERDEPLOY ORG REGISTRY: Platform Script (ID {0}) appeared after the create request was sent. It may have been created by this run or by another admin, so it was left unchanged for review." -f $id) $object.Message "$whose : the exact report"
        Assert-Equal 0 @(Get-Calls -Method Post -Like '*/assign').Count "$whose : no assign"
        Assert-Equal 0 @(Get-Calls -Method Patch).Count "$whose : no PATCH"
        Assert-Equal 0 @(Get-Calls -Method Delete).Count "$whose : no delete"
        Assert-Equal 1 $script:Tenant.PlatformScript.Count "$whose : it is still there"
        Assert-Equal 0 @($script:Tenant.PlatformScript[0].assignments).Count "$whose : its assignments are untouched"
    }
}

Add-TestCase 'O59' 'with retries enabled, reads are retried and writes are never repeated' {
    $savedAttempts = $script:PDGraph.MaxAttempts
    $savedDelay = $script:PDGraph.BaseRetryDelaySec
    try {
        $script:PDGraph.MaxAttempts = 3
        $script:PDGraph.BaseRetryDelaySec = 0
        $busy = { New-MockResponse -Status 503 -Body 'busy' -Headers @{ 'Retry-After' = '0' } }

        Reset-Tenant
        $script:FailedOnce = @{}
        $script:Busy = $busy
        $script:Hook = {
            param($Method, $Uri, $Body)
            if ($Method -eq 'Get' -and $Uri -match '/deviceManagementScripts\?' -and -not $script:FailedOnce['list']) { $script:FailedOnce['list'] = $true; return (& $script:Busy) }
            if ($Method -eq 'Post' -and $Uri -like '*/deviceManagementScripts') { return (& $script:Busy) }
            return $null
        }
        $result = Invoke-TestUpload -Types @('PlatformScript') -Targets @(Get-GroupTargets -Terms @('IT PCs'))
        Assert-Equal 1 @(Get-Calls -Method Post -Like '*/deviceManagementScripts').Count 'the create POST was sent once'
        Assert-Equal 'Unknown' $result.Objects[0].CleanupStatus 'a 5xx create is an unknown outcome, not a retry'

        foreach ($case in @(@{ Method = 'Patch'; Like = '*/deviceHealthScripts/*' }, @{ Method = 'Post'; Like = '*/deviceHealthScripts/*/assign' })) {
            Reset-Tenant
            Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' | Out-Null
            $script:Case = $case
            $script:Hook = { param($Method, $Uri, $Body) if ($Method -eq $script:Case.Method -and $Uri -like $script:Case.Like) { return (& $script:Busy) }; return $null }
            $result = Invoke-TestUpload -Types @('Remediation') -Targets @(Get-GroupTargets -Terms @('IT PCs'))
            Assert-Equal 1 @(Get-Calls -Method $case.Method -Like $case.Like).Count ("the {0} was sent once" -f $case.Method)
            Assert-Equal 'Failed' $result.Objects[0].Status 'and the run failed instead of repeating it'
        }

        Reset-Tenant
        $script:FailedOnce = @{}
        $script:Hook = { param($Method, $Uri, $Body) if ($Method -eq 'Get' -and $Uri -match '/deviceHealthScripts\?' -and -not $script:FailedOnce['list']) { $script:FailedOnce['list'] = $true; return (& $script:Busy) }; return $null }
        $inventory = @(Get-PDOrgRegistryIntuneObjects -AuthContext $script:FakeAuth -Types @('Remediation'))
        Assert-Equal 2 @(Get-Calls -Method Get | Where-Object { $_.Uri -match '/deviceHealthScripts\?' }).Count 'a read that got 503 was retried'
    } finally {
        $script:PDGraph.MaxAttempts = $savedAttempts
        $script:PDGraph.BaseRetryDelaySec = $savedDelay
    }
}

# ---------------------------------------------------------------------------
# Deletion list
# ---------------------------------------------------------------------------

Add-TestCase 'O60' 'deletion list: numbered, just-uploaded objects listed but not selectable, selection parsing' {
    Reset-Tenant
    $ps1 = Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script'
    $ps2 = Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC-TESTING] [VER: abc]'
    $rem = Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation'
    $odd = Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation copy'
    $inventory = @(Get-PDOrgRegistryIntuneObjects -AuthContext $script:FakeAuth)
    $list = @(Get-PDOrgRegistryDeletionList -Inventory $inventory -JustUploadedIds @($ps1))

    Assert-Equal 4 $list.Count 'every object with the prefix'
    Assert-Equal '1,2,3,4' (@($list | ForEach-Object Number) -join ',') 'numbered from 1'
    Assert-Equal 'Remediation' $list[0].Type 'Intune Remediations first, the order of the menu'
    $just = @($list | Where-Object { $_.Id -eq $ps1 })[0]
    Assert-True ($just.JustUploaded -and -not $just.Selectable) 'the object just uploaded is labelled and cannot be selected'
    Assert-Equal '(name not recognized)' (@($list | Where-Object { $_.Id -eq $odd })[0]).DeployMode 'an unrecognized name is still listed'

    Assert-Equal 0 @((ConvertFrom-PDOrgRegistryDeletionSelection -Text '' -List $list).Selected).Count 'Enter deletes nothing'
    Assert-Equal 0 @((ConvertFrom-PDOrgRegistryDeletionSelection -Text '   ' -List $list).Selected).Count 'spaces delete nothing'
    $justNumber = $just.Number
    $others = @($list | Where-Object { $_.Selectable } | ForEach-Object Number)
    $pick = ConvertFrom-PDOrgRegistryDeletionSelection -Text (" {0} ,{1},{0}" -f $others[1], $others[0]) -List $list
    Assert-Equal 0 @($pick.Errors).Count 'valid'
    Assert-Equal (($others[0], $others[1]) -join ',') (@($pick.Selected | ForEach-Object Number) -join ',') 'each once, in list order'

    $bad = ConvertFrom-PDOrgRegistryDeletionSelection -Text ("{0}, x, 99, {1}, 2-3" -f $others[0], $justNumber) -List $list
    Assert-Equal 0 @($bad.Selected).Count 'any problem selects nothing'
    $errors = @($bad.Errors) -join ' | '
    Assert-Like "*'x' is not a number*" $errors 'text'
    Assert-Like '*99 is not in the list*' $errors 'out of range'
    Assert-Like ("*{0} was just uploaded*" -f $justNumber) $errors 'just uploaded'
    Assert-Like "*'2-3' is not a number*" $errors 'ranges are not accepted'
}

Add-TestCase 'O61' 'delete: name, ID and assignments are logged first; unreadable assignments mean no delete' {
    Reset-Tenant
    $id = Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' -Assignments @(New-AllDevicesAssignment -Remediation)
    $inventory = @(Get-PDOrgRegistryIntuneObjects -AuthContext $script:FakeAuth)
    $entry = @(Get-PDOrgRegistryDeletionList -Inventory $inventory)[0]
    $script:Calls = @(); $script:LogLines = @()

    $outcome = Remove-PDOrgRegistryIntuneObject -AuthContext $script:FakeAuth -Entry $entry -Log $script:TestLog
    Assert-Equal 'Deleted' $outcome.Result 'deleted'
    Assert-Equal 'Get|Delete' (@($script:Calls | ForEach-Object Method) -join '|') 'assignments read fresh, then the delete'
    $logged = @($script:LogLines | Where-Object { $_ -like '*Deleting the Intune Remediation*' })
    Assert-Equal 1 $logged.Count 'one line before the delete'
    Assert-Like ('*' + $id + '*allDevicesAssignmentTarget*') $logged[0] 'it carries the ID and the assignments'
    Assert-Like '*POWERDEPLOY ORG REGISTRY: Remediation*' $logged[0] 'and the name'

    Assert-Equal 'AlreadyGone' (Remove-PDOrgRegistryIntuneObject -AuthContext $script:FakeAuth -Entry $entry).Result 'a second delete finds it gone'

    Reset-Tenant
    Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script' | Out-Null
    $entry = @(Get-PDOrgRegistryDeletionList -Inventory @(Get-PDOrgRegistryIntuneObjects -AuthContext $script:FakeAuth))[0]
    $script:Hook = { param($Method, $Uri, $Body) if ($Uri -like '*/assignments*') { return (New-MockResponse -Status 503 -Body 'busy') }; return $null }
    $script:Calls = @()
    $outcome = Remove-PDOrgRegistryIntuneObject -AuthContext $script:FakeAuth -Entry $entry
    Assert-Equal 'ReadFailed' $outcome.Result 'not deleted'
    Assert-Equal 0 @(Get-Calls -Method Delete).Count 'no delete was sent'
}

# ---------------------------------------------------------------------------
# Credential check and wizard text
# ---------------------------------------------------------------------------

Add-TestCase 'O70' 'the credential check refuses a token without the scripts permission' {
    $realCredential = (Get-Command -CommandType Function -Name 'Get-PDGraphCredential').ScriptBlock
    $realToken = (Get-Command -CommandType Function -Name 'Get-PDGraphToken').ScriptBlock
    try {
        Set-Item -Path function:global:Get-PDGraphCredential -Value { param($Path) [pscustomobject]@{ Warnings = @(); SecretExpiresOn = [DateTimeOffset]::UtcNow.AddHours(5) } }
        Set-Item -Path function:global:Get-PDGraphToken -Value { param($Credential) @{ AccessToken = 'x'; Roles = @('DeviceManagementApps.ReadWrite.All', 'Group.Read.All') } }
        Assert-Throws { Get-PDOrgRegistryAuthContext } -MessagePattern "*DeviceManagementScripts.ReadWrite.All*" | Out-Null
        Set-Item -Path function:global:Get-PDGraphToken -Value { param($Credential) @{ AccessToken = 'x'; Roles = @($script:PDGraph.RequiredAppRoles) } }
        $auth = Get-PDOrgRegistryAuthContext
        Assert-True ($null -ne $auth.AuthContext) 'all roles: an auth context'
        Assert-True ($null -eq $auth.PSObject.Properties['Token']) 'no token in the result'
    } finally {
        Set-Item -Path function:global:Get-PDGraphCredential -Value $realCredential
        Set-Item -Path function:global:Get-PDGraphToken -Value $realToken
    }
}

Add-TestCase 'O71' 'wizard text: product voice, one name per thing, the agreed titles and questions' {
    $names = @('OrganizationRegistryEntries--InTune-Setup') + $script:WizardHelpers
    $strings = @()
    foreach ($name in $names) {
        $fn = @($script:SetupFunctions | Where-Object { $_.Name -eq $name })[0]
        $strings += @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true) | ForEach-Object { [string]$_.Value })
    }
    $text = $strings -join "`n"

    foreach ($required in @('1 - Generate the registry scripts and set them up in Intune', '2 - View and delete existing registry scripts in Intune',
                            'What do you want to set up in Intune?', '1 - Intune Remediation and Intune Platform Script (both)', '2 - Intune Remediation only',
                            '3 - Intune Platform Script only', 'How do you want to set it up?', '1 - Guided manual steps', '2 - Automatic via API',
                            'UPLOAD REGISTRY REMEDIATION TO INTUNE', 'UPLOAD REGISTRY PLATFORM SCRIPT TO INTUNE', 'Devices > Scripts and remediations',
                            'Enter the numbers to delete, separated by commas, or press Enter to delete nothing.', '(just uploaded)',
                            'Only device groups run the Intune Platform Script during the Autopilot device phase.',
                            'The registry script files have been created.', 'Detection script file:', 'Remediation script file:', 'Platform script file:',
                            'Packaging the remediation script as an .intunewin package...', 'Do you need the .intunewin package of the remediation script?', 'The .intunewin package has been created at: ', '(for example: Test Devices; Lab Devices)')) {
        Assert-True ($text.Contains($required)) "the wizard says: $required"
    }
    foreach ($line in $strings) {
        Assert-True ($line -cnotmatch '\bI\b') "no 'I': $line"
        Assert-True ($line -notmatch '(?i)\b(my|we|our)\b') "no my/we/our: $line"
        Assert-True ($line -notmatch '(?i)your Autopilot|I recommend|personally|once replace') "no personal or pre-existing slips: $line"
        # Function names (InTuneAPI--Setup-and-Manage, Make-InTuneWin) keep their own spelling.
        $prose = [regex]::Replace($line, '\S*--\S*|InTuneWin', '')
        Assert-True ($prose -cnotmatch 'InTune') "Intune is spelled one way: $line"
        Assert-True ($line -notmatch '(?i)PowerDeploy Registry Update') "no legacy name is special-cased: $line"
        Assert-True ($line -notmatch '(?i)workstation|IT PCs; Techs|InTuneWin stuff|Win32 app package|Detection Script:') -and ($line -cnotmatch 'Platform Script file|InTuneWin package') "PC, not workstation; neutral group examples: $line"
        Assert-True ($line -notmatch 'Intune Platform Script and (the )?Intune Remediation') "one order: the Intune Remediation first: $line"
        Assert-True ($line -notmatch '(?i)\b(the the|to to|a a)\b') "no doubled words: $line"
    }
}

# ---------------------------------------------------------------------------
# The wizard side, driven end to end with scripted answers against the mock tenant
# ---------------------------------------------------------------------------

$script:WizardFunctionText = (@($script:WizardHelpers + @('Read-IntuneGroupList', 'Read-GraphUploadYesNo', 'Show-GraphUploadError')) | ForEach-Object {
    $name = $_
    @($script:SetupFunctions | Where-Object { $_.Name -eq $name })[0].Extent.Text
}) -join "`r`n"

function Invoke-WizardScript {
    # Runs one Setup.ps1 wizard call with every prompt answered from -Answers, in a child scope
    # where the Setup-only dependencies are stubbed. Returns { Result; Log; Left }.
    param([Parameter(Mandatory = $true)][scriptblock]$Call, [string[]]$Answers = @())

    $script:Answers = @($Answers)
    $script:WizardLog = @()
    $result = & {
        function Write-Log { param([string]$Message, [string]$Level = 'INFO', [switch]$LogOnly) $script:WizardLog += ('[{0}]{1} {2}' -f $Level, $(if ($LogOnly) { '[log]' } else { '' }), $Message) }
        function Read-Host {
            param($Prompt, [switch]$AsSecureString)
            if (@($script:Answers).Count -eq 0) { throw "the wizard asked more than the script answers: $Prompt" }
            $answer = [string]$script:Answers[0]
            $script:Answers = @($script:Answers | Select-Object -Skip 1)
            $script:WizardLog += ('[ANSWER] {0} -> {1}' -f $Prompt, $answer)
            return $answer
        }
        function Pause { }
        # 'Clear' is an alias of Clear-Host, and an alias wins over a function of the same name.
        function Clear-Host { }
        function Confirm-GraphUploadSecretFresh { return $true }
        function Get-PDGraphCredentialSummary { param($CredentialPath) return @{ Stored = $true; Usable = $true; AppDisplayName = 'PowerDeploy Intune Upload'; ClientId = '99999999-9999-9999-9999-999999999999' } }
        function Get-PDOrgRegistryAuthContext { param($CredentialPath) return [pscustomobject]@{ AuthContext = $script:FakeAuth; Warnings = @(); SecretExpiresOn = [DateTimeOffset]::UtcNow.AddHours(5) } }
        $GraphUploadAvailable = $true
        $GraphUploadLoadError = $null
        $OrgRegistryUploadLoadError = $null
        $LogPath = 'C:\Logs\Setup.log'
        . ([scriptblock]::Create($script:WizardFunctionText))
        & $Call
    }
    return [pscustomobject]@{ Result = $result; Log = @($script:WizardLog); Left = @($script:Answers) }
}

Add-TestCase 'O80' 'wizard, automatic setup via API: plan, groups, overlap warning, review, write, deletion list' {
    Reset-Tenant
    $rem = Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation' -Assignments @(New-AllDevicesAssignment -Remediation)
    $other = Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script [MODE: PUBLIC-TESTING] [VER: a]' -Assignments @(New-GroupAssignment -GroupId '11111111-1111-1111-1111-111111111111')

    $metadata = New-Metadata
    $files = @{ PlatformScript = $script:PlatformFile; DetectScript = $script:DetectionFile; RemediationScript = $script:RemediationFile }
    $run = Invoke-WizardScript -Answers @('IT PCs', 'y', 'y', '') -Call {
        Invoke-OrgRegistryIntuneAutoUpload -Types @('PlatformScript', 'Remediation') -DeployMode 'PRODUCTION' -Files $files -Metadata $metadata
    }
    $log = $run.Log -join "`n"

    Assert-Equal 'Done' $run.Result.Reason "the run finished: $log"
    Assert-Equal 0 @($run.Result.Pending).Count 'nothing left for the guided steps'
    Assert-Equal 0 $run.Left.Count 'every scripted answer was used'
    Assert-Like '*Intune Platform Script: none exists for deploy mode PRODUCTION, so a new one will be created.*' $log 'the plan is stated'
    Assert-Like ('*Intune Remediation: the existing one will be updated: POWERDEPLOY ORG REGISTRY: Remediation (' + $rem + ')*') $log 'with the existing object'
    Assert-Like '*The Intune Platform Script is new, so it needs groups.*' $log 'why Enter cannot keep'
    Assert-Like '*Only device groups run the Intune Platform Script during the Autopilot device phase.*' $log 'the device group note'
    Assert-Like ('*Other registry scripts in Intune are already assigned*' + $other + '*IT PCs*') $log 'the overlap is shown with its ID and group'
    Assert-Like '*Enter the groups to assign the Intune Remediation and the Intune Platform Script to*' $log 'one order, the order of the menu'
    Assert-Like '*REVIEW - nothing has been changed in Intune yet*' $log 'the review'
    Assert-Like '*Schedule:  Hourly, every 1 hour, for each group*' $log 'the schedule'
    Assert-Like '*Intune Platform Script created, assigned and verified.*' $log 'reported'
    Assert-Like '*Intune admin center: https://intune.microsoft.com/*' $log 'with the link'
    Assert-Like '*(just uploaded)*' $log 'the deletion list follows, marking the new objects'
    Assert-Like '*Nothing was deleted.*' $log 'Enter deleted nothing'
    Assert-Equal 3 ($script:Tenant.PlatformScript.Count + $script:Tenant.Remediation.Count) 'nothing was deleted'
    $created = @($script:Tenant.PlatformScript | Where-Object { $_.id -ne $other })[0]
    Assert-Equal '11111111-1111-1111-1111-111111111111' ([string]$created.assignments[0].target.groupId) 'the new Intune Platform Script is assigned'
    foreach ($secret in @($script:FakeSas, $script:FakeToken)) { Assert-True (-not $log.Contains($secret)) 'no secret on screen or in the log' }
}

Add-TestCase 'O81' 'wizard, view and delete: one confirmation, then the selected object is deleted and logged' {
    Reset-Tenant
    $keep = Add-TenantObject -Type PlatformScript -DisplayName 'POWERDEPLOY ORG REGISTRY: Platform Script'
    $gone = Add-TenantObject -Type Remediation -DisplayName 'POWERDEPLOY ORG REGISTRY: Remediation [MODE: PUBLIC-TESTING] [VER: a]'

    $run = Invoke-WizardScript -Answers @('7', '1', 'y') -Call { Invoke-OrgRegistryIntuneDeletion }
    $log = $run.Log -join "`n"
    Assert-Like "*7 is not in the list.*" $log 'a bad number is refused and asked again'
    Assert-Like '*These will be deleted from Intune:*' $log 'the selection is shown'
    Assert-Like '*Deleting them does not remove the registry values from devices.*' $log 'and what deleting means'
    Assert-Like ('*Deleted: POWERDEPLOY ORG REGISTRY: Remediation*' + $gone + '*') $log 'reported'
    Assert-Like ('*[log]*Deleting the Intune Remediation*' + $gone + '*Its assignments*') $log 'logged before the delete'
    Assert-True ($null -eq (Get-TenantObject -Type Remediation -Id $gone)) 'deleted'
    Assert-True ($null -ne (Get-TenantObject -Type PlatformScript -Id $keep)) 'the other one is kept'
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
        $script:Failures += @{ Id = $case.Id; Name = $case.Name; Reason = $_.Exception.Message; Site = $_.InvocationInfo.PositionMessage }
        Write-Host ("FAIL  {0,-6} {1}" -f $case.Id, $case.Name) -ForegroundColor Red
        Write-Host ("      {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    } finally {
        $script:Hook = $null
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
