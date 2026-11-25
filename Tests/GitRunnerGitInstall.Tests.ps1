<#

.SYNOPSIS
    Offline behavioural tests for Git-Runner's Git for Windows install (CheckAndInstall-Git in
    Templates\Git-Runner_TEMPLATE.ps1) and for the exit-code ending that New-IntuneGitRunnerCommand
    (Other_Tools\Generate_Install-Command.ps1) puts on every command.

.DESCRIPTION
    Same dependency-free harness as Tests\IntuneOrgRegistryScripts.Tests.ps1.

    CheckAndInstall-Git calls "exit", so each install scenario runs in a child Windows PowerShell 5.1
    process (the endpoint runtime). The child loads only the needed functions from the template (AST),
    replaces Get-Command (git is never found unless the case says so), Start-Process and, in most cases,
    the download helper with stand-ins, and uses short time limits and a per-test mutex name.
    The latest-tag URL (and, for real downloads, the release download base URL) point at a small HTTP
    server on 127.0.0.1 started by this file.
    Nothing here installs, uninstalls or looks for the real Git, touches the real
    Global\PowerDeploy_GitInstall mutex, or reaches the internet.

        powershell -NoProfile -ExecutionPolicy Bypass -File Tests\GitRunnerGitInstall.Tests.ps1
        pwsh       -NoProfile -ExecutionPolicy Bypass -File Tests\GitRunnerGitInstall.Tests.ps1

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

function Assert-NotLike {
    param([string]$Pattern, [object]$Actual, [string]$Message)
    if (([string]$Actual) -like $Pattern) { throw "Expected '$Pattern' NOT to match '$Actual'. $Message" }
}

# Runs $Body, expects it to throw within $MinSec..$MaxSec seconds with an OperationCanceledException
# somewhere in the exception chain (Windows PowerShell 5.1: TaskCanceledException innermost; PowerShell 7
# wraps more under it).
function Assert-TimesOut {
    param([scriptblock]$Body, [double]$MinSec, [double]$MaxSec)
    $caught = $null
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try { & $Body | Out-Null } catch { $caught = $_ }
    $sw.Stop()
    Assert-True ($null -ne $caught) 'threw'
    $chain = @()
    $inner = $caught.Exception
    while ($inner) { $chain += $inner; $inner = $inner.InnerException }
    Assert-True (@($chain | Where-Object { $_ -is [System.OperationCanceledException] }).Count -gt 0) ("timeout exception, got " + (($chain | ForEach-Object { $_.GetType().FullName }) -join ' > '))
    Assert-True ($sw.Elapsed.TotalSeconds -ge $MinSec -and $sw.Elapsed.TotalSeconds -lt $MaxSec) ("stopped between {0} and {1} s, took {2:N1} s" -f $MinSec, $MaxSec, $sw.Elapsed.TotalSeconds)
}

# ---------------------------------------------------------------------------
# Code under test
# ---------------------------------------------------------------------------

$repoRoot      = Split-Path $PSScriptRoot -Parent
$gitRunnerPath = Join-Path $repoRoot 'Templates\Git-Runner_TEMPLATE.ps1'
$generatorPath = Join-Path $repoRoot 'Other_Tools\Generate_Install-Command.ps1'
$script:Ps51   = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

foreach ($path in @($gitRunnerPath, $generatorPath, $script:Ps51)) {
    if (-not (Test-Path -LiteralPath $path)) { Write-Host "FATAL: $path not found"; exit 2 }
}

function Get-FunctionText {
    param([string]$Path, [string]$Name)
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$parseErrors)
    $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true)
    if (-not $fn) { throw "Function $Name not found in $Path" }
    return $fn.Extent.Text
}

# Only the pure helpers are loaded here; CheckAndInstall-Git runs in child processes.
foreach ($helper in @('Invoke-PDHttpGet', 'Get-PDLatestGitInstaller', 'Save-PDGitInstaller', 'Get-PDRunningGitInstaller')) {
    . ([scriptblock]::Create((Get-FunctionText -Path $gitRunnerPath -Name $helper)))
}

$script:TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('PowerDeploy-GitInstallTests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null

Write-Host "================================================================"
Write-Host " GitRunnerGitInstall tests"
Write-Host " Engine : PowerShell $($PSVersionTable.PSVersion)"
Write-Host " Temp   : $script:TempRoot"
Write-Host "================================================================"
Write-Host ""

# ---------------------------------------------------------------------------
# Local HTTP server (127.0.0.1, random port). Each connection is served on its own runspace.
#   /ok /404 /ua (echoes the User-Agent)
#   /tag/<name>    latest-tag text from $script:TagBodies
#   /slowdl/*      like /slow (a release download that trickles)
#   /slow          headers at once (Content-Length), body trickles for minutes
#   /chunked-slow  chunked body, one small chunk every 0.5 s for minutes
#   /silent        chunked body, one chunk, then silence
#   anything else  404
# ---------------------------------------------------------------------------

$script:TagBodies = @{
    'w1'      = "v2.99.0.windows.1`n"
    'w2'      = "  v2.99.0.windows.2`r`n"
    'w2real'  = 'v2.47.1.windows.2'
    'bom'     = ([string][char]0xFEFF) + 'v2.99.0.windows.1'
    'html'    = '<html>rate limited</html>'
    'empty'   = ''
    'inject'  = 'v2.99.0.windows.1; x'
    'lines'   = "v2.99.0.windows.1`nv2.98.0.windows.1"
    'upper'   = 'V2.99.0.WINDOWS.1'
    'digits'  = 'v2.99.' + ([string][char]0x0663) + '.windows.1'
    'long'    = ('x' * 200)
}

$handlerText = @'
param($client, $tagBodies)
try {
    $stream = $client.GetStream()
    $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII, $false, 1024, $true)
    $requestLine = $reader.ReadLine()
    $userAgent = ''
    while ($true) {
        $line = $reader.ReadLine()
        if ($null -eq $line -or $line -eq '') { break }
        if ($line -like 'User-Agent:*') { $userAgent = $line.Substring(11).Trim() }
    }
    $requestPath = ($requestLine -split ' ')[1]
    if ($requestPath -like '/slowdl/*') { $requestPath = '/slow' }

    function Send-Bytes { param([byte[]]$Bytes) $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush() }
    function Send-Ascii { param([string]$Text) Send-Bytes ([System.Text.Encoding]::ASCII.GetBytes($Text)) }
    function Send-Whole {
        param([string]$Status, [string]$Body)
        $b = [System.Text.Encoding]::UTF8.GetBytes($Body)
        Send-Ascii "HTTP/1.1 $Status`r`nContent-Type: text/plain`r`nContent-Length: $($b.Length)`r`nConnection: close`r`n`r`n"
        Send-Bytes $b
    }

    if ($requestPath -like '/tag/*' -and $tagBodies.ContainsKey($requestPath.Substring(5))) {
        Send-Whole '200 OK' $tagBodies[$requestPath.Substring(5)]
    } else {
        switch ($requestPath) {
            '/ok' { Send-Whole '200 OK' 'PDTEST-INSTALLER-BYTES' }
            '/ua' { Send-Whole '200 OK' $userAgent }
            '/slow' {
                Send-Ascii "HTTP/1.1 200 OK`r`nContent-Type: application/octet-stream`r`nContent-Length: 50000000`r`nConnection: close`r`n`r`n"
                $chunk = New-Object byte[] 1000
                for ($i = 0; $i -lt 480; $i++) { Send-Bytes $chunk; Start-Sleep -Milliseconds 500 }
            }
            '/chunked-slow' {
                Send-Ascii "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nTransfer-Encoding: chunked`r`nConnection: close`r`n`r`n"
                Send-Ascii "1`r`nv`r`n"
                for ($i = 0; $i -lt 480; $i++) { Send-Ascii ("10`r`n" + ('2' * 16) + "`r`n"); Start-Sleep -Milliseconds 500 }
            }
            '/silent' {
                Send-Ascii "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nTransfer-Encoding: chunked`r`nConnection: close`r`n`r`n"
                Send-Ascii "1`r`nv`r`n"
                for ($i = 0; $i -lt 240; $i++) {
                    if ($client.Client.Poll(0, [System.Net.Sockets.SelectMode]::SelectRead) -and $client.Client.Available -eq 0) { break }
                    Start-Sleep -Milliseconds 500
                }
            }
            default { Send-Whole '404 Not Found' 'not found' }
        }
    }
} catch {
    # Client went away (timed out)
} finally {
    $client.Close()
}
'@

$script:Listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
$script:Listener.Start()
$script:BaseUrl = 'http://127.0.0.1:{0}' -f $script:Listener.LocalEndpoint.Port
$script:Pool = [runspacefactory]::CreateRunspacePool(1, 16)
$script:Pool.Open()

$script:ServerPs = [powershell]::Create()
[void]$script:ServerPs.AddScript({
    param($listener, $pool, $handlerText, $tagBodies)
    while ($true) {
        $client = $null
        try { $client = $listener.AcceptTcpClient() } catch { break }
        $p = [powershell]::Create()
        $p.RunspacePool = $pool
        [void]$p.AddScript($handlerText).AddArgument($client).AddArgument($tagBodies)
        [void]$p.BeginInvoke()
    }
}).AddArgument($script:Listener).AddArgument($script:Pool).AddArgument($handlerText).AddArgument($script:TagBodies)
$script:ServerHandle = $script:ServerPs.BeginInvoke()

# ---------------------------------------------------------------------------
# Child process driver for CheckAndInstall-Git scenarios
# ---------------------------------------------------------------------------

$script:DriverPath = Join-Path $script:TempRoot 'Invoke-GitInstallScenario.ps1'
$driverText = @'
param([string]$ConfigPath)
$ErrorActionPreference = 'Continue'
$cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json

$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($cfg.GitRunnerPath, [ref]$null, [ref]$parseErrors)
foreach ($name in @('Write-Log', 'Get-PDRunningGitInstaller', 'Invoke-PDHttpGet', 'Get-PDLatestGitInstaller', 'Save-PDGitInstaller', 'CheckAndInstall-Git')) {
    $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
    if (-not $fn) { Write-Host "FATAL: $name not found"; exit 99 }
    . ([scriptblock]::Create($fn.Extent.Text))
}

# Same variables the template's Vars section sets, with short limits and local URLs for the test
$ThisFileName = 'Git-Runner_TEMPLATE.ps1'
$WorkingDirectory = $cfg.WorkingDirectory
$LogPath = $cfg.LogPath
$GitInstallMutexName = $cfg.MutexName
$GitInstallMutexWaitSec = [int]$cfg.MutexWaitSec
$GitReleaseLookupTimeoutSec = [int]$cfg.LookupTimeoutSec
$GitLatestTagUrl = $cfg.TagUrl
$GitReleaseDownloadBaseUrl = $cfg.DownloadBaseUrl
$GitDownloadTimeoutSec = [int]$cfg.DownloadTimeoutSec
$GitInstallerTimeoutSec = [int]$cfg.InstallerTimeoutSec

function Write-Record { param([string]$Line) Add-Content -LiteralPath $cfg.RecordPath -Value $Line }

# The real Git on this machine is never looked at or changed
function Get-Command {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$Name)
    if ($Name -eq 'git') {
        Write-Record 'GET_COMMAND_GIT'
        if ($cfg.GitFound) { return [pscustomobject]@{ Name = 'git.exe' } }
        return $null
    }
    Microsoft.PowerShell.Core\Get-Command @PSBoundParameters
}

# Tripwire: the lookup must not use Invoke-RestMethod or Invoke-WebRequest (their -TimeoutSec does not bound the body)
function Invoke-RestMethod { Write-Record 'IRM_CALLED'; throw 'Invoke-RestMethod must not be used' }
function Invoke-WebRequest { Write-Record 'IWR_CALLED'; throw 'Invoke-WebRequest must not be used' }

if ($cfg.Download -ne 'Real') {
    function Save-PDGitInstaller {
        param([string]$Url, [string]$OutFile, [int]$TimeoutSec)
        Write-Record "DOWNLOAD_URL=$Url"
        Write-Record "DOWNLOAD_TIMEOUT=$TimeoutSec"
        [System.IO.File]::WriteAllText($OutFile, 'partial')
        if ($cfg.Download -eq 'Fail') { throw (New-Object System.Threading.Tasks.TaskCanceledException 'A task was canceled.') }
    }
}

if ($cfg.RunningInstaller) {
    function Get-PDRunningGitInstaller { param([string[]]$ProcessName) Write-Record 'RUNNING_CHECK'; return @([pscustomobject]@{ Id = 4242 }) }
}

function Start-Process {
    [CmdletBinding()]
    param([string]$FilePath, [string[]]$ArgumentList, [switch]$PassThru)
    Write-Record "START=$FilePath $($ArgumentList -join ' ')"
    $exe = Join-Path $PSHOME 'powershell.exe'
    if ($cfg.Installer -eq 'Hang') {
        $p = Microsoft.PowerShell.Management\Start-Process -FilePath $exe -ArgumentList '-NoProfile', '-Command', 'Start-Sleep -Seconds 90' -PassThru -WindowStyle Hidden
    } else {
        $p = Microsoft.PowerShell.Management\Start-Process -FilePath $exe -ArgumentList '-NoProfile', '-Command', 'exit 3' -PassThru -WindowStyle Hidden
    }
    Write-Record "INSTALLER_PID=$($p.Id)"
    return $p
}

Write-Record 'CALL'
CheckAndInstall-Git
Write-Record 'RETURNED'
exit 0
'@
[System.IO.File]::WriteAllText($script:DriverPath, $driverText, (New-Object System.Text.UTF8Encoding($true)))

function New-MutexName { return ('Local\PowerDeploy_GitInstall_Test_' + [guid]::NewGuid().ToString('N')) }

function Invoke-GitInstallScenario {
    param(
        [string]$TagPath = '/tag/w1',
        [string]$DownloadBaseUrl = 'https://example.invalid/dl',
        [string]$Download = 'Ok',
        [string]$Installer = 'Exit',
        [switch]$RunningInstaller,
        [switch]$GitFound,
        [switch]$LeftoverInstaller,
        [int]$MutexWaitSec = 5,
        [int]$LookupTimeoutSec = 7,
        [int]$DownloadTimeoutSec = 300,
        [int]$InstallerTimeoutSec = 600,
        [string]$MutexName = (New-MutexName),
        [switch]$HoldMutex
    )

    $dir = Join-Path $script:TempRoot ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $cfg = [ordered]@{
        GitRunnerPath       = $gitRunnerPath
        WorkingDirectory    = (Join-Path $dir 'wd')
        LogPath             = (Join-Path $dir 'git.log')
        RecordPath          = (Join-Path $dir 'record.txt')
        MutexName           = $MutexName
        MutexWaitSec        = $MutexWaitSec
        LookupTimeoutSec    = $LookupTimeoutSec
        TagUrl              = ($script:BaseUrl + $TagPath)
        DownloadBaseUrl     = $DownloadBaseUrl
        DownloadTimeoutSec  = $DownloadTimeoutSec
        InstallerTimeoutSec = $InstallerTimeoutSec
        Download            = $Download
        Installer           = $Installer
        RunningInstaller    = [bool]$RunningInstaller
        GitFound            = [bool]$GitFound
    }
    New-Item -ItemType Directory -Path $cfg.WorkingDirectory -Force | Out-Null
    $installerPath = Join-Path $cfg.WorkingDirectory 'TEMP\git-installer.exe'
    if ($LeftoverInstaller) {
        New-Item -ItemType Directory -Path (Split-Path $installerPath -Parent) -Force | Out-Null
        [System.IO.File]::WriteAllText($installerPath, 'leftover')
    }
    $cfgPath = Join-Path $dir 'config.json'
    [System.IO.File]::WriteAllText($cfgPath, ($cfg | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))

    # This process keeps its own handle open for the whole run, so a child that exits while still owning
    # the mutex shows up afterwards as an abandoned mutex instead of silently disappearing.
    $observer = New-Object System.Threading.Mutex($false, $MutexName)
    try {
        if ($HoldMutex) { [void]$observer.WaitOne(0) }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        & $script:Ps51 -NoProfile -ExecutionPolicy Bypass -File $script:DriverPath -ConfigPath $cfgPath *> $null
        $exitCode = $LASTEXITCODE
        $sw.Stop()

        if ($HoldMutex) {
            $observer.ReleaseMutex()
            $mutexState = 'HeldByTest'
        } else {
            $mutexState = 'Unknown'
            try {
                if ($observer.WaitOne(0)) { $mutexState = 'Released'; $observer.ReleaseMutex() } else { $mutexState = 'StillHeld' }
            } catch [System.Threading.AbandonedMutexException] {
                $mutexState = 'Abandoned'
                $observer.ReleaseMutex()
            }
        }
    } finally {
        $observer.Dispose()
    }

    $record = @()
    if (Test-Path -LiteralPath $cfg.RecordPath) { $record = @(Get-Content -LiteralPath $cfg.RecordPath) }
    $log = ''
    if (Test-Path -LiteralPath $cfg.LogPath) { $log = [System.IO.File]::ReadAllText($cfg.LogPath) }

    return [pscustomobject]@{
        ExitCode      = $exitCode
        Record        = $record
        Log           = $log
        InstallerPath = $installerPath
        ElapsedSec    = $sw.Elapsed.TotalSeconds
        MutexState    = $mutexState
    }
}

function Get-RecordValue {
    param([object[]]$Record, [string]$Key)
    $line = @($Record | Where-Object { $_ -like "$Key=*" }) | Select-Object -First 1
    if ($null -eq $line) { return $null }
    return $line.Substring($Key.Length + 1)
}

# A lookup that fails must end the run with 1618 before anything is downloaded, with the mutex released
function Assert-LookupRetry {
    param([object]$Result, [string]$Context)
    Assert-Equal 1618 $Result.ExitCode "exit code ($Context)"
    Assert-True ($null -eq (Get-RecordValue $Result.Record 'DOWNLOAD_URL')) "nothing downloaded ($Context)"
    Assert-True ($null -eq (Get-RecordValue $Result.Record 'START')) "installer not started ($Context)"
    Assert-Like '*WARNING] SCRIPT: Git-Runner_TEMPLATE.ps1 | END | The latest Git release tag is not available right now. Exiting with 1618*' $Result.Log "end line ($Context)"
    Assert-Equal 'Released' $Result.MutexState "mutex released ($Context)"
}

# ---------------------------------------------------------------------------
# Cases: production values in the template
# ---------------------------------------------------------------------------

$script:TemplateText = [System.IO.File]::ReadAllText($gitRunnerPath)

Add-TestCase 'V01' 'Template keeps the production limits (300 s mutex wait, 30 s lookup, 300 s download, 600 s installer) and the two URLs' {
    Assert-True ($script:TemplateText -match '(?m)^\$GitInstallMutexName = "Global\\PowerDeploy_GitInstall"') 'mutex name'
    Assert-True ($script:TemplateText -match '(?m)^\$GitInstallMutexWaitSec = 300\b') 'mutex wait'
    Assert-True ($script:TemplateText -match '(?m)^\$GitReleaseLookupTimeoutSec = 30\b') 'lookup'
    Assert-True ($script:TemplateText -match '(?m)^\$GitLatestTagUrl = "https://gitforwindows\.org/latest-tag\.txt"') 'latest-tag URL'
    Assert-True ($script:TemplateText -match '(?m)^\$GitReleaseDownloadBaseUrl = "https://github\.com/git-for-windows/git/releases/download"') 'download base URL'
    Assert-True ($script:TemplateText -match '(?m)^\$GitDownloadTimeoutSec = 300\b') 'download'
    Assert-True ($script:TemplateText -match '(?m)^\$GitInstallerTimeoutSec = 600\b') 'installer'
}

Add-TestCase 'V02' 'Template has no built-in Git version (the latest tag is read at run time)' {
    Assert-NotLike '*GitPinned*' $script:TemplateText 'no pinned variables'
    Assert-True ($script:TemplateText -notmatch 'Git-[0-9]+\.[0-9]+') 'no Git-<version> installer file name'
    Assert-True ($script:TemplateText -notmatch 'v[0-9]+\.[0-9]+\.[0-9]+\.windows') 'no release tag'
}

Add-TestCase 'V03' 'The install variables sit after the first ##### marker, so stamped custom scripts keep them' {
    $marker = $script:TemplateText.IndexOf('#####')
    $vars = $script:TemplateText.IndexOf('$GitInstallMutexName = ')
    Assert-True ($marker -ge 0 -and $vars -gt $marker) 'variables after the marker'
}

Add-TestCase 'V04' 'No GitHub API lookup is left: no api.github.com, release JSON, Invoke-RestMethod or Invoke-WebRequest' {
    Assert-NotLike '*api.github.com*' $script:TemplateText 'no api.github.com'
    Assert-NotLike '*assets*' $script:TemplateText 'no release assets'
    Assert-NotLike '*tag_name*' $script:TemplateText 'no release JSON'
    $text = Get-FunctionText -Path $gitRunnerPath -Name 'CheckAndInstall-Git'
    Assert-NotLike '*Invoke-RestMethod*' $text 'no Invoke-RestMethod'
    Assert-NotLike '*Invoke-WebRequest*' $text 'no Invoke-WebRequest'
    Assert-NotLike '*ConvertFrom-Json*' $text 'no JSON parsing'
}

# ---------------------------------------------------------------------------
# Cases: HTTP and tag helpers (in this process, against the local server)
# ---------------------------------------------------------------------------

Add-TestCase 'H01' 'Save-PDGitInstaller writes the downloaded bytes' {
    $out = Join-Path $script:TempRoot 'h01.bin'
    Save-PDGitInstaller -Url "$script:BaseUrl/ok" -OutFile $out -TimeoutSec 10
    Assert-Equal 'PDTEST-INSTALLER-BYTES' ([System.IO.File]::ReadAllText($out)) 'file content'
}

Add-TestCase 'H02' 'Save-PDGitInstaller throws on a non-success status and writes no file' {
    $out = Join-Path $script:TempRoot 'h02.bin'
    $caught = $null
    try { Save-PDGitInstaller -Url "$script:BaseUrl/404" -OutFile $out -TimeoutSec 10 } catch { $caught = $_ }
    Assert-True ($null -ne $caught) 'threw'
    Assert-Like '*HTTP 404*' $caught.Exception.Message 'message'
    Assert-True (-not (Test-Path -LiteralPath $out)) 'no file'
}

Add-TestCase 'H03' 'Save-PDGitInstaller stops a body that trickles in, at the time limit (whole-transfer bound)' {
    $out = Join-Path $script:TempRoot 'h03.bin'
    Assert-TimesOut -Body { Save-PDGitInstaller -Url "$script:BaseUrl/slow" -OutFile $out -TimeoutSec 3 } -MinSec 2.5 -MaxSec 15
    Assert-True (-not (Test-Path -LiteralPath $out)) 'no file'
}

Add-TestCase 'H04' 'Invoke-PDHttpGet sends a generic User-Agent' {
    $bytes = Invoke-PDHttpGet -Url "$script:BaseUrl/ua" -TimeoutSec 10
    Assert-True ($bytes -is [byte[]]) 'returns a byte array'
    Assert-Equal 'PowerDeploy-GitRunner' ([System.Text.Encoding]::ASCII.GetString($bytes)) 'User-Agent'
}

Add-TestCase 'H05' 'Get-PDLatestGitInstaller: windows.1 tag -> Git-X.Y.Z-64-bit.exe (trailing newline trimmed)' {
    $r = Get-PDLatestGitInstaller -TagUrl "$script:BaseUrl/tag/w1" -DownloadBaseUrl 'https://example.invalid/dl/' -TimeoutSec 10
    Assert-Equal 'v2.99.0.windows.1' $r.Tag 'tag'
    Assert-Equal 'https://example.invalid/dl/v2.99.0.windows.1/Git-2.99.0-64-bit.exe' $r.Url 'URL'
}

Add-TestCase 'H06' 'Get-PDLatestGitInstaller: windows.N tag (N other than 1) -> Git-X.Y.Z.N-64-bit.exe (surrounding whitespace trimmed)' {
    $r = Get-PDLatestGitInstaller -TagUrl "$script:BaseUrl/tag/w2" -DownloadBaseUrl 'https://example.invalid/dl' -TimeoutSec 10
    Assert-Equal 'https://example.invalid/dl/v2.99.0.windows.2/Git-2.99.0.2-64-bit.exe' $r.Url 'URL'
    $real = Get-PDLatestGitInstaller -TagUrl "$script:BaseUrl/tag/w2real" -DownloadBaseUrl 'https://github.com/git-for-windows/git/releases/download' -TimeoutSec 10
    Assert-Equal 'https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.2/Git-2.47.1.2-64-bit.exe' $real.Url 'matches the real v2.47.1.windows.2 asset name'
}

Add-TestCase 'H07' 'Get-PDLatestGitInstaller accepts a UTF-8 byte order mark before the tag' {
    $r = Get-PDLatestGitInstaller -TagUrl "$script:BaseUrl/tag/bom" -DownloadBaseUrl 'https://example.invalid/dl' -TimeoutSec 10
    Assert-Equal 'v2.99.0.windows.1' $r.Tag 'tag'
}

Add-TestCase 'H08' 'Get-PDLatestGitInstaller refuses text that is not exactly a release tag' {
    foreach ($name in @('html', 'empty', 'inject', 'lines', 'upper', 'digits', 'long')) {
        $caught = $null
        try { Get-PDLatestGitInstaller -TagUrl "$script:BaseUrl/tag/$name" -DownloadBaseUrl 'https://example.invalid/dl' -TimeoutSec 10 | Out-Null } catch { $caught = $_ }
        Assert-True ($null -ne $caught) "refused: $name"
        Assert-Like '*not a Git for Windows release tag*' $caught.Exception.Message "message: $name"
    }
}

Add-TestCase 'H09' 'A refused tag is shown at most 40 characters long, with only safe characters' {
    $caught = $null
    try { Get-PDLatestGitInstaller -TagUrl "$script:BaseUrl/tag/long" -DownloadBaseUrl 'https://example.invalid/dl' -TimeoutSec 10 | Out-Null } catch { $caught = $_ }
    Assert-Like ("*: '" + ('x' * 40) + "...'") $caught.Exception.Message 'truncated to 40 characters'
    try { Get-PDLatestGitInstaller -TagUrl "$script:BaseUrl/tag/html" -DownloadBaseUrl 'https://example.invalid/dl' -TimeoutSec 10 | Out-Null } catch { $caught = $_ }
    Assert-Like "*: '?html?rate limited??html?'" $caught.Exception.Message 'unsafe characters replaced'
}

Add-TestCase 'H10' 'Get-PDLatestGitInstaller stops a chunked body that trickles in, at the time limit' {
    Assert-TimesOut -Body { Get-PDLatestGitInstaller -TagUrl "$script:BaseUrl/chunked-slow" -DownloadBaseUrl 'https://example.invalid/dl' -TimeoutSec 3 } -MinSec 2.5 -MaxSec 15
}

Add-TestCase 'H11' 'Get-PDLatestGitInstaller stops a chunked body that goes silent after one chunk, at the time limit' {
    Assert-TimesOut -Body { Get-PDLatestGitInstaller -TagUrl "$script:BaseUrl/silent" -DownloadBaseUrl 'https://example.invalid/dl' -TimeoutSec 3 } -MinSec 2.5 -MaxSec 15
}

Add-TestCase 'H12' 'Get-PDRunningGitInstaller looks for the installer and its Inno Setup child by name, from any path' {
    $text = Get-FunctionText -Path $gitRunnerPath -Name 'Get-PDRunningGitInstaller'
    Assert-True ($text -match "ProcessName = @\('git-installer', 'git-installer\.tmp'\)") 'default names'
    # Any path: this process runs from the PowerShell folder, not a working directory
    $self = Get-Process -Id $PID
    $found = @(Get-PDRunningGitInstaller -ProcessName @('pd-no-such-process-name', $self.ProcessName))
    Assert-True (@($found | Where-Object { $_.Id -eq $PID }).Count -eq 1) 'finds this process by name'
    Assert-Equal 0 @(Get-PDRunningGitInstaller -ProcessName @('pd-no-such-process-name')).Count 'no match, no error'
}

# ---------------------------------------------------------------------------
# Cases: CheckAndInstall-Git in a child Windows PowerShell 5.1 process
# ---------------------------------------------------------------------------

Add-TestCase 'G01' 'windows.1 tag: the built installer URL is downloaded, without Invoke-RestMethod/Invoke-WebRequest' {
    $r = Invoke-GitInstallScenario -TagPath '/tag/w1'
    Assert-Equal 'https://example.invalid/dl/v2.99.0.windows.1/Git-2.99.0-64-bit.exe' (Get-RecordValue $r.Record 'DOWNLOAD_URL') 'download URL'
    Assert-True ($r.Record -notcontains 'IRM_CALLED' -and $r.Record -notcontains 'IWR_CALLED') 'no Invoke-RestMethod/Invoke-WebRequest'
    Assert-Like '*Downloading Git v2.99.0.windows.1 from: https://example.invalid/dl/v2.99.0.windows.1/Git-2.99.0-64-bit.exe*' $r.Log 'logged'
    Assert-NotLike '*Exiting with 1618*' $r.Log 'no retry exit'
}

Add-TestCase 'G02' 'windows.2 tag: the .N installer file name is downloaded' {
    $r = Invoke-GitInstallScenario -TagPath '/tag/w2'
    Assert-Equal 'https://example.invalid/dl/v2.99.0.windows.2/Git-2.99.0.2-64-bit.exe' (Get-RecordValue $r.Record 'DOWNLOAD_URL') 'download URL'
}

Add-TestCase 'G03' '(a) Latest-tag lookup fails (HTTP 404): exit 1618, nothing downloaded, mutex released' {
    $r = Invoke-GitInstallScenario -TagPath '/404'
    Assert-LookupRetry $r '404'
    Assert-Like '*WARNING] Could not get the latest Git for Windows release tag from http://127.0.0.1:*/404 (time limit: 7s) (*HTTP 404*' $r.Log 'lookup warning'
}

Add-TestCase 'G04' '(a) Latest-tag text is not a release tag (HTML, empty, extra text, extra lines): exit 1618, nothing downloaded' {
    foreach ($name in @('html', 'empty', 'inject', 'lines')) {
        $r = Invoke-GitInstallScenario -TagPath "/tag/$name"
        Assert-LookupRetry $r $name
        Assert-Like '*WARNING] Could not get the latest Git for Windows release tag*not a Git for Windows release tag*' $r.Log "warning ($name)"
        if ($name -eq 'inject') { Assert-NotLike '*; x*' $r.Log 'unsafe characters not logged as-is' }
    }
}

Add-TestCase 'G05' '(a) Latest-tag lookup trickles past its limit: exit 1618 in bounded time' {
    $r = Invoke-GitInstallScenario -TagPath '/chunked-slow' -LookupTimeoutSec 3
    Assert-LookupRetry $r 'trickle'
    Assert-Like '*(time limit: 3s) (System.Threading.Tasks.TaskCanceledException*' $r.Log 'timeout warning'
    Assert-True ($r.ElapsedSec -lt 30) ("bounded, whole child run took {0:N1} s" -f $r.ElapsedSec)
}

Add-TestCase 'G06' '(a) Latest-tag lookup goes silent: exit 1618 in bounded time' {
    $r = Invoke-GitInstallScenario -TagPath '/silent' -LookupTimeoutSec 3
    Assert-LookupRetry $r 'silent'
    Assert-True ($r.ElapsedSec -lt 30) ("bounded, whole child run took {0:N1} s" -f $r.ElapsedSec)
}

Add-TestCase 'G07' '(b) Download fails: exit 1618, partial installer file removed, installer never started, mutex released' {
    $r = Invoke-GitInstallScenario -Download 'Fail'
    Assert-Equal 1618 $r.ExitCode 'exit code'
    Assert-Equal '300' (Get-RecordValue $r.Record 'DOWNLOAD_TIMEOUT') 'download limit passed through'
    Assert-True (-not (Test-Path -LiteralPath $r.InstallerPath)) 'partial file removed'
    Assert-True ($null -eq (Get-RecordValue $r.Record 'START')) 'installer not started'
    Assert-Like '*WARNING] Git installer download failed or did not finish within 300s (System.Threading.Tasks.TaskCanceledException*' $r.Log 'warning names the exception'
    Assert-Like '*Exiting with 1618*' $r.Log 'end line'
    Assert-Equal 'Released' $r.MutexState 'finally released the mutex on exit'
}

Add-TestCase 'G08' '(b) Built installer URL returns 404 (real download): exit 1618, no file, mutex released' {
    $r = Invoke-GitInstallScenario -Download 'Real' -DownloadBaseUrl "$script:BaseUrl/dl404"
    Assert-Equal 1618 $r.ExitCode 'exit code'
    Assert-True (-not (Test-Path -LiteralPath $r.InstallerPath)) 'no installer file'
    Assert-Like "*Downloading Git v2.99.0.windows.1 from: $script:BaseUrl/dl404/v2.99.0.windows.1/Git-2.99.0-64-bit.exe*" $r.Log 'built URL'
    Assert-Like '*WARNING] Git installer download failed*HTTP 404*' $r.Log 'warning'
    Assert-Equal 'Released' $r.MutexState 'mutex released'
}

Add-TestCase 'G09' '(b) Real download that trickles past the limit: exit 1618 near the limit, no file left' {
    $r = Invoke-GitInstallScenario -Download 'Real' -DownloadBaseUrl "$script:BaseUrl/slowdl" -DownloadTimeoutSec 3
    Assert-Equal 1618 $r.ExitCode 'exit code'
    Assert-True (-not (Test-Path -LiteralPath $r.InstallerPath)) 'no installer file'
    Assert-True ($r.ElapsedSec -lt 30) ("bounded, whole child run took {0:N1} s" -f $r.ElapsedSec)
    Assert-Like '*did not finish within 3s*' $r.Log 'warning'
    Assert-Equal 'Released' $r.MutexState 'mutex released'
}

Add-TestCase 'G10' '(c) Installer still running after the limit: exit 1618, installer left running, installer file kept' {
    $r = Invoke-GitInstallScenario -Installer 'Hang' -InstallerTimeoutSec 2
    $installerPid = [int](Get-RecordValue $r.Record 'INSTALLER_PID')
    try {
        Assert-Equal 1618 $r.ExitCode 'exit code'
        Assert-True ($null -ne (Get-Process -Id $installerPid -ErrorAction SilentlyContinue)) 'installer process not stopped'
        Assert-True (Test-Path -LiteralPath $r.InstallerPath) 'installer file kept'
        Assert-Like "*WARNING] The Git installer (process ID: $installerPid) is still running after 2s. It is left running*" $r.Log 'warning'
        Assert-Like '*/VERYSILENT /NORESTART*' (Get-RecordValue $r.Record 'START') 'installer arguments'
        Assert-Equal 'Released' $r.MutexState 'mutex released'
    } finally {
        Stop-Process -Id $installerPid -Force -ErrorAction SilentlyContinue
    }
}

Add-TestCase 'G11' '(c) A Git installer is already running on the device: exit 1618 before downloading' {
    $r = Invoke-GitInstallScenario -RunningInstaller
    Assert-Equal 1618 $r.ExitCode 'exit code'
    Assert-True ($r.Record -contains 'RUNNING_CHECK') 'checked for a running installer'
    Assert-True ($null -eq (Get-RecordValue $r.Record 'DOWNLOAD_URL')) 'no download'
    Assert-Like '*still running (process ID: 4242). It is left running.*' $r.Log 'warning'
    Assert-Equal 'Released' $r.MutexState 'mutex released'
}

Add-TestCase 'G12' '(d) Mutex wait times out: exit 1618, nothing looked up or downloaded' {
    $r = Invoke-GitInstallScenario -MutexName (New-MutexName) -HoldMutex -MutexWaitSec 2
    Assert-Equal 1618 $r.ExitCode 'exit code'
    Assert-True ($null -eq (Get-RecordValue $r.Record 'DOWNLOAD_URL')) 'no download'
    Assert-NotLike '*release tag*' $r.Log 'no lookup'
    Assert-Like '*WARNING] Timed out after 2s waiting for another Git installation to finish.*' $r.Log 'warning'
    Assert-NotLike '*ERROR]*' $r.Log 'not logged as an error'
}

Add-TestCase 'G13' '(e) Installer exits but git is still not found: exit 1, installer exit code logged, installer file removed' {
    $r = Invoke-GitInstallScenario
    Assert-Equal 1 $r.ExitCode 'exit code'
    Assert-Like '*WARNING] Git installer exited with code: 3*' $r.Log 'installer exit code'
    Assert-Like '*ERROR] Git is not working. Please investigate.*' $r.Log 'final check'
    Assert-True (-not (Test-Path -LiteralPath $r.InstallerPath)) 'installer file cleaned up'
    Assert-Equal 'Released' $r.MutexState 'mutex released'
}

Add-TestCase 'G14' 'Git already installed: a leftover installer file is removed when no installer is running' {
    $r = Invoke-GitInstallScenario -GitFound -LeftoverInstaller
    Assert-Equal 0 $r.ExitCode 'exit code'
    Assert-True ($r.Record -contains 'RETURNED') 'returned normally'
    Assert-True (-not (Test-Path -LiteralPath $r.InstallerPath)) 'leftover removed'
    Assert-Like '*INFO] Removed leftover git installer file at:*' $r.Log 'logged'
}

Add-TestCase 'G15' 'Git already installed: a leftover installer file is kept while an installer is running' {
    $r = Invoke-GitInstallScenario -GitFound -LeftoverInstaller -RunningInstaller
    Assert-Equal 0 $r.ExitCode 'exit code'
    Assert-True (Test-Path -LiteralPath $r.InstallerPath) 'leftover kept'
}

Add-TestCase 'G16' 'Harness check: a child that exits while owning the mutex is seen as Abandoned' {
    $name = New-MutexName
    $observer = New-Object System.Threading.Mutex($false, $name)
    try {
        & $script:Ps51 -NoProfile -Command "`$m = New-Object System.Threading.Mutex(`$false, '$name'); [void]`$m.WaitOne(); exit 5" *> $null
        $state = 'Unknown'
        try { if ($observer.WaitOne(0)) { $state = 'Released'; $observer.ReleaseMutex() } } catch [System.Threading.AbandonedMutexException] { $state = 'Abandoned'; $observer.ReleaseMutex() }
        Assert-Equal 'Abandoned' $state 'observer detects a missing release'
    } finally {
        $observer.Dispose()
    }
}

# ---------------------------------------------------------------------------
# Cases: install command shape (New-IntuneGitRunnerCommand)
# ---------------------------------------------------------------------------

function Write-Log { param([Parameter(ValueFromRemainingArguments = $true)]$Rest) }
$ThisFileName = 'Generate_Install-Command.ps1'
$CustomGitRunnerMakerScript = { 'stub-custom-script.ps1' }
. ([scriptblock]::Create((Get-FunctionText -Path $generatorPath -Name 'New-IntuneGitRunnerCommand')))

$script:ExitEnding = '; if ($LASTEXITCODE -is [int]) { exit $LASTEXITCODE } else { exit 1 }'
$script:ExitSuffix = $script:ExitEnding + '"'

function Get-EndingCount { param([string]$Command) return ([regex]::Matches($Command, [regex]::Escape($script:ExitEnding))).Count }

# Runs a command line through cmd.exe (as a management agent would), in $Dir. Sysnative exists only for
# 32-bit callers (the Intune agent); this test process may be 64-bit, so System32 is used instead.
function Invoke-CommandLine {
    param([string]$CommandLine, [string]$Dir)
    $runnable = $CommandLine.Replace('%SystemRoot%\Sysnative\', '%SystemRoot%\System32\')
    $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgumentList ('/d /c ' + $runnable) -WorkingDirectory $Dir -NoNewWindow -Wait -PassThru
    return $p.ExitCode
}

Add-TestCase 'C01' 'Command without -RequireOrgKeys and with parameters ends in the exit-code ending' {
    $cmd = New-IntuneGitRunnerCommand -RepoNickName 'R' -RepoUrl 'https://example.invalid/r.git' -RepoBranch 'main' -TargetWorkingDirectory 'C:\ProgramData\PD' -ScriptPath 'Installers\X.ps1' -ScriptParams @{ A = 'b' }
    Assert-True ($cmd.EndsWith("-ScriptParamsBase64 '" + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{ A = 'b' } | ConvertTo-Json -Compress))) + "'" + $script:ExitSuffix)) $cmd
    Assert-NotLike '*RequireOrgKeys*' $cmd 'no switch'
    Assert-Equal 1 (Get-EndingCount $cmd) 'one ending'
}

Add-TestCase 'C02' 'Command without parameters ends in the exit-code ending' {
    $cmd = New-IntuneGitRunnerCommand -RepoNickName 'R' -RepoUrl 'https://example.invalid/r.git' -RepoBranch 'main' -TargetWorkingDirectory 'C:\ProgramData\PD' -ScriptPath 'Installers\X.ps1'
    Assert-True ($cmd.EndsWith("-ScriptPath 'Installers\X.ps1'" + $script:ExitSuffix)) $cmd
    Assert-Equal 1 (Get-EndingCount $cmd) 'one ending'
}

Add-TestCase 'C03' 'Command with -RequireOrgKeys keeps the switch before the exit-code ending' {
    $cmd = New-IntuneGitRunnerCommand -RepoNickName 'R' -RepoUrl 'https://example.invalid/r.git' -RepoBranch 'dev' -TargetWorkingDirectory 'C:\ProgramData\PD' -ScriptPath 'Installers\X.ps1' -ScriptParams @{ A = 'b' } -RequireOrgKeys 'Printers'
    Assert-True ($cmd.EndsWith(" -RequireOrgKeys 'Printers'" + $script:ExitSuffix)) $cmd
    Assert-Like "*-RepoUrl 'https://example.invalid/r.git' -RepoBranch 'dev' -WorkingDirectory*" $cmd 'branch switch kept'
    Assert-Equal 1 (Get-EndingCount $cmd) 'one ending'
}

Add-TestCase 'C04' 'Through cmd.exe: Git-Runner exit codes 1618, 1 and 0 pass through; a thrown error gives 1' {
    $dir = Join-Path $script:TempRoot 'cmdrun-codes'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $cmd = New-IntuneGitRunnerCommand -RepoNickName 'R' -RepoUrl 'https://example.invalid/r.git' -RepoBranch 'main' -TargetWorkingDirectory 'C:\ProgramData\PD' -ScriptPath 'Installers\X.ps1' -ScriptParams @{ A = 'b' } -RequireOrgKeys 'Applications'
    $stub = Join-Path $dir 'Git-Runner_TEMPLATE.ps1'
    foreach ($code in @(1618, 1, 0)) {
        [System.IO.File]::WriteAllText($stub, "param([Parameter(ValueFromRemainingArguments=`$true)]`$Rest)`r`nExit $code`r`n")
        Assert-Equal $code (Invoke-CommandLine -CommandLine $cmd -Dir $dir) "stub exit $code"
    }
    [System.IO.File]::WriteAllText($stub, "param([Parameter(ValueFromRemainingArguments=`$true)]`$Rest)`r`nthrow 'boom'`r`n")
    Assert-Equal 1 (Invoke-CommandLine -CommandLine $cmd -Dir $dir) 'thrown error'
}

Add-TestCase 'C05' 'Through cmd.exe: Git-Runner that never starts (missing file, parse error, parameter binding error) gives 1, not 0' {
    $dir = Join-Path $script:TempRoot 'cmdrun-nostart'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $cmd = New-IntuneGitRunnerCommand -RepoNickName 'R' -RepoUrl 'https://example.invalid/r.git' -RepoBranch 'main' -TargetWorkingDirectory 'C:\ProgramData\PD' -ScriptPath 'Installers\X.ps1' -ScriptParams @{ A = 'b' }
    $stub = Join-Path $dir 'Git-Runner_TEMPLATE.ps1'

    Assert-Equal 1 (Invoke-CommandLine -CommandLine $cmd -Dir $dir) 'missing file'

    [System.IO.File]::WriteAllText($stub, "param([string]`$RepoNickName)`r`nif (`$true) {`r`nExit 0`r`n")
    Assert-Equal 1 (Invoke-CommandLine -CommandLine $cmd -Dir $dir) 'parse error'

    [System.IO.File]::WriteAllText($stub, "param([int]`$RepoNickName)`r`nExit 0`r`n")
    Assert-Equal 1 (Invoke-CommandLine -CommandLine $cmd -Dir $dir) 'binding error'

    # Why the -is [int] test is there: a plain "; exit $LASTEXITCODE" reports a missing file as 0 (success).
    Remove-Item -LiteralPath $stub -Force
    $plain = $cmd.Replace($script:ExitEnding, '; exit $LASTEXITCODE')
    Assert-Equal 0 (Invoke-CommandLine -CommandLine $plain -Dir $dir) 'plain ending, missing file'
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

try {
    foreach ($case in $script:Cases) {
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
} finally {
    try { $script:Listener.Stop() } catch { }
    try { $script:ServerPs.Stop(); $script:ServerPs.Dispose() } catch { }
    try { $script:Pool.Close(); $script:Pool.Dispose() } catch { }
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
