#__PD_STAMP_HEADER__

<#

.SYNOPSIS
    Intune Platform Script: writes PowerDeploy's organization registry values under
    HKLM\SOFTWARE\PowerDeploy, self-contained (no Git, no clone, no network, no repo files).

.DESCRIPTION
    Why this exists: Intune Remediations do not run during the Autopilot Enrollment Status Page, so
    PowerDeploy's Win32 apps used to race the "POWERDEPLOY ORG REGISTRY: Remediation" package (they
    wait for it with Git-Runner -RequireOrgKeys, exit 1618). Intune Platform Scripts run BEFORE Win32
    apps, so this script puts the same values in place first. The Remediation stays as the hourly
    drift/rotation mechanism; both write the same names, key paths, types and blank-value behaviour.

    This file is a TEMPLATE. Other_Tools\Generate_Install-Command.ps1 (function
    OrgRegistryPlatformScript) fills in the stamp regions below: the header comment and the stamped
    values block. Platform scripts take no parameters, so everything this script needs is stamped.
    Run unstamped, it changes nothing and exits 1.

    What it does, in order:
      1. Opens HKLM in the explicit 64-bit registry view (same as Configure-Registry.ps1 and the
         Git-Runner org registry values check).
      2. Creates the root key and the General, Printers and Applications subkeys as needed.
      3. Applies the strict ACL to every one of those keys BEFORE any value is written: protected
         (no inheritance), SYSTEM (S-1-5-18) and BUILTIN\Administrators (S-1-5-32-544) only, Allow,
         FullControl, ContainerInherit, no propagation flags. This is exactly what
         Configure-Registry.ps1 Set-StrictRegAcl writes: Security_Manager.ps1 locks the root key with
         it, and the Remediation locks each subkey it creates with it, so when Git-Runner's Security
         Manager runs later it finds nothing to change. Every ACL is built from SIDs, never names.
         If any key cannot be locked down, no value is written and the script exits 1.
      4. Writes the stamped String (REG_SZ) values. A blank value is written as an empty String
         value (it exists, with no data), the same as the Remediation does.
      5. Reads every value back. Exit 0 only if every ACL and every value is confirmed.

    Intune settings (Devices > Scripts and remediations > Platform scripts):
      - Run this script using the logged on credentials: No   (runs as SYSTEM)
      - Enforce script signature check:                 No
      - Run script in 64-bit PowerShell host:            Yes
      - Assign to DEVICE groups (the Autopilot device phase only runs device-targeted scripts).

    Output and log: value NAMES and written / already correct / verified / FAILED only, NEVER the
    values. Intune copies platform script output into
    C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AgentExecutor.log, which is readable more
    widely than the PowerDeploy logs. The log file goes to <working directory>\Logs\Config_Logs (the
    same folder Configure-Registry.ps1 logs to); if it cannot be written the script carries on.

    Exit codes: 0 = all values and ACLs confirmed; 1 = anything else (Intune retries a failed
    platform script up to 3 times).

    Windows PowerShell 5.1 (Intune's 64-bit host) is the target; the file is ASCII so 5.1 reads it
    correctly. The generated copy is UTF-8 with BOM because a stamped value may be non-ASCII.

#>

# ---------------------------------------------------------------------------
# Stamped values (replaced by the generator; the unstamped defaults change nothing)
# ---------------------------------------------------------------------------
#__PD_STAMP_BEGIN__
$PDStamped          = $false
$PDDeployMode       = ''
$PDSourceCommit     = ''
$PDRegistryRoot     = 'SOFTWARE\PowerDeploy'
$PDWorkingDirectory = ''
$PDOrgValues        = @()
#__PD_STAMP_END__

########
# Vars #
########

$ThisFileName = $MyInvocation.MyCommand.Name

# The only subkeys this script will create under the root. Matches the layout in
# Generate_Install-Command.ps1 OrgRegistryEntryList.
$PDAllowedSubKeys = @('General', 'Printers', 'Applications')

# The real root, or the test-only root the generator can stamp for Tests\OrgRegistryPlatformScript.Tests.ps1.
# Checked again here so a hand-edited copy can never lock down some other key. Ends in \z, not $:
# .NET's $ also matches before a final newline, which would let "SOFTWARE\PowerDeploy`n" through.
$PDAllowedRootPattern = '^SOFTWARE\\PowerDeploy(-Test-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})?\z'

$LogPath = $null
if (-not [string]::IsNullOrWhiteSpace($PDWorkingDirectory)) {
    $LogRoot = "$PDWorkingDirectory\Logs\Config_Logs"
    $LogPath = "$LogRoot\PowerDeploy-OrgRegistry_PlatformScript._Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
}
$script:PDLogWritable = [bool]$LogPath

###############
## Functions ##
###############

# Same shape as the other PowerDeploy endpoint scripts, except that a log file that cannot be
# written never stops the script: the registry work matters more than the log. Callers only ever
# pass value NAMES and statuses here.
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default   { Write-Host $logEntry }
    }

    if (-not $script:PDLogWritable) { return }

    try {
        $logDir = Split-Path $LogPath -Parent
        if (!(Test-Path -LiteralPath $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force -ErrorAction Stop | Out-Null
        }
    } catch {
        $script:PDLogWritable = $false
        Write-Host "[$timestamp] [WARNING] The log folder could not be created ($($_.Exception.GetType().Name)); continuing without a log file." -ForegroundColor Yellow
        return
    }

    # Resilient log write: retry an atomic append so a transient AV/EDR file lock
    # (Defender, CrowdStrike, etc.) cannot throw. Encoding::Default (system ANSI) matches the other
    # PowerDeploy endpoint logs.
    for ($logAttempt = 1; $logAttempt -le 5; $logAttempt++) {
        try {
            [System.IO.File]::AppendAllText($LogPath, $logEntry + [Environment]::NewLine, [System.Text.Encoding]::Default)
            break
        } catch {
            if ($logAttempt -eq 5) {
                $script:PDLogWritable = $false
                Write-Host "[$timestamp] [WARNING] The log file could not be written; continuing without a log file." -ForegroundColor Yellow
                break
            }
            Start-Sleep -Milliseconds 40
        }
    }
}

# The ACL Configure-Registry.ps1 Set-StrictRegAcl writes, built the same way: a fresh
# RegistrySecurity, inheritance protected and inherited rules dropped, then SYSTEM and
# Administrators by SID with FullControl, ContainerInherit, no propagation flags, Allow.
function New-PDStrictRegistrySecurity {

    $regSec = New-Object System.Security.AccessControl.RegistrySecurity
    $regSec.SetAccessRuleProtection($true, $false)

    $sidSystem = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-18"
    $sidAdmins = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-32-544"

    $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $propFlags    = [System.Security.AccessControl.PropagationFlags]::None
    $accessType   = [System.Security.AccessControl.AccessControlType]::Allow
    $fc           = [System.Security.AccessControl.RegistryRights]::FullControl

    $ruleSystem = New-Object System.Security.AccessControl.RegistryAccessRule(
        $sidSystem, $fc, $inheritFlags, $propFlags, $accessType
    )
    $regSec.AddAccessRule($ruleSystem)

    $ruleAdmins = New-Object System.Security.AccessControl.RegistryAccessRule(
        $sidAdmins, $fc, $inheritFlags, $propFlags, $accessType
    )
    $regSec.AddAccessRule($ruleAdmins)

    return $regSec
}

# True only when the ACL is exactly what New-PDStrictRegistrySecurity writes. That is stricter than
# Configure-Registry.ps1 Test-StrictRegAcl (which, for example, also accepts extra inheritance flags),
# so anything this accepts, Test-StrictRegAcl accepts too. Rules are read as SIDs, so no account name
# is ever translated (an unresolvable Entra user SID cannot make this throw).
function Test-PDStrictRegistrySecurity {
    param([AllowNull()][object]$Security)

    if ($null -eq $Security) { return $false }
    if (-not $Security.AreAccessRulesProtected) { return $false }

    $sidSystem = 'S-1-5-18'
    $sidAdmins = 'S-1-5-32-544'
    $fc = [System.Security.AccessControl.RegistryRights]::FullControl
    $ci = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $np = [System.Security.AccessControl.PropagationFlags]::None

    $hasSystem = $false
    $hasAdmins = $false
    $ruleCount = 0

    foreach ($rule in $Security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        $ruleCount++
        $sid = $rule.IdentityReference.Value

        if (($sid -cne $sidSystem) -and ($sid -cne $sidAdmins)) { return $false }
        if ($rule.IsInherited) { return $false }
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
        if ($rule.RegistryRights -ne $fc) { return $false }
        if ($rule.InheritanceFlags -ne $ci) { return $false }
        if ($rule.PropagationFlags -ne $np) { return $false }

        if ($sid -ceq $sidSystem) { $hasSystem = $true }
        if ($sid -ceq $sidAdmins) { $hasAdmins = $true }
    }

    return ($hasSystem -and $hasAdmins -and ($ruleCount -eq 2))
}

# Reads a key's ACL the way Test-StrictRegAcl does (ReadPermissions only) and checks it.
function Test-PDStrictKeyAcl {
    param(
        [Parameter(Mandatory = $true)][Microsoft.Win32.RegistryKey]$BaseKey,
        [Parameter(Mandatory = $true)][string]$SubKeyPath
    )

    $subKey = $null
    try {
        $subKey = $BaseKey.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
        if ($null -eq $subKey) { return $false }
        return (Test-PDStrictRegistrySecurity -Security $subKey.GetAccessControl())
    } catch {
        Write-Log "$SubKeyPath : the ACL could not be read ($($_.Exception.GetType().Name)): $($_.Exception.Message)" "WARNING"
        return $false
    } finally {
        if ($subKey) { $subKey.Dispose() }
    }
}

# Creates the key if needed, then makes sure its ACL is strict. Returns $true only when the ACL is
# confirmed strict.
#   - A new key gets the strict ACL at creation, so it is never open, not even briefly, and then the
#     same SetAccessControl call Set-StrictRegAcl makes, so its DACL is byte-for-byte what
#     Set-StrictRegAcl writes (creation alone leaves out the auto-inherited flag: D:P instead of D:PAI).
#   - An existing key: test, set only if needed (opened with ChangePermissions, as Set-StrictRegAcl
#     does), test again.
function Set-PDStrictKey {
    param(
        [Parameter(Mandatory = $true)][Microsoft.Win32.RegistryKey]$BaseKey,
        [Parameter(Mandatory = $true)][string]$SubKeyPath
    )

    $key = $null
    $created = $false
    try {
        # Existence check with the least access (ReadPermissions), so it works on any key whose ACL
        # this script is about to check or fix.
        $key = $BaseKey.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
        if ($null -eq $key) {
            $key = $BaseKey.CreateSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, (New-PDStrictRegistrySecurity))
            if ($null -eq $key) { throw "CreateSubKey returned nothing" }
            $created = $true
            Write-Log "$SubKeyPath : key created"
        } else {
            Write-Log "$SubKeyPath : key already exists"
        }
    } catch {
        Write-Log "$SubKeyPath : the key could not be created or opened ($($_.Exception.GetType().Name)): $($_.Exception.Message)" "ERROR"
        return $false
    } finally {
        if ($key) { $key.Dispose() }
    }

    if ($created) {
        Write-Log "$SubKeyPath : applying the strict ACL to the new key."
    } elseif (Test-PDStrictKeyAcl -BaseKey $BaseKey -SubKeyPath $SubKeyPath) {
        Write-Log "$SubKeyPath : ACL already strict (SYSTEM + Administrators only). No change."
        return $true
    } else {
        Write-Log "$SubKeyPath : ACL not strict. Applying the strict ACL."
    }

    $key = $null
    try {
        $key = $BaseKey.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        if ($null -eq $key) { throw "the key disappeared" }
        $key.SetAccessControl((New-PDStrictRegistrySecurity))
    } catch {
        Write-Log "$SubKeyPath : the strict ACL could not be applied ($($_.Exception.GetType().Name)): $($_.Exception.Message)" "ERROR"
        return $false
    } finally {
        if ($key) { $key.Dispose() }
    }

    if (Test-PDStrictKeyAcl -BaseKey $BaseKey -SubKeyPath $SubKeyPath) {
        Write-Log "$SubKeyPath : ACL set to strict (SYSTEM + Administrators only)." "SUCCESS"
        return $true
    }

    Write-Log "$SubKeyPath : ACL still not strict after applying it." "ERROR"
    return $false
}

# Writes one String value unless it is already exactly right. Returns 'written', 'already correct'
# or 'FAILED'. Only the exception TYPE is logged: nothing about the data is ever printed.
function Set-PDOrgValue {
    param(
        [Parameter(Mandatory = $true)][Microsoft.Win32.RegistryKey]$BaseKey,
        [Parameter(Mandatory = $true)][string]$SubKeyPath,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowEmptyString()][AllowNull()][string]$ExpectedData
    )

    if ($null -eq $ExpectedData) { $ExpectedData = '' }

    $key = $null
    try {
        $key = $BaseKey.OpenSubKey($SubKeyPath, $true)
        if ($null -eq $key) { return 'FAILED' }

        if (@($key.GetValueNames()) -contains $Name) {
            $kind = $key.GetValueKind($Name)
            $CurrentData = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if (($kind -eq [Microsoft.Win32.RegistryValueKind]::String) -and ($CurrentData -is [string]) -and ($CurrentData -ceq $ExpectedData)) {
                return 'already correct'
            }
        }

        $key.SetValue($Name, $ExpectedData, [Microsoft.Win32.RegistryValueKind]::String)
        return 'written'
    } catch {
        Write-Log "$SubKeyPath\$Name : write error ($($_.Exception.GetType().Name))" "ERROR"
        return 'FAILED'
    } finally {
        if ($key) { $key.Dispose() }
    }
}

# Read-back: the value must exist, be a String, and match exactly (case-sensitive; a blank value
# must exist as an empty String, as the Remediation's detect script requires).
function Test-PDOrgValue {
    param(
        [Parameter(Mandatory = $true)][Microsoft.Win32.RegistryKey]$BaseKey,
        [Parameter(Mandatory = $true)][string]$SubKeyPath,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowEmptyString()][AllowNull()][string]$ExpectedData
    )

    if ($null -eq $ExpectedData) { $ExpectedData = '' }

    $key = $null
    try {
        $key = $BaseKey.OpenSubKey($SubKeyPath, $false)
        if ($null -eq $key) { return $false }
        if (-not (@($key.GetValueNames()) -contains $Name)) { return $false }
        if ($key.GetValueKind($Name) -ne [Microsoft.Win32.RegistryValueKind]::String) { return $false }
        $ReadData = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        return (($ReadData -is [string]) -and ($ReadData -ceq $ExpectedData))
    } catch {
        Write-Log "$SubKeyPath\$Name : read error ($($_.Exception.GetType().Name))" "ERROR"
        return $false
    } finally {
        if ($key) { $key.Dispose() }
    }
}

##########
## Main ##
##########

Write-Log ""
Write-Log "===== SCRIPT: $ThisFileName | START ====="
Write-Log "Deploy mode: $PDDeployMode | Source commit: $PDSourceCommit"
Write-Log "Target: HKLM\$PDRegistryRoot (64-bit registry view) | 64-bit process: $([Environment]::Is64BitProcess)"
if (-not $script:PDLogWritable) { Write-Log "No log file for this run (no working directory stamped, or it could not be written)." "WARNING" }
Write-Log ""

if ($PDStamped -ne $true) {
    Write-Log "SCRIPT: $ThisFileName | END | This is the unstamped template. Generate the platform script with Setup.ps1 (OrganizationRegistryEntries--InTune-Setup). Nothing was changed." "ERROR"
    Exit 1
}

if (($PDRegistryRoot -isnot [string]) -or ($PDRegistryRoot -cnotmatch $PDAllowedRootPattern)) {
    Write-Log "SCRIPT: $ThisFileName | END | The stamped registry root is not allowed: HKLM\$PDRegistryRoot. Nothing was changed." "ERROR"
    Exit 1
}

$PDEntries = @($PDOrgValues)
if ($PDEntries.Count -eq 0) {
    Write-Log "SCRIPT: $ThisFileName | END | No values were stamped. Nothing was changed." "ERROR"
    Exit 1
}

foreach ($Entry in $PDEntries) {
    if (($PDAllowedSubKeys -cnotcontains $Entry.SubKey) -or [string]::IsNullOrWhiteSpace($Entry.Name)) {
        Write-Log "SCRIPT: $ThisFileName | END | A stamped entry has an unexpected subkey or no name ($($Entry.SubKey)\$($Entry.Name)). Nothing was changed." "ERROR"
        Exit 1
    }
}

# SYSTEM is a member of BUILTIN\Administrators, so this passes for an Intune platform script.
$isAdmin = $false
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $isAdmin = $false
}
if (-not $isAdmin) {
    Write-Log "SCRIPT: $ThisFileName | END | Administrator (or SYSTEM) rights are required to write HKLM. Nothing was changed." "ERROR"
    Exit 1
}

# Root first, so every subkey is created under an already strict parent.
$PDSubKeys = @($PDEntries | ForEach-Object { $_.SubKey } | Select-Object -Unique)
$KeyPaths = @($PDRegistryRoot) + @($PDSubKeys | ForEach-Object { "$PDRegistryRoot\$_" })

$ExitCode = 1
$BaseKey = $null

try {

    $BaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)

    Write-Log "---------------------------------"
    Write-Log "STEP 1: Create keys and apply the strict ACL (before any value is written)"
    Write-Log "---------------------------------"

    $AclOk = $true
    foreach ($KeyPath in $KeyPaths) {
        if (-not (Set-PDStrictKey -BaseKey $BaseKey -SubKeyPath $KeyPath)) {
            $AclOk = $false
            break
        }
    }

    if (-not $AclOk) {
        Write-Log "SCRIPT: $ThisFileName | END | A key could not be locked down to SYSTEM + Administrators. No value was written." "ERROR"
        Exit 1
    }

    Write-Log "---------------------------------"
    Write-Log "STEP 2: Write values"
    Write-Log "---------------------------------"

    $WriteFailures = 0
    foreach ($Entry in $PDEntries) {
        $Status = Set-PDOrgValue -BaseKey $BaseKey -SubKeyPath "$PDRegistryRoot\$($Entry.SubKey)" -Name $Entry.Name -ExpectedData $Entry.Value
        if ($Status -eq 'FAILED') {
            $WriteFailures++
            Write-Log "   $($Entry.SubKey)\$($Entry.Name) : FAILED" "ERROR"
        } else {
            Write-Log "   $($Entry.SubKey)\$($Entry.Name) : $Status"
        }
    }

    Write-Log "---------------------------------"
    Write-Log "STEP 3: Read back"
    Write-Log "---------------------------------"

    $VerifyFailures = 0
    foreach ($Entry in $PDEntries) {
        if (Test-PDOrgValue -BaseKey $BaseKey -SubKeyPath "$PDRegistryRoot\$($Entry.SubKey)" -Name $Entry.Name -ExpectedData $Entry.Value) {
            Write-Log "   $($Entry.SubKey)\$($Entry.Name) : verified"
        } else {
            $VerifyFailures++
            Write-Log "   $($Entry.SubKey)\$($Entry.Name) : FAILED (missing, wrong type, or does not match)" "ERROR"
        }
    }

    # The ACLs once more, after the writes: the exit code covers both.
    $AclFailures = 0
    foreach ($KeyPath in $KeyPaths) {
        if (-not (Test-PDStrictKeyAcl -BaseKey $BaseKey -SubKeyPath $KeyPath)) {
            $AclFailures++
            Write-Log "   $KeyPath : ACL FAILED final check" "ERROR"
        }
    }

    if (($WriteFailures -eq 0) -and ($VerifyFailures -eq 0) -and ($AclFailures -eq 0)) {
        $ValueCount = $PDEntries.Count
        Write-Log "SCRIPT: $ThisFileName | END | All $ValueCount values and $($KeyPaths.Count) key ACLs confirmed." "SUCCESS"
        $ExitCode = 0
    } else {
        Write-Log "SCRIPT: $ThisFileName | END | Not confirmed: $WriteFailures write failure(s), $VerifyFailures read-back failure(s), $AclFailures ACL failure(s)." "ERROR"
        $ExitCode = 1
    }

} catch {

    Write-Log "SCRIPT: $ThisFileName | END | Unexpected error ($($_.Exception.GetType().Name))." "ERROR"
    $ExitCode = 1

} finally {

    if ($BaseKey) { $BaseKey.Dispose() }

}

Exit $ExitCode
