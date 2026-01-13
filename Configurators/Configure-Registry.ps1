# Windows Registry modifier

# TODO: Add AlsoLockDown + Read combo functionality - Read the function and verify if it has the desired ACLs


Param(

    [ValidateSet("Backup", "Modify", "Read","Read-All","Lockdown")]
    [string]$Function="Modify", # Backup, Modify, Read, or Read-All

    #[Parameter(Mandatory=$true)]
    [string]$KeyPath,

    #[Parameter(Mandatory=$true)]
    [string]$ValueName, # Change to ValueName
    
    [ValidateSet("String", "DWord", "QWord", "Binary", "MultiString", "ExpandString")]
    [string]$ValueType, # Change to ValueType

    [string]$Value, # Change to ValueData
    
    [Parameter(Mandatory=$true)]
    [string]$WorkingDirectory,

    [string]$KeyOnly = $false, # Used to create an empty key without setting a value


    [string]$ValueNameOnly = $False, # Used to create an empty key without setting a value

    
    $AlsoLockDown = $False # Used for doing lockdown during initial creation of a key

    # [ValidateSet('Auto','Reg32','Reg64')]
    # [string]$RegistryView = 'Auto'

)

$ThisFileName = $MyInvocation.MyCommand.Name
$LogRoot = "$WorkingDirectory\Logs\Config_Logs"

$LogPath = "$LogRoot\$ThisFileName.$Function.$ValueName._Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

$BackupPath = "$WorkingDirectory\temp\Registry_Backups\RegBackup.$ValueName._$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"



#################
### Functions ###
#################

# NOTE: This function will not use write-log.
function Test-PathSyntaxValidity {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Paths,
        [switch]$ExitOnError
    )
    
    # Windows illegal path characters (excluding : for drive letters and \ for path separators)
    $illegalChars = '[<>"|?*]'
    
    # Reserved Windows filenames
    $reservedNames = @(
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    )
    
    $allValid = $true
    $issues = @()
    
    foreach ($paramName in $Paths.Keys) {
        $path = $Paths[$paramName]
        
        # Skip if null or empty
        if ([string]::IsNullOrWhiteSpace($path)) {
            $issues += "Parameter '$paramName' is null or empty"
            $allValid = $false
            continue
        }
        
        # Check for trailing backslash before closing quote pattern (common BAT file issue)
        if ($path -match '\\["\' + "']$") {
            $issues += "Parameter '$paramName' has trailing backslash before quote: '$path' - This will cause escape character issues"
            $allValid = $false
        }
        
        # Check for illegal characters
        if ($path -match $illegalChars) {
            $matches = [regex]::Matches($path, $illegalChars)
            $foundChars = ($matches | ForEach-Object { $_.Value }) -join ', '
            $issues += "Parameter '$paramName' contains illegal characters ($foundChars): '$path'"
            $allValid = $false
        }
        
        # Check for invalid double backslashes (except at start for UNC paths)
        if ($path -match '(?<!^)\\\\') {
            $issues += "Parameter '$paramName' contains double backslashes (not a UNC path): '$path'"
            $allValid = $false
        }
        
        # Check for reserved Windows names in path components
        $pathComponents = $path -split '[\\/]'
        foreach ($component in $pathComponents) {
            $nameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($component)
            if ($nameWithoutExt -in $reservedNames) {
                $issues += "Parameter '$paramName' contains reserved Windows name '$nameWithoutExt': '$path'"
                $allValid = $false
            }
        }
        
        # Check for paths that are too long (MAX_PATH = 260 characters in Windows)
        if ($path.Length -gt 260) {
            $issues += "Parameter '$paramName' exceeds maximum path length (260 characters): '$path' (Length: $($path.Length))"
            $allValid = $false
        }
        
        # Check for invalid drive letter format
        if ($path -match '^[a-zA-Z]:' -and $path -notmatch '^[a-zA-Z]:\\') {
            $issues += "Parameter '$paramName' has invalid drive format (missing backslash after colon): '$path'"
            $allValid = $false
        }
        
        # Check for spaces at beginning or end of path (common copy-paste issue)
        if ($path -ne $path.Trim()) {
            $issues += "Parameter '$paramName' has leading or trailing whitespace: '$path'"
            $allValid = $false
        }
    }
    
    # Report results
    if (-not $allValid) {
        Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX PATH VALIDATION FAILED - Issues detected:"
        foreach ($issue in $issues) {
            Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX - $issue"
        }
        
        if ($ExitOnError) {
            Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Exiting script due to path validation errors"
            Exit 1
        }
    } else {
        Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Path validation successful - all parameters valid"
    }
    
    #return $allValid

}



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
        "DRYRUN"  { Write-Host $logEntry -ForegroundColor Cyan }
        default   { Write-Host $logEntry }
    }
    
    # Ensure log directory exists
    $logDir = Split-Path $LogPath -Parent
    if (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    Add-Content -Path $LogPath -Value $logEntry
}


# ============================================
# REGISTRY OPERATIONS
# ============================================



Function Reg-Read{
    param(

        [string]$registryPath = "$KeyPath",
        [string]$ValueNameToRead = "$ValueName"

    )

    Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"


    # Check if the key exists
    if (Test-Path $registryPath) {


        If($ValueNameToRead -eq "") {
            Write-Log "No ValueName provided to read at key path, BUT the path was found: ($registryPath)"
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"
            Return "Path found only"
        }

        Try {

            $ThisValue = Get-ItemProperty -Path $registryPath -Name $ValueNameToRead -ErrorAction SilentlyContinue
            $ReturnValue = $($ThisValue.$ValueNameToRead)
            Write-Log "Current value: $ReturnValue"
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"

            if ($ReturnValue -eq $null -and -not ($ThisValue.PSObject.Properties.Name -contains $ValueNameToRead)) {
                Write-Log "Key path ($registryPath) exists, but value name at ($ValueNameToRead) does not exist"
                Return "KeyPath exists, but ValueName does not exist"
            }

            # if ($ReturnValue -eq $null) {
            #     Write-Log "Value name at ($ValueNameToRead) at key path ($registryPath) does not contain a value"
            #     Return "Value not found"
            # }

            Return $ReturnValue


        } catch {

            Write-Log "Could not read key: ($ValueNameToRead) at key path: ($registryPath)"
            Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"

            Return "KeyPath exists, but could not read value"

        }


    } else {

        Write-Log "KeyPath does not exist: $registryPath"
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"
        Return "KeyPath does not exist"

    }

}


Function Reg-Backup {

    Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"

    # Ensure backup directory exists
    $backupDir = Split-Path -Parent $BackupPath
    Write-Log "Checking if backup file directory exists at $backupDir..."
    if (-not (Test-Path $backupDir)) { Write-Log "Directory not found. Creating..."; New-Item -ItemType Directory -Path $backupDir -Force | Out-Null } else {Write-Log "Path exists."}


    Write-Log "Backing registry value $KeyPath to $backupPath"
    Try {

            # Map of full hive names to abbreviations to fix for reg backups
            # $hiveMap = @{
            #     'HKLM:' = 'HKLM'
            #     'HKCU:' = 'HKCU'
            #     'HKU:'  = 'HKU'
            #     'HKCR:' = 'HKCR'
            #     'HKCC:' = 'HKCC'
            # }

            # $output = $KeyPath

            # foreach ($fullName in $hiveMap.Keys) {
            #     # Case-insensitive replacement of the full hive with its abbreviation
            #     $pattern = [regex]::Escape($fullName)
            #     $output  = $output -replace $pattern, $hiveMap[$fullName]
            # }


            # Convert HK??:\… -> HK??\… for reg.exe

        $RegExePath = $KeyPath `
        -replace '^HKLM:\\', 'HKLM\' `
        -replace '^HKCU:\\', 'HKCU\' `
        -replace '^HKCR:\\', 'HKCR\' `
        -replace '^HKU:\\',  'HKU\'  `
        -replace '^HKCC:\\', 'HKCC\'

        #$backupPath = "$env:TEMP\registry-backup.reg"

        # Run export with proper quoting; optionally pick registry view
        $RegViewSwitch = if ($env:PROCESSOR_ARCHITECTURE -eq 'x86') { '/reg:32' } else { '/reg:64' }
        $result = & reg.exe export "$RegExePath" "$BackupPath" /y $RegViewSwitch


        # $result = reg export "$output" $backupPath /y

        foreach ($line in $result){Write-Log "reg export: $_"}
        Write-Log "Registry backed up to: $backupPath"


        Write-Log "Checking if backup was successful..."

        if ((Test-Path $backupPath) -and ((Get-Item $backupPath).Length -gt 0)) {

            Write-Log "Backup file created successfully"
            Return $True

        } else {

            Throw "Backup file empty or nonexistant"

        }


    } catch {

        Write-Log "Could not do backup. Error code/message: $_"
        Exit 1

    }

}


function Reg-Modify {

    Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"

    Write-Log "Attempting to modify key"

    try {

        # Create the key if it doesn't exist

        Write-Log "Checking if key [$key] exists at: $KeyPath"

        if (-not (Test-Path $KeyPath)) {
            Write-Log "Key does not exist. Attempting to create."
            New-Item -Path $KeyPath -Force | Out-Null
            Write-Log "Key created."

            if ($AlsoLockDown -eq $True) {

                Write-Log "Lockdown of key requested"

                Reg-Lockdown

                Write-Log "Lockdown of key complete."


            }

        } else {
            Write-Log "Key already exists."
        }
        Write-Log ""
        Write-Log "KeyOnly: $KeyOnly"
        Write-Log ""

        if ($KeyOnly -eq $false) {

            # Set the value
            Write-Log "Attempting to set the following:"
            Write-Log "KeyPath: $KeyPath"
            Write-Log "ValueName: $ValueName"
            Write-Log "Value: $Value"       
            Write-Log "Type: $ValueType"

            Set-ItemProperty -Path $KeyPath -Name $ValueName -Value $Value -Type $ValueType

            Write-Log "Successfully set $ValueName in $KeyPath" "SUCCESS"

        } 

        Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"

        return $true
    }
    catch {
        Write-Log "Error: $($_.Exception.Message)" "ERROR"
        Write-Log "Function: $($MyInvocation.MyCommand.Name) | End"

        return $false
    }
}

function Reg-Read-All {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    # Example of use from another script:
    <#
    Write-Host "Requesting read of all registry values under: $RegistryRoot`n"
    $RegData = & $RegEditScriptPath `
        -Function "Read-All" `
        -WorkingDirectory $WorkingDirectory `
        -KeyPath $RegistryRoot

    Write-Host "`nTesting access to specific registry values:"

    $RegData["HKLM:\Software\PowerDeploy-Test\Applications"]["ApplicationContainerSASkey"]
    #>

    Function AddValues-To-Hash{

        Param(

            [Parameter(Mandatory)]
            [string]$Key

        )

        $ConvertedKey = Convert-RegistryRootToAbbrev -InputString $Key
        Write-Log "SCRIPT: $ThisFileName | Function: $($MyInvocation.MyCommand.Name) | Converted Key: $ConvertedKey"

        # Resolve the key
        Write-Log "SCRIPT: $ThisFileName | Function: $($MyInvocation.MyCommand.Name) | Reading values for key: $ConvertedKey"

            try {

                if(!(Test-Path $ConvertedKey)) {
                    Write-Log "SCRIPT: $ThisFileName | Function: $($MyInvocation.MyCommand.Name) | Key does not exist: $ConvertedKey" "WARNING"
                    #return
                }
                      
                $ConvertedKeyObj = Get-Item -LiteralPath $ConvertedKey -ErrorAction SilentlyContinue
                
                if (-not $ConvertedKeyObj) {
                    Write-Log "Get-Item returned `$null for path: $ConvertedKey" "WARNING"
                    Write-Log "$ConvertedKeyObj"
                    return
                }

                $valueNames = $ConvertedKeyObj.GetValueNames()
                #$valueNames = Get-ItemProperty -LiteralPath $ConvertedKey -ErrorAction SilentlyContinue
                Write-Log "SCRIPT: $ThisFileName | Function: $($MyInvocation.MyCommand.Name) | Retrieved value names:"
                foreach( $vn in $valueNames) {
                    Write-Log " - $vn"
                }
            }
            catch {
                # Some keys are protected / weird, just skip them
                Write-Log "SCRIPT: $ThisFileName | Function: $($MyInvocation.MyCommand.Name) | Values not found for key: $ConvertedKey. Continuing anyways." "WARNING"
                continue
            }

            if (-not $valueNames -or $valueNames.Count -eq 0) {
                Write-Log "SCRIPT: $ThisFileName | Function: $($MyInvocation.MyCommand.Name) | Result: No values found for key: $ConvertedKey. Continuing anyways." #"WARNING"
                
            }


            $keyTable = @{}

            foreach ($name in $valueNames) {
                #$value = $key.GetValue($name)
                $value = $ConvertedKeyObj.GetValue($name)

                $keyTable[$name] = $value
            }

            if ($keyTable.Count -eq 0) { continue }

            # Convert .Name (e.g. 'HKEY_LOCAL_MACHINE\SOFTWARE\PowerDeploy')
            # into a friendly PS-style path (HKLM:\SOFTWARE\PowerDeploy)
            #$rawName = $ConvertedKeyObj.Name
            $psPath  = switch -Regex ($rawName) {
                '^HKEY_LOCAL_MACHINE\\(.*)'    { "HKLM:\$($Matches[1])"; break }
                '^HKEY_CURRENT_USER\\(.*)'     { "HKCU:\$($Matches[1])"; break }
                '^HKEY_CLASSES_ROOT\\(.*)'     { "HKCR:\$($Matches[1])"; break }
                '^HKEY_USERS\\(.*)'            { "HKU:\$($Matches[1])"; break }
                '^HKEY_CURRENT_CONFIG\\(.*)'   { "HKCC:\$($Matches[1])"; break }
                #default                        { $rawName }
                default                        { $ConvertedKey }
            }


            Write-Log "SCRIPT: $ThisFileName | Function: $($MyInvocation.MyCommand.Name) | Adding ValueName/Values to hashtable"

            # Normalize backslashes after the drive
            $psPath = $psPath -replace '\\', '\'

            $SCRIPT:result[$psPath] = $keyTable



    }

    Write-Log "SCRIPT: $ThisFileName | Function: $($MyInvocation.MyCommand.Name) | Attempting Read-All on path: $Path"
    # Master hashtable:
    #   Key   = registry key path (HKLM:\Software\...)
    #   Value = hashtable of value-name/value-data for that key
    $SCRIPT:result = @{}

    #$KeyPathsToCheck = @()
    #$KeyPathsToCheck += $Path

    $KeyPathsToCheck = [System.Collections.Generic.Queue[string]]::new()
    $KeyPathsToCheck.Enqueue($Path)

    while ($KeyPathsToCheck.Count -gt 0) {

        $KeyPath = $KeyPathsToCheck.Dequeue()

        Write-Log "SCRIPT: $ThisFileName | Function: $($MyInvocation.MyCommand.Name) | Reading values for key: $KeyPath"



        # Enqueue children
        $children = Get-ChildItem -LiteralPath $KeyPath -ErrorAction SilentlyContinue

        # If you want that “Found X children” log:
        if ($children) {
            Write-Log "SCRIPT: $ThisFileName | Function: $($MyInvocation.MyCommand.Name) | Found $($children.Count) child keys under: $KeyPath"
        }

        foreach ($child in $children) {

            $ChildName = $child.Name
            # .Name looks like "HKEY_LOCAL_MACHINE\Software\PowerDeploy\Printers"
            $KeyPathsToCheck.Enqueue($ChildName)

            Write-Log "   $ChildName"
        }



        # Process this key
        # Write-Log "Reading values for key: $KeyPath"
        AddValues-To-Hash -Key $KeyPath

        Write-log "SCRIPT: $ThisFileName | Function: $($MyInvocation.MyCommand.Name) | Keys remaining to process: $($KeyPathsToCheck.Count)"
    }

    return $SCRIPT:result

}

function Reg-LockdownOld{

    # NOTE: THIS IS UNTESTED

    Try {

        # Set ACL on a specific registry key to restrict access

        # 1. Registry key you want to protect
        $regPath = $KeyPath

        # 2. Get current ACL
        $acl = Get-Acl -Path $KeyPath

        # 3. Build identities for Administrators and SYSTEM
        $admins = New-Object System.Security.Principal.NTAccount('BUILTIN', 'Administrators')
        $system = New-Object System.Security.Principal.NTAccount('NT AUTHORITY', 'SYSTEM')

        # 4. Stop inheriting permissions from parent and remove existing inherited rules
        #    First bool: protect from inheritance
        #    Second bool: keep inherited rules (we set to $false to drop them)
        $acl.SetAccessRuleProtection($true, $false)

        # 5. Remove any existing explicit access rules
        $acl.Access | ForEach-Object {
            $acl.RemoveAccessRule($_) | Out-Null
        }

        # 6. Create new access rules – only Admins and SYSTEM get FullControl
        $ruleAdmins = New-Object System.Security.AccessControl.RegistryAccessRule(
            $admins,
            'FullControl',
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $ruleSystem = New-Object System.Security.AccessControl.RegistryAccessRule(
            $system,
            'FullControl',
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $acl.AddAccessRule($ruleAdmins)
        $acl.AddAccessRule($ruleSystem)

        # 7. Apply the new ACL
        Set-Acl -Path $regPath -AclObject $acl

        Write-Log "SCRIPT: $ThisFileName | Permissions updated. Only Administrators and SYSTEM can access $regPath"
        
    } Catch {

        Write-Log "SCRIPT: $ThisFileName | ERROR updating permissions on $regPath : $_" "ERROR"
        Exit 1

    }
}

Function Reg-Lockdown{

    function Get-RegistryKeyWithView {
        # param(
        #     [Parameter(Mandatory)]
        #     [string]$KeyPath
        # )
        
        # Parse the path - expects format like HKLM:\SOFTWARE\PowerDeploy # TODO: Replace this part with common function
        if ($KeyPath -match '^(HKLM|HKEY_LOCAL_MACHINE):\\?(.+)$') { 
            $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
            $subKeyPath = $Matches[2]
        }
        elseif ($KeyPath -match '^(HKCU|HKEY_CURRENT_USER):\\?(.+)$') {
            $hive = [Microsoft.Win32.RegistryHive]::CurrentUser
            $subKeyPath = $Matches[2]
        }
        else {
            throw "Unsupported registry path format: $KeyPath"
        }
        
        # Always use 64-bit registry view
        $regView = [Microsoft.Win32.RegistryView]::Registry64
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $regView)
        
        return @{
            BaseKey = $baseKey
            SubKeyPath = $subKeyPath
        }

    }

    function Set-StrictRegAcl {

    #     param(
    #         [Parameter(Mandatory)]
    #         [string]$KeyPath
    #     )

        # if (-not (Test-RegistryKeyExists -KeyPath $KeyPath)) {
        #     Write-Log "Registry key not found: $KeyPath" "WARNING"
        #     return
        # }

        try {

            $parsed = Get-RegistryKeyWithView -KeyPath $KeyPath
            $subKey = $parsed.BaseKey.OpenSubKey($parsed.SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
            
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

            $subKey.SetAccessControl($regSec)
            
            $subKey.Dispose()
            $parsed.BaseKey.Dispose()
            
            Write-Log "[$KeyPath] registry ACL reset to SYSTEM + Administrators only." "SUCCESS"

        }
        catch {

            Write-Log "Failed to set registry ACL: $($_.Exception.Message)" "ERROR"
            throw

        }
    }

    function Test-StrictRegAcl {

        # param(
        #     [Parameter(Mandatory)]
        #     [string]$KeyPath
        # )

        # if (-not (Test-RegistryKeyExists -KeyPath $KeyPath)) {
        #     Write-Log "Registry key not found: $KeyPath" "WARNING"
        #     return $false
        # }

        try {
            $parsed = Get-RegistryKeyWithView -KeyPath $KeyPath
            $subKey = $parsed.BaseKey.OpenSubKey($parsed.SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
            $acl = $subKey.GetAccessControl()
            
            $subKey.Dispose()
            $parsed.BaseKey.Dispose()
        }
        catch {
            Write-Log "Failed to get registry ACL: $($_.Exception.Message)" "ERROR"
            return $false
        }

        $sidSystem = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-18"
        $sidAdmins = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-32-544"
        $allowedSids = @($sidSystem.Value, $sidAdmins.Value)

        if (-not $acl.AreAccessRulesProtected) {
            Write-Log "DIAG: Registry ACL inheritance is NOT protected" "WARNING"
            return $false
        }

        $hasSystem = $false
        $hasAdmins = $false

        $fc = [System.Security.AccessControl.RegistryRights]::FullControl
        $ci = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit

        foreach ($rule in $acl.Access) {
            try {
                $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            }
            catch {
                Write-Log "DIAG: Failed to translate SID: $($rule.IdentityReference)" "WARNING"
                return $false
            }

            if ($sid -notin $allowedSids) { 
                Write-Log "DIAG: Unexpected SID in registry ACL: $sid" "WARNING"
                return $false 
            }

            if ($rule.AccessControlType -ne 'Allow') { return $false }
            if (($rule.RegistryRights -band $fc) -ne $fc) { return $false }

            if (($rule.InheritanceFlags -band $ci) -eq 0) {
                return $false
            }

            if ($sid -eq $sidSystem.Value) { $hasSystem = $true }
            if ($sid -eq $sidAdmins.Value) { $hasAdmins = $true }
        }

        #return ($hasSystem -and $hasAdmins)

        if ($hasSystem -and $hasAdmins) {
            Write-Log "[$KeyPath] registry ACL verified as SYSTEM + Administrators only." "SUCCESS"
            return $true
        } else {
            Write-Log "[$KeyPath] registry ACL verification failed: Missing SYSTEM or Administrators." "ERROR"
            return $false
        }

    }

    #############
    # Mini Main # 
    #############
    
    Write-Log "Function: $($MyInvocation.MyCommand.Name) | Begin"

    if (Test-StrictRegAcl -KeyPath $KeyPath) {

        Write-Log "Registry ACL already strict. No changes made."

    } else {

        Write-Log "Registry ACL not strict. Backing up before modification."

        Reg-Backup

        Write-Log "Applying strict ACL."

        Set-StrictRegAcl

        Write-Log "Re-testing registry ACL after modification."

        if (Test-StrictRegAcl) {

            Write-Log "Function: $($MyInvocation.MyCommand.Name) | End | Registry ACL successfully set to strict."

        } else {

            Write-Log "Function: $($MyInvocation.MyCommand.Name) | End | Failed to set registry ACL to strict." "ERROR"

            Exit 1

        }
    }

}

function Convert-RegistryRootToAbbrev {
    param(
        [Parameter(Mandatory)]
        [string]$InputString
    )

    # Map of full hive names to abbreviations
    $hiveMap = @{
        'HKEY_LOCAL_MACHINE' = 'HKLM:'
        'HKEY_CURRENT_USER'  = 'HKCU:'
        'HKEY_USERS'         = 'HKU:'
        'HKEY_CLASSES_ROOT'  = 'HKCR:'
        'HKEY_CURRENT_CONFIG'= 'HKCC:'
    }

    $output = $InputString

    foreach ($fullName in $hiveMap.Keys) {
        # Case-insensitive replacement of the full hive with its abbreviation
        $pattern = [regex]::Escape($fullName)
        $output  = $output -replace $pattern, $hiveMap[$fullName]
    }

    return $output
}


# ============================================
# COMMON REGISTRY PATHS
# ============================================

<#
HKEY_CLASSES_ROOT (HKCR:)  - File associations and COM registrations
HKEY_CURRENT_USER (HKCU:)  - Current user settings
HKEY_LOCAL_MACHINE (HKLM:) - System-wide settings (requires admin)
HKEY_USERS (HKU:)          - All user profiles
HKEY_CURRENT_CONFIG (HKCC:)- Hardware profile information

Common paths:
- HKCU:\Software - User application settings
- HKLM:\Software - System-wide application settings
- HKCU:\Control Panel - User control panel settings
- HKLM:\System\CurrentControlSet\Services - Windows services
- HKCU:\Environment - User environment variables
- HKLM:\System\CurrentControlSet\Control - System control settings
#>


##########
## MAIN ##
##########

## Pre-Check
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX PRE-CHECK for SCRIPT: $ThisFileName"
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX NOTE: PRE-CHECK is not logged"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX ERROR: Administrator privileges required for registry modifications" -ForegroundColor Red
    Exit 1
}
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Administrator check: PASSED"


Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Checking if supplied paths have valid syntax"

# Test the paths syntax
$KeyPathsToValidate = @{
    'WorkingDirectory' = $WorkingDirectory
    'LogRoot' = $LogRoot
    'LogPath' = $LogPath
    'BackupPath' = $BackupPath
}
Test-PathSyntaxValidity -Paths $KeyPathsToValidate -ExitOnError

# Test the paths existance
Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Checking if supplied paths exist"
$KeyPathsToTest = @{
    'WorkingDirectory' = $WorkingDirectory
}
Foreach ($KeyPathToTest in $KeyPathsToTest.keys){ 

    $TargetPath = $KeyPathsToTest[$KeyPathToTest]

    if((test-path $TargetPath) -eq $false){
        Write-Host "ERROR: Required path $KeyPathToTest does not exist at $TargetPath" -ForegroundColor Red
        Exit 1
    }

}

Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Checking if supplied ValueType is valid format"
Try {

    switch ($ValueType) {
    'DWord'    { if ($Value -notmatch '^\d+$') { Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Value must be an integer for DWord. Attempting to convert." -ForegroundColor Yellow}; $Value = [int]$Value }
    'QWord'    { if ($Value -notmatch '^\d+$') { Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Value must be an integer for QWord. Attempting to convert." -ForegroundColor Yellow}; $Value = [long]$Value }
    'MultiString' { if (-not ($Value -is [string[]])) { $Value = @($Value -split ';') } }
    'Binary'   { if (-not ($Value -is [byte[]])) { throw "Provide a byte[] for Binary" } }
    }
    Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Check complete."

} catch {

    Write-Host "ERROR: Issue with ValueType: $_" -ForegroundColor Red
    Exit 1

}

# Can use this in the future for forcing to run 64-bit
# if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
#     # Relaunch in 64-bit PowerShell
#     $sysnativePs = "$env:WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
#     & $sysnativePs -ExecutionPolicy Bypass -File $PSCommandPath @args
#     exit $LASTEXITCODE
# }


Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXX Path validation successful - all exist"

# Replace reg loc with appropriate abbreviation
$KeyPath = Convert-RegistryRootToAbbrev -InputString $KeyPath

Write-Host "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
Write-Log "===== Registry Configurator ====="
Write-Log "Function: $Function"
Write-Log "Targetted registry key:"
Write-Log "  KeyPath: $KeyPath"
Write-Log "  ValueName: $ValueName"
Write-Log "  Value: $Value"       
Write-Log "  Type: $ValueType"
Write-Log "  KeyOnly: $KeyOnly"
Write-log "================================="

Write-Log "SCRIPT: $ThisFileName | START "



# addition checks that should be logged

if ($KeyPath -notmatch '^HK(LM|CU|CR|U|CC):\\') {
    Write-Log "SCRIPT: $ThisFileName | END | KeyPath must start with registry hive (HKLM:\, HKCU:\, etc.)" "ERROR"
    Exit 1
}

if ($function -ne "Read-All" -and [string]::IsNullOrWhiteSpace($KeyPath)) {
    Write-Log "SCRIPT: $ThisFileName | END | ValueName and KeyPath parameter is required unless Function is 'Read-All'" "ERROR"
    Exit 1
}

if ($Function -eq "Modify" -and $KeyOnly -eq $false -and $ValueNameOnly -eq $false) {
    if ([string]::IsNullOrWhiteSpace($Value)) {
        Write-Log "SCRIPT: $ThisFileName | END | Value parameter is required when Function is 'Modify' and KeyOnly is false and ValueNameOnly is false" "ERROR"
        Exit 1
    }
    if ([string]::IsNullOrWhiteSpace($ValueType)) {
        Write-Log "SCRIPT: $ThisFileName | END | ValueType parameter is required when Function is 'Modify' and KeyOnly is false" "ERROR"
        Exit 1
    }
}
# 



# Do a read (check)
Write-Log "---------------------------------"
Write-Log "SCRIPT: $ThisFileName | STEP 1: Read Registry Key"
Write-Log "---------------------------------"

$ReturnValue = Reg-Read
$NoFoundValue = $False

if ($ReturnValue -eq "KeyPath exists, but could not read value" -or $ReturnValue -eq "KeyPath does not exist") {

    Write-Log "SCRIPT: $ThisFileName | No returnable value at ($KeyPath\$ValueName): $ReturnValue" "WARNING"
    $NoFoundValue = $True

} elseif ($ReturnValue -eq "Value not found") {

    Write-Log "SCRIPT: $ThisFileName | The path and value name were found, but there is no value."


} else {

    Write-Log "SCRIPT: $ThisFileName | Current value of ($KeyPath\$ValueName) is: $ReturnValue"

}

#Write-Log "SCRIPT: $ThisFileName | "

if ($function -eq "Read"){

    Write-Log "SCRIPT: $ThisFileName | END | Returning ""$ReturnValue"" to runner."
    return $Returnvalue
    
}

if ($function -eq "Read-All"){

    Write-Log "SCRIPT: $ThisFileName | Read-All function selected. Reading entire registry tree at $KeyPath"

    $RegData = Reg-Read-All -Path $KeyPath

    Write-Log "SCRIPT: $ThisFileName | Registry tree read complete. Here are the found results:"

    # Check first if data is empty or invalid
    if((!$RegData) -or ($RegData.Count -eq 0)) {
        Write-Log "SCRIPT: $ThisFileName | END | No data returned from registry read!" "ERROR"
        return $null
    }

    $regData.GetEnumerator() | ForEach-Object {
        $keyPath = $_.Key
        $values  = $_.Value  # this is a hashtable

        Write-log "[$keyPath]"
        $values.GetEnumerator() | ForEach-Object {
            Write-Host "  $($_.Key) = $($_.Value)"
        }
    }

    Write-Log "SCRIPT: $ThisFileName | END | Returning registry tree hashtable to runner." "SUCCESS"

    Return $RegData

}

Write-Log "---------------------------------"

If ($function -eq "Lockdown"){

    Write-Log "SCRIPT: $ThisFileName | STEP 2: Lockdown Registry Key"
    Write-Log "---------------------------------"

    Reg-Lockdown

    Write-Log "SCRIPT: $ThisFileName | END | Lockdown complete" "SUCCESS"
    Exit 0

}

if ($function -eq "Modify" -or $function -eq "Backup"){

    # Do a backup 
    Write-Log "---------------------------------"
    Write-Log "SCRIPT: $ThisFileName | STEP 2: Backup Registry Key"
    Write-Log "---------------------------------"
    if($function -eq "Backup" -and $NoFoundValue -eq $True){

        Write-Log "SCRIPT: $ThisFileName | There was no found local value, so backup is being skipped." "WARNING"

    } elseif ($function -eq "Backup") {

        Reg-Backup

    } else {

        Write-Log "SCRIPT: $ThisFileName | Checking if backup is needed before modification..."
    }

    Write-Log "---------------------------------"


    if ($function -eq "Modify"){

        if($ReturnValue -eq $Value){

            Write-Log "SCRIPT: $ThisFileName | END | Local registry key's value is already as desired. Skipping backup too." "SUCCESS"
            Exit 0

        } elseif($ReturnValue -eq "Path found only" -and $KeyOnly -eq $true){

            Write-Log "SCRIPT: $ThisFileName | END | Local registry key's path already exists as desired." "SUCCESS"
            Exit 0

        } else {

            Write-Log "SCRIPT: $ThisFileName | Local registry key's value is not as desired. Will backup first." 
            
            if($NoFoundValue -eq $True){

                Write-Log "SCRIPT: $ThisFileName | There was no found local value, so backup is being skipped." "WARNING"

            } else {

                Reg-Backup

            }

            Write-Log "SCRIPT: $ThisFileName | Now attempting modification of registry"

            # Do a modification
            Write-Log "---------------------------------"

            Write-Log "SCRIPT: $ThisFileName | STEP 3: Modify Local Registry Key"

            Write-Log "---------------------------------"

            Reg-Modify 

            Write-Log "---------------------------------"


            # Do a final read

            Write-Log "---------------------------------"
            Write-Log "SCRIPT: $ThisFileName | STEP 4: Final Check of Local Registry Key"
            Write-Log "---------------------------------"


            $FinalValue = Reg-Read

            Write-Log "---------------------------------"


            Write-Log "SCRIPT: $ThisFileName | Final local value of key $ValueName : $FinalValue"

            if($FinalValue -eq $Value){

                Write-Log "SCRIPT: $ThisFileName | END | Confirmed local registry value is now as desired." "SUCCESS"
                Exit 0

            }elseif ($FinalValue -eq "Path found only" -and $KeyOnly -eq $true){

                Write-Log "SCRIPT: $ThisFileName | END | Confirmed local registry key path exists as desired." "SUCCESS"
                Exit 0

            }else{

                Write-Log "SCRIPT: $ThisFileName | END | Local registry value still not as expected." "ERROR"
                Exit 1

            }


        }

    } else {

        Write-Log "SCRIPT: $ThisFileName | END | Backup complete" "SUCCESS"
        Exit 0

    }

}

