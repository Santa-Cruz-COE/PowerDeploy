<#

INSTRUCTIONS:
To run the script, you'll need to:
- run with administrator privileges 
- run directly on the print server.

This script will:
Get all TCP/IP printers from the print server
Collect detailed information about each printer's port and driver
Export the data to both a CSV file and display it in the console

#>

$ThisFileName = $MyInvocation.MyCommand.Name
$RepoRoot = (Split-Path $PSScriptRoot -Parent)
$WorkingDirectory = (Split-Path $RepoRoot -Parent)

if (!(Test-Path "$WorkingDirectory\TEMP")) {

    $WorkingDirectory = $PSScriptRoot
    
}

$PrintServerName = $ENV:computername
# $alreadyThere = $False


# --- Helpers --------------------------------------------------------------

# Suggest a PresetDriver "code" (the foreign key that links a printer to the
# drivers[] section of the JSON) from a raw driver name. This is only a
# STARTING POINT - review/rename the PresetDriver column in the CSV to match
# your own naming convention before converting to JSON.
function Get-PresetDriverCode {
    param([string]$DriverName)

    if ([string]::IsNullOrWhiteSpace($DriverName)) { return "" }

    # Common vendor prefixes -> your short codes. Extend as needed.
    $vendorMap = @{
        'HP'              = 'HP'
        'Hewlett'         = 'HP'
        'KONICA MINOLTA'  = 'KM'
        'Konica'          = 'KM'
        'Canon'           = 'CANON'
        'Xerox'           = 'XEROX'
        'Ricoh'           = 'RICOH'
        'Brother'         = 'BROTHER'
        'Lexmark'         = 'LEXMARK'
        'Epson'           = 'EPSON'
        'Kyocera'         = 'KYOCERA'
        'Sharp'           = 'SHARP'
        'Toshiba'         = 'TOSHIBA'
    }

    $prefix = $null
    foreach ($key in $vendorMap.Keys) {
        if ($DriverName -match [regex]::Escape($key)) { $prefix = $vendorMap[$key]; break }
    }

    # Build a slug from the whole driver name: keep alphanumerics, collapse the
    # rest into single underscores.
    $slug = ($DriverName -replace '[^A-Za-z0-9]+', '_').Trim('_').ToUpper()

    if ($prefix) {
        # Avoid doubling the prefix if the slug already starts with it.
        if ($slug -notmatch "^$prefix`_") { $slug = "$prefix`_$slug" }
    }

    return "$slug`_WIN_X64"
}

# Zero-pad an IPv4 address to match the "010.009.028.106" PortName style used
# in the JSON template. Returns "" if the input isn't a clean IPv4 address.
function Get-PaddedIP {
    param([string]$IP)

    if ([string]::IsNullOrWhiteSpace($IP)) { return "" }
    $octets = $IP.Trim() -split '\.'
    if ($octets.Count -ne 4) { return $IP }
    try {
        return ($octets | ForEach-Object { '{0:000}' -f [int]$_ }) -join '.'
    } catch {
        return $IP
    }
}


# Start 

#$PrintServerName = Read-host "Enter the print server you wish to connect to"

#$cred = Get-Credential -message "Enter the creds for connecting to PrinterServer: $PrintServerName"

Try {


    # $trustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts | Select-Object -ExpandProperty Value

    # if ($trustedHosts -match $PrintServerName) { 


    #     Write-Host "Looks like the PrintServer is already on your list of trusted hosts, going to skip adding to list"

    #     $alreadyThere = $True

    # } else {

    #     write-Host "PrintServer not found on TrustedHosts list, attempting to add."

    #     winrm set winrm/config/client @{TrustedHosts="$PrintServerName"}
    #     #Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "$PrintServerName" -Concatenate -Force

    # }


    # $cim  = New-CimSession -ComputerName $PrintServerName -Credential $cred

    $printers = Get-Printer #-CimSession $cim

    $ExportPath = "$WorkingDirectory\TEMP\PrintServer_Exports\$PrintServerName.Export.$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if(!(Test-Path $ExportPath)){new-item -ItemType File -Path $ExportPath -Force}

    # Get all printers from print server
    #$printers = Get-Printer -ComputerName "Davinci" #| Where-Object { $_.Type -eq "TCPIPPrinter" }

    # Create empty array to store results
    $results = @()

    foreach ($printer in $printers) {
        # Get printer port information
        $port = Get-PrinterPort -Name $printer.PortName
    
        # Get printer driver information
        $driver = Get-PrinterDriver -Name $printer.DriverName
    
        # Create custom object with required properties.
        #
        # Column notes for the reviewer (before running the converter):
        #   PortName        - ACTIVE column the converter reads. Pre-filled with
        #                     the zero-padded IP style to match the JSON template.
        #                     Edit this if you prefer the server's raw port name.
        #   PortName_Raw    - reference only: the port name as the print server
        #                     reports it. Copy into PortName if you want it.
        #   PortName_Padded - reference only: the zero-padded IP form.
        #   PresetDriver    - SUGGESTED code linking this printer to a driver.
        #                     Rename to match your convention; printers sharing a
        #                     driver should share the same PresetDriver value.
        $paddedIP = Get-PaddedIP -IP $port.PrinterHostAddress
        $printerInfo = [PSCustomObject]@{
            PrinterName     = $printer.Name
            PrinterIP       = $port.PrinterHostAddress
            PortName        = if ($paddedIP) { $paddedIP } else { $printer.PortName }
            PortName_Raw    = $printer.PortName
            PortName_Padded = $paddedIP
            PresetDriver    = Get-PresetDriverCode -DriverName $printer.DriverName
            DriverName      = $printer.DriverName
            INFFile         = $driver.InfPath
        }
    
        # Add to results array
        $results += $printerInfo
    }

    # Export results to CSV file
    $results | Export-Csv -Path "$ExportPath" -NoTypeInformation
    write-Host "Exported results to CSV at $ExportPath"

    # Display results in console
    $results | Format-Table -AutoSize
} Catch {

    Write-Warning "Process failed: $_"

} Finally {

    # Clean up

    # if ($alreadyThere -eq $true){

    #     Write-Host "Attempting to remove the PrintServer from the TrustedHosts list"
    #     $trustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts | Select-Object -ExpandProperty Value
    #     $trustedHosts = $trustedHosts -split ',' | Where-Object { $_ -ne "$PrintServerName" }
    #     Set-Item WSMan:\localhost\Client\TrustedHosts -Value ($trustedHosts -join ',') -Force

    # }

    # Write-Host "Attempting to remove CIM session containing the creds you entered."
    # Remove-CimSession $cim


}



Write-Host "Finished"