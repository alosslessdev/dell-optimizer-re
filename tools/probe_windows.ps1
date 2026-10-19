<#
Read-only Dell machine probe for the charge-level study.
  powershell -ExecutionPolicy Bypass -File probe_windows.ps1
  powershell -ExecutionPolicy Bypass -File probe_windows.ps1 -DumpSmbios smbios.bin
No settings are changed. Run as Administrator if the SMBIOS dump query is denied.
#>
param(
    [switch]$DumpSmbios,
    [string]$DumpPath = "smbios.bin"
)

$ErrorActionPreference = "SilentlyContinue"
function Section($t) { Write-Host "`n===== $t =====" }

Section "identity"
$cs   = Get-CimInstance Win32_ComputerSystem
$encl = Get-CimInstance Win32_SystemEnclosure
$bios = Get-CimInstance Win32_BIOS
$msi  = Get-CimInstance -Namespace root\wmi -ClassName MS_SystemInformation
"Manufacturer   : {0}" -f $cs.Manufacturer
"Model          : {0}" -f $cs.Model
"ChassisTypes   : {0}" -f (($encl.ChassisTypes | ForEach-Object { "$_ (0x{0:X})" -f $_ }) -join ", ")
"BIOS           : {0}  {1}" -f $bios.SMBIOSBIOSVersion, $bios.ReleaseDate
"MSI Vendor     : {0}" -f $msi.SystemManufacturer
"MSI Product    : {0}" -f $msi.SystemProductName
"MSI SystemSKU  : {0}" -f $msi.SystemSKU

Section "Dell Optimizer install"
$dir = Join-Path $env:ProgramFiles "Dell\DellOptimizer"
"install dir    : {0} ({1})" -f $dir, (Test-Path $dir)
Get-Service | Where-Object { $_.Name -match 'Dell' -or $_.DisplayName -match 'Dell Optimizer' } |
    Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String | Write-Host
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                 "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Where-Object { $_.DisplayName -match 'Dell Optimizer' } |
    Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize | Out-String | Write-Host

Section "batteries"
Get-CimInstance Win32_Battery | Select-Object Name, DeviceID, EstimatedChargeRemaining, BatteryStatus,
    DesignCapacity, FullChargeCapacity, Chemistry | Format-List | Out-String | Write-Host
Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData |
    Select-Object InstanceName, DesignedCapacity, ManufactureName, DeviceName, SerialNumber |
    Format-List | Out-String | Write-Host
Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity |
    Select-Object InstanceName, FullChargedCapacity | Format-List | Out-String | Write-Host
"NOTE: redact SerialNumber before publishing."

Section "gating verdict (Dell Optimizer 6.3.5.0 rules)"
function Verdict([string]$manufacturer, [string]$product, [string]$sku) {
    if ($manufacturer -notmatch 'Dell Inc\.' -and $manufacturer -notmatch 'Dell Technologies Inc\.') {
        return "FAIL: not a Dell system"
    }
    $cy26 = '^(D|DA|DX|C|P|PW|PR|PV|PE)([SAX9753M])?([MRST0-9][0-9])([0-9]{2})([0-9])$'
    $cy25 = '^[CDEPQMFR][ABCEV012789][MRST0-9][0-9]{4}$'
    $ctype = $null; $reason = $null
    foreach ($tok in ($product.ToUpper() -split '\s+')) {
        if ($tok -match $cy26) {
            if ($tok.StartsWith('C') -or ($tok.StartsWith('DA') -and $tok.Length -eq 8)) {
                return "FAIL: unsupported product line ($tok)"
            }
            if ($tok.StartsWith('D')) { $ctype = 'Consumer' } else { $ctype = 'Commercial' }
            $reason = "CY26 model ID $tok"
            break
        }
        if ($tok -match $cy25) {
            if ($tok.StartsWith('C') -or $tok[1] -eq '7' -or $tok[1] -eq '9') {
                return "FAIL: unsupported product line ($tok)"
            }
            if ('CDE'.Contains($tok[0])) { $ctype = 'Consumer' } else { $ctype = 'Commercial' }
            $reason = "CY25 model ID $tok"
            break
        }
    }
    if (-not $ctype) {
        foreach ($fam in 'Inspiron','Vostro','XPS') { if ($product -match $fam) { $ctype='Consumer'; $reason="family $fam"; break } }
    }
    if (-not $ctype) {
        foreach ($fam in 'Precision','Latitude','OptiPlex') { if ($product -match $fam) { $ctype='Commercial'; $reason="family $fam"; break } }
    }
    if (-not $ctype) { return "FAIL: no known product family in '$product'" }

    $gate = @{
        Commercial = @{ allow=@('0971','097E','0738','0739','073A','08B1','0873');
                        block=@('09F1','09F2','0A30','0A31','0A84','0A85'); anysku='0983' }
        Consumer   = @{ allow=@(); block=@('0C52','0B24','0B31','0AF4','0B70','0B25','0B32','0B26','0B33','0BB6'); anysku='0AF3' }
    }
    $g = $gate[$ctype]
    if (-not $sku) { return "UNKNOWN: $ctype ($reason) but no SystemSKU" }
    if ($g.allow -contains $sku) { return "PASS: $ctype SKU $sku explicitly allowed ($reason)" }
    if ($g.block -contains $sku) { return "FAIL: $ctype SKU $sku explicitly blocked ($reason)" }
    try {
        $n = [Convert]::ToInt32($sku, 16); $t = [Convert]::ToInt32($g.anysku, 16)
        if ($n -ge $t) { return "PASS: $ctype SKU 0x{0:X} >= AnySKU 0x{1} ($reason)" -f $n, $g.anysku }
        return "FAIL: $ctype SKU 0x{0:X} < AnySKU 0x{1} ($reason)" -f $n, $g.anysku
    } catch { return "UNKNOWN: unparsable SKU '$sku'" }
}
Verdict $msi.SystemManufacturer $msi.SystemProductName $msi.SystemSKU | Write-Host

if ($DumpSmbios) {
    Section "SMBIOS dump -> $DumpPath"
    $raw = Get-CimInstance -Namespace root\wmi -ClassName MSSmBios_RawSMBiosTables
    if ($raw -and $raw.SMBiosData) {
        [IO.File]::WriteAllBytes((Join-Path (Get-Location) $DumpPath), [byte[]]$raw.SMBiosData)
        "wrote $((Resolve-Path $DumpPath).Path) ($($raw.SMBiosData.Length) bytes)"
        "now run: python tools\parse_smbios_da.py $DumpPath"
    } else { "SMBIOS table unavailable (try Administrator)" }
}

Section "done"
"No settings were modified. Redact service tag/serials before publishing."
