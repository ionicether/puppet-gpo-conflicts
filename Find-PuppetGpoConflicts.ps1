#Requires -Version 5.1+
#Requires -RunAsAdministrator
<#
Author  : ionicether
Version : v.0.8.0
Date    : August 10th, 2026

.SYNOPSIS
Finds settings managed by both Puppet and Group Policy on this server.

.DESCRIPTION
Reads the agent's cached catalog and the computer RSoP data (the same data gpresult shows),
then lists every setting both of them touch. Exits 1 if it finds any.

Advanced audit is read from gpresult, and on the Puppet side from the CSV a dsc_auditpolicycsv
resource applies. It also flags old-style audit settings from Puppet that advanced audit overrides.
Not covered: Group Policy Preferences.

.PARAMETER CatalogPath
Catalog JSON to read. Defaults to the agent's cached catalog.

.PARAMETER CsvPath
Also write the results to this CSV file.

.PARAMETER Puppet
Puppet command to call, if puppet isn't on PATH.

.PARAMETER PassThru
Output result objects instead of a table.

.EXAMPLE
.\Find-PuppetGpoConflicts.ps1

.EXAMPLE
.\Find-PuppetGpoConflicts.ps1 -CsvPath C:\temp\conflicts.csv

.EXAMPLE
.\Find-PuppetGpoConflicts.ps1 -PassThru | Where-Object Agrees -eq $false
#>
param(
    [string]$CatalogPath,
    [string]$CsvPath,
    [string]$Puppet = 'puppet',
    [switch]$PassThru
)

$rsop = 'root\rsop\computer'

function Get-AgentSetting([string]$Name) {
    "$(& $Puppet config print $Name --section agent | Select-Object -Last 1)".Trim()
}

function Get-RegId([string]$Key, [string]$Name) {
    $Key = $Key -replace '^32:(HKLM|HKEY_LOCAL_MACHINE):?\\SOFTWARE\\', 'HKLM\SOFTWARE\WOW6432Node\'
    if ($Key -match '^32:') { return $null }
    $Key = $Key -replace '^(HKEY_LOCAL_MACHINE|HKLM:?|MACHINE)\\', 'HKLM\'
    if ($Key -notmatch '^HK') { $Key = "HKLM\$Key" }
    "reg:$($Key.TrimEnd('\'))|$Name"
}

function Split-RegPath([string]$Path) {
    # \\ splits key from value name when the name has a \ in it
    $i = $Path.IndexOf('\\')
    if ($i -gt 0) { return Get-RegId $Path.Substring(0, $i) $Path.Substring($i + 2) }
    $i = $Path.LastIndexOf('\')
    if ($i -lt 1) { return $null }
    Get-RegId $Path.Substring(0, $i) $Path.Substring($i + 1)
}

function Format-RegData($Data, [string]$Type) {
    switch ($Type) {
        'binary' { return ((@($Data) -join ' ') -replace '\b0x' -replace '[^0-9a-f]').ToLower() }
        { $_ -in 'dword', 'qword' } {
            $text = "$(@($Data)[0])".Trim()
            if ($text -match '^0x([0-9a-f]{1,16})$') { return [Convert]::ToUInt64($Matches[1], 16) }
            # DSC writes DWORDs as signed ints
            if ($Type -eq 'dword' -and $text -match '^-\d+$') { return [int64]$text + 4294967296 }
            return $text
        }
    }
    @($Data) -join ','
}

function ConvertTo-SidList([string]$List) {
    $sids = foreach ($account in $List -split ',') {
        $account = $account.Trim().TrimStart('*')
        if (-not $account) { continue }
        if ($account -match '^S-1-') { $account; continue }
        try { ([Security.Principal.NTAccount]$account).Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { $account.ToLower() }
    }
    (@($sids) | Sort-Object -Unique) -join ','
}

function Get-Comparable([string]$Id, [string]$Value) {
    $v = $Value.Trim()
    if ($Id -like 'right:*') { return ConvertTo-SidList ($v -replace '^set:') }
    if ($Id -like 'audit:*') {
        return ((($v -replace 'no auditing') -split '\s*,\s*' | Where-Object { $_ } | Sort-Object) -join ',').ToLower()
    }
    if ($v -in 'true', 'enabled') { return '1' }
    if ($v -in 'false', 'disabled') { return '0' }
    $v.ToLower()
}

function Get-DslAttr([string]$Body, [string]$Attr) {
    $m = [regex]::Match($Body, "(?m)^\s*$Attr\s*=>\s*'((?:[^'\\]|\\.)*)'")
    $m.Groups[1].Value -replace '\\(.)', '$1'
}

if (-not $CatalogPath) {
    $format = Get-AgentSetting catalog_cache_format
    if ($format -and $format -ne 'json') { throw "catalog_cache_format is '$format'. This only reads json." }
    $CatalogPath = Join-Path (Get-AgentSetting client_datadir) "catalog\$(Get-AgentSetting certname).json"
}
if (-not (Test-Path -LiteralPath $CatalogPath)) { throw "No cached catalog at $CatalogPath. Run the agent first." }
$catalog = Get-Content -LiteralPath $CatalogPath -Raw -Encoding UTF8 | ConvertFrom-Json
Write-Host ("Catalog {0}, cached {1}. Noop runs don't refresh it." -f $catalog.version, (Get-Item -LiteralPath $CatalogPath).LastWriteTime)

# --- GPO side ---

function Get-Winning([string]$Class) {
    Get-CimInstance -Namespace $rsop -ClassName $Class -Filter 'precedence = 1'
}

$gpoName = @{}
Get-CimInstance -Namespace $rsop -ClassName RSOP_GPO | ForEach-Object { $gpoName[$_.id] = $_.name }
if (-not $gpoName.Count) {
    throw "No RSoP data found. Run gpupdate /force, and check RSoP logging isn't turned off."
}

$gp = @{}
function Add-Gp([string]$Id, $Value, [string]$GpoId) {
    if (-not $Id) { return }
    $gpo = $gpoName[$GpoId]
    if (-not $gpo) { $gpo = $GpoId }
    $gp[$Id] = [pscustomobject]@{ Value = "$Value"; Gpo = $gpo }
}

# Admin templates
foreach ($s in Get-Winning RSOP_RegistryPolicySetting) {
    $valueName = "$($s.valueName)"
    $bytes = if ($s.value) { [byte[]]$s.value } else { [byte[]]@() }
    if ($valueName.StartsWith('**del.', [StringComparison]::OrdinalIgnoreCase)) {
        Add-Gp (Get-RegId $s.registryKey $valueName.Substring(6)) '<absent>' $s.GPOID
        continue
    }
    if ($valueName.StartsWith('**') -or -not ($valueName -or $bytes.Count)) { continue }

    $value = switch ($s.valueType) {
        4  { if ($bytes.Count -ge 4) { [BitConverter]::ToUInt32($bytes, 0) } }
        11 { if ($bytes.Count -ge 8) { [BitConverter]::ToUInt64($bytes, 0) } }
        { $_ -in 1, 2 } { [Text.Encoding]::Unicode.GetString($bytes).TrimEnd([char]0) }
        7  { ([Text.Encoding]::Unicode.GetString($bytes).TrimEnd([char]0) -split "`0") -join ',' }
        default { ($bytes | ForEach-Object { $_.ToString('x2') }) -join '' }
    }
    Add-Gp (Get-RegId $s.registryKey $valueName) $value $s.GPOID
}

# Security settings
foreach ($class in 'RSOP_SecuritySettingNumeric', 'RSOP_SecuritySettingBoolean', 'RSOP_SecuritySettingString') {
    foreach ($s in Get-Winning $class) { Add-Gp "sec:$($s.KeyName)" $s.Setting $s.GPOID }
}
foreach ($s in Get-Winning RSOP_UserPrivilegeRight) {
    Add-Gp "right:$($s.UserRight)" ($s.AccountList -join ',') $s.GPOID
}
foreach ($s in Get-Winning RSOP_AuditPolicy) {
    $flags = @(if ($s.Success) { 'Success' }; if ($s.Failure) { 'Failure' }) -join ','
    Add-Gp "audit:$($s.Category)" $flags $s.GPOID
}
foreach ($s in Get-Winning RSOP_RegistryValue) {
    Add-Gp (Split-RegPath $s.Path) $s.Data $s.GPOID
}

# advanced audit isn't in RSoP WMI, so read it from gpresult
function Get-AuditId([string]$Guid) { "advaudit:$($Guid.Trim('{}'))" }

function Get-XmlText($Node, [string[]]$Path) {
    $Node.SelectSingleNode(($Path | ForEach-Object { "*[local-name()='$_']" }) -join '/').InnerText
}

$gpXml = Join-Path $env:TEMP "gpresult-$PID.xml"
try {
    gpresult /scope computer /x $gpXml /f | Out-Null
    if (-not (Test-Path -LiteralPath $gpXml)) { throw "gpresult wrote no report (exit $LASTEXITCODE), so advanced audit can't be read." }
    $gpReport = [xml]::new()
    $gpReport.Load($gpXml)
}
finally {
    Remove-Item -LiteralPath $gpXml -ErrorAction SilentlyContinue
}

# 0 and 4 both show up for "no auditing" in practice
$auditLabels = @{ '0' = 'No auditing'; '1' = 'Success'; '2' = 'Failure'; '3' = 'Success,Failure'; '4' = 'No auditing' }
$advancedAudit = foreach ($a in $gpReport.SelectNodes("//*[local-name()='AuditSetting']")) {
    if ((Get-XmlText $a 'Precedence') -ne '1') { continue }
    # per-user rows use a different value encoding
    if ((Get-XmlText $a 'PolicyTarget') -notin '', 'System') { continue }
    $guid = Get-XmlText $a 'GPO', 'Identifier'
    $gpoKey = if ($guid) { $gpoName.Keys | Where-Object { $_ -like "*$guid*" } | Select-Object -First 1 }
    $setting = Get-XmlText $a 'SettingValue'
    $label = $auditLabels[$setting]
    if (-not $label) { $label = $setting }
    Add-Gp (Get-AuditId (Get-XmlText $a 'SubcategoryGuid')) $label $(if ($gpoKey) { $gpoKey } else { $guid })
    Get-XmlText $a 'SubcategoryName'
}

# on by default, so old-style audit is ignored once any advanced audit is set
$lsa = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue
$advancedAuditTypes = 'Dsc_auditpolicycsv', 'Dsc_auditpolicysubcategory', 'Dsc_auditpolicyguid'
$advancedAuditSet = $advancedAudit -or @($catalog.resources.type | Where-Object { $_ -in $advancedAuditTypes }).Count
$legacyAuditIgnored = $advancedAuditSet -and (-not $lsa -or $lsa.SCENoApplyLegacyAuditPolicy -eq 1)
$ignoredByPuppet = [Collections.Generic.List[string]]::new()

# --- Puppet side ---

# manifests usually only use the secpol.msc name, so ask the provider for the real one
# (its current value uses the manifest's format, so Agrees compares against that)
$lspMap = @{}
if ($catalog.resources.type -contains 'Local_security_policy') {
    $lspText = (& $Puppet resource local_security_policy) -join "`n"
    foreach ($m in [regex]::Matches($lspText, '(?ms)^local_security_policy \{ ''((?:[^''\\]|\\.)*)'':(.*?)^\}')) {
        $body = $m.Groups[2].Value
        $lspMap[$m.Groups[1].Value -replace '\\(.)', '$1'] = [pscustomobject]@{
            Setting = Get-DslAttr $body 'policy_setting'
            Type    = Get-DslAttr $body 'policy_type'
            Current = Get-DslAttr $body 'policy_value'
        }
    }
}

$checkedTypes = 'Registry_value', 'Dsc_registry', 'Dsc_xregistry', 'Local_security_policy'
$uncheckedTypes = 'Advanced_security_policy', 'Advanced_audit_policy'
$conflicts = [Collections.Generic.List[object]]::new()

function Add-Conflict([string]$Id, [string]$Ref, [string]$Value, $CompareTo) {
    $hit = $gp[$Id]
    if (-not $hit) { return }
    if ($null -eq $CompareTo) { $CompareTo = $hit.Value }
    $conflicts.Add([pscustomobject]@{
        Setting     = $Id
        Puppet      = $Ref
        PuppetValue = $Value
        Gpo         = $hit.Gpo
        GpoValue    = $hit.Value
        # merge: only adds accounts, compare means nothing
        Agrees      = if ($Value -match '^merge:') { $null } else { (Get-Comparable $Id $Value) -eq (Get-Comparable $Id $CompareTo) }
    })
}
$skipped = [Collections.Generic.List[string]]::new()

foreach ($r in $catalog.resources) {
    if ($r.exported) { continue }
    $p = $r.parameters
    $ref = "$($r.type)[$($r.title)]"

    # one resource applies a whole audit CSV, so check each row
    if ($r.type -eq 'Dsc_auditpolicycsv') {
        if (-not $p.dsc_csvpath -or -not (Test-Path -LiteralPath $p.dsc_csvpath)) { $skipped.Add("$ref (no CSV at '$($p.dsc_csvpath)')"); continue }
        $rows = @(Import-Csv -LiteralPath $p.dsc_csvpath | Where-Object { $_.'Subcategory GUID' -and $_.'Policy Target' -eq 'System' })
        if (-not $rows) { $skipped.Add("$ref (no subcategory rows in $($p.dsc_csvpath))"); continue }
        $inCsv = @{}
        foreach ($row in $rows) {
            $label = $auditLabels["$($row.'Setting Value')"]
            if (-not $label) { $label = $row.'Setting Value' }
            $auditId = Get-AuditId $row.'Subcategory GUID'
            $inCsv[$auditId] = $true
            Add-Conflict $auditId "$ref > $($row.Subcategory)" $label
        }
        # the CSV restore wipes the whole audit policy, so GPO-only subcategories get reset too
        $gpoOnly = @($gp.Keys | Where-Object { $_ -like 'advaudit:*' -and -not $inCsv[$_] }).Count
        if ($gpoOnly) { $skipped.Add("$ref (restores the whole audit policy, so $gpoOnly GPO-only audit subcategories get reset till the next GP refresh)") }
        continue
    }
    $id = $null
    $value = $null
    $compareTo = $null

    switch ($r.type) {
        'Registry_value' {
            $id = Split-RegPath $(if ($p.path) { $p.path } else { $r.title })
            $value = Format-RegData $p.data $p.type
        }
        { $_ -in 'Dsc_registry', 'Dsc_xregistry' } {
            $id = Get-RegId $p.dsc_key $p.dsc_valuename
            $value = Format-RegData $p.dsc_valuedata $p.dsc_valuetype
        }
        'Local_security_policy' {
            $known = $lspMap[$(if ($p.name) { $p.name } else { $r.title })]
            $setting = if ($p.policy_setting) { $p.policy_setting } else { $known.Setting }
            $type = if ($p.policy_type) { $p.policy_type } else { $known.Type }
            $value = $p.policy_value
            if ($known -and $known.Current) { $compareTo = $known.Current }
            if ($setting) {
                $id = switch ($type) {
                    'System Access'    { "sec:$setting" }
                    'Privilege Rights' { "right:$setting" }
                    'Event Audit'      { "audit:$setting" }
                    'Registry Values'  { Split-RegPath $setting }
                }
            }
            if ($type -eq 'Event Audit' -and $legacyAuditIgnored) { $ignoredByPuppet.Add($ref) }
        }
    }

    if (-not $id) {
        $unchecked = $r.type -in $checkedTypes + $uncheckedTypes -or $r.type -like 'Dsc_*' -or
            ($r.type -eq 'Registry_key' -and $p.purge_values)
        if ($unchecked) { $skipped.Add($ref) }
        continue
    }
    if ($p.ensure -eq 'absent' -or $p.dsc_ensure -eq 'absent') { $value = '<absent>' }

    Add-Conflict $id $ref "$value" $compareTo
}

if ($ignoredByPuppet.Count) {
    Write-Warning ("Advanced audit is set (by GPO or Puppet), so these old-style audit settings from Puppet likely aren't applied:`n  " +
        ($ignoredByPuppet -join "`n  "))
}

if ($skipped.Count) {
    Write-Warning ("Not checked:`n  " + ($skipped -join "`n  "))
}

if (-not $conflicts.Count) {
    'No settings managed by both Puppet and GPO.'
    exit 0
}

# disagreements first, then blanks, then agreements
$sorted = $conflicts | Sort-Object @{ Expression = { if ($null -eq $_.Agrees) { 1 } elseif ($_.Agrees) { 2 } else { 0 } } }, Setting
if ($CsvPath) { $sorted | Export-Csv $CsvPath -NoTypeInformation -Encoding UTF8 }
if ($PassThru) { $sorted } else { $sorted | Format-Table -AutoSize -Wrap }
exit 1
