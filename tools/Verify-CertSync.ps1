<#
.SYNOPSIS
    READ-ONLY verification of the certsync agent. Makes no changes: no imports, no bindings,
    no service restarts, no task starts. Safe to run on a production federation server.

.DESCRIPTION
    Reports the detected role, agent install state, scheduled task health, the certificates
    in LocalMachine\My, what AD FS / WAP / IIS are actually bound to, what http.sys is
    serving, and the tail of the agent log.

.PARAMETER SubjectFilter
    Wildcard matched against certificate Subject to decide which certificates to list.
    Defaults to '*' (all of them). Narrow it to cut the noise on a machine with a large
    store, e.g. -SubjectFilter '*contoso.com*'.

.PARAMETER ExpectedThumbprint
    Optional. When supplied, every binding is flagged current or STALE against it, which
    turns this from a dump into a pass/fail check.

.EXAMPLE
    .\Verify-CertSync.ps1

.EXAMPLE
    .\Verify-CertSync.ps1 -SubjectFilter '*contoso.com*' -ExpectedThumbprint ABC123...
#>
[CmdletBinding()]
param(
    [string]$SubjectFilter      = '*',
    [string]$ExpectedThumbprint
)

$ErrorActionPreference = 'Continue'
if ($ExpectedThumbprint) { $ExpectedThumbprint = ($ExpectedThumbprint -replace '[^0-9a-fA-F]', '').ToUpperInvariant() }

function Line { param($k,$v) Write-Output ("{0,-22}: {1}" -f $k, $v) }
function Flag {
    param([string]$Thumbprint)
    if (-not $ExpectedThumbprint) { return '' }
    if (($Thumbprint -replace '[^0-9a-fA-F]', '').ToUpperInvariant() -eq $ExpectedThumbprint) { return '  current' }
    return '  <-- STALE'
}

Write-Output "=============== $env:COMPUTERNAME ==============="
Line 'os' (Get-CimInstance Win32_OperatingSystem).Caption

# --- role ---------------------------------------------------------------------
try {
    Import-Module ServerManager -ErrorAction Stop
    $f = Get-WindowsFeature -Name 'ADFS-Federation','Web-Application-Proxy' -ErrorAction Stop
    $adfs = [bool](($f | Where-Object Name -eq 'ADFS-Federation').Installed)
    $wap  = [bool](($f | Where-Object Name -eq 'Web-Application-Proxy').Installed)
    Line 'roles installed' "ADFS=$adfs WAP=$wap"
} catch { Line 'roles installed' "unknown: $($_.Exception.Message)" }

$svc = Get-Service -Name 'adfssrv','appproxysvc' -ErrorAction SilentlyContinue
Line 'services' (($svc | ForEach-Object { "$($_.Name)=$($_.Status)" }) -join '  ')

# --- agent install ------------------------------------------------------------
Write-Output ''
Write-Output '--- agent ---'
$bin = Join-Path $env:ProgramData 'KeyVaultCertSync\bin'
Line 'bin folder' $(if (Test-Path $bin) { (Get-ChildItem $bin | ForEach-Object { $_.Name }) -join ', ' } else { 'MISSING' })

$task = Get-ScheduledTask -TaskName 'KeyVault Certificate Sync' -TaskPath '\Microsoft\KeyVaultCertSync\' -ErrorAction SilentlyContinue
if ($task) {
    $info = Get-ScheduledTaskInfo -InputObject $task
    Line 'scheduled task' "state=$($task.State)"
    Line 'last run' $info.LastRunTime
    Line 'last result' ("0x{0:X}" -f $info.LastTaskResult)
    Line 'next run' $info.NextRunTime
} else {
    Line 'scheduled task' 'NOT REGISTERED'
}

$state = Join-Path $env:ProgramData 'KeyVaultCertSync\state.json'
if (Test-Path $state) {
    Write-Output ''
    Write-Output '--- state.json ---'
    Get-Content $state -Raw
} else {
    Line 'state.json' 'MISSING - the agent has not completed a sync'
}

# --- certificate store --------------------------------------------------------
Write-Output ''
Write-Output "--- LocalMachine\My (Subject -like '$SubjectFilter') ---"
$certs = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
         Where-Object { $_.Subject -like $SubjectFilter } | Sort-Object NotAfter -Descending
foreach ($c in $certs) {
    $days = [int]($c.NotAfter - (Get-Date)).TotalDays
    Write-Output ("  {0}  {1,-28} exp {2} ({3,4}d)  key={4}  issuer={5}{6}" -f `
        $c.Thumbprint, $c.Subject, $c.NotAfter.ToString('yyyy-MM-dd'), $days, $c.HasPrivateKey,
        (($c.Issuer -split ',')[0] -replace '^CN=',''), (Flag $c.Thumbprint))
}
if (-not $certs) { Write-Output '  (none)' }

# --- what is actually bound ---------------------------------------------------
Write-Output ''
Write-Output '--- bindings ---'
if (Get-Command Get-AdfsCertificate -ErrorAction SilentlyContinue) {
    try {
        $sc = Get-AdfsCertificate -CertificateType Service-Communications -ErrorAction Stop
        Line 'adfs svc-comms' ("{0}{1}" -f $sc.Thumbprint, (Flag $sc.Thumbprint))
    } catch { Line 'adfs svc-comms' "error: $($_.Exception.Message)" }
    try {
        $ssl = Get-AdfsSslCertificate -ErrorAction Stop | Select-Object -First 1
        Line 'adfs ssl' ("{0}{1}" -f $ssl.CertificateHash, (Flag $ssl.CertificateHash))
    } catch { Line 'adfs ssl' "error: $($_.Exception.Message)" }
}
if (Get-Command Get-WebApplicationProxySslCertificate -ErrorAction SilentlyContinue) {
    try {
        $w = Get-WebApplicationProxySslCertificate -ErrorAction Stop | Select-Object -First 1
        Line 'wap ssl' ("{0}{1}" -f $w.CertificateHash, (Flag $w.CertificateHash))
    } catch { Line 'wap ssl' "error: $($_.Exception.Message)" }
    try {
        $apps = @(Get-WebApplicationProxyApplication -ErrorAction Stop)
        foreach ($a in $apps) {
            Write-Output ("  app {0,-28} {1}{2}" -f $a.Name, $a.ExternalCertificateThumbprint, (Flag $a.ExternalCertificateThumbprint))
        }
    } catch { Line 'wap apps' "error: $($_.Exception.Message)" }
}

$mwa = Join-Path $env:SystemRoot 'System32\inetsrv\Microsoft.Web.Administration.dll'
if (Test-Path $mwa) {
    try {
        [void][Reflection.Assembly]::LoadFrom($mwa)
        $sm = New-Object Microsoft.Web.Administration.ServerManager
        foreach ($site in $sm.Sites) {
            foreach ($b in $site.Bindings) {
                if ($b.Protocol -ne 'https') { continue }
                $h = ''
                try {
                    $raw = $b.CertificateHash
                    if ($raw) { $h = (($raw | ForEach-Object { '{0:X2}' -f $_ }) -join '') }
                } catch { $h = '<err>' }
                Write-Output ("  iis {0,-16} {1,-32} {2}{3}" -f $site.Name, $b.BindingInformation, $h, (Flag $h))
            }
        }
        $sm.Dispose()
    } catch { Line 'iis bindings' "error: $($_.Exception.Message)" }
}

Write-Output ''
Write-Output '--- http.sys ---'
# Parsed by value SHAPE, not by label, to match the agent: netsh labels are localised
# ('IP:Port' / 'Zertifikathash' on a German Windows) and label matching returns nothing there.
$out = & "$env:SystemRoot\System32\netsh.exe" http show sslcert 2>$null
$cur = $null
foreach ($l in $out) {
    if ("$l" -notmatch '^\s*(.+?)\s+:\s+(.*?)\s*$') { continue }
    $v = $Matches[2]
    if ($v -match '^(?:(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\]|[A-Za-z0-9\-\._\*]+\.[A-Za-z0-9\-\._\*]*):\d{1,5}$') {
        $cur = $v
    } elseif ($v -match '^[0-9a-fA-F]{40}$' -and $cur) {
        Write-Output ("  {0,-40} {1}{2}" -f $cur, $v.ToUpper(), (Flag $v))
    }
}

# --- agent log ----------------------------------------------------------------
Write-Output ''
Write-Output '--- agent log (tail) ---'
$logDir = Join-Path $env:ProgramData 'KeyVaultCertSync\Logs'
if (Test-Path $logDir) {
    Get-ChildItem $logDir -Filter 'sync-*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1 |
        ForEach-Object { Get-Content $_.FullName -Tail 25 }
} else { Write-Output '  (no log directory)' }

Write-Output ''
Write-Output 'READ-ONLY CHECK COMPLETE - nothing was modified.'
