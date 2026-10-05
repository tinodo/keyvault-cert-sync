# READ-ONLY. Dumps the IIS https binding layout. Changes nothing.
$ErrorActionPreference = 'Continue'

function Format-Hash {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value.Replace(' ', '').ToUpperInvariant() }
    return (($Value | ForEach-Object { '{0:X2}' -f $_ }) -join '')
}

Write-Output "=============== $env:COMPUTERNAME ==============="
Write-Output ('IIS installed: {0}' -f (Test-Path (Join-Path $env:SystemRoot 'System32\inetsrv\Microsoft.Web.Administration.dll')))
Write-Output ('W3SVC state  : {0}' -f (Get-Service W3SVC -ErrorAction SilentlyContinue).Status)

Write-Output ''
Write-Output '--- sites + bindings (Microsoft.Web.Administration) ---'
try {
    [void][Reflection.Assembly]::LoadFrom((Join-Path $env:SystemRoot 'System32\inetsrv\Microsoft.Web.Administration.dll'))
    $sm = New-Object Microsoft.Web.Administration.ServerManager
    foreach ($site in $sm.Sites) {
        Write-Output ("site: {0}  state={1}" -f $site.Name, $site.State)
        foreach ($b in $site.Bindings) {
            $hash = ''
            try { $hash = Format-Hash $b.CertificateHash } catch { $hash = '<err>' }
            $store = ''
            try { $store = $b.CertificateStoreName } catch { }
            $flags = ''
            try { $flags = $b.SslFlags } catch { }
            Write-Output ("    proto={0,-5} info={1,-34} sslFlags={2,-3} store={3,-8} hash={4}" -f `
                          $b.Protocol, $b.BindingInformation, $flags, $store, $hash)
        }
    }
    $sm.Dispose()
} catch {
    Write-Output "  MWA failed: $($_.Exception.Message)"
}

Write-Output ''
Write-Output '--- netsh (what http.sys actually serves) ---'
$out = & "$env:SystemRoot\System32\netsh.exe" http show sslcert 2>$null
$cur = $null
foreach ($l in $out) {
    if ($l -match '(?:IP:port|Hostname:port|Central Certificate Store|Scoped IP:port)\s*:\s*(.+)$') { $cur = $Matches[1].Trim() }
    if ($l -match 'Certificate Hash\s*:\s*([0-9a-fA-F]{40})' -and $cur) {
        Write-Output ("  {0,-38} {1}" -f $cur, $Matches[1].ToUpper())
    }
}

Write-Output ''
Write-Output '--- LocalMachine\My ---'
Get-ChildItem Cert:\LocalMachine\My | ForEach-Object {
    Write-Output ("  {0}  key={1,-5} notAfter={2}  subject={3}" -f `
        $_.Thumbprint, $_.HasPrivateKey, $_.NotAfter.ToString('yyyy-MM-dd'), $_.Subject)
    foreach ($e in $_.Extensions) {
        if ($e.Oid.Value -eq '2.5.29.17') { Write-Output ("      SAN: {0}" -f ($e.Format($false))) }
    }
}

Write-Output ''
Write-Output '--- cert sync agent ---'
$state = Join-Path $env:ProgramData 'KeyVaultCertSync\state.json'
if (Test-Path $state) { Get-Content $state -Raw } else { Write-Output '  (agent not installed)' }
Get-ScheduledTask -TaskPath '\Microsoft\KeyVaultCertSync\' -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Output ("  task: {0} state={1}" -f $_.TaskName, $_.State) }

Write-Output ''
Write-Output 'READ-ONLY - nothing modified.'
