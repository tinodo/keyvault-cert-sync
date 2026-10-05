<#
.SYNOPSIS
    Builds a READ-ONLY probe that exercises the new IIS functions on a real server.

.DESCRIPTION
    Embeds src\Sync-KeyVaultCertificate.ps1 as base64, then emits a script that extracts
    only the IIS helper functions through the AST and runs the ones that cannot change
    anything: binding enumeration, http.sys parsing, endpoint key mapping and the
    binding-selection decision.

    Nothing is imported, written or bound. Use it to confirm what a real run WOULD do
    before letting it do it.

.PARAMETER PretendCertificateThumbprint
    Thumbprint of a certificate already in LocalMachine\My to stand in for the Key Vault
    certificate. Pick the superseded one: the live bindings must then be reported as
    claimable for exactly the reason a real run would use.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [Parameter(Mandatory = $true)][string]$PretendCertificateThumbprint,
    [ValidateSet('Managed', 'Matching', 'All')][string]$IisBindingScope = 'Managed'
)

$ErrorActionPreference = 'Stop'

$root    = Split-Path $PSScriptRoot -Parent
$syncPs1 = Join-Path $root 'src\Sync-KeyVaultCertificate.ps1'
if (-not $OutputPath) { $OutputPath = Join-Path $root 'dist\probe-iis-plan.ps1' }

$syncB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content $syncPs1 -Raw)))

$probe = @"
# READ-ONLY. Reports what the IIS code path WOULD do. Imports nothing, binds nothing.
`$ErrorActionPreference = 'Continue'
`$IisSites         = @()
`$IisBindingScope  = '$IisBindingScope'
`$Role             = 'IIS'
`$script:EventLogReady = `$false
`$script:LogFile       = Join-Path `$env:TEMP 'certsync-probe.log'

`$text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$syncB64'))
`$ast  = [System.Management.Automation.Language.Parser]::ParseInput(`$text, [ref]`$null, [ref]`$null)

`$wanted = 'Write-Log','Get-IisAdminAssemblyPath','Import-IisAdmin','ConvertTo-HexString',
           'ConvertFrom-HexString','Get-SubjectAlternativeDnsName','Get-CertificateDnsName',
           'Test-DnsNameCovered','Get-IisHttpsBinding','Select-IisBindingToUpdate',
           'ConvertFrom-NetshSslCertOutput','Get-HttpSysSslBinding','Get-HttpSysEndpointKey',
           'Get-DetectedRole','Get-ThumbprintsInUse','Test-SupersededCertificate'
foreach (`$fn in `$ast.FindAll({ param(`$n) `$n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, `$true)) {
    if (`$wanted -contains `$fn.Name) { . ([scriptblock]::Create(`$fn.Extent.Text)) }
}

Write-Output "=============== `$env:COMPUTERNAME ==============="
Write-Output ("detected role       : {0}" -f (Get-DetectedRole))
Write-Output ("binding scope       : $IisBindingScope")
Write-Output ''

`$pretend = Get-Item 'Cert:\LocalMachine\My\$PretendCertificateThumbprint' -ErrorAction SilentlyContinue
if (-not `$pretend) { Write-Output 'FATAL: stand-in certificate $PretendCertificateThumbprint not found.'; exit 1 }
Write-Output ("stand-in cert       : {0}" -f `$pretend.Thumbprint)
Write-Output ("  subject           : {0}" -f `$pretend.Subject)
Write-Output ("  dns names         : {0}" -f ((Get-CertificateDnsName -Certificate `$pretend) -join ', '))
Write-Output ''

Write-Output '--- https bindings seen by Microsoft.Web.Administration ---'
`$bindings = @(Get-IisHttpsBinding)
foreach (`$b in `$bindings) {
    Write-Output ("  site={0,-14} info={1,-34} flags={2} store={3,-4} hash={4}" -f `$b.Site, `$b.Info, `$b.SslFlags, `$b.Store, `$b.Hash)
    `$ep = Get-HttpSysEndpointKey -Binding `$b
    Write-Output ("      http.sys key -> {0}={1}" -f `$ep.Argument, `$ep.Key)
}
Write-Output ''

Write-Output '--- http.sys, as parsed by the agent ---'
`$live = Get-HttpSysSslBinding
foreach (`$k in (`$live.Keys | Sort-Object)) {
    Write-Output ("  {0,-34} {1}  appid={2}" -f `$k, `$live[`$k].Hash, `$live[`$k].AppId)
}
Write-Output ''

Write-Output '--- decision: bindings a real run would re-point ---'
`$sel = @(Select-IisBindingToUpdate -Bindings `$bindings -Certificate `$pretend -Scope '$IisBindingScope')
if (`$sel.Count -eq 0) { Write-Output '  (none - every in-scope binding already current)' }
foreach (`$s in `$sel) {
    Write-Output ("  WOULD REBIND  site={0,-14} info={1,-34}" -f `$s.Site, `$s.Info)
    Write-Output ("                reason: {0}" -f `$s.Reason)
}
Write-Output ''

Write-Output '--- certificates the agent considers in use (cleanup protection) ---'
`$inUse = @(Get-ThumbprintsInUse | Sort-Object -Unique)
foreach (`$t in `$inUse) { Write-Output "  `$t" }
Write-Output ''

Write-Output '--- decision: certificates CleanupMode=Expired would delete ---'
`$protect = @(`$inUse) + @(`$pretend.Thumbprint.ToUpperInvariant())
`$supers  = @(Get-ChildItem 'Cert:\LocalMachine\My' |
             Where-Object { `$_.Thumbprint.ToUpperInvariant() -notin `$protect -and
                            (Test-SupersededCertificate -Candidate `$_ -Current `$pretend) })
if (`$supers.Count -eq 0) { Write-Output '  (no superseded certificates found)' }
foreach (`$s in `$supers) {
    `$verdict = if (`$s.NotAfter -lt (Get-Date)) { 'WOULD DELETE (expired)' } else { 'kept (still valid)' }
    Write-Output ("  {0,-22} {1}  notAfter={2}  {3}" -f `$verdict, `$s.Thumbprint, `$s.NotAfter.ToString('yyyy-MM-dd'), `$s.Subject)
}
Write-Output ''
Write-Output '--- certificates deliberately NOT considered superseded ---'
foreach (`$c in (Get-ChildItem 'Cert:\LocalMachine\My')) {
    if (`$c.Thumbprint.ToUpperInvariant() -in `$protect) { continue }
    if (Test-SupersededCertificate -Candidate `$c -Current `$pretend) { continue }
    Write-Output ("  safe   {0}  {1}" -f `$c.Thumbprint, `$c.Subject)
}
Write-Output ''
Write-Output 'READ-ONLY - nothing was imported, bound or deleted.'
"@

$err = $null
[System.Management.Automation.Language.Parser]::ParseInput($probe, [ref]$null, [ref]$err) | Out-Null
if ($err) { throw "generated probe has parse errors: $($err[0].Message) (line $($err[0].Extent.StartLineNumber))" }

$outDir = Split-Path $OutputPath -Parent
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
[System.IO.File]::WriteAllText($OutputPath, $probe, (New-Object System.Text.UTF8Encoding $false))

Write-Host "wrote $OutputPath ($([math]::Round((Get-Item $OutputPath).Length / 1KB, 1)) KB)" -ForegroundColor Green
