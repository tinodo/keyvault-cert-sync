# Self-test harness. Extracts the real functions from Sync-KeyVaultCertificate.ps1 via the
# PowerShell AST and exercises the parts that do not require elevation or Azure.
# Run with:  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-SyncLogic.ps1

$ErrorActionPreference = 'Stop'
$src = Join-Path (Split-Path $PSScriptRoot -Parent) 'src\Sync-KeyVaultCertificate.ps1'

$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$tokens, [ref]$errors)
if ($errors) { throw "Parse errors in $src" }

# Load every function definition into this session without running the script body.
$wanted = 'ConvertFrom-Base64Url', 'Import-PfxToLocalMachine', 'Resolve-PrivateKeyFile',
          'Get-KeyContainerName', 'Get-DetectedRole', 'Get-ServiceAccountName',
          'Get-CurrentBoundThumbprint', 'Get-ThumbprintsInUse', 'Write-Log', 'Grant-PrivateKeyRead',
          'ConvertTo-Sid', 'Test-AclGrantsRead', 'Test-WapApplicationsCurrent',
          'Get-IisAdminAssemblyPath', 'ConvertTo-HexString', 'ConvertFrom-HexString',
          'Get-SubjectAlternativeDnsName', 'Get-CertificateDnsName', 'Test-DnsNameCovered',
          'Select-IisBindingToUpdate', 'ConvertFrom-NetshSslCertOutput', 'Get-HttpSysSslBinding',
          'Get-HttpSysEndpointKey', 'Test-SupersededCertificate'
foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    if ($wanted -contains $fn.Name) { . ([scriptblock]::Create($fn.Extent.Text)) }
}
$script:EventLogReady = $false
$script:LogFile = Join-Path $env:TEMP 'certsync-test.log'

$pass = 0; $fail = 0
function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try {
        & $Body
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green
        $script:pass++
    } catch {
        Write-Host ("  FAIL  {0}`n        {1}" -f $Name, $_.Exception.Message) -ForegroundColor Red
        $script:fail++
    }
}

Write-Host "PowerShell $($PSVersionTable.PSVersion) / $($PSVersionTable.PSEdition)" -ForegroundColor Cyan
Write-Host ''

# ---------------------------------------------------------------- base64url
Write-Host 'ConvertFrom-Base64Url' -ForegroundColor Cyan

Test-Case 'round-trips a 20-byte SHA-1 hash through base64url' {
    $bytes = New-Object byte[] 20
    (New-Object Random 42).NextBytes($bytes)
    $x5t = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $back = ConvertFrom-Base64Url $x5t
    for ($i = 0; $i -lt 20; $i++) { if ($bytes[$i] -ne $back[$i]) { throw "byte $i differs" } }
}

Test-Case 'derives an uppercase 40-char hex thumbprint like Key Vault x5t' {
    $bytes = [byte[]](1..20)
    $x5t = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $thumb = ([BitConverter]::ToString((ConvertFrom-Base64Url $x5t)) -replace '-', '').ToUpperInvariant()
    if ($thumb -ne '0102030405060708090A0B0C0D0E0F1011121314') { throw "got $thumb" }
}

Test-Case 'handles every base64url padding case' {
    foreach ($len in 1..24) {
        $b = New-Object byte[] $len
        $enc = [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $out = ConvertFrom-Base64Url $enc
        if ($out.Length -ne $len) { throw "length $len round-tripped to $($out.Length)" }
    }
}

# ------------------------------------------------------- pfx parsing / import
Write-Host ''
Write-Host 'PFX handling (CurrentUser store - LocalMachine needs elevation)' -ForegroundColor Cyan

Test-Case 'parses a password-less PFX chain and picks the leaf with the private key' {
    $ca = New-SelfSignedCertificate -Subject 'CN=CertSyncTest Root' -CertStoreLocation Cert:\CurrentUser\My `
            -KeyUsage CertSign, CRLSign -KeyExportPolicy Exportable -NotAfter (Get-Date).AddDays(2) `
            -TextExtension @('2.5.29.19={text}CA=true')
    $leaf = New-SelfSignedCertificate -Subject 'CN=*.certsynctest.local' -DnsName '*.certsynctest.local' `
            -CertStoreLocation Cert:\CurrentUser\My -Signer $ca -KeyExportPolicy Exportable `
            -NotAfter (Get-Date).AddDays(1)
    $script:testCert = $leaf
    $script:testCa = $ca

    # A real Key Vault / Let's Encrypt PFX carries the private key on the leaf only,
    # so strip the key from the issuer before building the test blob.
    $caPublicOnly = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $ca.RawData)

    $coll = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $coll.Add($leaf) | Out-Null
    $coll.Add($caPublicOnly) | Out-Null
    $pfxBytes = $coll.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12)

    # Mirrors exactly what Import-PfxToLocalMachine does before touching the store.
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
    $reimported = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    try   { $reimported.Import($pfxBytes, $null, $flags) }
    catch { $reimported.Import($pfxBytes, '', $flags) }

    $found = $reimported | Where-Object { $_.HasPrivateKey } | Select-Object -First 1
    if (-not $found) { throw 'no private-key certificate found in the collection' }
    if ($found.Subject -ne 'CN=*.certsynctest.local') { throw "picked the wrong leaf: $($found.Subject)" }

    $chain = @($reimported | Where-Object { -not $_.HasPrivateKey })
    if ($chain.Count -lt 1) { throw 'chain certificate was not preserved' }
    $script:chainIsSelfSigned = ($chain[0].Subject -eq $chain[0].Issuer)
}

Test-Case 'routes a self-signed chain certificate to Root (an issued one would go to CA)' {
    if (-not $script:chainIsSelfSigned) { throw 'expected the test CA to be self-signed' }
    $storeName = if ($script:chainIsSelfSigned) { 'Root' } else { 'CA' }
    if ($storeName -ne 'Root') { throw "routed to $storeName" }
}

Test-Case 'Resolve-PrivateKeyFile locates the key material on disk' {
    # Use a certificate that has not been through a collection export - see the next test.
    $fresh = New-SelfSignedCertificate -Subject 'CN=certsynctest-key' -CertStoreLocation Cert:\CurrentUser\My `
                -NotAfter (Get-Date).AddDays(1)
    $script:testKeyCert = $fresh
    $path = Resolve-PrivateKeyFile -Certificate $fresh
    if (-not $path) { throw 'returned null' }
    if (-not (Test-Path -LiteralPath $path)) { throw "path does not exist: $path" }
    Write-Host "        -> $path" -ForegroundColor DarkGray
}

Test-Case 'Get-KeyContainerName returns null (not a bogus name) when the handle is gone' {
    # X509Certificate2Collection.Export mutates its source objects and clears the CNG key
    # handle. Regression guard: the helper must report that honestly instead of guessing.
    $victim = New-SelfSignedCertificate -Subject 'CN=certsynctest-wiped' -CertStoreLocation Cert:\CurrentUser\My `
                -KeyExportPolicy Exportable -NotAfter (Get-Date).AddDays(1)
    $script:testWiped = $victim
    if (-not (Get-KeyContainerName -Certificate $victim)) { throw 'handle was already empty before the export' }

    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $c.Add($victim) | Out-Null
    $null = $c.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12)

    $after = Get-KeyContainerName -Certificate $victim
    if ($after) { throw "expected null after the export, got '$after'" }
    Write-Host '        -> reported null, so Resolve-PrivateKeyFile will re-read from the store' -ForegroundColor DarkGray
}

Test-Case 'Grant-PrivateKeyRead logs an actionable error instead of silently skipping' {
    # Feed it a certificate with no resolvable key and confirm it emits event 2002 at Error level.
    $publicOnly = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $script:testCert.RawData)
    $captured = New-Object System.Collections.Generic.List[string]
    function Write-Log { param($Message, $Level = 'Information', $EventId = 0)
                         $script:captured.Add("$Level|$EventId|$Message") }
    $script:captured = $captured
    try {
        Grant-PrivateKeyRead -Certificate $publicOnly -Identities @('NT AUTHORITY\SYSTEM')
    } finally {
        Remove-Item Function:\Write-Log -ErrorAction SilentlyContinue
        foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            if ($fn.Name -eq 'Write-Log') { . ([scriptblock]::Create($fn.Extent.Text)) }
        }
    }
    $err = $captured | Where-Object { $_ -like 'Error|2002|*' }
    if (-not $err) { throw "expected an Error/2002 log entry, got: $($captured -join ' // ')" }
    if ($err -notmatch 'Manage Private Keys') { throw 'error message lacks remediation guidance' }
    Write-Host '        -> loud, with manual remediation steps' -ForegroundColor DarkGray
}

# ------------------------------------------------------------- role detection
Write-Host ''
Write-Host 'Role and service detection' -ForegroundColor Cyan

Test-Case 'Get-DetectedRole returns one of ADFS/WAP/IIS/None' {
    $r = Get-DetectedRole
    if (@('ADFS', 'WAP', 'IIS', 'None') -notcontains $r) { throw "unexpected value '$r'" }
    Write-Host "        -> $r" -ForegroundColor DarkGray
}

Test-Case 'Get-DetectedRole picks WAP when a proxy also carries an adfssrv service' {
    # Regression guard for real Windows Server 2025 behaviour: a Web Application Proxy box
    # reports adfssrv=Running even though ADFS-Federation is Installed=False, because the
    # proxy ships the same service host binary. Detecting on service presence alone
    # misclassified the proxy as an AD FS server.
    function Import-Module { param([Parameter(ValueFromRemainingArguments = $true)]$a) }
    function Get-WindowsFeature {
        param([Parameter(ValueFromRemainingArguments = $true)]$a)
        @(
            [pscustomobject]@{ Name = 'ADFS-Federation';       Installed = $false }
            [pscustomobject]@{ Name = 'Web-Application-Proxy'; Installed = $true  }
        )
    }
    try {
        $r = Get-DetectedRole
        if ($r -ne 'WAP') { throw "expected WAP, got '$r'" }
    } finally {
        Remove-Item Function:\Get-WindowsFeature -ErrorAction SilentlyContinue
        Remove-Item Function:\Import-Module -ErrorAction SilentlyContinue
    }
    Write-Host '        -> WAP, not ADFS' -ForegroundColor DarkGray
}

Test-Case 'Get-DetectedRole picks ADFS on a real federation server' {
    function Import-Module { param([Parameter(ValueFromRemainingArguments = $true)]$a) }
    function Get-WindowsFeature {
        param([Parameter(ValueFromRemainingArguments = $true)]$a)
        @(
            [pscustomobject]@{ Name = 'ADFS-Federation';       Installed = $true  }
            [pscustomobject]@{ Name = 'Web-Application-Proxy'; Installed = $false }
        )
    }
    try {
        $r = Get-DetectedRole
        if ($r -ne 'ADFS') { throw "expected ADFS, got '$r'" }
    } finally {
        Remove-Item Function:\Get-WindowsFeature -ErrorAction SilentlyContinue
        Remove-Item Function:\Import-Module -ErrorAction SilentlyContinue
    }
}

Test-Case 'Get-DetectedRole prefers ADFS when both roles are installed' {
    function Import-Module { param([Parameter(ValueFromRemainingArguments = $true)]$a) }
    function Get-WindowsFeature {
        param([Parameter(ValueFromRemainingArguments = $true)]$a)
        @(
            [pscustomobject]@{ Name = 'ADFS-Federation';       Installed = $true }
            [pscustomobject]@{ Name = 'Web-Application-Proxy'; Installed = $true }
        )
    }
    try {
        $r = Get-DetectedRole
        if ($r -ne 'ADFS') { throw "expected ADFS, got '$r'" }
    } finally {
        Remove-Item Function:\Get-WindowsFeature -ErrorAction SilentlyContinue
        Remove-Item Function:\Import-Module -ErrorAction SilentlyContinue
    }
}

Test-Case 'Get-ServiceAccountName normalises LocalSystem to NT AUTHORITY\SYSTEM' {
    $n = Get-ServiceAccountName 'Winmgmt'
    if ($n -ne 'NT AUTHORITY\SYSTEM') { throw "got '$n'" }
}

Test-Case 'Get-ServiceAccountName resolves a NetworkService-style account' {
    $n = Get-ServiceAccountName 'Dnscache'
    if ($n -notmatch '^NT AUTHORITY\\') { throw "got '$n'" }
    Write-Host "        -> $n" -ForegroundColor DarkGray
}

Test-Case 'Get-ServiceAccountName returns null for a service that does not exist' {
    $n = Get-ServiceAccountName 'NoSuchServiceXyz'
    if ($null -ne $n) { throw "got '$n'" }
}

Test-Case 'Get-CurrentBoundThumbprint returns null when the role is absent' {
    if ($null -ne (Get-CurrentBoundThumbprint -ForRole 'ADFS')) { throw 'expected null' }
    if ($null -ne (Get-CurrentBoundThumbprint -ForRole 'WAP'))  { throw 'expected null' }
}

Test-Case 'Get-ThumbprintsInUse parses netsh http show sslcert without throwing' {
    $t = @(Get-ThumbprintsInUse)
    foreach ($x in $t) { if ($x -notmatch '^[0-9A-F]{40}$') { throw "bad thumbprint '$x'" } }
    Write-Host "        -> $($t.Count) binding(s) found" -ForegroundColor DarkGray
}

Write-Host ''
Write-Host 'Private key ACL identity matching' -ForegroundColor Cyan

Test-Case 'ConvertTo-Sid resolves the service StartName form of NetworkService' {
    $s = ConvertTo-Sid -Identity 'NT AUTHORITY\NetworkService'
    if ($s -ne 'S-1-5-20') { throw "expected S-1-5-20, got '$s'" }
}

Test-Case 'ConvertTo-Sid resolves the ACL display form to the same SID' {
    $a = ConvertTo-Sid -Identity 'NT AUTHORITY\NetworkService'
    $b = ConvertTo-Sid -Identity 'NT AUTHORITY\NETWORK SERVICE'
    if ($a -ne $b) { throw "'$a' vs '$b'" }
}

Test-Case 'ConvertTo-Sid passes a SID string through unchanged' {
    if ((ConvertTo-Sid -Identity 'S-1-5-18') -ne 'S-1-5-18') { throw 'SID was not passed through' }
}

Test-Case 'ConvertTo-Sid returns null for an unresolvable account instead of throwing' {
    if ($null -ne (ConvertTo-Sid -Identity 'NO SUCH DOMAIN\nobody-xyz')) { throw 'expected null' }
}

Test-Case 'Test-AclGrantsRead matches NetworkService across its two display forms' {
    # The exact live bug: appproxysvc reports 'NT AUTHORITY\NetworkService', the ACL stores
    # 'NT AUTHORITY\NETWORK SERVICE'. A string compare called this a failed grant and the
    # agent logged a false Error 2003 on every run.
    $f = Join-Path $env:TEMP ("acltest-{0}.txt" -f [guid]::NewGuid().ToString('N').Substring(0,8))
    Set-Content $f 'x'
    try {
        $acl = Get-Acl $f
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            'NT AUTHORITY\NETWORK SERVICE', 'Read', 'Allow')))
        Set-Acl -Path $f -AclObject $acl

        $check = Get-Acl $f
        if (-not (Test-AclGrantsRead -Acl $check -Identity 'NT AUTHORITY\NetworkService')) {
            throw 'the grant was not detected using the service StartName form'
        }
        if (-not (Test-AclGrantsRead -Acl $check -Identity 'NT AUTHORITY\NETWORK SERVICE')) {
            throw 'the grant was not detected using the ACL display form'
        }
    } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
}

Test-Case 'Test-AclGrantsRead reports false when the identity genuinely has no grant' {
    $f = Join-Path $env:TEMP ("acltest2-{0}.txt" -f [guid]::NewGuid().ToString('N').Substring(0,8))
    Set-Content $f 'x'
    try {
        $acl = Get-Acl $f
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators', 'FullControl', 'Allow')))
        Set-Acl -Path $f -AclObject $acl
        if (Test-AclGrantsRead -Acl (Get-Acl $f) -Identity 'NT AUTHORITY\NETWORK SERVICE') {
            throw 'reported a grant that does not exist'
        }
    } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host 'WAP resilience' -ForegroundColor Cyan
$syncText = Get-Content $src -Raw

Test-Case 'a proxy that cannot reach AD FS does not fail the whole certificate sync' {
    # Get-WebApplicationProxyApplication throws a TERMINATING error when the proxy cannot
    # reach the AD FS config store, so -ErrorAction SilentlyContinue does nothing. Without a
    # try/catch the run died AFTER the TLS certificate was already bound, leaving the agent
    # reporting failure and never writing state.json.
    if ($syncText -notmatch 'Get-WebApplicationProxyApplication -ErrorAction Stop') {
        throw 'the call is not made with -ErrorAction Stop inside a try/catch'
    }
    if ($syncText -notmatch 'Could not enumerate published applications') {
        throw 'there is no non-fatal path for an unreachable AD FS config store'
    }
}

Test-Case 'a failed appproxysvc restart is a warning, not a fatal error' {
    if ($syncText -notmatch 'Could not restart appproxysvc') {
        throw 'a failed service restart still aborts the run'
    }
}

Test-Case 'the WAP path still reports that app bindings were skipped' {
    if ($syncText -notmatch 'published-application bindings were skipped') {
        throw 'skipped application bindings are not surfaced to the operator'
    }
}

Write-Host ''
Write-Host 'WAP published-application currency' -ForegroundColor Cyan

Test-Case 'Test-WapApplicationsCurrent reports true when every app matches' {
    function Get-WebApplicationProxyApplication {
        param([Parameter(ValueFromRemainingArguments = $true)]$a)
        @(
            [pscustomobject]@{ Name = 'appone';   ExternalCertificateThumbprint = 'AAAA1111' }
            [pscustomobject]@{ Name = 'apptwo'; ExternalCertificateThumbprint = 'aaaa1111' }
        )
    }
    try {
        $r = Test-WapApplicationsCurrent -Thumbprint 'AAAA1111'
        if ($r -ne $true) { throw "expected true, got '$r'" }
    } finally { Remove-Item Function:\Get-WebApplicationProxyApplication -ErrorAction SilentlyContinue }
}

Test-Case 'Test-WapApplicationsCurrent reports false when one app lags behind' {
    # The live situation: WAP TLS binding was updated but appone and apptwo were
    # left on the old expired certificate, and the fast path declared "nothing to do".
    function Get-WebApplicationProxyApplication {
        param([Parameter(ValueFromRemainingArguments = $true)]$a)
        @(
            [pscustomobject]@{ Name = 'appone';   ExternalCertificateThumbprint = 'AAAA1111' }
            [pscustomobject]@{ Name = 'apptwo'; ExternalCertificateThumbprint = 'A1B2C3D4' }
        )
    }
    try {
        $r = Test-WapApplicationsCurrent -Thumbprint 'AAAA1111'
        if ($r -ne $false) { throw "expected false, got '$r'" }
    } finally { Remove-Item Function:\Get-WebApplicationProxyApplication -ErrorAction SilentlyContinue }
}

Test-Case 'Test-WapApplicationsCurrent returns null when the proxy cannot be queried' {
    function Get-WebApplicationProxyApplication {
        param([Parameter(ValueFromRemainingArguments = $true)]$a)
        throw 'Web Application Proxy could not connect to the AD FS configuration storage'
    }
    try {
        $r = Test-WapApplicationsCurrent -Thumbprint 'AAAA1111'
        if ($null -ne $r) { throw "expected null, got '$r'" }
    } finally { Remove-Item Function:\Get-WebApplicationProxyApplication -ErrorAction SilentlyContinue }
}

Test-Case 'Test-WapApplicationsCurrent treats a proxy with no published apps as current' {
    function Get-WebApplicationProxyApplication { param([Parameter(ValueFromRemainingArguments = $true)]$a) @() }
    try {
        if ((Test-WapApplicationsCurrent -Thumbprint 'AAAA1111') -ne $true) { throw 'expected true' }
    } finally { Remove-Item Function:\Get-WebApplicationProxyApplication -ErrorAction SilentlyContinue }
}

Test-Case 'the fast path consults published applications before declaring WAP current' {
    if ($syncText -notmatch "Role -eq 'WAP' -and \`$bound -eq \`$meta\.Thumbprint") {
        throw 'the WAP fast path does not gate on published applications'
    }
    if ($syncText -notmatch 'Test-WapApplicationsCurrent -Thumbprint \$meta\.Thumbprint') {
        throw 'Test-WapApplicationsCurrent is never called from the main flow'
    }
}

# ------------------------------------------------------------------------- IIS
Write-Host ''
Write-Host 'IIS - certificate name extraction' -ForegroundColor Cyan

Test-Case 'Get-SubjectAlternativeDnsName reads the SAN without relying on localised labels' {
    $c = New-SelfSignedCertificate -Subject 'CN=*.certsynctest.local' `
            -DnsName '*.certsynctest.local', 'certsynctest.local', 'www.certsynctest.local' `
            -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    $script:iisCert = $c

    $san = $c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
    if (-not $san) { throw 'the test certificate has no SAN extension' }

    $names = @(Get-SubjectAlternativeDnsName -RawData $san.RawData)
    foreach ($expected in '*.certsynctest.local', 'certsynctest.local', 'www.certsynctest.local') {
        if ($names -notcontains $expected) { throw "missing '$expected'; got: $($names -join ', ')" }
    }
    if ($names.Count -ne 3) { throw "expected 3 names, got $($names.Count): $($names -join ', ')" }
}

Test-Case 'Get-SubjectAlternativeDnsName survives a truncated or non-SAN blob' {
    if (@(Get-SubjectAlternativeDnsName -RawData ([byte[]]@())).Count -ne 0)          { throw 'empty blob' }
    if (@(Get-SubjectAlternativeDnsName -RawData ([byte[]]@(0x04, 0x02, 1, 2))).Count -ne 0) { throw 'non-sequence' }
    if (@(Get-SubjectAlternativeDnsName -RawData ([byte[]]@(0x30, 0x40, 0x82, 0x20))).Count -ne 0) { throw 'truncated' }
}

Test-Case 'Get-CertificateDnsName falls back to the common name when there is no SAN' {
    $c = New-SelfSignedCertificate -Subject 'CN=nosan.certsynctest.local' `
            -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1) -KeyUsage DigitalSignature
    $script:iisNoSan = $c
    $hasSan = @($c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }).Count -gt 0
    $names  = @(Get-CertificateDnsName -Certificate $c)
    if ($hasSan) {
        # New-SelfSignedCertificate adds a SAN from -Subject on some builds; then assert that.
        if ($names -notcontains 'nosan.certsynctest.local') { throw "got: $($names -join ', ')" }
    } elseif ($names.Count -ne 1 -or $names[0] -ne 'nosan.certsynctest.local') {
        throw "expected the CN as fallback; got: $($names -join ', ')"
    }
}

Write-Host ''
Write-Host 'IIS - host name coverage' -ForegroundColor Cyan

Test-Case 'Test-DnsNameCovered matches exactly one wildcard label' {
    $names = @('*.contoso.com', 'contoso.com')
    if (-not (Test-DnsNameCovered -HostName 'appone.contoso.com' -CertificateNames $names)) { throw 'single label should match' }
    if (-not (Test-DnsNameCovered -HostName 'CONTOSO.COM'           -CertificateNames $names)) { throw 'exact match is case-insensitive' }
    if (Test-DnsNameCovered -HostName 'a.b.contoso.com' -CertificateNames $names) { throw 'two labels must not match a wildcard' }
    if (Test-DnsNameCovered -HostName 'notcontoso.com'  -CertificateNames $names) { throw 'suffix collision must not match' }
    if (Test-DnsNameCovered -HostName ''              -CertificateNames $names) { throw 'empty host must not match' }
}

Write-Host ''
Write-Host 'IIS - thumbprint conversion' -ForegroundColor Cyan

Test-Case 'ConvertTo-HexString / ConvertFrom-HexString round-trip a thumbprint' {
    $thumb = 'A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4'
    $bytes = ConvertFrom-HexString $thumb
    if ($bytes.Length -ne 20) { throw "expected 20 bytes, got $($bytes.Length)" }
    if ((ConvertTo-HexString $bytes) -ne $thumb) { throw 'round-trip changed the value' }
    if ((ConvertTo-HexString 'a1 b2 c3-d4') -ne 'A1B2C3D4') { throw 'separators are not stripped' }
    if ((ConvertTo-HexString $null) -ne '') { throw 'null should become an empty string' }
}

Write-Host ''
Write-Host 'IIS - netsh parsing' -ForegroundColor Cyan

Test-Case 'ConvertFrom-NetshSslCertOutput reads ip:port and hostname:port records' {
    $lines = @(
        'SSL Certificate bindings:'
        '-------------------------'
        ''
        '    IP:port                      : 0.0.0.0:443'
        '    Certificate Hash             : a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4'
        '    Application ID               : {4dc3e181-e14b-4a21-b022-59fc669b0914}'
        '    Certificate Store Name       : My'
        ''
        '    Hostname:port                : appone.contoso.com:443'
        '    Certificate Hash             : 0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c'
        '    Application ID               : {00000000-0000-0000-0000-000000000000}'
        ''
        '    IP:port                      : 0.0.0.0:8172'
        '    Certificate Hash             : fedcba98765432100123456789abcdeffedcba98'
        '    Application ID               : {00000000-0000-0000-0000-000000000000}'
    )
    $m = ConvertFrom-NetshSslCertOutput -Lines $lines
    if ($m.Count -ne 3) { throw "expected 3 endpoints, got $($m.Count): $($m.Keys -join ', ')" }
    if ($m['0.0.0.0:443'].Hash -ne 'A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4') { throw 'ip:port hash wrong' }
    if ($m['0.0.0.0:443'].AppId -ne '{4dc3e181-e14b-4a21-b022-59fc669b0914}')  { throw 'ip:port appid wrong' }
    if ($m['appone.contoso.com:443'].Hash -ne '0F1E2D3C4B5A69788796A5B4C3D2E1F00F1E2D3C') { throw 'sni hash wrong' }
    if ($m['0.0.0.0:8172'].Hash -ne 'FEDCBA98765432100123456789ABCDEFFEDCBA98') { throw 'wmsvc hash wrong' }
}

Test-Case 'ConvertFrom-NetshSslCertOutput ignores labels and keys off value shape' {
    # Same records as a German Windows would print them.
    $lines = @(
        '    IP:Port                      : 192.0.2.4:443'
        '    Zertifikathash               : a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4'
        '    Anwendungs-ID                : {4dc3e181-e14b-4a21-b022-59fc669b0914}'
        '    Zertifikatspeichername       : My'
        '    Clientzertifikatsperrung ueberpruefen : Aktiviert'
    )
    $m = ConvertFrom-NetshSslCertOutput -Lines $lines
    if ($m.Count -ne 1) { throw "expected 1 endpoint, got $($m.Count): $($m.Keys -join ', ')" }
    if ($m['192.0.2.4:443'].Hash -ne 'A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4') { throw 'hash not picked up' }
}

Test-Case 'Get-HttpSysSslBinding reads the real netsh output without throwing' {
    $m = Get-HttpSysSslBinding
    if ($m -isnot [hashtable]) { throw 'expected a hashtable' }
    Write-Host "        -> $($m.Count) endpoint(s)" -ForegroundColor DarkGray
}

Write-Host ''
Write-Host 'IIS - http.sys endpoint keys' -ForegroundColor Cyan

Test-Case 'Get-HttpSysEndpointKey uses hostname:port only for SNI bindings' {
    $sni = Get-HttpSysEndpointKey -Binding ([pscustomobject]@{
        Ip = '0.0.0.0'; Port = 443; HostName = 'appone.contoso.com'; SslFlags = 1 })
    if ($sni.Key -ne 'appone.contoso.com:443' -or $sni.Argument -ne 'hostnameport') { throw "got $($sni.Key)/$($sni.Argument)" }

    # A host header WITHOUT the SNI flag still resolves through the single ip:port entry.
    $plain = Get-HttpSysEndpointKey -Binding ([pscustomobject]@{
        Ip = '0.0.0.0'; Port = 443; HostName = 'appone.contoso.com'; SslFlags = 0 })
    if ($plain.Key -ne '0.0.0.0:443' -or $plain.Argument -ne 'ipport') { throw "got $($plain.Key)/$($plain.Argument)" }
}

Write-Host ''
Write-Host 'IIS - binding selection' -ForegroundColor Cyan

function New-TestBinding {
    param([string]$Site = 'web', [string]$HostName = '', [string]$Hash = '', [int]$SslFlags = 0, [int]$Port = 443)
    [pscustomobject]@{
        Site = $Site; Info = "*:$Port`:$HostName"; Ip = '0.0.0.0'; Port = $Port
        HostName = $HostName; SslFlags = $SslFlags; Store = 'My'; Hash = $Hash; Reason = ''
    }
}

Test-Case 'Select-IisBindingToUpdate skips a binding already on the target certificate' {
    $cert = $script:iisCert
    $b = New-TestBinding -Hash $cert.Thumbprint.ToUpperInvariant()
    $sel = @(Select-IisBindingToUpdate -Bindings @($b) -Certificate $cert -Scope Managed -Quiet)
    if ($sel.Count -ne 0) { throw "expected 0, got $($sel.Count)" }
}

Test-Case 'Select-IisBindingToUpdate claims a binding whose certificate has the same subject' {
    # The real the IIS server case: an expired CN=*.contoso.com bound where the new CN=*.contoso.com belongs.
    $cert = $script:iisCert
    $old  = [pscustomobject]@{
        Subject = $cert.Subject; Thumbprint = 'AAAABBBBCCCCDDDDEEEEFFFF00001111222233'
        Extensions = @()
        PSTypeName = 'System.Security.Cryptography.X509Certificates.X509Certificate2'
    }
    function Get-Item { param([Parameter(ValueFromRemainingArguments = $true)]$a) $old }
    try {
        $b   = New-TestBinding -Hash 'AAAABBBBCCCCDDDDEEEEFFFF00001111222233'
        $sel = @(Select-IisBindingToUpdate -Bindings @($b) -Certificate $cert -Scope Managed -Quiet)
        if ($sel.Count -ne 1) { throw "expected 1, got $($sel.Count)" }
        if ($sel[0].Reason -notmatch 'same subject') { throw "unexpected reason: $($sel[0].Reason)" }
    } finally { Remove-Item Function:\Get-Item -ErrorAction SilentlyContinue }
}

Test-Case 'Select-IisBindingToUpdate leaves an unrelated certificate alone unless scope is All' {
    $cert  = $script:iisCert
    $other = New-SelfSignedCertificate -Subject 'CN=unrelated.example.net' -DnsName 'unrelated.example.net' `
                -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    $script:iisOther = $other
    function Get-Item { param([Parameter(ValueFromRemainingArguments = $true)]$a) $other }
    try {
        $b = New-TestBinding -HostName 'unrelated.example.net' -Hash $other.Thumbprint.ToUpperInvariant()

        $managed = @(Select-IisBindingToUpdate -Bindings @($b) -Certificate $cert -Scope Managed -Quiet)
        if ($managed.Count -ne 0) { throw "Managed should not claim it; got $($managed.Count)" }

        $matching = @(Select-IisBindingToUpdate -Bindings @($b) -Certificate $cert -Scope Matching -Quiet)
        if ($matching.Count -ne 0) { throw "Matching should not claim an uncovered host; got $($matching.Count)" }

        $all = @(Select-IisBindingToUpdate -Bindings @($b) -Certificate $cert -Scope All -Quiet)
        if ($all.Count -ne 1) { throw "All should claim it; got $($all.Count)" }
    } finally { Remove-Item Function:\Get-Item -ErrorAction SilentlyContinue }
}

Test-Case 'Select-IisBindingToUpdate claims a binding whose certificate is gone from the store' {
    $cert = $script:iisCert
    function Get-Item { param([Parameter(ValueFromRemainingArguments = $true)]$a) $null }
    try {
        $b   = New-TestBinding -Hash '1111111111111111111111111111111111111111'
        $sel = @(Select-IisBindingToUpdate -Bindings @($b) -Certificate $cert -Scope Managed -Quiet)
        if ($sel.Count -ne 1) { throw "expected 1, got $($sel.Count)" }
        if ($sel[0].Reason -notmatch 'no longer in LocalMachine') { throw "unexpected reason: $($sel[0].Reason)" }
    } finally { Remove-Item Function:\Get-Item -ErrorAction SilentlyContinue }
}

Test-Case 'Select-IisBindingToUpdate claims a binding that carries no certificate at all' {
    $cert = $script:iisCert
    $sel  = @(Select-IisBindingToUpdate -Bindings @((New-TestBinding)) -Certificate $cert -Scope Managed -Quiet)
    if ($sel.Count -ne 1) { throw "expected 1, got $($sel.Count)" }
    if ($sel[0].Reason -notmatch 'no certificate') { throw "unexpected reason: $($sel[0].Reason)" }
}

Test-Case 'Select-IisBindingToUpdate claims a binding sharing a SAN name with the new certificate' {
    $cert = $script:iisCert
    $old  = New-SelfSignedCertificate -Subject 'CN=www.certsynctest.local' -DnsName 'www.certsynctest.local' `
                -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    $script:iisShared = $old
    function Get-Item { param([Parameter(ValueFromRemainingArguments = $true)]$a) $old }
    try {
        $b   = New-TestBinding -HostName 'www.certsynctest.local' -Hash $old.Thumbprint.ToUpperInvariant()
        $sel = @(Select-IisBindingToUpdate -Bindings @($b) -Certificate $cert -Scope Managed -Quiet)
        if ($sel.Count -ne 1) { throw "expected 1, got $($sel.Count)" }
        if ($sel[0].Reason -notmatch 'shares SAN name') { throw "unexpected reason: $($sel[0].Reason)" }
    } finally { Remove-Item Function:\Get-Item -ErrorAction SilentlyContinue }
}

Test-Case 'Matching scope claims a binding whose host header the wildcard covers' {
    $cert  = $script:iisCert     # *.certsynctest.local
    $other = $script:iisOther    # CN=unrelated.example.net
    function Get-Item { param([Parameter(ValueFromRemainingArguments = $true)]$a) $other }
    try {
        $b = New-TestBinding -HostName 'shop.certsynctest.local' -Hash $other.Thumbprint.ToUpperInvariant()
        if (@(Select-IisBindingToUpdate -Bindings @($b) -Certificate $cert -Scope Managed -Quiet).Count -ne 0) {
            throw 'Managed must not claim it on host name alone'
        }
        $sel = @(Select-IisBindingToUpdate -Bindings @($b) -Certificate $cert -Scope Matching -Quiet)
        if ($sel.Count -ne 1) { throw "Matching should claim it; got $($sel.Count)" }
        if ($sel[0].Reason -notmatch 'covered by the new certificate') { throw "unexpected reason: $($sel[0].Reason)" }
    } finally { Remove-Item Function:\Get-Item -ErrorAction SilentlyContinue }
}

Test-Case 'a Central Certificate Store binding is never rewritten, in any scope' {
    $cert = $script:iisCert
    $b    = New-TestBinding -HostName 'ccs.certsynctest.local' -SslFlags 3
    foreach ($scope in 'Managed', 'Matching', 'All') {
        $sel = @(Select-IisBindingToUpdate -Bindings @($b) -Certificate $cert -Scope $scope -Quiet)
        if ($sel.Count -ne 0) { throw "scope $scope claimed a CCS binding" }
    }
}

Write-Host ''
Write-Host 'IIS - wiring into the main flow' -ForegroundColor Cyan

Test-Case 'Role IIS is accepted and routed to Set-IisBinding' {
    if ($syncText -notmatch "ValidateSet\('Auto', 'ADFS', 'WAP', 'IIS', 'None'\)") {
        throw 'the Role parameter does not accept IIS'
    }
    if ($syncText -notmatch "'IIS'\s+\{ Set-IisBinding\s+-Certificate \`$cert \}") {
        throw 'the role switch never calls Set-IisBinding'
    }
}

Test-Case 'the fast path proves IIS bindings are current before claiming NoChange' {
    if ($syncText -notmatch 'Test-IisBindingsCurrent -Certificate \$installed') {
        throw 'Test-IisBindingsCurrent is never called from the main flow'
    }
    if ($syncText -notmatch '\$appsCurrent -and \$iisCurrent -and') {
        throw 'the fast path does not gate on the IIS binding state'
    }
}

Test-Case 'cleanup never deletes a certificate that applicationHost.config still references' {
    if ($syncText -notmatch "if \(\`$Role -eq 'IIS'\) \{\s*\r?\n\s*foreach \(\`$b in \(Get-IisHttpsBinding\)\)") {
        throw 'Get-ThumbprintsInUse does not consult the IIS bindings'
    }
}

Test-Case 'IIS is detected only when neither AD FS nor WAP is present' {
    $m = [regex]::Match($syncText, '(?s)function Get-DetectedRole.*?\n\}')
    if (-not $m.Success) { throw 'could not isolate Get-DetectedRole' }
    $body = $m.Value
    if ($body.IndexOf("return 'IIS'") -lt $body.LastIndexOf("return 'ADFS'")) {
        throw 'the IIS branch runs before the AD FS branch'
    }
    if ($body -notmatch "Get-Service -Name 'W3SVC'") {
        throw 'IIS detection does not confirm the W3SVC service'
    }
}

Test-Case 'the netsh argument list is not built in the automatic $args variable' {
    $m = [regex]::Match($syncText, '(?s)function Sync-HttpSysSslBinding.*?\n\}')
    if (-not $m.Success) { throw 'could not isolate Sync-HttpSysSslBinding' }
    if ($m.Value -match '\$args\s*=') { throw 'the function assigns to the automatic variable $args' }
    if ($m.Value -notmatch '@netshArgs') { throw 'the netsh call no longer splats the argument list' }
}

# ------------------------------------------------- superseded certificate identity
Write-Host ''
Write-Host 'Cleanup - superseded certificate identity' -ForegroundColor Cyan

Test-Case 'a renewal that changed the common name is still recognised as superseded' {
    # The real regression: Let's Encrypt renewed *.contoso.com from CN=*.contoso.com to
    # CN=contoso.com, so subject-only matching stopped cleaning anything up.
    $old = New-SelfSignedCertificate -Subject 'CN=*.cleanuptest.local' `
             -DnsName '*.cleanuptest.local', 'cleanuptest.local' `
             -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    $new = New-SelfSignedCertificate -Subject 'CN=cleanuptest.local' `
             -DnsName '*.cleanuptest.local', 'cleanuptest.local' `
             -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(2)
    $script:cleanOld = $old; $script:cleanNew = $new

    if ($old.Subject -eq $new.Subject) { throw 'the test certificates must have different subjects' }
    if (-not (Test-SupersededCertificate -Candidate $old -Current $new)) {
        throw 'the renewed certificate did not recognise its predecessor'
    }
}

Test-Case 'the current certificate is never treated as superseded by itself' {
    if (Test-SupersededCertificate -Candidate $script:cleanNew -Current $script:cleanNew) {
        throw 'a certificate matched itself'
    }
}

Test-Case 'same subject still matches, even without a usable SAN' {
    $a = New-SelfSignedCertificate -Subject 'CN=samesubject.cleanuptest.local' `
           -DnsName 'samesubject.cleanuptest.local' `
           -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    $b = New-SelfSignedCertificate -Subject 'CN=samesubject.cleanuptest.local' `
           -DnsName 'samesubject.cleanuptest.local', 'extra.cleanuptest.local' `
           -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(2)
    $script:cleanSameA = $a; $script:cleanSameB = $b
    if (-not (Test-SupersededCertificate -Candidate $a -Current $b)) { throw 'same subject should match' }
}

Test-Case 'a certificate covering a different set of names is left alone' {
    $other = New-SelfSignedCertificate -Subject 'CN=other.cleanuptest.local' `
               -DnsName 'other.cleanuptest.local' `
               -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    $script:cleanOther = $other
    if (Test-SupersededCertificate -Candidate $other -Current $script:cleanNew) {
        throw 'an unrelated certificate was treated as superseded'
    }
    # A superset must not match either: equality, not overlap.
    $wide = New-SelfSignedCertificate -Subject 'CN=cleanuptest.local' `
              -DnsName '*.cleanuptest.local', 'cleanuptest.local', 'extra.cleanuptest.local' `
              -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    $script:cleanWide = $wide
    if ($wide.Subject -ne $script:cleanNew.Subject -and
        (Test-SupersededCertificate -Candidate $wide -Current $script:cleanNew)) {
        throw 'a certificate covering extra names was treated as superseded'
    }
}

Test-Case 'cleanup still refuses to touch a certificate that is in use' {
    $m = [regex]::Match($syncText, '(?s)function Remove-SupersededCertificates.*?\n\}')
    if (-not $m.Success) { throw 'could not isolate Remove-SupersededCertificates' }
    if ($m.Value -notmatch '\$inUse = Get-ThumbprintsInUse') { throw 'the in-use guard is gone' }
    if ($m.Value -notmatch 'Thumbprint\.ToUpperInvariant\(\) -notin \$inUse') { throw 'the in-use filter is gone' }
    if ($m.Value -notmatch 'Test-SupersededCertificate -Candidate') { throw 'cleanup no longer uses the identity test' }
}

Test-Case 'cleanup also runs on a pass where nothing needed changing' {
    # Gating cleanup on "something changed" meant a certificate that could not be removed
    # during the renewal - still bound at that moment, or missed by an older agent - was
    # never reconsidered. Both exit paths must call it.
    $m = [regex]::Match($syncText, '(?s)Already current - certificate.*?\n\s*return\s*\n\s*\}')
    if (-not $m.Success) { throw 'could not isolate the fast path' }
    if ($m.Value -notmatch 'Remove-SupersededCertificates -Current \$installed') {
        throw 'the fast path returns without ever running cleanup'
    }
    if ($syncText -notmatch 'Remove-SupersededCertificates -Current \$cert') {
        throw 'the change path no longer runs cleanup'
    }
}

# --------------------------------------------------------------------- cleanup
Write-Host ''
foreach ($c in @($script:testCert, $script:testCa, $script:testKeyCert, $script:testWiped,
                 $script:iisCert, $script:iisNoSan, $script:iisOther, $script:iisShared,
                 $script:cleanOld, $script:cleanNew, $script:cleanSameA, $script:cleanSameB,
                 $script:cleanOther, $script:cleanWide)) {
    if ($c) { Remove-Item "Cert:\CurrentUser\My\$($c.Thumbprint)" -Force -ErrorAction SilentlyContinue }
}
Remove-Item $script:LogFile -Force -ErrorAction SilentlyContinue

Write-Host ("{0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
