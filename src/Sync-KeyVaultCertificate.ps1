<#
.SYNOPSIS
    Pulls the current version of a certificate (including private key) from Azure Key Vault
    and installs + binds it on an AD FS, Web Application Proxy (WAP) or IIS server.

.DESCRIPTION
    Designed to run unattended as SYSTEM on each AD FS / WAP / IIS node.

    Uses only in-box Windows components:
      * Windows PowerShell 5.1
      * .NET Framework X509 classes
      * The ADFS / WebApplicationProxy modules that ship with the role
      * Microsoft.Web.Administration for IIS (ships with the Web-Server role)
    No Az modules, no Python, no third-party binaries.

    Authentication is passwordless. The script obtains an OAuth token from the local
    Instance Metadata Service:
      * Azure VM              -> http://169.254.169.254/metadata/identity/...
      * Azure Arc-enabled VM  -> http://localhost:40342/metadata/identity/...  (challenge/response)
    The VM's managed identity needs the "Key Vault Secrets User" role (or a get-secret
    access policy) on the vault.

    The script is idempotent and safe to run every hour. If the certificate currently
    bound to the role already matches the latest Key Vault version, it exits without
    touching anything.

.PARAMETER VaultName
    Short name of the Key Vault, e.g. 'kv-contoso-acmebot'.

.PARAMETER CertificateName
    Name of the certificate object in Key Vault, e.g. 'contoso-com' (for *.contoso.com).

.PARAMETER Role
    Auto (default) | ADFS | WAP | IIS | None. 'Auto' detects the installed role.
    'None' imports the certificate only (no binding) - useful for load balancers.

.PARAMETER IisBindingScope
    Which IIS https bindings this agent is allowed to re-point. Only used when Role = IIS.

    Managed (default) - a binding is re-pointed when the certificate currently on it is one
                        this agent can legitimately claim: it is missing from LocalMachine\My,
                        the binding carries no certificate at all, or the bound certificate
                        shares a Subject or a SAN DNS name with the Key Vault certificate.
                        Bindings holding an unrelated certificate are left alone and logged.
    Matching          - Managed, plus any binding whose host header is covered by the Key Vault
                        certificate (wildcards honoured).
    All               - every https binding on the server, regardless of what is on it today.
                        Use only when the box serves exactly one certificate.

.PARAMETER IisSites
    Restrict IIS binding updates to these site names. Default: every site.

.PARAMETER IdentityClientId
    Client ID of a user-assigned managed identity to authenticate with.

    Only needed when the machine has more than one identity attached. A VM with BOTH a
    system-assigned and one or more user-assigned identities defaults to the system-assigned
    one; a VM with several user-assigned identities and no system-assigned one cannot pick for
    itself and IMDS returns an error. Setting this removes the ambiguity in every case, so it
    is worth pinning explicitly on any VM that has more than one identity.

.PARAMETER AdditionalPrivateKeyReaders
    Extra identities to grant Read on the private key, e.g. 'CONTOSO\svc-monitor'.

.PARAMETER CleanupMode
    None | Expired (default) | KeepLatest. Controls removal of superseded certificates from
    LocalMachine\My. A certificate counts as superseded when it has the same subject as the
    new one OR covers exactly the same set of DNS names - ACME issuers change the common name
    between renewals, so subject alone is not a reliable identity. Certificates that are
    still bound anywhere (http.sys, AD FS, IIS configuration) are never removed.

.PARAMETER KeepLatest
    Used with -CleanupMode KeepLatest. Number of superseded certs to keep. Default 1.

.PARAMETER Force
    Re-import and re-bind even when the thumbprint already matches.

.PARAMETER ForceLocalBinding
    On an AD FS secondary node in a 2016+ farm, force Set-AdfsSslCertificate locally
    instead of letting the primary replicate it.

.PARAMETER SkipServiceRestart
    Import and bind but do not restart adfssrv / appproxysvc. Use for a maintenance window.
    IIS is never restarted: http.sys serves the new certificate to new connections as soon
    as the binding is rewritten, so a restart would be pure downtime.

.PARAMETER Exportable
    Mark the imported private key exportable. Off by default (recommended).

.EXAMPLE
    .\Sync-KeyVaultCertificate.ps1 -VaultName kv-contoso-acmebot -CertificateName contoso-com

.EXAMPLE
    .\Sync-KeyVaultCertificate.ps1 -VaultName kv-contoso-acmebot -CertificateName contoso-com -WhatIf

.NOTES
    Exit codes: 0 = success (changed or already current), 1 = failure.
    Logs to Application event log, source 'KeyVaultCertSync', plus a rolling text log
    under %ProgramData%\KeyVaultCertSync\Logs.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$VaultName,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$CertificateName,
    [ValidateSet('Auto', 'ADFS', 'WAP', 'IIS', 'None')][string]$Role = 'Auto',
    [ValidateSet('Managed', 'Matching', 'All')][string]$IisBindingScope = 'Managed',
    [string[]]$IisSites = @(),
    [string]$IdentityClientId,
    [string[]]$AdditionalPrivateKeyReaders = @(),
    [ValidateSet('None', 'Expired', 'KeepLatest')][string]$CleanupMode = 'Expired',
    [int]$KeepLatest = 1,
    [string]$VaultDnsSuffix = 'vault.azure.net',
    [switch]$Force,
    [switch]$ForceLocalBinding,
    [switch]$SkipServiceRestart,
    [switch]$Exportable
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:EventSource   = 'KeyVaultCertSync'
$script:StateRoot     = Join-Path $env:ProgramData 'KeyVaultCertSync'
$script:LogFile       = Join-Path $script:StateRoot ('Logs\sync-{0}.log' -f (Get-Date -Format 'yyyyMM'))
$script:StateFile     = Join-Path $script:StateRoot 'state.json'
$script:EventLogReady = $false
$script:Changed       = $false

#region ---------------------------------------------------------------- logging

function Initialize-Logging {
    foreach ($p in @($script:StateRoot, (Split-Path $script:LogFile -Parent))) {
        # -WhatIf must never suppress logging infrastructure; it only governs real changes.
        if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force -WhatIf:$false | Out-Null }
    }
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($script:EventSource)) {
            [System.Diagnostics.EventLog]::CreateEventSource($script:EventSource, 'Application')
        }
        $script:EventLogReady = $true
    } catch {
        $script:EventLogReady = $false
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('Information', 'Warning', 'Error')][string]$Level = 'Information',
        [int]$EventId = 1000
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level.Substring(0, 4).ToUpper(), $Message
    switch ($Level) {
        'Error'   { Write-Host $line -ForegroundColor Red }
        'Warning' { Write-Host $line -ForegroundColor Yellow }
        default   { Write-Host $line }
    }
    try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 -WhatIf:$false } catch { }
    if ($script:EventLogReady) {
        try {
            Write-EventLog -LogName Application -Source $script:EventSource -EntryType $Level `
                           -EventId $EventId -Message $Message
        } catch { }
    }
}

function Save-State {
    <# Small JSON breadcrumb so monitoring can assert "this node is current". #>
    param($Meta, [string]$Status)
    try {
        [pscustomobject]@{
            Computer        = $env:COMPUTERNAME
            Vault           = $VaultName
            Certificate     = $CertificateName
            Role            = $Role
            Thumbprint      = $Meta.Thumbprint
            KeyVaultVersion = $Meta.Version
            ExpiresUtc      = $Meta.Expires.ToString('o')
            DaysRemaining   = [int]($Meta.Expires - [DateTime]::UtcNow).TotalDays
            Status          = $Status
            LastRunUtc      = ([DateTime]::UtcNow).ToString('o')
        } | ConvertTo-Json | Set-Content -Path $script:StateFile -Encoding UTF8
    } catch {
        Write-Log "Could not write state file: $($_.Exception.Message)" -Level Warning -EventId 2008
    }
}

#endregion

#region ------------------------------------------------- managed identity token

function Get-ManagedIdentityToken {
    <#
        Returns an access token for the given resource using the local managed identity.
        Supports Azure VM IMDS and Azure Arc (challenge/response). No modules required.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Resource,
        [string]$ClientId
    )

    # --- Azure Arc: the presence of IMDS_ENDPOINT/IDENTITY_ENDPOINT wins ---------
    $arcEndpoint = $env:IDENTITY_ENDPOINT
    if (-not $arcEndpoint -and (Test-Path 'HKLM:\SOFTWARE\Microsoft\Azure Connected Machine Agent')) {
        $arcEndpoint = 'http://localhost:40342/metadata/identity/oauth2/token'
    }
    if ($arcEndpoint) {
        try { return Get-ArcToken -Endpoint $arcEndpoint -Resource $Resource }
        catch { Write-Log "Arc identity attempt failed: $($_.Exception.Message)" -Level Warning -EventId 2001 }
    }

    # --- Azure VM IMDS ----------------------------------------------------------
    $uri = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={0}' -f `
           [uri]::EscapeDataString($Resource)
    if ($ClientId) {
        $uri += '&client_id={0}' -f [uri]::EscapeDataString($ClientId)
        Write-Log "Requesting a token for user-assigned identity client_id=$ClientId."
    }

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $r = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ Metadata = 'true' } -TimeoutSec 20
            return $r.access_token
        } catch {
            $detail = Get-HttpErrorBody -ErrorRecord $_

            # A machine with multiple identities and no default cannot choose one for itself.
            # Retrying will never fix that, so fail immediately with the actionable message.
            if ($detail -match 'multiple|ambiguous|identity_not_found|more than one') {
                throw ("IMDS could not decide which managed identity to use on this machine. " +
                       "Re-run with -IdentityClientId <clientId of the intended user-assigned identity>. " +
                       "IMDS said: $detail")
            }
            if ($attempt -ge 4) {
                $hint = if ($ClientId) {
                    "Confirm the user-assigned identity with client_id '$ClientId' is actually attached to this machine."
                } else {
                    "Confirm a system- or user-assigned managed identity is enabled on this machine " +
                    "(or that the Azure Arc agent is connected). If several identities are attached, " +
                    "pass -IdentityClientId to pick one."
                }
                throw ("Could not obtain a managed identity token from IMDS after $attempt attempts. $hint " +
                       "Underlying error: $($_.Exception.Message)$(if ($detail) { " / $detail" })")
            }
            Start-Sleep -Seconds ([math]::Pow(2, $attempt))
        }
    }
}

function Get-HttpErrorBody {
    <# Pulls the response body out of a failed Invoke-RestMethod so errors are diagnosable. #>
    param($ErrorRecord)
    try {
        $resp = $ErrorRecord.Exception.Response
        if (-not $resp) { return $null }
        $stream = $resp.GetResponseStream()
        if (-not $stream) { return $null }
        $reader = New-Object System.IO.StreamReader($stream)
        try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
    } catch { return $null }
}

function Get-ArcToken {
    param([string]$Endpoint, [string]$Resource)

    $uri = '{0}?api-version=2020-06-01&resource={1}' -f $Endpoint, [uri]::EscapeDataString($Resource)
    $challengeFile = $null
    try {
        Invoke-WebRequest -Method Get -Uri $uri -Headers @{ Metadata = 'true' } -UseBasicParsing -TimeoutSec 20 | Out-Null
    } catch {
        $resp = $_.Exception.Response
        if ($null -eq $resp) { throw }
        $auth = $resp.Headers['WWW-Authenticate']
        if ($auth -match 'realm=(.+)$') { $challengeFile = $Matches[1].Trim() }
    }
    if (-not $challengeFile) { throw 'Arc identity endpoint did not return a WWW-Authenticate challenge.' }
    if (-not (Test-Path $challengeFile)) {
        throw ("Arc challenge file '$challengeFile' is not readable. Add the account running this script " +
               "to the local 'Hybrid agent extension applications' group.")
    }
    $secret = Get-Content -Path $challengeFile -Raw
    $r = Invoke-RestMethod -Method Get -Uri $uri -TimeoutSec 20 `
            -Headers @{ Metadata = 'true'; Authorization = "Basic $secret" }
    return $r.access_token
}

#endregion

#region ------------------------------------------------------------- key vault

function ConvertFrom-Base64Url {
    param([string]$Value)
    $s = $Value.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } 1 { throw 'Invalid base64url.' } }
    return [Convert]::FromBase64String($s)
}

function Get-KeyVaultCertificateMetadata {
    <# Cheap call: returns thumbprint + expiry of the current version without pulling the key. #>
    param([string]$Token, [string]$BaseUri, [string]$Name)

    $uri = '{0}/certificates/{1}?api-version=7.4' -f $BaseUri, $Name
    $c = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ Authorization = "Bearer $Token" } -TimeoutSec 60

    $attr = $c.attributes
    $nbf = if ($attr.PSObject.Properties.Name -contains 'nbf' -and $attr.nbf) {
               [DateTimeOffset]::FromUnixTimeSeconds([long]$attr.nbf).UtcDateTime
           } else { [DateTime]::MinValue }
    $exp = if ($attr.PSObject.Properties.Name -contains 'exp' -and $attr.exp) {
               [DateTimeOffset]::FromUnixTimeSeconds([long]$attr.exp).UtcDateTime
           } else { [DateTime]::MaxValue }

    [pscustomobject]@{
        Thumbprint = ([BitConverter]::ToString((ConvertFrom-Base64Url $c.x5t)) -replace '-', '').ToUpperInvariant()
        Version    = ($c.id -split '/')[-1]
        NotBefore  = $nbf
        Expires    = $exp
        Enabled    = [bool]$attr.enabled
    }
}

function Get-KeyVaultPfxBytes {
    <# The secret behind a KV certificate is the base64 PKCS#12 blob (no password). #>
    param([string]$Token, [string]$BaseUri, [string]$Name)

    $uri = '{0}/secrets/{1}?api-version=7.4' -f $BaseUri, $Name
    $s = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ Authorization = "Bearer $Token" } -TimeoutSec 120

    $contentType = if ($s.PSObject.Properties.Name -contains 'contentType') { $s.contentType } else { '' }
    if ($contentType -and $contentType -notmatch 'pkcs12') {
        throw ("Key Vault secret '$Name' has content type '$contentType'. This script requires a " +
               "PKCS#12 (PFX) backed certificate. Re-issue the certificate with a PFX policy.")
    }
    return [Convert]::FromBase64String($s.value)
}

#endregion

#region ------------------------------------------------------- certificate store

function ConvertTo-Sid {
    <#
        Resolves an account name to its SID.

        Needed because a Windows account has several display forms. A service reports its
        logon account as 'NT AUTHORITY\NetworkService' (Win32_Service.StartName) while the
        same account appears in an ACL as 'NT AUTHORITY\NETWORK SERVICE'. Comparing those
        two strings says "different"; comparing SIDs says "same".
    #>
    param([string]$Identity)
    if (-not $Identity) { return $null }
    try {
        if ($Identity -match '^S-1-') { return $Identity }
        return (New-Object System.Security.Principal.NTAccount($Identity)
               ).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $null
    }
}

function Test-AclGrantsRead {
    <# True when the ACL already grants Read to the given identity, compared by SID. #>
    param($Acl, [string]$Identity)

    $wantSid = ConvertTo-Sid -Identity $Identity
    foreach ($rule in $Acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if (-not ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read)) { continue }

        $ruleSid = $null
        try {
            $ruleSid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            $ruleSid = ConvertTo-Sid -Identity $rule.IdentityReference.Value
        }
        if ($wantSid -and $ruleSid -and $ruleSid -eq $wantSid) { return $true }
        if (-not $wantSid -and $rule.IdentityReference.Value -ieq $Identity) { return $true }
    }
    return $false
}

function Import-PfxToLocalMachine {
    <#
        Imports the leaf into LocalMachine\My (machine key set, persisted) and any
        chain certificates into LocalMachine\CA. Returns the leaf X509Certificate2.
    #>
    param([byte[]]$PfxBytes, [switch]$AllowExport)

    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor `
             [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
    if ($AllowExport) {
        $flags = $flags -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    }

    $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    try {
        $collection.Import($PfxBytes, $null, $flags)
    } catch {
        # Some Key Vault policies emit an empty-string password instead of none.
        $collection.Import($PfxBytes, '', $flags)
    }

    $leaf = $collection | Where-Object { $_.HasPrivateKey } | Select-Object -First 1
    if (-not $leaf) { throw 'The PFX from Key Vault contains no certificate with a private key.' }

    $my = New-Object System.Security.Cryptography.X509Certificates.X509Store 'My', 'LocalMachine'
    $my.Open('ReadWrite')
    try { $my.Add($leaf) } finally { $my.Close() }
    Write-Log "Imported leaf $($leaf.Thumbprint) ($($leaf.Subject)) into LocalMachine\My." -EventId 1002

    foreach ($chainCert in ($collection | Where-Object { -not $_.HasPrivateKey })) {
        $storeName = if ($chainCert.Subject -eq $chainCert.Issuer) { 'Root' } else { 'CA' }
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store $storeName, 'LocalMachine'
        $store.Open('ReadWrite')
        try {
            if (-not ($store.Certificates | Where-Object { $_.Thumbprint -eq $chainCert.Thumbprint })) {
                $store.Add($chainCert)
                Write-Log "Added chain certificate '$($chainCert.Subject)' to LocalMachine\$storeName." -EventId 1002
            }
        } finally { $store.Close() }
    }

    # Re-read from the store so we get the store-backed handle with the persisted key.
    return Get-Item "Cert:\LocalMachine\My\$($leaf.Thumbprint)"
}

function Grant-PrivateKeyRead {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string[]]$Identities
    )
    if (-not $Identities -or $Identities.Count -eq 0) { return }

    $keyFile = Resolve-PrivateKeyFile -Certificate $Certificate
    if (-not $keyFile) {
        Write-Log ("Could not locate the private key file for $($Certificate.Thumbprint) on disk, so the " +
                   "private key ACL was NOT updated. AD FS / WAP may fail to start with " +
                   "'the private key is not accessible'. Fix manually with certlm.msc -> the certificate " +
                   "-> All Tasks -> Manage Private Keys -> add: $($Identities -join ', ')") `
                  -Level Error -EventId 2002
        return
    }

    $acl = Get-Acl -Path $keyFile
    $dirty = $false
    $granted = New-Object System.Collections.Generic.List[string]
    foreach ($id in ($Identities | Where-Object { $_ } | Select-Object -Unique)) {
        try {
            if (Test-AclGrantsRead -Acl $acl -Identity $id) { continue }
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'Read', 'Allow')
            $acl.AddAccessRule($rule)
            $granted.Add($id)
            $dirty = $true
        } catch {
            Write-Log "Could not add ACL for '$id': $($_.Exception.Message)" -Level Warning -EventId 2003
        }
    }
    if (-not $dirty) {
        Write-Log 'Private key ACL already grants Read to every required identity.'
        return
    }
    if ($PSCmdlet.ShouldProcess($keyFile, 'Update private key ACL')) {
        Set-Acl -Path $keyFile -AclObject $acl
        # Verify rather than assume - a silently missing ACL breaks the service at restart.
        $check = Get-Acl -Path $keyFile
        foreach ($id in $granted) {
            if (Test-AclGrantsRead -Acl $check -Identity $id) {
                Write-Log "Granted Read on the private key to '$id'."
            } else {
                Write-Log "ACL for '$id' did not persist on $keyFile." -Level Error -EventId 2003
            }
        }
    }
}

function Resolve-PrivateKeyFile {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $uniqueName = Get-KeyContainerName -Certificate $Certificate

    if (-not $uniqueName) {
        # An in-memory X509Certificate2 can lose its key handle (for example after the object
        # has been used in an X509Certificate2Collection.Export call). Re-open a clean handle
        # from the store and try again before giving up.
        foreach ($storeName in 'My', 'WebHosting') {
            try {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store $storeName, 'LocalMachine'
                $store.Open('ReadOnly')
                try {
                    $fresh = $store.Certificates | Where-Object { $_.Thumbprint -eq $Certificate.Thumbprint } |
                             Select-Object -First 1
                    if ($fresh) { $uniqueName = Get-KeyContainerName -Certificate $fresh }
                } finally { $store.Close() }
            } catch { }
            if ($uniqueName) {
                Write-Log "Recovered the private key handle by re-reading LocalMachine\$storeName."
                break
            }
        }
    }

    if (-not $uniqueName) { return $null }
    if (Test-Path -LiteralPath $uniqueName) { return (Resolve-Path -LiteralPath $uniqueName).Path }

    # Machine key locations first - that is where a LocalMachine\My certificate always lands.
    # The user locations are a fallback so the function stays verifiable outside of a role server.
    $roots = @(
        (Join-Path $env:ProgramData 'Microsoft\Crypto\RSA\MachineKeys'),
        (Join-Path $env:ProgramData 'Microsoft\Crypto\Keys'),
        (Join-Path $env:ProgramData 'Microsoft\Crypto\SystemKeys'),
        (Join-Path $env:ProgramData 'Microsoft\Crypto\PCPKSP'),
        (Join-Path $env:APPDATA    'Microsoft\Crypto\Keys'),
        (Join-Path $env:APPDATA    'Microsoft\Crypto\RSA')
    )
    foreach ($root in $roots) {
        $candidate = Join-Path $root $uniqueName
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $found = Get-ChildItem -Path (Join-Path $env:ProgramData 'Microsoft\Crypto') -Recurse -Filter $uniqueName `
                           -Force -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return $found.FullName }
    return $null
}

function Get-KeyContainerName {
    <# Returns the on-disk key container file name for a certificate, or $null. #>
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    if (-not $Certificate -or -not $Certificate.HasPrivateKey) { return $null }

    $rsa = $null
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        if ($rsa -is [System.Security.Cryptography.RSACng]) {
            $n = $rsa.Key.UniqueName
        } elseif ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
            $n = $rsa.CspKeyContainerInfo.UniqueKeyContainerName
        } else {
            $n = $null
        }
        if ($n -and "$n".Trim()) { return "$n" }
        return $null
    } catch {
        Write-Log "Could not read the private key handle: $($_.Exception.Message)" -Level Warning -EventId 2004
        return $null
    } finally {
        if ($rsa -and $rsa -is [IDisposable]) { $rsa.Dispose() }
    }
}

#endregion

#region ----------------------------------------------------------- role binding

function Get-DetectedRole {
    <#
        Determines what this machine actually is.

        Service presence alone is NOT sufficient. A Web Application Proxy server also carries
        a running 'adfssrv' service because the proxy ships the same service host binary, even
        though the AD FS role itself is not installed. Verified on Windows Server 2025:
        WAP box reported adfssrv=Running while Get-WindowsFeature ADFS-Federation was
        Installed=False and the ADFS PowerShell module did not exist. Detecting on the service
        alone would classify every WAP server as AD FS.

        Order of evidence: installed role features, then cmdlet availability, then services.
        IIS is only ever returned when neither AD FS nor WAP is present - on a box that is
        both, the federation role owns the certificate and IIS is incidental.
    #>

    # 1. Role features - the authoritative signal.
    try {
        Import-Module ServerManager -ErrorAction Stop
        $f = Get-WindowsFeature -Name 'ADFS-Federation', 'Web-Application-Proxy' -ErrorAction Stop
        $adfsInstalled = [bool](($f | Where-Object { $_.Name -eq 'ADFS-Federation' }).Installed)
        $wapInstalled  = [bool](($f | Where-Object { $_.Name -eq 'Web-Application-Proxy' }).Installed)

        if ($adfsInstalled -and -not $wapInstalled) { return 'ADFS' }
        if ($wapInstalled  -and -not $adfsInstalled) { return 'WAP' }
        if ($adfsInstalled -and $wapInstalled) {
            # Unsupported by Microsoft but possible in a lab. AD FS owns the certificate.
            Write-Log ('Both the AD FS and Web Application Proxy roles are installed. Treating this ' +
                       'machine as AD FS. Pass -Role WAP explicitly to override.') -Level Warning -EventId 2009
            return 'ADFS'
        }
    } catch {
        Write-Log "Could not read installed role features: $($_.Exception.Message)" -Level Warning -EventId 2009
    }

    # 2. Cmdlet availability - the role modules only exist when the role is installed.
    if (Get-Command 'Get-AdfsProperties' -ErrorAction SilentlyContinue) { return 'ADFS' }
    if (Get-Command 'Get-WebApplicationProxySslCertificate' -ErrorAction SilentlyContinue) { return 'WAP' }

    # 3. Services - last resort, and deliberately checks appproxysvc FIRST, because an
    #    adfssrv service can exist on a proxy but appproxysvc never exists on a plain
    #    federation server.
    $svc = Get-Service -Name 'adfssrv', 'appproxysvc' -ErrorAction SilentlyContinue
    if ($svc | Where-Object { $_.Name -eq 'appproxysvc' }) { return 'WAP' }
    if ($svc | Where-Object { $_.Name -eq 'adfssrv' })     { return 'ADFS' }

    # 4. IIS. Detected from the management assembly plus the W3SVC service, because the
    #    WebAdministration module is absent on a Server Core install that still runs IIS,
    #    and the assembly alone can linger after the role is removed.
    if ((Test-Path (Get-IisAdminAssemblyPath)) -and (Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue)) {
        return 'IIS'
    }

    return 'None'
}

function Get-ServiceAccountName {
    param([string]$ServiceName)
    $s = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if (-not $s) { return $null }
    switch -Regex ($s.StartName) {
        '^LocalSystem$'              { return 'NT AUTHORITY\SYSTEM' }
        '^NT AUTHORITY\\'            { return $s.StartName }
        '^\.\\(.+)$'                 { return "$env:COMPUTERNAME\$($Matches[1])" }
        default                      { return $s.StartName }
    }
}

function Get-CurrentBoundThumbprint {
    param([string]$ForRole)

    $obj = $null
    try {
        if ($ForRole -eq 'ADFS') {
            $obj = Get-AdfsSslCertificate -ErrorAction Stop | Select-Object -First 1
        } elseif ($ForRole -eq 'WAP') {
            $obj = Get-WebApplicationProxySslCertificate -ErrorAction Stop | Select-Object -First 1
        }
    } catch {
        Write-Log "Could not read the current binding: $($_.Exception.Message)" -Level Warning -EventId 2005
        return $null
    }
    if (-not $obj) { return $null }

    # Property name differs across OS versions / cmdlets.
    foreach ($prop in 'CertificateHash', 'Thumbprint', 'CertificateThumbprint', 'HostNameCertificateHash') {
        if ($obj.PSObject.Properties.Name -contains $prop) {
            $v = "$($obj.$prop)".Replace(' ', '').Replace('-', '')
            if ($v -match '^[0-9a-fA-F]{40}$') { return $v.ToUpperInvariant() }
        }
    }
    return $null
}

function Set-AdfsBinding {
    param([string]$Thumbprint)

    Import-Module ADFS -ErrorAction Stop

    $isSecondary = $false
    try {
        $sync = Get-AdfsSyncProperties -ErrorAction Stop
        $isSecondary = ($sync.Role -eq 'SecondaryComputer')
    } catch { }

    if ($PSCmdlet.ShouldProcess('AD FS', "Set Service-Communications certificate to $Thumbprint")) {
        Set-AdfsCertificate -CertificateType Service-Communications -Thumbprint $Thumbprint
        Write-Log "AD FS Service-Communications certificate set to $Thumbprint." -EventId 1003
    }

    if ($isSecondary -and -not $ForceLocalBinding) {
        Write-Log ('This node is an AD FS secondary. Set-AdfsSslCertificate is replicated from the ' +
                   'primary node; skipping local TLS binding. Use -ForceLocalBinding to override.') -Level Warning -EventId 1003
    } elseif ($PSCmdlet.ShouldProcess('AD FS', "Set TLS/SSL certificate to $Thumbprint")) {
        Set-AdfsSslCertificate -Thumbprint $Thumbprint
        Write-Log "AD FS TLS/SSL certificate set to $Thumbprint." -EventId 1003
    }

    if (-not $SkipServiceRestart -and $PSCmdlet.ShouldProcess('adfssrv', 'Restart service')) {
        Restart-Service -Name adfssrv -Force
        Write-Log 'Restarted the Active Directory Federation Services service (adfssrv).' -EventId 1003
    }
}

function Test-WapApplicationsCurrent {
    <#
        Returns $true when every published application already points at $Thumbprint,
        $false when at least one does not, and $null when the proxy cannot be queried.

        This exists because the "already current" fast path only looked at the main WAP TLS
        binding. A proxy can have that correct while its published applications still carry an
        old - possibly expired - certificate on their own host:port bindings. Without this
        check the agent reports "nothing to do" forever and those bindings never get fixed.
    #>
    param([string]$Thumbprint)

    try {
        $apps = @(Get-WebApplicationProxyApplication -ErrorAction Stop)
    } catch {
        return $null
    }

    foreach ($app in $apps) {
        if ($app.PSObject.Properties.Name -notcontains 'ExternalCertificateThumbprint') { continue }
        $t = "$($app.ExternalCertificateThumbprint)".Replace(' ', '').ToUpperInvariant()
        if ($t -and $t -ne $Thumbprint) { return $false }
    }
    return $true
}

function Set-WapBinding {
    param([string]$Thumbprint)

    Import-Module WebApplicationProxy -ErrorAction Stop

    if ($PSCmdlet.ShouldProcess('Web Application Proxy', "Set TLS/SSL certificate to $Thumbprint")) {
        Set-WebApplicationProxySslCertificate -Thumbprint $Thumbprint
        Write-Log "WAP TLS/SSL certificate set to $Thumbprint." -EventId 1004
    }

    $apps = @()
    $appsReadable = $true
    try {
        # This throws a TERMINATING error on a proxy that cannot reach the AD FS configuration
        # store, so -ErrorAction SilentlyContinue does not help and try/catch is required.
        # The TLS certificate is already bound at this point; failing the whole run here would
        # throw away work that succeeded and leave state.json unwritten.
        $apps = @(Get-WebApplicationProxyApplication -ErrorAction Stop)
    } catch {
        $appsReadable = $false
        Write-Log ("Could not enumerate published applications, so their per-application " +
                   "certificate bindings were NOT updated: $($_.Exception.Message) " +
                   "The Web Application Proxy TLS certificate itself was set successfully. " +
                   "Re-run this agent once the proxy can reach the AD FS configuration store " +
                   "(Install-WebApplicationProxy).") -Level Warning -EventId 2010
    }

    foreach ($app in $apps) {
        $current = ''
        if ($app.PSObject.Properties.Name -contains 'ExternalCertificateThumbprint') {
            $current = "$($app.ExternalCertificateThumbprint)".Replace(' ', '').ToUpperInvariant()
        }
        if (-not $current -or $current -eq $Thumbprint) { continue }
        if ($PSCmdlet.ShouldProcess($app.Name, "Set ExternalCertificateThumbprint to $Thumbprint")) {
            try {
                Set-WebApplicationProxyApplication -ID $app.ID -ExternalCertificateThumbprint $Thumbprint
                Write-Log "Published application '$($app.Name)' re-pointed to $Thumbprint." -EventId 1004
            } catch {
                Write-Log "Failed to update published application '$($app.Name)': $($_.Exception.Message)" `
                          -Level Error -EventId 2006
                throw
            }
        }
    }

    if (-not $SkipServiceRestart -and $PSCmdlet.ShouldProcess('appproxysvc', 'Restart service')) {
        try {
            Restart-Service -Name appproxysvc -Force -ErrorAction Stop
            Write-Log 'Restarted the Web Application Proxy service (appproxysvc).' -EventId 1004
        } catch {
            # A proxy that is not joined to the farm often cannot start. That is an existing
            # configuration problem, not a certificate problem - do not fail the sync for it.
            Write-Log ("Could not restart appproxysvc: $($_.Exception.Message) " +
                       "The certificate is installed and bound; the service needs attention " +
                       "separately.") -Level Warning -EventId 2011
        }
    }

    if (-not $appsReadable) {
        Write-Log ('Certificate work completed, but published-application bindings were skipped. ' +
                   'Check them once the proxy is healthy.') -Level Warning -EventId 2010
    }
}

#endregion

#region ------------------------------------------------------------------- IIS

function Get-IisAdminAssemblyPath {
    Join-Path $env:SystemRoot 'System32\inetsrv\Microsoft.Web.Administration.dll'
}

function Import-IisAdmin {
    <#
        Loads Microsoft.Web.Administration instead of the WebAdministration PowerShell module.
        The assembly ships with the Web-Server role on every SKU including Server Core, whereas
        the module needs the Web-Scripting-Tools feature which is frequently not installed.
    #>
    if ('Microsoft.Web.Administration.ServerManager' -as [type]) { return }
    $dll = Get-IisAdminAssemblyPath
    if (-not (Test-Path $dll)) {
        throw "The IIS management assembly was not found at $dll. Is the Web-Server role installed?"
    }
    [void][System.Reflection.Assembly]::LoadFrom($dll)
}

function ConvertTo-HexString {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return ($Value -replace '[^0-9a-fA-F]', '').ToUpperInvariant() }
    return (($Value | ForEach-Object { '{0:X2}' -f $_ }) -join '')
}

function ConvertFrom-HexString {
    param([string]$Hex)
    $clean = ($Hex -replace '[^0-9a-fA-F]', '')
    $bytes = New-Object byte[] ($clean.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
    }
    return , $bytes
}

function Get-SubjectAlternativeDnsName {
    <#
        Walks the DER of a subjectAltName extension and returns its dNSName entries.

        X509Extension.Format() is NOT used on purpose: it emits localised labels, so
        matching on the literal text "DNS Name=" silently returns nothing on a German or
        French Windows and every binding would then look unrelated to the new certificate.
        SubjectAlternativeName ::= SEQUENCE OF GeneralName, dNSName = context tag [2] (0x82).
    #>
    param([byte[]]$RawData)

    $names = New-Object System.Collections.Generic.List[string]
    if ($null -eq $RawData -or $RawData.Length -lt 2 -or $RawData[0] -ne 0x30) { return $names.ToArray() }

    $i   = 1
    $len = $RawData[$i]; $i++
    if ($len -band 0x80) {
        $n = $len -band 0x7F
        $len = 0
        for ($k = 0; $k -lt $n -and $i -lt $RawData.Length; $k++) { $len = ($len -shl 8) -bor $RawData[$i]; $i++ }
    }

    $end = [Math]::Min($i + $len, $RawData.Length)
    while ($i -lt $end -and ($i + 1) -lt $RawData.Length) {
        $tag = $RawData[$i]; $i++
        $l   = $RawData[$i]; $i++
        if ($l -band 0x80) {
            $n = $l -band 0x7F
            $l = 0
            for ($k = 0; $k -lt $n -and $i -lt $RawData.Length; $k++) { $l = ($l -shl 8) -bor $RawData[$i]; $i++ }
        }
        if ($l -lt 0 -or ($i + $l) -gt $RawData.Length) { break }
        if ($tag -eq 0x82 -and $l -gt 0) {
            $names.Add([System.Text.Encoding]::ASCII.GetString($RawData, $i, $l).Trim().ToLowerInvariant())
        }
        $i += $l
    }
    return $names.ToArray()
}

function Get-CertificateDnsName {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($ext in $Certificate.Extensions) {
        if ($ext.Oid.Value -ne '2.5.29.17') { continue }
        foreach ($n in (Get-SubjectAlternativeDnsName -RawData $ext.RawData)) { $names.Add($n) }
    }
    if ($names.Count -eq 0) {
        # Pre-SAN certificates still carry the host name in the common name.
        $cn = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if ($cn) { $names.Add($cn.Trim().ToLowerInvariant()) }
    }
    return @($names | Select-Object -Unique)
}

function Test-DnsNameCovered {
    param([string]$HostName, [string[]]$CertificateNames)

    if ([string]::IsNullOrWhiteSpace($HostName)) { return $false }
    $h = $HostName.Trim().ToLowerInvariant()

    foreach ($n in $CertificateNames) {
        if ($n -eq $h) { return $true }
        if ($n.StartsWith('*.')) {
            # A wildcard matches exactly one label, so a.b.contoso.com is NOT covered by *.contoso.com.
            $suffix = $n.Substring(1)
            if ($h.Length -gt $suffix.Length -and $h.EndsWith($suffix)) {
                $label = $h.Substring(0, $h.Length - $suffix.Length)
                if ($label -and $label.IndexOf('.') -lt 0) { return $true }
            }
        }
    }
    return $false
}

function Get-IisHttpsBinding {
    Import-IisAdmin

    $result = New-Object System.Collections.Generic.List[object]
    $sm     = New-Object Microsoft.Web.Administration.ServerManager
    try {
        foreach ($site in $sm.Sites) {
            if ($IisSites.Count -gt 0 -and $site.Name -notin $IisSites) { continue }
            foreach ($b in $site.Bindings) {
                if ($b.Protocol -ne 'https') { continue }

                $info  = "$($b.BindingInformation)"
                $parts = $info -split ':', 3

                $flags = 0; try { $flags = [int]$b.SslFlags } catch { }
                $hash  = '';  try { $hash  = ConvertTo-HexString $b.CertificateHash } catch { }
                $store = 'My'
                try { if ($b.CertificateStoreName) { $store = "$($b.CertificateStoreName)" } } catch { }

                $result.Add([pscustomobject]@{
                    Site     = "$($site.Name)"
                    Info     = $info
                    Ip       = $(if ($parts[0] -eq '*' -or -not $parts[0]) { '0.0.0.0' } else { $parts[0] })
                    Port     = [int]$parts[1]
                    HostName = $(if ($parts.Count -ge 3) { $parts[2] } else { '' })
                    SslFlags = $flags
                    Store    = $store
                    Hash     = $hash
                    Reason   = ''
                })
            }
        }
    } finally {
        $sm.Dispose()
    }
    return $result.ToArray()
}

function Select-IisBindingToUpdate {
    <#
        Decides which https bindings this agent is allowed to re-point, so that a server
        hosting an unrelated certificate next to ours never gets it silently replaced.
    #>
    param(
        [object[]]$Bindings,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$Scope,
        [switch]$Quiet
    )

    $target    = $Certificate.Thumbprint.ToUpperInvariant()
    $certNames = @(Get-CertificateDnsName -Certificate $Certificate)
    $selected  = New-Object System.Collections.Generic.List[object]

    foreach ($b in $Bindings) {
        if ($b.SslFlags -band 2) {
            # Central Certificate Store: IIS resolves the certificate from a file share by
            # host name and applicationHost.config holds no thumbprint to update.
            if (-not $Quiet) {
                Write-Log ("Binding {0} on site '{1}' uses the Central Certificate Store; nothing to rebind." -f `
                           $b.Info, $b.Site) -Level Warning -EventId 2012
            }
            continue
        }
        if ($b.Hash -eq $target) { continue }

        $reason = $null
        if ($Scope -eq 'All') {
            $reason = 'IisBindingScope=All'
        } elseif (-not $b.Hash) {
            $reason = 'the binding carries no certificate'
        } else {
            $existing = Get-Item ('Cert:\LocalMachine\{0}\{1}' -f $b.Store, $b.Hash) -ErrorAction SilentlyContinue
            if (-not $existing) {
                $reason = "the bound certificate $($b.Hash) is no longer in LocalMachine\$($b.Store)"
            } elseif ($existing.Subject -eq $Certificate.Subject) {
                $reason = "the bound certificate has the same subject ($($existing.Subject))"
            } else {
                $shared = @(@(Get-CertificateDnsName -Certificate $existing) | Where-Object { $_ -in $certNames })
                if ($shared.Count -gt 0) {
                    $reason = "the bound certificate shares SAN name(s) $($shared -join ', ')"
                } elseif ($Scope -eq 'Matching' -and (Test-DnsNameCovered -HostName $b.HostName -CertificateNames $certNames)) {
                    $reason = "host header $($b.HostName) is covered by the new certificate"
                }
            }
        }

        if ($reason) {
            $b.Reason = $reason
            $selected.Add($b)
        } elseif (-not $Quiet) {
            Write-Log ("Leaving binding {0} on site '{1}' alone: it holds unrelated certificate {2}. " +
                       "Use -IisBindingScope All to include it." -f $b.Info, $b.Site, $b.Hash) -EventId 1006
        }
    }
    return $selected.ToArray()
}

function ConvertFrom-NetshSslCertOutput {
    <#
        Turns the output of 'netsh http show sslcert' into endpoint -> {Hash, AppId}.

        Parsed by the SHAPE of each value rather than by its label, because netsh output is
        localised: on a German Windows the labels read 'IP:Port' and 'Zertifikathash', so
        label matching silently returns nothing and every endpoint then looks unbound.
    #>
    param([string[]]$Lines)

    $map = @{}
    $key = $null

    foreach ($line in $Lines) {
        if ("$line" -notmatch '^\s*(.+?)\s+:\s+(.*?)\s*$') { continue }
        $value = $Matches[2]

        if ($value -match '^(?:(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\]):\d{1,5}$' -or
            $value -match '^[A-Za-z0-9\-\._\*]+\.[A-Za-z0-9\-\._\*]*:\d{1,5}$') {
            $key = $value
            if (-not $map.ContainsKey($key)) {
                $map[$key] = [pscustomobject]@{ Key = $key; Hash = ''; AppId = '' }
            }
            continue
        }
        if (-not $key) { continue }
        if ($value -match '^[0-9a-fA-F]{40}$')           { $map[$key].Hash  = $value.ToUpperInvariant() }
        elseif ($value -match '^\{[0-9a-fA-F\-]{36}\}$') { $map[$key].AppId = $value }
    }
    return $map
}

function Get-HttpSysSslBinding {
    <# Returns the SSL certificate bindings http.sys is actually serving, keyed by endpoint. #>
    return (ConvertFrom-NetshSslCertOutput -Lines (& "$env:SystemRoot\System32\netsh.exe" http show sslcert 2>$null))
}

function Get-HttpSysEndpointKey {
    param([object]$Binding)
    # SNI (sslFlags bit 0) registers under hostname:port; everything else under ip:port.
    if (($Binding.SslFlags -band 1) -and $Binding.HostName) {
        return [pscustomobject]@{ Key = ('{0}:{1}' -f $Binding.HostName, $Binding.Port); Argument = 'hostnameport' }
    }
    return [pscustomobject]@{ Key = ('{0}:{1}' -f $Binding.Ip, $Binding.Port); Argument = 'ipport' }
}

function Set-IisBindingConfiguration {
    <#
        Writes the thumbprint into applicationHost.config for every pending binding in a
        single commit. One commit rather than one per binding, so IIS reloads configuration
        once instead of once per site.
    #>
    param([object[]]$Pending, [string]$Thumbprint)

    Import-IisAdmin
    $bytes = ConvertFrom-HexString $Thumbprint
    $sm    = New-Object Microsoft.Web.Administration.ServerManager
    try {
        foreach ($p in $Pending) {
            $site = $sm.Sites | Where-Object { $_.Name -eq $p.Site } | Select-Object -First 1
            if (-not $site) { continue }
            $binding = $site.Bindings |
                       Where-Object { $_.Protocol -eq 'https' -and "$($_.BindingInformation)" -eq $p.Info } |
                       Select-Object -First 1
            if (-not $binding) { continue }

            # Store name must be set before the hash; MWA validates the pair on assignment.
            $binding.CertificateStoreName = $p.Store
            $binding.CertificateHash      = $bytes
        }
        $sm.CommitChanges()
    } finally {
        $sm.Dispose()
    }
}

function Sync-HttpSysSslBinding {
    <#
        Reconciles http.sys with applicationHost.config.

        Committing the configuration normally makes W3SVC register the certificate in http.sys
        by itself, but that does not happen when the service is stopped, and a hand-run
        'netsh http delete sslcert' leaves the two permanently out of step. Checking first and
        only calling netsh for endpoints that are genuinely wrong keeps this idempotent.
    #>
    param([object[]]$Bindings, [string]$Thumbprint)

    $iisAppId  = '{4dc3e181-e14b-4a21-b022-59fc669b0914}'
    $live      = Get-HttpSysSslBinding
    $processed = @{}
    $repaired  = 0

    foreach ($b in $Bindings) {
        if ($b.SslFlags -band 2) { continue }
        $ep = Get-HttpSysEndpointKey -Binding $b
        if ($processed.ContainsKey($ep.Key)) { continue }
        $processed[$ep.Key] = $true

        $entry = $null
        if ($live.ContainsKey($ep.Key)) { $entry = $live[$ep.Key] }
        if ($entry -and $entry.Hash -eq $Thumbprint) { continue }

        $verb       = if ($entry) { 'update' } else { 'add' }
        $appId      = if ($entry -and $entry.AppId) { $entry.AppId } else { $iisAppId }
        # Never name this $args: that is an automatic variable, and shadowing it makes the
        # splat below depend on scope rules rather than on what was just assigned.
        $netshArgs  = @('http', $verb, 'sslcert', ('{0}={1}' -f $ep.Argument, $ep.Key),
                        "certhash=$Thumbprint", "appid=$appId", "certstorename=$($b.Store)")

        if (-not $PSCmdlet.ShouldProcess($ep.Key, "netsh http $verb sslcert -> $Thumbprint")) { continue }

        $output = & "$env:SystemRoot\System32\netsh.exe" @netshArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ("netsh http $verb sslcert failed for $($ep.Key): " + (($output | Out-String).Trim()))
        }
        Write-Log ("http.sys endpoint {0} now serves {1} (was '{2}')." -f `
                   $ep.Key, $Thumbprint, $(if ($entry) { $entry.Hash } else { 'not registered' })) -EventId 1006
        $repaired++
    }
    return $repaired
}

function Test-IisBindingsCurrent {
    <#
        True when every in-scope https binding points at $Certificate in BOTH
        applicationHost.config and http.sys.
    #>
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    try {
        $bindings = @(Get-IisHttpsBinding)
    } catch {
        Write-Log "Could not read the IIS bindings: $($_.Exception.Message)" -Level Warning -EventId 2012
        return $true
    }
    if ($bindings.Count -eq 0) { return $true }

    $pending = @(Select-IisBindingToUpdate -Bindings $bindings -Certificate $Certificate `
                                           -Scope $IisBindingScope -Quiet)
    if ($pending.Count -gt 0) { return $false }

    $thumb = $Certificate.Thumbprint.ToUpperInvariant()
    $live  = Get-HttpSysSslBinding
    foreach ($b in $bindings) {
        if ($b.SslFlags -band 2) { continue }
        if ($b.Hash -ne $thumb)  { continue }   # out of scope and deliberately left alone
        $ep = Get-HttpSysEndpointKey -Binding $b
        if (-not $live.ContainsKey($ep.Key) -or $live[$ep.Key].Hash -ne $thumb) { return $false }
    }
    return $true
}

function Set-IisBinding {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $thumb    = $Certificate.Thumbprint.ToUpperInvariant()
    $bindings = @(Get-IisHttpsBinding)

    if ($bindings.Count -eq 0) {
        Write-Log ('IIS has no https bindings' +
                   $(if ($IisSites.Count -gt 0) { " on site(s) $($IisSites -join ', ')" } else { '' }) +
                   '. The certificate was imported but there was nothing to rebind.') -Level Warning -EventId 2012
        return
    }

    $pending = @(Select-IisBindingToUpdate -Bindings $bindings -Certificate $Certificate -Scope $IisBindingScope)

    if ($pending.Count -gt 0) {
        foreach ($p in $pending) {
            Write-Log ("Re-pointing IIS binding {0} on site '{1}' to {2} - {3}." -f `
                       $p.Info, $p.Site, $thumb, $p.Reason) -EventId 1006
        }
        $targets = ($pending | ForEach-Object { "$($_.Site) $($_.Info)" }) -join '; '
        if ($PSCmdlet.ShouldProcess($targets, "Set the IIS certificate to $thumb")) {
            Set-IisBindingConfiguration -Pending $pending -Thumbprint $thumb
            $script:Changed = $true

            # Verify the write landed before touching http.sys.
            $after = @(Get-IisHttpsBinding)
            $still = @(Select-IisBindingToUpdate -Bindings $after -Certificate $Certificate `
                                                 -Scope $IisBindingScope -Quiet)
            if ($still.Count -gt 0) {
                throw ('applicationHost.config still does not reference {0} for: {1}' -f `
                       $thumb, (($still | ForEach-Object { "$($_.Site) $($_.Info)" }) -join '; '))
            }
            $bindings = $after
        }
    } else {
        Write-Log 'Every in-scope IIS https binding already references the current certificate.' -EventId 1006
    }

    # Only reconcile endpoints that config says should serve this certificate.
    $ours = @($bindings | Where-Object { $_.Hash -eq $thumb })
    if ($ours.Count -gt 0) {
        $repaired = Sync-HttpSysSslBinding -Bindings $ours -Thumbprint $thumb
        if ($repaired -gt 0) { $script:Changed = $true }

        $live = Get-HttpSysSslBinding
        $verified = New-Object System.Collections.Generic.HashSet[string]
        foreach ($b in $ours) {
            $ep = Get-HttpSysEndpointKey -Binding $b
            if (-not $live.ContainsKey($ep.Key) -or $live[$ep.Key].Hash -ne $thumb) {
                throw "http.sys endpoint $($ep.Key) still does not serve $thumb after the update."
            }
            [void]$verified.Add($ep.Key)
        }
        Write-Log ("Verified {0} http.sys endpoint(s) now serve {1}." -f $verified.Count, $thumb) -EventId 1006
    }

    Write-Log ('IIS was not restarted on purpose: http.sys serves the new certificate to new ' +
               'connections as soon as the binding is rewritten, so a restart would only cause ' +
               'downtime.') -EventId 1006
}

#endregion

#region --------------------------------------------------------------- cleanup

function Test-SupersededCertificate {
    <#
        Decides whether $Candidate is an older copy of $Current, i.e. a previous issuance of
        the same certificate that this agent may clean up.

        Matching on Subject alone is not enough and silently stopped working in production:
        ACME issuers change the common name between renewals. The *.contoso.com certificate
        renewed from 'CN=*.contoso.com' to 'CN=contoso.com', so every superseded copy stopped
        being recognised and expired certificates accumulated in the store forever.

        The reliable identity of "the same certificate, re-issued" is the set of names it is
        valid for. Equality - not overlap - is required on purpose: a certificate covering a
        different or wider set of names is a different certificate and may well be in use by
        something this agent knows nothing about.
    #>
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Candidate,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Current
    )

    if ($Candidate.Thumbprint -eq $Current.Thumbprint) { return $false }
    if ($Candidate.Subject -eq $Current.Subject)       { return $true }

    $a = @(Get-CertificateDnsName -Certificate $Candidate | Sort-Object)
    $b = @(Get-CertificateDnsName -Certificate $Current   | Sort-Object)
    if ($a.Count -eq 0 -or $a.Count -ne $b.Count) { return $false }
    for ($i = 0; $i -lt $a.Count; $i++) {
        if ($a[$i] -ne $b[$i]) { return $false }
    }
    return $true
}

function Remove-SupersededCertificates {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Current,
        [string]$Mode,
        [int]$Keep
    )
    if ($Mode -eq 'None') { return }

    $inUse = Get-ThumbprintsInUse
    $inUse += $Current.Thumbprint.ToUpperInvariant()

    $siblings = @(Get-ChildItem 'Cert:\LocalMachine\My' |
                  Where-Object { $_.Thumbprint.ToUpperInvariant() -notin $inUse -and
                                 (Test-SupersededCertificate -Candidate $_ -Current $Current) } |
                  Sort-Object NotAfter -Descending)

    $targets = switch ($Mode) {
        'Expired'    { $siblings | Where-Object { $_.NotAfter -lt (Get-Date) } }
        'KeepLatest' { $siblings | Select-Object -Skip $Keep }
    }

    foreach ($c in @($targets)) {
        if ($PSCmdlet.ShouldProcess($c.Thumbprint, 'Remove superseded certificate from LocalMachine\My')) {
            try {
                Remove-Item -Path "Cert:\LocalMachine\My\$($c.Thumbprint)" -Force -DeleteKey
                Write-Log "Removed superseded certificate $($c.Thumbprint) (expired $($c.NotAfter.ToString('u')))." -EventId 1005
            } catch {
                Write-Log "Could not remove $($c.Thumbprint): $($_.Exception.Message)" -Level Warning -EventId 2007
            }
        }
    }
}

function Get-ThumbprintsInUse {
    $result = New-Object System.Collections.Generic.List[string]
    try {
        $out = & "$env:SystemRoot\System32\netsh.exe" http show sslcert 2>$null
        foreach ($line in $out) {
            if ($line -match 'Certificate Hash\s*:\s*([0-9a-fA-F]{40})') {
                $result.Add($Matches[1].ToUpperInvariant())
            }
        }
    } catch { }
    try {
        if (Get-Command Get-AdfsCertificate -ErrorAction SilentlyContinue) {
            foreach ($c in (Get-AdfsCertificate -ErrorAction SilentlyContinue)) {
                if ($c.Thumbprint) { $result.Add($c.Thumbprint.ToUpperInvariant()) }
            }
        }
    } catch { }
    try {
        # applicationHost.config can reference a certificate that http.sys has not picked up
        # yet. Deleting it here would leave IIS pointing at a thumbprint that no longer exists.
        if ($Role -eq 'IIS') {
            foreach ($b in (Get-IisHttpsBinding)) {
                if ($b.Hash) { $result.Add($b.Hash) }
            }
        }
    } catch { }
    return $result.ToArray()
}

#endregion

#region ------------------------------------------------------------------ main

$exitCode = 0
try {
    Initialize-Logging
    Write-Log "=== KeyVaultCertSync starting on $env:COMPUTERNAME (vault=$VaultName, cert=$CertificateName) ===" -EventId 1000

    if ($Role -eq 'Auto') {
        $Role = Get-DetectedRole
        Write-Log "Detected role: $Role"
    }

    $baseUri = 'https://{0}.{1}' -f $VaultName, $VaultDnsSuffix
    $token   = Get-ManagedIdentityToken -Resource ('https://{0}' -f $VaultDnsSuffix) -ClientId $IdentityClientId
    Write-Log 'Acquired an access token via managed identity.'

    $meta = Get-KeyVaultCertificateMetadata -Token $token -BaseUri $baseUri -Name $CertificateName
    if (-not $meta.Enabled) { throw "Key Vault certificate '$CertificateName' is disabled." }
    Write-Log ("Key Vault current version {0}: thumbprint {1}, expires {2} ({3} days left)." -f `
               $meta.Version, $meta.Thumbprint, $meta.Expires.ToString('u'),
               [int]($meta.Expires - [DateTime]::UtcNow).TotalDays)

    $installed = Get-Item "Cert:\LocalMachine\My\$($meta.Thumbprint)" -ErrorAction SilentlyContinue
    $bound     = Get-CurrentBoundThumbprint -ForRole $Role

    # The main binding matching is not sufficient on a proxy: each published application
    # carries its own certificate thumbprint and its own host:port binding in http.sys.
    $appsCurrent = $true
    if ($Role -eq 'WAP' -and $bound -eq $meta.Thumbprint) {
        $appsCurrent = Test-WapApplicationsCurrent -Thumbprint $meta.Thumbprint
        if ($null -eq $appsCurrent) {
            Write-Log ('Could not read published applications, so their individual certificate ' +
                       'bindings could not be verified. Treating the node as current because ' +
                       'nothing can be changed until the proxy can reach the AD FS configuration ' +
                       'store.') -Level Warning -EventId 2010
            $appsCurrent = $true
        } elseif (-not $appsCurrent) {
            Write-Log ('The Web Application Proxy TLS certificate is current, but at least one ' +
                       'published application still points at a different certificate. Updating ' +
                       'those bindings.') -Level Warning -EventId 1004
        }
    }

    # IIS has no single "the" binding - a server can hold dozens, and http.sys can disagree
    # with applicationHost.config - so being current has to be proven across all of them.
    $iisCurrent = $true
    if ($Role -eq 'IIS') {
        $iisCurrent = $false
        if ($installed -and $installed.HasPrivateKey) {
            $iisCurrent = Test-IisBindingsCurrent -Certificate $installed
            if (-not $iisCurrent) {
                Write-Log ('At least one IIS https binding does not yet serve the current ' +
                           'certificate. Updating.') -EventId 1006
            }
        }
    }

    if (-not $Force -and $installed -and $installed.HasPrivateKey -and $appsCurrent -and $iisCurrent -and
        ($Role -eq 'None' -or $Role -eq 'IIS' -or $bound -eq $meta.Thumbprint)) {
        Write-Log "Already current - certificate $($meta.Thumbprint) is installed and bound. Nothing to do." -EventId 1001

        # Cleanup runs here too, not only after a renewal. It is cheap and idempotent, and
        # gating it on "something changed" meant a superseded certificate that could not be
        # removed during the renewal - because it was still bound at that moment, or because
        # an older agent failed to recognise it - was never reconsidered and stayed in the
        # store until the next renewal came round.
        Remove-SupersededCertificates -Current $installed -Mode $CleanupMode -Keep $KeepLatest

        Save-State -Meta $meta -Status 'NoChange'
        return
    }

    if ($installed -and $installed.HasPrivateKey -and -not $Force) {
        Write-Log 'Certificate already present in the store; only the binding needs updating.'
        $cert = $installed
    } else {
        Write-Log 'Retrieving the PFX (certificate + private key) from Key Vault.'
        $pfx = Get-KeyVaultPfxBytes -Token $token -BaseUri $baseUri -Name $CertificateName
        if ($PSCmdlet.ShouldProcess('LocalMachine\My', "Import certificate $($meta.Thumbprint)")) {
            $cert = Import-PfxToLocalMachine -PfxBytes $pfx -AllowExport:$Exportable
        } else {
            Write-Log 'WhatIf: import skipped; stopping here because later steps depend on it.'
            return
        }
        [Array]::Clear($pfx, 0, $pfx.Length)
        $script:Changed = $true
    }

    if ($cert.Thumbprint.ToUpperInvariant() -ne $meta.Thumbprint) {
        throw "Thumbprint mismatch: Key Vault reported $($meta.Thumbprint) but the imported certificate is $($cert.Thumbprint)."
    }

    $readers = New-Object System.Collections.Generic.List[string]
    switch ($Role) {
        'ADFS' { $a = Get-ServiceAccountName 'adfssrv';     if ($a) { $readers.Add($a) } }
        'WAP'  { $a = Get-ServiceAccountName 'appproxysvc'; if ($a) { $readers.Add($a) } }
    }
    foreach ($extra in $AdditionalPrivateKeyReaders) { $readers.Add($extra) }
    Grant-PrivateKeyRead -Certificate $cert -Identities $readers.ToArray()

    switch ($Role) {
        'ADFS' { Set-AdfsBinding -Thumbprint $cert.Thumbprint; $script:Changed = $true }
        'WAP'  { Set-WapBinding  -Thumbprint $cert.Thumbprint; $script:Changed = $true }
        'IIS'  { Set-IisBinding  -Certificate $cert }
        'None' { Write-Log 'Role = None: certificate imported, no binding performed.' }
    }

    Remove-SupersededCertificates -Current $cert -Mode $CleanupMode -Keep $KeepLatest

    Save-State -Meta $meta -Status $(if ($script:Changed) { 'Updated' } else { 'NoChange' })
    Write-Log "=== Completed successfully. Active thumbprint: $($cert.Thumbprint) ===" -EventId 1010
}
catch {
    $exitCode = 1
    $msg = "KeyVaultCertSync FAILED on $env:COMPUTERNAME`r`n$($_.Exception.Message)`r`n$($_.ScriptStackTrace)"
    try { Write-Log $msg -Level Error -EventId 2000 } catch { Write-Host $msg -ForegroundColor Red }
}
finally {
    exit $exitCode
}

#endregion
