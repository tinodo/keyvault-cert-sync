# Troubleshooting

Start here:

```powershell
.\tools\Verify-CertSync.ps1
```

Then the log tail at `%ProgramData%\KeyVaultCertSync\Logs\sync-YYYYMM.log`, or the Application
event log filtered to source `KeyVaultCertSync`.

---

## `403 Forbidden` after a successful token acquisition

```
Acquired an access token via managed identity.
KeyVaultCertSync FAILED ... The remote server returned an error: (403) Forbidden.
```

The identity authenticated but is not authorised. Almost always **only one of the two required
roles** has been granted.

The agent reads certificate *metadata* first, then the backing *secret*. `Key Vault Secrets
User` alone passes the token request and fails the metadata call.

Grant both `Key Vault Secrets User` and `Key Vault Certificate User` at vault scope — see
[installation.md](installation.md#grant-the-managed-identity-access).

Other causes, in rough order of likelihood:

- RBAC has not propagated yet. Wait a few minutes.
- The role was granted to a different identity than IMDS is returning. See
  [which identity gets used](installation.md#which-identity-gets-used).
- The vault uses access policies, not RBAC, and no policy covers this principal.
- A vault firewall is blocking the VM's subnet.

## `Could not enumerate published applications` on WAP

```
[WARN] Could not read published applications, so their individual certificate bindings
       could not be verified. Treating the node as current because nothing can be changed
       until the proxy can reach the AD FS configuration store.
```

The proxy cannot reach the AD FS configuration store — usually error `0x8007520c`. This is a
**proxy trust problem, not a certificate problem**, so the agent deliberately does not fail the
run: the main TLS certificate work has already succeeded and failing here would discard it.

The proxy trust certificate expires 12 months after establishment and does not renew itself if
the proxy has been offline. Re-establish it on the proxy:

```powershell
Install-WebApplicationProxy `
    -FederationServiceName 'sts.contoso.com' `
    -FederationServiceTrustCredential (Get-Credential) `
    -CertificateThumbprint <thumbprint>
```

This needs AD FS administrator credentials and must be run interactively or with credentials
supplied securely — never embed the password in a Run Command payload, where it lands in
deployment history and activity logs.

Once the proxy is healthy, the next agent pass repairs the published applications' bindings by
itself. To avoid waiting for the schedule:

```powershell
Start-ScheduledTask -TaskName 'KeyVault Certificate Sync' -TaskPath '\Microsoft\KeyVaultCertSync\'
```

A healthy run logs `Already current` **without** that warning. If the warning is still there,
the proxy is still broken.

## Published applications keep an old certificate

Published applications each carry their own `ExternalCertificateThumbprint` and their own
`host:port` registration in `http.sys`. The proxy's main TLS binding can be perfectly current
while they are not.

The agent handles this, but only when it can enumerate them — see the previous entry. Check:

```powershell
Get-WebApplicationProxyApplication | Select-Object Name, ExternalCertificateThumbprint
```

## An IIS binding was not updated

Expected, if the certificate on it is unrelated to the Key Vault certificate. The log says so:

```
Leaving binding *:443:other.example.net on site 'Other' alone: it holds unrelated
certificate A1B2C3D4.... Use -IisBindingScope All to include it.
```

Under the default `Managed` scope the agent only claims bindings it can justify. If you want it
claimed, either widen the scope or check whether the certificates genuinely share a Subject or
SAN name. See [iis.md](iis.md#binding-scopes).

For Central Certificate Store bindings there is nothing to update — the thumbprint is not stored
in `applicationHost.config` at all.

Use the [dry-run planner](iis.md#dry-run) to see the decision and its reason for every binding.

## `http.sys` disagrees with IIS Manager

IIS Manager reads `applicationHost.config`; clients get what `http.sys` serves. They can
diverge if `W3SVC` was stopped when configuration changed, or if someone ran
`netsh http delete sslcert` by hand.

```powershell
netsh http show sslcert
```

The agent reconciles this automatically on every run, so a single pass usually fixes it. If it
cannot, it throws rather than reporting success:

```
http.sys endpoint 0.0.0.0:443 still does not serve <thumbprint> after the update.
```

That normally means something else is rewriting the binding, or the account lacks rights to
modify `http.sys`.

## Expired certificates are not being removed

Check in order:

1. `-CleanupMode` is not `None`.
2. The certificate is genuinely superseded — same Subject, or an identical SAN name set. A
   certificate covering a *different* set of names is intentionally left alone.
3. It is not still in use. Cleanup never removes a certificate referenced by `http.sys`, AD FS
   or `applicationHost.config`, even when expired.

Point 3 is the usual answer, and it is correct behaviour: on a proxy whose published
applications still reference an expired certificate, removing it would break them further.

The [dry-run planner](iis.md#dry-run) prints both the removal list and the explicitly-safe list.

## The task runs but nothing happens

Expected when everything is current — that is the idempotent path:

```
Already current - certificate <thumbprint> is installed and bound. Nothing to do.
```

If that is wrong, force a full pass:

```powershell
& "$env:ProgramData\KeyVaultCertSync\bin\Sync-KeyVaultCertificate.ps1" `
    -VaultName kv-contoso-certs -CertificateName contoso-com -Force
```

## The scheduled task does not run at all

```powershell
Get-ScheduledTaskInfo -TaskName 'KeyVault Certificate Sync' -TaskPath '\Microsoft\KeyVaultCertSync\'
```

| `LastTaskResult` | Meaning |
|---|---|
| `0x0` | Success |
| `0x1` | The agent reported failure — read the log |
| `0x41303` | Never run |
| `0x41301` | Currently running |

If `LastRunTime` is stale, confirm the task is Ready rather than Disabled, and that the trigger
survived. Re-running the installer re-registers it cleanly.

## Private key access denied

The agent grants the role's service account Read on the private key. If a service still cannot
use the certificate, confirm which account it runs as and grant it explicitly:

```powershell
-AdditionalPrivateKeyReaders 'CONTOSO\svc-monitor'
```

This is also the mechanism for a certificate consumed by something other than AD FS, WAP or IIS.

## Thumbprint mismatch after import

```
Thumbprint mismatch: Key Vault reported <a> but the imported certificate is <b>.
```

The PFX did not contain the expected leaf. Usually the Key Vault certificate was replaced
between the metadata call and the secret download — a renewal landing mid-run. The next pass
resolves it. If it persists, inspect the certificate in the vault.

## Role detected incorrectly

```powershell
-Role ADFS   # or WAP, IIS, None
```

Worth checking first: a Web Application Proxy legitimately carries a running `adfssrv` service,
and the agent accounts for that. See [role detection](configuration.md#role-detection).

## Getting more detail

```powershell
& "$env:ProgramData\KeyVaultCertSync\bin\Sync-KeyVaultCertificate.ps1" `
    -VaultName kv-contoso-certs -CertificateName contoso-com -Verbose -WhatIf
```

`-WhatIf` resolves everything and reports the planned actions without changing anything.
