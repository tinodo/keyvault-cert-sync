# Configuration

## Agent parameters

`src\Sync-KeyVaultCertificate.ps1`

| Parameter | Default | Purpose |
|---|---|---|
| `-VaultName` | *required* | Short name of the Key Vault, e.g. `kv-contoso-certs` |
| `-CertificateName` | *required* | Certificate object name in the vault, e.g. `contoso-com` |
| `-Role` | `Auto` | `Auto` \| `ADFS` \| `WAP` \| `IIS` \| `None` |
| `-IisBindingScope` | `Managed` | `Managed` \| `Matching` \| `All` — see [iis.md](iis.md) |
| `-IisSites` | *(all)* | Restrict IIS binding updates to named sites |
| `-IdentityClientId` | *(auto)* | Client ID of a user-assigned identity to authenticate with |
| `-AdditionalPrivateKeyReaders` | *(none)* | Extra identities to grant Read on the private key |
| `-CleanupMode` | `Expired` | `None` \| `Expired` \| `KeepLatest` |
| `-KeepLatest` | `1` | With `CleanupMode KeepLatest`, how many superseded certs to keep |
| `-VaultDnsSuffix` | `vault.azure.net` | Override for sovereign clouds |
| `-Force` | off | Re-import and rebind even when the thumbprint already matches |
| `-ForceLocalBinding` | off | On an AD FS secondary, bind locally instead of waiting for replication |
| `-SkipServiceRestart` | off | Import and bind but do not restart `adfssrv` / `appproxysvc` |
| `-Exportable` | off | Mark the imported private key exportable |
| `-WhatIf` | off | Report what would happen; change nothing |

### Role detection

`-Role Auto` decides in this order, stopping at the first clear answer:

1. **Installed role features** via `Get-WindowsFeature` — the authoritative signal.
2. **Cmdlet availability** — the role modules only exist when the role is installed.
3. **Services** — checking `appproxysvc` *before* `adfssrv`.
4. **IIS** — the `Microsoft.Web.Administration` assembly plus a present `W3SVC` service.

A Web Application Proxy carries a running `adfssrv` service even though the AD FS role is not
installed, because the proxy ships the same service host binary. Detecting on service presence
alone misclassifies every WAP server as AD FS, which is why features are checked first and why
`appproxysvc` is tested before `adfssrv` in the fallback.

IIS is only ever selected when neither AD FS nor WAP is present. On a server carrying both AD FS
and IIS, the federation role owns the certificate and IIS is incidental — override with
`-Role IIS` if that is genuinely what you want.

`-Role None` imports the certificate and grants key access but performs no binding. Useful on a
machine where something else — a load balancer agent, a custom service — consumes the
certificate from the store.

### Cleanup

`-CleanupMode` controls removal of superseded certificates from `LocalMachine\My`.

| Mode | Behaviour |
|---|---|
| `None` | Never remove anything |
| `Expired` *(default)* | Remove superseded certificates whose `NotAfter` has passed |
| `KeepLatest` | Keep the `-KeepLatest` most recent superseded certificates, remove the rest |

A certificate counts as **superseded** when it is not the current one and either:

- it has the **same Subject** as the current certificate, or
- it covers **exactly the same set of DNS names**.

The DNS-name rule matters because ACME issuers change the common name between renewals. A
wildcard certificate can renew from `CN=*.contoso.com` to `CN=contoso.com` while covering an
identical SAN list — subject-only matching stops recognising its own predecessors at that point
and expired certificates accumulate indefinitely.

Equality of the name set is required, not overlap. A certificate covering a *different* or
*wider* set of names is a different certificate and may well be in use by something the agent
knows nothing about.

Regardless of mode, a certificate is **never** removed while it is still referenced by:

- any `http.sys` SSL binding,
- any AD FS certificate,
- any https binding in `applicationHost.config`.

Cleanup runs on every pass, including passes where nothing else changed. Gating it on "something
changed" means a certificate that could not be removed during a renewal — because it was still
bound at that moment — is never reconsidered.

## Installer parameters

`src\Install-CertSyncAgent.ps1` accepts everything above that makes sense at install time, plus:

| Parameter | Default | Purpose |
|---|---|---|
| `-IntervalHours` | `4` | How often the task runs. Key Vault metadata calls are tiny; `1` is fine |
| `-RandomDelayMinutes` | `15` | Jitter, so farm members do not restart services simultaneously |
| `-TaskName` | `KeyVault Certificate Sync` | Scheduled task name |
| `-TaskPath` | `\Microsoft\KeyVaultCertSync\` | Scheduled task folder |
| `-RunNow` | off | Run one synchronisation immediately after registering the task |

## Logging and monitoring

| Destination | Path |
|---|---|
| Event log | Application, source `KeyVaultCertSync` |
| Text log | `%ProgramData%\KeyVaultCertSync\Logs\sync-YYYYMM.log` |
| State | `%ProgramData%\KeyVaultCertSync\state.json` |

### Event IDs

| ID | Meaning |
|---|---|
| 1000 | Run starting |
| 1001 | Already current, nothing to do |
| 1003 | AD FS binding changed |
| 1004 | WAP binding changed |
| 1005 | Superseded certificate removed |
| 1006 | IIS binding changed |
| 1010 | Run completed successfully |
| 2000 | Run failed |
| 2005 | Could not read the current binding |
| 2009 | Role detection problem |
| 2010 | WAP published applications could not be enumerated |
| 2011 | Service restart failed (non-fatal) |
| 2012 | IIS binding problem |

### state.json

```json
{
    "Computer":        "WEBSRV01",
    "Vault":           "kv-contoso-certs",
    "Certificate":     "contoso-com",
    "Role":            "IIS",
    "Thumbprint":      "0F1E2D3C4B5A69788796A5B4C3D2E1F00F1E2D3C",
    "KeyVaultVersion": "bf31dba4afb842dbabbdf71740da2d62",
    "ExpiresUtc":      "2026-12-30T19:19:46.0000000Z",
    "DaysRemaining":   87,
    "Status":          "NoChange",
    "LastRunUtc":      "2026-10-04T12:06:17.4628757Z"
}
```

Good things to alert on:

- `DaysRemaining` below your renewal threshold — the vault is not renewing.
- `LastRunUtc` older than `2 × IntervalHours` — the task is not running.
- Scheduled task `LastTaskResult` other than `0`.
- Any event ID 2000.

Exit codes: `0` success — whether it changed something or was already current; `1` failure.

## Sovereign clouds

Set `-VaultDnsSuffix` to the correct suffix for your cloud. The agent uses it both for the
vault URI and as the token audience, so no other change is needed.

| Cloud | Suffix |
|---|---|
| Azure Public | `vault.azure.net` *(default)* |
| Azure US Government | `vault.usgovcloudapi.net` |
| Azure China | `vault.azure.cn` |
