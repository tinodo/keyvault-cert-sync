# keyvault-cert-sync

Keep TLS certificates on Windows servers in step with Azure Key Vault, automatically.

An unattended agent that pulls the current version of a certificate from Key Vault using the
machine's **managed identity**, installs it into `LocalMachine\My`, and rebinds **AD FS**,
**Web Application Proxy** or **IIS** to it. Designed for certificates that rotate often —
ACME/Let's Encrypt issues 90-day certificates, which is too frequent to renew by hand.

- **No secrets on disk.** Authentication is the machine's managed identity. Nothing is stored
  but the script and its parameters.
- **No dependencies.** Windows PowerShell 5.1, the .NET Framework X.509 classes, and the role
  modules that ship with Windows. No Az modules, no Python, no third-party binaries.
- **Idempotent.** Safe to run hourly. If the bound certificate already matches the current
  Key Vault version, it exits without touching anything.
- **Conservative.** It will not re-point a binding that holds a certificate it cannot
  reasonably claim, and it will not delete a certificate that is still in use anywhere.

## Contents

- [Why this exists](#why-this-exists)
- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Documentation](#documentation)
- [Repository layout](#repository-layout)
- [Testing](#testing)
- [License](#license)

## Why this exists

Azure has good answers for certificate rotation on PaaS. On IaaS Windows — a domain-joined
AD FS farm, a Web Application Proxy in a perimeter network, an IIS server — there is no
built-in mechanism that notices a Key Vault certificate rolled over and rebinds the services
that depend on it.

The usual workarounds all have problems:

| Approach | Problem |
|---|---|
| Manual renewal | 90-day certificates means four outages a year per server, each one a chance to forget |
| Scheduled script with a service principal | A client secret or certificate to store, protect and itself rotate |
| `Set-AzKeyVaultSecret` + Az modules | A large dependency to install and keep current on a hardened server |
| Azure Key Vault VM extension | Imports the certificate but does **not** bind AD FS, WAP or IIS to it |

This agent does the last mile: import **and** bind, using an identity the VM already has.

## What it does

On each run:

1. Obtains a token from the Instance Metadata Service — Azure VM or Azure Arc-enabled server.
2. Reads the current certificate version metadata from Key Vault (a few hundred bytes).
3. If the installed and bound certificate already matches, logs it and exits.
4. Otherwise downloads the PFX, imports it, places chain certificates in `CA`/`Root`.
5. Grants the role's service account read access to the private key.
6. Rebinds according to the detected role:
   - **AD FS** — Service-Communications certificate and the TLS binding, then restarts `adfssrv`.
     Honours primary/secondary farm roles.
   - **WAP** — the proxy TLS certificate **and** every published application's own
     `ExternalCertificateThumbprint`, then restarts `appproxysvc`.
   - **IIS** — every in-scope https binding in `applicationHost.config`, then reconciles
     `http.sys`. IIS is deliberately not restarted.
7. Removes superseded certificates, never touching one that is still bound anywhere.

Everything is logged to the Application event log (source `KeyVaultCertSync`) and to a rolling
text log, with a small `state.json` breadcrumb for monitoring.

## Requirements

| | |
|---|---|
| OS | Windows Server 2016 or later (developed against Server 2025) |
| PowerShell | Windows PowerShell 5.1 — **not** PowerShell 7 |
| Identity | A managed identity on the VM (system- or user-assigned), or Azure Arc |
| Key Vault | The certificate, with its private key, stored as a Key Vault certificate |
| RBAC | **Key Vault Secrets User** *and* **Key Vault Certificate User** on the vault |

> **Both roles are required.** The agent reads certificate *metadata* first, then the PFX from
> the backing *secret*. With only Secrets User you get a valid token and then a `403` on the
> metadata call, which looks like an authentication bug but is not.
> See [docs/installation.md](docs/installation.md#grant-the-managed-identity-access).

PowerShell 7 is explicitly not supported: the `ADFS` and `WebApplicationProxy` modules do not
load there without the WinPSCompatSession shim. The installer always registers the task against
`powershell.exe` 5.1.

## Quick start

Run once per server, elevated:

```powershell
git clone https://github.com/tinodo/keyvault-cert-sync.git
cd keyvault-cert-sync

.\src\Install-CertSyncAgent.ps1 `
    -VaultName       kv-contoso-certs `
    -CertificateName contoso-com `
    -RunNow
```

That installs the agent under `%ProgramData%\KeyVaultCertSync`, registers a SYSTEM scheduled
task that runs every 4 hours and at startup, and performs one synchronisation immediately.

Check what it would do first, without changing anything:

```powershell
.\src\Sync-KeyVaultCertificate.ps1 -VaultName kv-contoso-certs -CertificateName contoso-com -WhatIf
```

Verify afterwards:

```powershell
.\tools\Verify-CertSync.ps1
```

For fleet deployment via Azure Compute Gallery VM Applications or Run Command, see
[docs/deployment.md](docs/deployment.md).

### Deploying to a fleet

For more than a couple of servers, publish the agent as an Azure Compute Gallery
**VM Application** — versioned, declarative, and visible in the VM's own resource definition:

```powershell
.\tools\Publish-GalleryVersion.ps1 `
    -Version 1.0.0 `
    -ResourceGroup rg-gallery -GalleryName mygallery -StorageAccount mystorageacct `
    -VaultName kv-contoso-certs -CertificateName contoso-com `
    -AssignToVm 'rg-identity/ADFS01','rg-dmz/WAP01','rg-web/WEBSRV01'
```

That builds the artifact, uploads it, generates and verifies a read SAS, publishes the version
through an ARM template, confirms it provisioned, and assigns it to the named VMs.

See [docs/vm-application.md](docs/vm-application.md) for the full pipeline, permissions, and
the non-obvious failure modes.

## Documentation

| Document | Covers |
|---|---|
| [docs/installation.md](docs/installation.md) | Prerequisites, RBAC, managed identity selection, first install |
| [docs/configuration.md](docs/configuration.md) | Every parameter, scheduling, logging, monitoring |
| [docs/iis.md](docs/iis.md) | IIS binding scopes, SNI, Central Certificate Store, http.sys |
| [docs/vm-application.md](docs/vm-application.md) | **Compute Gallery VM Application deployment**, permissions, gotchas |
| [docs/deployment.md](docs/deployment.md) | Direct install, Run Command, the self-contained build |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Failure modes and what they actually mean |
| [docs/architecture.md](docs/architecture.md) | Design decisions and the reasoning behind them |

## Repository layout

```
src/          The agent and its installer - what runs on the server
extensions/   Template for building a single self-contained deployment script
tools/        Build, probe and verification utilities (all read-only except the builder)
test/         91 tests across four suites, no Azure or elevation required
azure/        ARM template for publishing a VM Application version
docs/         Documentation
```

`dist/` is generated by `tools\Build-ExtensionScript.ps1` and is not committed.

## Testing

The suites extract functions from the agent via the PowerShell AST and exercise them without
needing Azure, a federation server or elevation. They run on any Windows machine.

```powershell
.\test\Test-SyncLogic.ps1          # 59 tests - agent logic
.\test\Test-ExtensionPayload.ps1   # 14 tests - build integrity
.\test\Test-InstallerStaging.ps1   #  9 tests - installer file handling
.\test\Test-GalleryTemplate.ps1    #  9 tests - ARM template vs. the agent it deploys
```

All four run in CI on every push — see [.github/workflows/ci.yml](.github/workflows/ci.yml).

## Contributing

Issues and pull requests are welcome. If you change anything under `src/`, run the three test
suites and `tools\Build-ExtensionScript.ps1` before opening a PR; CI does the same.

## Security

Please report security issues privately — see [SECURITY.md](SECURITY.md).

`tools\Test-NoSensitiveContent.ps1` scans a tree for credentials, key material and local
identifiers before you publish or share it. Its built-in checks are generic; supply values
specific to your own environment via `-ExtraPatternFile`, pointing at a file you keep out of
source control:

```powershell
.\tools\Test-NoSensitiveContent.ps1 -Path . -ExtraPatternFile ..\my-patterns.psd1 -IncludeGitHistory
```

## License

[MIT](LICENSE)
