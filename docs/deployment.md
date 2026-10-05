# Deployment

Three ways to get the agent onto servers, in increasing order of automation.

| Method | Good for |
|---|---|
| [Direct](#direct) | One server, or a first trial |
| [Run Command](#run-command) | A handful of servers, no gallery infrastructure |
| [VM Application](#vm-application) | A fleet, with versioning and repeatable rollout |

## Direct

Clone or copy the repository to the server and run the installer elevated. See
[installation.md](installation.md).

## The self-contained build

Both remote methods need the agent as a **single file**. `tools\Build-ExtensionScript.ps1`
base64-embeds `src\Sync-KeyVaultCertificate.ps1` and `src\Install-CertSyncAgent.ps1` into
`extensions\bootstrap-template.ps1` and writes `dist\certsync-extension.ps1`.

```powershell
.\tools\Build-ExtensionScript.ps1
```

Before writing anything it asserts that:

- both source scripts parse;
- the generated script parses;
- no `__*_B64__` placeholder survives in executable code;
- the embedded payload decodes back byte-for-byte;
- the result is small enough for the extension mechanism.

On the server the bootstrap writes both scripts to `%ProgramData%\KeyVaultCertSync\bin`,
re-parses them to catch a corrupted transfer, runs the installer, and exits non-zero on failure
so the deployment reports failure rather than going green.

`dist/` is generated and not committed. Rebuild after every change under `src/`.

## Run Command

```powershell
az vm run-command invoke `
  --resource-group <rg> --name <vm> `
  --command-id RunPowerShellScript `
  --scripts "@dist\certsync-extension.ps1" `
  --parameters VaultName=kv-contoso-certs CertificateName=contoso-com `
  --query "value[0].message" -o tsv
```

Accepted parameters: `VaultName`, `CertificateName`, `Role`, `IisBindingScope`, `IisSites`
(comma-separated), `IdentityClientId`, `IntervalHours`, `CleanupMode`, `RunNow`.

Run Command passes every parameter as a string, which the bootstrap accounts for — a
non-numeric `IntervalHours` falls back to the default rather than crashing.

> Run Command invocations against the same VM **serialise**. If one appears to hang, another
> is probably still running — including a VM Application install.

## VM Application

An Azure Compute Gallery **VM Application** gives you versioned, declarative deployment: set
the version on the VM and Azure installs it. This is the right choice for a fleet.

It has enough moving parts — and enough non-obvious failure modes — to warrant its own page:

**→ [vm-application.md](vm-application.md)**

The short version:

```powershell
.\tools\Publish-GalleryVersion.ps1 `
    -Version 1.0.0 `
    -ResourceGroup rg-gallery -GalleryName mygallery -StorageAccount mystorageacct `
    -VaultName kv-contoso-certs -CertificateName contoso-com `
    -AssignToVm 'rg-web/WEBSRV01'
```

That builds the artifact, uploads it, generates and verifies a read SAS, publishes the
version through `azure\publish-gallery-version.json`, confirms it provisioned, and assigns it.

Read [vm-application.md](vm-application.md) before the first run — particularly the
[gotchas](vm-application.md#gotchas), which cover why the ARM template exists, why a SAS is
required, and why `az vm application set` can silently remove your other applications.
## Upgrading

The agent is stateless apart from `state.json`, so upgrading is just deploying a newer version.
The installer replaces the scheduled task and overwrites the scripts. No migration, no cleanup.

Because `state.json` only caches the last result, a new build re-evaluates everything on its
first run regardless of what the previous one recorded.
