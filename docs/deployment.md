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
the version on the VM and Azure installs it.

### One-time setup

```powershell
az sig create --resource-group <rg> --gallery-name <gallery>

az sig gallery-application create `
  --resource-group <rg> --gallery-name <gallery> `
  --name certsync --os-type Windows
```

You also need a storage account to host the artifact.

### Publish a version

Bump the version number every time. Never overwrite a published one — VMs referencing it will
not reliably pick up the change.

```powershell
$ver     = '1.0.0'
$account = '<storage-account>'
$rg      = '<gallery-rg>'

az storage blob upload `
  --account-name $account -c scripts `
  -n "certsync-$ver.ps1" -f dist\certsync-extension.ps1 `
  --auth-mode login --overwrite

$expiry = (Get-Date).ToUniversalTime().AddHours(4).ToString('yyyy-MM-ddTHH:mmZ')
$sas = az storage blob generate-sas `
  --account-name $account -c scripts -n "certsync-$ver.ps1" `
  --permissions r --expiry $expiry --auth-mode login --as-user -o tsv

$url = "https://$account.blob.core.windows.net/scripts/certsync-$ver.ps1?$($sas.Trim())"

# Prove the SAS reads before handing it to the gallery.
(Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing).StatusCode
```

Then create the version with the ARM template in `azure\`:

```powershell
$p = @{
  '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
  contentVersion = '1.0.0.0'
  parameters     = @{
    versionName     = @{ value = $ver }
    mediaLink       = @{ value = $url }
    galleryName     = @{ value = '<gallery>' }
    vaultName       = @{ value = 'kv-contoso-certs' }
    certificateName = @{ value = 'contoso-com' }
  }
}
$path = "$env:TEMP\certsync-$ver.params.json"
$p | ConvertTo-Json -Depth 5 | Set-Content $path -Encoding UTF8

az deployment group create `
  --resource-group $rg `
  --name "certsync-$($ver -replace '\.','-')" `
  --template-file azure\publish-gallery-version.json `
  --parameters "@$path"

Remove-Item $path -Force
```

### Why an ARM template and not `az sig gallery-application version create`

Two problems make the direct CLI call unreliable, both of which produce confusing failures:

**The manage-action strings get mangled.** The install command contains `&` and the remove
command contains nested single and double quotes. Between PowerShell's parser and the CLI's
argument handling, both arrive corrupted — typically as
`unrecognized arguments: -TaskName 'KeyVault Certificate Sync' ...`. The ARM template builds
these strings server-side from simple parameters, so no shell ever sees them.

**A SAS URL cannot be passed inline.** The `&` separating SAS fields terminates the command,
producing errors like `'sv' is not recognized as an internal or external command`. Passing the
parameters as a **file** avoids this entirely.

### Why a SAS is needed

If the storage account blocks public blob access — which it should — the gallery cannot read a
bare blob URL and fails with:

```
The gallery application version url '...' cannot be accessed due to the following error:
Public access is not permitted on this storage account.
```

A short-lived read SAS solves it. Azure copies the artifact into gallery-managed storage during
ingestion, so the SAS only needs to be valid for the duration of the publish — a few hours is
ample. The stored `mediaLink` afterwards shows the URL without the SAS.

### Assign to VMs

```powershell
$version = "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute" +
           "/galleries/<gallery>/applications/certsync/versions/1.0.0"

az vm application set `
  --resource-group <rg> --name <vm> `
  --app-version-ids $version `
  --treat-deployment-as-failure true
```

`--treat-deployment-as-failure true` matters: without it a failed install reports success and
you discover the problem at renewal time.

`az vm application set` **replaces the entire application profile** on the VM. If the VM carries
other applications, pass all of them in one call.

Setting the version triggers install, which re-registers the scheduled task and runs one
synchronisation immediately. Re-running is safe — the installer replaces the task rather than
duplicating it.

### Verify the rollout

```powershell
az vm run-command invoke `
  --resource-group <rg> --name <vm> `
  --command-id RunPowerShellScript `
  --scripts "@tools\Verify-CertSync.ps1" `
  --query "value[0].message" -o tsv
```

Or across a fleet, with `tools\Check-AgentVersion.ps1`, which reports the agent's SHA-256 and
which capabilities its build carries.

## Upgrading

The agent is stateless apart from `state.json`, so upgrading is just deploying a newer version.
The installer replaces the scheduled task and overwrites the scripts. No migration, no cleanup.

Because `state.json` only caches the last result, a new build re-evaluates everything on its
first run regardless of what the previous one recorded.
