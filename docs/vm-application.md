# Deploying as a VM Application (Azure Compute Gallery)

An Azure Compute Gallery **VM Application** is the best fit for a fleet: you publish a
version once, then set that version on each VM and Azure installs it. No Run Command
orchestration, no configuration management agent, and the assignment is visible in the VM's
own resource definition.

This page covers the whole pipeline and the handful of behaviours that are not obvious and
produce confusing errors when you hit them.

## Contents

- [How VM Applications work](#how-vm-applications-work)
- [One-time setup](#one-time-setup)
- [Publishing a version](#publishing-a-version)
- [Assigning to VMs](#assigning-to-vms)
- [Verifying an install](#verifying-an-install)
- [Gotchas](#gotchas)
- [Scale sets](#scale-sets)
- [Removing it](#removing-it)

## How VM Applications work

The model is worth understanding before the commands, because the failure modes follow
directly from it.

1. You upload an artifact — here, the single self-contained `certsync-extension.ps1` — to
   blob storage.
2. You create a **gallery application version** pointing at that blob. Azure copies the
   artifact into gallery-managed storage and replicates it to the regions you name.
3. You set the version on a VM. The **VM Application extension** on the VM downloads the
   artifact and runs the version's **install command**.
4. Changing the version on the VM runs the **update command**; removing it runs the
   **remove command**.

The artifact lands on the VM in a working directory as a file named **exactly after the
application, with no extension** — so `certsync`, not `certsync.ps1`. PowerShell will not
execute an extensionless file, which is why the install command starts with a rename:

```
rename certsync certsync.ps1 & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\certsync.ps1 ...
```

Manage actions run under **cmd.exe**, not PowerShell, hence `&` rather than `;`. The ARM
template builds this string from the application name so the two can never drift apart.

## One-time setup

You need a gallery, an application inside it, and a storage account for the artifact.

```powershell
# Gallery
az sig create --resource-group rg-gallery --gallery-name mygallery

# Application (one per piece of software; versions live underneath)
az sig gallery-application create `
  --resource-group rg-gallery --gallery-name mygallery `
  --name certsync --os-type Windows

# Storage for the artifact
az storage account create `
  --resource-group rg-gallery --name mystorageacct `
  --sku Standard_LRS --allow-blob-public-access false

az storage container create `
  --account-name mystorageacct --name scripts --auth-mode login
```

Leave public blob access **disabled**. The publish step uses a short-lived SAS instead.

### Permissions you need

| To do this | You need |
|---|---|
| Upload the artifact | **Storage Blob Data Contributor** on the storage account |
| Publish a version | **Contributor** on the gallery resource group |
| Assign to a VM | **Virtual Machine Contributor** on the VM |

Storage Blob Data Contributor is a **data-plane** role. The control-plane Contributor role
does not grant it, and `--auth-mode login` fails without it — a common first-run surprise.

## Publishing a version

### The easy way

`tools\Publish-GalleryVersion.ps1` runs the whole pipeline with validation at each stage:
build, preflight, upload, SAS, publish, verify, and optionally assign.

```powershell
.\tools\Publish-GalleryVersion.ps1 `
    -Version 1.0.0 `
    -ResourceGroup rg-gallery `
    -GalleryName mygallery `
    -StorageAccount mystorageacct `
    -VaultName kv-contoso-certs `
    -CertificateName contoso-com
```

Publish and roll out in one step:

```powershell
.\tools\Publish-GalleryVersion.ps1 -Version 1.0.1 `
    -ResourceGroup rg-gallery -GalleryName mygallery -StorageAccount mystorageacct `
    -VaultName kv-contoso-certs -CertificateName contoso-com `
    -AssignToVm 'rg-identity/ADFS01','rg-dmz/WAP01','rg-web/WEBSRV01'
```

Useful options:

| Option | Effect |
|---|---|
| `-Role IIS` | Pin the role instead of auto-detecting |
| `-IisBindingScope Matching` | Widen which IIS bindings may be re-pointed |
| `-IisSites 'Default Web Site'` | Restrict IIS updates to named sites |
| `-IntervalHours 1` | Check hourly instead of every 4 hours |
| `-IdentityClientId <guid>` | Pin a user-assigned identity |
| `-TargetRegion westeurope,northeurope` | Replicate to several regions |
| `-WhatIf` | Show what would happen, change nothing |
| `-SkipBuild` | Use the existing `dist\certsync-extension.ps1` |

The script refuses to reuse an existing version number unless you pass `-Force`, verifies
the SAS can actually read the blob before handing it to Azure, and deletes the temporary
parameters file afterwards because it contains a credential.

### The manual way

If you would rather drive it yourself:

```powershell
$ver = '1.0.0'

# 1. Build
.\tools\Build-ExtensionScript.ps1

# 2. Upload
az storage blob upload --account-name mystorageacct -c scripts `
  -n "certsync-$ver.ps1" -f dist\certsync-extension.ps1 --auth-mode login --overwrite

# 3. Read SAS, and prove it works
$expiry = (Get-Date).ToUniversalTime().AddHours(4).ToString('yyyy-MM-ddTHH:mmZ')
$sas = az storage blob generate-sas --account-name mystorageacct -c scripts `
         -n "certsync-$ver.ps1" --permissions r --expiry $expiry `
         --auth-mode login --as-user -o tsv
$url = "https://mystorageacct.blob.core.windows.net/scripts/certsync-$ver.ps1?$($sas.Trim())"
(Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing).StatusCode   # expect 200

# 4. Publish via the ARM template, passing parameters as a FILE
$p = @{
  '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
  contentVersion = '1.0.0.0'
  parameters     = @{
    galleryName     = @{ value = 'mygallery' }
    versionName     = @{ value = $ver }
    mediaLink       = @{ value = $url }
    vaultName       = @{ value = 'kv-contoso-certs' }
    certificateName = @{ value = 'contoso-com' }
  }
}
$f = "$env:TEMP\certsync-$ver.params.json"
$p | ConvertTo-Json -Depth 6 | Set-Content $f -Encoding UTF8

az deployment group create -g rg-gallery `
  --name "certsync-$($ver -replace '\.','-')" `
  --template-file azure\publish-gallery-version.json `
  --parameters "@$f"

Remove-Item $f -Force    # contains a SAS token
```

## Assigning to VMs

```powershell
$versionId = "/subscriptions/<sub>/resourceGroups/rg-gallery/providers/Microsoft.Compute" +
             "/galleries/mygallery/applications/certsync/versions/1.0.0"

az vm application set -g rg-web -n WEBSRV01 `
  --app-version-ids $versionId `
  --treat-deployment-as-failure true
```

Assignment triggers the install immediately, which registers the scheduled task and runs one
synchronisation. Re-assigning the same version re-runs it; the installer replaces the task
rather than duplicating it.

To upgrade, assign the new version. Azure runs the **update** command, which for this
application is identical to install.

## Verifying an install

The extension reports status back to Azure, so the first place to look is the VM's instance
view:

```powershell
az vm get-instance-view -g rg-web -n WEBSRV01 `
  --query "instanceView.extensions[?contains(name,'VMAppExtension')].{name:name,statuses:statuses[].{code:code,message:message}}" `
  -o json
```

On the VM itself the extension keeps logs under:

```
C:\Packages\Plugins\Microsoft.CPlat.Core.VMApplicationManagerWindows\<version>\Status\
C:\WindowsAzure\Logs\Plugins\Microsoft.CPlat.Core.VMApplicationManagerWindows\<version>\
```

The agent's own logs are separate and usually more informative:

```
%ProgramData%\KeyVaultCertSync\Logs\sync-YYYYMM.log
```

Or run the read-only checker:

```powershell
az vm run-command invoke -g rg-web -n WEBSRV01 `
  --command-id RunPowerShellScript `
  --scripts "@tools\Verify-CertSync.ps1" `
  --query "value[0].message" -o tsv
```

## Gotchas

These all produce errors whose text does not point at the cause.

### `az sig gallery-application version create` corrupts the manage actions

The install command contains `&` and the remove command contains nested single and double
quotes. Between PowerShell's parser and the CLI's argument handling, both arrive mangled —
typically surfacing as:

```
ERROR: unrecognized arguments: -TaskName 'KeyVault Certificate Sync' -TaskPath ...
```

Use the ARM template. It builds those strings server-side from plain parameters, so no shell
ever sees them. This is the entire reason `azure\publish-gallery-version.json` exists.

### A SAS URL cannot be passed with inline `--parameters`

The `&` separating SAS fields terminates the command:

```
'sv' is not recognized as an internal or external command
'sig' is not recognized as an internal or external command
```

Pass parameters as a **file**. Delete it afterwards — it contains a credential.

### The gallery cannot read a blob on a locked-down storage account

```
The gallery application version url '...' cannot be accessed due to the following error:
Public access is not permitted on this storage account.
```

Despite how it reads, the fix is not to enable public access. Supply a **read SAS**. Azure
copies the artifact into gallery-managed storage during ingestion, so the SAS only needs to
be valid for the publish itself — a few hours is plenty. Afterwards the stored `mediaLink`
shows the URL without the SAS, which makes it look as though the SAS was ignored.

### `az vm application set` replaces the whole application profile

It is not additive. If a VM already carries other gallery applications and you assign only
this one, **the others are removed**. Pass every application the VM should end up with in a
single call:

```powershell
az vm application set -g rg -n vm --app-version-ids $otherAppId $certsyncId
```

### Without `--treat-deployment-as-failure`, failures report success

By default a failing install still shows as a successful deployment. You then discover the
problem at certificate-renewal time, which is the worst possible moment. Always pass
`--treat-deployment-as-failure true`.

### Never reuse a version number

VMs referencing an overwritten version do not reliably pick up the new content. Bump the
version. `Publish-GalleryVersion.ps1` refuses to overwrite unless forced.

### Run Command and VM Application installs serialise

Both use the same extension handler pipeline. A `run-command invoke` issued while a VM
Application install is in progress blocks, or returns:

```
(Conflict) Run command extension execution is in progress.
```

Wait and retry — it is not a failure.

### Replication takes time

A version is only assignable in regions it has replicated to. Publishing to several regions
takes longer; the publish script reports which regions completed.

## Scale sets

The same version works for a VMSS, set at the scale set level:

```powershell
az vmss application set -g rg -n myscaleset `
  --app-version-ids $versionId --treat-deployment-as-failure true

az vmss update-instances -g rg -n myscaleset --instance-ids '*'
```

For a scale set, prefer `-IntervalHours 1` and keep the default jitter: instances created
from the same image otherwise align their schedules and hit Key Vault simultaneously.

## Removing it

```powershell
# Remove all gallery applications from the VM, running each remove command
az vm application set -g rg-web -n WEBSRV01 --app-version-ids
```

The remove command unregisters the scheduled task. It deliberately leaves the installed
certificate and the bindings in place — uninstalling the agent must never take a service
offline. To clean up fully, afterwards:

```powershell
Remove-Item "$env:ProgramData\KeyVaultCertSync" -Recurse -Force
```
