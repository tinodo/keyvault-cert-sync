<#
.SYNOPSIS
    Builds, uploads and publishes a version of the agent as an Azure Compute Gallery
    VM Application, then optionally assigns it to VMs.

.DESCRIPTION
    Runs the whole pipeline with validation at each step, so a failure tells you which
    stage broke rather than leaving a half-published version behind:

      1. Build        - tools\Build-ExtensionScript.ps1 (skip with -SkipBuild)
      2. Preflight    - gallery, application and storage container exist; version is new
      3. Upload       - the built script to blob storage
      4. SAS          - short-lived read SAS, proven to fetch before it is handed to Azure
      5. Publish      - ARM deployment of azure\publish-gallery-version.json
      6. Verify       - the version provisioned successfully
      7. Assign       - optional, to one or more VMs

    Two things this handles that a hand-rolled az command does not:

      * `az sig gallery-application version create` mangles the manage-action strings.
        The install command contains '&' and the remove command contains nested quotes;
        between PowerShell's parser and the CLI's argument handling both arrive corrupted.
        The ARM template builds them server-side instead.

      * A SAS URL cannot be passed with inline --parameters, because the '&' separating
        SAS fields terminates the command. Parameters go through a temp file, which is
        deleted afterwards because it contains a credential.

.PARAMETER Version
    Semantic version to publish, e.g. 1.0.0. Must not already exist.

.PARAMETER ResourceGroup
    Resource group containing the compute gallery.

.PARAMETER GalleryName
    Name of the Azure Compute Gallery.

.PARAMETER StorageAccount
    Storage account hosting the artifact. You need Storage Blob Data Contributor on it.

.PARAMETER VaultName
    Short name of the Key Vault the agent will read, e.g. kv-contoso-certs.

.PARAMETER CertificateName
    Certificate object name in that vault, e.g. contoso-com.

.PARAMETER AssignToVm
    Optional. One or more VMs to assign the new version to, as 'resourceGroup/name' or
    'subscription/resourceGroup/name'.

.EXAMPLE
    .\Publish-GalleryVersion.ps1 -Version 1.0.0 `
        -ResourceGroup rg-gallery -GalleryName mygallery `
        -StorageAccount mystorageacct `
        -VaultName kv-contoso-certs -CertificateName contoso-com

.EXAMPLE
    # Publish and roll out in one go.
    .\Publish-GalleryVersion.ps1 -Version 1.0.1 `
        -ResourceGroup rg-gallery -GalleryName mygallery -StorageAccount mystorageacct `
        -VaultName kv-contoso-certs -CertificateName contoso-com `
        -AssignToVm 'rg-identity/ADFS01','rg-dmz/WAP01'

.EXAMPLE
    # See what would happen without touching anything.
    .\Publish-GalleryVersion.ps1 -Version 1.0.2 ... -WhatIf

.NOTES
    Requires the Azure CLI, logged in, with rights to the gallery and storage account.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory = $true)][string]$ResourceGroup,
    [Parameter(Mandatory = $true)][string]$GalleryName,
    [Parameter(Mandatory = $true)][string]$StorageAccount,
    [Parameter(Mandatory = $true)][string]$VaultName,
    [Parameter(Mandatory = $true)][string]$CertificateName,

    [string]$ApplicationName = 'certsync',
    [string]$Container       = 'scripts',
    [string]$Subscription,

    [ValidateSet('Auto', 'ADFS', 'WAP', 'IIS', 'None')][string]$Role = 'Auto',
    [ValidateSet('Managed', 'Matching', 'All')][string]$IisBindingScope = 'Managed',
    [string[]]$IisSites = @(),
    [ValidateRange(1, 24)][int]$IntervalHours = 4,
    [ValidateSet('None', 'Expired', 'KeepLatest')][string]$CleanupMode = 'Expired',
    [string]$IdentityClientId,

    [string[]]$TargetRegion = @(),
    [ValidateRange(1, 10)][int]$ReplicaCount = 1,
    [int]$SasHours = 4,

    [string[]]$AssignToVm = @(),
    [switch]$SkipBuild,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent

function Step { param([string]$m) Write-Host ("==> {0}" -f $m) -ForegroundColor Cyan }
function Ok   { param([string]$m) Write-Host ("    {0}" -f $m) -ForegroundColor Green }
function Note { param([string]$m) Write-Host ("    {0}" -f $m) -ForegroundColor Gray }

function Invoke-Az {
    <#
        Runs the Azure CLI and throws on failure with the actual error text.

        az writes errors to stderr and signals failure only through the exit code, so a
        plain call silently continues on failure and the next step fails somewhere less
        obvious.
    #>
    param([string[]]$Arguments, [switch]$AllowFailure)

    $out = & az @Arguments 2>&1
    $text = ($out | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        if ($AllowFailure) { return $null }
        throw ("az {0}`n{1}" -f ($Arguments -join ' '), $text)
    }
    return $text
}

$subArgs = @()
if ($Subscription) { $subArgs = @('--subscription', $Subscription) }

Write-Host ''
Write-Host ("Publishing {0} {1} to gallery {2}" -f $ApplicationName, $Version, $GalleryName) -ForegroundColor White
Write-Host ('-' * 70)

# --- 1. build ----------------------------------------------------------------
$artifact = Join-Path $root 'dist\certsync-extension.ps1'
if ($SkipBuild) {
    if (-not (Test-Path $artifact)) { throw "-SkipBuild was passed but $artifact does not exist." }
    Step 'Build skipped'
    Note ("using existing {0} ({1:N0} bytes)" -f $artifact, (Get-Item $artifact).Length)
} else {
    Step 'Building the self-contained extension script'
    & (Join-Path $root 'tools\Build-ExtensionScript.ps1') | Out-Null
    if (-not (Test-Path $artifact)) { throw 'Build did not produce dist\certsync-extension.ps1.' }
    Ok ("built ({0:N0} bytes)" -f (Get-Item $artifact).Length)
}

# --- 2. preflight ------------------------------------------------------------
Step 'Preflight'

$acct = Invoke-Az (@('account', 'show', '--query', '{name:name,id:id}', '-o', 'json') + $subArgs)
Note ("signed in to {0}" -f (($acct | ConvertFrom-Json).name))

$null = Invoke-Az (@('sig', 'show', '-g', $ResourceGroup, '--gallery-name', $GalleryName, '-o', 'none') + $subArgs)
Ok "gallery '$GalleryName' exists"

$null = Invoke-Az (@('sig', 'gallery-application', 'show', '-g', $ResourceGroup,
                     '--gallery-name', $GalleryName, '--name', $ApplicationName, '-o', 'none') + $subArgs)
Ok "application '$ApplicationName' exists"

$existing = Invoke-Az (@('sig', 'gallery-application', 'version', 'show', '-g', $ResourceGroup,
                         '--gallery-name', $GalleryName, '--application-name', $ApplicationName,
                         '--gallery-application-version-name', $Version,
                         '--query', 'provisioningState', '-o', 'tsv') + $subArgs) -AllowFailure
if ($existing) {
    if (-not $Force) {
        throw ("Version $Version already exists (provisioningState=$existing). " +
               'Bump the version rather than overwriting it: VMs referencing an overwritten ' +
               'version do not reliably pick up the change. Use -Force only if you are certain.')
    }
    Write-Warning "Version $Version already exists and -Force was passed; it will be replaced."
}
Ok "version $Version is new"

$blobName = "$ApplicationName-$Version.ps1"
$exists = Invoke-Az (@('storage', 'blob', 'exists', '--account-name', $StorageAccount,
                       '-c', $Container, '-n', $blobName, '--auth-mode', 'login',
                       '--query', 'exists', '-o', 'tsv') + $subArgs) -AllowFailure
if ($null -eq $exists) {
    throw ("Could not reach container '$Container' on storage account '$StorageAccount'. " +
           'Check the names, and that you hold Storage Blob Data Contributor (the control-plane ' +
           'Contributor role is not sufficient for --auth-mode login).')
}
Ok "storage container '$Container' reachable"

# --- 3. upload ---------------------------------------------------------------
Step "Uploading $blobName"
if ($PSCmdlet.ShouldProcess("$StorageAccount/$Container/$blobName", 'Upload artifact')) {
    $null = Invoke-Az (@('storage', 'blob', 'upload', '--account-name', $StorageAccount,
                         '-c', $Container, '-n', $blobName, '-f', $artifact,
                         '--auth-mode', 'login', '--overwrite', '-o', 'none') + $subArgs)
    Ok 'uploaded'
} else {
    Note 'skipped (WhatIf)'
}

# --- 4. SAS ------------------------------------------------------------------
Step 'Generating a read SAS'
Note 'Required because the gallery cannot read a blob on an account that blocks public access.'

$url = $null
if ($PSCmdlet.ShouldProcess($blobName, 'Generate read SAS')) {
    $expiry = (Get-Date).ToUniversalTime().AddHours($SasHours).ToString('yyyy-MM-ddTHH:mmZ')
    $sas = Invoke-Az (@('storage', 'blob', 'generate-sas', '--account-name', $StorageAccount,
                        '-c', $Container, '-n', $blobName, '--permissions', 'r',
                        '--expiry', $expiry, '--auth-mode', 'login', '--as-user', '-o', 'tsv') + $subArgs)
    if (-not $sas) { throw 'Failed to generate a SAS token.' }
    $url = "https://$StorageAccount.blob.core.windows.net/$Container/$blobName`?$($sas.Trim())"

    # Prove it before handing it to Azure: a SAS that cannot read produces a confusing
    # "Public access is not permitted" error from the gallery several minutes later.
    try {
        $head = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -TimeoutSec 30
        Ok ("SAS verified: HTTP {0}, {1:N0} bytes" -f $head.StatusCode, $head.Headers['Content-Length'])
    } catch {
        throw "The generated SAS could not read the blob: $($_.Exception.Message)"
    }
} else {
    Note 'skipped (WhatIf)'
}

# --- 5. publish --------------------------------------------------------------
Step 'Publishing the gallery application version'

$paramObject = @{
    '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
    contentVersion = '1.0.0.0'
    parameters     = @{
        galleryName     = @{ value = $GalleryName }
        applicationName = @{ value = $ApplicationName }
        versionName     = @{ value = $Version }
        mediaLink       = @{ value = $url }
        vaultName       = @{ value = $VaultName }
        certificateName = @{ value = $CertificateName }
        role            = @{ value = $Role }
        iisBindingScope = @{ value = $IisBindingScope }
        intervalHours   = @{ value = $IntervalHours }
        cleanupMode     = @{ value = $CleanupMode }
        replicaCount    = @{ value = $ReplicaCount }
    }
}
if ($IisSites.Count -gt 0)  { $paramObject.parameters.iisSites         = @{ value = ($IisSites -join ',') } }
if ($IdentityClientId)      { $paramObject.parameters.identityClientId = @{ value = $IdentityClientId } }
if ($TargetRegion.Count -gt 0) {
    $paramObject.parameters.targetRegions = @{
        value = @($TargetRegion | ForEach-Object {
            @{ name = $_; regionalReplicaCount = $ReplicaCount; storageAccountType = 'Standard_LRS' }
        })
    }
}

$deploymentName = "$ApplicationName-$($Version -replace '\.', '-')"
$template = Join-Path $root 'azure\publish-gallery-version.json'

if ($PSCmdlet.ShouldProcess("$GalleryName/$ApplicationName/$Version", 'Create gallery application version')) {
    # A parameters FILE, not inline --parameters: the '&' separating SAS fields would
    # otherwise terminate the command and produce errors like
    # "'sv' is not recognized as an internal or external command".
    $paramFile = Join-Path ([System.IO.Path]::GetTempPath()) "$deploymentName.params.json"
    try {
        $paramObject | ConvertTo-Json -Depth 6 | Set-Content -Path $paramFile -Encoding UTF8
        $result = Invoke-Az (@('deployment', 'group', 'create', '-g', $ResourceGroup,
                               '--name', $deploymentName, '--template-file', $template,
                               '--parameters', "@$paramFile",
                               '--query', 'properties.outputs', '-o', 'json') + $subArgs)
        Ok 'published'
        $outputs = $result | ConvertFrom-Json
        Note ('install command: ' + $outputs.installCommand.value)
    } finally {
        # Contains a SAS token.
        Remove-Item $paramFile -Force -ErrorAction SilentlyContinue
    }
} else {
    Note 'skipped (WhatIf)'
}

# --- 6. verify ---------------------------------------------------------------
Step 'Verifying'
$versionId = $null
if ($PSCmdlet.ShouldProcess($Version, 'Verify provisioning state')) {
    $state = Invoke-Az (@('sig', 'gallery-application', 'version', 'show', '-g', $ResourceGroup,
                          '--gallery-name', $GalleryName, '--application-name', $ApplicationName,
                          '--gallery-application-version-name', $Version,
                          '--query', '{state:provisioningState,id:id,regions:publishingProfile.targetRegions[].name}',
                          '-o', 'json') + $subArgs) | ConvertFrom-Json
    if ($state.state -ne 'Succeeded') { throw "Version $Version provisioned as '$($state.state)'." }
    $versionId = $state.id
    Ok ("provisioningState = Succeeded, replicated to: {0}" -f ($state.regions -join ', '))
} else {
    Note 'skipped (WhatIf)'
}

# --- 7. assign ---------------------------------------------------------------
if ($AssignToVm.Count -gt 0) {
    Step 'Assigning to VMs'
    Write-Warning ('az vm application set REPLACES the entire application profile on the VM. ' +
                   'If these VMs carry other gallery applications, assign them all in one call ' +
                   'or they will be removed.')

    foreach ($target in $AssignToVm) {
        $parts = $target -split '/'
        switch ($parts.Count) {
            2 { $vmSub = $Subscription; $vmRg = $parts[0]; $vmName = $parts[1] }
            3 { $vmSub = $parts[0];     $vmRg = $parts[1]; $vmName = $parts[2] }
            default { throw "AssignToVm entry '$target' must be 'rg/vm' or 'sub/rg/vm'." }
        }
        $vmSubArgs = @()
        if ($vmSub) { $vmSubArgs = @('--subscription', $vmSub) }

        if (-not $PSCmdlet.ShouldProcess("$vmRg/$vmName", "Assign $ApplicationName $Version")) { continue }

        Note "assigning to $vmRg/$vmName ..."
        $null = Invoke-Az (@('vm', 'application', 'set', '-g', $vmRg, '-n', $vmName,
                             '--app-version-ids', $versionId,
                             '--treat-deployment-as-failure', 'true', '-o', 'none') + $vmSubArgs)
        Ok "$vmRg/$vmName assigned"
    }
}

Write-Host ''
Write-Host ('-' * 70)
Write-Host ("Done. {0} {1} published." -f $ApplicationName, $Version) -ForegroundColor Green
if ($versionId) {
    Write-Host ''
    Write-Host 'Assign it to a VM with:' -ForegroundColor Cyan
    Write-Host ("  az vm application set -g <rg> -n <vm> ``") -ForegroundColor Gray
    Write-Host ("    --app-version-ids {0} ``" -f $versionId) -ForegroundColor Gray
    Write-Host ("    --treat-deployment-as-failure true") -ForegroundColor Gray
}
Write-Host ''
