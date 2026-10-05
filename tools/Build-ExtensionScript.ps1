<#
.SYNOPSIS
    Builds the self-contained extension script from the agent sources.

.DESCRIPTION
    Reads src\Sync-KeyVaultCertificate.ps1 and src\Install-CertSyncAgent.ps1, base64-encodes
    them into extensions\bootstrap-template.ps1, and writes dist\certsync-extension.ps1.

    That one output file is everything the VM needs. Hand it to az:

        az vm run-command create ... --script "@dist\certsync-extension.ps1"

    There is no storage account, no SAS token, and nothing to copy to the VM first.

    Run this once, and again whenever you edit anything under src\.

    Validation performed before writing the output:
      * both source scripts parse
      * the generated file parses
      * no placeholder survives in executable code
      * the embedded payload decodes back byte-for-byte
      * the result is small enough for the extension mechanism you intend to use

.PARAMETER OutputPath
    Where to write the built script. Defaults to dist\certsync-extension.ps1.

.EXAMPLE
    .\Build-ExtensionScript.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

$root     = Split-Path $PSScriptRoot -Parent
$template = Join-Path $root 'extensions\bootstrap-template.ps1'
$syncPs1  = Join-Path $root 'src\Sync-KeyVaultCertificate.ps1'
$instPs1  = Join-Path $root 'src\Install-CertSyncAgent.ps1'

if (-not $OutputPath) { $OutputPath = Join-Path $root 'dist\certsync-extension.ps1' }

foreach ($f in $template, $syncPs1, $instPs1) {
    if (-not (Test-Path $f)) { throw "Missing required input: $f" }
}

function Assert-Parses {
    param([string]$Text, [string]$Label)
    $err = $null
    [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$null, [ref]$err) | Out-Null
    if ($err) {
        throw "$Label has $($err.Count) parse error(s); first at line $($err[0].Extent.StartLineNumber): $($err[0].Message)"
    }
}

Write-Host 'Building the certsync extension script' -ForegroundColor Cyan
Write-Host ('-' * 62)

$syncText = Get-Content $syncPs1 -Raw
$instText = Get-Content $instPs1 -Raw
Assert-Parses -Text $syncText -Label 'Sync-KeyVaultCertificate.ps1'
Assert-Parses -Text $instText -Label 'Install-CertSyncAgent.ps1'
Write-Host '  source scripts parse'

$syncB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($syncText))
$instB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($instText))

# Verify the encode/decode round-trip before it ever reaches a federation server.
if ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($syncB64)) -ne $syncText) {
    throw 'Sync-KeyVaultCertificate.ps1 did not survive base64 round-trip.'
}
if ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($instB64)) -ne $instText) {
    throw 'Install-CertSyncAgent.ps1 did not survive base64 round-trip.'
}
Write-Host '  payload round-trips byte-for-byte'

$built = (Get-Content $template -Raw).
            Replace('__SYNC_B64__',    $syncB64).
            Replace('__INSTALL_B64__', $instB64)

Assert-Parses -Text $built -Label 'generated certsync-extension.ps1'
Write-Host '  generated script parses'

# Placeholders are named in the header comment on purpose, so check executable code only.
$tokens = $null; $null = $null
[System.Management.Automation.Language.Parser]::ParseInput($built, [ref]$tokens, [ref]$null) | Out-Null
$codeText = ($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' '
foreach ($p in '__SYNC_B64__', '__INSTALL_B64__') {
    if ($codeText -match [regex]::Escape($p)) { throw "$p was not substituted." }
}
Write-Host '  no placeholders left in executable code'

$outDir = Split-Path $OutputPath -Parent
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

# UTF8 without BOM: az reads the file as text and a BOM can end up inside the script body.
[System.IO.File]::WriteAllText($OutputPath, $built, (New-Object System.Text.UTF8Encoding $false))

$sizeKB = [math]::Round((Get-Item $OutputPath).Length / 1KB, 1)
$cseKB  = [math]::Round(([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($built))).Length / 1KB, 1)

Write-Host ''
Write-Host "  wrote $OutputPath" -ForegroundColor Green
Write-Host "  size: $sizeKB KB inline, $cseKB KB if base64-wrapped for Custom Script Extension" -ForegroundColor Gray

if ($sizeKB -gt 250) {
    Write-Warning ("The built script is $sizeKB KB. Inline extension payloads are not unlimited - " +
                   'if a deployment starts failing on size, host this file in a blob and use ' +
                   '--script-uri (Run Command) or fileUris (CSE) instead of inlining it.')
}

Write-Host ''
Write-Host '  Deploy it with:' -ForegroundColor Cyan
Write-Host ''
Write-Host '    az vm run-command create \'
Write-Host '      --name InstallKeyVaultCertSync \'
Write-Host '      --vm-name <vm> --resource-group <rg> --subscription <sub> \'
Write-Host "      --script `"@$OutputPath`" \"
Write-Host '      --parameters VaultName=<vault> CertificateName=<cert> \'
Write-Host '      --timeout-in-seconds 1800'
Write-Host ''
