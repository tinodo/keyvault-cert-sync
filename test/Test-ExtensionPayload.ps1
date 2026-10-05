# Validates the VM-extension script build entirely offline.
#
# tools\Build-ExtensionScript.ps1 embeds the two agent scripts into the bootstrap template
# and writes dist\certsync-extension.ps1. If that produced broken PowerShell you would not
# find out until the extension had already run on a federation server. This reproduces the
# same steps locally and checks the result parses and round-trips.
#
# Also fails if dist\ is stale relative to src\, so you cannot deploy an old build by mistake.
#
# Run with:  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-ExtensionPayload.ps1
# No Azure calls. Writes nothing.

$ErrorActionPreference = 'Stop'
$root     = Split-Path $PSScriptRoot -Parent
$extDir   = Join-Path $root 'extensions'
$srcDir   = Join-Path $root 'src'
$template = Join-Path $extDir 'bootstrap-template.ps1'
$syncPs1  = Join-Path $srcDir 'Sync-KeyVaultCertificate.ps1'
$instPs1  = Join-Path $srcDir 'Install-CertSyncAgent.ps1'
$built    = Join-Path $root 'dist\certsync-extension.ps1'

$pass = 0; $fail = 0
function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try { & $Body; Write-Host "  PASS  $Name" -ForegroundColor Green; $script:pass++ }
    catch { Write-Host "  FAIL  $Name`n        $($_.Exception.Message)" -ForegroundColor Red; $script:fail++ }
}

function Test-Parses {
    param([string]$Text, [string]$Label)
    $err = $null
    [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$null, [ref]$err) | Out-Null
    if ($err) { throw "$Label has $($err.Count) parse error(s); first: L$($err[0].Extent.StartLineNumber) $($err[0].Message)" }
}

function Get-CodeTokens {
    param([string]$Text)
    $tokens = $null
    [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$null) | Out-Null
    return ($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' '
}

Write-Host "PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
Write-Host ''
Write-Host 'Inputs' -ForegroundColor Cyan

Test-Case 'all input files exist' {
    foreach ($f in $template, $syncPs1, $instPs1) { if (-not (Test-Path $f)) { throw "missing $f" } }
}

Test-Case 'template is valid PowerShell before substitution' {
    Test-Parses -Text (Get-Content $template -Raw) -Label 'bootstrap-template.ps1'
}

Test-Case 'template declares the parameters the deploy command passes' {
    $t = Get-Content $template -Raw
    foreach ($p in 'VaultName','CertificateName','Role','IdentityClientId','IntervalHours','CleanupMode','RunNow') {
        if ($t -notmatch "\`$$p\b") { throw "template does not declare -$p" }
    }
}

# --- reproduce what Build-ExtensionScript.ps1 does ---------------------------
$syncB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content $syncPs1 -Raw)))
$instB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content $instPs1 -Raw)))
$payload = (Get-Content $template -Raw).Replace('__SYNC_B64__', $syncB64).Replace('__INSTALL_B64__', $instB64)

Write-Host ''
Write-Host 'Generated script' -ForegroundColor Cyan

Test-Case 'substituted payload is valid PowerShell' {
    Test-Parses -Text $payload -Label 'generated extension script'
    Write-Host "        payload is $([int]($payload.Length/1KB)) KB" -ForegroundColor DarkGray
}

Test-Case 'no placeholder tokens survive in executable code' {
    $code = Get-CodeTokens -Text $payload
    foreach ($p in '__SYNC_B64__', '__INSTALL_B64__') {
        if ($code -match [regex]::Escape($p)) { throw "$p still present in code" }
    }
    $live = [regex]::Matches($code, '__[A-Z0-9_]+__') | ForEach-Object { $_.Value } | Sort-Object -Unique
    if ($live.Count) { throw "unsubstituted: $($live -join ', ')" }
}

Test-Case 'embedded sync script round-trips byte-for-byte' {
    $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($syncB64))
    if ($decoded -ne (Get-Content $syncPs1 -Raw)) { throw 'decoded sync script differs from source' }
    Test-Parses -Text $decoded -Label 'decoded Sync-KeyVaultCertificate.ps1'
}

Test-Case 'embedded installer round-trips byte-for-byte' {
    $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($instB64))
    if ($decoded -ne (Get-Content $instPs1 -Raw)) { throw 'decoded installer differs from source' }
    Test-Parses -Text $decoded -Label 'decoded Install-CertSyncAgent.ps1'
}

Test-Case 'payload survives the base64 wrapping a CSE deployment would apply' {
    $wrapped = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
    $back    = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($wrapped))
    if ($back -ne $payload) { throw 'payload did not survive the outer base64 round-trip' }
    Test-Parses -Text $back -Label 'CSE-wrapped payload'
    Write-Host "        CSE settings would carry $([int]($wrapped.Length/1KB)) KB" -ForegroundColor DarkGray
}

Test-Case 'generated script has no BOM, which az would otherwise send inside the body' {
    if (Test-Path $built) {
        $bytes = [System.IO.File]::ReadAllBytes($built) | Select-Object -First 3
        if ($bytes.Count -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            throw 'dist\certsync-extension.ps1 starts with a UTF-8 BOM'
        }
    } else {
        Write-Host '        (dist not built yet - run tools\Build-ExtensionScript.ps1)' -ForegroundColor DarkGray
    }
}

Test-Case 'the built artifact on disk matches a fresh build of the current sources' {
    if (-not (Test-Path $built)) { throw 'dist\certsync-extension.ps1 not found - run tools\Build-ExtensionScript.ps1' }
    $onDisk = Get-Content $built -Raw
    if ($onDisk -ne $payload) {
        throw 'dist\certsync-extension.ps1 is stale - src\ has changed since it was built. Re-run tools\Build-ExtensionScript.ps1.'
    }
}

Write-Host ''
Write-Host 'Runtime parameter handling' -ForegroundColor Cyan

Test-Case 'a non-numeric IntervalHours is tolerated rather than crashing the extension' {
    # Run Command passes every parameter as a string, so the guard matters.
    if ($payload -notmatch 'defaulting to 4') { throw 'no fallback path for a non-numeric interval' }
    if ($payload -notmatch "IntervalHours -match '\^\\d\+\\\$'") {
        if ($payload -notmatch 'IntervalHours -match') { throw 'no numeric validation on IntervalHours' }
    }
}

Test-Case 'an empty IdentityClientId is omitted rather than passed as an empty string' {
    if ($payload -notmatch 'if \(\$IdentityClientId\)') {
        throw 'IdentityClientId is not guarded before being added to the installer arguments'
    }
}

Test-Case 'the extension exits non-zero on failure so a broken install is not reported green' {
    if ($payload -notmatch 'exit 1') { throw 'no non-zero exit path' }
    if ($payload -notmatch 'the scheduled task was not registered') {
        throw 'the script does not verify the scheduled task was actually created'
    }
}

Test-Case 'the extension verifies both scripts parse on the VM after transfer' {
    if ($payload -notmatch 'failed to parse after transfer') {
        throw 'no post-transfer integrity check'
    }
}

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })

