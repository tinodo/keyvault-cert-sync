# Regression tests for the installer's file staging.
#
# The bug these exist for: a VM Application stages both scripts into
# %ProgramData%\KeyVaultCertSync\bin and then runs the installer FROM that directory, so the
# installer's copy source and destination are the same file. Copy-Item throws
# "Cannot overwrite the item with itself", the installer exits non-zero, and the whole
# VM Application install fails with VMExtensionProvisioningError.
#
# Offline. Creates and deletes temp directories only.

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$inst = Join-Path $root 'src\Install-CertSyncAgent.ps1'

$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($inst, [ref]$tokens, [ref]$errors)
if ($errors) { throw 'Install-CertSyncAgent.ps1 has parse errors' }

$found = $false
foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    if ($fn.Name -eq 'Copy-AgentScript') { . ([scriptblock]::Create($fn.Extent.Text)); $found = $true }
}
if (-not $found) { throw 'Copy-AgentScript not found in the installer' }

$pass = 0; $fail = 0
function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try { & $Body; Write-Host "  PASS  $Name" -ForegroundColor Green; $script:pass++ }
    catch { Write-Host "  FAIL  $Name`n        $($_.Exception.Message)" -ForegroundColor Red; $script:fail++ }
}

$work = Join-Path $env:TEMP ("certsync-copytest-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $work -Force | Out-Null

Write-Host "PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
Write-Host ''
Write-Host 'Agent script staging' -ForegroundColor Cyan

try {
    Test-Case 'the hazard is real: Copy-Item onto itself throws' {
        $f = Join-Path $work 'hazard.ps1'
        Set-Content $f 'x'
        $threw = $false
        try { Copy-Item -LiteralPath $f -Destination $f -Force -ErrorAction Stop }
        catch { $threw = $true }
        if (-not $threw) { throw 'Copy-Item onto itself did not throw; this test no longer guards anything' }
    }

    Test-Case 'returns false and does not throw when source IS the destination' {
        $bin = Join-Path $work 'bin1'
        New-Item -ItemType Directory -Path $bin -Force | Out-Null
        $f = Join-Path $bin 'Sync-KeyVaultCertificate.ps1'
        Set-Content $f '# agent'
        $copied = Copy-AgentScript -Source $f -Destination $f
        if ($copied -ne $false) { throw "expected `$false, got '$copied'" }
        if (-not (Test-Path $f)) { throw 'the file was destroyed' }
        if ((Get-Content $f -Raw).Trim() -ne '# agent') { throw 'file contents changed' }
    }

    Test-Case 'same file reached by differently-cased paths is still detected' {
        $bin = Join-Path $work 'bin2'
        New-Item -ItemType Directory -Path $bin -Force | Out-Null
        $f = Join-Path $bin 'Sync-KeyVaultCertificate.ps1'
        Set-Content $f '# agent'
        $copied = Copy-AgentScript -Source $f.ToUpper() -Destination $f.ToLower()
        if ($copied -ne $false) { throw "case-different paths were treated as distinct files" }
    }

    Test-Case 'same file reached via a relative path segment is still detected' {
        $bin = Join-Path $work 'bin3'
        New-Item -ItemType Directory -Path $bin -Force | Out-Null
        $f = Join-Path $bin 'Sync-KeyVaultCertificate.ps1'
        Set-Content $f '# agent'
        $indirect = Join-Path (Join-Path $bin 'sub\..') 'Sync-KeyVaultCertificate.ps1'
        New-Item -ItemType Directory -Path (Join-Path $bin 'sub') -Force | Out-Null
        $copied = Copy-AgentScript -Source $indirect -Destination $f
        if ($copied -ne $false) { throw 'a relative path to the same file was treated as distinct' }
    }

    Test-Case 'a genuine copy still happens when the paths differ' {
        $src = Join-Path $work 'stage'
        $dst = Join-Path $work 'bin4'
        New-Item -ItemType Directory -Path $src, $dst -Force | Out-Null
        $sf = Join-Path $src 'Sync-KeyVaultCertificate.ps1'
        $df = Join-Path $dst 'Sync-KeyVaultCertificate.ps1'
        Set-Content $sf '# fresh agent'
        $copied = Copy-AgentScript -Source $sf -Destination $df
        if ($copied -ne $true) { throw "expected `$true, got '$copied'" }
        if (-not (Test-Path $df)) { throw 'destination file was not created' }
        if ((Get-Content $df -Raw).Trim() -ne '# fresh agent') { throw 'destination has wrong content' }
    }

    Test-Case 'an existing destination is overwritten, not skipped' {
        $src = Join-Path $work 'stage2'
        $dst = Join-Path $work 'bin5'
        New-Item -ItemType Directory -Path $src, $dst -Force | Out-Null
        $sf = Join-Path $src 'Sync-KeyVaultCertificate.ps1'
        $df = Join-Path $dst 'Sync-KeyVaultCertificate.ps1'
        Set-Content $sf '# new version'
        Set-Content $df '# old version'
        $copied = Copy-AgentScript -Source $sf -Destination $df
        if ($copied -ne $true) { throw 'copy was skipped' }
        if ((Get-Content $df -Raw).Trim() -ne '# new version') { throw 'destination was not updated' }
    }

    Test-Case 'a missing source throws a clear error' {
        $missing = Join-Path $work 'nope\Sync-KeyVaultCertificate.ps1'
        $msg = $null
        try { Copy-AgentScript -Source $missing -Destination (Join-Path $work 'bin6\x.ps1') }
        catch { $msg = $_.Exception.Message }
        if (-not $msg) { throw 'did not throw' }
        if ($msg -notmatch 'not found') { throw "unhelpful message: $msg" }
    }

    Write-Host ''
    Write-Host 'Installer wiring' -ForegroundColor Cyan
    $text = Get-Content $inst -Raw

    Test-Case 'the installer uses Copy-AgentScript rather than a bare Copy-Item' {
        if ($text -notmatch 'Copy-AgentScript -Source') { throw 'installer does not call Copy-AgentScript' }

        # Use the AST, not a regex: the helper's own doc comment mentions Copy-Item, and a
        # text search cannot tell a comment from a call.
        $tk = $null; $er = $null
        $tree = [System.Management.Automation.Language.Parser]::ParseFile($inst, [ref]$tk, [ref]$er)

        $helper = $tree.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Copy-AgentScript'
        }, $true) | Select-Object -First 1
        if (-not $helper) { throw 'Copy-AgentScript is not defined' }

        $calls = $tree.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.CommandAst] -and
            $n.GetCommandName() -eq 'Copy-Item'
        }, $true)

        foreach ($c in $calls) {
            $inHelper = $c.Extent.StartOffset -ge $helper.Extent.StartOffset -and
                        $c.Extent.EndOffset   -le $helper.Extent.EndOffset
            if (-not $inHelper) {
                throw "unguarded Copy-Item at line $($c.Extent.StartLineNumber)"
            }
        }
        Write-Host "        $($calls.Count) Copy-Item call(s), all inside the guarded helper" -ForegroundColor DarkGray
    }

    Test-Case 'the installer passes IdentityClientId through to the scheduled task' {
        if ($text -notmatch 'IdentityClientId') { throw 'IdentityClientId is not handled' }
    }
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
