<#
.SYNOPSIS
    Scans a tree for credentials, key material and local-machine identifiers before you
    publish or share it.

.DESCRIPTION
    Two classes of check:

      BLOCKING  - must be zero. Credential literals, private keys, storage SAS tokens,
                  bearer tokens, and local profile paths.
      REVIEW    - reported for a human to judge. GUIDs, thumbprints, hostnames, IPs and
                  email-shaped strings are legitimate in documentation and test fixtures,
                  so they are listed with context rather than failed automatically.

    The built-in checks are deliberately GENERIC. Values specific to your environment -
    internal domain names, server names, certificate thumbprints, service accounts - are
    not listed here, because a scanner that hardcodes them would publish the very strings
    it is meant to catch.

    Supply those through -ExtraPatternFile, pointing at a file you do NOT commit.

.PARAMETER Path
    Root of the tree to scan.

.PARAMETER ExtraPatternFile
    Optional. A PowerShell data file (.psd1) contributing environment-specific checks.
    Keep it outside the repository, or add it to .gitignore. Format:

        @{
            Blocking = @(
                @{ Name = 'internal domain'; Pattern = '(?i)mycompany\.internal' }
                @{ Name = 'server names';    Pattern = '(?i)\b(SRV01|SRV02)\b' }
            )
            Allow = @('192.0.2.1', 'example.internal')
            Accepted = @(
                @{ File = 'LICENSE'; Check = 'local username'; Why = 'copyright holder' }
            )
        }

.PARAMETER IncludeGitHistory
    Also scan every blob in git history, not just the working tree. Rewriting history is
    far harder than not committing in the first place, so run this before making a
    repository public.

.EXAMPLE
    .\Test-NoSensitiveContent.ps1 -Path .

.EXAMPLE
    .\Test-NoSensitiveContent.ps1 -Path . -ExtraPatternFile ..\my-private-patterns.psd1 -IncludeGitHistory
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$ExtraPatternFile,
    [switch]$IncludeGitHistory
)

$ErrorActionPreference = 'Stop'

# --- generic: things that are never acceptable in a published tree ------------
$blocking = @(
    @{ Name = 'private key block';     Pattern = '-----BEGIN [A-Z ]*PRIVATE KEY-----' },
    @{ Name = 'storage SAS token';     Pattern = '[?&]s(i?g|v)=[A-Za-z0-9%+/=]{16,}' },
    @{ Name = 'JWT or PAT';            Pattern = '(?i)\b(eyJ[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})' },
    @{ Name = 'AWS access key';        Pattern = '\b(AKIA|ASIA)[0-9A-Z]{16}\b' },
    @{ Name = 'hardcoded password';    Pattern = "(?i)(password|passwd|pwd)\s*=\s*[`"'][^`"'`$)\r\n]{4,}" },
    @{ Name = 'client secret';         Pattern = "(?i)(client_secret|clientsecret)\s*=\s*[`"'][^`"'`$]+" },
    @{ Name = 'connection string';     Pattern = '(?i)(AccountKey|SharedAccessKey|Password)=[A-Za-z0-9+/=]{16,}' },
    @{ Name = 'plaintext securestring';Pattern = "(?i)ConvertTo-SecureString\s+[`"'][^`"'`$]{8,}" },
    @{ Name = 'local profile path';    Pattern = '(?i)[A-Z]:\\Users\\[a-z0-9._-]+\\' },
    @{ Name = 'OneDrive tenant path';  Pattern = '(?i)OneDrive\s*-\s*\w' }
)

# --- reported, not failed ----------------------------------------------------
$review = @(
    @{ Name = 'GUID';        Pattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' },
    @{ Name = 'SHA1-shaped'; Pattern = '\b[0-9a-fA-F]{40}\b' },
    @{ Name = 'email';       Pattern = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' },
    @{ Name = 'routable IP'; Pattern = '\b(?!0\.|127\.|255\.)(?:\d{1,3}\.){3}\d{1,3}\b' },
    @{ Name = 'UNC path';    Pattern = '\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9._$-]+' },
    @{ Name = 'FQDN';        Pattern = '(?i)\b[a-z0-9-]+\.[a-z0-9-]+\.(com|net|org|local|io|cn)\b' }
)

# Known-public constants and reserved documentation values, excluded from REVIEW noise.
$allow = @(
    '4dc3e181-e14b-4a21-b022-59fc669b0914'      # documented IIS http.sys application ID
    '00000000-0000-0000-0000-000000000000'      # null GUID
    '4633458b-17de-408a-b874-0445c86b69e6'      # Azure role definition: Key Vault Secrets User
    'db79e9a7-68ee-4b58-9aeb-b90e7c24fcba'      # Azure role definition: Key Vault Certificate User
    '169.254.169.254'                           # Azure IMDS
    '192.0.2.4'                                 # RFC 5737 TEST-NET-1
    '0.0.0.0'
    '2.5.29.17', '2.5.29.19'                    # X.509 extension OIDs
    '1.0.0.0'                                   # ARM contentVersion
    # Synthetic / reserved names used throughout the docs and tests
    'contoso.com', 'notcontoso.com', 'www.contoso.com', 'b.contoso.com'
    'sts.contoso.com', 'appone.contoso.com', 'apptwo.contoso.com'
    'example.com', 'example.net', 'other.example.net', 'unrelated.example.net'
    'certsynctest.local', 'cleanuptest.local', 'ccs.certsynctest.local'
    'www.certsynctest.local', 'nosan.certsynctest.local', 'shop.certsynctest.local'
    'samesubject.cleanuptest.local', 'other.cleanuptest.local', 'extra.cleanuptest.local'
    # Public endpoints
    'management.azure.com', 'schema.management.azure.com', 'keepachangelog.com'
    'vault.azure.net', 'vault.usgovcloudapi.net', 'vault.azure.cn'
    'core.windows.net', 'blob.core.windows.net'
    # Obviously synthetic fixtures
    '0102030405060708090A0B0C0D0E0F1011121314'
    '1111111111111111111111111111111111111111'
    'A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4', 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4'
    '0F1E2D3C4B5A69788796A5B4C3D2E1F00F1E2D3C', '0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c'
    'FEDCBA98765432100123456789ABCDEFFEDCBA98', 'fedcba98765432100123456789abcdeffedcba98'
    'AAAABBBBCCCCDDDDEEEEFFFF00001111222233'
    'bf31dba4afb842dbabbdf71740da2d62'          # illustrative version string in a doc sample
)

# Reviewed and accepted (file, check) pairs. Narrow by design: the same value elsewhere
# still fails.
$accepted = @()

# --- merge environment-specific checks ---------------------------------------
if ($ExtraPatternFile) {
    if (-not (Test-Path $ExtraPatternFile)) { throw "ExtraPatternFile not found: $ExtraPatternFile" }
    $extra = Import-PowerShellDataFile -Path $ExtraPatternFile
    if ($extra.Blocking) { $blocking += $extra.Blocking }
    if ($extra.Allow)    { $allow    += $extra.Allow }
    if ($extra.Accepted) { $accepted += $extra.Accepted }
    Write-Host ("Loaded {0} extra blocking check(s) from {1}" -f @($extra.Blocking).Count, $ExtraPatternFile) -ForegroundColor Cyan
}

$files = Get-ChildItem $Path -Recurse -File |
         Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\dist\\' }

Write-Host ("Scanning {0} file(s) under {1}" -f $files.Count, $Path) -ForegroundColor Cyan
Write-Host ('=' * 78)

# --- blocking ----------------------------------------------------------------
$blockHits    = @()
$acceptedHits = @()
foreach ($chk in $blocking) {
    foreach ($f in $files) {
        $rel = $f.FullName.Replace("$Path\", '')
        foreach ($m in (Select-String -Path $f.FullName -Pattern $chk.Pattern -AllMatches -ErrorAction SilentlyContinue)) {
            $hit = [pscustomobject]@{ Check = $chk.Name; File = $rel; Line = $m.LineNumber; Text = $m.Line.Trim() }
            $exc = $accepted | Where-Object { $_.Check -eq $chk.Name -and ($_.File -eq $rel -or $_.File -eq $f.Name) } | Select-Object -First 1
            if ($exc) { $acceptedHits += [pscustomobject]@{ Hit = $hit; Why = $exc.Why } }
            else      { $blockHits += $hit }
        }
    }
}

if ($acceptedHits) {
    Write-Host ''
    Write-Host 'ACCEPTED (reviewed exceptions):' -ForegroundColor Cyan
    foreach ($a in $acceptedHits) {
        Write-Host ("  [{0}] {1}:{2}  {3}" -f $a.Hit.Check, $a.Hit.File, $a.Hit.Line, $a.Hit.Text) -ForegroundColor Gray
        Write-Host ("      reason: {0}" -f $a.Why) -ForegroundColor DarkGray
    }
}

Write-Host ''
if ($blockHits) {
    Write-Host ("BLOCKING: {0} finding(s)" -f $blockHits.Count) -ForegroundColor Red
    $blockHits | ForEach-Object {
        Write-Host ("  [{0}] {1}:{2}" -f $_.Check, $_.File, $_.Line) -ForegroundColor Red
        Write-Host ("      {0}" -f $_.Text) -ForegroundColor DarkRed
    }
} else {
    Write-Host 'BLOCKING: none' -ForegroundColor Green
}

# --- review ------------------------------------------------------------------
Write-Host ''
Write-Host 'REVIEW (not failures - confirm each is intended):' -ForegroundColor Yellow
$reviewTotal = 0
foreach ($chk in $review) {
    $vals = @{}
    foreach ($f in $files) {
        foreach ($m in (Select-String -Path $f.FullName -Pattern $chk.Pattern -AllMatches -ErrorAction SilentlyContinue)) {
            foreach ($mm in $m.Matches) {
                if ($allow -contains $mm.Value) { continue }
                if (-not $vals.ContainsKey($mm.Value)) { $vals[$mm.Value] = @() }
                $vals[$mm.Value] += ("{0}:{1}" -f $f.Name, $m.LineNumber)
            }
        }
    }
    if ($vals.Count -eq 0) { continue }
    Write-Host ("  {0}: {1} distinct value(s)" -f $chk.Name, $vals.Count) -ForegroundColor Yellow
    foreach ($k in ($vals.Keys | Sort-Object)) {
        Write-Host ("      {0,-46} {1}" -f $k, (($vals[$k] | Select-Object -Unique -First 3) -join ', ')) -ForegroundColor DarkYellow
        $reviewTotal++
    }
}
if ($reviewTotal -eq 0) { Write-Host '  none' -ForegroundColor Green }

# --- git history -------------------------------------------------------------
if ($IncludeGitHistory) {
    Write-Host ''
    Write-Host 'Scanning git history (all blobs, all commits)...' -ForegroundColor Cyan
    Push-Location $Path
    try {
        $histHits = @()

        # Map blob SHA -> path so the same exclusions as the working-tree scan apply.
        # Without it the accepted exceptions would be re-reported on every run, and a
        # check that always fails is a check nobody reads.
        $blobPath = @{}
        foreach ($line in (git rev-list --objects --all 2>$null)) {
            $parts = "$line" -split ' ', 2
            if ($parts.Count -eq 2 -and $parts[1]) { $blobPath[$parts[0]] = $parts[1] }
        }

        foreach ($b in $blobPath.Keys) {
            $p    = $blobPath[$b]
            $leaf = Split-Path $p -Leaf
            if ((git cat-file -t $b 2>$null) -ne 'blob') { continue }
            $content = git cat-file -p $b 2>$null | Out-String
            if (-not $content) { continue }

            foreach ($chk in $blocking) {
                if ($content -notmatch $chk.Pattern) { continue }
                if ($accepted | Where-Object { $_.Check -eq $chk.Name -and ($_.File -eq $p -or $_.File -eq $leaf) }) { continue }
                $histHits += ("{0} in {1} (blob {2})" -f $chk.Name, $p, $b.Substring(0, 8))
            }
        }

        if ($histHits) {
            Write-Host ("HISTORY: {0} finding(s)" -f $histHits.Count) -ForegroundColor Red
            $histHits | Select-Object -Unique | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
            $blockHits += [pscustomobject]@{ Check = 'git history'; File = '-'; Line = 0; Text = 'see above' }
        } else {
            Write-Host ("HISTORY: clean ({0} blob(s) examined)" -f $blobPath.Count) -ForegroundColor Green
        }
    } finally { Pop-Location }
}

Write-Host ''
Write-Host ('=' * 78)
if ($blockHits) {
    Write-Host 'RESULT: NOT SAFE TO PUBLISH' -ForegroundColor Red
    exit 1
}
Write-Host 'RESULT: no blocking findings' -ForegroundColor Green
exit 0
