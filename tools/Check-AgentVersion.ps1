<#
.SYNOPSIS
    Reports which build of the agent is installed on this machine and which capabilities it
    carries. READ-ONLY - makes no changes.

.DESCRIPTION
    Intended for a quick "is this node running what I think it is?" check across a fleet,
    without having to diff the script itself.

    Capabilities are detected by probing for the function that implements each feature
    rather than by reading a version string, because the agent carries no embedded version
    number: it is versioned by whatever artifact shipped it (a VM Application version, a
    release tag, a file hash). The SHA-256 below is the authoritative identity.

.EXAMPLE
    .\Check-AgentVersion.ps1
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:ProgramData 'KeyVaultCertSync'),
    [string]$TaskName    = 'KeyVault Certificate Sync',
    [string]$TaskPath    = '\Microsoft\KeyVaultCertSync\'
)

$ErrorActionPreference = 'Continue'

function Line { param($k, $v) Write-Output ("{0,-26}: {1}" -f $k, $v) }

Write-Output "=============== $env:COMPUTERNAME ==============="

$agent = Join-Path $InstallRoot 'bin\Sync-KeyVaultCertificate.ps1'
if (-not (Test-Path $agent)) {
    Line 'agent' 'NOT INSTALLED'
    return
}

$f = Get-Item $agent
Line 'agent path'     $agent
Line 'agent modified' $f.LastWriteTime
Line 'agent size'     ("{0:N0} bytes" -f $f.Length)
Line 'agent sha256'   (Get-FileHash $agent -Algorithm SHA256).Hash

$text = Get-Content $agent -Raw

Write-Output ''
Write-Output '--- capabilities ---'
$capabilities = [ordered]@{
    'AD FS binding'              = 'function Set-AdfsBinding'
    'WAP binding'                = 'function Set-WapBinding'
    'WAP published-app repair'   = 'function Test-WapApplicationsCurrent'
    'IIS binding'                = 'function Set-IisBinding'
    'IIS http.sys reconcile'     = 'function Sync-HttpSysSslBinding'
    'locale-safe SAN parsing'    = 'function Get-SubjectAlternativeDnsName'
    'SAN-based cleanup identity' = 'function Test-SupersededCertificate'
    'Azure Arc managed identity' = 'function Get-ArcToken'
}
foreach ($c in $capabilities.Keys) {
    Line $c $(if ($text -match [regex]::Escape($capabilities[$c])) { 'yes' } else { 'no' })
}

Write-Output ''
Write-Output '--- scheduled task ---'
$task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
if ($task) {
    $i = Get-ScheduledTaskInfo -InputObject $task
    Line 'state'       $task.State
    Line 'last run'    $i.LastRunTime
    Line 'last result' ("0x{0:X}  ({1})" -f $i.LastTaskResult,
                        $(if ($i.LastTaskResult -eq 0) { 'success' } else { 'FAILURE' }))
    Line 'next run'    $i.NextRunTime
    $args = ($task.Actions | Select-Object -First 1).Arguments
    if ($args) { Line 'arguments' $args }
} else {
    Line 'scheduled task' 'NOT REGISTERED'
}

Write-Output ''
Write-Output '--- state.json ---'
$state = Join-Path $InstallRoot 'state.json'
if (Test-Path $state) { Get-Content $state -Raw } else { Write-Output '  MISSING - no sync has completed yet' }

Write-Output ''
Write-Output 'READ-ONLY - nothing was modified.'
