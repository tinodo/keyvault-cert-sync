<#
.SYNOPSIS
    One-time bootstrap on an AD FS, WAP or IIS server. Installs the sync script under
    %ProgramData% and registers a SYSTEM scheduled task that keeps the certificate current.

.DESCRIPTION
    Run once per server, elevated. Afterwards the server self-heals: every $IntervalHours
    it asks Key Vault for the current thumbprint and only acts when something changed.

    Nothing is stored on disk except the script and its parameters - no secrets, no
    credentials. Authentication is the machine's managed identity.

.PARAMETER VaultName
    Short name of the Key Vault, e.g. 'kv-contoso-acmebot'.

.PARAMETER CertificateName
    Name of the certificate object in Key Vault, e.g. 'contoso-com'.

.PARAMETER IntervalHours
    How often to check. Default 4. Key Vault metadata calls are tiny, so 1 is also fine.

.PARAMETER RandomDelayMinutes
    Jitter so that two AD FS nodes never restart adfssrv at the same second. Default 15.

.PARAMETER Role
    Auto (default) | ADFS | WAP | IIS | None.

.PARAMETER IisBindingScope
    Managed (default) | Matching | All. Which IIS https bindings may be re-pointed.
    See Sync-KeyVaultCertificate.ps1 for the full definition.

.PARAMETER IisSites
    Restrict IIS binding updates to these site names. Default: every site.

.PARAMETER RunNow
    Execute one synchronisation immediately after registering the task.

.EXAMPLE
    .\Install-CertSyncAgent.ps1 -VaultName kv-contoso-acmebot -CertificateName contoso-com -RunNow
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$VaultName,
    [Parameter(Mandatory = $true)][string]$CertificateName,
    [ValidateSet('Auto', 'ADFS', 'WAP', 'IIS', 'None')][string]$Role = 'Auto',
    [ValidateSet('Managed', 'Matching', 'All')][string]$IisBindingScope = 'Managed',
    [string[]]$IisSites = @(),
    [string]$IdentityClientId,
    [ValidateRange(1, 24)][int]$IntervalHours = 4,
    [ValidateRange(0, 120)][int]$RandomDelayMinutes = 15,
    [ValidateSet('None', 'Expired', 'KeepLatest')][string]$CleanupMode = 'Expired',
    [string]$TaskName = 'KeyVault Certificate Sync',
    [string]$TaskPath = '\Microsoft\KeyVaultCertSync\',
    [switch]$RunNow
)

$ErrorActionPreference = 'Stop'

function Assert-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
              [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This installer must run elevated (Run as Administrator).'
    }
}

function Copy-AgentScript {
    <#
        Copies the agent next to the installer, unless it is already there.

        When a VM Application or extension stages both scripts into the install directory and
        then runs the installer from that directory, Source and Destination are the same file.
        Copy-Item throws "Cannot overwrite the item with itself" in that case, which fails the
        whole install. Compare resolved paths first.

        Returns $true if a copy happened, $false if the file was already in place.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        throw "Agent script not found at $Source."
    }

    $sourceFull = (Resolve-Path -LiteralPath $Source).Path
    $destFull   = if (Test-Path -LiteralPath $Destination) {
                      (Resolve-Path -LiteralPath $Destination).Path
                  } else {
                      [System.IO.Path]::GetFullPath($Destination)
                  }

    if ($sourceFull -ieq $destFull) { return $false }

    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    return $true
}

Assert-Elevated

$installRoot = Join-Path $env:ProgramData 'KeyVaultCertSync'
$binDir      = Join-Path $installRoot 'bin'
$target      = Join-Path $binDir 'Sync-KeyVaultCertificate.ps1'
$source      = Join-Path $PSScriptRoot 'Sync-KeyVaultCertificate.ps1'

if (-not (Test-Path $source)) {
    throw "Sync-KeyVaultCertificate.ps1 was not found next to this installer ($PSScriptRoot)."
}
Write-Host "Installing to $binDir ..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $binDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $installRoot 'Logs') -Force | Out-Null

if (Copy-AgentScript -Source $source -Destination $target) {
    Write-Host '  copied the agent script into place.' -ForegroundColor Gray
} else {
    Write-Host '  agent script is already in place; skipping copy.' -ForegroundColor Gray
}

# Lock the folder down: SYSTEM + Administrators full, nothing else.
$acl = Get-Acl $installRoot
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
foreach ($principal in 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators') {
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
Set-Acl -Path $installRoot -AclObject $acl

# Event log source so the task can write structured events as SYSTEM.
if (-not [System.Diagnostics.EventLog]::SourceExists('KeyVaultCertSync')) {
    [System.Diagnostics.EventLog]::CreateEventSource('KeyVaultCertSync', 'Application')
    Write-Host 'Created Application event log source "KeyVaultCertSync".' -ForegroundColor Cyan
}

# Always use Windows PowerShell 5.1 - the ADFS / WebApplicationProxy modules are not
# supported in PowerShell 7 without the WinPSCompatSession shim.
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

$argList = @(
    '-NoProfile'
    '-NonInteractive'
    '-ExecutionPolicy Bypass'
    "-File `"$target`""
    "-VaultName `"$VaultName`""
    "-CertificateName `"$CertificateName`""
    "-Role $Role"
    "-CleanupMode $CleanupMode"
)
if ($IdentityClientId) { $argList += "-IdentityClientId `"$IdentityClientId`"" }
if ($Role -eq 'IIS' -or $Role -eq 'Auto') { $argList += "-IisBindingScope $IisBindingScope" }
if ($IisSites.Count -gt 0) {
    # Quote each name individually: IIS site names routinely contain spaces.
    $argList += '-IisSites ' + (($IisSites | ForEach-Object { "`"$_`"" }) -join ',')
}
$argList = $argList -join ' '

$action = New-ScheduledTaskAction -Execute $psExe -Argument $argList -WorkingDirectory $binDir

$triggers = @()
$onceTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes(3) `
                   -RepetitionInterval (New-TimeSpan -Hours $IntervalHours)
if ($RandomDelayMinutes -gt 0) {
    $onceTrigger.RandomDelay = ([System.Xml.XmlConvert]::ToString((New-TimeSpan -Minutes $RandomDelayMinutes)))
}
$triggers += $onceTrigger
$triggers += New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
               -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
               -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) `
               -DontStopOnIdleEnd -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

$existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
if ($existing) {
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
    Write-Host 'Replaced the existing scheduled task.' -ForegroundColor Yellow
}

Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $triggers `
    -Principal $principal -Settings $settings `
    -Description ("Pulls the current version of Key Vault certificate '$CertificateName' from vault " +
                  "'$VaultName' using this machine's managed identity, installs it in LocalMachine\My " +
                  "and rebinds the AD FS / WAP / IIS TLS configuration. Idempotent.") | Out-Null

Write-Host "Registered scheduled task '$TaskPath$TaskName' (every $IntervalHours h, +/- $RandomDelayMinutes min jitter, and at startup)." -ForegroundColor Green

Write-Host ''
Write-Host 'Next: grant this machine''s managed identity the "Key Vault Secrets User" role on the vault.' -ForegroundColor Cyan
Write-Host '      See azure\Grant-KeyVaultAccess.ps1' -ForegroundColor Cyan

if ($RunNow) {
    Write-Host ''
    Write-Host 'Running an initial synchronisation...' -ForegroundColor Cyan
    Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
    Start-Sleep -Seconds 5
    $deadline = (Get-Date).AddMinutes(10)
    while ((Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath).State -eq 'Running' -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
    }
    $info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath
    Write-Host ("Last result: 0x{0:X} (0 = success)" -f $info.LastTaskResult) `
        -ForegroundColor $(if ($info.LastTaskResult -eq 0) { 'Green' } else { 'Red' })

    $log = Get-ChildItem (Join-Path $installRoot 'Logs') -Filter 'sync-*.log' -ErrorAction SilentlyContinue |
           Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($log) {
        Write-Host ''
        Write-Host "--- tail of $($log.Name) ---" -ForegroundColor DarkGray
        Get-Content $log.FullName -Tail 25
    }
}
