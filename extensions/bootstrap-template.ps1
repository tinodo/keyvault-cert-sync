<#
    TEMPLATE - do not run directly, and do not edit the two __*_B64__ tokens by hand.

    tools\Build-ExtensionScript.ps1 reads this file, replaces __SYNC_B64__ and __INSTALL_B64__
    with the base64 of the two agent scripts from ..\src\, and writes the result to
    dist\certsync-extension.ps1.

    That output file is what you hand to az. It is self-contained - it carries the agent
    inside it, so there is nothing to copy to the VM beforehand and no storage account.

    All configuration (vault, certificate, role, interval) is passed at deploy time as
    Run Command parameters, so the same built file works for every server.

    What it does on the VM, running once as SYSTEM:
      1. writes the two agent scripts to %ProgramData%\KeyVaultCertSync\bin
      2. runs the installer, which registers the SYSTEM scheduled task
      3. exits non-zero on failure so the extension reports failure instead of going green

    Recurrence comes from the scheduled task, not from the extension. Re-running the
    extension is safe: the installer replaces the task.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$VaultName,
    [Parameter(Mandatory = $true)][string]$CertificateName,
    [string]$Role             = 'Auto',
    [string]$IisBindingScope  = 'Managed',
    [string]$IisSites         = '',
    [string]$IdentityClientId = '',
    [string]$IntervalHours    = '4',
    [string]$CleanupMode      = 'Expired',
    [string]$RunNow           = 'True'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Write-Step { param([string]$m) Write-Output ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $m) }

try {
    Write-Step "certsync bootstrap starting on $env:COMPUTERNAME"
    Write-Step "powershell $($PSVersionTable.PSVersion) / $($PSVersionTable.PSEdition)"
    Write-Step "running as $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Step "config: vault=$VaultName cert=$CertificateName role=$Role"

    $bin = Join-Path $env:ProgramData 'KeyVaultCertSync\bin'
    New-Item -ItemType Directory -Path $bin -Force | Out-Null

    # UTF8 without BOM. 5.1 tolerates a BOM but it makes the files noisy to diff.
    $enc = New-Object System.Text.UTF8Encoding $false

    $files = @{
        'Sync-KeyVaultCertificate.ps1' = '__SYNC_B64__'
        'Install-CertSyncAgent.ps1'    = '__INSTALL_B64__'
    }
    foreach ($name in $files.Keys) {
        $path = Join-Path $bin $name
        $text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($files[$name]))
        [System.IO.File]::WriteAllText($path, $text, $enc)
        Write-Step ("wrote {0} ({1:N0} bytes)" -f $name, (Get-Item $path).Length)
    }

    # Fail fast on a corrupted transfer rather than registering a task that can never work.
    foreach ($name in $files.Keys) {
        $path = Join-Path $bin $name
        $err = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$err)
        if ($err) { throw "$name failed to parse after transfer: $($err[0].Message)" }
    }
    Write-Step 'both scripts parsed cleanly'

    # Run Command hands every parameter over as a string, so guard the numeric one.
    $interval = 4
    if ($IntervalHours -match '^\d+$') { $interval = [int]$IntervalHours }
    else { Write-Step "IntervalHours '$IntervalHours' is not a number; defaulting to 4" }

    $installArgs = @{
        VaultName       = $VaultName
        CertificateName = $CertificateName
        Role            = $Role
        IntervalHours   = $interval
        CleanupMode     = $CleanupMode
    }
    if ($IdentityClientId) { $installArgs['IdentityClientId'] = $IdentityClientId }
    if ($IisBindingScope)  { $installArgs['IisBindingScope']  = $IisBindingScope }
    if ($IisSites) {
        # Run Command cannot pass an array, so accept a comma-separated list.
        $installArgs['IisSites'] = @($IisSites -split ',' |
                                     ForEach-Object { $_.Trim() } |
                                     Where-Object { $_ })
    }
    if ($RunNow -eq 'True') { $installArgs['RunNow'] = $true }

    Write-Step ("invoking installer: vault={0} cert={1} role={2} interval={3}h cleanup={4} runNow={5} iisScope={6}" -f `
                $VaultName, $CertificateName, $Role, $interval, $CleanupMode, $RunNow, $IisBindingScope)

    & (Join-Path $bin 'Install-CertSyncAgent.ps1') @installArgs
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "installer exited with code $LASTEXITCODE" }

    # Prove the task exists - the extension must not report success otherwise.
    $task = Get-ScheduledTask -TaskName 'KeyVault Certificate Sync' `
                              -TaskPath '\Microsoft\KeyVaultCertSync\' -ErrorAction SilentlyContinue
    if (-not $task) { throw 'the scheduled task was not registered' }
    Write-Step "scheduled task registered, state=$($task.State)"

    $statePath = Join-Path $env:ProgramData 'KeyVaultCertSync\state.json'
    if (Test-Path $statePath) {
        Write-Step 'last sync state:'
        Get-Content $statePath -Raw | Write-Output
    }

    Write-Step 'certsync bootstrap completed successfully'
    exit 0
}
catch {
    Write-Output "certsync bootstrap FAILED: $($_.Exception.Message)"
    Write-Output $_.ScriptStackTrace
    $log = Join-Path $env:ProgramData 'KeyVaultCertSync\Logs'
    if (Test-Path $log) {
        Write-Output '--- agent log tail ---'
        Get-ChildItem $log -Filter 'sync-*.log' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1 |
            ForEach-Object { Get-Content $_.FullName -Tail 30 }
    }
    exit 1
}
