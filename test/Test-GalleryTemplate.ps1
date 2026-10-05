# Validates azure\publish-gallery-version.json against the agent and installer it deploys.
#
# These are drift guards. A VM Application failure surfaces minutes after a deployment, as
# a generic non-zero exit buried in extension status, so a mismatch between the template and
# the scripts is expensive to diagnose and cheap to catch here.
#
# Run with:  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-GalleryTemplate.ps1

$ErrorActionPreference = 'Stop'
$root     = Split-Path $PSScriptRoot -Parent
$template = Join-Path $root 'azure\publish-gallery-version.json'
$agent    = Join-Path $root 'src\Sync-KeyVaultCertificate.ps1'
$installer= Join-Path $root 'src\Install-CertSyncAgent.ps1'
$bootstrap= Join-Path $root 'extensions\bootstrap-template.ps1'

$pass = 0; $fail = 0
function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try {
        & $Body
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green
        $script:pass++
    } catch {
        Write-Host ("  FAIL  {0}`n        {1}" -f $Name, $_.Exception.Message) -ForegroundColor Red
        $script:fail++
    }
}

Write-Host "PowerShell $($PSVersionTable.PSVersion) / $($PSVersionTable.PSEdition)" -ForegroundColor Cyan
Write-Host ''

$json = Get-Content $template -Raw | ConvertFrom-Json

function Get-ParameterDefault {
    param([string]$Name)
    $p = $json.parameters.$Name
    if ($null -eq $p) { throw "template has no parameter '$Name'" }
    if ($p.PSObject.Properties.Name -notcontains 'defaultValue') { return "<$Name>" }
    return $p.defaultValue
}

function Resolve-ArmExpression {
    <#
        Evaluates the subset of the ARM expression language this template uses:
        concat(), parameters(), string(), if(), empty() and literals.

        Deliberately small and strict - it throws on anything it does not understand
        rather than silently returning a wrong string, because a wrong string here would
        make the test pass while the real deployment produces a broken install command.
    #>
    param([string]$Expression)

    $e = $Expression.Trim()
    if ($e.StartsWith('[') -and $e.EndsWith(']')) { $e = $e.Substring(1, $e.Length - 2).Trim() }

    function Split-Args {
        param([string]$Text)
        $parts = New-Object System.Collections.Generic.List[string]
        $depth = 0; $inStr = $false; $cur = ''
        for ($i = 0; $i -lt $Text.Length; $i++) {
            $c = $Text[$i]
            if ($c -eq "'") {
                # ARM escapes a literal quote by doubling it. Consume both characters so
                # the string state does not flip, otherwise everything after a '' is
                # mis-tokenised - which is exactly what the remove command contains.
                if ($inStr -and ($i + 1) -lt $Text.Length -and $Text[$i + 1] -eq "'") {
                    $cur += "''"; $i++
                    continue
                }
                $inStr = -not $inStr; $cur += $c
                continue
            }
            if (-not $inStr) {
                if ($c -eq '(') { $depth++ }
                elseif ($c -eq ')') { $depth-- }
                elseif ($c -eq ',' -and $depth -eq 0) { $parts.Add($cur.Trim()); $cur = ''; continue }
            }
            $cur += $c
        }
        if ($cur.Trim()) { $parts.Add($cur.Trim()) }
        return $parts.ToArray()
    }

    function Eval {
        param([string]$Text)
        $t = $Text.Trim()

        if ($t.Length -ge 2 -and $t.StartsWith("'") -and $t.EndsWith("'")) {
            return $t.Substring(1, $t.Length - 2).Replace("''", "'")
        }
        if ($t -match '^-?\d+$') { return $t }

        if ($t -match '^(?<fn>[a-zA-Z]+)\((?<body>.*)\)$') {
            $fn   = $Matches['fn'].ToLowerInvariant()
            $body = $Matches['body']
            # @() is load-bearing: PowerShell unrolls a single-element array on return, so
            # a one-argument call like parameters('x') would otherwise yield a STRING here
            # and $fnArgs[0] would index its first character rather than the argument.
            # Not $args - that is an automatic variable.
            $fnArgs = @(Split-Args $body)

            switch ($fn) {
                'parameters' { return [string](Get-ParameterDefault (Eval $fnArgs[0])) }
                'variables'  {
                    $vn = Eval $fnArgs[0]
                    return Resolve-ArmExpression $json.variables.$vn
                }
                'concat'     {
                    $sb = New-Object System.Text.StringBuilder
                    foreach ($a in $fnArgs) { [void]$sb.Append([string](Eval $a)) }
                    return $sb.ToString()
                }
                'string'     { return [string](Eval $fnArgs[0]) }
                'empty'      { $v = Eval $fnArgs[0]; return [string]([string]::IsNullOrEmpty("$v")) }
                'if'         {
                    $cond = Eval $fnArgs[0]
                    if ("$cond" -eq 'True') { return Eval $fnArgs[1] }
                    return Eval $fnArgs[2]
                }
                default { throw "Resolve-ArmExpression does not implement '$fn'" }
            }
        }
        throw "Resolve-ArmExpression could not evaluate: $t"
    }

    return Eval $e
}

# ---------------------------------------------------------------- template shape
Write-Host 'Template shape' -ForegroundColor Cyan

Test-Case 'the template is valid JSON with a gallery application version resource' {
    $res = @($json.resources | Where-Object { $_.type -eq 'Microsoft.Compute/galleries/applications/versions' })
    if ($res.Count -ne 1) { throw "expected exactly 1 version resource, found $($res.Count)" }
}

Test-Case 'every parameter the publish script passes exists in the template' {
    $script = Get-Content (Join-Path $root 'tools\Publish-GalleryVersion.ps1') -Raw
    # Parameter names assigned inside the $paramObject.parameters hashtable.
    $block = [regex]::Match($script, '(?s)parameters\s*=\s*@\{(.*?)\n    \}')
    if (-not $block.Success) { throw 'could not isolate the parameters hashtable in the publish script' }
    $names = [regex]::Matches($block.Groups[1].Value, '(?m)^\s{8}(\w+)\s*=\s*@\{') | ForEach-Object { $_.Groups[1].Value }
    if ($names.Count -lt 5) { throw "only found $($names.Count) parameter assignments; the regex probably broke" }
    foreach ($n in $names) {
        if ($json.parameters.PSObject.Properties.Name -notcontains $n) {
            throw "publish script passes '$n' but the template has no such parameter"
        }
    }
}

# ------------------------------------------------------------- install command
Write-Host ''
Write-Host 'Install command' -ForegroundColor Cyan

$install = Resolve-ArmExpression $json.variables.installCommand
$remove  = Resolve-ArmExpression $json.variables.removeCommand
Write-Host ("        -> {0}" -f $install) -ForegroundColor DarkGray

Test-Case 'the rename target matches the file that is then executed' {
    # A VM Application arrives named after the application with no extension, so the
    # install command renames it. If those two names drift the install fails on the VM
    # with a bare "cannot find path", minutes after deployment.
    if ($install -notmatch 'rename\s+(\S+)\s+(\S+)\s+&') { throw "no rename found in: $install" }
    $from = $Matches[1]; $to = $Matches[2]
    if ($install -notmatch '-File\s+\.\\(\S+\.ps1)') { throw "no -File argument found in: $install" }
    $file = $Matches[1]
    if ($to -ne $file) { throw "renames to '$to' but executes '$file'" }
    $app = Get-ParameterDefault 'applicationName'
    if ($from -ne $app) { throw "renames from '$from' but the application is named '$app'" }
}

Test-Case 'the install command uses cmd-style chaining, not a semicolon' {
    # Manage actions run under cmd.exe, where ';' is not a separator.
    if ($install -notmatch '&') { throw 'no & found' }
    if ($install -match ';\s*powershell') { throw 'uses ; which cmd.exe does not treat as a separator' }
}

Test-Case 'every agent switch in the install command is a real agent parameter' {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($agent, [ref]$null, [ref]$null)
    $agentParams = $ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }

    # The install command invokes the BOOTSTRAP, which forwards to the installer; the
    # switches must therefore be valid on the bootstrap.
    $bootAst = [System.Management.Automation.Language.Parser]::ParseFile($bootstrap, [ref]$null, [ref]$null)
    $bootParams = $bootAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }

    $used = [regex]::Matches($install, '\s-([A-Z]\w+)') | ForEach-Object { $_.Groups[1].Value }
    $used = $used | Where-Object { $_ -notin 'NoProfile', 'ExecutionPolicy', 'File' }
    if ($used.Count -eq 0) { throw 'no agent switches found in the install command' }

    foreach ($u in $used) {
        if ($bootParams -notcontains $u) {
            throw "install command passes -$u, which the bootstrap does not accept (bootstrap has: $($bootParams -join ', '))"
        }
    }
    Write-Host ("        -> {0} switch(es) checked against the bootstrap" -f $used.Count) -ForegroundColor DarkGray
}

Test-Case 'the bootstrap forwards those switches to the installer' {
    $bootText = Get-Content $bootstrap -Raw
    $instAst  = [System.Management.Automation.Language.Parser]::ParseFile($installer, [ref]$null, [ref]$null)
    $instParams = $instAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }

    foreach ($k in 'VaultName', 'CertificateName', 'Role', 'IisBindingScope', 'CleanupMode') {
        if ($bootText -notmatch [regex]::Escape($k)) { throw "bootstrap never mentions $k" }
        if ($instParams -notcontains $k) { throw "installer has no -$k parameter" }
    }
}

Test-Case 'optional arguments are omitted when empty rather than passed blank' {
    # Passing -IdentityClientId with an empty value makes the agent try to authenticate
    # as a user-assigned identity with no client ID, which fails confusingly.
    if ($install -match '-IdentityClientId\s*(-|$)') { throw 'IdentityClientId is passed empty' }
    if ($install -match '-IisSites\s*(-|$)')         { throw 'IisSites is passed empty' }
}

# -------------------------------------------------------------- remove command
Write-Host ''
Write-Host 'Remove command' -ForegroundColor Cyan

Test-Case 'the remove command unregisters the task the installer registers' {
    $instText = Get-Content $installer -Raw
    $defName = [regex]::Match($instText, "\`$TaskName\s*=\s*'([^']+)'").Groups[1].Value
    $defPath = [regex]::Match($instText, "\`$TaskPath\s*=\s*'([^']+)'").Groups[1].Value
    if (-not $defName) { throw 'could not read the default task name from the installer' }

    $tplName = Get-ParameterDefault 'taskName'
    $tplPath = Get-ParameterDefault 'taskPath'

    if ($tplName -ne $defName) { throw "template taskName '$tplName' != installer default '$defName'" }
    if ($tplPath -ne $defPath) { throw "template taskPath '$tplPath' != installer default '$defPath'" }
    if ($remove -notmatch [regex]::Escape($defName)) { throw "remove command does not reference '$defName'" }
}

Test-Case 'the remove command does not delete certificates or bindings' {
    # Uninstalling the agent must never take a service offline.
    foreach ($danger in 'Remove-Item', 'netsh', 'Set-AdfsCertificate', 'Remove-WebBinding', 'Cert:') {
        if ($remove -match [regex]::Escape($danger)) { throw "remove command contains '$danger'" }
    }
}

# --------------------------------------------------------------------- summary
Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
