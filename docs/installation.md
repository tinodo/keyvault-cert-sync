# Installation

## Prerequisites

| | |
|---|---|
| OS | Windows Server 2016 or later |
| PowerShell | Windows PowerShell 5.1 (not PowerShell 7) |
| Privileges | Local administrator for the install; the task itself runs as `SYSTEM` |
| Identity | A managed identity on the VM, or an Azure Arc-enabled server |
| Key Vault | A Key Vault **certificate** (not a bare secret) with an exportable private key |

## Store the certificate correctly

The agent reads a Key Vault *certificate* object, then downloads its backing *secret*, which
Key Vault returns as a PFX containing the leaf, the chain and the private key.

This means the certificate must have been **created or imported into Key Vault as a
certificate**, not uploaded as a secret. If you are issuing from Let's Encrypt, tools such as
[Key Vault Acmebot](https://github.com/shibayan/keyvault-acmebot) do this correctly.

## Grant the managed identity access

The VM's identity needs **two** roles at vault scope:

| Role | GUID | Why |
|---|---|---|
| Key Vault Secrets User | `4633458b-17de-408a-b874-0445c86b69e6` | Download the PFX |
| Key Vault Certificate User | `db79e9a7-68ee-4b58-9aeb-b90e7c24fcba` | Read certificate metadata |

> **Granting only Secrets User is the single most common setup mistake.** The token request
> succeeds, so authentication looks fine, and then the metadata call returns `403 Forbidden`.
> Grant both.

```powershell
$vault = '/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>'
$principalId = (az vm show -g <rg> -n <vm> --query identity.principalId -o tsv)

foreach ($role in '4633458b-17de-408a-b874-0445c86b69e6',
                  'db79e9a7-68ee-4b58-9aeb-b90e7c24fcba') {
    az role assignment create `
        --assignee-object-id $principalId `
        --assignee-principal-type ServicePrincipal `
        --role $role `
        --scope $vault
}
```

On a vault using **access policies** rather than RBAC, grant `Get` on both secrets and
certificates instead.

RBAC propagation is not instant. If the first run fails with `403`, wait a few minutes and
re-run before assuming the assignment is wrong.

### Which identity gets used

| VM identity configuration | What IMDS returns |
|---|---|
| System-assigned only | That identity |
| One user-assigned only | That identity |
| System-assigned **and** user-assigned | The **system-assigned** one |
| Several user-assigned, no system-assigned | An error — IMDS cannot choose |

Grant the role to whichever identity will actually be used, or remove the ambiguity with
`-IdentityClientId`:

```powershell
.\src\Install-CertSyncAgent.ps1 `
    -VaultName kv-contoso-certs -CertificateName contoso-com `
    -IdentityClientId 00000000-0000-0000-0000-000000000000
```

Pinning it explicitly is worth doing on any VM that has more than one identity, even when it
currently works — adding a second identity later silently changes the behaviour otherwise.

### Azure Arc

Arc-enabled servers are supported. The agent detects Arc and performs the challenge/response
handshake against `localhost:40342` automatically. The Arc agent's identity needs the same two
roles. No extra configuration is required.

## Install

```powershell
.\src\Install-CertSyncAgent.ps1 `
    -VaultName       kv-contoso-certs `
    -CertificateName contoso-com `
    -RunNow
```

This will:

1. Copy both scripts to `%ProgramData%\KeyVaultCertSync\bin`.
2. Lock that folder down to `SYSTEM` and `Administrators` only, with inheritance disabled.
3. Create the `KeyVaultCertSync` Application event log source.
4. Register a scheduled task running as `NT AUTHORITY\SYSTEM` with highest privileges.
5. With `-RunNow`, perform one synchronisation and print the result and log tail.

The task triggers every `-IntervalHours` (default 4) **and** at startup, with
`-RandomDelayMinutes` of jitter (default 15) so that two federation servers never restart
`adfssrv` in the same second.

## Verify

```powershell
.\tools\Verify-CertSync.ps1
```

Reports the detected role, task state, `state.json`, the certificate store, what AD FS / WAP /
IIS are bound to, what `http.sys` is serving, and the log tail. Makes no changes.

Pass `-ExpectedThumbprint` to turn it into a pass/fail check:

```powershell
.\tools\Verify-CertSync.ps1 -ExpectedThumbprint 0F1E2D3C4B5A69788796A5B4C3D2E1F00F1E2D3C
```

## Dry run first

On a server already carrying certificates you care about, confirm what the agent *would* do
before letting it act:

```powershell
# Agent-level: resolves and reports, imports nothing, binds nothing.
.\src\Sync-KeyVaultCertificate.ps1 -VaultName kv-contoso-certs -CertificateName contoso-com -WhatIf
```

For IIS specifically there is a dedicated read-only planner that reports which bindings would
be re-pointed and which certificates cleanup would remove, with the reason for each decision:

```powershell
.\tools\Build-IisPlanProbe.ps1 -PretendCertificateThumbprint <a-thumbprint-already-in-the-store>
# then run the generated dist\probe-iis-plan.ps1 on the server
```

See [iis.md](iis.md#dry-run) for how to read its output.

## Uninstall

```powershell
Unregister-ScheduledTask -TaskName 'KeyVault Certificate Sync' `
                         -TaskPath '\Microsoft\KeyVaultCertSync\' -Confirm:$false
Remove-Item "$env:ProgramData\KeyVaultCertSync" -Recurse -Force
```

This removes the agent only. Certificates it installed and bindings it made are left exactly
as they are — removing the agent must never take a service offline.
