# Security Policy

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.

Use [GitHub private vulnerability reporting](https://github.com/tinodo/keyvault-cert-sync/security/advisories/new)
on this repository.

Include what you need to describe the problem — affected version or commit, the behaviour you
observed, and how to reproduce it if that is practical.

## Scope

This project installs and binds TLS certificates on Windows servers and runs as `SYSTEM`.
Findings of particular interest:

- Any path by which the agent could be made to import or bind a certificate other than the one
  named in its parameters.
- Local privilege escalation via the install directory, the scheduled task, or the script's own
  handling of paths and arguments.
- Private key material or access tokens reaching the log, the event log, `state.json`, or any
  other location that is not `LocalMachine\My`.
- Weakening of the private-key ACL beyond the identities explicitly requested.

## Design notes relevant to security

- **No secrets at rest.** Authentication is the machine's managed identity. The agent stores no
  credentials, and the PFX byte array is cleared immediately after import.
- **Install directory is locked down.** `%ProgramData%\KeyVaultCertSync` has inheritance disabled
  and grants `SYSTEM` and `Administrators` only.
- **Private keys are not exportable** unless `-Exportable` is passed explicitly.
- **Least privilege on the vault.** The agent needs only `Key Vault Secrets User` and
  `Key Vault Certificate User` — both read-only. It never writes to Key Vault.
- **Destructive actions are guarded.** A certificate still referenced by `http.sys`, AD FS or
  `applicationHost.config` is never removed, regardless of cleanup mode.

## Operational guidance

Do not embed credentials in Run Command or VM Application payloads. They are transmitted to
Azure and retained in deployment history and activity logs. Everything this project deploys
authenticates with managed identity for exactly that reason.
