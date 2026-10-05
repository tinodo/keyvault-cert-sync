# Architecture and design notes

Why the agent is built the way it is. Most of these decisions exist because the obvious
approach failed in a real environment.

## Constraints

1. **No secrets at rest.** Rules out service principals with client secrets.
2. **No dependencies.** A hardened federation server should not need Az modules installed and
   kept current. Windows PowerShell 5.1, the .NET X.509 classes, and the in-box role modules.
3. **Safe to run unattended, often.** Every path idempotent; nothing destructive without proof.
4. **Fails visibly.** A certificate agent that silently does nothing is worse than none at all,
   because you only discover it at expiry.

## Authentication

The managed identity token comes from the Instance Metadata Service:

| Host | Endpoint |
|---|---|
| Azure VM | `http://169.254.169.254/metadata/identity/oauth2/token` |
| Azure Arc | `http://localhost:40342/metadata/identity/oauth2/token` |

Arc uses a challenge/response handshake: the first request returns `401` with a
`WWW-Authenticate` header naming a file readable only by local administrators. The agent reads
it and retries with its contents as a bearer token — proving local administrative rights
without a stored secret.

Certificate metadata is fetched before the PFX. The metadata response is a few hundred bytes and
carries `x5t`, the SHA-1 thumbprint, base64url-encoded. On the common path where nothing has
changed, the agent never downloads the private key at all.

## Why PowerShell 5.1 only

The `ADFS` and `WebApplicationProxy` modules do not load under PowerShell 7 without the
WinPSCompatSession shim, which adds a failure mode on a machine whose whole job is authentication.
The installer always registers the task against `powershell.exe` 5.1 explicitly rather than
whatever `pwsh` happens to be on `PATH`.

## Role detection

Order: installed role features → cmdlet availability → services → IIS.

The reason the obvious check is wrong: **a Web Application Proxy carries a running `adfssrv`
service** even though `ADFS-Federation` is not installed, because the proxy ships the same
service host binary. Verified on Windows Server 2025 — a WAP box reported `adfssrv=Running`
while `Get-WindowsFeature ADFS-Federation` returned `Installed=False` and the ADFS module did not
exist. Detecting on service presence alone misclassifies every WAP server as AD FS.

Hence features first, and in the service fallback `appproxysvc` is tested **before** `adfssrv`:
an `adfssrv` service can exist on a proxy, but `appproxysvc` never exists on a plain federation
server.

IIS is only chosen when neither is present, and requires both the management assembly and a
present `W3SVC` — the assembly alone can linger after the role is removed.

## Locale independence

Two places parse Windows output, and both deliberately avoid matching on English text.

**SAN extraction** walks the DER directly rather than calling `X509Extension.Format()`.
`Format()` emits *localised* labels, so matching the literal string `DNS Name=` returns nothing
on a German or French Windows. Every binding would then look unrelated to the new certificate
and nothing would ever be claimed. The parser walks `SubjectAlternativeName ::= SEQUENCE OF
GeneralName` and takes context tag `[2]` (`0x82`), the `dNSName` entries.

**netsh output** is parsed by the *shape* of each value, not by its label. On a German Windows
`IP:port` becomes `IP:Port` and `Certificate Hash` becomes `Zertifikathash`. The parser
recognises an endpoint by matching `ip:port` or `hostname:port`, a thumbprint by 40 hex
characters, and an application ID by GUID-in-braces. Labels are ignored entirely.

Both are covered by tests that feed in German-labelled fixtures.

## IIS

### Microsoft.Web.Administration, not the WebAdministration module

`Microsoft.Web.Administration.dll` ships with the Web-Server role on every SKU including Server
Core. The `WebAdministration` PowerShell module requires the `Web-Scripting-Tools` feature,
which is frequently not installed. The assembly is also a cleaner API for reading and writing
binding certificate hashes.

### Configuration and http.sys are separate problems

Committing `applicationHost.config` normally makes `W3SVC` register the certificate in
`http.sys` itself — but not when the service is stopped, and a hand-run
`netsh http delete sslcert` leaves the two permanently out of step with nothing in IIS Manager
indicating it.

So the agent writes configuration, verifies the write landed, then separately reconciles
`http.sys`, then verifies that too. Checking before acting keeps it idempotent: a correct
endpoint produces no `netsh` call.

All pending bindings are written in a **single** `CommitChanges()` so IIS reloads configuration
once rather than once per site.

### Claiming bindings conservatively

A server can serve several unrelated certificates. Re-pointing all https bindings to the Key
Vault certificate would be straightforward and occasionally catastrophic.

The default `Managed` scope claims a binding only when the agent can justify it: the certificate
is absent, missing from the store, shares a Subject, or shares a SAN name. Everything else is
skipped **and logged with the thumbprint**, so a skip is visible rather than silent.

The `WMSvc` management certificate is the motivating example — unrelated subject, no shared
names. Under `Managed` it is correctly untouched; under `All` it would be broken.

## Cleanup identity

Originally a superseded certificate meant "same Subject". That silently stopped working: ACME
issuers change the common name between renewals. A wildcard certificate renewed from
`CN=*.contoso.com` to `CN=contoso.com` while covering an identical SAN list, so no previous
issuance matched any more and expired certificates accumulated indefinitely.

The reliable identity of "the same certificate, re-issued" is **the set of names it is valid
for**. Equality is required, not overlap — a certificate covering a different or wider set is a
different certificate and may be in use by something the agent knows nothing about.

Subject equality is kept as a first test because it is cheap and correct when it matches.

### Cleanup runs even when nothing changed

Gating cleanup on "something changed" meant a certificate that could not be removed during a
renewal — because it was still bound at that moment, or because an older build failed to
recognise it — was never reconsidered, and stayed until the next renewal.

It is cheap and idempotent, so it runs on every pass including the fast path.

### Never remove something in use

Before deleting, the agent collects every thumbprint referenced by `http.sys`, AD FS and
`applicationHost.config`. Anything in that set is excluded regardless of expiry.

This is deliberately more conservative than "expired means safe". On a proxy whose published
applications still reference an expired certificate, removing it would make a broken situation
worse.

## Failure philosophy

Distinguishing *this did not work* from *this cannot work yet* matters.

**Fatal** — the certificate could not be obtained, imported, or bound; verification failed after
a write. Exit `1`, event `2000`.

**Warned, not fatal** — the work that succeeded is kept and the problem is reported:

- A WAP that cannot reach the AD FS configuration store. The TLS certificate is already bound;
  failing would discard that. The agent says exactly what is wrong and what to run.
- `appproxysvc` failing to restart on a proxy that is not joined to its farm — a pre-existing
  configuration problem, not a certificate problem.
- Removing a superseded certificate failing.

The guiding rule: never throw away work that succeeded because of a problem the agent cannot
fix, and never report success for work that did not happen.

## Testing

91 tests across four suites, none requiring Azure, a federation server or elevation.

`Test-SyncLogic.ps1` extracts functions from the agent through the **PowerShell AST** and dot-
sources them individually, so real production code is exercised without running the script body
or reaching the network. Dependencies are shadowed with local function definitions where needed.

Where behaviour cannot be unit-tested — the order of branches in role detection, whether the
fast path consults published applications, whether cleanup is wired into both exit paths — the
tests assert against the **source text** instead. Less elegant, but it catches the regression
that matters: someone removing the call entirely.

Several tests are regression guards with the original failure recorded in a comment:

- WAP reporting `adfssrv=Running`
- A renewal that changed the common name
- `Copy-Item` onto itself when source and destination are the same staged file
- `$args` as a variable name, which shadows the automatic variable

## What this does not do

- **Issue or renew certificates.** It consumes what is in Key Vault. Pair it with an ACME tool
  such as Key Vault Acmebot.
- **Configure AD FS or WAP.** It only manages certificates on an existing, working deployment.
- **Manage non-Windows TLS.** Linux, appliances and load balancers are out of scope.
- **Cluster or coordinate.** Each node acts independently; jitter prevents simultaneous restarts.
  An AD FS farm's own replication handles the rest.
