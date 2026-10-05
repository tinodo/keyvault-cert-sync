# IIS

IIS differs from AD FS and WAP in one important way: there is no single "the" certificate. A
server can carry dozens of https bindings across many sites, serving several unrelated
certificates, and `http.sys` can disagree with `applicationHost.config` about any of them.

The agent therefore has to decide *which* bindings it is entitled to touch, and prove the
result in both places.

## Binding scopes

`-IisBindingScope` controls which https bindings may be re-pointed.

### `Managed` (default)

A binding is claimed when the agent can legitimately say the certificate on it is one of its
own — that is, when **any** of the following holds:

- the binding carries no certificate at all;
- the bound certificate is no longer present in `LocalMachine\<store>`;
- the bound certificate has the **same Subject** as the Key Vault certificate;
- the bound certificate shares **at least one SAN DNS name** with the Key Vault certificate.

Anything else is left alone and logged:

```
Leaving binding *:443:other.example.net on site 'Other' alone: it holds unrelated
certificate A1B2C3D4.... Use -IisBindingScope All to include it.
```

This is the right default for a shared server. It repairs what it owns and does not touch a
certificate it has no relationship with.

### `Matching`

Everything `Managed` claims, plus any binding whose **host header is covered** by the new
certificate — even if the certificate currently on it is unrelated.

Wildcards match exactly one label, per RFC 6125: `*.contoso.com` covers `www.contoso.com` but
**not** `a.b.contoso.com`, and not the bare `contoso.com` unless that is separately listed in
the SAN.

Use this when consolidating onto one wildcard certificate and you want bindings migrated off
whatever they are on today.

### `All`

Every https binding on the server, regardless of what it carries. Only appropriate on a box
that serves exactly one certificate. It will happily re-point an unrelated application's
binding, which is usually not what you want.

### Restricting by site

Orthogonal to scope, and combines with it:

```powershell
-IisSites 'Default Web Site','Intranet'
```

## What is never touched

**Central Certificate Store bindings** (`sslFlags` bit 1). With CCS, IIS resolves the
certificate from a file share by host name and `applicationHost.config` holds no thumbprint to
update. Rewriting it would be meaningless. These are skipped in every scope, with a warning.

**Bindings holding a certificate the agent does not recognise**, unless scope is `All`.

## http.sys reconciliation

Writing `applicationHost.config` is only half the job. The agent then checks what `http.sys` is
actually serving and repairs any endpoint that disagrees.

This matters because:

- committing configuration normally makes `W3SVC` register the certificate in `http.sys` by
  itself — but not when the service is stopped;
- a hand-run `netsh http delete sslcert` leaves the two permanently out of step, and nothing in
  IIS Manager will tell you.

Endpoint keys follow the SNI flag:

| Binding | `http.sys` key |
|---|---|
| SNI enabled (`sslFlags` bit 0) and a host header present | `hostname:port` |
| Everything else | `ip:port` |

A non-SNI binding with a host header still resolves through the single `ip:port` entry, which is
why several sites sharing `*:443` map to one `0.0.0.0:443` registration. The agent de-duplicates
by endpoint so it issues one `netsh` call per endpoint, not one per binding.

The existing application ID is preserved when updating an endpoint; new registrations use the
well-known IIS application ID `{4dc3e181-e14b-4a21-b022-59fc669b0914}`.

After reconciling, every endpoint is re-read and verified. If one still does not serve the
expected thumbprint, the run fails loudly rather than reporting success.

## IIS is not restarted

Deliberately. `http.sys` serves the new certificate to new connections as soon as the binding is
rewritten. An `iisreset` would drop existing connections for no benefit, so the agent logs the
decision instead:

```
IIS was not restarted on purpose: http.sys serves the new certificate to new connections
as soon as the binding is rewritten, so a restart would only cause downtime.
```

Existing TLS sessions continue on the old certificate until they end, which is normal and
applies equally to a manual rebind.

## Dry run

Never let it loose on a server carrying certificates you care about without checking first.

```powershell
.\tools\Build-IisPlanProbe.ps1 `
    -PretendCertificateThumbprint <a-thumbprint-already-in-LocalMachine\My> `
    -IisBindingScope Managed
```

That generates `dist\probe-iis-plan.ps1`, a self-contained **read-only** script. Run it on the
server — via Run Command, PsExec or an interactive session. It imports nothing, binds nothing
and deletes nothing.

Pass the *superseded* thumbprint to see what a renewal would do; pass the *current* one to see
what cleanup would do.

Sample output:

```
detected role       : IIS
binding scope       : Managed

stand-in cert       : A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4
  subject           : CN=*.contoso.com
  dns names         : *.contoso.com, contoso.com

--- https bindings seen by Microsoft.Web.Administration ---
  site=appone         info=*:443:appone.contoso.com          flags=0 store=My   hash=A1B2C3D4...
      http.sys key -> ipport=0.0.0.0:443

--- decision: bindings a real run would re-point ---
  WOULD REBIND  site=appone         info=*:443:appone.contoso.com
                reason: the bound certificate has the same subject (CN=*.contoso.com)

--- decision: certificates CleanupMode=Expired would delete ---
  WOULD DELETE (expired) A1B2C3D4...  notAfter=2026-09-29  CN=*.contoso.com
  kept (still valid)     0F1E2D3C...  notAfter=2026-12-30  CN=contoso.com

--- certificates deliberately NOT considered superseded ---
  safe   FEDCBA98...  CN=WMSvc-SHA2-WEBSRV
```

Every decision carries its reason. If a line says `WOULD REBIND` for something you did not
expect, narrow the scope or use `-IisSites` before running for real.

## Management service certificates

The IIS Web Management Service (`WMSvc`, usually `0.0.0.0:8172`) has its own self-signed
certificate with an unrelated subject and no shared SAN names. Under `Managed` and `Matching`
it is correctly left alone, and cleanup will not remove it.

Under `All` it **will** be re-pointed, which breaks remote management until you repair it. One
more reason to prefer `Managed`.
