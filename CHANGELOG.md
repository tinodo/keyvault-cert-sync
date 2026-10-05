# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-10-05

First public release.

### Added

- **Key Vault certificate synchronisation** using the machine's managed identity, with support
  for both Azure VMs and Azure Arc-enabled servers.
- **AD FS binding** — Service-Communications certificate and TLS binding, with primary/secondary
  farm role awareness.
- **Web Application Proxy binding** — the proxy TLS certificate plus each published
  application's own `ExternalCertificateThumbprint`.
- **IIS binding** — `applicationHost.config` plus separate `http.sys` reconciliation, with three
  binding scopes (`Managed`, `Matching`, `All`) and per-site restriction.
- **Superseded certificate cleanup** identified by Subject *or* an identical SAN name set, with
  an in-use guard covering `http.sys`, AD FS and `applicationHost.config`.
- **Locale-independent parsing** — SAN names read from DER, netsh output parsed by value shape,
  so neither breaks on a non-English Windows.
- **Self-contained build** (`tools\Build-ExtensionScript.ps1`) producing a single file for
  Run Command or VM Application deployment.
- **Read-only tooling** — `Verify-CertSync.ps1`, `Check-AgentVersion.ps1`, `Probe-Iis.ps1`, and
  `Build-IisPlanProbe.ps1`, which generates a dry-run planner reporting exactly which bindings
  would be re-pointed and which certificates removed, with a reason for each.
- **ARM template** for publishing Compute Gallery VM Application versions, avoiding the CLI's
  mangling of quoted manage-action strings.
- **82 tests** across three suites, requiring neither Azure, a federation server nor elevation.

### Notes

This release consolidates work developed and validated against a live AD FS farm, Web
Application Proxy and IIS server. Several behaviours exist specifically because the obvious
implementation failed in that environment — see
[docs/architecture.md](docs/architecture.md) for the reasoning:

- Role detection checks installed features before services, because a Web Application Proxy
  carries a running `adfssrv` service.
- SAN names are parsed from DER rather than `X509Extension.Format()`, whose output is localised.
- Cleanup identifies superseded certificates by SAN name set as well as Subject, because ACME
  issuers change the common name between renewals.
- Cleanup runs on passes where nothing else changed, so a certificate that was unremovable
  during a renewal is reconsidered later.

[1.0.0]: https://github.com/tinodo/keyvault-cert-sync/releases/tag/v1.0.0
