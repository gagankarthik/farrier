# Changelog

All notable changes to Farrier are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html):

- **MAJOR** for changes that break the REST API, the CLI, config files or stored data.
- **MINOR** for new features that keep existing setups working.
- **PATCH** for fixes.

Until 1.0.0, minor releases may still change the API; each one says how to upgrade.

To release: bump `farrier/__init__.py`, `web/package.json`, `site/package.json` and the default image in
`docker-compose.yml` to the same version, move the Unreleased notes under a new heading, then push the tag
`vX.Y.Z`. The release workflow refuses a tag that doesn't match them and this file; it publishes the signed
images, then creates the GitHub Release with this file's notes for the version.

## [Unreleased]

### Changed

- The release workflow also creates the GitHub Release, with the tag's CHANGELOG.md notes, once both
  images are published and signed.

## [0.2.0] - 2026-11-13

### Upgrading from 0.1.0

- Schema migrations 9 to 11 (runner jobs, audit hash chain, ACME server tables) run by themselves at
  start-up, under a lock. Back up first (`farrier backup`).
- The activity log is sealed into its hash chain on the first cycle after the upgrade; events from
  before the upgrade are sealed too.
- New Python dependency: `tzdata` (the images include it).
- The root `docker-compose.yml` now runs the release images; add `--build` to keep building from source.
- Setting both OIDC and SAML in the dashboard now fails closed: choose one.
- Nothing else changes until you opt in: runners, approvals, issuance policy, the ACME server, cloud
  inventory and the new connectors are all off until configured.

### Added

- AWS Certificate Manager managed ACME: the `aws-acm` issuer preset (no DNS-01; with `acm_eab_arn` the
  directory URL and EAB key come from ACM through IAM) and `farrier acm` commands to create endpoints,
  prevalidate domains and manage External Account Bindings. Terraform: `acm_acme_endpoint_arns`.
- AWS Private CA (`aws_pca`) and Google Certificate Authority Service (`gcp_cas`) issuers, with a
  dashboard **Test** that checks the engine can reach the CA.
- One-command install: `install.sh` writes a `.env` with a random token and password, pulls the signed
  images and starts them; `FARRIER_MODE=demo` runs the simulated estate in Docker (`farrier demo --host`).
  The root `docker-compose.yml` now uses the release images (`--build` still builds from source).
- Nightly live checks against Let's Encrypt staging and AWS ACM (`.github/workflows/live.yml`), enabled
  by repository secrets.
- Dashboard: four sidebar sections (Overview, Certificates, Security, Setup) with each section's pages
  as tabs; every page keeps its URL.
- Website: solution pages for F5, FortiGate, PAN-OS, the 47-day schedule, AWS ACM, cloud private CAs and
  open-source CLM, with schema.org FAQ, breadcrumb and software data, and canonical URLs.
- Connectors for Citrix ADC / NetScaler (NITRO), Kubernetes TLS Secrets (with an in-cluster backup and
  optional rollout restart) and IIS (OpenSSH and PowerShell).
- Issuance policy in `settings.json`: allowed names, issuers and key types per project, checked before
  any request to a CA.
- Remote runners for segmented networks: `farrier runner start` inside a DMZ, OT or branch network
  connects out over HTTPS and runs that group's observe, deploy, verify and rollback jobs with the
  same connectors; device credentials can stay on the runner. Group tokens from `farrier runner token`
  or **Settings → Remote runners** (schema migration 9).
- Cloud certificate inventory: **Certificates → Cloud**, `farrier cloud-certs` and
  `GET /api/cloud/certificates` list certificates in AWS ACM, Azure Key Vault and Google Certificate
  Manager (settings `cloud_inventory`).
- Approval gates: `approvals` in `settings.json` holds renewals before issuance until an admin approves
  them in the dashboard or API, or until a ServiceNow change request is approved.
- Change windows take a time zone (`"tz": "Europe/Berlin"`), following daylight saving; invalid windows
  are refused when an endpoint is saved. New dependency: `tzdata`.
- Tamper-evident activity log: events are sealed in a SHA-256 hash chain each cycle (schema migration
  10); `farrier audit verify|export|check`, `/api/audit/*`, and an integrity badge and signed export in
  Activity. Compliance report: `farrier report`, `/api/reports/compliance` (JSON or CSV).
- Replace and revoke: `farrier replace`, `POST /api/replace` and **Certificates → Replace…** renew every
  certificate matching a CA, issuer, key type, project or tag now, and optionally revoke the old ones
  (ACME, AWS Private CA) once nothing serves them.
- ACME server (RFC 8555): certbot, cert-manager, lego, acme.sh and win-acme get internal certificates
  from a Farrier issuer at `/acme/<profile>/directory` (settings `acme_server`). Accounts need an EAB
  key (`farrier acme-server eab create`); names are authorized by the profile, the key and the issuance
  policy; every certificate is logged with its account (schema migration 11).
- Connectors `aws_acm` (re-import in place, or import and switch an ELBv2 listener with exact
  rollback), `azure_keyvault` (new certificate version, optional Application Gateway and Front Door
  refresh) and `gcp_certificate_manager` (Certificate Manager and classic HTTPS proxies).
- Cross-account AWS: a shared, cached `sts:AssumeRole` (with ExternalId) for connectors, inventory
  (`cloud_inventory.aws_accounts`) and Route 53; Terraform `assumable_role_arns`.
- SAML 2.0 single sign-on for the dashboard (`FARRIER_SAML_*`, Helm `web.auth.mode=saml`), with the
  same roles, projects and session as OIDC. Setting both OIDC and SAML fails closed.
- Renewals carry a `reason_code` and a one-line `hint`; `farrier explain <endpoint>` and
  `GET /api/endpoints/{id}/explain` say why the next renewal is when it is. New metrics for planned
  renewals, failures by reason, approvals, runner groups and audit integrity; opt-in Helm
  PrometheusRule alerts and Grafana dashboard. Troubleshooting guide.
- Certificate Transparency discovery: `farrier ct <domain>`, `GET /api/discover/ct` and **Find names** on
  the Discovery page list every name with a valid public certificate.

### Fixed

- The ServiceMonitor keeps Farrier's `endpoint` label (`honorLabels: true`).

- A failing CA, DNS provider or device is no longer retried every tick. Issuance attempts back off
  (5, 10, 20, 40 min, or the CA's `Retry-After`), and after a failed or rolled-back renewal the next
  one waits 1 h, doubling up to 32 h. "Renew now" still starts at once.

## [0.1.0] - 2026-11-12

First public release.

### Added

- Renewal engine: scan, plan inside change windows with daily caps, issue, deploy, verify, roll back.
- Connectors for F5 BIG-IP, FortiGate, Palo Alto PAN-OS, Java keystores and files over SSH, plus
  change packs (PEM, PFX, runbook, ticket) for every other device.
- ACME client (RFC 8555) with External Account Binding, presets for Let's Encrypt, ZeroSSL,
  Google Trust Services, Buypass, SSL.com, DigiCert and Sectigo, and a built-in private CA.
- DNS-01 through 29 DNS providers with several accounts each and CNAME delegation.
- SQLite, PostgreSQL and MySQL, schema migrations, and several replicas with leader election.
- Deployment verification (fingerprint, chain, names, every VIP), domain health grades and a
  zombie certificate scanner.
- MCP server for Claude, Gemini CLI, Codex and other MCP clients, read-only by default.
- Web dashboard with OIDC single sign-on and viewer, operator and admin roles; docs and site.
- Prometheus metrics, CSV inventory, and Slack, Teams, webhook and email (SMTP, SES) alerts.
- Let's Encrypt: renewal timing from the CA (ARI, RFC 9773) and `replaces` on new orders,
  certificate profiles (`classic`, `tlsserver`, `shortlived`), preferred alternate chains,
  and rate-limit handling with `Retry-After`.
- CI runs the ACME client against Pebble, Let's Encrypt's ACME test server.
- Dashboard Settings: edit the renewal policy; view CAs, DNS accounts, notifiers and the engine.
- `GET /api/config` and `PUT /api/config/settings`.
- Configure certificate authorities, DNS accounts, alert channels and custom alert rules from the
  dashboard; secrets are write-only, stored through a pluggable secret backend (sealed locally by
  default) and referenced as `vault:NAME`.
- Custom alert rules: renewal events, expiring within N days, health grade below a threshold,
  zombie certificates and unreachable endpoints, with filters, channels and a cooldown.
- The private CA issues certificates with key identifiers (AKI, SKI).
- Agentless SSH key management: host keys and algorithms read from the handshake (no login),
  authorized_keys inventory over SSH with stored credentials, findings for weak, duplicate,
  unknown and orphaned keys, and verified single-line removal with a backup.
- Cryptographic discovery and post-quantum readiness: TLS versions, cipher suites, key exchange
  (including X25519MLKEM768 hybrid), weak-crypto flags, a ready/hybrid/vulnerable/unknown rating
  per asset, and a CycloneDX 1.6 CBOM export.
- Certificate details: subject, SANs, chain, key, signature, fingerprints, history and renewals.
- ServiceNow and Jira tickets for change packs (opened, updated, closed when verified live),
  Datadog events and expiry metrics, and Splunk HEC events with a daily inventory.
- Cloud secret managers (AWS, Google Cloud, Azure, HashiCorp Vault), a KMS-wrapped master key,
  object storage for change packs and backups, and CloudEvents to EventBridge, Pub/Sub and Event Grid.
- Terraform for AWS, Google Cloud and Azure, a Helm chart, production Docker Compose, and event-driven
  functions (ACM, Certificate Manager and Key Vault import).
- Managed Kubernetes: Helm values and Terraform for EKS, GKE and AKS with workload identity.
- Teams and projects: each team sees and changes only its own endpoints, keys, scans and alerts, with
  membership from SSO groups and scope enforced by the engine.
- Command line for the whole product: `ssh scan`, `ssh keys`, `crypto scan`, `crypto summary`,
  `crypto cbom`, `certs show`, `endpoints approve` and `version`.
- Discovered endpoints are monitored but renewed only after an admin approves them.
- Signed backups; scan targets counted before they are built; private keys, system files and
  ambient cloud credentials never reachable through secret references.
- The landing page and docs are a separate static app (`site/`); installs ship only the dashboard
  (`web/`), whose `/` opens the dashboard.

[Unreleased]: https://github.com/gagankarthik/farrier/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gagankarthik/farrier/releases/tag/v0.1.0
