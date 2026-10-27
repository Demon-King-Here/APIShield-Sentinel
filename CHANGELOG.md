# Changelog

## Production application distribution — 2026-10-27

- Distribute the Windows management dashboard and separate TLS-capable API gateway.
- Start with an empty inventory; register existing backends through API Inventory.
- Retain password login, session/CSRF protections, persistent rate limits,
  read-only discovery, policy enforcement, live telemetry and SQLite backups.
- Limit standard start/stop launchers to Sentinel's owned process.
- Keep developer regression tests and CI separate from runtime dependencies.
- Preserve existing database records during upgrades and keep private state out of Git.

See [deployment](docs/DEPLOYMENT.md) for the supported topology and operational setup.
