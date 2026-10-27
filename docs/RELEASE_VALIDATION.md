# Application validation — 27 October 2026

The current distribution was checked in an isolated checkout, independently of
the maintainer's running installation and private data.

- 108 automated tests passed on Windows/Python 3.14.5 after removing presentation features.
- Authentication, salted password storage, sessions, CSRF, request validation,
  proxy forwarding, quotas, persistence, backups, discovery and verification remain covered.
- A real TLS listener accepted a trusted certificate and rejected an untrusted client.
- New installations contain no registered backends and require local account setup.
- JavaScript syntax validation passed. Local documentation links were checked.
- Runtime dependencies remain pinned and audited by the GitHub workflow.

The upstream Starlette TestClient emits one deprecation warning with the pinned
stack. This does not represent an application test failure.

Validate trusted certificates, host permissions, backend access controls,
supervision, backup restoration and capacity for the deployment environment.
Passing automated tests does not establish external reachability or complete
protection against every attack. See [Security policy](../SECURITY.md).
