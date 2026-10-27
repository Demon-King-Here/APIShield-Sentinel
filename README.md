# APIShield Sentinel

A self-hosted Windows API security gateway and discovery dashboard built with
FastAPI, HTTPX and SQLite. Register your own private backends, apply route
policies, and inspect real gateway traffic, security events and Windows listener
evidence. Every new installation starts with an empty API inventory and a locally
created administrator account.

## Install and start

Use Windows 10/11 or Windows Server and Python 3.11+. In PowerShell:

```powershell
git clone https://github.com/Demon-King-Here/APIShield-Sentinel.git
cd APIShield-Sentinel
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.venv\Scripts\python.exe -m app --check-config
.venv\Scripts\python.exe -m app
```

Open [http://127.0.0.1:8002](http://127.0.0.1:8002). For first setup, read the
one-time code from `data/admin-setup-code.txt` and choose a username and passphrase
of at least 15 characters. The code file is deleted after account creation.
Later starts reuse your account and database. Stop the foreground server with
Ctrl+C. Virtual-environment activation is optional when using the explicit path.

On Windows, double-click `Start_APIShield.bat` to start Sentinel in the background
and open the dashboard. `Stop_APIShield.bat` stops only the process recorded by
that launcher. These launchers do not start or stop your backend applications.

The default dashboard listener is **127.0.0.1:8002**; the separate API gateway is
**127.0.0.1:8080**. Administration stays on loopback. Use a protected tunnel such
as SSH for remote administrative access. No Windows Firewall rules are changed.

## Connect your API

1. Run your existing backend on a private address, preferably loopback on this host.
2. Sign in and open **API Inventory → Add API**.
3. Set its origin, such as `http://127.0.0.1:9000`, a gateway prefix such as
   `/service`, and the backend health and verification paths.
4. Configure policies, save, and use **Verify**.
5. Send requests through the gateway and inspect **Live Traffic** and **Security Events**.

With **Strip gateway prefix** enabled, `/service/health` on the gateway forwards
to `/health` on the backend. Registration stores routing configuration; it does
not create an application, copy its business database, or manage its process.

**API Discovery → Scan now** observes local listening TCP sockets and owning
processes. Review a listener's purpose and protocol before registering an API.
Finding a listener does not prove that it is HTTP, healthy, or externally reachable.

## Policies and authentication

Policies support per-client/per-route sliding-window limits, permitted HTTP
methods and paths, bounded request sizes, optional client API keys and optional
upstream bearer credentials. Secret values stay in process environment variables;
the inventory stores only the variable names.

Administrator passwords use salted scrypt. Login uses expiring, revocable sessions,
hashed server-side identifiers, HttpOnly/SameSite cookies, CSRF checks and
authentication throttling. Gateway API credentials and administrator login are
separate. Cookies and internal control headers are filtered before forwarding.

## Deployment and persistence

Gateway access on a private network address requires a PEM certificate and key.
Configure `APISHIELD_GATEWAY_CERTFILE`, `APISHIELD_GATEWAY_KEYFILE` and, when using
a private CA, `APISHIELD_CA_FILE`. Set `APISHIELD_GATEWAY_HOST` or select an
adapter with `APISHIELD_GATEWAY_INTERFACE`. Certificates must cover the address
used by clients and internal health checks. Configuration is validated before
listeners start. `.env.example` documents settings and is not loaded automatically.

SQLite stores your routes, policies, administrator records, request history,
events, audit records, verification history and rate-limit windows. The database
is not encrypted at rest. Use **Settings → Download SQLite backup** for a
consistent snapshot, and protect the data directory and exported files.

Supported operation is one Windows host, one administrator, one Python process
and a local SQLite database. Multiple Uvicorn workers, reload, shared network
storage, high availability, public-IP upstreams, WebSockets and unbounded streaming
are outside the current scope. Linux discovery is a labeled development fallback.

Gateway controls apply to routed HTTP requests. Direct backend connections bypass
those controls and telemetry, so protect backend bindings and host/network access
separately. APIShield is not a complete WAF, IDS or DDoS protection service.

## Development

```powershell
.venv\Scripts\python.exe -m pip install -r requirements-dev-lock.txt
.venv\Scripts\python.exe -m pytest -q
```

Security and regression tests remain under `tests/` and use temporary storage
and mocked upstreams. Application installation excludes test packages. GitHub CI
checks Windows/Linux with Python 3.11/3.14 and audits pinned runtime dependencies.
Database files, secrets, keys, logs, local IDE files and generated test output
are excluded from Git. See [Contributing](CONTRIBUTING.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Deployment and operations](docs/DEPLOYMENT.md)
- [Security policy](SECURITY.md)
- [Validation](docs/RELEASE_VALIDATION.md)
- [Changelog](CHANGELOG.md)

Licensed under [MIT](LICENSE). Vendored Chart.js retains its
[upstream license](frontend/js/vendor/LICENSE.Chart.js.txt).
