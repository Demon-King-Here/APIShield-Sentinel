# Deployment and operations

## Supported topology

APIShield supports a single Windows host, a single operator, and one Python
process. Management stays on loopback; the gateway binds one loopback or private
address. Use a local disk for SQLite. Multiple workers, `--reload`, shared network
filesystems, horizontal scaling and high availability are unsupported. Choose
capacity from measurements on your hardware and real upstreams. No throughput
or uptime SLA has been established.

## Installation

Clone the repository, create a Python 3.11+ virtual environment and install
`requirements-lock.txt`. Runtime installation excludes pytest and test tools.
Run from the repository root:

```powershell
.venv\Scripts\python.exe -m app --check-config
.venv\Scripts\python.exe -m app
```

The foreground command supports graceful Ctrl+C shutdown. The Windows batch
launchers run only Sentinel and keep ownership-checked process records and logs
under `runtime/`. A production supervisor should run the foreground command,
restart failed processes, and capture/rotate stdout/stderr. Configure the absolute
Python executable, `-m app` arguments, the checkout as working directory, and a
dedicated unprivileged service account. Configure single-instance execution.
No Windows service is installed automatically.

## Persistent configuration

Set variables in the account or supervisor that starts the process. `.env.example`
is reference documentation; `.env` files are not automatically imported. PowerShell
`$env:` assignments apply to the current shell and its children; launching a batch
file from Explorer does not inherit a different terminal's variables.

| Variable | Default / purpose |
| --- | --- |
| `APISHIELD_DB` | `data/sentinel.db`; use an absolute protected path outside the checkout for a live service |
| `APISHIELD_ADMIN_HOST` | `127.0.0.1`; loopback addresses only |
| `APISHIELD_ADMIN_PORT` | `8002` |
| `APISHIELD_GATEWAY_HOST` | Optional explicit IP override; shipped configuration uses `127.0.0.1` |
| `APISHIELD_GATEWAY_INTERFACE` | Optional adapter name; effective when the host override is unset |
| `APISHIELD_GATEWAY_PORT` | `8080` |
| `APISHIELD_GATEWAY_CERTFILE` | PEM certificate chain for gateway TLS |
| `APISHIELD_GATEWAY_KEYFILE` | PEM private key; configure together with certificate |
| `APISHIELD_CA_FILE` | Optional PEM trust bundle for internal HTTPS probes and HTTPS upstreams |
| `APISHIELD_UPSTREAM_HOSTS` | `127.0.0.1,::1`; comma-separated explicit allowlisted private/loopback IPs |
| `APISHIELD_ADMIN_TOKEN` | Optional random automation bearer token, at least 32 characters |
| `APISHIELD_HISTORY_LIMIT` | `20000` rows per main history table, range 100–1000000 |

Ports must be 1024–65535 and the two listeners must use different ports. Invalid
configuration stops startup. Existing database routes are preserved on upgrade;
existing API configuration and history are preserved. Review outdated routes
through API Inventory rather than deleting the database.

## TLS and network access


Obtain a certificate and key from your trusted CA. Certificate subject alternative
names must cover the exact gateway IP used by clients **and** the gateway's own
health and verification requests. Hostnames and public-IP bindings are not currently
supported configuration values. A private CA is suitable for a managed private
network if all clients trust it. Include its CA in the configured trust bundle.
Certificate validation stays enabled; the app does not offer a skip-verify switch.

```powershell
$env:APISHIELD_GATEWAY_HOST = "192.168.1.20"  # replace with an address on this host
$env:APISHIELD_GATEWAY_CERTFILE = "C:\APIShield\certs\gateway-chain.pem"
$env:APISHIELD_GATEWAY_KEYFILE = "C:\APIShield\certs\gateway-key.pem"
$env:APISHIELD_CA_FILE = "C:\APIShield\certs\trust-bundle.pem"
.venv\Scripts\python.exe -m app --check-config
.venv\Scripts\python.exe -m app
```

To follow an adapter, unset the host override and set `APISHIELD_GATEWAY_INTERFACE`
to its exact Windows name. IP changes require certificates valid for the new IP;
automatically rebinding the listener does not renew certificates. Restart after
renewing a certificate. Keep management on loopback and tunnel it for remote use.
The gateway ignores forwarded IP headers: rate limits identify the actual TCP
peer. A reverse proxy or tunnel in front of the gateway makes users share that
peer's quota. Trusted-proxy client identity is not implemented.

## First account and file protection

Open `http://127.0.0.1:8002`. Read `admin-setup-code.txt` beside the configured
database, enter the code, and choose a username and passphrase of 15–128 characters.
The file rotates on unconfigured restarts and is removed after account creation.
Restrict Windows ACLs on the database directory, backups, runtime logs and TLS keys
to the service account and trusted administrators. The setup file's POSIX mode
does not establish a restrictive Windows ACL. Do not serve these folders over HTTP.
Local users who can modify these files or the Python source are outside the
application's protection boundary.

Passwords, cookies and full HTTP bodies are not included in telemetry. Paths,
API names, listener/process details and client addresses can be sensitive.
Configure retention and protect exports and backups. Route secrets are environment
variables; the inventory stores their variable names, not the secret values.

## Monitoring and backups

`GET /api/health` checks management liveness and reports gateway status.
`GET /api/ready` returns 200 only when the gateway health request succeeds,
otherwise 503. `GET /_sentinel/health` is the gateway's own liveness endpoint.
Readiness does not promise that every configured upstream is healthy. Monitor
disk space, failed authentication, gateway errors, process restarts and certificate
expiry. Disable response buffering if transporting the dashboard's SSE stream.

Use **Settings → Download SQLite backup** for a consistent snapshot. Back up route
environment variables and certificates separately using your secret-management
process. Periodically test restoration on a separate installation. To restore,
stop Sentinel, preserve the current database and matching WAL/SHM sidecars
together in a separate location, then place the snapshot at `APISHIELD_DB` with no
stale sidecars. Start and verify login, routes and forwarding. Do not copy a live
SQLite file without a consistent snapshot or replace a running database.

## Upgrades and recovery

Back up first, stop the process, review release notes, install the new pinned
requirements in a fresh environment, check configuration, and restart. Schema
changes are additive; a newer unsupported database schema fails closed. Roll back
code and the matching database backup together if compatibility requires it.
Never delete the live database merely to reset a password. With Sentinel stopped:

```powershell
.venv\Scripts\python.exe scripts\reset_admin.py --confirm-local-reset
```

This creates a backup and removes administrator credentials/sessions while retaining
API configuration and monitoring data. Restart and complete setup again.

## Release checks

Run the automated suite and dependency audit, verify a fresh clone and real TLS
handshake, test backup/restore, and evaluate host firewall rules and upstream
authentication for the actual environment. Review GitHub CI after pushing. Branch
protection, private security reporting, TLS issuance, service supervision and
external network validation need repository/host configuration by the operator.

References: [FastAPI deployment concepts](https://fastapi.tiangolo.com/deployment/concepts/)
and [GitHub Python CI](https://docs.github.com/en/actions/tutorials/build-and-test-code/python).
