# Contributing

Use Python 3.11 or newer and a separate virtual environment. Install development
dependencies with `python -m pip install -r requirements-dev-lock.txt`, then run
`python -m pytest -q` and `python -m pip check` before opening a pull request.
The maintained Windows discovery feature should also be checked on Windows.
CI tests Windows and Linux on Python 3.11 and 3.14; Linux discovery is a development fallback.

Keep application startup independent of test fixtures. Do not add default credentials,
automatic port imports, firewall changes, built-in traffic generators, or claims
of security that have not been verified. Add regression coverage for changes to
authentication, forwarding, persistence, or deployment configuration.

Tests use temporary databases under ignored `test-results/`. Keep those tests
in Git; exclude generated output, database files, environment secrets, keys,
logs and local IDE configuration. See [security reporting](SECURITY.md) for
vulnerabilities. Report ordinary bugs in GitHub Issues with reproduction steps,
Python/Windows versions, and redacted errors. Never upload your live database.
