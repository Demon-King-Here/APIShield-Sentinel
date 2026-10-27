# Security policy

Security fixes target the latest revision on `main`. Review CI results before
updating an installation; there is no separate long-term-support branch.

Report suspected vulnerabilities through the repository's GitHub **Security →
Report a vulnerability** option when private reporting is enabled. If it is not
available, contact the maintainer privately through their GitHub profile. Do not
publish credentials, live databases, private keys or exploit details in public
issues. Maintainers should enable private vulnerability reporting before release.

## Supported deployment boundary

One administrator, one Python process, one local SQLite database, one selected
gateway address. Keep management on loopback; access it remotely through a
protected tunnel. Network gateway traffic requires a valid TLS certificate and
private key. Upstreams are explicit, allowlisted loopback/private IP addresses.
Keep backend ports private using their binding and host/network access controls.

Gateway controls apply only to routed HTTP traffic. Direct backend access is not
intercepted or logged. Discovery observes local TCP listeners and cannot establish
external reachability or identify every listener's protocol. The app does not
modify Windows Firewall. It is not a complete WAF, IDS, DDoS service, or substitute
for security controls in the upstream applications.

Administrator passwords use salted scrypt; SQLite stores hashes of session
tokens. Cookies use HttpOnly/SameSite=Strict, sessions expire, mutations require
CSRF protection, and authentication is throttled. SQLite itself is not encrypted.
Windows file permissions, disk encryption, OS patching, secret management and
backup protection remain part of the operator's deployment.
