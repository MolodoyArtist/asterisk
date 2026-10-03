# Security policy

Please report vulnerabilities privately through GitHub's security-advisory
feature. Do not include credentials, import links, server addresses, logs, or
other private deployment data in a public issue.

## Scope and assumptions

- The supported target is a new Ubuntu 22.04 or 24.04 VPS.
- SSH and the VPS provider account remain the operator's responsibility.
- The web portal is intentionally public at `/` and depends on a strong,
  generated password plus rate limiting.
- Device import links are bearer secrets. Anyone who obtains one can use that
  device identity until it is deleted.
- No single-server design can resist direct blocking of its public IP.

The installer does not send deployment secrets to the repository maintainer.
It contacts Ubuntu mirrors, Snap, GitHub, Let's Encrypt, and an IP-discovery
service as part of installation.
