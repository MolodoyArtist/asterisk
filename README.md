# vpnctl — one-command proxy appliance for a fresh VPS

A self-hosted VLESS + XHTTP proxy with no third-party management panel. The
installer sets up Xray, Nginx, HTTPS, and a small local control portal. The
generated connection link can be imported into v2RayTun.

> This project is intended for lawful access to your own resources and for
> protecting network traffic. Follow the laws of your jurisdiction and your VPS
> provider's terms of service.

## What you get

- A working proxy as soon as installation finishes.
- An HTTPS control portal on the server's root page.
- Random portal credentials, device identifier, and XHTTP path.
- A separate VLESS link and QR code for every device.
- A guided domain-addition flow in the portal.
- Automatic certificate renewal.
- Service status, local metrics, and logs scrubbed of addresses and secrets.
- No 3x-ui, database, analytics, or browser-side third-party scripts.

## Requirements

- A new Ubuntu 22.04 or 24.04 VPS.
- x86_64 or arm64 architecture.
- A public IPv4 address.
- Root access or a user with `sudo`.
- Inbound TCP ports 80 and 443 allowed by the provider firewall.

The installer changes Nginx and UFW. Run it on a new VPS, not on a server that
already hosts websites.

## Quick start

Connect to the VPS over SSH and run:

```bash
curl -fsSL https://raw.githubusercontent.com/MolodoyArtist/asterisk/main/install.sh | sudo bash
```

The installer asks whether you already have a domain.

Running the same command again on an installed appliance performs a safe update
with a backup and automatic rollback if an error occurs. Devices, the domain,
and portal credentials are preserved.

### Option 1: no domain yet

Answer `N` or press Enter. The installer requests a short-lived public IP
certificate from Let's Encrypt. It renews automatically, so the portal and
proxy use trusted HTTPS from the first connection: portal credentials are not
sent in clear text.

This mode is secure transport but less stealthy. TLS without a conventional
domain is more noticeable, and blocking the VPS IP will still stop access. Use
IP mode as a starting or recovery path rather than a complete replacement for a
domain.

At completion, the installer prints:

- Portal URL.
- Generated login and password.
- VLESS import link.
- QR code.

Copy the link into v2RayTun or scan the QR code in the app. Then sign in to the
portal and open **Domain**.

### Option 2: you already have a domain

Before installation, create an A record pointing the domain to the VPS public
IPv4 address. Answer `Y` when prompted and enter a fully qualified hostname,
for example `access.example.com`. The installer validates DNS and issues a
normal domain certificate.

With Cloudflare DNS, the record must be **DNS only** (gray cloud). Otherwise,
the validation intentionally fails.

Create an AAAA record only when the VPS has a working public IPv6 address. An
incorrect AAAA record can send some users to another server and prevent
certificate issuance.

## Add a domain later

1. Sign in to the portal by IP address.
2. Open **Domain**. It provides a guided flow and links to No-IP, DuckDNS,
   FreeDNS, deSEC, and Cloudflare DNS.
3. Create an A record using the value displayed by the portal.
4. Wait for DNS propagation and select **Check DNS**.
5. Issue the certificate and activate the domain.
6. On **Devices**, import and test the new domain link.
7. Only after testing, disable IP mode.

Until the final step, the IP and domain profiles work simultaneously. Disabling
IP mode removes direct HTTPS access by IP and stops renewal of its certificate.
The portal then sends the browser to the domain; sign in again because secure
cookies cannot transfer between an IP address and a hostname.

Free No-IP hostnames need confirmation every 30 days. Missing that confirmation
will make the domain profile unavailable.

## Core commands

```bash
sudo vpnctl status
sudo vpnctl doctor
sudo vpnctl client list
sudo vpnctl client add laptop
sudo vpnctl client delete old-phone
sudo vpnctl domain check access.example.com
sudo vpnctl domain add access.example.com
sudo vpnctl certificate renew
sudo vpnctl admin reset-password
```

The old password cannot be recovered. Resetting it creates a new password,
prints it once, and invalidates existing portal sessions.

Initial credentials are also stored root-only in `/root/vpnctl-install.json`.
Delete the file after saving the credentials:

```bash
sudo rm /root/vpnctl-install.json
```

## Security and privacy

- Xray listens only on `127.0.0.1`; SSH, HTTP, and HTTPS are externally
  reachable.
- HTTP serves ACME validation and redirects the known endpoint to HTTPS.
- Unknown Host/SNI values and an invalid XHTTP path receive a normal 404.
- Access logs for the portal and XHTTP are disabled.
- Xray does not retain browsing logs; service output is scrubbed before it is
  shown in the portal.
- Portal sessions are signed; cookies use `Secure`, `HttpOnly`, and
  `SameSite=Strict`; state-changing requests require a CSRF token.
- Login attempts are rate-limited and passwords are stored as `scrypt` hashes.
- Local, link-local, cloud-metadata, BitTorrent, and outbound SMTP/25 access is
  blocked.
- A single VPS cannot be made resilient to blocking of its public IP.

A VLESS import link is a secret. If a device is lost or its link is shared,
delete that device in the portal and create a replacement.

See [SECURITY.md](SECURITY.md) for scope assumptions and vulnerability-reporting
guidance.

## Validate the source tree

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q src
bash -n install.sh scripts/check-repository.sh scripts/integration-smoke.sh
bash scripts/check-repository.sh
```

Xray is pinned to a reviewed version and its archive is checked against the
SHA-256 published with the official release. Updating it requires an explicit
change to `VPNCTL_XRAY_VERSION`; the installer never silently downloads an
arbitrary `latest` build.

## License

[MIT](LICENSE)
