# vpnctl — one-command proxy appliance for a fresh VPS

A self-hosted VLESS appliance with no third-party management panel. The
default profile is VLESS + REALITY + RAW/TCP + XTLS-RPRX-Vision. The installer
also provides a neutral HTTPS account portal and can add VLESS + XHTTP + TLS
when the owner later supplies a domain.

> This project is intended for lawful access to your own resources and for
> protecting network traffic. Follow the laws of your jurisdiction and your VPS
> provider's terms of service.

## What you get

- A working REALITY/Vision proxy as soon as installation finishes; no domain is required.
- An HTTPS control portal at `https://SERVER_IP:8443/`.
- Random portal credentials, REALITY keys, device identifier, and XHTTP path.
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
- Inbound TCP ports 80, 443 and 8443 allowed by the provider firewall.

The installer changes Nginx and UFW. Run it on a new VPS, not on a server that
already hosts websites.

## Quick start

Connect to the VPS over SSH and run:

```bash
curl -fsSL https://raw.githubusercontent.com/MolodoyArtist/asterisk/main/install.sh | sudo bash
```

The installer asks whether you already have a domain. The recommended REALITY
profile is always created; a supplied domain additionally enables XHTTP + TLS.

Running the same command again on an installed appliance performs a safe update
with a backup and automatic rollback if an error occurs. Devices, the domain,
and portal credentials are preserved.

For installations created by older XHTTP-only releases, the updater preserves
the existing XHTTP + TLS endpoint and every existing client link. It does not
silently add or switch profiles, so no client-side action is required.

### Option 1: no domain yet

Answer `N` or press Enter. The installer requests a short-lived public IP
certificate from Let's Encrypt for the portal on port 8443. It renews
automatically, so portal credentials are not sent in clear text.

The proxy itself uses REALITY on TCP/443, directly in Xray; Nginx is not in its
data path. Blocking the VPS IP still stops access.

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
6. On **Devices**, import and test the additional XHTTP + TLS link.

The recommended REALITY profile remains available on TCP/443. The domain profile
uses Nginx on TCP/8443, because an independent XHTTP/TLS service cannot also
bind TCP/443 while REALITY owns that port.

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

- Xray REALITY listens directly on TCP/443; the XHTTP inbound is loopback-only
  and exists only after a domain is added. SSH, HTTP, TCP/443 and TCP/8443 are
  externally reachable.
- HTTP serves ACME validation only; the portal never accepts credentials over HTTP.
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

## REALITY target

The installer tests a small candidate set from the VPS and uses the first
reachable target; it does not hard-code a single global SNI. The chosen name is
used both as SNI in the connection URI and as the REALITY target. You can set a
specific target at first installation with `VPNCTL_REALITY_TARGET=hostname`, or
replace the candidate list with `VPNCTL_REALITY_TARGETS=name1,name2`. Use a
stable public HTTPS hostname verified from that VPS. Updates preserve existing
profiles and do not silently change their target or client links.

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
