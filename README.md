# vpnctl — a proxy on a fresh VPS in one command

vpnctl installs Xray, a small HTTPS account portal and an optional Telegram
proxy. It has no third-party management panel, database or analytics.
Deployment keys, device names, credentials and paths are generated on the VPS;
they are never uploaded to this repository.

## Two simple stages

1. **No domain:** VLESS + REALITY + Vision works immediately on TCP/443.
   Open the account portal at `https://SERVER_IP:9443/` using its generated
   credentials. The portal uses a publicly trusted, automatically renewed IP
   certificate.
2. **Domain ready:** enter the hostname in **Domain**, check DNS and confirm
   activation. vpnctl replaces the temporary REALITY profile with **VLESS +
   XHTTP + TLS on TCP/443** and **Hysteria 2 on UDP/443**. Download the new
   profiles from **Devices**. The old REALITY link stops working.

A domain is required for these domain profiles and their website cover; it
is not a promise that a domain makes every transport more resistant to DPI.
The VPS IP remains visible and can be blocked.

## Install

Use a **new Ubuntu 22.04 or 24.04 VPS**, x86_64 or arm64, with a public IPv4,
at least 512 MiB RAM and 2 GiB free disk space. The installer changes Nginx,
UFW and systemd, so do not run it on a server already hosting other services.

After the matching release is published, connect over SSH and run its numbered
bootstrap (the next release for this layout is `v0.3.0`):

```bash
curl -fsSL https://github.com/MolodoyArtist/asterisk/releases/download/v0.3.0/vpnctl-bootstrap-v0.3.0.sh | sudo bash
```

Use an actual published release, not `main`. Its bootstrap verifies the release
archive against an embedded SHA-256 before running anything as root. Xray and
mtg downloads are pinned to specific versions and checksums, too.

The installer asks whether you already have a domain. If yes, it creates the
domain profiles directly. Otherwise, it creates the temporary REALITY profile.
It prints the portal URL, random login and password, and the initial connection
link with a QR code. It also stores a root-only recovery copy in
`/root/vpnctl-install.json`; delete it after securely saving the credentials:

```bash
sudo rm /root/vpnctl-install.json
```

## Ports

| Port | Without a domain | After domain activation |
| --- | --- | --- |
| TCP/80 | ACME certificate validation | ACME certificate validation |
| TCP/443 | Xray REALITY + Vision | Nginx: public website and XHTTP |
| UDP/443 | Closed | Xray Hysteria 2 |
| TCP/8443 | Closed | Optional Telegram FakeTLS, only when enabled |
| TCP/9443 | Account portal by IP | Account portal by domain |
| TCP/5555 | Not used | XHTTP on loopback only; never open externally |

Allow SSH, TCP/80, TCP/443 and TCP/9443 in the VPS provider's firewall. After
activating a domain, also allow UDP/443. Allow TCP/8443 only for the optional
Telegram proxy. vpnctl manages the corresponding host UFW rules, but cannot
change a provider's external firewall.

Nginx is the reverse proxy for XHTTP: it forwards an installation-specific
random path to `127.0.0.1:5555`. It handles the portal separately on 9443.
Hysteria receives QUIC directly, not through Nginx. Ordinary HTTP/3 requests
without proxy authentication receive the public site through Hysteria's
masquerade. The public cover site has no route to the account portal.

## Add a domain in the portal

1. Register a hostname and create an **A record pointing to this VPS**.
   With Cloudflare, choose **DNS only**, not its orange-cloud proxy.
2. Create an AAAA record only if this VPS has working public IPv6. Incorrect
   AAAA records must be removed before certificate issuance.
3. Open **Domain**, enter the hostname and select **Check DNS**.
4. Confirm **Activate XHTTP and Hysteria**. The certificate is issued and
   validated before the temporary profile is stopped. A failed activation
   attempts to restore the previous settings and listener layout.
5. Your current REALITY connection closes. Disable it and sign in at
   `https://YOUR_DOMAIN:9443/` to get the new profiles from **Devices**.

Existing devices keep their names and VLESS identifiers. Each device receives
an independently generated Hysteria credential. Deleting a device revokes its
XHTTP and Hysteria access together. REALITY's server private key is removed
from the active state after the domain profiles start successfully.

Free hostnames may need periodic confirmation (for example, No-IP requires
confirmation every 30 days). Keep that account current.

## Download client profiles

**Devices** shows per-device import links and QR codes. After domain activation,
it also offers authenticated JSON downloads:

- **XHTTP JSON for Xray/v2RayTun:** VLESS over XHTTP and verified TLS. This is an
  Xray configuration, not a sing-box configuration. In a raw core deployment it
  provides a local SOCKS listener; a graphical client manages its own tunnel.
- **Hysteria JSON for sing-box:** a TUN profile for sing-box on macOS/iOS using
  Hysteria 2, verified TLS and DNS over HTTPS through the proxy. The server IP is
  used for the outer connection to avoid a bootstrap DNS dependency.

The sing-box profile requires a recent version supporting typed DNS servers
(1.12 or later). XHTTP requires an Xray-based client. Stock sing-box does not
support the XHTTP configuration exported here.

Downloads contain secrets, are never written to the web root and are served
with `Cache-Control: no-store`. Do not upload them to GitHub or share them in
public issues. Deleting a device revokes its credentials.

## Optional Telegram proxy

Once the domain profiles work, open **Telegram** and choose **Enable Telegram
proxy**. vpnctl installs **mtg with FakeTLS on TCP/8443**, generates a separate
secret and displays a Telegram link and QR code. It supports x86_64 and arm64.

The visible FakeTLS name is your domain. An ordinary TLS connection is passed
to the public website on TCP/443. The portal remains on its separate port;
mtg does not have access to its credentials or the appliance's private state.
Anti-replay is enabled. The service runs as an unprivileged account with
resource limits. IPv4 connectivity is used for this optional endpoint.

This proxy covers Telegram messaging and media transfers, not other apps or
the audio/video transport of calls. Calls may still work directly, but MTProxy
does not provide an unblock path for their media. FakeTLS does not guarantee
invisibility to every DPI implementation. mtg does not support sponsored-channel
`adtag` in this configuration.

Rotate a disclosed Telegram link; the previous link immediately stops working.
Disable stops the listener and removes its dedicated UFW rule. XHTTP and
Hysteria do not restart when Telegram is enabled, disabled or rotated.

## Management

```bash
sudo vpnctl status
sudo vpnctl doctor
sudo vpnctl client list
sudo vpnctl client add laptop
sudo vpnctl client delete old-phone
sudo vpnctl domain check access.example.com
sudo vpnctl domain add access.example.com
sudo vpnctl certificate renew
sudo vpnctl telegram status
sudo vpnctl telegram enable
sudo vpnctl telegram rotate
sudo vpnctl telegram disable
sudo vpnctl admin reset-password
```

Resetting the portal password creates a new password and invalidates existing
sessions. The old password cannot be recovered. Certificate renewal refreshes
Nginx and the private certificate copy used by Hysteria automatically.

## Updates and older installations

Run a newer numbered release bootstrap to update. The updater stages the new
application and pinned Xray release, validates them and keeps recovery copies.
If migration, validation, restart or final checks fail, it attempts to restore
the prior application, state, certificates, credentials, configuration and units.

Older installations keep their existing links and portal port on update; they
do not silently switch transports. Reconfirm domain activation to adopt the
new layout and move the portal to 9443. An enabled legacy Telegram/padding
profile must first be disabled in the old version; the updater refuses to
silently replace that running endpoint with a different protocol.

## Security and privacy

- State and private credentials stay on the VPS. There is no telemetry.
- The portal runs without root and uses a local Unix socket to request a small
  set of operations from a privileged agent. Xray and mtg have dedicated users.
- Portal sessions are signed, cookies are Secure/HttpOnly/SameSite=Strict,
  mutations require a CSRF token, and login attempts are rate-limited.
- Passwords are stored as scrypt hashes. New state is atomically written with
  restrictive permissions. The Xray-readable config is not world-readable.
- Unknown hosts and paths receive 404. The public site does not expose the
  portal. Access logs are disabled; logs shown in the portal are scrubbed.
- Private, local, cloud-metadata, BitTorrent and SMTP/25 outbound destinations
  are blocked by the generated Xray rules.
- Repository checks reject private keys, credential patterns, deployment files,
  home paths and non-example server addresses. Only documentation domains and
  synthetic device data belong in tests.

See [SECURITY.md](SECURITY.md). Protect release tags and the GitHub account;
a checksum obtained from a compromised release publisher is not an independent
trust anchor.

## Source checks

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q src
bash -n install.sh scripts/*.sh scripts/mtproxy-run
bash scripts/check-repository.sh
```

Linux CI additionally validates generated Nginx/Xray configurations and the
update/rollback flow. Installation and service integration require Linux;
unit tests alone do not prove successful deployment on a real VPS.

## License

[MIT](LICENSE)
