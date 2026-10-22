# vpnctl

**English** · [简体中文](README.zh-CN.md) · [Русский](README.ru.md) · [فارسی](README.fa.md)

Your own proxy on a fresh VPS: one command, a web panel, no manual config editing.
Open source, no analytics. Credentials are generated on your server.

> **Branch preview:** this setup is not released yet. The install command below
> becomes available when the next release is published.

## Install

You need a **fresh Ubuntu 22.04 or 24.04 VPS** with public IPv4, x86_64 or arm64,
512 MiB RAM and 2 GiB free disk space. The installer configures Nginx, UFW and
systemd; use a server without other services.

Connect to the VPS using SSH and paste:

```bash
curl -fsSL https://github.com/MolodoyArtist/asterisk/releases/latest/download/install.sh | sudo bash
```

Answer whether you already have a domain. Save the panel URL, login, password,
proxy link and QR code printed at the end.

## Connect

**No domain:** sign in at `https://SERVER_IP:9443`, open **Devices** and import
the VLESS + REALITY + Vision link or QR into a compatible client.

**With a domain:** sign in at `https://YOUR_DOMAIN:9443` and open **Devices**:

| Profile | Client | Import |
| --- | --- | --- |
| VLESS + XHTTP + TLS | Xray-based client, e.g. v2RayTun | Link, QR or Xray JSON |
| Hysteria 2 | sing-box 1.12+ | JSON file |

XHTTP JSON provides a local SOCKS proxy; a graphical client manages its tunnel.
Stock sing-box does not support this XHTTP profile. Add a device for each phone
or computer; deleting it revokes access.

## Add a domain later

1. Point the domain's **A record** to your VPS IP. In Cloudflare, choose **DNS only**.
   Add AAAA only if public IPv6 works on the VPS.
2. In the panel: **Domain → Check DNS → Activate XHTTP and Hysteria**.
3. REALITY stops working. Disconnect it, sign in at `https://YOUR_DOMAIN:9443`
   and download the new profiles from **Devices**.

Nginx serves a cover website and forwards a randomly generated XHTTP path to
Xray at `127.0.0.1:5555`. Hysteria receives QUIC directly. Certificates renew
automatically. A domain does not guarantee protection against DPI or IP blocking.

## Optional Telegram proxy

After domain activation: **Telegram → Enable Telegram proxy**. Open its link in
Telegram. This uses **mtg + FakeTLS** with your website as cover, for messaging
and media. Call traffic may still need a VPN.

## Ports

Allow these in the provider's firewall. vpnctl manages the server's UFW rules.

| Port | Purpose |
| --- | --- |
| Your SSH port | Server access |
| 80/TCP | Certificate validation |
| 443/TCP | REALITY, then Nginx + XHTTP after domain activation |
| 9443/TCP | Web panel |
| 443/UDP | Hysteria, after domain activation |
| 8443/TCP | Telegram, only when enabled |

**5555 stays local.** The cover site has no route to the panel.

## Updates and help

Run the same install command to update to the latest published release. Changes
are validated; failures trigger an attempted rollback. Older installs keep their
links until you activate the new domain setup. Disable old Telegram/padding
profiles before upgrading.

```bash
sudo vpnctl doctor                 # Check services and certificates
sudo vpnctl admin reset-password   # Reset the panel password
```

If the panel is unreachable, check the provider's firewall and DNS first.
Delete `/root/vpnctl-install.json` after safely saving your initial credentials.
Never publish exported JSON, proxy links or server logs.

CI checks Ubuntu 22.04/24.04, configs, FakeTLS cover, updates and rollback.
A full installation on a separate clean VPS has not yet been verified.

[Security](SECURITY.md) · [MIT license](LICENSE)
