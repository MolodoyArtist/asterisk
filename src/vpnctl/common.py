from __future__ import annotations

import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

STATE_DIR = Path(os.environ.get("VPNCTL_STATE_DIR", "/var/lib/vpnctl"))
CONFIG_DIR = Path(os.environ.get("VPNCTL_CONFIG_DIR", "/etc/vpnctl"))
STATE_FILE = STATE_DIR / "state.json"
AUTH_FILE = STATE_DIR / "auth.json"
XRAY_CONFIG = CONFIG_DIR / "xray.json"
NGINX_SITE = Path(os.environ.get("VPNCTL_NGINX_SITE", "/etc/nginx/sites-available/vpnctl"))
DEFAULT_CERT = CONFIG_DIR / "tls" / "default.crt"
DEFAULT_KEY = CONFIG_DIR / "tls" / "default.key"
# Keeping this configurable makes the rendered configuration testable without
# creating anything under /etc. Production retains Certbot's standard path.
CERT_LIVE_DIR = Path(os.environ.get("VPNCTL_CERT_LIVE_DIR", "/etc/letsencrypt/live"))
PANEL_PORT = 9443
MTPROXY_PORT = 8443

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$", re.IGNORECASE)
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{24,64}")
SHORT_ID_RE = re.compile(r"[0-9a-f]{2,16}")


class ValidationError(ValueError):
    pass


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def random_token(length: int = 24) -> str:
    return b64url(secrets.token_bytes(length))


def validate_name(value: str) -> str:
    value = value.strip()
    if not NAME_RE.fullmatch(value):
        raise ValidationError("Use 1-32 letters, numbers, dots, dashes or underscores.")
    return value


def validate_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(value):
        raise ValidationError("Enter a valid fully-qualified domain name.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValidationError("Enter a hostname, not an IP address.")


def validate_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValidationError("Enter a valid public IP address.") from exc
    return str(address)


def atomic_write(path: Path, data: str, mode: int = 0o600, owner: tuple[int, int] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        if owner:
            os.fchown(fd, *owner)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValidationError("JSON state must be an object.")
    return value


def write_json(path: Path, value: dict[str, Any], mode: int = 0o600, owner: tuple[int, int] | None = None) -> None:
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n", mode, owner)


def load_state() -> dict[str, Any]:
    state = read_json(STATE_FILE)
    validate_state(state)
    return state


def validate_state(state: dict[str, Any]) -> None:
    if state.get("schema") not in {2, 3}:
        raise ValidationError("Unsupported state schema.")
    if ":" in validate_ip(str(state.get("public_ip", ""))):
        raise ValidationError("The primary public address must be IPv4.")
    if state.get("public_ipv6") and ":" not in validate_ip(str(state["public_ipv6"])):
        raise ValidationError("The optional public IPv6 address is invalid.")
    if state.get("domain") is not None and validate_domain(str(state["domain"])) != state["domain"]:
        raise ValidationError("The domain name must use its canonical form.")
    layout = state.get("layout", "reality-primary")
    if layout not in {"reality-primary", "domain-primary", "legacy-xhttp-primary"}:
        raise ValidationError("The network layout is invalid.")
    if layout == "domain-primary" and not state.get("domain"):
        raise ValidationError("A domain is required for the domain profile.")
    port = state.get("panel_port", PANEL_PORT)
    if type(port) is not int or port not in {8443, 9443}:
        raise ValidationError("The portal port is invalid.")
    if not TOKEN_RE.fullmatch(str(state.get("xhttp_path", ""))):
        raise ValidationError("The XHTTP path is invalid.")
    if layout == "reality-primary":
        reality = state.get("reality")
        if not isinstance(reality, dict):
            raise ValidationError("REALITY settings are missing.")
        target = validate_domain(str(reality.get("target", "")))
        if target != validate_domain(str(reality.get("server_name", ""))):
            raise ValidationError("REALITY target and SNI must match.")
        if not all(isinstance(reality.get(key), str) and reality[key] for key in ("private_key", "public_key")):
            raise ValidationError("REALITY keys are invalid.")
        if not SHORT_ID_RE.fullmatch(str(reality.get("short_id", ""))):
            raise ValidationError("REALITY short ID is invalid.")
    clients = state.get("clients")
    if not isinstance(clients, list) or not clients or len(clients) > 1000:
        raise ValidationError("State must contain between 1 and 1000 clients.")
    names, ids = set(), set()
    for item in clients:
        if not isinstance(item, dict):
            raise ValidationError("A client record is invalid.")
        name = validate_name(str(item.get("name", "")))
        try:
            identifier = str(uuid.UUID(str(item.get("id", ""))))
        except ValueError as exc:
            raise ValidationError("A client identifier is invalid.") from exc
        if not isinstance(item.get("enabled", True), bool) or name.casefold() in names or identifier in ids:
            raise ValidationError("Client records must be unique and valid.")
        if layout == "domain-primary" and not TOKEN_RE.fullmatch(str(item.get("hysteria_password", ""))):
            raise ValidationError("The Hysteria credential is invalid.")
        names.add(name.casefold())
        ids.add(identifier)
    telegram = state.get("telegram")
    if telegram is not None:
        if not isinstance(telegram, dict) or not isinstance(telegram.get("enabled"), bool):
            raise ValidationError("Telegram proxy settings are invalid.")
        if telegram["enabled"]:
            port = telegram.get("port")
            secret = telegram.get("secret")
            if not isinstance(port, int) or not 1024 <= port <= 65535 or port in {443, panel_port(state)}:
                raise ValidationError("Telegram proxy port is invalid.")
            if telegram.get("implementation") == "mtg" and (not state.get("domain") or port != MTPROXY_PORT):
                raise ValidationError("FakeTLS requires a domain and its dedicated port.")
            if not isinstance(secret, str) or not re.fullmatch(r"[0-9a-f]{32}", secret):
                raise ValidationError("Telegram proxy secret is invalid.")


def telegram_uri(state: dict[str, Any]) -> str:
    telegram = state.get("telegram")
    if not isinstance(telegram, dict) or not telegram.get("enabled"):
        raise ValidationError("Telegram proxy is not enabled.")
    if telegram.get("implementation") == "mtg":
        domain = validate_domain(str(state.get("domain", "")))
        secret = "ee" + telegram["secret"] + domain.encode("ascii").hex()
        server = domain
    else:
        secret, server = "dd" + telegram["secret"], state["public_ip"]
    return "tg://proxy?" + urllib.parse.urlencode({"server": server, "port": telegram["port"], "secret": secret})


def panel_port(state: dict[str, Any]) -> int:
    return int(state.get("panel_port", PANEL_PORT))


def domain_mode(state: dict[str, Any]) -> bool:
    return state.get("layout") == "domain-primary"


def hysteria_uri(state: dict[str, Any], client: dict[str, Any]) -> str:
    if not domain_mode(state) or not client.get("hysteria_password"):
        raise ValidationError("Activate the domain profiles first.")
    params = urllib.parse.urlencode({"sni": state["domain"], "alpn": "h3"})
    return f"hysteria2://{client['hysteria_password']}@{state['domain']}:443?{params}#{urllib.parse.quote(client['name'], safe='')}"


def client_config(state: dict[str, Any], client: dict[str, Any], profile: str) -> dict[str, Any]:
    if not domain_mode(state):
        raise ValidationError("JSON profiles become available after domain activation.")
    domain = state["domain"]
    if profile == "hysteria":
        return {
            "log": {"level": "warn"},
            "dns": {"servers": [{"type": "https", "tag": "dns-proxy", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "tls": {"enabled": True, "server_name": "cloudflare-dns.com"}, "detour": "proxy"}], "final": "dns-proxy"},
            "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"], "mtu": 1400, "auto_route": True}],
            "outbounds": [{"type": "hysteria2", "tag": "proxy", "server": state["public_ip"], "server_port": 443, "password": client["hysteria_password"], "tls": {"enabled": True, "server_name": domain, "alpn": ["h3"], "insecure": False}}],
            "route": {"rules": [{"port": 53, "action": "hijack-dns"}], "final": "proxy", "auto_detect_interface": True},
        }
    if profile == "xhttp":
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": domain, "port": 443, "users": [{"id": client["id"], "encryption": "none"}]}]}, "streamSettings": {"network": "xhttp", "security": "tls", "xhttpSettings": {"path": f"/{state['xhttp_path']}/", "host": domain, "mode": "auto"}, "tlsSettings": {"serverName": domain, "allowInsecure": False, "fingerprint": "firefox", "alpn": ["h2", "http/1.1"]}}}],
        }
    raise ValidationError("Unknown JSON profile.")



def hash_password(password: str, salt: bytes | None = None) -> dict[str, Any]:
    if len(password) < 16:
        raise ValidationError("Password must contain at least 16 characters.")
    salt = salt or secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)
    return {"algorithm": "scrypt", "n": 2**15, "r": 8, "p": 1, "salt": b64url(salt), "hash": b64url(key)}


def verify_password(password: str, record: dict[str, Any]) -> bool:
    try:
        key = hashlib.scrypt(password.encode(), salt=b64url_decode(record["salt"]), n=int(record["n"]), r=int(record["r"]), p=int(record["p"]), dklen=32, maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(key, b64url_decode(record["hash"]))
    except (KeyError, TypeError, ValueError):
        return False


def make_session(username: str, secret: str, ttl: int = 3600) -> tuple[str, str]:
    csrf = random_token(18)
    body = b64url(json.dumps({"user": username, "csrf": csrf, "exp": int(time.time()) + ttl, "nonce": random_token(12)}, separators=(",", ":"), sort_keys=True).encode())
    signature = b64url(hmac.new(b64url_decode(secret), body.encode(), hashlib.sha256).digest())
    return f"{body}.{signature}", csrf


def verify_session(token: str, secret: str) -> dict[str, Any] | None:
    try:
        body, signature = token.split(".", 1)
        expected = b64url(hmac.new(b64url_decode(secret), body.encode(), hashlib.sha256).digest())
        payload = json.loads(b64url_decode(body))
        if not hmac.compare_digest(signature, expected) or not isinstance(payload, dict) or int(payload["exp"]) <= int(time.time()):
            return None
        return payload if isinstance(payload.get("user"), str) and isinstance(payload.get("csrf"), str) else None
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def client_uri(state: dict[str, Any], client: dict[str, Any], profile: str = "reality") -> str:
    label = urllib.parse.quote(str(client["name"]), safe="")
    if profile == "reality":
        if state.get("layout", "reality-primary") != "reality-primary":
            raise ValidationError("This upgraded installation keeps its existing XHTTP profile unchanged.")
        reality = state["reality"]
        params = {"encryption": "none", "flow": "xtls-rprx-vision", "security": "reality", "sni": reality["server_name"], "fp": "chrome", "pbk": reality["public_key"], "sid": reality["short_id"], "type": "tcp", "headerType": "none"}
        return f"vless://{client['id']}@{state['public_ip']}:443?{urllib.parse.urlencode(params)}#{label}"
    domain = state.get("domain")
    legacy = state.get("layout", "reality-primary") == "legacy-xhttp-primary"
    if profile != "xhttp" or (not domain and not legacy):
        raise ValidationError("A domain is required for an XHTTP profile.")
    host = str(domain or state["public_ip"])
    params = {"type": "xhttp", "security": "tls", "encryption": "none", "mode": "auto", "path": f"/{state['xhttp_path']}/", "fp": "firefox", "packetEncoding": "xudp"}
    if domain:
        params.update({"sni": domain, "host": domain})
    xhttp_port = panel_port(state) if state.get("layout", "reality-primary") == "reality-primary" else 443
    return f"vless://{client['id']}@{host}:{xhttp_port}?{urllib.parse.urlencode(params)}#{label}"


def _clients(state: dict[str, Any], flow: str | None = None) -> list[dict[str, str]]:
    return [{"id": item["id"], "email": item["name"], **({"flow": flow} if flow else {})} for item in state["clients"] if item.get("enabled", True)]


def render_xray(state: dict[str, Any]) -> str:
    inbounds: list[dict[str, Any]] = []
    if state.get("layout", "reality-primary") == "reality-primary":
        reality = state["reality"]
        inbounds.append({"port": 443, "protocol": "vless", "settings": {"clients": _clients(state, "xtls-rprx-vision"), "decryption": "none"}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"show": False, "dest": f"{reality['target']}:443", "xver": 0, "serverNames": [reality["server_name"]], "privateKey": reality["private_key"], "shortIds": [reality["short_id"]]}}, "sniffing": {"enabled": False}})
    if state.get("domain") or state.get("layout", "reality-primary") == "legacy-xhttp-primary":
        inbounds.append({"listen": "127.0.0.1", "port": 5555, "protocol": "vless", "settings": {"clients": _clients(state), "decryption": "none"}, "streamSettings": {"network": "xhttp", "security": "none", "xhttpSettings": {"path": f"/{state['xhttp_path']}/", "mode": "auto"}}, "sniffing": {"enabled": False}})
    if domain_mode(state):
        domain = state["domain"]
        # Public QUIC ingress; access is authenticated by a per-device secret.
        inbounds.append({
            "listen": "0.0.0.0",  # nosec B104
            "port": 443,
            "tag": "hysteria",
            "protocol": "hysteria",
            "settings": {
                "version": 2,
                "clients": [{"auth": c["hysteria_password"], "email": c["name"]} for c in state["clients"] if c.get("enabled", True)],
            },
            "streamSettings": {
                "network": "hysteria",
                "security": "tls",
                "hysteriaSettings": {
                    "version": 2,
                    "udpIdleTimeout": 60,
                    "masquerade": {"type": "proxy", "url": f"https://{domain}/", "rewriteHost": True, "insecure": False},
                },
                "tlsSettings": {
                    "minVersion": "1.3", "maxVersion": "1.3", "alpn": ["h3"],
                    "certificates": [{"certificateFile": str(CONFIG_DIR / "tls/domain.crt"), "keyFile": str(CONFIG_DIR / "tls/domain.key"), "oneTimeLoading": False}],
                },
            },
        })
    config = {"log": {"loglevel": "warning", "access": "none", "error": "none"}, "inbounds": inbounds, "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "blocked"}], "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "ip": ["geoip:private", "169.254.169.254/32", "fe80::/10"], "outboundTag": "blocked"}, {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"}, {"type": "field", "port": "25", "network": "tcp", "outboundTag": "blocked"}]}}
    return json.dumps(config, indent=2, sort_keys=True) + "\n"


def _application_server(name: str, cert_name: str, default: bool, state: dict[str, Any], with_xhttp: bool, port_override: int | None = None, cover: bool = False) -> str:
    port = panel_port(state) if state.get("layout", "reality-primary") == "reality-primary" else 443
    if port_override is not None:
        port = port_override
    flag = " default_server" if default else ""
    guard = f'    if ($host != "{name}") {{ return 404; }}\n' if default else ""
    xhttp = ""
    if with_xhttp:
        xhttp = f'''    location ^~ /{state["xhttp_path"]}/ {{
        client_max_body_size 0;
        limit_conn vpnctl_xhttp_conn 32;
        proxy_pass http://127.0.0.1:5555;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 360s;
        proxy_send_timeout 360s;
        proxy_intercept_errors on;
        error_page 400 404 405 =404 @not_found;
    }}
'''
    routes = '''    location = /login {
        client_max_body_size 16k;
        limit_req zone=vpnctl_login burst=5 nodelay;
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 900s;
        proxy_send_timeout 900s;
    }
    location / {
        client_max_body_size 16k;
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 900s;
        proxy_send_timeout 900s;
        proxy_intercept_errors on;
        error_page 404 = @not_found;
    }
    location @not_found { return 404; }
'''
    if cover:
        routes = '''    location = / { default_type text/html; return 200 '<!doctype html><html lang="en"><title>Welcome</title><h1>Welcome</h1><p>This site is online.</p></html>'; }
    location / { return 404; }
    location @not_found { return 404; }
'''
    return f'''server {{
    listen {port} ssl http2{flag};
    listen [::]:{port} ssl http2{flag};
    server_name {name};
    server_tokens off;
    access_log off;
    error_log /dev/null crit;
    ssl_certificate {CERT_LIVE_DIR}/{cert_name}/fullchain.pem;
    ssl_certificate_key {CERT_LIVE_DIR}/{cert_name}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
{guard}{xhttp}{routes}}}
'''


def _reject_server(port: int) -> str:
    return f'''server {{
    listen {port} ssl http2 default_server;
    listen [::]:{port} ssl http2 default_server;
    server_name _;
    ssl_certificate {DEFAULT_CERT};
    ssl_certificate_key {DEFAULT_KEY};
    access_log off;
    return 404;
}}
'''


def render_nginx(state: dict[str, Any]) -> str:
    legacy = state.get("layout", "reality-primary") == "legacy-xhttp-primary"
    blocks = ["# Generated by vpnctl. Manual edits are overwritten.\nlimit_req_zone $binary_remote_addr zone=vpnctl_login:10m rate=5r/m;\nlimit_conn_zone $binary_remote_addr zone=vpnctl_xhttp_conn:10m;\n", '''server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    access_log off;
    location ^~ /.well-known/acme-challenge/ { root /var/www/vpnctl-acme; }
    location / { return 404; }
}
''']
    if domain_mode(state):
        domain = state["domain"]
        portal = panel_port(state)
        blocks.extend([_reject_server(443), _reject_server(portal)])
        blocks.append(_application_server(domain, domain, False, state, True, port_override=443, cover=True))
        blocks.append(_application_server(domain, domain, False, state, False, port_override=portal))
        return "\n".join(blocks)
    if state.get("domain"):
        blocks.append(_reject_server(443 if legacy else panel_port(state)))
    else:
        blocks.append(_application_server(str(state["public_ip"]), str(state["public_ip"]), True, state, legacy))
    if state.get("domain"):
        blocks.append(_application_server(str(state["domain"]), str(state["domain"]), False, state, True))
    return "\n".join(blocks)


IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b")
URI_SECRET_RE = re.compile(r"(?:vless|hysteria2?|hy2|tg)://[^\s<]+", re.IGNORECASE)
MTPROXY_SECRET_RE = re.compile(r"\b(?:MTPROXY_SECRET|secret)=[0-9a-f]{32}\b", re.IGNORECASE)


def redact_log(text: str) -> str:
    return IPV6_RE.sub("[REDACTED_IP]", IPV4_RE.sub("[REDACTED_IP]", UUID_RE.sub("[REDACTED_UUID]", MTPROXY_SECRET_RE.sub("[REDACTED_SECRET]", URI_SECRET_RE.sub("[REDACTED_URI]", text)))))


def h(value: Any) -> str:
    return html.escape(str(value), quote=True)
