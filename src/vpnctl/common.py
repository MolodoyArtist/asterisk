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

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


class ValidationError(ValueError):
    pass


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


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
    return value


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValidationError("Enter a valid public IP address.") from exc


def atomic_write(path: Path, data: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n", mode)


def load_state() -> dict[str, Any]:
    state = read_json(STATE_FILE)
    validate_state(state)
    return state


def validate_state(state: dict[str, Any]) -> None:
    if state.get("schema") != 1:
        raise ValidationError("Unsupported state schema.")
    public_ip = validate_ip(str(state.get("public_ip", "")))
    if ":" in public_ip:
        raise ValidationError("The primary public address must be IPv4.")
    if state.get("public_ipv6"):
        public_ipv6 = validate_ip(str(state["public_ipv6"]))
        if ":" not in public_ipv6:
            raise ValidationError("The optional public IPv6 address is invalid.")
    if state.get("domain"):
        validate_domain(str(state["domain"]))
    path = str(state.get("xhttp_path", ""))
    if not re.fullmatch(r"[A-Za-z0-9_-]{24,64}", path):
        raise ValidationError("The transport path is invalid.")
    clients = state.get("clients")
    if not isinstance(clients, list) or not clients or len(clients) > 1000:
        raise ValidationError("State must contain between 1 and 1000 clients.")
    names: set[str] = set()
    identifiers: set[str] = set()
    for client in clients:
        if not isinstance(client, dict):
            raise ValidationError("A client record is invalid.")
        name = validate_name(str(client.get("name", "")))
        try:
            identifier = str(uuid.UUID(str(client.get("id", ""))))
        except ValueError as exc:
            raise ValidationError("A client identifier is invalid.") from exc
        if name.casefold() in names or identifier in identifiers:
            raise ValidationError("Client names and identifiers must be unique.")
        names.add(name.casefold())
        identifiers.add(identifier)


def hash_password(password: str, salt: bytes | None = None) -> dict[str, Any]:
    if len(password) < 16:
        raise ValidationError("Password must contain at least 16 characters.")
    salt = salt or secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)
    return {
        "algorithm": "scrypt",
        "n": 2**15,
        "r": 8,
        "p": 1,
        "salt": b64url(salt),
        "hash": b64url(key),
    }


def verify_password(password: str, record: dict[str, Any]) -> bool:
    try:
        key = hashlib.scrypt(
            password.encode(),
            salt=b64url_decode(record["salt"]),
            n=int(record["n"]),
            r=int(record["r"]),
            p=int(record["p"]),
            dklen=32,
            maxmem=64 * 1024 * 1024,
        )
        return hmac.compare_digest(key, b64url_decode(record["hash"]))
    except (KeyError, TypeError, ValueError):
        return False


def make_session(username: str, secret: str, ttl: int = 3600) -> tuple[str, str]:
    csrf = random_token(18)
    payload = {
        "user": username,
        "csrf": csrf,
        "exp": int(time.time()) + ttl,
        "nonce": random_token(12),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    body = b64url(raw)
    signature = b64url(hmac.new(b64url_decode(secret), body.encode(), hashlib.sha256).digest())
    return f"{body}.{signature}", csrf


def verify_session(token: str, secret: str) -> dict[str, Any] | None:
    try:
        body, signature = token.split(".", 1)
        expected = b64url(hmac.new(b64url_decode(secret), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(b64url_decode(body))
        if int(payload["exp"]) < int(time.time()):
            return None
        return payload
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def active_host(state: dict[str, Any], prefer_domain: bool = True) -> str:
    if prefer_domain and state.get("domain"):
        return str(state["domain"])
    return str(state["public_ip"])


def client_uri(state: dict[str, Any], client: dict[str, Any], prefer_domain: bool = True) -> str:
    host = active_host(state, prefer_domain)
    query: dict[str, str] = {
        "type": "xhttp",
        "security": "tls",
        "encryption": "none",
        "mode": "auto",
        "path": f"/{state['xhttp_path']}/",
        "fp": "firefox",
        "packetEncoding": "xudp",
    }
    if state.get("domain") and prefer_domain:
        query["sni"] = str(state["domain"])
        query["host"] = str(state["domain"])
    address = f"[{host}]" if ":" in host else host
    label = urllib.parse.quote(str(client["name"]), safe="")
    return f"vless://{client['id']}@{address}:443?{urllib.parse.urlencode(query)}#{label}"


def render_xray(state: dict[str, Any]) -> str:
    clients = [
        {"id": item["id"], "email": item["name"]}
        for item in state.get("clients", [])
        if item.get("enabled", True)
    ]
    config = {
        "log": {"loglevel": "warning", "access": "none", "error": "none"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 5555,
                "protocol": "vless",
                "settings": {"clients": clients, "decryption": "none"},
                "streamSettings": {
                    "network": "xhttp",
                    "security": "none",
                    "xhttpSettings": {"path": f"/{state['xhttp_path']}/", "mode": "auto"},
                },
                "sniffing": {"enabled": False},
            }
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "blocked"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "ip": ["geoip:private", "169.254.169.254/32", "fe80::/10"],
                    "outboundTag": "blocked",
                },
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
                {"type": "field", "port": "25", "network": "tcp", "outboundTag": "blocked"},
            ],
        },
    }
    return json.dumps(config, indent=2, sort_keys=True) + "\n"


def _cert_paths(name: str) -> tuple[str, str]:
    base = f"/etc/letsencrypt/live/{name}"
    return f"{base}/fullchain.pem", f"{base}/privkey.pem"


def _https_application_server(server_name: str, cert_name: str, default: bool, state: dict[str, Any]) -> str:
    cert, key = _cert_paths(cert_name)
    default_flag = " default_server" if default else ""
    path = state["xhttp_path"]
    host_guard = f'    if ($host != "{server_name}") {{ return 404; }}\n' if default else ""
    return f"""
server {{
    listen 443 ssl http2{default_flag};
    listen [::]:443 ssl http2{default_flag};
    server_name {server_name};
    server_tokens off;
    access_log off;
    error_log /dev/null crit;

    ssl_certificate {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:VPNCTL_SSL:10m;
    ssl_session_timeout 1h;

{host_guard}

    location ^~ /{path}/ {{
        client_max_body_size 0;
        proxy_pass http://127.0.0.1:5555;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 360s;
        proxy_send_timeout 360s;
        proxy_connect_timeout 10s;
        proxy_intercept_errors on;
        error_page 400 404 405 =404 @vpnctl_not_found;
    }}

    location @vpnctl_not_found {{ return 404; }}

    location = /login {{
        client_max_body_size 16k;
        limit_req zone=vpnctl_login burst=5 nodelay;
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_hide_header Server;
    }}

    location / {{
        client_max_body_size 16k;
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_hide_header Server;
        proxy_connect_timeout 5s;
        proxy_read_timeout 240s;
        proxy_send_timeout 240s;
        proxy_intercept_errors on;
        error_page 404 = @vpnctl_not_found;
    }}
}}
"""


def _http_identity_server(name: str) -> str:
    return f"""
server {{
    listen 80;
    listen [::]:80;
    server_name {name};
    access_log off;
    location ^~ /.well-known/acme-challenge/ {{ root /var/www/vpnctl-acme; }}
    location / {{ return 301 https://{name}$request_uri; }}
}}
"""


def render_nginx(state: dict[str, Any]) -> str:
    blocks = [
        """# Generated by vpnctl. Manual edits are overwritten.
limit_req_zone $binary_remote_addr zone=vpnctl_login:10m rate=5r/m;

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    access_log off;
    location ^~ /.well-known/acme-challenge/ { root /var/www/vpnctl-acme; }
    location / { return 404; }
}
"""
    ]
    ip_enabled = bool(state.get("ip_mode", False))
    domain = state.get("domain")
    if ip_enabled:
        ip = str(state["public_ip"])
        blocks.append(_http_identity_server(ip))
        blocks.append(_https_application_server(ip, ip, True, state))
    elif domain:
        blocks.append(
            f"""
server {{
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;
    ssl_certificate {DEFAULT_CERT};
    ssl_certificate_key {DEFAULT_KEY};
    access_log off;
    return 404;
}}
"""
        )
    if domain:
        blocks.append(_http_identity_server(str(domain)))
        # The catch-all TLS server above owns default_server once IP mode is off.
        blocks.append(_https_application_server(str(domain), str(domain), False, state))
    return "\n".join(blocks)


IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b")
URI_SECRET_RE = re.compile(r"vless://[^\s<]+", re.IGNORECASE)


def redact_log(text: str) -> str:
    text = URI_SECRET_RE.sub("[REDACTED_URI]", text)
    text = UUID_RE.sub("[REDACTED_UUID]", text)
    text = IPV4_RE.sub("[REDACTED_IP]", text)
    text = IPV6_RE.sub("[REDACTED_IP]", text)
    return text


def h(value: Any) -> str:
    return html.escape(str(value), quote=True)
