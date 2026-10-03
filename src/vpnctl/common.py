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
PANEL_PORT = 8443
MTPROXY_PORT = 8444

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
    if state.get("schema") != 2:
        raise ValidationError("Unsupported state schema.")
    if ":" in validate_ip(str(state.get("public_ip", ""))):
        raise ValidationError("The primary public address must be IPv4.")
    if state.get("public_ipv6") and ":" not in validate_ip(str(state["public_ipv6"])):
        raise ValidationError("The optional public IPv6 address is invalid.")
    if state.get("domain") is not None and validate_domain(str(state["domain"])) != state["domain"]:
        raise ValidationError("The domain name must use its canonical form.")
    layout = state.get("layout", "reality-primary")
    if layout not in {"reality-primary", "legacy-xhttp-primary"}:
        raise ValidationError("The network layout is invalid.")
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
        names.add(name.casefold())
        ids.add(identifier)
    telegram = state.get("telegram")
    if telegram is not None:
        if not isinstance(telegram, dict) or not isinstance(telegram.get("enabled"), bool):
            raise ValidationError("Telegram proxy settings are invalid.")
        if telegram["enabled"]:
            port = telegram.get("port")
            secret = telegram.get("secret")
            if not isinstance(port, int) or not 1024 <= port <= 65535 or port in {443, PANEL_PORT}:
                raise ValidationError("Telegram proxy port is invalid.")
            if not isinstance(secret, str) or not re.fullmatch(r"[0-9a-f]{32}", secret):
                raise ValidationError("Telegram proxy secret is invalid.")


def telegram_uri(state: dict[str, Any]) -> str:
    telegram = state.get("telegram")
    if not isinstance(telegram, dict) or not telegram.get("enabled"):
        raise ValidationError("Telegram proxy is not enabled.")
    # `dd` asks Telegram clients to use MTProxy random padding. The server keeps
    # the underlying 16-byte secret, as required by the official implementation.
    return "tg://proxy?" + urllib.parse.urlencode({"server": state["public_ip"], "port": telegram["port"], "secret": "dd" + telegram["secret"]})


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
    xhttp_port = PANEL_PORT if state.get("layout", "reality-primary") == "reality-primary" else 443
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
    config = {"log": {"loglevel": "warning", "access": "none", "error": "none"}, "inbounds": inbounds, "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "blocked"}], "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "ip": ["geoip:private", "169.254.169.254/32", "fe80::/10"], "outboundTag": "blocked"}, {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"}, {"type": "field", "port": "25", "network": "tcp", "outboundTag": "blocked"}]}}
    return json.dumps(config, indent=2, sort_keys=True) + "\n"


def _application_server(name: str, cert_name: str, default: bool, state: dict[str, Any], with_xhttp: bool) -> str:
    port = PANEL_PORT if state.get("layout", "reality-primary") == "reality-primary" else 443
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
    return f'''server {{
    listen {port} ssl http2{flag};
    listen [::]:{port} ssl http2{flag};
    server_name {name};
    server_tokens off;
    access_log off;
    error_log /dev/null crit;
    ssl_certificate /etc/letsencrypt/live/{cert_name}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{cert_name}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
{guard}{xhttp}    location = /login {{
        client_max_body_size 16k;
        limit_req zone=vpnctl_login burst=5 nodelay;
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 900s;
        proxy_send_timeout 900s;
    }}
    location / {{
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
    }}
    location @not_found {{ return 404; }}
}}
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
    if state.get("domain"):
        blocks.append(_reject_server(443 if legacy else PANEL_PORT))
    else:
        blocks.append(_application_server(str(state["public_ip"]), str(state["public_ip"]), True, state, legacy))
    if state.get("domain"):
        blocks.append(_application_server(str(state["domain"]), str(state["domain"]), False, state, True))
    return "\n".join(blocks)


IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b")
URI_SECRET_RE = re.compile(r"(?:vless|tg)://[^\s<]+", re.IGNORECASE)
MTPROXY_SECRET_RE = re.compile(r"\b(?:MTPROXY_SECRET|secret)=[0-9a-f]{32}\b", re.IGNORECASE)


def redact_log(text: str) -> str:
    return IPV6_RE.sub("[REDACTED_IP]", IPV4_RE.sub("[REDACTED_IP]", UUID_RE.sub("[REDACTED_UUID]", MTPROXY_SECRET_RE.sub("[REDACTED_SECRET]", URI_SECRET_RE.sub("[REDACTED_URI]", text)))))


def h(value: Any) -> str:
    return html.escape(str(value), quote=True)
