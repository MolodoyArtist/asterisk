from __future__ import annotations

import base64
import binascii
import hashlib
import http.cookies
import os
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .common import (
    AUTH_FILE,
    h,
    make_session,
    read_json,
    verify_password,
    verify_session,
)
from .rpc import RPCError, call

LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)
LOGIN_LOCK = threading.Lock()
LOGIN_HASH_SLOTS = threading.BoundedSemaphore(2)
MAX_FORM_BYTES = 16_384


class InvalidRequestBody(ValueError):
    pass


class RequestBodyTooLarge(ValueError):
    pass


CSS = """
:root{color-scheme:dark;--bg:#0d1117;--card:#161b22;--line:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#2f81f7;--bad:#f85149;--ok:#3fb950}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}main{max-width:980px;margin:5vh auto;padding:20px}.login{max-width:390px;margin:15vh auto}section,.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:14px 0}nav{display:flex;gap:16px;align-items:center;flex-wrap:wrap}nav a{color:var(--text)}nav .grow{flex:1}h1,h2{line-height:1.2}label{display:block;margin:12px 0 5px}input,button{font:inherit;border-radius:7px;border:1px solid var(--line);padding:10px 12px}input{width:100%;background:#0d1117;color:var(--text)}button,.button{background:var(--accent);color:white;border:0;cursor:pointer;text-decoration:none;display:inline-block;padding:10px 14px;border-radius:7px}.danger{background:var(--bad)}.muted{color:var(--muted)}.ok{color:var(--ok)}.bad{color:var(--bad)}code,pre{background:#0d1117;border:1px solid var(--line);border-radius:6px}code{padding:2px 5px}pre{padding:12px;white-space:pre-wrap;overflow-wrap:anywhere}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}.metric{font-size:1.4rem}.notice{border-left:4px solid var(--accent)}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid var(--line);padding:10px 6px;vertical-align:top}.inline{display:inline}.inline button{padding:6px 9px}img.qr{max-width:260px;background:white;padding:8px}
"""


def layout(title: str, body: str, authenticated: bool = True, csrf: str | None = None) -> str:
    nav = ""
    if authenticated:
        logout = f'<form class="inline" method="post" action="/logout"><input type="hidden" name="csrf" value="{h(csrf or "")}"><button>Sign out</button></form>' if csrf else ""
        nav = f"""<nav><a href="/">Overview</a><a href="/clients">Devices</a><a href="/domain">Domain</a><a href="/telegram">Telegram</a><a href="/logs">Logs</a><span class="grow"></span>{logout}</nav>"""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>{h(title)}</title><style>{CSS}</style></head><body><main>{nav}{body}</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Account"
    sys_version = ""

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def auth(self) -> dict[str, Any] | None:
        try:
            auth = read_json(AUTH_FILE)
            cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            token = cookie.get("__Host-session")
            if not token:
                return None
            session = verify_session(token.value, auth["session_secret"])
            if not session or session.get("user") != auth.get("username"):
                return None
            return session
        except (OSError, KeyError, TypeError, ValueError, http.cookies.CookieError):
            return None

    def body(self) -> dict[str, str]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise InvalidRequestBody from exc
        if length < 0:
            raise InvalidRequestBody
        if length > MAX_FORM_BYTES:
            self.close_connection = True
            raise RequestBodyTooLarge
        parsed = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
        return {key: values[-1] for key, values in parsed.items()}

    def send_html(self, body: str, status: int = 200, headers: dict[str, str] | None = None) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, target: str, cookie: str | None = None) -> None:
        self.send_response(303)
        self.send_header("Location", target)
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def csrf(self, session: dict[str, Any], fields: dict[str, str]) -> bool:
        return bool(fields.get("csrf")) and fields["csrf"] == session.get("csrf")

    def require_auth(self) -> dict[str, Any] | None:
        session = self.auth()
        if not session:
            self.redirect("/")
        return session

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        session = self.auth()
        if not session:
            if parsed.path == "/":
                self.login_page()
            else:
                self.send_error(404)
            return
        try:
            if parsed.path == "/":
                self.dashboard(session)
            elif parsed.path == "/clients":
                self.clients(session)
            elif parsed.path == "/domain":
                self.domain(session)
            elif parsed.path == "/telegram":
                self.telegram(session)
            elif parsed.path == "/logs":
                self.logs(session)
            elif parsed.path == "/qr":
                name = urllib.parse.parse_qs(parsed.query).get("name", [""])[0]
                profile = urllib.parse.parse_qs(parsed.query).get("profile", ["reality"])[0]
                self.qr(name, profile)
            elif parsed.path == "/telegram/qr":
                self.telegram_qr()
            else:
                self.send_error(404)
        except RPCError as exc:
            self.send_html(layout("Error", f"<section><h1>Operation failed</h1><p>{h(exc)}</p><p><a href=\"/\">Return</a></p></section>"), 400)
        except (KeyError, TypeError, ValueError):
            self.send_html(layout("Error", "<section><h1>Temporarily unavailable</h1><p>Reload the page and try again.</p></section>"), 502)

    def do_POST(self) -> None:
        try:
            fields = self.body()
        except RequestBodyTooLarge:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        except InvalidRequestBody:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        if self.path == "/login":
            self.login(fields)
            return
        known_paths = {
            "/logout",
            "/clients/add",
            "/clients/delete",
            "/domain/check",
            "/domain/add",
            "/certificates/renew",
            "/telegram/enable",
            "/telegram/disable",
            "/telegram/rotate",
        }
        if self.path not in known_paths:
            self.send_error(404)
            return
        session = self.require_auth()
        if not session:
            return
        if not self.csrf(session, fields):
            self.send_html(layout("Error", "<section><h1>Request expired</h1><p>Reload the page and try again.</p></section>"), 403)
            return
        try:
            if self.path == "/logout":
                self.redirect("/", "__Host-session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict")
                return
            routes = {
                "/clients/add": ("client_add", {"name": fields.get("name", "")}, "/clients"),
                "/clients/delete": ("client_delete", {"name": fields.get("name", "")}, "/clients"),
                "/domain/check": ("domain_check", {"domain": fields.get("domain", "")}, "/domain?checked=1"),
                "/domain/add": ("domain_add", {"domain": fields.get("domain", "")}, "/domain?added=1"),
                "/certificates/renew": ("certificate_renew", {}, "/?renewed=1"),
                "/telegram/enable": ("telegram_enable", {}, "/telegram?enabled=1"),
                "/telegram/disable": ("telegram_disable", {}, "/telegram?disabled=1"),
                "/telegram/rotate": ("telegram_rotate", {}, "/telegram?rotated=1"),
            }
            action, payload, target = routes[self.path]
            call(action, payload)
            if fields.get("domain"):
                target += "&domain=" + urllib.parse.quote(fields["domain"])
            self.redirect(target)
        except RPCError as exc:
            back = "/domain" if self.path.startswith("/domain/") else "/telegram" if self.path.startswith("/telegram/") else "/clients" if self.path.startswith("/clients/") else "/"
            self.send_html(layout("Error", f"<section><h1>Could not complete that step</h1><p>{h(exc)}</p><p><a href=\"{back}\">Go back</a></p></section>"), 400)
        except (KeyError, TypeError, ValueError):
            self.send_html(layout("Error", "<section><h1>Control service returned invalid data</h1><p>Reload the page and try again.</p></section>"), 502)

    def login_page(self, error: str = "") -> None:
        message = f'<p class="bad">{h(error)}</p>' if error else ""
        page = f"""<div class="login"><section><h1>Sign in</h1>{message}<form method="post" action="/login"><label for="username">Login</label><input id="username" name="username" autocomplete="username" required autofocus><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><p><button type="submit">Continue</button></p></form></section></div>"""
        self.send_html(layout("Sign in", page, False), 401 if error else 200)

    def login(self, fields: dict[str, str]) -> None:
        # Keep only a one-way bucket identifier in memory; no client address is logged.
        source = self.headers.get("X-Real-IP", self.client_address[0])
        key = hashlib.sha256(source.encode()).hexdigest()
        now = time.monotonic()
        with LOGIN_LOCK:
            if len(LOGIN_ATTEMPTS) > 4096:
                for bucket, entries in list(LOGIN_ATTEMPTS.items()):
                    while entries and entries[0] < now - 900:
                        entries.popleft()
                    if not entries:
                        LOGIN_ATTEMPTS.pop(bucket, None)
                while len(LOGIN_ATTEMPTS) > 4096:
                    LOGIN_ATTEMPTS.pop(next(iter(LOGIN_ATTEMPTS)))
            attempts = LOGIN_ATTEMPTS[key]
            while attempts and attempts[0] < now - 900:
                attempts.popleft()
            limited = len(attempts) >= 8
            if not limited:
                attempts.append(now)
        if limited:
            self.login_page("Please wait before trying again.")
            return
        if not LOGIN_HASH_SLOTS.acquire(blocking=False):
            self.login_page("Please wait before trying again.")
            return
        try:
            auth = read_json(AUTH_FILE)
            good_user = fields.get("username", "") == auth["username"]
            good_password = verify_password(fields.get("password", ""), auth["password"])
        except (OSError, KeyError, TypeError, ValueError):
            self.send_html(layout("Unavailable", "<section><h1>Temporarily unavailable</h1><p>Try again in a moment.</p></section>", False), 503)
            return
        finally:
            LOGIN_HASH_SLOTS.release()
        if not (good_user and good_password):
            with LOGIN_LOCK:
                attempt_count = len(LOGIN_ATTEMPTS[key])
            time.sleep(min(2.0, 0.25 * attempt_count))
            self.login_page("Login or password is incorrect.")
            return
        with LOGIN_LOCK:
            LOGIN_ATTEMPTS.pop(key, None)
        token, _ = make_session(auth["username"], auth["session_secret"])
        self.redirect("/", f"__Host-session={token}; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Strict")

    def dashboard(self, session: dict[str, Any]) -> None:
        status = call("status")
        metrics = status["metrics"]
        services = status["services"]
        healthy = all(services.values())
        memory_used = metrics["memory_total"] - metrics["memory_available"]
        domain_card = ""
        if not status.get("domain"):
            domain_card = '<section class="notice"><h2>Add an optional domain profile</h2><p>A domain enables the additional VLESS + XHTTP + TLS profile. The recommended REALITY profile already works without one.</p><a class="button" href="/domain">Add a domain</a></section>'
        certs = "".join(f"<li>{h(c['name'])}: {h(c.get('days_remaining', '?'))} days remaining</li>" for c in status["certificates"])
        body = f"""<h1>Overview</h1>{domain_card}<h2>System</h2><div class="grid"><section><div class="muted">Services</div><div class="metric {'ok' if healthy else 'bad'}">{'Online' if healthy else 'Needs attention'}</div></section><section><div class="muted">Devices</div><div class="metric">{status['client_count']}</div></section><section><div class="muted">Connections</div><div class="metric">{metrics['connections']}</div></section><section><div class="muted">Load</div><div class="metric">{metrics['load'][0]}</div></section><section><div class="muted">Memory</div><div class="metric">{memory_used // 1048576} / {metrics['memory_total'] // 1048576} MiB</div></section><section><div class="muted">Disk free</div><div class="metric">{metrics['disk_free'] // 1073741824} GiB</div></section></div><section><h2>Certificates</h2><ul>{certs}</ul><form method="post" action="/certificates/renew"><input type="hidden" name="csrf" value="{h(session['csrf'])}"><button>Check renewal now</button></form></section>"""
        self.send_html(layout("Overview", body, csrf=session["csrf"]))

    def clients(self, session: dict[str, Any]) -> None:
        rows = []
        for item in call("clients")["clients"]:
            if item.get("enabled"):
                uri = ""
                if item.get("reality_uri"):
                    uri += f"<div class=\"muted\">Recommended: VLESS + REALITY + Vision</div><pre>{h(item['reality_uri'])}</pre>"
                if item.get("xhttp_uri"):
                    uri += f"<div class=\"muted\">VLESS + XHTTP + TLS</div><pre>{h(item['xhttp_uri'])}</pre>"
            else:
                uri = "Disabled"
            qr = ""
            if item.get("enabled") and item.get("reality_uri"):
                qr += f'<p><a href="/qr?name={urllib.parse.quote(item["name"])}&amp;profile=reality">Show REALITY QR code</a></p>'
            if item.get("enabled") and item.get("xhttp_uri"):
                qr += f'<p><a href="/qr?name={urllib.parse.quote(item["name"])}&amp;profile=xhttp">Show XHTTP QR code</a></p>'
            rows.append(f"<tr><td>{h(item['name'])}</td><td>{uri}{qr}</td><td><form class=\"inline\" method=\"post\" action=\"/clients/delete\"><input type=\"hidden\" name=\"csrf\" value=\"{h(session['csrf'])}\"><input type=\"hidden\" name=\"name\" value=\"{h(item['name'])}\"><button class=\"danger\">Delete</button></form></td></tr>")
        body = f"""<h1>Devices</h1><section><p>Import the VLESS link into v2RayTun from the clipboard, or open its QR code and scan it in the app.</p><form method="post" action="/clients/add"><input type="hidden" name="csrf" value="{h(session['csrf'])}"><label for="name">Device name</label><input id="name" name="name" maxlength="32" pattern="[A-Za-z0-9_.-]+" required><p><button>Add device</button></p></form></section><section><table><thead><tr><th>Name</th><th>v2RayTun import link</th><th></th></tr></thead><tbody>{''.join(rows)}</tbody></table></section>"""
        self.send_html(layout("Devices", body, csrf=session["csrf"]))

    def domain(self, session: dict[str, Any]) -> None:
        status = call("status")
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        value = query.get("domain", [status.get("domain") or ""])[0]
        banner = ""
        if "checked" in query:
            banner = '<section class="ok">DNS is ready. You can issue the certificate now.</section>'
        elif "added" in query:
            banner = '<section class="ok">Domain profile is active. Import the XHTTP + TLS link from Devices and test it.</section>'
        if status.get("domain"):
            domain_form = f"""<section><h2>Active domain</h2><p><code>{h(status['domain'])}</code> is configured. The VLESS + XHTTP + TLS profile is now available on the Devices page. Certificate renewal is automatic.</p></section>"""
        else:
            ipv6_help = f" If you use IPv6, create an AAAA record with <code>{h(status['public_ipv6'])}</code>." if status.get("public_ipv6") else " Do not create an AAAA record because this VPS has no detected public IPv6."
            activate_form = ""
            if "checked" in query and value:
                activate_form = f"""<form method="post" action="/domain/add"><input type="hidden" name="csrf" value="{h(session['csrf'])}"><input type="hidden" name="domain" value="{h(value)}"><button>Issue certificate and activate</button></form>"""
            domain_form = f"""<section><h2>1. Register a hostname</h2><p>The quickest free option is <a href="https://www.noip.com/personal" rel="noreferrer">No-IP</a>. Its free hostnames must be confirmed every 30 days.</p><h2>2. Point it to this server</h2><p>Create an A record whose value is <code>{h(status['public_ip'])}</code>.{ipv6_help}</p><h2>3. Check DNS and activate</h2><form method="post" action="/domain/check"><input type="hidden" name="csrf" value="{h(session['csrf'])}"><label for="domain">Hostname</label><input id="domain" name="domain" value="{h(value)}" placeholder="access.example.com" required><p><button>Check DNS</button></p></form>{activate_form}</section>"""
        self.send_html(layout("Domain", f"<h1>Domain setup</h1>{banner}{domain_form}", csrf=session["csrf"]))

    def telegram(self, session: dict[str, Any]) -> None:
        status = call("telegram_status")
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        banner = ""
        if "enabled" in query:
            banner = '<section class="ok">Telegram proxy is ready. Open the link in Telegram or scan its QR code.</section>'
        elif "rotated" in query:
            banner = '<section class="ok">A new Telegram link is ready. The old link no longer works.</section>'
        elif "disabled" in query:
            banner = '<section class="ok">Telegram proxy is disabled. Its port is no longer listening.</section>'
        if not status["enabled"]:
            body = f"""<h1>Telegram proxy</h1>{banner}<section><h2>Optional MTProto profile</h2><p>This is for Telegram only. It is separate from your VLESS profiles and uses TCP port 8444, so it does not change REALITY, XHTTP, Nginx or port 443.</p><p class="muted">Enabling it downloads and builds the checksum-verified official Telegram MTProxy source. It uses a separate connection secret and random padding.</p><form method="post" action="/telegram/enable"><input type="hidden" name="csrf" value="{h(session['csrf'])}"><button>Enable Telegram proxy</button></form></section>"""
        else:
            uri = status["uri"]
            service_state = "Online" if status.get("active") else "Needs attention"
            state_class = "ok" if status.get("active") else "bad"
            body = f"""<h1>Telegram proxy</h1>{banner}<section><p class="{state_class}">{service_state} on TCP port {h(status['port'])}</p><p>Open this private link on a device with Telegram, or scan its QR code from Telegram's proxy settings.</p><pre>{h(uri)}</pre><p><a class="button" href="/telegram/qr">Show Telegram QR code</a></p><p class="muted">Anyone with this link can use this Telegram-only proxy. Rotate it if it is shared accidentally.</p><form class="inline" method="post" action="/telegram/rotate"><input type="hidden" name="csrf" value="{h(session['csrf'])}"><button>Rotate link</button></form> <form class="inline" method="post" action="/telegram/disable"><input type="hidden" name="csrf" value="{h(session['csrf'])}"><button class="danger">Disable</button></form></section>"""
        self.send_html(layout("Telegram", body, csrf=session["csrf"]))

    def logs(self, session: dict[str, Any]) -> None:
        text = call("logs")["text"]
        self.send_html(layout("Logs", f"<h1>Sanitized logs</h1><section><p class=\"muted\">Recent service events only. Addresses, device identifiers and import links are redacted.</p><pre>{h(text)}</pre></section>", csrf=session["csrf"]))

    def qr(self, name: str, profile: str) -> None:
        try:
            if profile not in {"reality", "xhttp"}:
                raise RPCError("Unknown profile.")
            raw = base64.b64decode(call("client_qr", {"name": name, "profile": profile})["png"], validate=True)
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise RPCError("Control service returned an invalid QR code.") from exc
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def telegram_qr(self) -> None:
        try:
            raw = base64.b64decode(call("telegram_qr")["png"], validate=True)
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise RPCError("Control service returned an invalid QR code.") from exc
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)


def main() -> None:
    address = os.environ.get("VPNCTL_WEB_ADDRESS", "127.0.0.1")
    port = int(os.environ.get("VPNCTL_WEB_PORT", "8787"))
    ThreadingHTTPServer((address, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
