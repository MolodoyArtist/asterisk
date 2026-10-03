from __future__ import annotations

import base64
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


CSS = """
:root{color-scheme:dark;--bg:#0d1117;--card:#161b22;--line:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#2f81f7;--bad:#f85149;--ok:#3fb950}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}main{max-width:980px;margin:5vh auto;padding:20px}.login{max-width:390px;margin:15vh auto}section,.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:14px 0}nav{display:flex;gap:16px;align-items:center;flex-wrap:wrap}nav a{color:var(--text)}nav .grow{flex:1}h1,h2{line-height:1.2}label{display:block;margin:12px 0 5px}input,button{font:inherit;border-radius:7px;border:1px solid var(--line);padding:10px 12px}input{width:100%;background:#0d1117;color:var(--text)}button,.button{background:var(--accent);color:white;border:0;cursor:pointer;text-decoration:none;display:inline-block;padding:10px 14px;border-radius:7px}.danger{background:var(--bad)}.muted{color:var(--muted)}.ok{color:var(--ok)}.bad{color:var(--bad)}code,pre{background:#0d1117;border:1px solid var(--line);border-radius:6px}code{padding:2px 5px}pre{padding:12px;white-space:pre-wrap;overflow-wrap:anywhere}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}.metric{font-size:1.4rem}.q{display:inline-grid;place-items:center;width:21px;height:21px;border:1px solid var(--line);border-radius:50%;text-decoration:none}.notice{border-left:4px solid var(--accent)}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid var(--line);padding:10px 6px;vertical-align:top}.inline{display:inline}.inline button{padding:6px 9px}img.qr{max-width:260px;background:white;padding:8px}
"""


def layout(title: str, body: str, authenticated: bool = True) -> str:
    nav = ""
    if authenticated:
        nav = """<nav><a href="/">Overview</a><a href="/clients">Devices</a><a href="/domain">Domain</a><a href="/logs">Logs</a><a href="/help">Help</a><span class="grow"></span><form class="inline" method="post" action="/logout"><button>Sign out</button></form></nav>"""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>{h(title)}</title><style>{CSS}</style></head><body><main>{nav}{body}</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Account"
    sys_version = ""

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def auth(self) -> dict[str, Any] | None:
        auth = read_json(AUTH_FILE)
        cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        token = cookie.get("__Host-session")
        if not token:
            return None
        return verify_session(token.value, auth["session_secret"])

    def body(self) -> dict[str, str]:
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 16384)
        except ValueError:
            length = 0
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
            elif parsed.path == "/logs":
                self.logs(session)
            elif parsed.path == "/help":
                self.help_page(session)
            elif parsed.path == "/qr":
                name = urllib.parse.parse_qs(parsed.query).get("name", [""])[0]
                self.qr(name)
            else:
                self.send_error(404)
        except RPCError as exc:
            self.send_html(layout("Error", f"<section><h1>Operation failed</h1><p>{h(exc)}</p><p><a href=\"/\">Return</a></p></section>"), 400)

    def do_POST(self) -> None:
        fields = self.body()
        if self.path == "/login":
            self.login(fields)
            return
        known_paths = {
            "/logout",
            "/clients/add",
            "/clients/delete",
            "/domain/check",
            "/domain/add",
            "/domain/disable-ip",
            "/certificates/renew",
        }
        if self.path not in known_paths:
            self.send_error(404)
            return
        session = self.require_auth()
        if not session:
            return
        if self.path == "/logout":
            self.redirect("/", "__Host-session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict")
            return
        if not self.csrf(session, fields):
            self.send_html(layout("Error", "<section><h1>Request expired</h1><p>Reload the page and try again.</p></section>"), 403)
            return
        try:
            routes = {
                "/clients/add": ("client_add", {"name": fields.get("name", "")}, "/clients"),
                "/clients/delete": ("client_delete", {"name": fields.get("name", "")}, "/clients"),
                "/domain/check": ("domain_check", {"domain": fields.get("domain", "")}, "/domain?checked=1"),
                "/domain/add": ("domain_add", {"domain": fields.get("domain", "")}, "/domain?added=1"),
                "/domain/disable-ip": ("ip_disable", {}, "/domain?disabled=1"),
                "/certificates/renew": ("certificate_renew", {}, "/?renewed=1"),
            }
            action, payload, target = routes[self.path]
            result = call(action, payload)
            if self.path == "/domain/disable-ip":
                domain_url = f"https://{result['domain']}/"
                body = f"""<section><h1>IP mode is disabled</h1><p>Use the domain from now on. Your browser will ask you to sign in once more because cookies are not transferred between an IP address and a domain.</p><p><a class="button" href="{h(domain_url)}">Open {h(result['domain'])}</a></p></section>"""
                self.send_html(layout("Migration complete", body))
                return
            if fields.get("domain"):
                target += "&domain=" + urllib.parse.quote(fields["domain"])
            self.redirect(target)
        except RPCError as exc:
            self.send_html(layout("Error", f"<section><h1>Could not complete that step</h1><p>{h(exc)}</p><p><a href=\"{h(self.headers.get('Referer', '/'))}\">Go back</a></p></section>"), 400)

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
        auth = read_json(AUTH_FILE)
        try:
            good_user = fields.get("username", "") == auth["username"]
            good_password = verify_password(fields.get("password", ""), auth["password"])
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
            domain_card = '<section class="notice"><h2>Finish secure setup</h2><p>Add a domain to use a conventional long-lived certificate and avoid relying on the temporary IP certificate.</p><a class="button" href="/domain">Add a domain</a> <a class="q" href="/help#domain">?</a></section>'
        certs = "".join(f"<li>{h(c['name'])}: {h(c.get('days_remaining', '?'))} days remaining</li>" for c in status["certificates"])
        body = f"""<h1>Overview</h1>{domain_card}<h2>System <a class="q" href="/help#metrics">?</a></h2><div class="grid"><section><div class="muted">Services</div><div class="metric {'ok' if healthy else 'bad'}">{'Online' if healthy else 'Needs attention'}</div></section><section><div class="muted">Devices</div><div class="metric">{status['client_count']}</div></section><section><div class="muted">Connections</div><div class="metric">{metrics['connections']}</div></section><section><div class="muted">Load</div><div class="metric">{metrics['load'][0]}</div></section><section><div class="muted">Memory</div><div class="metric">{memory_used // 1048576} / {metrics['memory_total'] // 1048576} MiB</div></section><section><div class="muted">Disk free</div><div class="metric">{metrics['disk_free'] // 1073741824} GiB</div></section></div><section><h2>Certificates <a class="q" href="/help#certificates">?</a></h2><ul>{certs}</ul><form method="post" action="/certificates/renew"><input type="hidden" name="csrf" value="{h(session['csrf'])}"><button>Check renewal now</button></form></section>"""
        self.send_html(layout("Overview", body))

    def clients(self, session: dict[str, Any]) -> None:
        rows = []
        for item in call("clients")["clients"]:
            if item.get("enabled"):
                uri = f"<div class=\"muted\">Preferred link</div><pre>{h(item['uri'])}</pre>"
                if item.get("ip_uri"):
                    uri += f"<div class=\"muted\">Temporary IP link</div><pre>{h(item['ip_uri'])}</pre>"
            else:
                uri = "Disabled"
            qr = f'<p><a href="/qr?name={urllib.parse.quote(item["name"])}">Show QR code</a></p>' if item.get("enabled") else ""
            rows.append(f"<tr><td>{h(item['name'])}</td><td>{uri}{qr}</td><td><form class=\"inline\" method=\"post\" action=\"/clients/delete\"><input type=\"hidden\" name=\"csrf\" value=\"{h(session['csrf'])}\"><input type=\"hidden\" name=\"name\" value=\"{h(item['name'])}\"><button class=\"danger\">Delete</button></form></td></tr>")
        body = f"""<h1>Devices <a class="q" href="/help#devices">?</a></h1><section><form method="post" action="/clients/add"><input type="hidden" name="csrf" value="{h(session['csrf'])}"><label for="name">Device name</label><input id="name" name="name" maxlength="32" pattern="[A-Za-z0-9_.-]+" required><p><button>Add device</button></p></form></section><section><table><thead><tr><th>Name</th><th>Import link</th><th></th></tr></thead><tbody>{''.join(rows)}</tbody></table></section>"""
        self.send_html(layout("Devices", body))

    def domain(self, session: dict[str, Any]) -> None:
        status = call("status")
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        value = query.get("domain", [status.get("domain") or ""])[0]
        banner = ""
        if "checked" in query:
            banner = '<section class="ok">DNS is ready. You can issue the certificate now.</section>'
        elif "added" in query:
            banner = '<section class="ok">Domain mode is active. Import the domain link from Devices, test it, then disable IP mode below.</section>'
        elif "disabled" in query:
            banner = '<section class="ok">IP mode and its automatic renewal are disabled.</section>'
        if status.get("domain"):
            domain_form = f"""<section><h2>Active domain</h2><p><code>{h(status['domain'])}</code> is configured. Certificate renewal is automatic.</p></section>"""
        else:
            ipv6_help = f" If you use IPv6, create an AAAA record with <code>{h(status['public_ipv6'])}</code>." if status.get("public_ipv6") else " Do not create an AAAA record because this VPS has no detected public IPv6."
            activate_form = ""
            if "checked" in query and value:
                activate_form = f"""<form method="post" action="/domain/add"><input type="hidden" name="csrf" value="{h(session['csrf'])}"><input type="hidden" name="domain" value="{h(value)}"><button>Issue certificate and activate</button></form>"""
            domain_form = f"""<section><h2>1. Register a hostname</h2><p>The quickest free option is <a href="https://www.noip.com/personal" rel="noreferrer">No-IP</a>. Its free hostnames must be confirmed every 30 days. <a class="q" href="/help#domain">?</a></p><h2>2. Point it to this server</h2><p>Create an A record whose value is <code>{h(status['public_ip'])}</code>.{ipv6_help}</p><h2>3. Check DNS and activate</h2><form method="post" action="/domain/check"><input type="hidden" name="csrf" value="{h(session['csrf'])}"><label for="domain">Hostname</label><input id="domain" name="domain" value="{h(value)}" placeholder="access.example.com" required><p><button>Check DNS</button></p></form>{activate_form}</section>"""
        disable = ""
        if status.get("domain") and status["tls_mode"] == "dual":
            disable = f"""<section><h2>4. Finish migration</h2><p>First import and test the domain profile shown on the Devices page. This step removes direct HTTPS access by IP and stops renewal of the IP certificate.</p><form method="post" action="/domain/disable-ip"><input type="hidden" name="csrf" value="{h(session['csrf'])}"><button class="danger">I tested the domain — disable IP mode</button></form></section>"""
        self.send_html(layout("Domain", f"<h1>Domain setup</h1>{banner}{domain_form}{disable}"))

    def logs(self, _session: dict[str, Any]) -> None:
        text = call("logs")["text"]
        self.send_html(layout("Logs", f"<h1>Sanitized logs <a class=\"q\" href=\"/help#logs\">?</a></h1><section><p class=\"muted\">Recent service events only. Addresses, device identifiers and import links are redacted.</p><pre>{h(text)}</pre></section>"))

    def help_page(self, _session: dict[str, Any]) -> None:
        body = """<h1>Help</h1>
<section id="domain"><h2>Adding a domain</h2><ol><li>Register a hostname. Start with <a href="https://www.noip.com/personal" rel="noreferrer">No-IP</a>, or use <a href="https://freedns.afraid.org/" rel="noreferrer">FreeDNS</a>, <a href="https://www.duckdns.org/" rel="noreferrer">DuckDNS</a>, <a href="https://desec.io/signup?domainType=dynDNS" rel="noreferrer">deSEC</a>, or <a href="https://www.cloudflare.com/dns/" rel="noreferrer">Cloudflare DNS</a>.</li><li>Create an <strong>A record</strong>: it maps a name to this server's IPv4 address. In Cloudflare, keep the record in DNS-only mode (gray cloud).</li><li>An <strong>AAAA record</strong> maps a name to IPv6. Do not create one unless the VPS has working IPv6 and the shown address matches.</li><li>Wait for DNS propagation, enter the hostname on the Domain page and run the check.</li><li>Activate it, import the new device link, test it, then disable IP mode.</li></ol><p>No-IP free hostnames require confirmation every 30 days. Missing that confirmation can stop the domain profile from working.</p></section>
<section id="certificates"><h2>Certificates</h2><p>Certificates encrypt the connection and prove the server identity. Domain certificates renew automatically. The initial IP certificate is deliberately short-lived and renews automatically until you finish the domain migration.</p></section>
<section id="devices"><h2>Devices</h2><p>Each device gets a separate import link. Delete a device immediately if it is lost or its link is shared. The link contains a secret and should be handled like a password.</p></section>
<section id="logs"><h2>Logs</h2><p>Proxy access logging is disabled. The panel only displays a small, sanitized window of service events and removes addresses, identifiers and import links.</p></section>
<section id="metrics"><h2>Metrics</h2><p>Overview shows local CPU load, memory, disk space, service state and the current number of established TCP connections. It does not use third-party analytics.</p></section>
<section id="recovery"><h2>Forgotten password</h2><p>Connect over SSH and run <code>sudo vpnctl admin reset-password</code>. The previous password cannot be recovered.</p></section>
<section id="troubleshooting"><h2>Troubleshooting</h2><p>Run <code>sudo vpnctl doctor</code> over SSH. DNS changes may take time to propagate. If an AAAA record points elsewhere, remove it before requesting a certificate.</p></section>"""
        self.send_html(layout("Help", body))

    def qr(self, name: str) -> None:
        raw = base64.b64decode(call("client_qr", {"name": name})["png"])
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
