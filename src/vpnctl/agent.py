from __future__ import annotations

import argparse
import base64
import datetime as dt
import grp
import ipaddress
import json
import os
import pwd
import shutil
import socket
import socketserver
import struct
import subprocess  # nosec B404
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .common import (
    AUTH_FILE,
    CONFIG_DIR,
    NGINX_SITE,
    STATE_FILE,
    XRAY_CONFIG,
    ValidationError,
    atomic_write,
    client_uri,
    hash_password,
    load_state,
    random_token,
    read_json,
    redact_log,
    render_nginx,
    render_xray,
    validate_domain,
    validate_name,
    validate_state,
    write_json,
)

SOCKET_PATH = Path(os.environ.get("VPNCTL_AGENT_SOCKET", "/run/vpnctl/agent.sock"))
XRAY_BIN = os.environ.get("VPNCTL_XRAY_BIN", "/usr/local/bin/xray")
CERTBOT_BIN = os.environ.get("VPNCTL_CERTBOT_BIN", "/snap/bin/certbot")
SYSTEMCTL_BIN = os.environ.get("VPNCTL_SYSTEMCTL_BIN", "/usr/bin/systemctl")
OPENSSL_BIN = os.environ.get("VPNCTL_OPENSSL_BIN", "/usr/bin/openssl")
NGINX_BIN = os.environ.get("VPNCTL_NGINX_BIN", "/usr/sbin/nginx")
SS_BIN = os.environ.get("VPNCTL_SS_BIN", "/usr/bin/ss")
JOURNALCTL_BIN = os.environ.get("VPNCTL_JOURNALCTL_BIN", "/usr/bin/journalctl")
QRENCODE_BIN = os.environ.get("VPNCTL_QRENCODE_BIN", "/usr/bin/qrencode")
LOCK = threading.RLock()

# Subprocess calls use fixed argument vectors for local system tools; shell mode is never used.


class AgentError(RuntimeError):
    pass


def run(command: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)  # nosec B603


def service_active(name: str) -> bool:
    return run([SYSTEMCTL_BIN, "is-active", "--quiet", name], 10).returncode == 0


def certificate_info(name: str) -> dict[str, Any]:
    cert = Path("/etc/letsencrypt/live") / name / "fullchain.pem"
    if not cert.exists():
        return {"name": name, "present": False}
    result = run([OPENSSL_BIN, "x509", "-in", str(cert), "-noout", "-enddate", "-subject"], 10)
    if result.returncode != 0:
        return {"name": name, "present": True, "error": "Certificate could not be read."}
    not_after = ""
    subject = ""
    for line in result.stdout.splitlines():
        if line.startswith("notAfter="):
            not_after = line.split("=", 1)[1]
        elif line.startswith("subject="):
            subject = line.split("=", 1)[1].strip()
    days_remaining = None
    try:
        expires = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        days_remaining = max(0, int((expires - dt.datetime.now(dt.timezone.utc)).total_seconds() // 86400))
    except ValueError:
        pass
    return {"name": name, "present": True, "not_after": not_after, "subject": subject, "days_remaining": days_remaining}


def system_metrics() -> dict[str, Any]:
    load1, load5, load15 = os.getloadavg()
    memory: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            memory[key] = int(value.strip().split()[0]) * 1024
    except (OSError, ValueError):
        pass
    disk = shutil.disk_usage("/")
    connections = 0
    ss = run([SS_BIN, "-Hnt", "state", "established"], 10)
    if ss.returncode == 0:
        connections = len([line for line in ss.stdout.splitlines() if line.strip()])
    return {
        "load": [round(load1, 2), round(load5, 2), round(load15, 2)],
        "memory_total": memory.get("MemTotal", 0),
        "memory_available": memory.get("MemAvailable", 0),
        "disk_total": disk.total,
        "disk_free": disk.free,
        "connections": connections,
        "uptime_seconds": _uptime(),
    }


def _uptime() -> int:
    try:
        return int(float(Path("/proc/uptime").read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        return 0


def resolve_domain(domain: str) -> dict[str, list[str]]:
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM):
            if family == socket.AF_INET:
                ipv4.add(str(ipaddress.ip_address(sockaddr[0])))
            elif family == socket.AF_INET6:
                ipv6.add(str(ipaddress.ip_address(sockaddr[0])))
    except socket.gaierror as exc:
        raise AgentError("The domain does not resolve yet. Check its DNS record and try again.") from exc
    return {"a": sorted(ipv4), "aaaa": sorted(ipv6)}


def check_domain(state: dict[str, Any], domain: str) -> dict[str, Any]:
    domain = validate_domain(domain)
    resolved = resolve_domain(domain)
    if resolved["a"] != [state["public_ip"]]:
        raise AgentError("Every domain A answer must point only to this server.")
    expected_v6 = state.get("public_ipv6")
    if resolved["aaaa"] and resolved["aaaa"] != [expected_v6]:
        raise AgentError("Every domain AAAA answer must point only to this server. Remove or correct it.")
    return {"domain": domain, **resolved}


def validate_and_install_xray(state: dict[str, Any]) -> None:
    content = render_xray(state)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="xray.", suffix=".json", dir=str(CONFIG_DIR))
    try:
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        result = run([XRAY_BIN, "run", "-test", "-config", temp_name], 20)
        if result.returncode != 0:
            raise AgentError("Xray rejected the generated configuration.")
        os.replace(temp_name, XRAY_CONFIG)
        try:
            shutil.chown(XRAY_CONFIG, user="root", group="xray")
        except LookupError:
            pass
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def install_nginx(state: dict[str, Any]) -> None:
    previous = NGINX_SITE.read_text() if NGINX_SITE.exists() else None
    atomic_write(NGINX_SITE, render_nginx(state), 0o644)
    check = run([NGINX_BIN, "-t"], 20)
    if check.returncode != 0:
        if previous is None:
            NGINX_SITE.unlink(missing_ok=True)
        else:
            atomic_write(NGINX_SITE, previous, 0o644)
        raise AgentError("Nginx rejected the generated configuration.")
    reload_result = run([SYSTEMCTL_BIN, "reload", "nginx"], 20)
    if reload_result.returncode != 0:
        raise AgentError("Nginx configuration is valid, but reload failed.")


def save_state(state: dict[str, Any]) -> None:
    write_json(STATE_FILE, state, 0o600)
    try:
        shutil.chown(STATE_FILE, user="root", group="root")
    except LookupError:
        pass


def mutate_clients(mutator: Callable[[dict[str, Any]], Any]) -> Any:
    with LOCK:
        original = load_state()
        updated = json.loads(json.dumps(original))
        result = mutator(updated)
        validate_state(updated)
        try:
            validate_and_install_xray(updated)
            save_state(updated)
            restart = run([SYSTEMCTL_BIN, "restart", "xray"], 30)
            if restart.returncode != 0:
                raise AgentError("Xray restart failed.")
        except Exception as exc:
            validate_and_install_xray(original)
            save_state(original)
            run([SYSTEMCTL_BIN, "restart", "xray"], 30)
            if isinstance(exc, AgentError):
                raise AgentError(f"{exc} The previous configuration was restored.") from exc
            raise
        return result


def action_status(_: dict[str, Any]) -> dict[str, Any]:
    state = load_state()
    certs = []
    if not state.get("domain"):
        certs.append(certificate_info(state["public_ip"]))
    if state.get("domain"):
        certs.append(certificate_info(state["domain"]))
    metrics = system_metrics()
    return {
        "services": {"xray": service_active("xray"), "nginx": service_active("nginx"), "panel": service_active("vpnctl-web")},
        "metrics": metrics,
        "checks": {
            "memory": metrics["memory_available"] >= 64 * 1024 * 1024,
            "disk": metrics["disk_free"] >= 512 * 1024 * 1024,
        },
        "profiles": {"reality": state.get("layout", "reality-primary") == "reality-primary", "xhttp": bool(state.get("domain")) or state.get("layout") == "legacy-xhttp-primary"},
        "domain": state.get("domain"),
        "public_ip": state.get("public_ip"),
        "public_ipv6": state.get("public_ipv6"),
        "certificates": certs,
        "client_count": len([c for c in state.get("clients", []) if c.get("enabled", True)]),
    }


def action_clients(_: dict[str, Any]) -> dict[str, Any]:
    state = load_state()
    items = []
    for client in state.get("clients", []):
        row = {"name": client["name"], "enabled": client.get("enabled", True), "created_at": client.get("created_at", "")}
        if row["enabled"]:
            if state.get("layout", "reality-primary") == "reality-primary":
                row["reality_uri"] = client_uri(state, client, "reality")
            if state.get("domain") or state.get("layout") == "legacy-xhttp-primary":
                row["xhttp_uri"] = client_uri(state, client, "xhttp")
        items.append(row)
    return {"clients": items}


def action_client_add(payload: dict[str, Any]) -> dict[str, Any]:
    name = validate_name(str(payload.get("name", "")))

    def add(state: dict[str, Any]) -> dict[str, Any]:
        if any(item["name"].lower() == name.lower() for item in state.get("clients", [])):
            raise AgentError("A client with this name already exists.")
        client = {"name": name, "id": str(uuid.uuid4()), "enabled": True, "created_at": int(time.time())}
        state.setdefault("clients", []).append(client)
        profile = "reality" if state.get("layout", "reality-primary") == "reality-primary" else "xhttp"
        return {"name": name, "uri": client_uri(state, client, profile)}

    return mutate_clients(add)


def action_client_delete(payload: dict[str, Any]) -> dict[str, Any]:
    name = validate_name(str(payload.get("name", "")))

    def delete(state: dict[str, Any]) -> dict[str, Any]:
        before = len(state.get("clients", []))
        state["clients"] = [item for item in state.get("clients", []) if item["name"].lower() != name.lower()]
        if len(state["clients"]) == before:
            raise AgentError("Client not found.")
        if not state["clients"]:
            raise AgentError("At least one client must remain. Add a replacement before deleting this one.")
        return {"deleted": name}

    return mutate_clients(delete)


def action_client_qr(payload: dict[str, Any]) -> dict[str, Any]:
    name = validate_name(str(payload.get("name", "")))
    state = load_state()
    client = next((item for item in state.get("clients", []) if item["name"] == name and item.get("enabled", True)), None)
    if not client:
        raise AgentError("Active client not found.")
    try:
        result = subprocess.run(
            [QRENCODE_BIN, "-t", "PNG", "-s", "6", "-m", "2", "-o", "-"],
            input=client_uri(state, client, str(payload.get("profile", "reality"))).encode(),
            capture_output=True,
            timeout=15,
            check=False,  # nosec B603
        )
    except subprocess.TimeoutExpired as exc:
        raise AgentError("QR code generation timed out.") from exc
    if result.returncode != 0:
        raise AgentError("QR code generation failed.")
    return {"png": base64.b64encode(result.stdout).decode("ascii")}


def action_domain_check(payload: dict[str, Any]) -> dict[str, Any]:
    return check_domain(load_state(), str(payload.get("domain", "")))


def action_domain_add(payload: dict[str, Any]) -> dict[str, Any]:
    with LOCK:
        state = load_state()
        checked = check_domain(state, str(payload.get("domain", "")))
        domain = checked["domain"]
        if state.get("domain") and state["domain"] != domain:
            raise AgentError("A different domain is already configured.")
        command = [
            CERTBOT_BIN,
            "certonly",
            "--non-interactive",
            "--agree-tos",
            "--register-unsafely-without-email",
            "--webroot",
            "--webroot-path",
            "/var/www/vpnctl-acme",
            "--cert-name",
            domain,
            "--domains",
            domain,
        ]
        result = run(command, 180)
        if result.returncode != 0:
            raise AgentError("Certificate issuance failed. DNS may not have propagated yet.")
        original = json.loads(json.dumps(state))
        state["domain"] = domain
        state["domain_added_at"] = int(time.time())
        try:
            validate_and_install_xray(state)
            install_nginx(state)
            save_state(state)
        except Exception:
            validate_and_install_xray(original)
            install_nginx(original)
            raise
        restart = run([SYSTEMCTL_BIN, "restart", "xray"], 30)
        if restart.returncode != 0:
            validate_and_install_xray(original)
            install_nginx(original)
            save_state(original)
            run([SYSTEMCTL_BIN, "restart", "xray"], 30)
            raise AgentError("Xray restart failed. The previous configuration was restored.")
        return {"domain": domain, "xhttp": True}


def action_ip_disable(_: dict[str, Any]) -> dict[str, Any]:
    raise AgentError("IP panel access remains enabled for recovery and cannot be disabled.")


def action_certificate_renew(_: dict[str, Any]) -> dict[str, Any]:
    result = run([CERTBOT_BIN, "renew", "--deploy-hook", f"{SYSTEMCTL_BIN} reload nginx"], 300)
    if result.returncode != 0:
        raise AgentError("Certificate renewal failed. See the sanitized service log.")
    return {"renewed": True}


def action_logs(_: dict[str, Any]) -> dict[str, Any]:
    result = run(
        [JOURNALCTL_BIN, "-u", "xray", "-u", "nginx", "-u", "vpnctl-agent", "-u", "vpnctl-web", "-u", "vpnctl-health", "-n", "160", "--no-pager", "-o", "short-iso"],
        20,
    )
    text = redact_log(result.stdout[-30000:])
    state = load_state()
    sensitive = [state.get("xhttp_path"), state.get("domain"), state.get("public_ipv6")]
    sensitive.extend(item.get("name") for item in state.get("clients", []))
    for value in sensitive:
        if value and len(str(value)) >= 4:
            text = text.replace(str(value), "[REDACTED]")
    return {"text": text}


def action_reset_password(_: dict[str, Any]) -> dict[str, Any]:
    with LOCK:
        password = random_token(24)
        auth = read_json(AUTH_FILE)
        auth["password"] = hash_password(password)
        auth["session_secret"] = random_token(32)
        try:
            owner = (pwd.getpwnam("vpnctl").pw_uid, grp.getgrnam("vpnctl").gr_gid)
        except KeyError as exc:
            raise AgentError("The portal service account is missing.") from exc
        write_json(AUTH_FILE, auth, 0o600, owner)
        return {"username": auth["username"], "password": password}


ACTIONS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "status": action_status,
    "clients": action_clients,
    "client_add": action_client_add,
    "client_delete": action_client_delete,
    "client_qr": action_client_qr,
    "domain_check": action_domain_check,
    "domain_add": action_domain_add,
    "certificate_renew": action_certificate_renew,
    "logs": action_logs,
    "reset_password": action_reset_password,
}


def dispatch(request: dict[str, Any], peer_uid: int = 0) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise AgentError("Invalid request.")
    action = str(request.get("action", ""))
    handler = ACTIONS.get(action)
    if not handler:
        raise AgentError("Unsupported operation.")
    if action == "reset_password" and peer_uid != 0:
        raise AgentError("This operation is available only through sudo vpnctl.")
    payload = request.get("payload", {})
    if payload is None:
        payload = {}
    elif not isinstance(payload, dict):
        raise AgentError("Invalid request payload.")
    return handler(payload)


class RequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        credentials = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _, peer_uid, _ = struct.unpack("3i", credentials)
        raw = self.rfile.readline(65537)
        if len(raw) > 65536:
            response = {"ok": False, "error": "Request too large."}
        else:
            try:
                request = json.loads(raw)
                response = {"ok": True, "result": dispatch(request, peer_uid)}
            except (json.JSONDecodeError, ValidationError, AgentError) as exc:
                response = {"ok": False, "error": str(exc)}
            except Exception:  # noqa: BLE001 - never expose privileged internals to the web process
                response = {"ok": False, "error": "Internal operation failed."}
        self.wfile.write((json.dumps(response, separators=(",", ":")) + "\n").encode())


class UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


def serve() -> None:
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    SOCKET_PATH.unlink(missing_ok=True)
    with UnixServer(str(SOCKET_PATH), RequestHandler) as server:
        gid = grp.getgrnam("vpnctl").gr_gid
        os.chown(SOCKET_PATH, 0, gid)
        # The group-write bit is the intentional root:vpnctl IPC boundary.
        os.chmod(SOCKET_PATH, 0o660)  # nosec B103
        server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="vpnctl privileged agent")
    parser.add_argument("--serve", action="store_true")
    args = parser.parse_args()
    if args.serve:
        serve()
    else:
        parser.error("--serve is required")


if __name__ == "__main__":
    main()
