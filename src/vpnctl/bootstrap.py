from __future__ import annotations

import argparse
import json
import os
import shutil
import time
import uuid

from .common import (
    AUTH_FILE,
    PANEL_PORT,
    STATE_FILE,
    client_uri,
    hash_password,
    random_token,
    validate_domain,
    validate_ip,
    validate_name,
    write_json,
)


def chown(path, user: str, group: str) -> None:
    shutil.chown(path, user=user, group=group)


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize a vpnctl appliance")
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--public-ipv6")
    parser.add_argument("--domain")
    parser.add_argument("--reality-target")
    parser.add_argument("--reality-private-key")
    parser.add_argument("--reality-public-key")
    parser.add_argument("--reality-short-id")
    parser.add_argument("--client-name", default="first-device")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        parser.error("bootstrap must run as root")
    if STATE_FILE.exists() or AUTH_FILE.exists():
        parser.error("appliance is already initialized")

    public_ip = validate_ip(args.public_ip)
    if ":" in public_ip:
        parser.error("--public-ip must be IPv4")
    public_ipv6 = validate_ip(args.public_ipv6) if args.public_ipv6 else None
    domain = validate_domain(args.domain) if args.domain else None
    reality_target = validate_domain(args.reality_target) if args.reality_target else None
    if not domain and not all((reality_target, args.reality_private_key, args.reality_public_key, args.reality_short_id)):
        parser.error("REALITY keys are required")
    client_name = validate_name(args.client_name)
    username = f"member-{random_token(5).lower()}"
    password = random_token(24)
    client = {
        "name": client_name,
        "id": str(uuid.uuid4()),
        "enabled": True,
        "created_at": int(time.time()),
        "hysteria_password": random_token(24),
    }
    state = {
        "schema": 3,
        "created_at": int(time.time()),
        "public_ip": public_ip,
        "public_ipv6": public_ipv6,
        "domain": domain,
        "layout": "domain-primary" if domain else "reality-primary",
        "panel_port": PANEL_PORT,
        "xhttp_path": random_token(24),
        "reality": {
            "target": reality_target,
            "server_name": reality_target,
            "private_key": args.reality_private_key,
            "public_key": args.reality_public_key,
            "short_id": args.reality_short_id,
        },
        "clients": [client],
    }
    if domain:
        state.pop("reality", None)
    auth = {
        "username": username,
        "password": hash_password(password),
        "session_secret": random_token(32),
    }
    write_json(STATE_FILE, state, 0o600)
    write_json(AUTH_FILE, auth, 0o600)
    chown(STATE_FILE, "root", "root")
    chown(AUTH_FILE, "vpnctl", "vpnctl")

    result = {
        "panel_url": f"https://{domain or public_ip}:{PANEL_PORT}/",
        "username": username,
        "password": password,
        "client_name": client_name,
        "client_uri": client_uri(state, client, "xhttp" if domain else "reality"),
    }
    with open(args.output, "x", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        json.dump(result, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
