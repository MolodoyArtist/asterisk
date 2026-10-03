from __future__ import annotations

import argparse
import json
import sys

from .rpc import RPCError, call


def emit(value: object) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(prog="vpnctl", description="Manage the local proxy appliance")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("doctor")

    admin = sub.add_parser("admin")
    admin_sub = admin.add_subparsers(dest="admin_command", required=True)
    admin_sub.add_parser("reset-password")

    clients = sub.add_parser("client")
    clients_sub = clients.add_subparsers(dest="client_command", required=True)
    clients_sub.add_parser("list")
    add = clients_sub.add_parser("add")
    add.add_argument("name")
    delete = clients_sub.add_parser("delete")
    delete.add_argument("name")

    domain = sub.add_parser("domain")
    domain_sub = domain.add_subparsers(dest="domain_command", required=True)
    check = domain_sub.add_parser("check")
    check.add_argument("hostname")
    add_domain = domain_sub.add_parser("add")
    add_domain.add_argument("hostname")

    cert = sub.add_parser("certificate")
    cert_sub = cert.add_subparsers(dest="cert_command", required=True)
    cert_sub.add_parser("renew")

    args = parser.parse_args()
    try:
        if args.command in {"status", "doctor"}:
            result = call("status")
            emit(result)
            if args.command == "doctor":
                bad_certificate = any(
                    not item.get("present")
                    or item.get("error")
                    or (item.get("days_remaining") is not None and item["days_remaining"] <= 1)
                    for item in result["certificates"]
                )
                if not all(result["services"].values()) or not all(result.get("checks", {}).values()) or bad_certificate:
                    raise SystemExit(1)
        elif args.command == "admin":
            emit(call("reset_password"))
        elif args.command == "client":
            if args.client_command == "list":
                emit(call("clients"))
            elif args.client_command == "add":
                emit(call("client_add", {"name": args.name}))
            else:
                emit(call("client_delete", {"name": args.name}))
        elif args.command == "domain":
            if args.domain_command == "check":
                emit(call("domain_check", {"domain": args.hostname}))
            elif args.domain_command == "add":
                emit(call("domain_add", {"domain": args.hostname}))
        elif args.command == "certificate":
            emit(call("certificate_renew"))
    except RPCError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
