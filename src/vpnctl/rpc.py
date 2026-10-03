from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any

SOCKET_PATH = Path(os.environ.get("VPNCTL_AGENT_SOCKET", "/run/vpnctl/agent.sock"))


class RPCError(RuntimeError):
    pass


def call(action: str, payload: dict[str, Any] | None = None, timeout: int = 310) -> dict[str, Any]:
    request = json.dumps({"action": action, "payload": payload or {}}, separators=(",", ":")) + "\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(str(SOCKET_PATH))
        connection.sendall(request.encode())
        chunks = bytearray()
        while not chunks.endswith(b"\n"):
            part = connection.recv(65536)
            if not part:
                break
            chunks.extend(part)
            if len(chunks) > 1_000_000:
                raise RPCError("Agent response was too large.")
    try:
        response = json.loads(chunks)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RPCError("Agent returned an invalid response.") from exc
    if not response.get("ok"):
        raise RPCError(str(response.get("error", "Operation failed.")))
    return response["result"]
