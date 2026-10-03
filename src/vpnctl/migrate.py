from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .common import ValidationError, atomic_write, validate_state


class MigrationError(RuntimeError):
    pass


def migrate_state(state: dict[str, Any]) -> dict[str, Any]:
    schema = state.get("schema")
    if schema == 2:
        validate_state(state)
        return state
    if schema != 1:
        raise MigrationError("This installation is too old for an automatic update.")
    migrated = json.loads(json.dumps(state))
    migrated["schema"] = 2
    migrated.pop("ip_mode", None)
    # Preserve every existing XHTTP/TLS URI and do not add another profile.
    migrated["layout"] = "legacy-xhttp-primary"
    try:
        validate_state(migrated)
    except ValidationError as exc:
        raise MigrationError(f"Existing state cannot be migrated: {exc}") from exc
    return migrated


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate vpnctl state without losing devices or credentials")
    parser.add_argument("--state-file", required=True)
    args = parser.parse_args()
    path = Path(args.state_file)
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(state, dict):
            raise MigrationError("State file must contain an object.")
        if state.get("schema") == 1:
            state = migrate_state(state)
            atomic_write(path, json.dumps(state, indent=2, sort_keys=True) + "\n", 0o600)
        else:
            validate_state(state)
    except (OSError, json.JSONDecodeError, ValidationError, MigrationError) as exc:
        raise SystemExit(f"state migration failed: {exc}") from exc


if __name__ == "__main__":
    main()
