#!/usr/bin/env bash
# Optional FakeTLS proxy. Only checksum-pinned upstream binaries are installed.
set -Eeuo pipefail
umask 077

MTG_VERSION=2.2.8
MTPROXY_DIR="${VPNCTL_MTPROXY_DIR:-/opt/MTProxy}"
MTPROXY_ETC="${VPNCTL_MTPROXY_ETC:-/etc/mtproxy}"
STATE_FILE="${VPNCTL_STATE_FILE:-/var/lib/vpnctl/state.json}"
INSTALL_DIR="${VPNCTL_INSTALL_DIR:-/opt/vpnctl}"
UFW_BIN="${VPNCTL_UFW_BIN:-/usr/sbin/ufw}"
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || die "Run as root."

prepare() {
  local arch expected temporary archive
  case "$(uname -m)" in
    x86_64) arch=amd64; expected=7ef19d079d85f4e00d4f8334ec1f3f3c8718e3d0ed1f3109ea9a8673138a2102 ;;
    aarch64|arm64) arch=arm64; expected=562a94dd4cafcb8f179b76cfeafb76da12747c8e230bc76235bf8746cc189644 ;;
    *) die "Telegram FakeTLS requires x86_64 or arm64." ;;
  esac
  getent group mtproxy >/dev/null || groupadd --system mtproxy
  id mtproxy >/dev/null 2>&1 || useradd --system --gid mtproxy --home-dir /nonexistent --shell /usr/sbin/nologin mtproxy
  install -d -o root -g root -m 0755 "${MTPROXY_DIR}"
  install -d -o root -g mtproxy -m 0750 "${MTPROXY_ETC}"
  if [[ -x "${MTPROXY_DIR}/mtg" && -f "${MTPROXY_DIR}/.vpnctl-version" ]] && grep -Fxq "${MTG_VERSION}" "${MTPROXY_DIR}/.vpnctl-version"; then
    return
  fi
  temporary="$(mktemp -d /tmp/vpnctl-mtg.XXXXXX)"
  trap 'rm -rf -- "${temporary}"' RETURN
  archive="${temporary}/mtg.tar.gz"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --output "${archive}" "https://github.com/9seconds/mtg/releases/download/v${MTG_VERSION}/mtg-${MTG_VERSION}-linux-${arch}.tar.gz"
  [[ "$(sha256sum "${archive}" | awk '{print $1}')" == "${expected}" ]] || die "mtg archive checksum mismatch."
  /usr/bin/python3 - "${archive}" "${temporary}/mtg" <<'PY'
import pathlib, sys, tarfile
with tarfile.open(sys.argv[1], "r:gz") as archive:
    members = [item for item in archive.getmembers() if item.isfile() and pathlib.PurePosixPath(item.name).name == "mtg"]
    if len(members) != 1:
        raise SystemExit("Unexpected mtg archive layout.")
    pathlib.Path(sys.argv[2]).write_bytes(archive.extractfile(members[0]).read())
PY
  install -o root -g root -m 0755 "${temporary}/mtg" "${MTPROXY_DIR}/mtg"
  printf '%s\n' "${MTG_VERSION}" >"${MTPROXY_DIR}/.vpnctl-version"
}

configure() {
  [[ -d "${MTPROXY_ETC}" ]] || die "Telegram proxy is not prepared."
  PYTHONPATH="${INSTALL_DIR}/src" /usr/bin/python3 - "${STATE_FILE}" "${MTPROXY_ETC}/mtg.toml" <<'PY'
import grp, json, os, sys
from pathlib import Path
from vpnctl.common import atomic_write, domain_mode, telegram_uri, validate_state
state = json.loads(Path(sys.argv[1]).read_text())
validate_state(state)
telegram = state.get("telegram", {})
if not domain_mode(state) or not telegram.get("enabled") or telegram.get("implementation") != "mtg":
    raise SystemExit("Activate a domain before enabling Telegram FakeTLS.")
import urllib.parse
secret = urllib.parse.parse_qs(urllib.parse.urlsplit(telegram_uri(state)).query)["secret"][0]
content = f'''debug = false
secret = {json.dumps(secret)}
bind-to = "0.0.0.0:8443"
public-ipv4 = {json.dumps(state["public_ip"])}
concurrency = 128
prefer-ip = "only-ipv4"
auto-update = false
[domain-fronting]
ip = "127.0.0.1"
port = 443
[defense.anti-replay]
enabled = true
max-size = "1mib"
[defense.blocklist]
enabled = false
[stats.prometheus]
enabled = false
[stats.statsd]
enabled = false
'''
atomic_write(Path(sys.argv[2]), content, 0o640, (0, grp.getgrnam("mtproxy").gr_gid))
PY
}

provision() {
  prepare
  configure
  "${UFW_BIN}" allow vpnctl-mtproxy >/dev/null
}

cleanup() {
  "${UFW_BIN}" --force delete allow vpnctl-mtproxy >/dev/null 2>&1 || true
  rm -f -- "${MTPROXY_ETC}/mtg.toml" "${MTPROXY_ETC}/vpnctl.env"
}

case "${1:-}" in
  prepare) prepare ;;
  configure) configure ;;
  provision) provision ;;
  cleanup) cleanup ;;
  *) die "Usage: $0 {prepare|configure|provision|cleanup}" ;;
esac
