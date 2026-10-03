#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/xray.sh
source "${ROOT}/scripts/xray.sh"

# This validates the Linux distribution that the appliance actually installs.
# Treat a developer workstation on another platform as an explicit skip rather
# than a false product failure after downloading an un-runnable binary.
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  printf 'integration smoke skipped: requires Linux x86_64\n'
  exit 0
fi

TEMP_DIR="$(mktemp -d /tmp/vpnctl-smoke.XXXXXX)"
CERT_LIVE_DIR="${TEMP_DIR}/letsencrypt/live"
IP_CERT_DIR="${CERT_LIVE_DIR}/192.0.2.10"
DOMAIN_CERT_DIR="${CERT_LIVE_DIR}/access.example.com"

cleanup() {
  rm -rf -- "${TEMP_DIR}"
}
trap cleanup EXIT

archive="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip"
printf 'Downloading pinned Xray archive\n'
curl --fail --show-error --location --proto '=https' --tlsv1.2 "${archive}" -o "${TEMP_DIR}/xray.zip"
printf 'Verifying Xray archive\n'
expected="$(xray_sha256 64)"
actual="$(sha256sum "${TEMP_DIR}/xray.zip" | awk '{print $1}')"
[[ "${actual}" == "${expected}" ]] || { echo 'Xray archive checksum mismatch.' >&2; exit 1; }
printf 'Unpacking Xray archive\n'
unzip -q "${TEMP_DIR}/xray.zip" -d "${TEMP_DIR}/xray"

printf 'Generating test TLS certificates\n'
mkdir -p "${IP_CERT_DIR}" "${DOMAIN_CERT_DIR}"
for cert_dir in "${IP_CERT_DIR}" "${DOMAIN_CERT_DIR}"; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=example' \
    -keyout "${cert_dir}/privkey.pem" -out "${cert_dir}/fullchain.pem" >/dev/null 2>&1
done
mkdir -p "${TEMP_DIR}/config/tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -keyout "${TEMP_DIR}/config/tls/default.key" -out "${TEMP_DIR}/config/tls/default.crt" >/dev/null 2>&1
printf 'Generating REALITY test keys\n'
if ! reality_keys="$("${TEMP_DIR}/xray/xray" x25519 2>&1)"; then
  printf 'Xray key generation failed: %s\n' "${reality_keys}" >&2
  exit 1
fi
reality_private_key="$(awk -F': ' '/^Private( key|Key):/{print $2; exit}' <<<"${reality_keys}")"
reality_public_key="$(awk -F': ' '/^(Public key|Password)( \(PublicKey\))?:/{print $2; exit}' <<<"${reality_keys}")"
if [[ -z "${reality_private_key}" || -z "${reality_public_key}" ]]; then
  printf 'Unrecognized Xray x25519 output: %s\n' "$(sed -E 's/: .*/: [redacted]/' <<<"${reality_keys}" | tr '\n' ';')" >&2
  exit 1
fi

printf 'Rendering test configurations\n'
VPNCTL_CONFIG_DIR="${TEMP_DIR}/config" \
VPNCTL_NGINX_SITE="${TEMP_DIR}/vpnctl.nginx" \
VPNCTL_CERT_LIVE_DIR="${CERT_LIVE_DIR}" \
VPNCTL_SMOKE_DIR="${TEMP_DIR}" \
VPNCTL_REALITY_PRIVATE_KEY="${reality_private_key}" \
VPNCTL_REALITY_PUBLIC_KEY="${reality_public_key}" \
PYTHONPATH="${ROOT}/src" python3 - <<'PY'
import os
from pathlib import Path
from vpnctl.common import XRAY_CONFIG, render_nginx, render_xray

base = {
    "public_ip": "192.0.2.10",
    "public_ipv6": "2001:db8::10",
    "xhttp_path": "A_random_path_with_enough_entropy",
    "reality": {
        "target": "www.example.com",
        "server_name": "www.example.com",
        "private_key": os.environ["VPNCTL_REALITY_PRIVATE_KEY"],
        "public_key": os.environ["VPNCTL_REALITY_PUBLIC_KEY"],
        "short_id": "a1b2c3d4",
    },
    "clients": [{"name": "smoke", "id": "00000000-0000-4000-8000-000000000001", "enabled": True}],
}
states = {"ip": dict(base, domain=None), "domain": dict(base, domain="access.example.com")}
root = Path(os.environ["VPNCTL_SMOKE_DIR"])
XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
for name, state in states.items():
    (root / f"xray-{name}.json").write_text(render_xray(state))
    (root / f"nginx-{name}.conf").write_text(render_nginx(state))
PY

for mode in ip domain; do
  printf 'Validating Xray %s configuration\n' "${mode}"
  XRAY_LOCATION_ASSET="${TEMP_DIR}/xray" "${TEMP_DIR}/xray/xray" run -test -config "${TEMP_DIR}/xray-${mode}.json"
  cat >"${TEMP_DIR}/nginx-${mode}-root.conf" <<EOF
pid ${TEMP_DIR}/nginx-${mode}.pid;
error_log stderr;
events { worker_connections 4096; }
http {
    include /etc/nginx/mime.types;
    include ${TEMP_DIR}/nginx-${mode}.conf;
}
EOF
  printf 'Validating Nginx %s configuration\n' "${mode}"
  nginx -t -c "${TEMP_DIR}/nginx-${mode}-root.conf"
done
