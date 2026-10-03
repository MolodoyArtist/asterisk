#!/usr/bin/env bash
set -Eeuo pipefail

[[ "${EUID}" -eq 0 ]] || { echo 'run as root' >&2; exit 1; }

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR="$(mktemp -d /tmp/vpnctl-smoke.XXXXXX)"
IP_CERT_DIR=/etc/letsencrypt/live/192.0.2.10
DOMAIN_CERT_DIR=/etc/letsencrypt/live/access.example.com

cleanup() {
  rm -rf -- "${TEMP_DIR}" "${IP_CERT_DIR}" "${DOMAIN_CERT_DIR}"
}
trap cleanup EXIT

[[ ! -e "${IP_CERT_DIR}" && ! -e "${DOMAIN_CERT_DIR}" ]] || {
  echo 'documentation certificate paths unexpectedly exist' >&2
  exit 1
}

version=v26.3.27
archive="https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-64.zip"
curl -fsSL "${archive}" -o "${TEMP_DIR}/xray.zip"
curl -fsSL "${archive}.dgst" -o "${TEMP_DIR}/xray.dgst"
expected="$(awk 'BEGIN{IGNORECASE=1} /SHA2-256/{for(i=1;i<=NF;i++) if($i ~ /^[0-9a-fA-F]{64}$/){print tolower($i); exit}}' "${TEMP_DIR}/xray.dgst")"
actual="$(sha256sum "${TEMP_DIR}/xray.zip" | awk '{print $1}')"
[[ -n "${expected}" && "${actual}" == "${expected}" ]]
unzip -q "${TEMP_DIR}/xray.zip" -d "${TEMP_DIR}/xray"

mkdir -p "${IP_CERT_DIR}" "${DOMAIN_CERT_DIR}"
for cert_dir in "${IP_CERT_DIR}" "${DOMAIN_CERT_DIR}"; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=example' \
    -keyout "${cert_dir}/privkey.pem" -out "${cert_dir}/fullchain.pem" >/dev/null 2>&1
done
mkdir -p "${TEMP_DIR}/config/tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -keyout "${TEMP_DIR}/config/tls/default.key" -out "${TEMP_DIR}/config/tls/default.crt" >/dev/null 2>&1
reality_keys="$("${TEMP_DIR}/xray/xray" x25519)"
reality_private_key="$(awk -F': ' '/Private key/{print $2; exit}' <<<"${reality_keys}")"
reality_public_key="$(awk -F': ' '/Public key/{print $2; exit}' <<<"${reality_keys}")"
[[ -n "${reality_private_key}" && -n "${reality_public_key}" ]]

VPNCTL_CONFIG_DIR="${TEMP_DIR}/config" \
VPNCTL_NGINX_SITE="${TEMP_DIR}/vpnctl.nginx" \
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
  nginx -t -c "${TEMP_DIR}/nginx-${mode}-root.conf"
done
