#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

REPOSITORY="${VPNCTL_REPOSITORY:-MolodoyArtist/asterisk}"
BRANCH="${VPNCTL_BRANCH:-main}"
XRAY_VERSION="${VPNCTL_XRAY_VERSION:-v26.3.27}"
INSTALL_DIR=/opt/vpnctl
ACME_ROOT=/var/www/vpnctl-acme
RESULT_FILE=/root/vpnctl-install.json

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || die "Run this installer as root."
[[ -r /etc/os-release ]] || die "Cannot identify this operating system."
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == ubuntu ]] || die "This release supports Ubuntu 22.04 and 24.04 only."
case "${VERSION_ID:-}" in 22.04|24.04) ;; *) die "This release supports Ubuntu 22.04 and 24.04 only." ;; esac

exec 9>/run/vpnctl-install.lock
flock -n 9 || die "Another installation is running."

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
TEMP_DIR="$(mktemp -d /tmp/vpnctl-install.XXXXXX)"
cleanup() { rm -rf -- "${TEMP_DIR}"; }
trap cleanup EXIT

if [[ ! -f "${SOURCE_DIR}/src/vpnctl/common.py" ]]; then
  log "Downloading installer files"
  curl --fail --show-error --location --proto '=https' --tlsv1.2 \
    "https://github.com/${REPOSITORY}/archive/refs/heads/${BRANCH}.tar.gz" \
    -o "${TEMP_DIR}/source.tar.gz"
  mkdir "${TEMP_DIR}/source"
  tar -xzf "${TEMP_DIR}/source.tar.gz" -C "${TEMP_DIR}/source" --strip-components=1
  SOURCE_DIR="${TEMP_DIR}/source"
fi

if [[ -e /var/lib/vpnctl/state.json ]]; then
  log "Existing installation detected; switching to safe update mode"
  VPNCTL_LOCK_HELD=1 bash "${SOURCE_DIR}/scripts/update.sh"
  exit
fi
[[ ! -e "${RESULT_FILE}" ]] || die "${RESULT_FILE} already exists. Move or delete it before installing."

log "Installing operating-system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl iproute2 nginx openssl python3 qrencode snapd unzip ufw

log "Installing current Certbot"
systemctl enable --now snapd.socket
snap install core >/dev/null 2>&1 || snap refresh core >/dev/null
snap install --classic certbot >/dev/null 2>&1 || snap refresh certbot >/dev/null
ln -sfn /snap/bin/certbot /usr/local/bin/certbot
/snap/bin/certbot --version
/snap/bin/certbot certonly --help all >"${TEMP_DIR}/certbot-help.txt"
grep -q -- '--ip-address' "${TEMP_DIR}/certbot-help.txt" || die "Installed Certbot does not support public IP certificates."

log "Installing Xray ${XRAY_VERSION}"
case "$(uname -m)" in
  x86_64) XRAY_ARCH=64 ;;
  aarch64|arm64) XRAY_ARCH=arm64-v8a ;;
  *) die "Only x86_64 and arm64 VPS architectures are supported." ;;
esac
XRAY_BASE="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip"
curl --fail --show-error --location --proto '=https' --tlsv1.2 "${XRAY_BASE}" -o "${TEMP_DIR}/xray.zip"
curl --fail --show-error --location --proto '=https' --tlsv1.2 "${XRAY_BASE}.dgst" -o "${TEMP_DIR}/xray.dgst"
EXPECTED_SHA256="$(awk 'BEGIN{IGNORECASE=1} /SHA2-256/{for(i=1;i<=NF;i++) if($i ~ /^[0-9a-fA-F]{64}$/){print tolower($i); exit}}' "${TEMP_DIR}/xray.dgst")"
[[ -n "${EXPECTED_SHA256}" ]] || die "Could not read the published Xray checksum."
ACTUAL_SHA256="$(sha256sum "${TEMP_DIR}/xray.zip" | awk '{print $1}')"
[[ "${ACTUAL_SHA256}" == "${EXPECTED_SHA256}" ]] || die "Xray checksum verification failed."
mkdir "${TEMP_DIR}/xray"
unzip -q "${TEMP_DIR}/xray.zip" -d "${TEMP_DIR}/xray"
install -m 0755 "${TEMP_DIR}/xray/xray" /usr/local/bin/xray
install -d -m 0755 /usr/local/share/xray
install -m 0644 "${TEMP_DIR}/xray/geoip.dat" "${TEMP_DIR}/xray/geosite.dat" /usr/local/share/xray/

log "Creating restricted service accounts"
getent group xray >/dev/null || groupadd --system xray
id xray >/dev/null 2>&1 || useradd --system --gid xray --home-dir /nonexistent --shell /usr/sbin/nologin xray
getent group vpnctl >/dev/null || groupadd --system vpnctl
id vpnctl >/dev/null 2>&1 || useradd --system --gid vpnctl --home-dir /nonexistent --shell /usr/sbin/nologin vpnctl
install -d -o root -g vpnctl -m 0750 /var/lib/vpnctl
install -d -o root -g xray -m 0750 /etc/vpnctl
install -d -o root -g root -m 0755 /etc/vpnctl/tls "${ACME_ROOT}" /run/vpnctl

log "Installing appliance files"
install -d -o root -g root -m 0755 "${INSTALL_DIR}"
cp -a "${SOURCE_DIR}/src" "${INSTALL_DIR}/"
find "${INSTALL_DIR}" -type d -exec chmod 0755 {} +
find "${INSTALL_DIR}" -type f -exec chmod 0644 {} +
install -m 0644 "${SOURCE_DIR}"/systemd/*.service "${SOURCE_DIR}"/systemd/*.timer /etc/systemd/system/
cat >/usr/local/bin/vpnctl <<'EOF'
#!/usr/bin/env bash
export PYTHONPATH=/opt/vpnctl/src
export PYTHONDONTWRITEBYTECODE=1
exec /usr/bin/python3 -m vpnctl.cli "$@"
EOF
chmod 0755 /usr/local/bin/vpnctl

log "Detecting public address"
PUBLIC_IP="$(curl --fail --silent --show-error --max-time 15 --proto '=https' --tlsv1.2 https://api.ipify.org)"
/usr/bin/python3 - "${PUBLIC_IP}" <<'PY'
import ipaddress, sys
address = ipaddress.ip_address(sys.argv[1])
if address.version != 4 or not address.is_global:
    raise SystemExit("A public IPv4 address is required.")
PY
printf 'Detected public IPv4: %s\n' "${PUBLIC_IP}"
PUBLIC_IPV6="$(curl -6 --fail --silent --show-error --max-time 5 --proto '=https' --tlsv1.2 https://api64.ipify.org 2>/dev/null || true)"
if [[ -n "${PUBLIC_IPV6}" ]]; then
  if ! /usr/bin/python3 - "${PUBLIC_IPV6}" <<'PY'
import ipaddress, sys
address = ipaddress.ip_address(sys.argv[1])
if address.version != 6 or not address.is_global:
    raise SystemExit(1)
PY
  then
    printf 'Ignoring an invalid detected IPv6 address.\n' >&2
    PUBLIC_IPV6=
  else
    printf 'Detected public IPv6: %s\n' "${PUBLIC_IPV6}"
  fi
fi

# Open validation and HTTPS before asking the CA to reach the machine. Preserve
# the active SSH destination port and configured sshd ports so enabling UFW
# cannot lock out an SSH session or a console installation with a custom port.
SSH_PORT_CANDIDATES=()
ACTIVE_SSH_PORT="${SSH_CONNECTION:-}"
ACTIVE_SSH_PORT="${ACTIVE_SSH_PORT##* }"
[[ "${ACTIVE_SSH_PORT}" =~ ^[0-9]+$ ]] && SSH_PORT_CANDIDATES+=("${ACTIVE_SSH_PORT}")
if [[ -x /usr/sbin/sshd ]]; then
  while read -r configured_port; do
    [[ "${configured_port}" =~ ^[0-9]+$ ]] && SSH_PORT_CANDIDATES+=("${configured_port}")
  done < <(/usr/sbin/sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' || true)
fi
((${#SSH_PORT_CANDIDATES[@]})) || SSH_PORT_CANDIDATES=(22)
mapfile -t SSH_PORTS < <(printf '%s\n' "${SSH_PORT_CANDIDATES[@]}" | sort -nu)
for ssh_port in "${SSH_PORTS[@]}"; do
  ufw allow "${ssh_port}/tcp" comment 'SSH' >/dev/null
done
ufw allow 80/tcp comment 'HTTP certificate validation' >/dev/null
ufw allow 443/tcp comment 'HTTPS' >/dev/null
ufw --force enable >/dev/null

MODE=ip
DOMAIN=
if [[ -r /dev/tty ]]; then
  printf '\nDo you already have a domain pointing to this VPS? [y/N] ' >/dev/tty
  read -r HAS_DOMAIN </dev/tty || true
  if [[ "${HAS_DOMAIN:-}" =~ ^[Yy]$ ]]; then
    MODE=domain
    printf 'Domain name: ' >/dev/tty
    read -r DOMAIN </dev/tty
    DOMAIN="$(printf '%s' "${DOMAIN}" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')"
    /usr/bin/python3 - "${DOMAIN}" "${PUBLIC_IP}" "${PUBLIC_IPV6}" <<'PY'
import socket, sys
import ipaddress
domain, expected_v4, expected_v6 = sys.argv[1:]
try:
    answers = socket.getaddrinfo(domain, 443, 0, socket.SOCK_STREAM)
except socket.gaierror as exc:
    raise SystemExit(f"The domain does not resolve yet: {exc}")
ipv4 = {str(ipaddress.ip_address(item[4][0])) for item in answers if item[0] == socket.AF_INET}
ipv6 = {str(ipaddress.ip_address(item[4][0])) for item in answers if item[0] == socket.AF_INET6}
if ipv4 != {expected_v4}:
    raise SystemExit("Every domain A answer must point only to this VPS.")
if ipv6 and ipv6 != {expected_v6}:
    raise SystemExit("Every domain AAAA answer must point only to this VPS. Remove or correct it.")
PY
  fi
fi

log "Preparing certificate challenge"
rm -f /etc/nginx/sites-enabled/default
cat >/etc/nginx/sites-available/vpnctl <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    access_log off;
    location ^~ /.well-known/acme-challenge/ { root /var/www/vpnctl-acme; }
    location / { return 404; }
}
EOF
ln -sfn /etc/nginx/sites-available/vpnctl /etc/nginx/sites-enabled/vpnctl
sed -ri 's/worker_connections[[:space:]]+[0-9]+;/worker_connections 4096;/' /etc/nginx/nginx.conf
nginx -t
systemctl enable --now nginx
systemctl reload nginx

if [[ "${MODE}" == domain ]]; then
  log "Issuing domain certificate"
  /snap/bin/certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
    --webroot --webroot-path "${ACME_ROOT}" --cert-name "${DOMAIN}" --domains "${DOMAIN}"
else
  log "Issuing short-lived public IP certificate"
  /snap/bin/certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
    --preferred-profile shortlived --webroot --webroot-path "${ACME_ROOT}" \
    --cert-name "${PUBLIC_IP}" --ip-address "${PUBLIC_IP}"
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=localhost' \
  -keyout /etc/vpnctl/tls/default.key -out /etc/vpnctl/tls/default.crt >/dev/null 2>&1
chmod 0600 /etc/vpnctl/tls/default.key
chmod 0644 /etc/vpnctl/tls/default.crt

log "Generating private configuration"
BOOTSTRAP=(/usr/bin/python3 -m vpnctl.bootstrap --public-ip "${PUBLIC_IP}" --output "${RESULT_FILE}")
[[ -n "${PUBLIC_IPV6}" ]] && BOOTSTRAP+=(--public-ipv6 "${PUBLIC_IPV6}")
[[ "${MODE}" == domain ]] && BOOTSTRAP+=(--domain "${DOMAIN}")
PYTHONPATH="${INSTALL_DIR}/src" "${BOOTSTRAP[@]}"
PYTHONPATH="${INSTALL_DIR}/src" XRAY_LOCATION_ASSET=/usr/local/share/xray /usr/bin/python3 - <<'PY'
from vpnctl.agent import install_nginx, load_state, validate_and_install_xray
state = load_state()
validate_and_install_xray(state)
install_nginx(state)
PY

install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat >/etc/letsencrypt/renewal-hooks/deploy/reload-nginx <<'EOF'
#!/usr/bin/env bash
set -eu
/usr/sbin/nginx -t
/bin/systemctl reload nginx
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/reload-nginx

install -d -m 0755 /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/vpnctl.conf <<'EOF'
[Journal]
SystemMaxUse=128M
RuntimeMaxUse=64M
MaxRetentionSec=7day
EOF
systemctl restart systemd-journald
systemctl daemon-reload
systemctl enable --now xray vpnctl-agent vpnctl-web vpnctl-health.timer

log "Configuring firewall"
ufw status verbose

log "Running final checks"
nginx -t
/usr/local/bin/xray run -test -config /etc/vpnctl/xray.json
sleep 2
vpnctl doctor
/snap/bin/certbot certificates >/dev/null
systemctl is-enabled snap.certbot.renew.timer >/dev/null

PANEL_URL="$(/usr/bin/python3 -c 'import json; print(json.load(open("/root/vpnctl-install.json"))["panel_url"])')"
USERNAME="$(/usr/bin/python3 -c 'import json; print(json.load(open("/root/vpnctl-install.json"))["username"])')"
PASSWORD="$(/usr/bin/python3 -c 'import json; print(json.load(open("/root/vpnctl-install.json"))["password"])')"
CLIENT_URI="$(/usr/bin/python3 -c 'import json; print(json.load(open("/root/vpnctl-install.json"))["client_uri"])')"

printf '\nInstallation complete.\n\nPanel: %s\nLogin: %s\nPassword: %s\n\nv2RayTun import link:\n%s\n\n' \
  "${PANEL_URL}" "${USERNAME}" "${PASSWORD}" "${CLIENT_URI}"
printf '%s' "${CLIENT_URI}" | qrencode -t ANSIUTF8
printf '\nA root-only copy is stored in %s. Delete it after saving the credentials.\n' "${RESULT_FILE}"
if [[ "${MODE}" == ip ]]; then
  printf 'IP mode is ready. Sign in to the panel and follow Domain setup for the recommended permanent configuration.\n'
fi
