#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

INSTALL_DIR="${VPNCTL_INSTALL_DIR:-/opt/vpnctl}"
STATE_FILE="${VPNCTL_STATE_FILE:-/var/lib/vpnctl/state.json}"
XRAY_CONFIG="${VPNCTL_XRAY_CONFIG:-/etc/vpnctl/xray.json}"
NGINX_SITE="${VPNCTL_NGINX_SITE:-/etc/nginx/sites-available/vpnctl}"
SYSTEMD_DIR="${VPNCTL_SYSTEMD_DIR:-/etc/systemd/system}"
SYSTEMCTL_BIN="${VPNCTL_SYSTEMCTL_BIN:-/usr/bin/systemctl}"
NGINX_BIN="${VPNCTL_NGINX_BIN:-/usr/sbin/nginx}"
XRAY_BIN="${VPNCTL_XRAY_BIN:-/usr/local/bin/xray}"
XRAY_ASSET_DIR="${VPNCTL_XRAY_ASSET_DIR:-/usr/local/share/xray}"
AUTH_FILE="${VPNCTL_AUTH_FILE:-/var/lib/vpnctl/auth.json}"
CLI_BIN="${VPNCTL_CLI_BIN:-/usr/local/bin/vpnctl}"
PYTHON_BIN="${VPNCTL_PYTHON_BIN:-/usr/bin/python3}"
HELPER_DIR="${VPNCTL_HELPER_DIR:-/usr/local/lib/vpnctl}"
UFW_APP_DIR="${VPNCTL_UFW_APP_DIR:-/etc/ufw/applications.d}"
UFW_APP_FILE="${UFW_APP_DIR}/vpnctl-mtproxy"
MTPROXY_ENV="${VPNCTL_MTPROXY_ENV:-/etc/mtproxy/vpnctl.env}"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR="$(mktemp -d /tmp/vpnctl-update.XXXXXX)"
STAGED_SRC="${INSTALL_DIR}/src.update"
BACKUP_SRC="${INSTALL_DIR}/src.rollback"
STAGED_XRAY="${TEMP_DIR}/xray"
ROLLBACK_READY=0
STAGED_OWNED=0
BACKUP_OWNED=0

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

finish() {
  local status=$?
  local restore_failed=0
  trap - EXIT INT TERM
  set +e
  if [[ "${status}" -ne 0 && "${ROLLBACK_READY}" -eq 1 ]]; then
    printf '\nUpdate failed; restoring the previous installation.\n' >&2
    if [[ "${BACKUP_OWNED}" -eq 1 && -d "${BACKUP_SRC}" ]]; then
      rm -rf -- "${INSTALL_DIR}/src" || restore_failed=1
      if mv "${BACKUP_SRC}" "${INSTALL_DIR}/src"; then
        BACKUP_OWNED=0
      else
        restore_failed=1
      fi
    else
      restore_failed=1
    fi
    for unit in vpnctl-agent.service vpnctl-web.service vpnctl-health.service vpnctl-health.timer xray.service mtproxy.service mtproxy-refresh.service mtproxy-refresh.timer vpnctl-mtproxy-provision.service vpnctl-mtproxy-configure.service vpnctl-mtproxy-cleanup.service; do
      if [[ -f "${TEMP_DIR}/units/${unit}" ]]; then
        install -m 0644 "${TEMP_DIR}/units/${unit}" "${SYSTEMD_DIR}/${unit}" || restore_failed=1
      elif [[ -f "${TEMP_DIR}/units/${unit}.missing" ]]; then
        rm -f -- "${SYSTEMD_DIR}/${unit}" || restore_failed=1
      else
        restore_failed=1
      fi
    done
    cp -a "${TEMP_DIR}/xray.json" "${XRAY_CONFIG}" || restore_failed=1
    cp -a "${TEMP_DIR}/vpnctl.nginx" "${NGINX_SITE}" || restore_failed=1
    cp -a "${TEMP_DIR}/state.json" "${STATE_FILE}" || restore_failed=1
    if [[ -f "${TEMP_DIR}/auth.json" ]]; then
      cp -a "${TEMP_DIR}/auth.json" "${AUTH_FILE}" || restore_failed=1
    fi
    if [[ -f "${TEMP_DIR}/mtproxy.env" ]]; then
      install -d -m 0750 "$(dirname -- "${MTPROXY_ENV}")" || restore_failed=1
      cp -a "${TEMP_DIR}/mtproxy.env" "${MTPROXY_ENV}" || restore_failed=1
    else
      rm -f -- "${MTPROXY_ENV}" || restore_failed=1
    fi
    if [[ -d "${TEMP_DIR}/helpers" ]]; then
      install -m 0755 "${TEMP_DIR}/helpers/mtproxy" "${HELPER_DIR}/mtproxy" || restore_failed=1
      install -m 0755 "${TEMP_DIR}/helpers/mtproxy-run" "${HELPER_DIR}/mtproxy-run" || restore_failed=1
    else
      rm -f -- "${HELPER_DIR}/mtproxy" "${HELPER_DIR}/mtproxy-run" || restore_failed=1
    fi
    if [[ -f "${TEMP_DIR}/mtproxy.ufw-profile" ]]; then
      install -d -m 0755 "${UFW_APP_DIR}" || restore_failed=1
      cp -a "${TEMP_DIR}/mtproxy.ufw-profile" "${UFW_APP_FILE}" || restore_failed=1
    else
      rm -f -- "${UFW_APP_FILE}" || restore_failed=1
    fi
    if [[ -f "${TEMP_DIR}/xray.binary" && -d "${TEMP_DIR}/xray-assets" ]]; then
      install -m 0755 "${TEMP_DIR}/xray.binary" "${XRAY_BIN}" || restore_failed=1
      install -d -m 0755 "${XRAY_ASSET_DIR}" || restore_failed=1
      install -m 0644 "${TEMP_DIR}/xray-assets/geoip.dat" "${TEMP_DIR}/xray-assets/geosite.dat" "${XRAY_ASSET_DIR}/" || restore_failed=1
    else
      restore_failed=1
    fi
    "${SYSTEMCTL_BIN}" daemon-reload || restore_failed=1
    "${NGINX_BIN}" -t || restore_failed=1
    "${SYSTEMCTL_BIN}" reload nginx || restore_failed=1
    "${SYSTEMCTL_BIN}" restart xray vpnctl-agent vpnctl-web || restore_failed=1
    if "${SYSTEMCTL_BIN}" is-enabled --quiet mtproxy; then
      "${SYSTEMCTL_BIN}" restart mtproxy || true
    fi
    if [[ "${restore_failed}" -eq 0 ]]; then
      ROLLBACK_READY=0
    else
      printf 'Automatic rollback was incomplete. Recovery files were preserved at %s and %s.\n' \
        "${BACKUP_SRC}" "${TEMP_DIR}" >&2
    fi
  fi
  if [[ "${restore_failed}" -eq 0 ]]; then
    rm -rf -- "${TEMP_DIR}"
    if [[ "${STAGED_OWNED}" -eq 1 ]]; then
      rm -rf -- "${STAGED_SRC}"
    fi
    if [[ "${BACKUP_OWNED}" -eq 1 && "${ROLLBACK_READY}" -eq 0 ]]; then
      rm -rf -- "${BACKUP_SRC}"
    fi
  fi
  exit "${status}"
}

trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ "${EUID}" -eq 0 || "${VPNCTL_SMOKE_ALLOW_NONROOT:-0}" == 1 ]] || die "Run this updater as root."
[[ -f "${STATE_FILE}" ]] || die "vpnctl is not installed."
[[ -d "${INSTALL_DIR}/src" ]] || die "The existing installation is incomplete."
[[ -f "${ROOT}/src/vpnctl/common.py" ]] || die "Update sources are incomplete."
if [[ "${VPNCTL_LOCK_HELD:-0}" != 1 ]]; then
  exec 9>/run/vpnctl-install.lock
  flock -n 9 || die "An install or update is already running."
fi
[[ ! -e "${STAGED_SRC}" && ! -e "${BACKUP_SRC}" ]] || die "A previous update needs manual recovery."

log "Staging and validating new files"
cp -a "${ROOT}/src" "${STAGED_SRC}"
STAGED_OWNED=1
find "${STAGED_SRC}" -type d -exec chmod 0755 {} +
find "${STAGED_SRC}" -type f -exec chmod 0644 {} +
PYTHONPATH="${STAGED_SRC}" VPNCTL_STATE_DIR="$(dirname -- "${STATE_FILE}")" "${PYTHON_BIN}" -m compileall -q "${STAGED_SRC}"
"${PYTHON_BIN}" - "${STATE_FILE}" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(value, dict) or value.get("schema") not in (1, 2):
    raise SystemExit("unsupported state schema")
PY
bash -n "${ROOT}/install.sh" "${ROOT}"/scripts/*.sh
# shellcheck source=scripts/xray.sh
source "${ROOT}/scripts/xray.sh"
log "Staging pinned Xray ${XRAY_VERSION}"
if [[ -n "${VPNCTL_XRAY_STAGE_DIR:-}" ]]; then
  [[ -x "${VPNCTL_XRAY_STAGE_DIR}/xray" && -f "${VPNCTL_XRAY_STAGE_DIR}/geoip.dat" && -f "${VPNCTL_XRAY_STAGE_DIR}/geosite.dat" ]] || die "VPNCTL_XRAY_STAGE_DIR is incomplete."
  mkdir -p "${STAGED_XRAY}/payload"
  cp -a "${VPNCTL_XRAY_STAGE_DIR}/." "${STAGED_XRAY}/payload/"
else
  xray_stage "${STAGED_XRAY}" || die "Could not stage the verified Xray release."
fi

install -d -m 0700 "${TEMP_DIR}/units"
for unit in vpnctl-agent.service vpnctl-web.service vpnctl-health.service vpnctl-health.timer xray.service mtproxy.service mtproxy-refresh.service mtproxy-refresh.timer vpnctl-mtproxy-provision.service vpnctl-mtproxy-configure.service vpnctl-mtproxy-cleanup.service; do
  if [[ -f "${SYSTEMD_DIR}/${unit}" ]]; then
    cp -a "${SYSTEMD_DIR}/${unit}" "${TEMP_DIR}/units/${unit}"
  else
    touch "${TEMP_DIR}/units/${unit}.missing"
  fi
done
cp -a "${XRAY_CONFIG}" "${TEMP_DIR}/xray.json"
cp -a "${NGINX_SITE}" "${TEMP_DIR}/vpnctl.nginx"
cp -a "${STATE_FILE}" "${TEMP_DIR}/state.json"
[[ -f "${AUTH_FILE}" ]] && cp -a "${AUTH_FILE}" "${TEMP_DIR}/auth.json"
[[ -f "${MTPROXY_ENV}" ]] && cp -a "${MTPROXY_ENV}" "${TEMP_DIR}/mtproxy.env"
[[ -f "${UFW_APP_FILE}" ]] && cp -a "${UFW_APP_FILE}" "${TEMP_DIR}/mtproxy.ufw-profile"
if [[ -x "${HELPER_DIR}/mtproxy" && -x "${HELPER_DIR}/mtproxy-run" ]]; then
  install -d -m 0700 "${TEMP_DIR}/helpers"
  cp -a "${HELPER_DIR}/mtproxy" "${HELPER_DIR}/mtproxy-run" "${TEMP_DIR}/helpers/"
fi
cp -a "${XRAY_BIN}" "${TEMP_DIR}/xray.binary"
install -d -m 0700 "${TEMP_DIR}/xray-assets"
cp -a "${XRAY_ASSET_DIR}/geoip.dat" "${XRAY_ASSET_DIR}/geosite.dat" "${TEMP_DIR}/xray-assets/"
ROLLBACK_READY=1
mv "${INSTALL_DIR}/src" "${BACKUP_SRC}"
BACKUP_OWNED=1
mv "${STAGED_SRC}" "${INSTALL_DIR}/src"
STAGED_OWNED=0
install -m 0644 "${ROOT}"/systemd/*.service "${ROOT}"/systemd/*.timer "${SYSTEMD_DIR}/"
install -d -m 0755 "${HELPER_DIR}"
install -m 0755 "${ROOT}/scripts/mtproxy.sh" "${HELPER_DIR}/mtproxy"
install -m 0755 "${ROOT}/scripts/mtproxy-run" "${HELPER_DIR}/mtproxy-run"
install -d -m 0755 "${UFW_APP_DIR}"
install -m 0644 "${ROOT}/ufw/vpnctl-mtproxy" "${UFW_APP_DIR}/vpnctl-mtproxy"

log "Regenerating configuration"
"${SYSTEMCTL_BIN}" daemon-reload
log "Migrating saved settings when needed"
PYTHONPATH="${INSTALL_DIR}/src" "${PYTHON_BIN}" -m vpnctl.migrate \
  --state-file "${STATE_FILE}"
PYTHONPATH="${INSTALL_DIR}/src" \
VPNCTL_STATE_DIR="$(dirname -- "${STATE_FILE}")" \
VPNCTL_CONFIG_DIR="$(dirname -- "${XRAY_CONFIG}")" \
VPNCTL_NGINX_SITE="${NGINX_SITE}" \
VPNCTL_XRAY_BIN="${STAGED_XRAY}/payload/xray" \
VPNCTL_SYSTEMCTL_BIN="${SYSTEMCTL_BIN}" \
VPNCTL_NGINX_BIN="${NGINX_BIN}" \
XRAY_LOCATION_ASSET="${STAGED_XRAY}/payload" \
"${PYTHON_BIN}" - <<'PY'
from vpnctl.agent import install_nginx, load_state, validate_and_install_xray
state = load_state()
validate_and_install_xray(state)
install_nginx(state)
PY

log "Installing verified Xray ${XRAY_VERSION}"
xray_install_stage "${STAGED_XRAY}" "${XRAY_BIN}" "${XRAY_ASSET_DIR}"
XRAY_LOCATION_ASSET="${XRAY_ASSET_DIR}" "${XRAY_BIN}" run -test -config "${XRAY_CONFIG}"

log "Restarting services"
"${SYSTEMCTL_BIN}" restart xray vpnctl-agent vpnctl-web
if "${SYSTEMCTL_BIN}" is-enabled --quiet mtproxy; then
  "${SYSTEMCTL_BIN}" restart mtproxy
fi
"${SYSTEMCTL_BIN}" enable --now vpnctl-health.timer
sleep 2
"${CLI_BIN}" doctor

ROLLBACK_READY=0
rm -rf -- "${BACKUP_SRC}"
BACKUP_OWNED=0
log "Update complete"
