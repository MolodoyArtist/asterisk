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
CLI_BIN="${VPNCTL_CLI_BIN:-/usr/local/bin/vpnctl}"
PYTHON_BIN="${VPNCTL_PYTHON_BIN:-/usr/bin/python3}"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR="$(mktemp -d /tmp/vpnctl-update.XXXXXX)"
STAGED_SRC="${INSTALL_DIR}/src.update"
BACKUP_SRC="${INSTALL_DIR}/src.rollback"
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
    for unit in vpnctl-agent.service vpnctl-web.service vpnctl-health.service vpnctl-health.timer xray.service; do
      if [[ -f "${TEMP_DIR}/units/${unit}" ]]; then
        install -m 0644 "${TEMP_DIR}/units/${unit}" "${SYSTEMD_DIR}/${unit}" || restore_failed=1
      else
        restore_failed=1
      fi
    done
    cp -a "${TEMP_DIR}/xray.json" "${XRAY_CONFIG}" || restore_failed=1
    cp -a "${TEMP_DIR}/vpnctl.nginx" "${NGINX_SITE}" || restore_failed=1
    "${SYSTEMCTL_BIN}" daemon-reload || restore_failed=1
    "${NGINX_BIN}" -t || restore_failed=1
    "${SYSTEMCTL_BIN}" reload nginx || restore_failed=1
    "${SYSTEMCTL_BIN}" restart xray vpnctl-agent vpnctl-web || restore_failed=1
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

[[ "${EUID}" -eq 0 ]] || die "Run this updater as root."
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
PYTHONPATH="${STAGED_SRC}" VPNCTL_STATE_DIR="$(dirname -- "${STATE_FILE}")" "${PYTHON_BIN}" - <<'PY'
from vpnctl.common import load_state
load_state()
PY
bash -n "${ROOT}/install.sh" "${ROOT}/scripts/check-repository.sh" "${ROOT}/scripts/integration-smoke.sh" "${ROOT}/scripts/update.sh" "${ROOT}/scripts/update-smoke.sh"

install -d -m 0700 "${TEMP_DIR}/units"
for unit in vpnctl-agent.service vpnctl-web.service vpnctl-health.service vpnctl-health.timer xray.service; do
  cp -a "${SYSTEMD_DIR}/${unit}" "${TEMP_DIR}/units/${unit}"
done
cp -a "${XRAY_CONFIG}" "${TEMP_DIR}/xray.json"
cp -a "${NGINX_SITE}" "${TEMP_DIR}/vpnctl.nginx"
ROLLBACK_READY=1
mv "${INSTALL_DIR}/src" "${BACKUP_SRC}"
BACKUP_OWNED=1
mv "${STAGED_SRC}" "${INSTALL_DIR}/src"
STAGED_OWNED=0
install -m 0644 "${ROOT}"/systemd/*.service "${ROOT}"/systemd/*.timer "${SYSTEMD_DIR}/"

log "Regenerating configuration"
"${SYSTEMCTL_BIN}" daemon-reload
PYTHONPATH="${INSTALL_DIR}/src" \
VPNCTL_STATE_DIR="$(dirname -- "${STATE_FILE}")" \
VPNCTL_CONFIG_DIR="$(dirname -- "${XRAY_CONFIG}")" \
VPNCTL_NGINX_SITE="${NGINX_SITE}" \
VPNCTL_XRAY_BIN="${XRAY_BIN}" \
VPNCTL_SYSTEMCTL_BIN="${SYSTEMCTL_BIN}" \
VPNCTL_NGINX_BIN="${NGINX_BIN}" \
XRAY_LOCATION_ASSET=/usr/local/share/xray \
"${PYTHON_BIN}" - <<'PY'
from vpnctl.agent import install_nginx, load_state, validate_and_install_xray
state = load_state()
validate_and_install_xray(state)
install_nginx(state)
PY

log "Restarting services"
"${SYSTEMCTL_BIN}" restart xray vpnctl-agent vpnctl-web
"${SYSTEMCTL_BIN}" enable --now vpnctl-health.timer
sleep 2
"${CLI_BIN}" doctor

ROLLBACK_READY=0
rm -rf -- "${BACKUP_SRC}"
BACKUP_OWNED=0
log "Update complete"
