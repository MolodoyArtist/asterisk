#!/usr/bin/env bash
set -Eeuo pipefail

[[ "${EUID}" -eq 0 || "${VPNCTL_SMOKE_ALLOW_NONROOT:-0}" == 1 ]] || { echo 'run as root' >&2; exit 1; }

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_ROOT="$(mktemp -d /tmp/vpnctl-update-smoke.XXXXXX)"
trap 'rm -rf -- "${TEMP_ROOT}"' EXIT

make_fake_command() {
  local path=$1
  cat >"${path}" <<'EOF'
#!/usr/bin/env bash
set -eu
if [[ "${0##*/}" == vpnctl && "${VPNCTL_SMOKE_FAIL_DOCTOR:-0}" == 1 ]]; then
  exit 1
fi
if [[ "${0##*/}" == xray && "${1:-}" == x25519 ]]; then
  printf '%s\n' 'Private key: smoke-private-key' 'Public key: smoke-public-key'
fi
exit 0
EOF
  chmod 0755 "${path}"
}

prepare_case() {
  local case_dir=$1
  mkdir -p "${case_dir}/install/src" "${case_dir}/state" "${case_dir}/config" \
    "${case_dir}/nginx" "${case_dir}/systemd" "${case_dir}/bin"
  cp -a "${ROOT}/src/." "${case_dir}/install/src/"
  touch "${case_dir}/install/src/old-version-marker"
  cat >"${case_dir}/state/state.json" <<'EOF'
{
  "schema": 1,
  "created_at": 1,
  "public_ip": "192.0.2.10",
  "public_ipv6": null,
  "domain": null,
  "xhttp_path": "A_random_path_with_enough_entropy",
  "clients": [
    {"name": "phone", "id": "00000000-0000-4000-8000-000000000001", "enabled": true}
  ]
}
EOF
  printf '%s\n' 'old xray configuration' >"${case_dir}/config/xray.json"
  printf '%s\n' 'old nginx configuration' >"${case_dir}/nginx/vpnctl"
  for unit in vpnctl-agent.service vpnctl-web.service vpnctl-health.service vpnctl-health.timer xray.service; do
    printf 'old %s\n' "${unit}" >"${case_dir}/systemd/${unit}"
  done
  for command in systemctl nginx xray vpnctl ufw; do
    make_fake_command "${case_dir}/bin/${command}"
  done
  mkdir -p "${case_dir}/xray-stage"
  cp -a "${case_dir}/bin/xray" "${case_dir}/xray-stage/xray"
  printf '%s\n' 'new geoip' >"${case_dir}/xray-stage/geoip.dat"
  printf '%s\n' 'new geosite' >"${case_dir}/xray-stage/geosite.dat"
}

run_update() {
  local case_dir=$1 fail_doctor=$2
  VPNCTL_INSTALL_DIR="${case_dir}/install" \
  VPNCTL_STATE_FILE="${case_dir}/state/state.json" \
  VPNCTL_XRAY_CONFIG="${case_dir}/config/xray.json" \
  VPNCTL_NGINX_SITE="${case_dir}/nginx/vpnctl" \
  VPNCTL_SYSTEMD_DIR="${case_dir}/systemd" \
  VPNCTL_SYSTEMCTL_BIN="${case_dir}/bin/systemctl" \
  VPNCTL_NGINX_BIN="${case_dir}/bin/nginx" \
  VPNCTL_XRAY_BIN="${case_dir}/bin/xray" \
  VPNCTL_XRAY_ASSET_DIR="${case_dir}/assets" \
  VPNCTL_XRAY_STAGE_DIR="${case_dir}/xray-stage" \
  VPNCTL_CLI_BIN="${case_dir}/bin/vpnctl" \
  VPNCTL_UFW_BIN="${case_dir}/bin/ufw" \
  VPNCTL_HELPER_DIR="${case_dir}/helpers" \
  VPNCTL_PYTHON_BIN=/usr/bin/python3 \
  VPNCTL_LOCK_HELD=1 \
  VPNCTL_SMOKE_FAIL_DOCTOR="${fail_doctor}" \
  VPNCTL_SMOKE_ALLOW_NONROOT=1 bash "${ROOT}/scripts/update.sh"
}

success_dir="${TEMP_ROOT}/success"
prepare_case "${success_dir}"
mkdir -p "${success_dir}/assets"
printf '%s\n' 'old geoip' >"${success_dir}/assets/geoip.dat"
printf '%s\n' 'old geosite' >"${success_dir}/assets/geosite.dat"
run_update "${success_dir}" 0
[[ ! -e "${success_dir}/install/src/old-version-marker" ]]
grep -q '^Wants=nginx.service xray.service$' "${success_dir}/systemd/vpnctl-agent.service"
grep -q '"schema": 2' "${success_dir}/state/state.json"
grep -q '"layout": "legacy-xhttp-primary"' "${success_dir}/state/state.json"
grep -q '00000000-0000-4000-8000-000000000001' "${success_dir}/state/state.json"
grep -q '^new geoip$' "${success_dir}/assets/geoip.dat"

rollback_dir="${TEMP_ROOT}/rollback"
prepare_case "${rollback_dir}"
mkdir -p "${rollback_dir}/assets"
printf '%s\n' 'old geoip' >"${rollback_dir}/assets/geoip.dat"
printf '%s\n' 'old geosite' >"${rollback_dir}/assets/geosite.dat"
state_before="$(sha256sum "${rollback_dir}/state/state.json" | awk '{print $1}')"
if run_update "${rollback_dir}" 1; then
  echo 'the intentionally failing update unexpectedly succeeded' >&2
  exit 1
fi
[[ -e "${rollback_dir}/install/src/old-version-marker" ]]
grep -q '^old vpnctl-agent.service$' "${rollback_dir}/systemd/vpnctl-agent.service"
grep -q '^old xray configuration$' "${rollback_dir}/config/xray.json"
grep -q '^old nginx configuration$' "${rollback_dir}/nginx/vpnctl"
grep -q '^old geoip$' "${rollback_dir}/assets/geoip.dat"
[[ "$(sha256sum "${rollback_dir}/state/state.json" | awk '{print $1}')" == "${state_before}" ]]

recovery_dir="${TEMP_ROOT}/existing-recovery"
prepare_case "${recovery_dir}"
mkdir -p "${recovery_dir}/install/src.update" "${recovery_dir}/install/src.rollback"
touch "${recovery_dir}/install/src.update/keep-staged" "${recovery_dir}/install/src.rollback/keep-backup"
if run_update "${recovery_dir}" 0; then
  echo 'an update with existing recovery data unexpectedly succeeded' >&2
  exit 1
fi
[[ -e "${recovery_dir}/install/src.update/keep-staged" ]]
[[ -e "${recovery_dir}/install/src.rollback/keep-backup" ]]

echo 'update smoke tests passed'
