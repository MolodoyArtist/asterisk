#!/usr/bin/env bash
# Shared, pinned Xray distribution handling. Source this file; do not execute it.

XRAY_VERSION="${VPNCTL_XRAY_VERSION:-v26.6.1}"

xray_platform() {
  case "$(uname -m)" in
    x86_64) printf '%s\n' 64 ;;
    aarch64|arm64) printf '%s\n' arm64-v8a ;;
    *) printf '%s\n' 'Only x86_64 and arm64 VPS architectures are supported.' >&2; return 1 ;;
  esac
}

xray_sha256() {
  local arch=$1
  case "${XRAY_VERSION}:${arch}" in
    v26.6.1:64) printf '%s\n' '136e822e99e616692550723e8b607cd8858c62a390aea5704938bc27930904ba' ;;
    v26.6.1:arm64-v8a) printf '%s\n' '5c0f397b2605a853e5b308ae6485ad2ec395ca11ed7ae0fd023c480c7fdb279d' ;;
    *) printf '%s\n' "No reviewed SHA-256 is pinned for Xray ${XRAY_VERSION} (${arch})." >&2; return 1 ;;
  esac
}

xray_stage() {
  local destination=$1 arch expected archive actual
  arch="$(xray_platform)" || return 1
  expected="$(xray_sha256 "${arch}")" || return 1
  archive="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${arch}.zip"
  mkdir -p "${destination}"
  curl --fail --show-error --location --proto '=https' --tlsv1.2 "${archive}" -o "${destination}/xray.zip"
  actual="$(sha256sum "${destination}/xray.zip" | awk '{print $1}')"
  [[ "${actual}" == "${expected}" ]] || { printf '%s\n' 'Xray checksum verification failed.' >&2; return 1; }
  unzip -q "${destination}/xray.zip" -d "${destination}/payload"
  [[ -x "${destination}/payload/xray" && -f "${destination}/payload/geoip.dat" && -f "${destination}/payload/geosite.dat" ]] || {
    printf '%s\n' 'The verified Xray archive is incomplete.' >&2
    return 1
  }
}

xray_install_stage() {
  local stage=$1 binary=$2 assets=$3 temporary
  install -d -m 0755 "${assets}"
  temporary="$(mktemp "$(dirname "${binary}")/.xray.XXXXXX")"
  install -m 0755 "${stage}/payload/xray" "${temporary}"
  mv -f "${temporary}" "${binary}"
  for asset in geoip.dat geosite.dat; do
    temporary="$(mktemp "${assets}/.${asset}.XXXXXX")"
    install -m 0644 "${stage}/payload/${asset}" "${temporary}"
    mv -f "${temporary}" "${assets}/${asset}"
  done
}
