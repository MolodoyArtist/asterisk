#!/usr/bin/env bash
# Install the official Telegram MTProxy from a reviewed, immutable source archive.
set -Eeuo pipefail
umask 077

MTPROXY_COMMIT="f36d8af769ffaeac36978d38c2c0f6d1104c2137"
MTPROXY_SHA256="919795c416b870670841a21d1930ad97a24c7b84b9eb8c6f9e3de32f2fdf4655"
MTPROXY_DIR="${VPNCTL_MTPROXY_DIR:-/opt/MTProxy}"
MTPROXY_ETC="${VPNCTL_MTPROXY_ETC:-/etc/mtproxy}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || die "Run as root."

ensure_user() {
  id mtproxy >/dev/null 2>&1 || useradd --system --home /nonexistent --shell /usr/sbin/nologin mtproxy
}

prepare() {
  [[ "$(uname -m)" == "x86_64" ]] || die "The optional official Telegram MTProxy build currently requires an x86_64 VPS."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends build-essential ca-certificates curl libssl-dev zlib1g-dev
  ensure_user
  if [[ -x "${MTPROXY_DIR}/objs/bin/mtproto-proxy" && -f "${MTPROXY_DIR}/.vpnctl-commit" ]] && grep -Fxq "${MTPROXY_COMMIT}" "${MTPROXY_DIR}/.vpnctl-commit"; then
    return
  fi
  local temporary archive source
  temporary="$(mktemp -d /tmp/vpnctl-mtproxy.XXXXXX)"
  trap 'rm -rf -- "${temporary}"' RETURN
  archive="${temporary}/mtproxy.tar.gz"
  source="${temporary}/source"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --output "${archive}" "https://github.com/TelegramMessenger/MTProxy/archive/${MTPROXY_COMMIT}.tar.gz"
  [[ "$(sha256sum "${archive}" | awk '{print $1}')" == "${MTPROXY_SHA256}" ]] || die "MTProxy source checksum mismatch."
  install -d -o mtproxy -g mtproxy -m 0755 "${source}"
  tar -C "${source}" --strip-components=1 -xzf "${archive}"
  chown -R mtproxy:mtproxy "${source}"
  runuser -u mtproxy -- make -C "${source}" -j"$(nproc)"
  [[ -x "${source}/objs/bin/mtproto-proxy" ]] || die "MTProxy build did not produce its binary."
  printf '%s\n' "${MTPROXY_COMMIT}" >"${source}/.vpnctl-commit"
  chown -R root:root "${source}"
  find "${source}" -type d -exec chmod 0755 {} +
  chmod 0755 "${source}/objs/bin/mtproto-proxy"
  if [[ -e "${MTPROXY_DIR}" ]]; then
    mv "${MTPROXY_DIR}" "${MTPROXY_DIR}.previous.$(date +%Y%m%d%H%M%S)"
  fi
  mv "${source}" "${MTPROXY_DIR}"
  install -d -o root -g mtproxy -m 0750 "${MTPROXY_ETC}"
}

refresh() {
  [[ -d "${MTPROXY_ETC}" ]] || exit 0
  local temporary upstream_key config
  temporary="$(mktemp -d /tmp/vpnctl-mtproxy-refresh.XXXXXX)"
  trap 'rm -rf -- "${temporary}"' RETURN
  upstream_key="${temporary}/proxy-secret"
  config="${temporary}/proxy-multi.conf"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "${upstream_key}" https://core.telegram.org/getProxySecret
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "${config}" https://core.telegram.org/getProxyConfig
  [[ "$(wc -c < "${upstream_key}")" -eq 128 ]] || die "Telegram proxy secret has an unexpected format."
  if [[ "$(wc -c < "${config}")" -lt 100 ]] || ! grep -q '^default ' "${config}" || ! grep -q '^proxy_for ' "${config}"; then
    die "Telegram proxy configuration has an unexpected format."
  fi
  install -o root -g mtproxy -m 0640 "${upstream_key}" "${MTPROXY_ETC}/proxy-secret"
  install -o root -g mtproxy -m 0640 "${config}" "${MTPROXY_ETC}/proxy-multi.conf"
}

case "${1:-}" in
  prepare) prepare ;;
  refresh) refresh ;;
  *) die "Usage: $0 {prepare|refresh}" ;;
esac
