#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/reality-target.sh
source "${ROOT}/scripts/reality-target.sh"
TRUE_BIN="$(command -v true)"

reality_ipv4_asn() { printf '%s\n' 64500; }
reality_target_asn() {
  case "$1" in
    cloudflare) printf '%s\n' 13335 ;;
    same-asn) printf '%s\n' 64500 ;;
    *) printf '%s\n' 64501 ;;
  esac
}

reality_select_target 192.0.2.10 "fallback,cloudflare,same-asn" "${TRUE_BIN}"
[[ "${REALITY_SELECTED_TARGET}" == same-asn ]]
[[ "${REALITY_TARGET_MODE}" == same-asn ]]
[[ "${REALITY_TARGET_ASN}" == 64500 ]]

reality_target_asn() { printf '%s\n' 64501; }
reality_select_target 192.0.2.10 "fallback,second" "${TRUE_BIN}"
[[ "${REALITY_SELECTED_TARGET}" == fallback ]]
[[ "${REALITY_TARGET_MODE}" == fallback ]]
