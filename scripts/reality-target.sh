#!/usr/bin/env bash
# Candidate selection for REALITY. This deliberately ranks only supplied
# hostnames: there is no reliable way to invent a same-AS HTTPS hostname for
# every VPS provider.

REALITY_DIG_BIN="${VPNCTL_DIG_BIN:-/usr/bin/dig}"

reality_ipv4_asn() {
  local address reversed answer
  [[ "${1:-}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r a b c d <<<"${1}"
  reversed="${d}.${c}.${b}.${a}.origin.asn.cymru.com"
  answer="$("${REALITY_DIG_BIN}" +timeout=3 +tries=1 +short TXT "${reversed}" 2>/dev/null | tr -d '"' | head -n1)"
  [[ "${answer}" =~ ^([0-9]+)[[:space:]]*\| ]] || return 1
  printf '%s\n' "${BASH_REMATCH[1]}"
}

reality_target_ipv4() {
  getent ahostsv4 "${1}" 2>/dev/null | awk '{print $1}' | sort -u | head -n1
}

reality_target_asn() {
  local address
  address="$(reality_target_ipv4 "${1}")" || return 1
  [[ -n "${address}" ]] || return 1
  reality_ipv4_asn "${address}"
}

# shellcheck disable=SC2034 # This sourced function intentionally sets result globals for its caller.
reality_select_target() {
  local public_ip=$1 candidates=$2 xray_bin=$3 candidate candidate_asn server_asn fallback fallback_asn
  server_asn="$(reality_ipv4_asn "${public_ip}" || true)"
  fallback=
  fallback_asn=
  IFS=',' read -r -a REALITY_CANDIDATES <<<"${candidates}"
  for candidate in "${REALITY_CANDIDATES[@]}"; do
    candidate="${candidate//[[:space:]]/}"
    [[ -n "${candidate}" ]] || continue
    if ! "${xray_bin}" tls ping "${candidate}" >/dev/null 2>&1; then
      continue
    fi
    candidate_asn="$(reality_target_asn "${candidate}" || true)"
    # Project X explicitly warns against a Cloudflare target: failed REALITY
    # authentication is forwarded directly to it.
    [[ "${candidate_asn}" == 13335 ]] && continue
    if [[ -n "${server_asn}" && -n "${candidate_asn}" && "${candidate_asn}" == "${server_asn}" ]]; then
      REALITY_TARGET_ASN="${candidate_asn}"
      REALITY_SERVER_ASN="${server_asn}"
      REALITY_TARGET_MODE=same-asn
      REALITY_SELECTED_TARGET="${candidate}"
      return 0
    fi
    if [[ -z "${fallback}" ]]; then
      fallback="${candidate}"
      fallback_asn="${candidate_asn}"
    fi
  done
  [[ -n "${fallback}" ]] || return 1
  REALITY_TARGET_ASN="${fallback_asn}"
  REALITY_SERVER_ASN="${server_asn}"
  REALITY_TARGET_MODE=fallback
  REALITY_SELECTED_TARGET="${fallback}"
}
