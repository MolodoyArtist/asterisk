#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
marker=/etc/vpnctl/domain-firewall-owned
case "${1:-}" in
  enable)
    # Keep provider/owner rules, including pre-existing broad 443 permissions.
    if ! ufw show added | grep -Eq '^ufw allow (443(/udp)?)( |$)'; then
      ufw allow 443/udp comment 'Domain Hysteria' >/dev/null
      touch "${marker}"
    fi
    ufw allow 9443/tcp comment 'Account portal' >/dev/null
    ;;
  cleanup)
    if [[ -f "${marker}" ]]; then
      ufw --force delete allow 443/udp >/dev/null
      rm -f -- "${marker}"
    fi
    ;;
  *) exit 1 ;;
esac
