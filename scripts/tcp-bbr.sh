#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

etc_dir="${VPNCTL_TCP_ETC_DIR:-/etc}"
sysctl_bin="${VPNCTL_SYSCTL_BIN:-/usr/sbin/sysctl}"
modprobe_bin="${VPNCTL_MODPROBE_BIN:-/usr/sbin/modprobe}"
sysctl_file="${etc_dir}/sysctl.d/99-vpnctl-bbr.conf"
module_file="${etc_dir}/modules-load.d/vpnctl-bbr.conf"

# Leave explicit administrator settings and previous vpnctl installs in place.
[[ ! -e "${sysctl_file}" && ! -L "${sysctl_file}" ]] || exit 0
if grep -qsE '^[[:space:]]*-?[[:space:]]*net[./]ipv4[./]tcp_congestion_control[[:space:]]*=' \
  "${etc_dir}/sysctl.conf" "${etc_dir}"/sysctl.d/*.conf; then
  exit 0
fi
current="$("${sysctl_bin}" -n net.ipv4.tcp_congestion_control)"
case "${current}" in cubic|bbr) ;; *) exit 0 ;; esac

available="$("${sysctl_bin}" -n net.ipv4.tcp_available_congestion_control)"
if [[ " ${available} " != *' bbr '* ]]; then
  "${modprobe_bin}" tcp_bbr
fi

install -d -m 0755 "${etc_dir}/sysctl.d" "${etc_dir}/modules-load.d"
created=()
cleanup() {
  if [[ $? -ne 0 && ${#created[@]} -gt 0 ]]; then
    rm -f -- "${created[@]}"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
set -C

if [[ ! -e "${module_file}" && ! -L "${module_file}" ]]; then
  exec 3>"${module_file}"
  created+=("${module_file}")
  printf '%s\n' tcp_bbr >&3
  exec 3>&-
fi
exec 3>"${sysctl_file}"
created+=("${sysctl_file}")
printf '%s\n' 'net.ipv4.tcp_congestion_control = bbr' >&3
exec 3>&-

"${sysctl_bin}" -qw net.ipv4.tcp_congestion_control=bbr
printf 'Enabled TCP BBR for new connections.\n'
