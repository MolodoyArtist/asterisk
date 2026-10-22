#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

fail=0
check() {
  local description=$1 pattern=$2
  if rg --pcre2 --hidden --glob '!.git/**' --glob '!scripts/check-repository.sh' -l -i -- "${pattern}" .; then
    printf 'security check failed: %s\n' "${description}" >&2
    fail=1
  fi
}

check 'private keys' '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
check 'common credential assignments' "(password|passwd|token|secret|api[_-]?key)[[:space:]]*[:=][[:space:]]*[\"'](?!\\$\\()[^\"']{8,}"
check 'GitHub tokens' 'gh[pousr]_[A-Za-z0-9_]{20,}'
check 'cloud access keys' 'AKIA[0-9A-Z]{16}'
check 'local home paths' '/Users/[^/[:space:]]+|/home/[^/[:space:]]+'
check 'non-documentation IPv4 literals' '(^|[^0-9])(?!0\.0\.0\.0|1\.1\.1\.1|172\.19\.0\.1|127\.0\.0\.1|169\.254\.169\.254|192\.0\.2\.[0-9]{1,3}|198\.51\.100\.[0-9]{1,3}|203\.0\.113\.[0-9]{1,3})([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9]|$)'

# Ignore rules alone do not stop an accidental `git add --force` of deployment
# files. Check tracked filenames too, without printing their contents.
while IFS= read -r -d '' path; do
  case "${path##*/}" in
    .env|.env.*|*.pem|*.key|*.p12|*.db|*.db-*|*.sqlite*|*.pcap|*.pcapng|state.json|auth.json|xray.json|mtg.toml|vpnctl-install.json)
      printf 'security check failed: deployment file is tracked: %s\n' "${path}" >&2
      fail=1
      ;;
  esac
done < <(git ls-files -z)

exit "${fail}"
