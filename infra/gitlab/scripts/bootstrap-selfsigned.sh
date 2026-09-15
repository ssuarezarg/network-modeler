#!/usr/bin/env bash
# Generate a self-signed certificate so GitLab can start before the real
# internal-CA certificate is issued.
#
# This is a BOOTSTRAP AID, not a deployment step. Clients will reject it, so
# every git client would need TLS verification disabled — which is exactly the
# habit you do not want around a repository holding customer topology. Replace
# it with a properly issued certificate before anyone clones.
set -euo pipefail

FQDN="${1:-}"
shift || true
EXTRA_NAMES=("$@")
SSL_DIR="${SSL_DIR:-/srv/gitlab/ssl}"
DAYS="${DAYS:-90}"

if [[ -z "$FQDN" ]]; then
  echo "usage: $0 <primary-name> [additional-name ...]" >&2
  echo >&2
  echo "  $0 gitlab.internal.example.com" >&2
  echo "  $0 4.175.164.71 10.230.4.4" >&2
  echo >&2
  echo "The first name becomes the CN and the certificate filename, which must" >&2
  echo "match GITLAB_FQDN. Every name given becomes a SAN." >&2
  echo >&2
  echo "More than one is often necessary: a host reached by a public address" >&2
  echo "from outside and a private one from inside needs both, or whichever" >&2
  echo "side is missing fails verification — and a runner on the same VM" >&2
  echo "usually cannot reach its own public address at all." >&2
  exit 1
fi

mkdir -p "$SSL_DIR"

if [[ -e "${SSL_DIR}/${FQDN}.crt" ]]; then
  echo "refusing to overwrite existing ${SSL_DIR}/${FQDN}.crt" >&2
  exit 1
fi

# SAN is required: name verification via CN alone is no longer honoured by
# current clients, so a CN-only certificate fails even when it looks correct.
#
# An IP address needs `IP:`, not `DNS:`. A certificate for 10.0.0.1 carrying
# `subjectAltName=DNS:10.0.0.1` is rejected by every client that checks, and the
# error names the hostname rather than the SAN type - so it reads like a wrong
# certificate rather than a malformed one.
san_for() {
  local name="$1"
  if [[ "$name" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$name" == *:* ]]; then
    printf 'IP:%s' "$name"
  else
    printf 'DNS:%s' "$name"
  fi
}

SAN="$(san_for "$FQDN")"
for name in "${EXTRA_NAMES[@]}"; do
  SAN="${SAN},$(san_for "$name")"
done
echo "subjectAltName = ${SAN}"

openssl req -x509 -nodes -newkey rsa:2048 -days "$DAYS" \
  -keyout "${SSL_DIR}/${FQDN}.key" \
  -out    "${SSL_DIR}/${FQDN}.crt" \
  -subj   "/CN=${FQDN}" \
  -addext "subjectAltName=${SAN}"

chmod 600 "${SSL_DIR}/${FQDN}.key"
chmod 644 "${SSL_DIR}/${FQDN}.crt"

echo "Self-signed certificate written to ${SSL_DIR}/${FQDN}.{crt,key} (${DAYS} days)."
echo "Replace with an internal-CA certificate before handing the URL to anyone."
