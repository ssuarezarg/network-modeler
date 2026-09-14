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
SSL_DIR="${SSL_DIR:-/srv/gitlab/ssl}"
DAYS="${DAYS:-90}"

if [[ -z "$FQDN" ]]; then
  echo "usage: $0 <fqdn>   (e.g. $0 gitlab.internal.example.com)" >&2
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
if [[ "$FQDN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$FQDN" == *:* ]]; then
  SAN="IP:${FQDN}"
  echo "note: ${FQDN} is an IP address, issuing the certificate with an IP SAN."
else
  SAN="DNS:${FQDN}"
fi

openssl req -x509 -nodes -newkey rsa:2048 -days "$DAYS" \
  -keyout "${SSL_DIR}/${FQDN}.key" \
  -out    "${SSL_DIR}/${FQDN}.crt" \
  -subj   "/CN=${FQDN}" \
  -addext "subjectAltName=${SAN}"

chmod 600 "${SSL_DIR}/${FQDN}.key"
chmod 644 "${SSL_DIR}/${FQDN}.crt"

echo "Self-signed certificate written to ${SSL_DIR}/${FQDN}.{crt,key} (${DAYS} days)."
echo "Replace with an internal-CA certificate before handing the URL to anyone."
