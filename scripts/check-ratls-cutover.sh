#!/usr/bin/env bash
# T-03P cutover guard.
#
# Once RA-TLS becomes the production transport, the plaintext listener must stop
# being publicly routable. Until then it must stay published, because
# `DARKNYX_TEE_TRANSPORT_MODE` still defaults to `gateway-terminated` and every
# existing deployment reaches the CVM over :8080.
#
# Those two states are both correct, at different times, and the failure mode is
# shipping the first while believing the second — a deployment that reports
# "ra-tls" while an unauthenticated plaintext route sits open beside it. This
# script makes the pairing mechanical instead of remembered:
#
#   compose default is ra-tls  =>  :8080 MUST NOT be published
#   compose default is legacy  =>  :8080 MUST be published
#
# It reads only the committed compose, so it is a pre-merge gate rather than a
# deployment-time check. The live assertion ("the public plaintext route is
# unreachable") still belongs in the Phase 3 CVM window; this guard exists so
# that window cannot be reached with a compose that contradicts its own mode.
set -euo pipefail

COMPOSE="${1:-deploy/docker-compose.yaml}"
test -f "$COMPOSE" || { echo "✗ no such compose: $COMPOSE" >&2; exit 1; }

# The default is whatever follows `:-` in the ${VAR:-default} expansion.
mode=$(sed -n 's/.*DARKNYX_TEE_TRANSPORT_MODE:[[:space:]]*\${DARKNYX_TEE_TRANSPORT_MODE:-\([a-z-]*\)}.*/\1/p' "$COMPOSE" | head -1)
if [ -z "$mode" ]; then
  # A hard-coded literal is also legitimate; read that form too.
  mode=$(sed -n 's/.*DARKNYX_TEE_TRANSPORT_MODE:[[:space:]]*"\{0,1\}\([a-z-]*\)"\{0,1\}[[:space:]]*$/\1/p' "$COMPOSE" | head -1)
fi
test -n "$mode" || { echo "✗ $COMPOSE does not set DARKNYX_TEE_TRANSPORT_MODE" >&2; exit 1; }

plaintext_published=no
grep -qE '^[[:space:]]*-[[:space:]]*"8080:8080"' "$COMPOSE" && plaintext_published=yes

tls_published=no
grep -qE '^[[:space:]]*-[[:space:]]*"8443:8443"' "$COMPOSE" && tls_published=yes

echo "compose            : $COMPOSE"
echo "transport default  : $mode"
echo "8080 published     : $plaintext_published"
echo "8443 published     : $tls_published"

fail=0
case "$mode" in
  ra-tls)
    if [ "$plaintext_published" = yes ]; then
      echo "✗ transport default is ra-tls but :8080 is still published." >&2
      echo "  The cutover must remove the plaintext port publication, or a" >&2
      echo "  deployment reporting ra-tls leaves an open unauthenticated route." >&2
      fail=1
    fi
    if [ "$tls_published" = no ]; then
      echo "✗ transport default is ra-tls but :8443 is not published." >&2
      fail=1
    fi
    ;;
  gateway-terminated)
    if [ "$plaintext_published" = no ]; then
      echo "✗ transport default is gateway-terminated but :8080 is not published;" >&2
      echo "  existing deployments would have no route to the CVM." >&2
      fail=1
    fi
    ;;
  *)
    echo "✗ unrecognised transport default: $mode" >&2
    fail=1
    ;;
esac

if [ "$fail" -eq 0 ]; then
  echo "✓ RA-TLS cutover guard: compose ports are consistent with the transport default"
fi
exit "$fail"
