#!/usr/bin/env bash
# Guard: every `cvm-*` suite must reach the CVM through the verified transport.
#
# WHY THIS EXISTS. The `cvm-*` suites do not run in `pr-checks` — they need a
# live CVM and self-skip without their `RUN_*` flag. A skipped suite reports
# GREEN, so a suite that has become structurally unrunnable is indistinguishable
# from one that passed. Two of them stayed broken for weeks that way:
#
#   * cvm-attestation-e2e used global `fetch`, which cannot complete a TLS
#     handshake against the enclave's self-signed certificate.
#   * cvm-daemon-lifecycle HARDCODED `transportMode: "gateway-terminated"`,
#     a route that no longer exists, so it died before its first assertion.
#
# Both are detectable by reading the source, with no CVM and no secrets. That
# is what this does. It is deliberately a cheap textual check rather than a
# runtime one: the runtime signal is exactly what is unavailable in CI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0
note() { echo "  $*" >&2; }

# 1. No cvm-* suite may pin itself to the retired transport.
while IFS= read -r f; do
  if grep -nE 'transportMode:\s*"gateway-terminated"' "$f" | grep -qv 'RATLS\|ratls'; then
    echo "✗ $f pins transportMode to \"gateway-terminated\"" >&2
    note "That route is unpublished since the T-03P cutover, so this suite can"
    note "never run. Select the mode from DARKNYX_CVM_TRANSPORT instead."
    fail=1
  fi
done < <(find packages -name 'cvm-*.test.ts' -not -path '*/node_modules/*')

# 2. No cvm-* suite may call global fetch against the gateway. The enclave
#    serves a self-signed certificate; only the verified transport can talk to
#    it, and a bare fetch would also be an unverified peer if it could.
while IFS= read -r f; do
  hits=$(grep -nE 'await fetch\(|[^.[:alnum:]]fetch\(`\$\{GATEWAY\}' "$f" || true)
  if [ -n "$hits" ]; then
    echo "✗ $f calls global fetch against the CVM:" >&2
    echo "$hits" | sed 's/^/    /' >&2
    note "Route it through the harness (gwFetch / gwTransportFetch) or the"
    note "daemon transport, or the call bypasses the quote-bound channel."
    fail=1
  fi
done < <(find packages -name 'cvm-*.test.ts' -not -path '*/node_modules/*')

if [ "$fail" -eq 0 ]; then
  echo "✓ cvm-* suites all reach the CVM through the verified transport"
fi
exit "$fail"
