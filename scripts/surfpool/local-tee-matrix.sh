#!/usr/bin/env bash
# Proof-backed Phase 3 protocol matrix. Each flow owns a fresh offline Surfnet
# so Merkle shadows, replay guards, and leaf-count assertions cannot leak state
# between cases.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

FOUNDATION="$ROOT/scripts/surfpool/foundation.sh"
LOCAL_TEE="$ROOT/scripts/surfpool/local-tee.sh"
VITEST="$ROOT/node_modules/.bin/vitest"
SOL_USD_FEED="ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"

usage() {
  cat <<'EOF'
usage: scripts/surfpool/local-tee-matrix.sh [smoke|all|FLOW]

  smoke  deposit/withdraw/expiry plus one crossing settle, followed by a cold
         TEE restart, exact K-root reconciliation, and simulator-quote rejection
  all    smoke plus merge, multimatch, self-trade, and merge-then-order
  FLOW   one of deposit-withdraw, merge, settle, multimatch, self-trade,
         merge-then-order

No case reaches a public Solana RPC or starts a Phala CVM.
EOF
}

cleanup() {
  "$LOCAL_TEE" down >/dev/null 2>&1 || true
  "$FOUNDATION" down >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

run_vitest() {
  (
    cd "$ROOT/packages/sdk"
    "$VITEST" run "$@"
  )
}

assert_fixture_installer_loopback_guard() {
  if SOLANA_RPC_URL="https://api.devnet.solana.com" \
    node "$ROOT/scripts/surfpool/install-pyth-push.mjs" "$SOL_USD_FEED" \
      >/dev/null 2>&1; then
    echo "Surfpool oracle installer accepted a non-loopback RPC" >&2
    return 1
  fi
  echo "SURFPOOL_TEE_LOOPBACK_GUARD_PASS"
}

run_case() {
  local flow="$1"
  local label="phase3-$flow"
  echo "PHASE3_CASE_START flow=$flow"
  cleanup
  "$FOUNDATION" up "$label"
  "$LOCAL_TEE" up "$label"
  # shellcheck disable=SC1090
  source "$ROOT/.surfpool/local-tee/current/env.sh"

  case "$flow" in
    deposit-withdraw)
      RUN_DEVNET_DW=1 run_vitest tests/devnet-deposit-withdraw.test.ts \
        2>&1 | tee "$ROOT/.surfpool/local-tee/current/protocol.log"
      ;;
    merge)
      RUN_DEVNET_MERGE=1 run_vitest tests/devnet-merge.test.ts \
        2>&1 | tee "$ROOT/.surfpool/local-tee/current/protocol.log"
      ;;
    settle)
      DARKNYX_CVM_CHAIN_RECOVERY=1 run_vitest tests/cvm-settle-e2e.test.ts \
        2>&1 | tee "$ROOT/.surfpool/local-tee/current/protocol.log"
      "$LOCAL_TEE" restart
      run_vitest tests/surfpool-local-tee.test.ts \
        2>&1 | tee "$ROOT/.surfpool/local-tee/current/restart-boundary.log"
      ;;
    multimatch)
      DARKNYX_CVM_MATCHES=4 run_vitest tests/cvm-multimatch-settle.test.ts \
        2>&1 | tee "$ROOT/.surfpool/local-tee/current/protocol.log"
      ;;
    self-trade)
      DARKNYX_CVM_NO_MATCH_MS=8000 run_vitest tests/cvm-self-trade.test.ts \
        2>&1 | tee "$ROOT/.surfpool/local-tee/current/protocol.log"
      ;;
    merge-then-order)
      run_vitest tests/cvm-merge-then-order.test.ts \
        2>&1 | tee "$ROOT/.surfpool/local-tee/current/protocol.log"
      ;;
    *)
      usage
      return 2
      ;;
  esac

  jq -n \
    --arg flow "$flow" \
    --arg completedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{flow:$flow,result:"pass",completedAt:$completedAt,realProofs:true,localRpc:"Surfpool",guestApi:"dstack v0.5.9 simulator",tested:["production darknyx-tee process","production Solana RPC client","native getTransactionsForAddress mirror history","real circuit witnesses/proofs","real vault SBF"],notTested:["Intel TDX isolation","Intel-valid DCAP quote","Phala KMS durability/access control","RA-TLS passthrough","real validator confirmation/finality/timing"]}' \
    > "$ROOT/.surfpool/local-tee/current/phase3-result.json"
  "$LOCAL_TEE" down
  "$FOUNDATION" down
  echo "PHASE3_CASE_PASS flow=$flow"
}

mode="${1:-smoke}"
assert_fixture_installer_loopback_guard
case "$mode" in
  smoke)
    flows=(deposit-withdraw settle)
    ;;
  all)
    flows=(deposit-withdraw merge settle multimatch self-trade merge-then-order)
    ;;
  deposit-withdraw|merge|settle|multimatch|self-trade|merge-then-order)
    flows=("$mode")
    ;;
  *)
    usage
    exit 2
    ;;
esac

for flow in "${flows[@]}"; do
  run_case "$flow"
done

trap - EXIT HUP INT TERM
echo "PHASE3_MATRIX_PASS cases=${#flows[@]} mode=$mode"
