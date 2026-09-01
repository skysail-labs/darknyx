#!/usr/bin/env bash
# Run the bounded Phase 4 hosted-integration cadence and reject vacuous green
# results. The full six-case protocol matrix remains a local developer gate;
# scheduled CI runs the two cases that cover client custody plus TEE settlement,
# cold replay, and the simulator-evidence boundary.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

LOG_DIR="$ROOT/.surfpool/phase4"
LOG="$LOG_DIR/hosted-smoke.log"
mkdir -p "$LOG_DIR"

cleanup() {
  local original_status=$?
  local cleanup_status=0
  trap - EXIT HUP INT TERM
  set +e
  bash "$ROOT/scripts/surfpool/local-tee.sh" down >/dev/null 2>&1 \
    || cleanup_status=1
  bash "$ROOT/scripts/surfpool/foundation.sh" down >/dev/null 2>&1 \
    || cleanup_status=1
  node "$ROOT/scripts/surfpool/ports-closed.mjs" \
    127.0.0.1 18080 18899 18900 19488 || cleanup_status=1
  set -e

  if [[ $cleanup_status -ne 0 ]]; then
    echo "PHASE4_TEARDOWN_FAIL" >&2
    exit "$cleanup_status"
  fi
  echo "PHASE4_TEARDOWN_PASS ports=18080,18899,18900,19488"
  exit "$original_status"
}
trap cleanup EXIT HUP INT TERM

bash "$ROOT/scripts/surfpool/local-tee-matrix.sh" smoke 2>&1 | tee "$LOG"

required_markers=(
  "SURFPOOL_TEE_LOOPBACK_GUARD_PASS"
  "PHASE3_CASE_PASS flow=deposit-withdraw"
  "PHASE3_CASE_PASS flow=settle"
  "SURFPOOL_TEE_RESTART_RECONCILED"
  "SURFPOOL_TEE_SIMULATOR_QUOTE_REJECTED kind=quote_invalid"
  "PHASE3_MATRIX_PASS cases=2 mode=smoke"
)

for marker in "${required_markers[@]}"; do
  grep -qF "$marker" "$LOG" || {
    echo "hosted Surfpool smoke missed required marker: $marker" >&2
    exit 1
  }
done

echo "PHASE4_HOSTED_SMOKE_PASS cases=2 proofs=real"
