#!/usr/bin/env bash
# Reproducible, offline Darknyx foundation on the pinned Surfpool binary.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
STATE_ROOT="$ROOT/.surfpool/foundation"
CURRENT="$STATE_ROOT/current"
EVIDENCE="$STATE_ROOT/evidence"
SURFPOOL_BIN="${SURFPOOL_BIN:-$ROOT/.surfpool/bin/surfpool}"
RPC_HOST="127.0.0.1"
RPC_PORT="${SURFPOOL_RPC_PORT:-18899}"
WS_PORT="${SURFPOOL_WS_PORT:-18900}"
STUDIO_PORT="${SURFPOOL_STUDIO_PORT:-19488}"
RPC_URL="${SURFPOOL_RPC_URL:-http://$RPC_HOST:$RPC_PORT}"
EXPECTED_RPC_URL="http://$RPC_HOST:$RPC_PORT"
VAULT_PROGRAM_ID="C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx"

usage() {
  cat <<'EOF'
usage: scripts/surfpool/foundation.sh <up|verify|down|cycle|status> [label]

  up LABEL       start a fresh offline Surfnet and create the canonical K=2 foundation
  verify         run the production Pyth-push fixture suite against the active Surfnet
  down           stop the active Surfnet, prove ports/processes closed, and archive evidence
  cycle LABEL    run up, verify, and down with cleanup on failure or interruption
  status         print active metadata and fail unless the recorded process is alive
EOF
}

die() {
  echo "surfpool-foundation: $*" >&2
  exit 1
}

require_label() {
  local label="${1:-}"
  [[ "$label" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]] \
    || die "label must match [a-zA-Z0-9][a-zA-Z0-9._-]*"
}

assert_local_contract() {
  local port
  for port in "$RPC_PORT" "$WS_PORT" "$STUDIO_PORT"; do
    [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1024 && port <= 65535)) \
      || die "Surfpool ports must be distinct integers in 1024..65535"
  done
  [[ "$RPC_PORT" != "$WS_PORT" && "$RPC_PORT" != "$STUDIO_PORT" \
    && "$WS_PORT" != "$STUDIO_PORT" ]] \
    || die "Surfpool ports must be distinct integers in 1024..65535"
  node "$ROOT/scripts/surfpool/loopback.mjs" "$RPC_URL" >/dev/null
  [[ "$RPC_URL" == "$EXPECTED_RPC_URL" ]] \
    || die "RPC URL must match the explicitly bound endpoint $EXPECTED_RPC_URL"
  [[ -z "${SURFPOOL_DATASOURCE_RPC_URL:-}" ]] \
    || die "SURFPOOL_DATASOURCE_RPC_URL is forbidden for the offline foundation"
  [[ -z "${SURFPOOL_NETWORK:-}" ]] \
    || die "SURFPOOL_NETWORK is forbidden for the offline foundation"
}

rpc_healthy() {
  curl --noproxy '*' --fail --silent --show-error --max-time 1 \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"getVersion"}' \
    "$RPC_URL" >/dev/null 2>&1
}

pid_is_alive() {
  local pid="${1:-}"
  [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null
}

assert_recorded_process() {
  local pid="$1"
  local command
  command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
  [[ "$command" == *"$SURFPOOL_BIN"* && "$command" == *" start "* ]] \
    || die "PID $pid does not belong to the recorded Surfpool binary"
}

write_env() {
  {
    printf 'export SURFPOOL_RPC_URL=%q\n' "$RPC_URL"
    printf 'export SOLANA_RPC_URL=%q\n' "$RPC_URL"
    printf 'export DARKNYX_E2E_CONFIG_PATH=%q\n' "$CURRENT/e2e-config.json"
    printf 'export ADMIN_KEYPAIR=%q\n' "$CURRENT/keypairs/admin.json"
    printf 'export TEE_AUTHORITY_KEYPAIR=%q\n' "$CURRENT/keypairs/tee_authority.json"
    printf 'export TEE_AUTHORITY_1_KEYPAIR=%q\n' "$CURRENT/keypairs/tee_authority_1.json"
    printf 'export ROOT_KEY_KEYPAIR=%q\n' "$CURRENT/keypairs/root_key.json"
    printf 'export VAULT_PROGRAM_ID=%q\n' "$VAULT_PROGRAM_ID"
    printf 'export DARKNYX_NUM_TREES=%q\n' '2'
    printf 'export DARKNYX_TEE_FEE_EPOCH_KEY=%q\n' \
      '0008080808080808080808080808080808080808080808080808080808080808'
    printf 'export PROTOCOL_FEE_BPS=%q\n' '30'
    printf 'export DARKNYX_PRICE_SCALE=%q\n' '100000000'
    printf 'export DEMO_MINT_DECIMALS=%q\n' '6'
    printf 'export RUN_SURFPOOL_QUALIFICATION=%q\n' '1'
    printf 'export RUN_SURFPOOL_ORACLE_FIXTURE=%q\n' '1'
  } > "$CURRENT/env.sh"
}

file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

stop_process() {
  [[ -f "$CURRENT/surfpool.pid" ]] || return 0
  local pid
  pid="$(cat "$CURRENT/surfpool.pid")"
  if pid_is_alive "$pid"; then
    assert_recorded_process "$pid"
    kill "$pid" 2>/dev/null || true
    local attempt
    for attempt in $(seq 1 50); do
      pid_is_alive "$pid" || break
      sleep 0.2
    done
    if pid_is_alive "$pid"; then
      kill -9 "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
    for attempt in $(seq 1 10); do
      pid_is_alive "$pid" || break
      sleep 0.1
    done
  fi
}

assert_stopped() {
  local pid=""
  [[ -f "$CURRENT/surfpool.pid" ]] && pid="$(cat "$CURRENT/surfpool.pid")"
  if [[ -n "$pid" ]] && pid_is_alive "$pid"; then
    die "Surfpool PID $pid survived teardown"
  fi
  if rpc_healthy; then
    die "Surfpool RPC remains reachable after teardown"
  fi
  node "$ROOT/scripts/surfpool/ports-closed.mjs" \
    "$RPC_HOST" "$RPC_PORT" "$WS_PORT" "$STUDIO_PORT"
}

archive_current() {
  [[ -d "$CURRENT" ]] || return 0
  local label="unknown"
  [[ -f "$CURRENT/label" ]] && label="$(cat "$CURRENT/label")"
  local destination="$EVIDENCE/$label"
  # Evidence retains public topology and logs, never ephemeral signing or mint
  # material. The generated e2e config contains mint secret keys because live
  # SDK flows need them; strip those fields before archiving the stopped run.
  rm -rf "$CURRENT/keypairs"
  rm -f "$CURRENT/env.sh"
  if [[ -f "$CURRENT/e2e-config.json" ]]; then
    jq 'del(.baseMint.secretKey, .quoteMint.secretKey)' \
      "$CURRENT/e2e-config.json" > "$CURRENT/e2e-config.redacted.json"
    mv "$CURRENT/e2e-config.redacted.json" "$CURRENT/e2e-config.json"
  fi
  mkdir -p "$EVIDENCE"
  rm -rf "$destination"
  mv "$CURRENT" "$destination"
  echo "Surfpool evidence archived at $destination"
}

down() {
  assert_local_contract
  stop_process
  assert_stopped
  if [[ -d "$CURRENT" ]]; then
    date -u +%Y-%m-%dT%H:%M:%SZ > "$CURRENT/stopped-at"
    echo clean > "$CURRENT/teardown-status"
  fi
  archive_current
  echo "Surfpool stopped; PID and loopback ports are closed"
}

up() {
  local label="$1"
  require_label "$label"
  assert_local_contract
  local dependency
  for dependency in node curl jq rg solana solana-keygen; do
    command -v "$dependency" >/dev/null || die "$dependency is required"
  done
  [[ -x "$SURFPOOL_BIN" ]] \
    || die "Surfpool binary missing at $SURFPOOL_BIN (build the revision pinned in pin.json)"
  local surfpool_version expected_version surfpool_sha
  surfpool_version="$("$SURFPOOL_BIN" --version)"
  expected_version="$(jq -r .reportedVersion "$ROOT/scripts/surfpool/pin.json")"
  [[ "$surfpool_version" == "$expected_version" ]] \
    || die "Surfpool reports '$surfpool_version', expected '$expected_version'"
  surfpool_sha="$(file_sha256 "$SURFPOOL_BIN")"
  [[ -f "$ROOT/target/deploy/vault.so" ]] \
    || die "target/deploy/vault.so is missing; run scripts/build-vault-sbf.sh devnet-admin"
  [[ -f "$ROOT/target/deploy/vault.so.fingerprint" ]] \
    || die "vault SBF fingerprint is missing"
  [[ ! -d "$CURRENT" ]] \
    || die "an active or uncleared foundation exists; run foundation.sh down first"
  rpc_healthy && die "RPC port $RPC_PORT is already serving a process"

  mkdir -p "$CURRENT/keypairs" "$EVIDENCE"
  echo "$label" > "$CURRENT/label"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$CURRENT/started-at"
  write_env

  nohup "$SURFPOOL_BIN" start \
    --host "$RPC_HOST" \
    --offline --no-deploy --no-tui --no-studio --db :memory: \
    --port "$RPC_PORT" --ws-port "$WS_PORT" --studio-port "$STUDIO_PORT" \
    --airdrop-amount 0 \
    > "$CURRENT/surfpool.log" 2>&1 &
  echo "$!" > "$CURRENT/surfpool.pid"

  local attempt
  for attempt in $(seq 1 100); do
    if rpc_healthy; then
      break
    fi
    sleep 0.2
  done
  if ! rpc_healthy; then
    tail -200 "$CURRENT/surfpool.log" >&2 || true
    die "Surfpool did not become healthy"
  fi

  # shellcheck disable=SC1090
  source "$CURRENT/env.sh"
  node "$ROOT/scripts/surfpool/install-vault.mjs"
  local name
  for name in admin tee_authority tee_authority_1 root_key; do
    solana-keygen new --no-bip39-passphrase --silent --force \
      --outfile "$CURRENT/keypairs/$name.json"
  done
  local admin tee0 tee1
  admin="$(solana-keygen pubkey "$ADMIN_KEYPAIR")"
  tee0="$(solana-keygen pubkey "$TEE_AUTHORITY_KEYPAIR")"
  tee1="$(solana-keygen pubkey "$TEE_AUTHORITY_1_KEYPAIR")"
  solana airdrop 5 "$admin" --url "$SOLANA_RPC_URL" >/dev/null
  export DARKNYX_INITIAL_TEE_PUBKEYS="$tee0,$tee1"
  (
    cd "$ROOT/packages/sdk"
    RUN_DEVNET_E2E=1 ../../node_modules/.bin/vitest run tests/devnet-setup.test.ts
  ) 2>&1 | tee "$CURRENT/foundation.log"

  [[ -f "$DARKNYX_E2E_CONFIG_PATH" ]] || die "foundation config was not written"
  jq -e --arg rpc "$RPC_URL" --arg program "$VAULT_PROGRAM_ID" \
    '.l1RpcUrl == $rpc and .vaultProgramId == $program and .numTrees == 2 and (.merkleTreePdas | length) == 2' \
    "$DARKNYX_E2E_CONFIG_PATH" >/dev/null
  if rg -n "\.devnet/|helius|api\.devnet\.solana\.com" "$CURRENT"; then
    die "local foundation contains a real-devnet or provider reference"
  fi
  jq -n \
    --arg label "$label" \
    --arg rpc "$RPC_URL" \
    --arg pid "$(cat "$CURRENT/surfpool.pid")" \
    --arg startedAt "$(cat "$CURRENT/started-at")" \
    --arg config "$DARKNYX_E2E_CONFIG_PATH" \
    --arg surfpoolVersion "$surfpool_version" \
    --arg surfpoolSha256 "$surfpool_sha" \
    '{label:$label,rpcUrl:$rpc,pid:($pid|tonumber),startedAt:$startedAt,configPath:$config,offline:true,bindHost:"127.0.0.1",numTrees:2,surfpoolVersion:$surfpoolVersion,surfpoolSha256:$surfpoolSha256}' \
    > "$CURRENT/manifest.json"
  echo "Surfpool foundation ready: $CURRENT"
}

verify() {
  assert_local_contract
  [[ -f "$CURRENT/env.sh" ]] || die "no active foundation; run foundation.sh up first"
  local pid
  pid="$(cat "$CURRENT/surfpool.pid")"
  pid_is_alive "$pid" || die "recorded Surfpool process is not alive"
  assert_recorded_process "$pid"
  rpc_healthy || die "Surfpool RPC is not healthy"
  # shellcheck disable=SC1090
  source "$CURRENT/env.sh"
  node --test "$ROOT/scripts/surfpool/loopback.test.mjs"
  bash "$ROOT/scripts/surfpool/foundation-guard.test.sh"
  (
    cd "$ROOT"
    cargo test -p darknyx-tee --test surfpool_oracle_fixture -- --nocapture
  ) 2>&1 | tee "$CURRENT/oracle-fixture.log"
  rg -q 'SURFPOOL_ORACLE_FIXTURE cases=15 valid=1 rejected=14 recovered=14' \
    "$CURRENT/oracle-fixture.log" \
    || die "oracle fixture suite did not emit its non-vacuous pass marker"
  echo "Surfpool foundation verification passed"
}

status() {
  assert_local_contract
  [[ -f "$CURRENT/manifest.json" ]] || die "no active foundation"
  local pid
  pid="$(cat "$CURRENT/surfpool.pid")"
  pid_is_alive "$pid" || die "recorded Surfpool process is not alive"
  assert_recorded_process "$pid"
  rpc_healthy || die "Surfpool RPC is not healthy"
  cat "$CURRENT/manifest.json"
}

cycle() {
  local label="$1"
  require_label "$label"
  trap 'code=$?; down || true; exit $code' EXIT HUP INT TERM
  up "$label"
  verify
  down
  trap - EXIT HUP INT TERM
}

command="${1:-}"
case "$command" in
  up)
    label="${2:-}"
    require_label "$label"
    trap 'code=$?; if [[ $code -ne 0 ]]; then down || true; fi; exit $code' EXIT HUP INT TERM
    up "$label"
    trap - EXIT HUP INT TERM
    ;;
  verify) verify ;;
  down) down ;;
  cycle)
    label="${2:-}"
    require_label "$label"
    cycle "$label"
    ;;
  status) status ;;
  *) usage; exit 2 ;;
esac
