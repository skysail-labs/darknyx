#!/usr/bin/env bash
# Supervise the production darknyx-tee binary against an offline Surfpool
# foundation and the pinned dstack v0.5.9 guest-agent simulator.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

STATE_ROOT="$ROOT/.surfpool/local-tee"
CURRENT="$STATE_ROOT/current"
EVIDENCE="$STATE_ROOT/evidence"
FOUNDATION="$ROOT/.surfpool/foundation/current"
TEE_BIN="${DARKNYX_LOCAL_TEE_BIN:-$ROOT/target/release/darknyx-tee}"
TEE_HOST="127.0.0.1"
TEE_PORT="${DARKNYX_LOCAL_TEE_PORT:-18080}"
TEE_URL="http://$TEE_HOST:$TEE_PORT"
PINNED_DSTACK_COMMIT="282eeb27d22d8f091ad0fa5a90e638f85cf68751"
SOL_USD_FEED="ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"

usage() {
  cat <<'EOF'
usage: scripts/surfpool/local-tee.sh <up|restart|status|env|down> [label]

  up LABEL  verify an active Surfpool foundation, start the pinned dstack
            simulator, discover/authorize its K signer keys, and boot the
            production TEE in governed settlement mode
  restart   cold-restart only the TEE, preserving Surfpool and its ledger
  status    require all three processes to be healthy and print public state
  env       print the shell exports used by local proof-backed SDK suites
  down      stop the TEE and simulator, remove secrets, and archive evidence

Start Surfpool first with scripts/surfpool/foundation.sh up LABEL. This helper
never starts a Phala CVM and refuses every non-loopback RPC/listener.
Build the default optimized binary with `cargo build --release -p darknyx-tee`;
an unoptimized Ark binary makes each N=16 proving-key load take several minutes.
EOF
}

die() {
  echo "surfpool-local-tee: $*" >&2
  exit 1
}

require_label() {
  local label="${1:-}"
  [[ "$label" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]] \
    || die "label must match [a-zA-Z0-9][a-zA-Z0-9._-]*"
}

locate_dstack() {
  local candidate
  for candidate in "${DSTACK_REPO:-}" "$ROOT/dstack" "$ROOT/../dstack" "$HOME/dstack"; do
    [[ -n "$candidate" && -d "$candidate/sdk/simulator" ]] || continue
    printf '%s\n' "$candidate"
    return 0
  done
  die "dstack v0.5.9 checkout not found; set DSTACK_REPO"
}

pid_alive() {
  local pid="${1:-}"
  [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null
}

stop_pid_file() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  local pid
  pid="$(cat "$file")"
  if pid_alive "$pid"; then
    kill "$pid" 2>/dev/null || true
    local attempt
    for attempt in $(seq 1 50); do
      pid_alive "$pid" || break
      sleep 0.2
    done
    if pid_alive "$pid"; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
}

http_healthy() {
  curl --noproxy '*' --fail --silent --show-error --max-time 1 \
    "$TEE_URL/health" >/dev/null 2>&1
}

wait_for_http() {
  local attempts="${1:-300}"
  local attempt
  for attempt in $(seq 1 "$attempts"); do
    http_healthy && return 0
    if [[ -f "$CURRENT/tee.pid" ]] && ! pid_alive "$(cat "$CURRENT/tee.pid")"; then
      tail -200 "$CURRENT/tee.log" >&2 || true
      die "darknyx-tee exited during startup"
    fi
    sleep 0.5
  done
  tail -200 "$CURRENT/tee.log" >&2 || true
  die "darknyx-tee did not become healthy at $TEE_URL"
}

assert_loopback() {
  [[ "$TEE_PORT" =~ ^[0-9]+$ ]] && ((TEE_PORT >= 1024 && TEE_PORT <= 65535)) \
    || die "DARKNYX_LOCAL_TEE_PORT must be an integer in 1024..65535"
  node "$ROOT/scripts/surfpool/loopback.mjs" "$TEE_URL" >/dev/null
  [[ -f "$FOUNDATION/env.sh" && -f "$FOUNDATION/e2e-config.json" ]] \
    || die "no active Surfpool foundation; run foundation.sh up first"
  # shellcheck disable=SC1090
  source "$FOUNDATION/env.sh"
  node "$ROOT/scripts/surfpool/loopback.mjs" "$SOLANA_RPC_URL" >/dev/null
  [[ "$SOLANA_RPC_URL" == "http://127.0.0.1:18899" ]] \
    || die "Phase 3 requires the canonical loopback Surfpool RPC"
}

write_secrets() {
  umask 077
  {
    printf 'export DARKNYX_TEE_API_KEY=%q\n' "local-$(openssl rand -hex 16)"
    printf 'export DARKNYX_TEE_API_SECRET=%q\n' "$(openssl rand -hex 32)"
    printf 'export DARKNYX_TEE_PASSPHRASE=%q\n' "$(openssl rand -base64 32 | tr -d '\n')"
  } > "$CURRENT/secrets.env"
}

write_test_env() {
  # shellcheck disable=SC1090
  source "$FOUNDATION/env.sh"
  # shellcheck disable=SC1090
  source "$CURRENT/secrets.env"
  {
    cat "$FOUNDATION/env.sh"
    cat "$CURRENT/secrets.env"
    printf 'export DARKNYX_TEE_GATEWAY=%q\n' "$TEE_URL"
    printf 'export RUN_SURFPOOL_TEE_E2E=%q\n' '1'
    printf 'export FUNDER_KEYPAIR=%q\n' "$ADMIN_KEYPAIR"
    printf 'export DARKNYX_E2E_KEYPAIR_DIR=%q\n' "$FOUNDATION/keypairs"
    printf 'export DARKNYX_CVM_FEE_RATE_BPS=%q\n' '30'
    printf 'export DARKNYX_CVM_SETTLE_TIMEOUT_MS=%q\n' '180000'
  } > "$CURRENT/env.sh"
  chmod 600 "$CURRENT/env.sh" "$CURRENT/secrets.env"
}

start_simulator() {
  local dstack_repo="$1"
  local simulator="$dstack_repo/sdk/simulator/dstack-simulator"
  local socket="$dstack_repo/sdk/simulator/dstack.sock"
  [[ -x "$simulator" ]] || die "dstack simulator binary missing; run scripts/dstack-simulator-start.sh --build"
  rm -f "$socket"
  DSTACK_REPO="$dstack_repo" nohup "$ROOT/scripts/dstack-simulator-start.sh" \
    > "$CURRENT/dstack.log" 2>&1 &
  echo "$!" > "$CURRENT/dstack.pid"
  local attempt
  for attempt in $(seq 1 100); do
    [[ -S "$socket" ]] && break
    pid_alive "$(cat "$CURRENT/dstack.pid")" || {
      tail -100 "$CURRENT/dstack.log" >&2 || true
      die "dstack simulator exited during startup"
    }
    sleep 0.1
  done
  [[ -S "$socket" ]] || die "dstack simulator socket was not created"
  printf '%s\n' "$socket" > "$CURRENT/dstack.socket"
}

start_tee() {
  local mode="$1"
  local log="$CURRENT/tee.log"
  stop_pid_file "$CURRENT/tee.pid"
  rm -f "$CURRENT/tee.pid"
  : > "$log"
  # shellcheck disable=SC1090
  source "$FOUNDATION/env.sh"
  # shellcheck disable=SC1090
  source "$CURRENT/secrets.env"
  local socket
  socket="$(cat "$CURRENT/dstack.socket")"
  (
    export DSTACK_SIMULATOR_ENDPOINT="$socket"
    export DARKNYX_TEE_DEPLOYMENT_TIER=development
    export DARKNYX_TEE_ALLOW_TEST_AUTH=0
    export DARKNYX_TEE_HTTP_BIND="$TEE_HOST:$TEE_PORT"
    export DARKNYX_TEE_TRANSPORT_MODE=gateway-terminated
    export DARKNYX_TEE_SOLANA_RPC_URL="$SOLANA_RPC_URL"
    export DARKNYX_TEE_SYNC_FROM_SLOT=0
    export DARKNYX_TEE_STATE_DIR="$CURRENT/state"
    export DARKNYX_TEE_NUM_TREES=2
    export DARKNYX_TEE_CIRCUITS_DIR="$ROOT/circuits/build"
    export DARKNYX_TEE_PROVER=ark
    export DARKNYX_TEE_ORACLE_MODE=pyth-solana-push-v1
    export DARKNYX_TEE_API_KEY DARKNYX_TEE_API_SECRET DARKNYX_TEE_PASSPHRASE
    if [[ "$mode" == governed ]]; then
      local base_mint quote_mint settle_lookup_table protocol_owner_commitment
      base_mint="$(jq -er .baseMint.pubkey "$DARKNYX_E2E_CONFIG_PATH")"
      quote_mint="$(jq -er .quoteMint.pubkey "$DARKNYX_E2E_CONFIG_PATH")"
      settle_lookup_table="$(jq -er .settleLookupTable "$DARKNYX_E2E_CONFIG_PATH")"
      protocol_owner_commitment="$(jq -er .protocol.ownerCommitmentHex "$DARKNYX_E2E_CONFIG_PATH")"
      export DARKNYX_TEE_BASE_MINT="$base_mint"
      export DARKNYX_TEE_QUOTE_MINT="$quote_mint"
      export DARKNYX_TEE_MARKET_SYMBOL=SOL-USDC
      export DARKNYX_TEE_FEED_IDS="$SOL_USD_FEED"
      export DARKNYX_TEE_SETTLE_LOOKUP_TABLE="$settle_lookup_table"
      export DARKNYX_TEE_FEE_RATE_BPS=30
      export DARKNYX_TEE_FEE_EPOCH_KEY
      export DARKNYX_TEE_PROTOCOL_OWNER_COMMITMENT="$protocol_owner_commitment"
    else
      unset DARKNYX_TEE_BASE_MINT DARKNYX_TEE_QUOTE_MINT DARKNYX_TEE_FEED_IDS
      unset DARKNYX_TEE_SETTLE_LOOKUP_TABLE DARKNYX_TEE_PROTOCOL_OWNER_COMMITMENT
    fi
    exec "$TEE_BIN"
  ) > "$log" 2>&1 &
  echo "$!" > "$CURRENT/tee.pid"
  wait_for_http 600
  curl --noproxy '*' --fail --silent --show-error "$TEE_URL/info" > "$CURRENT/info.json"
}

authorize_signers() {
  local keys
  keys="$(jq -r '.tee_pubkeys | join(",")' "$CURRENT/info.json")"
  [[ "$(jq '.tee_pubkeys | length' "$CURRENT/info.json")" == "2" ]] \
    || die "simulator TEE did not derive the expected K=2 signer set"
  # shellcheck disable=SC1090
  source "$FOUNDATION/env.sh"
  SOLANA_RPC_URL="$SOLANA_RPC_URL" ADMIN_KEYPAIR="$ADMIN_KEYPAIR" \
    TEE_PUBKEYS="$keys" node "$ROOT/scripts/rotate-tee-pubkey.mjs" \
    > "$CURRENT/signer-rotation.log"
  SOLANA_RPC_URL="$SOLANA_RPC_URL" FUNDER_KEYPAIR="$ADMIN_KEYPAIR" \
    FUND_TARGET_SOL=1 TEE_PUBKEYS="$keys" node "$ROOT/scripts/fund-tee-keys.mjs" \
    > "$CURRENT/signer-funding.log"
}

wait_for_trading() {
  local attempt
  for attempt in $(seq 1 180); do
    local body
    body="$(curl --noproxy '*' --silent --show-error --max-time 1 "$TEE_URL/instruments" || true)"
    if jq -e '
      if type == "array" then
        any(.[]; .symbol == "SOL-USDC" and .trading_enabled == true)
      elif (.instruments | type) == "array" then
        any(.instruments[]; .symbol == "SOL-USDC" and .trading_enabled == true)
      else
        false
      end
    ' \
      >/dev/null 2>&1 <<<"$body"; then
      return 0
    fi
    sleep 0.5
  done
  curl --noproxy '*' --silent --show-error "$TEE_URL/system/status" >&2 || true
  tail -200 "$CURRENT/tee.log" >&2 || true
  die "governed local TEE did not enable SOL-USDC trading"
}

up() {
  local label="$1"
  require_label "$label"
  assert_loopback
  [[ -x "$TEE_BIN" ]] || die "darknyx-tee binary missing at $TEE_BIN"
  [[ ! -d "$CURRENT" ]] || die "local TEE state already exists; run local-tee.sh down first"
  local dstack_repo dstack_commit
  dstack_repo="$(locate_dstack)"
  dstack_commit="$(git -C "$dstack_repo" rev-parse HEAD)"
  [[ "$dstack_commit" == "$PINNED_DSTACK_COMMIT" ]] \
    || die "dstack checkout is $dstack_commit; expected pinned v0.5.9 $PINNED_DSTACK_COMMIT"
  mkdir -p "$CURRENT/state" "$EVIDENCE"
  printf '%s\n' "$label" > "$CURRENT/label"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$CURRENT/started-at"
  printf '%s\n' "$dstack_commit" > "$CURRENT/dstack.commit"
  write_secrets
  write_test_env
  start_simulator "$dstack_repo"

  # The deterministic simulator keys must first be discovered through the real
  # production boot path. That discovery boot has placeholder mints and cannot
  # settle. After exact K-key authorization and funding, the governed restart
  # constructs the live settlement driver.
  start_tee discovery
  authorize_signers
  stop_pid_file "$CURRENT/tee.pid"
  SOLANA_RPC_URL="$SOLANA_RPC_URL" \
    node "$ROOT/scripts/surfpool/install-pyth-push.mjs" "$SOL_USD_FEED" \
    > "$CURRENT/oracle-install.log" 2>&1
  start_tee governed
  wait_for_trading
  jq -n \
    --arg runLabel "$label" \
    --arg teeUrl "$TEE_URL" \
    --arg startedAt "$(cat "$CURRENT/started-at")" \
    --arg dstackCommit "$dstack_commit" \
    --argjson teePid "$(cat "$CURRENT/tee.pid")" \
    --argjson dstackPid "$(cat "$CURRENT/dstack.pid")" \
    --argjson teePubkeys "$(jq .tee_pubkeys "$CURRENT/info.json")" \
    '{label:$runLabel,teeUrl:$teeUrl,startedAt:$startedAt,dstackCommit:$dstackCommit,teePid:$teePid,dstackPid:$dstackPid,teePubkeys:$teePubkeys,rpc:"http://127.0.0.1:18899",evidenceBoundary:"Surfpool+dstack-simulator; not TDX, Phala KMS, RA-TLS, or real-cluster evidence"}' \
    > "$CURRENT/manifest.json"
  echo "Local production TEE ready at $TEE_URL"
  echo "Run: source $CURRENT/env.sh"
}

restart() {
  assert_loopback
  [[ -f "$CURRENT/manifest.json" && -f "$CURRENT/dstack.socket" ]] \
    || die "no active local TEE"
  cp "$CURRENT/info.json" "$CURRENT/info.before-restart.json"
  cp "$CURRENT/tee.log" "$CURRENT/tee.before-restart.log"
  start_tee governed
  wait_for_trading
  [[ "$(jq -r .boot_session_id "$CURRENT/info.before-restart.json")" \
      != "$(jq -r .boot_session_id "$CURRENT/info.json")" ]] \
    || die "cold restart reused the prior boot_session_id"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$CURRENT/restarted-at"
  echo "Local TEE cold restart complete at $TEE_URL"
}

status() {
  assert_loopback
  [[ -f "$CURRENT/manifest.json" ]] || die "no active local TEE"
  pid_alive "$(cat "$CURRENT/tee.pid")" || die "darknyx-tee is not running"
  pid_alive "$(cat "$CURRENT/dstack.pid")" || die "dstack simulator is not running"
  http_healthy || die "darknyx-tee health endpoint is unavailable"
  jq -s '.[0] + {info: .[1]}' "$CURRENT/manifest.json" "$CURRENT/info.json"
}

emit_env() {
  [[ -f "$CURRENT/env.sh" ]] || die "no active local TEE"
  cat "$CURRENT/env.sh"
}

down() {
  stop_pid_file "$CURRENT/tee.pid"
  stop_pid_file "$CURRENT/dstack.pid"
  if [[ -f "$CURRENT/dstack.socket" ]]; then
    rm -f "$(cat "$CURRENT/dstack.socket")"
  fi
  if http_healthy; then
    die "local TEE port remains reachable after teardown"
  fi
  if [[ -d "$CURRENT" ]]; then
    date -u +%Y-%m-%dT%H:%M:%SZ > "$CURRENT/stopped-at"
    printf 'clean\n' > "$CURRENT/teardown-status"
    rm -rf "$CURRENT/state"
    rm -f "$CURRENT/secrets.env" "$CURRENT/env.sh"
    local label destination
    label="$(cat "$CURRENT/label" 2>/dev/null || echo unknown)"
    destination="$EVIDENCE/$label"
    rm -rf "$destination"
    mv "$CURRENT" "$destination"
    echo "Local TEE evidence archived at $destination"
  fi
  echo "Local TEE and dstack simulator stopped"
}

case "${1:-}" in
  up) up "${2:-}" ;;
  restart) restart ;;
  status) status ;;
  env) emit_env ;;
  down) down ;;
  *) usage; exit 2 ;;
esac
