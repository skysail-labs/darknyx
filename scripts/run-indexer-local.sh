#!/usr/bin/env bash
# Run the Darknyx fills indexer LOCALLY for testing.
#
# The indexer is an off-TEE, read-only Solana indexer. For testing it does NOT
# need to be deployed anywhere: it runs on your machine, reads the SAME devnet
# RPC the CVM uses, and the test queries it by deterministic order_id. The CVM
# never needs to reach it (no TEE↔indexer coupling — that's the whole point of
# the account-agnostic, by-order_id design).
#
# Usage:
#   INDEXER_RPC_URL="$HELIUS" scripts/run-indexer-local.sh
#
# Env (all optional except the RPC):
#   INDEXER_RPC_URL   devnet RPC (falls back to $HELIUS, then public devnet)
#   INDEXER_PORT      HTTP port (default 8090)
#   INDEXER_DB        SQLite path (default: a fresh temp file, removed on exit)
#   INDEXER_PROGRAM_ID  vault program id (default: the devnet deploy)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RPC="${INDEXER_RPC_URL:-${HELIUS:-https://api.devnet.solana.com}}"
PORT="${INDEXER_PORT:-8090}"
DB="${INDEXER_DB:-$(mktemp -t darknyx-idx.XXXXXX).sqlite}"
PROGRAM="${INDEXER_PROGRAM_ID:-C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx}"

echo "building @darknyx/indexer..."
./node_modules/.bin/tsc -p packages/indexer/tsconfig.json

# Live-tail by default for local testing: skip the (possibly days-long)
# backfill so a settle that lands during a test surfaces in seconds. Set
# INDEXER_START_FROM_TIP=0 to get the production backfill-from-history path.
FROM_TIP="${INDEXER_START_FROM_TIP:-1}"

echo "starting indexer: rpc=$RPC port=$PORT db=$DB start_from_tip=$FROM_TIP"
INDEXER_RPC_URL="$RPC" INDEXER_PORT="$PORT" INDEXER_DB="$DB" INDEXER_PROGRAM_ID="$PROGRAM" \
  INDEXER_START_FROM_TIP="$FROM_TIP" \
  node packages/indexer/dist/bin/indexer.js &
IDX_PID=$!
# Clean up the process + the temp DB unless the caller supplied their own.
cleanup() {
  kill "$IDX_PID" 2>/dev/null || true
  [ -n "${INDEXER_DB:-}" ] || rm -f "$DB"*
}
trap cleanup EXIT INT TERM

for _ in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    echo "indexer healthy → http://127.0.0.1:$PORT   (db=$DB)"
    break
  fi
  sleep 0.5
done

echo "indexer running (pid $IDX_PID). Ctrl-C to stop."
wait "$IDX_PID"
