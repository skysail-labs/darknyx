#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNNER="$ROOT/scripts/surfpool/foundation.sh"

expect_failure() {
  local expected="$1"
  shift
  local output
  if output="$("$@" 2>&1)"; then
    echo "guard unexpectedly accepted: $*" >&2
    exit 1
  fi
  [[ "$output" == *"$expected"* ]] || {
    echo "guard failed for an unexpected reason: $output" >&2
    exit 1
  }
}

expect_failure "must be loopback" \
  env SURFPOOL_RPC_URL=http://example.com:18899 bash "$RUNNER" status
expect_failure "must be loopback" \
  env SURFPOOL_RPC_URL=http://0.0.0.0:18899 bash "$RUNNER" status
expect_failure "must not contain credentials" \
  env SURFPOOL_RPC_URL=http://user:secret@127.0.0.1:18899 bash "$RUNNER" status
expect_failure "SURFPOOL_DATASOURCE_RPC_URL is forbidden" \
  env SURFPOOL_DATASOURCE_RPC_URL=http://example.com bash "$RUNNER" status
expect_failure "ports must be distinct" \
  env SURFPOOL_WS_PORT=18899 bash "$RUNNER" status
expect_failure "ports must be distinct" \
  env SURFPOOL_RPC_PORT=80 SURFPOOL_RPC_URL=http://127.0.0.1:80 \
    bash "$RUNNER" status

echo "SURFPOOL_FOUNDATION_GUARDS cases=6 rejected=6"
