#!/usr/bin/env bash
# Start the dstack simulator for local nyx-tee development.
#
# The simulator exposes the same Unix-socket interface (`/var/run/
# dstack.sock` shape) that real TDX hardware exposes inside a Phala
# Cloud CVM. With it running, `cargo run -p nyx-tee` against
# DSTACK_SIMULATOR_ENDPOINT behaves byte-equivalent to running
# inside a real CVM — getKey() returns deterministic bytes,
# getQuote() returns a stub-but-well-formed quote, info() returns
# all expected fields.
#
# Usage:
#
#   ./scripts/dstack-simulator-start.sh
#       Starts the simulator in the foreground.
#
#   eval "$(./scripts/dstack-simulator-start.sh --env)"
#       Prints export statements for sourcing into your shell.
#
#   ./scripts/dstack-simulator-start.sh --build
#       Force a rebuild of the simulator from source.
#
# Requirements:
#   - Rust toolchain (already needed for the rest of the repo)
#   - The dstack repo cloned at $DSTACK_REPO (default: ../dstack
#     relative to this repo; or /Users/$USER/dstack)

set -euo pipefail

# ───── Locate the dstack repo ────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

candidates=(
    "${DSTACK_REPO:-}"
    "${REPO_ROOT}/dstack"
    "${REPO_ROOT}/../dstack"
    "${HOME}/dstack"
)

DSTACK_REPO=""
for c in "${candidates[@]}"; do
    [ -z "$c" ] && continue
    if [ -d "$c/sdk/simulator" ]; then
        DSTACK_REPO="$c"
        break
    fi
done

if [ -z "$DSTACK_REPO" ]; then
    cat >&2 <<EOF
[sim] ERROR: couldn't find a dstack checkout containing sdk/simulator/.
[sim] Looked in:
$(printf '[sim]   %s\n' "${candidates[@]}")
[sim]
[sim] Clone the repo and re-run:
[sim]   git clone https://github.com/Dstack-TEE/dstack.git ${REPO_ROOT}/dstack
EOF
    exit 1
fi

SIM_DIR="$DSTACK_REPO/sdk/simulator"
SIM_BIN="$SIM_DIR/dstack-simulator"
SOCK_PATH="$SIM_DIR/dstack.sock"

# ───── Parse args ─────────────────────────────────────────────────────
build=false
emit_env=false
case "${1:-}" in
    --build) build=true ;;
    --env)   emit_env=true ;;
    "")      ;;
    *)       echo "[sim] unknown arg: $1" >&2; exit 1 ;;
esac

# ───── --env mode: emit export statements + exit (no build) ──────────
# Pure side-effect-free env emission. Safe to `eval` from a shell rc
# file even before the simulator binary is built.
if [ "$emit_env" = true ]; then
    abs_sock="$(cd "$SIM_DIR" && pwd)/dstack.sock"
    cat <<EOF
export DSTACK_SIMULATOR_ENDPOINT="$abs_sock"
EOF
    exit 0
fi

# ───── Build the simulator if missing or if --build was passed ────────
if [ "$build" = true ] || [ ! -x "$SIM_BIN" ]; then
    echo "[sim] building simulator at $SIM_DIR ..." >&2
    ( cd "$SIM_DIR" && ./build.sh )
fi

# ───── Run mode: clean any stale socket + start simulator ─────────────
if [ -S "$SOCK_PATH" ]; then
    echo "[sim] removing stale socket at $SOCK_PATH" >&2
    rm -f "$SOCK_PATH"
fi

echo "[sim] starting dstack-simulator (DSTACK_SIMULATOR_ENDPOINT=$SOCK_PATH)" >&2
echo "[sim] (Ctrl-C to stop)" >&2
exec "$SIM_BIN"
