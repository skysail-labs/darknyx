#!/usr/bin/env bash
# CI circuit build: compile wasm only, then use committed circuit_final.zkey files.
#
# groth16 setup is non-deterministic across machines, so CI does NOT re-run the
# ceremony. Instead, the committed circuit_final.zkey (checked in via the
# !circuits/**/*_final.zkey gitignore exception) is used as-is. The on-chain
# Rust VK constants were generated from these exact zkeys via parse-vk-to-rust.js.
#
# For local development or after a circuit change, run build-circuits.sh instead
# (it runs the full ceremony and you must regenerate the Rust VK constants).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT/circuits/build"

build_wasm() {
    local name="$1"
    local src="$ROOT/circuits/$name/circuit.circom"
    local out="$BUILD_DIR/$name"
    local committed_zkey="$ROOT/circuits/build/$name/circuit_final.zkey"

    echo ""
    echo "=== ci-build circuit: $name ==="
    mkdir -p "$out"

    echo "[$name] circom compile (wasm + r1cs)"
    circom "$src" \
        --r1cs --wasm --sym \
        -l "$ROOT/node_modules" \
        -o "$out"

    if [ ! -f "$committed_zkey" ]; then
        echo "[$name] ERROR: committed zkey not found at $committed_zkey"
        echo "         Run scripts/build-circuits.sh locally, then commit the zkey."
        exit 1
    fi

    echo "[$name] using committed circuit_final.zkey (stable ceremony)"
    echo "[$name] done."
}

build_wasm valid_wallet_create
build_wasm valid_spend
build_wasm valid_input
build_wasm valid_create
build_wasm valid_price

echo ""
echo "CI circuit build complete. Wasm compiled fresh; zkeys from committed artifacts."
