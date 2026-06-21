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
# In-pool note merge (K=2/4) — wasm only; committed circuit_final.zkey.
build_wasm valid_merge_k2
build_wasm valid_merge_k4
# v3.1 valid_create + valid_price were removed in Phase 1c-hard
# (subsumed by the v3.5 batched-validity circuit). The N=16 batched
# circuit isn't wired into this CI step yet — it needs pot18, which
# would balloon the runner's PTAU cache by ~288 MB. The on-chain
# vault still embeds vk_match_batch_n16.rs (committed VK consts)
# so on-chain verification works regardless; the SDK match-batch
# prover tests run against the committed `circuits/build/match_batch_n16/`
# artifacts that are gitignore-exempted under the existing
# `!**/circuit_final.zkey` rule.

echo ""
echo "CI circuit build complete. Wasm compiled fresh; zkeys from committed artifacts."
