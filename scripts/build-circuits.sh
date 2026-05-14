#!/usr/bin/env bash
# Build all Phase 1 circuits:
#   1. circom compile  -> .r1cs + .wasm + .sym
#   2. snarkjs groth16 setup  -> initial .zkey from ptau
#   3. snarkjs zkey contribute (single contribution, deterministic for dev)
#   4. snarkjs zkey export verificationkey -> verification_key.json
#   5. snarkjs zkey export solidityverifier (unused on Solana, skipped)
#   6. parse_vk_to_rust -> Rust const for on-chain verifier
#
# Output layout:
#   circuits/build/<circuit_name>/
#       circuit.r1cs
#       circuit.sym
#       circuit_js/  (contains circuit.wasm + generate_witness.js + witness_calculator.js)
#       circuit_final.zkey
#       verification_key.json
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT/circuits/build"
PTAU="$ROOT/scripts/ptau/powersOfTau28_hez_final_16.ptau"
SNARKJS="$ROOT/node_modules/.bin/snarkjs"

if [ ! -f "$PTAU" ]; then
    echo "[build] ptau not found; running download-ptau.sh"
    bash "$ROOT/scripts/download-ptau.sh"
fi

if [ ! -x "$SNARKJS" ]; then
    echo "[build] snarkjs not found at $SNARKJS — run: npm install"
    exit 1
fi

build_circuit() {
    local name="$1"
    local src="$ROOT/circuits/$name/circuit.circom"
    local out="$BUILD_DIR/$name"

    echo ""
    echo "=== building circuit: $name ==="
    mkdir -p "$out"

    echo "[$name] circom compile"
    circom "$src" \
        --r1cs --wasm --sym \
        -l "$ROOT/node_modules" \
        -o "$out"

    # circom emits circuit.r1cs + circuit_js/ directory.
    # Rename zkey target for clarity.
    local r1cs="$out/circuit.r1cs"

    echo "[$name] groth16 setup"
    "$SNARKJS" groth16 setup "$r1cs" "$PTAU" "$out/circuit_0000.zkey"

    # Single deterministic dev contribution (entropy from fixed seed).
    # For production, this MUST be replaced with a real multi-party ceremony.
    echo "[$name] zkey contribute (dev-only, deterministic)"
    echo "nyx-phase1-dev-contribution-$name" | "$SNARKJS" zkey contribute \
        "$out/circuit_0000.zkey" "$out/circuit_final.zkey" \
        --name="nyx-dev-$name" -v -e="nyx-phase1-dev-contribution-$name"

    echo "[$name] export verification key"
    "$SNARKJS" zkey export verificationkey "$out/circuit_final.zkey" "$out/verification_key.json"

    # Clean intermediate artifact.
    rm -f "$out/circuit_0000.zkey"

    echo "[$name] done."
}

build_circuit valid_wallet_create
build_circuit valid_spend
build_circuit valid_input

echo ""
echo "All circuits built. Artifacts in $BUILD_DIR/"
