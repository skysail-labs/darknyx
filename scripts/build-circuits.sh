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
PTAU16="$ROOT/scripts/ptau/powersOfTau28_hez_final_16.ptau"
PTAU18="$ROOT/scripts/ptau/powersOfTau28_hez_final_18.ptau"
SNARKJS="$ROOT/node_modules/.bin/snarkjs"

if [ ! -f "$PTAU16" ] || [ ! -f "$PTAU18" ]; then
    echo "[build] ptau not found; running download-ptau.sh"
    bash "$ROOT/scripts/download-ptau.sh"
fi

if [ ! -x "$SNARKJS" ]; then
    echo "[build] snarkjs not found at $SNARKJS — run: npm install"
    exit 1
fi

build_circuit() {
    local name="$1"
    local ptau="${2:-$PTAU16}"
    local emit_rust_vk="${3:-yes}"
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
    "$SNARKJS" groth16 setup "$r1cs" "$ptau" "$out/circuit_0000.zkey"

    # Deterministic dev contribution via `zkey beacon`. Unlike `zkey
    # contribute -e=...`, which mixes user entropy with crypto.randomBytes()
    # and is therefore NOT reproducible across machines, `zkey beacon`
    # derives the contribution purely from the supplied hash + iteration
    # exponent. Identical inputs => byte-identical circuit_final.zkey =>
    # byte-identical verification_key.json => the committed Rust VK
    # constants in programs/vault/src/zk/vk_*.rs stay in sync across
    # every developer's local rebuild and every CI run.
    #
    # For production, this MUST be replaced with a real multi-party
    # ceremony (or a public-beacon contribution derived from an
    # unpredictable future event hash).
    echo "[$name] zkey beacon (dev-only, deterministic)"
    "$SNARKJS" zkey beacon \
        "$out/circuit_0000.zkey" "$out/circuit_final.zkey" \
        0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10 \
        --name="darknyx-dev-$name" -v

    echo "[$name] export verification key"
    "$SNARKJS" zkey export verificationkey "$out/circuit_final.zkey" "$out/verification_key.json"

    if [ "$emit_rust_vk" = "yes" ]; then
        echo "[$name] generate Rust verifier constants"
        local const_prefix
        const_prefix="$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')"
        node "$ROOT/scripts/parse-vk-to-rust.js" \
            "$out/verification_key.json" \
            "$ROOT/programs/vault/src/zk/vk_${name}.rs" \
            "$const_prefix"
    fi

    # Clean intermediate artifact.
    rm -f "$out/circuit_0000.zkey"

    echo "[$name] done."
}

build_circuit valid_wallet_create
build_circuit valid_deposit
build_circuit valid_spend
build_circuit valid_input
# In-pool note merge (K=2/4). Both fit pot16 (~26k / ~50k constraints).
build_circuit valid_merge_k2
build_circuit valid_merge_k4
# VALID_MATCH_BATCH v3. N=2/4 are host-test circuits and do not have on-chain
# Rust verifier modules. N=16 is the deployed verifier and requires pot18.
build_circuit match_batch_n2 "$PTAU16" no
build_circuit match_batch_n4 "$PTAU16" no
build_circuit match_batch_n16 "$PTAU18" yes

echo ""
echo "All circuits built. Artifacts in $BUILD_DIR/"
