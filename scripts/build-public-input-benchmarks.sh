#!/usr/bin/env bash
# Build the isolated public-input-compression benchmark artifacts.
#
# Nothing under circuits/build/ or any production VK is touched. Heavy and
# disposable R1CS/wasm/zkey outputs live under target/public-input-benchmarks.
# The tiny verifier fixtures are regenerated only in `fixtures`/`all` mode.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/target/public-input-benchmarks"
PTAU16="$ROOT/scripts/ptau/powersOfTau28_hez_final_16.ptau"
PTAU18="$ROOT/scripts/ptau/powersOfTau28_hez_final_18.ptau"
SNARKJS="$ROOT/node_modules/.bin/snarkjs"
MODE="${1:-all}"
BEACON=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20

case "$MODE" in
    match|fixtures|all) ;;
    *) echo "usage: $0 [match|fixtures|all]" >&2; exit 2 ;;
esac

if [ ! -f "$PTAU16" ] || [ ! -f "$PTAU18" ]; then
    echo "missing Powers-of-Tau files; run: bash scripts/download-ptau.sh" >&2
    exit 1
fi
if [ ! -x "$SNARKJS" ]; then
    echo "snarkjs missing at $SNARKJS; run: npm install" >&2
    exit 1
fi
if ! command -v circom >/dev/null 2>&1; then
    echo "circom is not on PATH" >&2
    exit 1
fi

mkdir -p "$OUT"

build_one() {
    local name="$1"
    local source="$2"
    local ptau="$3"
    local dir="$OUT/$name"

    if [ "${REBUILD_BENCHMARKS:-0}" != "1" ] \
        && [ -f "$dir/circuit.r1cs" ] \
        && [ -f "$dir/circuit_js/circuit.wasm" ] \
        && [ -f "$dir/circuit_final.zkey" ] \
        && [ "$source" -ot "$dir/circuit_final.zkey" ] \
        && [ "$ROOT/circuits/templates/match_batch.circom" -ot "$dir/circuit_final.zkey" ] \
        && [ "$ROOT/circuits/benchmarks/templates/match_batch_statement_digest.circom" -ot "$dir/circuit_final.zkey" ]; then
        echo "[$name] cached (set REBUILD_BENCHMARKS=1 to rebuild)"
        return
    fi

    mkdir -p "$dir"
    echo "[$name] circom"
    circom "$source" --r1cs --wasm --sym -l "$ROOT/node_modules" -o "$dir"
    echo "[$name] groth16 setup"
    "$SNARKJS" groth16 setup "$dir/circuit.r1cs" "$ptau" "$dir/circuit_0000.zkey"
    echo "[$name] deterministic benchmark beacon"
    "$SNARKJS" zkey beacon \
        "$dir/circuit_0000.zkey" "$dir/circuit_final.zkey" \
        "$BEACON" 10 --name="darknyx-public-input-bench-$name"
    "$SNARKJS" zkey export verificationkey \
        "$dir/circuit_final.zkey" "$dir/verification_key.json"
    rm -f "$dir/circuit_0000.zkey"
}

if [ "$MODE" = "match" ] || [ "$MODE" = "all" ]; then
    build_one \
        match_batch_n16_pi8 \
        "$ROOT/circuits/match_batch_n16/circuit.circom" \
        "$PTAU18"
    build_one \
        match_batch_n16_pi2 \
        "$ROOT/circuits/benchmarks/match_batch_n16_digest2/circuit.circom" \
        "$PTAU18"
    build_one \
        match_batch_n16_pi1 \
        "$ROOT/circuits/benchmarks/match_batch_n16_digest1/circuit.circom" \
        "$PTAU18"
fi

if [ "$MODE" = "fixtures" ] || [ "$MODE" = "all" ]; then
    for n in 8 2 1; do
        build_one \
            "verifier_pi$n" \
            "$ROOT/circuits/benchmarks/verifier_pi$n/circuit.circom" \
            "$PTAU16"
        node "$ROOT/scripts/parse-vk-to-rust.js" \
            "$OUT/verifier_pi$n/verification_key.json" \
            "$ROOT/programs/vault/src/zk/vk_benchmark_pi$n.rs" \
            "BENCHMARK_PI$n"
    done
    WRITE_TRACKED_FIXTURES=1 node \
        "$ROOT/scripts/generate-public-input-benchmark-fixtures.mjs"
fi

echo "benchmark artifacts ready under $OUT"
