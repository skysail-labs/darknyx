#!/usr/bin/env bash
# Build the native C++ witness generators required by
# `darknyx-tee-loadgen --real-settle`.
#
# Linux x86_64 uses Circom's optimized generated assembly. Apple Silicon uses
# Circom's portable `--no_asm` C++ output and Homebrew GMP. Both modes execute
# host-native binaries directly. Neither invokes WebAssembly or Wasmer, and
# there is intentionally no fallback.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT/circuits/build"
CIRCUITS=(valid_wallet_create valid_deposit valid_input valid_spend valid_merge_k2 valid_merge_k4)
HOST="$(uname -s):$(uname -m)"

if ! command -v circom >/dev/null 2>&1; then
    echo "circom is required (expected compiler 2.2.2)" >&2
    exit 1
fi
if [ "$(circom --version | awk '{print $3}')" != "2.2.2" ]; then
    echo "circom 2.2.2 is required" >&2
    exit 1
fi
if [ ! -d "$ROOT/node_modules/circomlib" ]; then
    echo "node_modules/circomlib is missing; run npm install" >&2
    exit 1
fi

circom_flags=(--c)
if [ "$HOST" = "Darwin:arm64" ]; then
    circom_flags+=(--no_asm)
fi

for circuit in "${CIRCUITS[@]}"; do
    source="$ROOT/circuits/$circuit/circuit.circom"
    output="$BUILD_DIR/$circuit"
    mkdir -p "$output"
    echo "[$circuit] generating native C++ witness source"
    circom "$source" "${circom_flags[@]}" -l "$ROOT/node_modules" -o "$output"
done

write_direct_wrapper() {
    local circuit="$1"
    local wrapper="$BUILD_DIR/$circuit/circuit_cpp/native-witness"
    {
        printf '%s\n' '#!/usr/bin/env bash'
        printf '%s\n' 'set -euo pipefail'
        printf '%s\n' 'HERE="$(cd "$(dirname "$0")" && pwd)"'
        printf '%s\n' 'exec "$HERE/circuit" "$@"'
    } > "$wrapper"
    chmod 0755 "$wrapper"
}

case "$HOST" in
    Linux:x86_64)
        for circuit in "${CIRCUITS[@]}"; do
            echo "[$circuit] compiling native x86_64 witness generator"
            make -B -C "$BUILD_DIR/$circuit/circuit_cpp"
            write_direct_wrapper "$circuit"
        done
        ;;
    Darwin:arm64)
        if ! command -v brew >/dev/null 2>&1; then
            echo "Homebrew is required for the Apple-Silicon native witness build" >&2
            exit 1
        fi
        brew_prefix="$(brew --prefix)"
        if [ ! -f "$brew_prefix/include/nlohmann/json.hpp" ] \
            || [ ! -f "$brew_prefix/include/gmp.h" ]; then
            echo "Homebrew nlohmann-json and gmp are required" >&2
            echo "install with: brew install nlohmann-json gmp" >&2
            exit 1
        fi
        for circuit in "${CIRCUITS[@]}"; do
            echo "[$circuit] compiling native arm64 witness generator (--no_asm)"
            # Circom's portable generator spells every GMP limb `uint64_t`.
            # On Apple Silicon that is `unsigned long long`, while Homebrew GMP
            # defines `mp_limb_t` as `unsigned long`; both are 64-bit but C++
            # correctly rejects the pointer-type mismatch. Use GMP's own limb
            # type throughout the generated field shim.
            perl -pi -e 's/\buint64_t\b/mp_limb_t/g' \
                "$BUILD_DIR/$circuit/circuit_cpp/fr.cpp" \
                "$BUILD_DIR/$circuit/circuit_cpp/fr.hpp"
            CPLUS_INCLUDE_PATH="$brew_prefix/include${CPLUS_INCLUDE_PATH:+:$CPLUS_INCLUDE_PATH}" \
                LIBRARY_PATH="$brew_prefix/lib${LIBRARY_PATH:+:$LIBRARY_PATH}" \
                make -B -C "$BUILD_DIR/$circuit/circuit_cpp"
            write_direct_wrapper "$circuit"
        done
        ;;
    *)
        echo "unsupported native witness host $HOST; use Linux x86_64 or Apple Silicon" >&2
        exit 1
        ;;
esac

for circuit in "${CIRCUITS[@]}"; do
    test -x "$BUILD_DIR/$circuit/circuit_cpp/native-witness"
done
echo "Native client witness generators ready (WASM/Wasmer disabled)."
