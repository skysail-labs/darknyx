#!/usr/bin/env bash
# Download Hermez Powers of Tau ceremony files.
#
# Why two PTAU files:
#   - pot16 (~72 MB)  covers up to ~65k constraints. Sufficient for the
#                     per-match v3 circuits (valid_create / valid_input /
#                     valid_spend / valid_wallet_create / valid_price)
#                     and the small batched-validity instances (N=2, N=4).
#   - pot18 (~288 MB) needed by the v3.5 batched validity circuit at
#                     N=16 — total constraints (non-linear + linear)
#                     reach ~163k, which requires a domain of size
#                     2^18 = 262,144 in the snarkjs setup. N=8 already
#                     overruns pot16; pot17 would suffice for it but pot18
#                     gives the headroom for any future per-slot
#                     additions.
#
# Reference: https://github.com/iden3/snarkjs#7-prepare-phase-2
set -euo pipefail

PTAU_DIR="$(cd "$(dirname "$0")" && pwd)/ptau"
mkdir -p "$PTAU_DIR"

declare -a PTAU_FILES=(
    "powersOfTau28_hez_final_16.ptau"
    "powersOfTau28_hez_final_18.ptau"
)

for PTAU_FILE in "${PTAU_FILES[@]}"; do
    URL="https://storage.googleapis.com/zkevm/ptau/${PTAU_FILE}"
    DEST="$PTAU_DIR/$PTAU_FILE"
    if [ -f "$DEST" ]; then
        echo "[ptau] $PTAU_FILE already present at $PTAU_DIR"
        continue
    fi
    case "$PTAU_FILE" in
        *_16.ptau) SIZE="~72 MB"  ;;
        *_18.ptau) SIZE="~288 MB" ;;
        *)         SIZE="(unknown size)" ;;
    esac
    echo "[ptau] downloading $PTAU_FILE ($SIZE) ..."
    curl -L --fail --progress-bar -o "$DEST" "$URL"
    echo "[ptau] done: $DEST"
done

echo "[ptau] WARNING: Phase 1 uses an unaudited ptau download. For mainnet launch,"
echo "[ptau]          replace with locally-hosted ceremony files and pin SHA256."
