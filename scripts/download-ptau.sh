#!/usr/bin/env bash
# Download Hermez Powers of Tau ceremony files + verify their SHA-256
# against a pinned digest.
#
# Why two PTAU files:
#   - pot16 (~72 MB)  covers up to ~65k constraints. Sufficient for the
#                     per-circuit ZK proofs (valid_input / valid_spend /
#                     client-side circuits) and the dev/test batched
#                     instances (N=2, N=4).
#   - pot18 (~288 MB) needed by the batched validity circuit at N=4, and
#                     formerly at N=16.
#   - pot19 (~576 MB) needed by the DEPLOYED batched validity circuit at
#                     N=16. The note-use tags grew it from 234,025 to
#                     285,401 total constraints; snarkjs needs a domain of
#                     next_power_of_2(total), so 2^18 = 262,144 no longer
#                     covers it and 2^19 = 524,288 does.
#
# SHA-256 pinning: the digests below are the bytes that were used to
# generate the committed `circuits/build/*/circuit_final.zkey` artifacts
# + the on-chain `programs/vault/src/zk/vk_*.rs` consts. A
# different-but-superficially-similar PTAU file would silently produce
# different VK consts, breaking on-chain verification. Hard fail at
# download time is the only safe behaviour.
#
# To bump: regenerate the artifact set against new PTAU, recompute the
# digest with `shasum -a 256 <file>`, commit the digest + the new zkeys
# + the new vk_*.rs in the SAME commit. See CLAUDE.md §4.
#
# Reference: https://github.com/iden3/snarkjs#7-prepare-phase-2
set -euo pipefail

PTAU_DIR="$(cd "$(dirname "$0")" && pwd)/ptau"
mkdir -p "$PTAU_DIR"

# Pinned SHA-256 digests for each ceremony file. Generated 2026-05-24
# against the artifacts that produced the committed zkeys + Rust VK
# consts. DO NOT update without also regenerating zkeys + vk_*.rs.
declare -A PTAU_SHA256=(
    ["powersOfTau28_hez_final_16.ptau"]="1c401abb57c9ce531370f3015c3e75c0892e0f32b8b1e94ace0f6682d9695922"
    ["powersOfTau28_hez_final_18.ptau"]="e970efa7774da80101e0ac336d083ef3339855c98112539338d706b2b89ac694"
    # pot19 added 2026-08-04 with the note-use tags. UNLIKE the two above,
    # this digest was computed from the file this repo downloaded rather than
    # inherited from a prior pinned artifact set — so on its own it proves
    # only that later downloads match the first one. Cross-check it against
    # an independent publication of the Hermez ceremony hashes before this
    # reaches mainnet; see CRYPTOGRAPHY.md §13 on the ceremony generally.
    ["powersOfTau28_hez_final_19.ptau"]="3f428d1a407e4704ef906960e000b03089e5e6ec29bf65b07bb5e3de005f4700"
)

declare -a PTAU_FILES=(
    "powersOfTau28_hez_final_16.ptau"
    "powersOfTau28_hez_final_18.ptau"
    "powersOfTau28_hez_final_19.ptau"
)

# Pick a SHA-256 tool. macOS ships `shasum`, Linux usually has
# `sha256sum`. Either works; we wrap so the script is portable.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "[ptau] ERROR: no sha256sum / shasum found — install one" >&2
        exit 1
    fi
}

verify_sha256() {
    local file="$1"
    local expected="$2"
    local actual
    actual=$(sha256_of "$file")
    if [ "$actual" != "$expected" ]; then
        echo "" >&2
        echo "[ptau] SHA-256 MISMATCH for $(basename "$file")" >&2
        echo "[ptau]   expected: $expected" >&2
        echo "[ptau]   actual:   $actual" >&2
        echo "[ptau]   This means EITHER the upstream file changed (supply-chain risk)" >&2
        echo "[ptau]   OR the local file is corrupted. Delete it + re-run, and if the" >&2
        echo "[ptau]   mismatch persists, do NOT trust the new bytes — investigate." >&2
        exit 1
    fi
    echo "[ptau] verified $(basename "$file") sha256=$actual"
}

for PTAU_FILE in "${PTAU_FILES[@]}"; do
    URL="https://storage.googleapis.com/zkevm/ptau/${PTAU_FILE}"
    DEST="$PTAU_DIR/$PTAU_FILE"
    EXPECTED="${PTAU_SHA256[$PTAU_FILE]}"

    if [ -f "$DEST" ]; then
        echo "[ptau] $PTAU_FILE already present at $PTAU_DIR"
        verify_sha256 "$DEST" "$EXPECTED"
        continue
    fi

    case "$PTAU_FILE" in
        *_16.ptau) SIZE="~72 MB"  ;;
        *_18.ptau) SIZE="~288 MB" ;;
        *_19.ptau) SIZE="~576 MB" ;;
        *)         SIZE="(unknown size)" ;;
    esac
    echo "[ptau] downloading $PTAU_FILE ($SIZE) ..."
    curl -L --fail --progress-bar -o "$DEST" "$URL"
    verify_sha256 "$DEST" "$EXPECTED"
    echo "[ptau] done: $DEST"
done

echo ""
echo "[ptau] All ceremony files verified. Pinning is supply-chain-safe."
echo "[ptau]"
echo "[ptau] NOTE: pot16 / pot18 / pot19 still use the public Hermez ceremony — fine"
echo "[ptau] testnet, but mainnet should host its own MPC contribution or run a"
echo "[ptau] new phase-2 ceremony with at least 3 independent contributors. See"
echo "[ptau] CRYPTOGRAPHY.md §13 + ARCHITECTURE.md \"What is NOT yet shipped\"."
