#!/usr/bin/env bash
# Build `target/deploy/vault.so` and record the fingerprint of the source it was
# built from, so the LiteSVM suite can refuse to validate a stale binary.
#
# Use this instead of a bare `cargo build-sbf`. A bare build produces the
# artifact but no manifest, and the tests then fail closed telling you to run
# this script — which is the intended behaviour, not a papercut: an unmanifested
# .so is exactly the "I don't know what this binary is" case.
#
# Default features are `devnet-admin` (what the LiteSVM suite and the devnet
# deploy need). A MAINNET build ships neither dev backdoor — build that with an
# explicit empty feature set: `bash scripts/build-vault-sbf.sh ""`.
#
# Usage: bash scripts/build-vault-sbf.sh [features]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FEATURES="${1-devnet-admin}"

cd "$ROOT"

if [ -n "$FEATURES" ]; then
  echo "building vault.so with features: $FEATURES"
  cargo build-sbf --manifest-path programs/vault/Cargo.toml --features "$FEATURES"
else
  echo "building vault.so with NO features (mainnet shape)"
  cargo build-sbf --manifest-path programs/vault/Cargo.toml
fi

SO="$ROOT/target/deploy/vault.so"
test -f "$SO" || { echo "expected $SO after build-sbf" >&2; exit 1; }

# Two-line manifest: the feature set the artifact was built with, then the
# fingerprint of the source it was built from. The reader needs the feature set
# to recompute the fingerprint, and needs it stated explicitly so it can also
# reject an artifact built without `devnet-admin` (which omits instructions the
# LiteSVM suite exercises, and would otherwise fail in confusing ways deep
# inside a test rather than at load).
FP="$(bash "$ROOT/scripts/vault-sbf-fingerprint.sh" "$FEATURES")"
{
  printf 'features=%s\n' "$FEATURES"
  printf 'fingerprint=%s\n' "$FP"
} > "$SO.fingerprint"
echo "wrote $SO.fingerprint (features='$FEATURES', fingerprint=$FP)"
