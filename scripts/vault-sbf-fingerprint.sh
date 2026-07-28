#!/usr/bin/env bash
# Print a content fingerprint of everything that determines the compiled
# `target/deploy/vault.so`.
#
# WHY CONTENT, NOT MTIME: a timestamp check answers "was the file written after
# the source?", which is the wrong question. It goes wrong in both directions —
# a `git checkout` or `touch` rewrites mtimes without changing code, and a
# rebuild from a *different feature set* leaves a newer .so that is still the
# wrong binary. A hash over the inputs answers the question that matters: "is
# this .so the one this source would produce?"
#
# This is the SINGLE definition of the fingerprint. `build-vault-sbf.sh` writes
# it beside the artifact and `programs/vault/tests/common` re-runs this script
# to compare, so the two can never drift apart.
#
# Inputs that change the binary:
#   - every tracked source file under programs/vault/
#   - the vault + workspace manifests and the lockfile
#   - the toolchain pin
#   - the cargo feature set the artifact was built with (passed as $1)
#
# Usage: bash scripts/vault-sbf-fingerprint.sh [features]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FEATURES="${1:-}"

cd "$ROOT"

# Sorted so the digest is order-stable across filesystems. `-print0`/`-d ''`
# so a path containing whitespace cannot split a record.
hash_inputs() {
  printf 'features=%s\n' "$FEATURES"
  while IFS= read -r -d '' f; do
    printf '%s ' "$f"
    shasum -a 256 "$f" | awk '{print $1}'
  done < <(find programs/vault/src -type f -name '*.rs' -print0 | sort -z)
  for f in programs/vault/Cargo.toml Cargo.toml Cargo.lock rust-toolchain.toml; do
    if [ -f "$f" ]; then
      printf '%s ' "$f"
      shasum -a 256 "$f" | awk '{print $1}'
    fi
  done
}

hash_inputs | shasum -a 256 | awk '{print $1}'
