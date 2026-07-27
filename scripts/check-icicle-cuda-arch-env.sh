#!/usr/bin/env bash
# Guard: the CUDA-arch env var the Dockerfile forwards MUST be one the PINNED
# icicle-snark submodule's build script actually reads.
#
# Why this exists: on 2026-07-21 a GPU image build died with
#   CMake Error in backend/cuda/CMakeLists.txt:
#     CUDA_ARCHITECTURES is set to "native", but no GPU was detected.
# The Dockerfile had been renamed to DARKNYX_ICICLE_CUDA_ARCH during the
# Darknyx brand rename while the vendored fork's build.rs still only read
# NYX_ICICLE_CUDA_ARCH. The name never matched, so `-DCUDA_ARCH` was never
# defined, cmake fell back to probing for a GPU the CI builder does not have,
# and the build failed.
#
# The failure is expensive and LATE: it only surfaces on a `-cuda` image build
# (rare), after the multi-GB CUDA toolkit layer has already been installed.
# This check catches the same mismatch in seconds, on every PR.
#
# Usage: bash scripts/check-icicle-cuda-arch-env.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCKERFILE="$ROOT/deploy/Dockerfile"
WRAPPERS="$ROOT/third_party/icicle-snark/wrappers/rust"

if [ ! -d "$WRAPPERS" ]; then
  echo "SKIP: $WRAPPERS not present (submodule not checked out)."
  echo "      Run: git submodule update --init --recursive third_party/icicle-snark"
  exit 0
fi

# EVERY build script that drives its own cmake CUDA backend must read the same
# var — they are independent cmake invocations, so one straggler is enough to
# fail the image build. Checking only icicle-runtime is what let the 2026-07-27
# `-cuda` failure through: the runtime read DARKNYX_*, icicle-bn254 still read
# only NYX_*, and this guard reported the pairing as correct.
BUILD_SCRIPTS="$(grep -rl 'CUDA_BACKEND' "$WRAPPERS" --include=build.rs | sort)"

if [ -z "$BUILD_SCRIPTS" ]; then
  echo "FAIL: no icicle build.rs under $WRAPPERS references CUDA_BACKEND."
  echo "      The submodule layout changed; this guard needs updating."
  exit 1
fi

# The var the Dockerfile forwards into the icicle-cuda cargo build, e.g.
#   DARKNYX_ICICLE_CUDA_ARCH="$CUDA_ARCH" \
DOCKER_VAR="$(grep -oE '^[[:space:]]*[A-Z_]*ICICLE_CUDA_ARCH=' "$DOCKERFILE" \
  | head -1 | tr -d ' ' | tr -d '=')"

if [ -z "$DOCKER_VAR" ]; then
  echo "FAIL: no *ICICLE_CUDA_ARCH= assignment found in deploy/Dockerfile."
  echo "      The GPU build needs it, or cmake probes for a GPU and fails."
  exit 1
fi

failed=0
for build_rs in $BUILD_SCRIPTS; do
  rel="${build_rs#"$ROOT"/}"

  # Every name this build.rs reads via env::var("...").
  READ_VARS="$(grep -oE 'env::var\("[A-Z_]*ICICLE_CUDA_ARCH"\)' "$build_rs" \
    | sed -E 's/env::var\("([A-Z_]+)"\)/\1/' | sort -u)"

  if [ -z "$READ_VARS" ]; then
    echo "FAIL: $rel reads no *ICICLE_CUDA_ARCH var."
    echo "      The submodule pointer may predate the CUDA-arch patch."
    failed=1
    continue
  fi

  if ! printf '%s\n' "$READ_VARS" | grep -qx "$DOCKER_VAR"; then
    echo "FAIL: CUDA-arch env var drift between the Dockerfile and the pinned submodule."
    echo "  deploy/Dockerfile forwards : $DOCKER_VAR"
    echo "  $rel reads : $(printf '%s' "$READ_VARS" | tr '\n' ' ')"
    failed=1
    continue
  fi

  echo "ok: $rel reads $DOCKER_VAR"
done

if [ "$failed" -ne 0 ]; then
  echo
  echo "  Effect if shipped: the value is silently dropped, cmake falls back to"
  echo "  CUDA_ARCHITECTURES=native, probes for a GPU the builder lacks, and the"
  echo "  -cuda image build fails late with 'no GPU was detected'."
  echo
  echo "  Fix: align the names in EVERY listed build script, or bump"
  echo "  third_party/icicle-snark to a commit whose build scripts all read"
  echo "  $DOCKER_VAR."
  exit 1
fi

echo "icicle CUDA-arch env check passed: Dockerfile forwards $DOCKER_VAR; every CUDA build script reads it."
