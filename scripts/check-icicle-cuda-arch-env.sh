#!/usr/bin/env bash
# Guard: the CUDA-arch env var the Dockerfile forwards MUST be one the PINNED
# icicle-snark submodule's build script actually reads.
#
# Why this exists: on 2026-07-21 a GPU image build died with
#   CMake Error in backend/cuda/CMakeLists.txt:
#     CUDA_ARCHITECTURES is set to "native", but no GPU was detected.
# The Dockerfile had been renamed to DARKNYX_ICICLE_CUDA_ARCH during the
# nyx->darknyx cutover while the vendored fork's build.rs still only read
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
BUILD_RS="$ROOT/third_party/icicle-snark/wrappers/rust/icicle-runtime/build.rs"

if [ ! -f "$BUILD_RS" ]; then
  echo "SKIP: $BUILD_RS not present (submodule not checked out)."
  echo "      Run: git submodule update --init --recursive third_party/icicle-snark"
  exit 0
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

# Every name the pinned build.rs reads via env::var("...").
READ_VARS="$(grep -oE 'env::var\("[A-Z_]*ICICLE_CUDA_ARCH"\)' "$BUILD_RS" \
  | sed -E 's/env::var\("([A-Z_]+)"\)/\1/' | sort -u)"

if [ -z "$READ_VARS" ]; then
  echo "FAIL: the pinned icicle-snark build.rs reads no *ICICLE_CUDA_ARCH var."
  echo "      The submodule pointer may predate the CUDA-arch patch."
  exit 1
fi

if ! printf '%s\n' "$READ_VARS" | grep -qx "$DOCKER_VAR"; then
  echo "FAIL: CUDA-arch env var drift between the Dockerfile and the pinned submodule."
  echo "  deploy/Dockerfile forwards : $DOCKER_VAR"
  echo "  pinned build.rs reads      : $(printf '%s' "$READ_VARS" | tr '\n' ' ')"
  echo
  echo "  Effect if shipped: the value is silently dropped, cmake falls back to"
  echo "  CUDA_ARCHITECTURES=native, probes for a GPU the builder lacks, and the"
  echo "  -cuda image build fails late with 'no GPU was detected'."
  echo
  echo "  Fix: align the names, or bump third_party/icicle-snark to a commit whose"
  echo "  build.rs reads $DOCKER_VAR."
  exit 1
fi

echo "icicle CUDA-arch env check passed: Dockerfile forwards $DOCKER_VAR; pinned build.rs reads it."
