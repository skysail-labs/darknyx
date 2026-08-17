# syntax=docker/dockerfile:1.6
#
# darknyx-tee Dockerfile — multi-stage Rust build → slim Debian runtime.
#
# This image gets deployed into a Phala Cloud Confidential VM via
# `phala deploy -c deploy/docker-compose.yaml`. The image's SHA-256
# digest is embedded in `app-compose.json`, which gets hashed into
# the `compose_hash` recorded in RTMR3. Any change to this Dockerfile
# (including base-image tag, build command, or COPY order) changes
# the compose-hash and therefore requires a new image authorization
# in dstack governance + a multisig rotation of
# `vault_config.tee_pubkey` on Solana. See docs/tee-attestation-flow.md
# §5 (the rotation ceremony).
#
# IMPORTANT — reproducibility:
#   * Base images MUST be pinned by digest (not by tag), otherwise
#     compose-hash drifts on every Docker pull. See `--platform` and
#     `@sha256:...` pins below.
#   * The `cargo build` step must be hermetic — no `git` calls, no
#     network access during build other than `cargo fetch`. We rely
#     on the lockfile for reproducibility.
#   * Don't add `LABEL` directives with timestamps / commits / etc.
#     unless the build is also reproducible (those bake into the
#     layer and shift compose-hash).
#
# Phase 1: the image runs the no-op skeleton (`cargo run -p darknyx-tee`
# just probes the dstack socket and exits). Once darknyx-tee actually
# serves traffic, expose port 8080 and add a HEALTHCHECK.
# ─────────────────────────────────────────────────────────────────────

# ─────────── Stage 1: builder ───────────
# rust:1.93-slim-bookworm — matches rust-toolchain.toml's floor, which the
# Anchor v2 port raised 1.91 -> 1.93: litesvm 0.15.x pulls solana-syscalls
# 4.2.x, which uses `maybe_uninit_write_slice` (stable only from 1.93), and
# downgrading solana-syscalls is blocked by a solana-program-runtime conflict.
# This base MUST move with rust-toolchain.toml — a 1.91 base would either fail
# the build or silently re-download a second toolchain inside the image.
#
# PINNED BY DIGEST (the multi-arch index — `--platform linux/amd64` still
# selects the amd64 variant). A floating tag would let the base drift on every
# pull and silently shift `compose_hash` (the attestation-relevant artifact
# baked into RTMR3). Re-resolve + bump deliberately with:
#   docker buildx imagetools inspect rust:1.93-slim-bookworm --format '{{.Manifest.Digest}}'
#
# ARCHITECTURE — build this for linux/amd64. Phala TDX CVMs are
# x86_64; an arm64 image (the default on Apple Silicon) fails the CVM
# pull with "no matching manifest for linux/amd64". Build it on a
# native amd64 host — i.e. a CI runner (`ubuntu-latest`) with
# `docker buildx build --platform linux/amd64 --push` — rather than
# cross-building under QEMU on a Mac (slow, and emulated build cycles
# are wasteful). See .github/workflows/tee-image.yml.
FROM rust:1.93-slim-bookworm@sha256:5b9332190bb3b9ece73b810cd1f1e9f06343b294ce184bcb067f0747d7d333ea AS builder

WORKDIR /build

# LTO is forced off for the image build. The workspace profile.release
# uses `lto = "fat"`, which is slow in CI/Docker for no meaningful win
# on a long-running service binary. Overridden via env so the committed
# profile.release is untouched — local host builds and the BPF programs
# still link with fat LTO.
#
# NB: the __rust_probestack link failure that blocked the first
# x86_64-linux builds of this binary (wasmer 4.4, pulled via ark-circom,
# references that x86 stack-probe intrinsic which Rust 1.91 no longer
# exports) is fixed at the source level in
# crates/darknyx-tee/src/probestack.rs — NOT with a linker/gc-sections
# workaround here. Stock Rust defaults (rust-lld, --gc-sections) link
# fine once the symbol is supplied. See memory `tee_binary_amd64_link`.
ENV CARGO_PROFILE_RELEASE_LTO=off

# System deps needed to build solana-poseidon + ark-* on Debian.
# Keep this list tight; every package on the build side leaks into
# CVE-monitoring scope.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        clang \
        cmake \
        ca-certificates \
        build-essential \
        nasm \
        m4 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ─── (optional) ICICLE CUDA backend toolchain — ENABLE_CUDA=1 ───
# Only the GPU image (DARKNYX_TEE_PROVER=icicle + DARKNYX_TEE_ICICLE_DEVICE=CUDA) needs
# this; the default CPU/rapidsnark image leaves ENABLE_CUDA=0 and skips it.
# nvcc + cudart-dev + curand-dev are enough to BUILD icicle's CUDA backend; no
# physical GPU is required because the build forwards DARKNYX_ICICLE_CUDA_ARCH so
# cmake skips its `native` GPU-arch probe (see the icicle build.rs change).
# Built on bookworm so the produced .so match the bookworm-slim runtime ABI
# (same glibc-match lesson as the native witness generator). The toolkit is
# multi-GB but stays in THIS builder stage — the runtime gets only cudart/curand.
# CUDA minor (12-6) must be within the H200 driver's compat window; bump if the
# apt package is unavailable or the deploy host's driver is older.
ARG ENABLE_CUDA=0
ARG CUDA_ARCH=90
ENV ICICLE_INSTALL_DIR=/build/icicle-install
# `git` is required by the icicle CPU backend's cmake: backend/cpu/CMakeLists.txt
# FetchContent's Taskflow v3.8.0 via GIT_REPOSITORY (a shallow clone) at configure
# time. Kept in the ENABLE_CUDA block so the CPU/rapidsnark image (which never
# compiles icicle) stays git-free. (Vendoring Taskflow for a hermetic build is a
# follow-up, like the gmp-download TODO.)
RUN if [ "$ENABLE_CUDA" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends gnupg wget git && \
        wget -qO /tmp/cuda-keyring.deb \
          https://developer.download.nvidia.com/compute/cuda/repos/debian12/x86_64/cuda-keyring_1.1-1_all.deb && \
        dpkg -i /tmp/cuda-keyring.deb && rm /tmp/cuda-keyring.deb && \
        apt-get update && apt-get install -y --no-install-recommends \
            cuda-nvcc-12-6 cuda-cudart-dev-12-6 libcurand-dev-12-6 && \
        ln -sf /usr/local/cuda-12.6 /usr/local/cuda && \
        rm -rf /var/lib/apt/lists/*; \
    fi
# nvcc lives at /usr/local/cuda/bin (symlinked above) — on PATH for cmake's
# find_package(CUDAToolkit). Harmless when ENABLE_CUDA=0 (the dir just doesn't exist).
ENV PATH=/usr/local/cuda/bin:$PATH

# ─── rapidsnark static libs (the `rapidsnark` prover backend) ───
# Built in its OWN early layer so it's cached across Rust-source changes
# (only invalidates when the third_party/rapidsnark submodule pin moves).
# We build ONLY the static lib target (not the pistache/libsodium server),
# so the link is self-contained: librapidsnark.a + libfr.a + libfq.a + a
# static libgmp.a. USE_ASM defaults ON for x86_64 (rapidsnark's primary,
# well-tested path). build_gmp.sh downloads the gmp tarball (build-time
# network) — vendoring it for a reproducible mainnet build is a follow-up.
COPY third_party/rapidsnark/ third_party/rapidsnark/
RUN cd third_party/rapidsnark && \
    ./build_gmp.sh host && \
    cmake -S . -B build_prover -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build_prover --target rapidsnarkStatic -j"$(nproc)"
ENV RAPIDSNARK_LIB_DIR=/build/third_party/rapidsnark/build_prover/src \
    RAPIDSNARK_GMP_LIB_DIR=/build/third_party/rapidsnark/depends/gmp/package/lib

# The vendored ICICLE prover (icicle-snark) is an OPTIONAL path dependency of
# darknyx-tee. Even the CPU-only (`--features rapidsnark`) build needs its manifest
# tree present, because cargo resolves the full dependency graph (incl. disabled
# optional deps) before building — without it, `cargo build -p darknyx-tee` fails at
# "failed to load source for dependency icicle-snark". The `icicle-cuda` build
# additionally compiles its CUDA backend from this source. Copied before the
# warmup so resolution succeeds; **/target is .dockerignore'd.
COPY third_party/icicle-snark/ third_party/icicle-snark/

# Copy workspace manifests + lockfile first so Docker layer caching
# can re-use the dependency build across iterations.
COPY Cargo.toml Cargo.lock ./
COPY crates/darkpool-crypto/Cargo.toml  crates/darkpool-crypto/
COPY crates/darkpool-matcher/Cargo.toml crates/darkpool-matcher/
COPY crates/darknyx-tee/Cargo.toml          crates/darknyx-tee/
# darknyx-tee-loadgen is a workspace member, so cargo must be able to
# parse its manifest to resolve the workspace graph — even though the
# warmup below only builds `-p darknyx-tee`. Without this COPY the warmup
# aborts with "failed to read .../darknyx-tee-loadgen/Cargo.toml", losing
# the dependency-cache layer (the real build still succeeds, just
# slower). It is NOT compiled into the runtime image.
COPY crates/darknyx-tee-loadgen/Cargo.toml  crates/darknyx-tee-loadgen/
COPY programs/vault/Cargo.toml          programs/vault/

# Create dummy main.rs/lib.rs so the dep build doesn't fail on
# missing sources. The real sources come in the next COPY.
RUN mkdir -p crates/darkpool-crypto/src crates/darkpool-matcher/src \
             crates/darknyx-tee/src crates/darknyx-tee-loadgen/src \
             programs/vault/src && \
    echo 'fn main() {}' > crates/darknyx-tee/src/main.rs && \
    echo 'fn main() {}' > crates/darknyx-tee-loadgen/src/main.rs && \
    echo 'fn main() {}' > crates/darknyx-tee/build.rs && \
    touch crates/darknyx-tee/src/lib.rs \
          crates/darkpool-crypto/src/lib.rs \
          crates/darkpool-matcher/src/lib.rs \
          crates/darknyx-tee-loadgen/src/lib.rs \
          programs/vault/src/lib.rs && \
    cargo build --release -p darknyx-tee || true

# Now the real sources.
COPY crates/ crates/
COPY programs/ programs/

# CRITICAL — bump the mtime of every workspace source after the COPY.
# The warmup above compiled the path-dep crates from EMPTY dummy
# lib.rs files and cached those .rlibs. COPY preserves the build
# context's (older) mtimes, so without this touch cargo considers the
# cached empty crates "up to date" and links darknyx-tee against empty
# darkpool-crypto / darkpool-matcher — surfacing as a wall of
# `unresolved import` / `fr_to_be_bytes not found` errors. Touching
# forces a rebuild of just the workspace crates; the external-dep
# cache (tokio, ark-*, …) is keyed separately and is preserved.
# Build features depend on ENABLE_CUDA: the CPU image ships rapidsnark; the GPU
# image additionally builds the ICICLE CUDA backend (icicle-cuda → icicle-snark
# → cmake/nvcc, arch pinned via DARKNYX_ICICLE_CUDA_ARCH=$CUDA_ARCH so no GPU is
# needed at build). `mkdir -p $ICICLE_INSTALL_DIR/lib` unconditionally so the
# runtime stage's COPY of the icicle libs always has a (possibly empty) source.
#
# ⚠️ This var name MUST be one the PINNED submodule's build script actually reads
# (third_party/icicle-snark/wrappers/rust/icicle-runtime/build.rs → `-DCUDA_ARCH`).
# If it is not, the setting is silently dropped, cmake falls back to
# `CUDA_ARCHITECTURES=native`, probes for a GPU the CI builder does not have, and
# the build dies with `CUDA_ARCHITECTURES is set to "native", but no GPU was
# detected` — exactly what happened on 2026-07-21, when this forwarded the
# renamed variable while the pinned fork still only read the pre-rename
# `NYX_ICICLE_CUDA_ARCH`. The fork now accepts BOTH (this canonical name, plus
# the old one as a deprecated warning fallback) and
# `scripts/check-icicle-cuda-arch-env.sh` pins the pairing in CI.
RUN find crates programs -name '*.rs' -exec touch {} + && \
    mkdir -p "$ICICLE_INSTALL_DIR/lib" && \
    if [ "$ENABLE_CUDA" = "1" ]; then \
        DARKNYX_ICICLE_CUDA_ARCH="$CUDA_ARCH" \
          cargo build --release -p darknyx-tee --features rapidsnark,icicle-cuda; \
    else \
        cargo build --release -p darknyx-tee --features rapidsnark; \
    fi && \
    cp /build/target/release/darknyx-tee /darknyx-tee && \
    strip /darknyx-tee

# ─────────── Stage 2: runtime ───────────
# debian:bookworm-slim — minimal Debian. We pick Debian (not Alpine)
# because solana-client + rustls + ed25519-dalek work cleanly on
# glibc and we don't need to fight musl quirks. PINNED BY DIGEST (the
# multi-arch index) for a stable compose_hash — re-resolve + bump with
# `docker buildx imagetools inspect debian:bookworm-slim --format '{{.Manifest.Digest}}'`.
# Keep this digest IN SYNC with the witness-gen container in tee-image.yml
# (same base, same glibc/ABI — the native witness binary must match this runtime).
FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716 AS runtime

# Mirrors the builder ARG (ARGs are per-stage). ENABLE_CUDA=1 pulls in the CUDA
# userspace runtime libs + the icicle backend .so for the GPU image.
ARG ENABLE_CUDA=0

# ca-certificates: needed for outbound HTTPS to Helius RPC + Pyth.
# tini: PID 1 reaper, gives us clean signal handling.
# libstdc++6: the rapidsnark static libs (librapidsnark/fr/fq) are C++;
#   gmp is linked statically but libstdc++ is dynamic, so the runtime needs
#   the C++ runtime. (gmp itself adds NO runtime dep — it's static.)
# libgmp10: the native circom `--c` witness generator (circuit_cpp/circuit,
#   below) links gmp DYNAMICALLY (`-lgmp`), unlike the static rapidsnark libs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tini \
        libstdc++6 \
        libgomp1 \
        libgmp10 \
    && rm -rf /var/lib/apt/lists/*

# ─── (optional) CUDA userspace runtime libs — ENABLE_CUDA=1 ───
# The icicle CUDA backend .so links cudart (+ curand for the proof blinding).
# These are USERSPACE libs and MUST be in the image. The GPU DRIVER itself
# (libcuda.so.1) is NOT baked — the nvidia container runtime injects it on the
# Phala H200 host at deploy. Keep the runtime base on bookworm (glibc match);
# do NOT switch to an nvidia/cuda runtime image (different glibc). A few hundred
# MB, vs the multi-GB build toolkit that stays in the builder stage.
RUN if [ "$ENABLE_CUDA" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends gnupg wget && \
        wget -qO /tmp/cuda-keyring.deb \
          https://developer.download.nvidia.com/compute/cuda/repos/debian12/x86_64/cuda-keyring_1.1-1_all.deb && \
        dpkg -i /tmp/cuda-keyring.deb && rm /tmp/cuda-keyring.deb && \
        apt-get update && apt-get install -y --no-install-recommends \
            cuda-cudart-12-6 libcurand-12-6 libatomic1 && \
        rm -rf /var/lib/apt/lists/*; \
    fi
# libatomic1: the icicle frontend/backend .so reference libatomic.so.1 (GCC
# atomic intrinsics). Caught by the no-GPU verify step (ldd "not found"). It is
# in the base Debian repo (not the CUDA repo) but gated here since only the GPU
# image links icicle.

# Run as a non-root user. UID/GID are fixed so the volume mounts
# behave predictably across deploys.
RUN groupadd -g 1100 darknyx && useradd -u 1100 -g 1100 -M -s /sbin/nologin darknyx

WORKDIR /opt/darknyx

# Binary. Owned by root, executable by everyone — running as darknyx user.
COPY --from=builder --chmod=755 /darknyx-tee /opt/darknyx/darknyx-tee

# ICICLE shared libs (frontend + CUDA backend). For the CPU image the builder's
# $ICICLE_INSTALL_DIR/lib is an empty dir (mkdir -p above), so this COPY is a
# no-op; for the GPU image it carries libicicle_device.so + the bn254 field/curve
# .so (frontend) and lib/backend/**/libicicle_backend_cuda_*.so (loaded at runtime
# from ICICLE_BACKEND_INSTALL_DIR). The darknyx-tee binary RPATHs the build-host install
# dir (absent here), so LD_LIBRARY_PATH points the loader at the frontend .so.
# Both ENVs are inert for the CPU image: the loader is only invoked when
# DARKNYX_TEE_ICICLE_DEVICE != CPU (icicle-snark lib.rs), and the dir is empty.
COPY --from=builder /build/icicle-install/lib/ /opt/icicle/lib/
ENV ICICLE_BACKEND_INSTALL_DIR=/opt/icicle/lib/backend \
    LD_LIBRARY_PATH=/opt/icicle/lib

# N=16 settle-prover artifacts. The runtime reads DARKNYX_TEE_CIRCUITS_DIR
# (default /circuits/build) and resolves
# match_batch_n16/{circuit_final.zkey, circuit.r1cs, circuit_js/circuit.wasm}
# (see crates/darknyx-tee/src/prover/ark_prover.rs). Without these the settle
# driver boots enqueue-only ("load N=16 prover ... No such file").
#
# Only circuit_final.zkey is git-tracked; circuit.r1cs + circuit.wasm are
# gitignored and compiled in CI (circom, no ptau needed — the zkey's
# ceremony is already committed) before this build. See
# .github/workflows/tee-image.yml + .dockerignore.
COPY --chown=darknyx:darknyx circuits/build/match_batch_n16/circuit_final.zkey \
     /circuits/build/match_batch_n16/circuit_final.zkey
COPY --chown=darknyx:darknyx circuits/build/match_batch_n16/circuit.r1cs \
     /circuits/build/match_batch_n16/circuit.r1cs
COPY --chown=darknyx:darknyx circuits/build/match_batch_n16/circuit_js/circuit.wasm \
     /circuits/build/match_batch_n16/circuit_js/circuit.wasm

# The native circom `--c` C++ witness generator (amd64 binary, built in CI from
# `circom --c` + make on the runner). When DARKNYX_TEE_WITNESS=native the prover
# spawns this instead of wasmer (≈18× faster witness-gen; see witness-bench).
# `circuit.dat` (the witness-gen constants) MUST sit next to the binary —
# main.cpp loads `<argv[0]>.dat` at runtime. Gitignored + CI-built like the
# wasm/r1cs above.
COPY --chown=darknyx:darknyx --chmod=755 circuits/build/match_batch_n16/circuit_cpp/circuit \
     /circuits/build/match_batch_n16/circuit_cpp/circuit
COPY --chown=darknyx:darknyx circuits/build/match_batch_n16/circuit_cpp/circuit.dat \
     /circuits/build/match_batch_n16/circuit_cpp/circuit.dat

# Persistent state dir for the Phase-1b auth snapshot (accounts.db).
# MUST be created + chowned to the runtime user BEFORE `USER darknyx`: when
# the empty `darknyx_state` named volume (docker-compose.yaml) first mounts
# here, Docker initialises it with this mountpoint's ownership. Without
# the chown the volume is root-owned, the `darknyx` process gets EACCES on
# every write, and persistence silently no-ops (best-effort) — exactly
# the spot-check regression this fixes. See DARKNYX_TEE_STATE_DIR.
RUN mkdir -p /var/lib/darknyx-tee && chown darknyx:darknyx /var/lib/darknyx-tee

USER darknyx

# darknyx-tee listens on :8080 internally; dstack-ingress fronts it on
# :443 over RA-HTTPS. Don't EXPOSE :443 here — that's
# dstack-ingress's job (see docker-compose.yaml).
EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/opt/darknyx/darknyx-tee"]
