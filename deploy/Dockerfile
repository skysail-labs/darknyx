# syntax=docker/dockerfile:1.6
#
# nyx-tee Dockerfile — multi-stage Rust build → slim Debian runtime.
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
# Phase 1: the image runs the no-op skeleton (`cargo run -p nyx-tee`
# just probes the dstack socket and exits). Once nyx-tee actually
# serves traffic, expose port 8080 and add a HEALTHCHECK.
# ─────────────────────────────────────────────────────────────────────

# ─────────── Stage 1: builder ───────────
# rust:1.91-slim-bookworm — matches rust-toolchain.toml's 1.91 floor
# (the dstack-sdk → alloy → ruint chain requires rustc 1.91+).
# TODO(phase1): pin to a SHA-256 digest
# once we're past the rapid-iteration scaffolding phase. For now
# the tag is fine; the deploy is dev-only.
#
# ARCHITECTURE — build this for linux/amd64. Phala TDX CVMs are
# x86_64; an arm64 image (the default on Apple Silicon) fails the CVM
# pull with "no matching manifest for linux/amd64". Build it on a
# native amd64 host — i.e. a CI runner (`ubuntu-latest`) with
# `docker buildx build --platform linux/amd64 --push` — rather than
# cross-building under QEMU on a Mac (slow, and emulated build cycles
# are wasteful). See .github/workflows/tee-image.yml.
FROM rust:1.91-slim-bookworm AS builder

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
# crates/nyx-tee/src/probestack.rs — NOT with a linker/gc-sections
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

# Copy workspace manifests + lockfile first so Docker layer caching
# can re-use the dependency build across iterations.
COPY Cargo.toml Cargo.lock ./
COPY crates/darkpool-crypto/Cargo.toml  crates/darkpool-crypto/
COPY crates/darkpool-matcher/Cargo.toml crates/darkpool-matcher/
COPY crates/nyx-tee/Cargo.toml          crates/nyx-tee/
# nyx-tee-loadgen is a workspace member, so cargo must be able to
# parse its manifest to resolve the workspace graph — even though the
# warmup below only builds `-p nyx-tee`. Without this COPY the warmup
# aborts with "failed to read .../nyx-tee-loadgen/Cargo.toml", losing
# the dependency-cache layer (the real build still succeeds, just
# slower). It is NOT compiled into the runtime image.
COPY crates/nyx-tee-loadgen/Cargo.toml  crates/nyx-tee-loadgen/
COPY programs/vault/Cargo.toml          programs/vault/

# Create dummy main.rs/lib.rs so the dep build doesn't fail on
# missing sources. The real sources come in the next COPY.
RUN mkdir -p crates/darkpool-crypto/src crates/darkpool-matcher/src \
             crates/nyx-tee/src crates/nyx-tee-loadgen/src \
             programs/vault/src && \
    echo 'fn main() {}' > crates/nyx-tee/src/main.rs && \
    echo 'fn main() {}' > crates/nyx-tee-loadgen/src/main.rs && \
    echo 'fn main() {}' > crates/nyx-tee/build.rs && \
    touch crates/nyx-tee/src/lib.rs \
          crates/darkpool-crypto/src/lib.rs \
          crates/darkpool-matcher/src/lib.rs \
          crates/nyx-tee-loadgen/src/lib.rs \
          programs/vault/src/lib.rs && \
    cargo build --release -p nyx-tee || true

# Now the real sources.
COPY crates/ crates/
COPY programs/ programs/

# CRITICAL — bump the mtime of every workspace source after the COPY.
# The warmup above compiled the path-dep crates from EMPTY dummy
# lib.rs files and cached those .rlibs. COPY preserves the build
# context's (older) mtimes, so without this touch cargo considers the
# cached empty crates "up to date" and links nyx-tee against empty
# darkpool-crypto / darkpool-matcher — surfacing as a wall of
# `unresolved import` / `fr_to_be_bytes not found` errors. Touching
# forces a rebuild of just the workspace crates; the external-dep
# cache (tokio, ark-*, …) is keyed separately and is preserved.
RUN find crates programs -name '*.rs' -exec touch {} + && \
    cargo build --release -p nyx-tee --features rapidsnark && \
    cp /build/target/release/nyx-tee /nyx-tee && \
    strip /nyx-tee

# ─────────── Stage 2: runtime ───────────
# debian:bookworm-slim — minimal Debian. We pick Debian (not Alpine)
# because solana-client + rustls + ed25519-dalek work cleanly on
# glibc and we don't need to fight musl quirks.
FROM debian:bookworm-slim AS runtime

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

# Run as a non-root user. UID/GID are fixed so the volume mounts
# behave predictably across deploys.
RUN groupadd -g 1100 nyx && useradd -u 1100 -g 1100 -M -s /sbin/nologin nyx

WORKDIR /opt/nyx

# Binary. Owned by root, executable by everyone — running as nyx user.
COPY --from=builder --chmod=755 /nyx-tee /opt/nyx/nyx-tee

# N=16 settle-prover artifacts. The runtime reads NYX_TEE_CIRCUITS_DIR
# (default /circuits/build) and resolves
# match_batch_n16/{circuit_final.zkey, circuit.r1cs, circuit_js/circuit.wasm}
# (see crates/nyx-tee/src/prover/ark_prover.rs). Without these the settle
# driver boots enqueue-only ("load N=16 prover ... No such file").
#
# Only circuit_final.zkey is git-tracked; circuit.r1cs + circuit.wasm are
# gitignored and compiled in CI (circom, no ptau needed — the zkey's
# ceremony is already committed) before this build. See
# .github/workflows/tee-image.yml + .dockerignore.
COPY --chown=nyx:nyx circuits/build/match_batch_n16/circuit_final.zkey \
     /circuits/build/match_batch_n16/circuit_final.zkey
COPY --chown=nyx:nyx circuits/build/match_batch_n16/circuit.r1cs \
     /circuits/build/match_batch_n16/circuit.r1cs
COPY --chown=nyx:nyx circuits/build/match_batch_n16/circuit_js/circuit.wasm \
     /circuits/build/match_batch_n16/circuit_js/circuit.wasm

# The native circom `--c` C++ witness generator (amd64 binary, built in CI from
# `circom --c` + make on the runner). When NYX_TEE_WITNESS=native the prover
# spawns this instead of wasmer (≈18× faster witness-gen; see witness-bench).
# Gitignored + CI-built like the wasm/r1cs above.
COPY --chown=nyx:nyx --chmod=755 circuits/build/match_batch_n16/circuit_cpp/circuit \
     /circuits/build/match_batch_n16/circuit_cpp/circuit

# Persistent state dir for the Phase-1b auth snapshot (accounts.db).
# MUST be created + chowned to the runtime user BEFORE `USER nyx`: when
# the empty `nyx_state` named volume (docker-compose.yaml) first mounts
# here, Docker initialises it with this mountpoint's ownership. Without
# the chown the volume is root-owned, the `nyx` process gets EACCES on
# every write, and persistence silently no-ops (best-effort) — exactly
# the spot-check regression this fixes. See NYX_TEE_STATE_DIR.
RUN mkdir -p /var/lib/nyx-tee && chown nyx:nyx /var/lib/nyx-tee

USER nyx

# nyx-tee listens on :8080 internally; dstack-ingress fronts it on
# :443 over RA-HTTPS. Don't EXPOSE :443 here — that's
# dstack-ingress's job (see docker-compose.yaml).
EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/opt/nyx/nyx-tee"]
