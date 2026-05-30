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
    && rm -rf /var/lib/apt/lists/*

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
COPY programs/matching_engine/Cargo.toml programs/matching_engine/

# Create dummy main.rs/lib.rs so the dep build doesn't fail on
# missing sources. The real sources come in the next COPY.
RUN mkdir -p crates/darkpool-crypto/src crates/darkpool-matcher/src \
             crates/nyx-tee/src crates/nyx-tee-loadgen/src \
             programs/vault/src programs/matching_engine/src && \
    echo 'fn main() {}' > crates/nyx-tee/src/main.rs && \
    echo 'fn main() {}' > crates/nyx-tee-loadgen/src/main.rs && \
    touch crates/nyx-tee/src/lib.rs \
          crates/darkpool-crypto/src/lib.rs \
          crates/darkpool-matcher/src/lib.rs \
          crates/nyx-tee-loadgen/src/lib.rs \
          programs/vault/src/lib.rs \
          programs/matching_engine/src/lib.rs && \
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
    cargo build --release -p nyx-tee && \
    cp /build/target/release/nyx-tee /nyx-tee && \
    strip /nyx-tee

# ─────────── Stage 2: runtime ───────────
# debian:bookworm-slim — minimal Debian. We pick Debian (not Alpine)
# because solana-client + rustls + ed25519-dalek work cleanly on
# glibc and we don't need to fight musl quirks.
FROM debian:bookworm-slim AS runtime

# ca-certificates: needed for outbound HTTPS to Helius RPC + Pyth.
# tini: PID 1 reaper, gives us clean signal handling.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user. UID/GID are fixed so the volume mounts
# behave predictably across deploys.
RUN groupadd -g 1100 nyx && useradd -u 1100 -g 1100 -M -s /sbin/nologin nyx

WORKDIR /opt/nyx

# Binary. Owned by root, executable by everyone — running as nyx user.
COPY --from=builder --chmod=755 /nyx-tee /opt/nyx/nyx-tee

# TODO(phase 2): COPY the compiled VALID_MATCH_BATCH zkey + the
# right-path zkeys into /opt/nyx/circuits/. Once that's in place,
# point prover/groth16.rs at /opt/nyx/circuits/match_batch_n16/
# circuit_final.zkey.

USER nyx

# nyx-tee listens on :8080 internally; dstack-ingress fronts it on
# :443 over RA-HTTPS. Don't EXPOSE :443 here — that's
# dstack-ingress's job (see docker-compose.yaml).
EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/opt/nyx/nyx-tee"]
