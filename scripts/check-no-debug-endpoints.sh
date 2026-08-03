#!/usr/bin/env bash
# Guard: `debug_endpoints` must never be enabled in a normal build (SW-33).
#
# `api/debug.rs` exposes an UNAUTHENTICATED `POST /__debug/oracle/seed` that
# writes straight into the `OracleCache`, bypassing Hermes + VAA verification
# entirely. Its own doc says the feature "MUST be off in any production build".
#
# It is off — but for a reason that is easy to destroy by accident:
#
#   * `crates/darknyx-tee/Cargo.toml` has `default = []`, and
#   * the loadgen requests the feature only under `[dev-dependencies]`, and
#   * the root `Cargo.toml` sets `resolver = "2"`, which does NOT unify features
#     requested by dev-dependencies into normal builds.
#
# Under resolver v1, that same `cargo build --workspace --release` WOULD have
# enabled it, shipping an unauthenticated oracle-write endpoint inside the
# enclave. So a real security boundary rests on one word in a manifest that
# reads like a routine build setting.
#
# WHY A GUARD RATHER THAN A COMMENT: the on-chain analogue is treated far more
# carefully — CLAUDE.md §2.3 documents the vault's `--features devnet-admin` as
# "OFF by default (audit_1 F-01/F-02) so a MAINNET build ships neither backdoor",
# because audit_1 rated exactly this shape a significant finding. The enclave's
# equivalent had the same correct default and none of the surrounding
# discipline. This makes the invariant testable instead of incidental.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() { echo "check-no-debug-endpoints: FAIL — $*" >&2; exit 1; }

# 1. The feature must not be on by default.
if ! grep -qE '^default = \[\]' crates/darknyx-tee/Cargo.toml; then
  fail "crates/darknyx-tee/Cargo.toml no longer has 'default = []'; \
debug_endpoints may now ship in a normal build"
fi

# 2. The resolver must stay at v2. Under v1 a dev-dependency's feature request
#    unifies into normal builds and turns the endpoint on everywhere.
if ! grep -qE '^resolver = "2"' Cargo.toml; then
  fail "root Cargo.toml is not on resolver \"2\" — a dev-dependency's \
debug_endpoints request would unify into normal builds"
fi

# 3. Nothing outside dev-dependencies may request the feature. A normal
#    dependency edge, a Dockerfile ARG, or a workflow flag all defeat 1 and 2.
#    Section-aware: a `[dev-dependencies]` request is fine, the same line under
#    `[dependencies]` is not, and the two are indistinguishable line-by-line —
#    which is why this is a parser and not a grep. (The first version of this
#    check WAS a grep and false-positived on the loadgen's legitimate
#    dev-dependency, which is the same blindness that would let a real offender
#    through in a differently-ordered manifest.)
offenders=$(python3 - <<'PYEOF'
import os, re, sys

# ONLY dev-dependencies is safe. `[features]` was in this set at first and made
# the guard useless: a mutation moving the loadgen's request out of
# dev-dependencies landed under `[features]` and passed. The feature's own
# `debug_endpoints = []` declaration is handled by the regex below, so nothing
# legitimate needs `[features]` here — and `full = ["debug_endpoints"]` in a
# features table WOULD be a real offender, since `--features full` would then
# enable the endpoint.
SAFE_SECTION = "dev-dependencies"
hits = []


def is_safe_section(header):
    """True for a dev-dependency table in any of its spellings.

    `[dev-dependencies]`, the per-crate `[dev-dependencies.darknyx-tee]` (the
    idiomatic place to write `features = ["debug_endpoints"]`), and both
    target-specific forms `[target.'cfg(unix)'.dev-dependencies][.crate]`.

    Matching on the LAST dotted segment handled only the first and third: a
    per-crate subtable ends in the crate name, so a legitimate manifest would
    have been reported as an offender. `[dependencies.foo]` stays unsafe
    because no segment is `dev-dependencies`, which is the distinction that
    matters — quotes are stripped so a quoted cfg predicate cannot smuggle one
    in.
    """
    return any(
        seg.strip().strip("'\"") == SAFE_SECTION for seg in header.split(".")
    )

for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in {"target", "node_modules", ".git"}]
    for name in files:
        path = os.path.join(root, name)
        if path.endswith("scripts/check-no-debug-endpoints.sh"):
            continue
        is_toml = name == "Cargo.toml"
        # A cargo config can enable the feature through an alias
        # (`[alias] tee = "run --features debug_endpoints"`), which is a normal
        # build wearing a short name and defeats checks 1 and 2 exactly as a
        # Dockerfile flag would. It has no dependency tables, so nothing in it
        # is ever safe — scanned with section awareness OFF.
        is_cargo_cfg = name in ("config.toml", "config") and os.path.basename(
            root
        ) in (".cargo", "cargo")
        is_other = name.startswith("Dockerfile") or name.endswith(
            (".yml", ".yaml", ".sh")
        )
        if not (is_toml or is_cargo_cfg or is_other):
            continue
        try:
            lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
        except OSError:
            continue

        section = ""
        for n, line in enumerate(lines, 1):
            if is_toml:
                m = re.match(r"\s*\[([^\]]+)\]", line)
                if m:
                    section = m.group(1)
            if "debug_endpoints" not in line:
                continue
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # The feature's own declaration.
            if re.match(r"debug_endpoints\s*=\s*\[", stripped):
                continue
            if is_toml and is_safe_section(section):
                continue
            hits.append(f"{path}:{n}: {stripped}")

print("\n".join(hits))
PYEOF
)
if [ -n "$offenders" ]; then
  fail "debug_endpoints is requested outside [dev-dependencies]:
$offenders"
fi

# 4. The route itself must be feature-gated at the source, so that even if the
#    feature were enabled the gating is visible rather than implicit.
if ! grep -qE '#\[cfg\(feature = "debug_endpoints"\)\]' crates/darknyx-tee/src/api/mod.rs; then
  fail "the /__debug route in api/mod.rs is no longer behind \
#[cfg(feature = \"debug_endpoints\")]"
fi

echo "debug-endpoint exclusion check passed: /__debug is off by default, \
resolver v2 keeps it off, and nothing outside dev-dependencies asks for it"
