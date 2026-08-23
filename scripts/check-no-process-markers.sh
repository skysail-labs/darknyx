#!/usr/bin/env bash
# Fail if implementation-process markers reappear in the crates listed below.
#
# These are references to an internal PR/phase sequence (4g.3, PR 4e.2,
# "Phase 2", "slice 5") that resolve to nothing outside the code. They
# accumulate during implementation and then tell a later reader that a change
# happened without saying what is true now. The convention that replaces them
# is CLAUDE.md §10.5.
#
# Audit finding IDs (T-06, SW-01, U-02, ...) are NOT matched here: they still
# resolve to audits/residual-backlog.md and some are open. CLAUDE.md §10.5
# governs how they may be cited — alongside the substance, never alone.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Crates that have had the pass and must stay clean. Add one here the moment
# its cleanup lands — a crate absent from this list is simply unguarded, and an
# unguarded crate re-accumulates markers within months.
DEFAULT_TARGETS=(
  "$ROOT/crates/darknyx-tee"
  "$ROOT/crates/darkpool-crypto"
  "$ROOT/crates/darkpool-matcher"
  "$ROOT/programs/vault"
  "$ROOT/packages"
)
# `packages` is listed as ONE target rather than as its seven workspace members,
# deliberately: a new package is then covered the day it is created. Enumerating
# members instead would have left `client-prover-bench` unguarded, since it is
# pure .mjs and matches no .ts glob.
# darknyx-tee-loadgen is deliberately ABSENT. Its run.rs numbers the sequential
# stages of a load-test run ("Phase 1: plan + deposit", "Phase 2: prove all
# VALID_INPUT concurrently"), which the `phase[- ]N` pattern cannot tell apart
# from an implementation-process marker. Rewording correct prose to satisfy the
# tool is the wrong trade; the crate was swept by hand instead.

if [ "$#" -gt 0 ]; then
  TARGETS=("$@")
else
  TARGETS=("${DEFAULT_TARGETS[@]}")
fi

# Fail closed on a target we cannot scan. Without this the guard reports OK
# for a path that was renamed or typo'd, which is worse than no guard.
for t in "${TARGETS[@]}"; do
  if [ ! -d "$t" ] || [ ! -r "$t" ]; then
    echo "ERROR: target is not a readable directory: $t" >&2
    exit 2
  fi
done

# Source extensions only, and never generated output. The .devnet exclusion is
# load-bearing: `packages/browser-client/.devnet/` holds minified esbuild
# bundles whose mangled identifiers match both patterns dozens of times, so
# without it the guard fails on any tree where the browser release has been
# built. dist/ and node_modules/ are the same hazard.
SCAN_OPTS=(
  --include='*.rs' --include='*.ts' --include='*.tsx'
  --include='*.mjs' --include='*.cjs' --include='*.js'
  --exclude-dir=node_modules --exclude-dir=dist
  --exclude-dir=.devnet --exclude-dir=build --exclude-dir=coverage
)

# Matched forms: 4g.3 / PR 4e.2 / bare "PR 4g" / Phase 2 / slice 5.
#
# The bare "PR <n><letter>" form matters: an earlier revision required a ".N"
# suffix and so reported OK while "PR 4c" and "PR 4d" sat in tests/ untouched.
#
# "step N" is deliberately NOT matched. Measured across the three crates that
# have had the pass, it produced 1 true positive against 11 false ones —
# darkpool-matcher alone has nine numbered algorithm stages ("Step 4 — fee
# buckets") plus a spec citation ("Spec §20.6 step 73"), and darknyx-tee had a
# numeric increment ("0..=100 step 10"). At ~8% precision the rule stops being
# a guard and starts pressuring correct prose into being reworded around it.
# TypeScript reproduced this independently at 0 of 5 — every hit there cites a
# numbered step of the attestation verification procedure.
#
# Bare "phase" (no digit) must NEVER be matched either. The daemon models order
# lifecycle as `OrderPhase` / `TERMINAL_PHASES`, giving ~140 uses of the word as
# load-bearing domain vocabulary. The digit is the entire reason this pattern
# reaches 100% precision on TypeScript; dropping it inverts the ratio.
# Two patterns, because they need different case sensitivity.
#
# CI_PATTERN is case-insensitive: "PR 4g.3", "PR-4d", "4e.2", "Phase 2",
# "Phase-1b", "slice 5", "5-phase". Spellings were added as earlier sweeps
# missed them — the hyphenated "Phase-5" and "PR-4d" forms both slipped past a
# pattern built only from the space-separated examples already seen, and the
# REVERSED "5-phase" form then slipped past that one. One TypeScript file
# carried both spellings on two lines and only the second was caught. Enumerate
# the shapes a marker can take; do not extrapolate from the ones in front of
# you.
CI_PATTERN='(\bPR[- ]?[0-9]+[a-z]?(\.[0-9]+[a-z]*)?\b|\b[0-9]+[a-z]\.[0-9]+[a-z]*\b|\bslice [0-9]+|\bphase[- ][0-9]+[a-z]?\b|\b[0-9]+-phase\b)'

# CS_PATTERN is case-SENSITIVE: the "P0".."P7" work-item series, as in
# "Amount-privacy (P3b)". It must not be folded into the case-insensitive pass —
# lowercase p0/p1/p2 are ordinary local variable names in this codebase
# (`let p0 = dummy_payload();`), and matching them produced 57 false positives
# against 31 real ones.
CS_PATTERN='\bP[0-9][a-z]?\b'

# -i so lowercase "step 2" is caught too. grep exit 1 means "no matches"; any
# other non-zero status is a real failure (unreadable target, bad pattern) and
# must NOT be reported as a pass.
set +e
ci_hits=$(grep -rniE "$CI_PATTERN" "${SCAN_OPTS[@]}" "${TARGETS[@]}")
rc_ci=$?
cs_hits=$(grep -rnE "$CS_PATTERN" "${SCAN_OPTS[@]}" "${TARGETS[@]}")
rc_cs=$?
set -e
for rc in "$rc_ci" "$rc_cs"; do
  if [ "$rc" -gt 1 ]; then
    echo "ERROR: grep failed with status $rc while scanning ${TARGETS[*]}" >&2
    exit "$rc"
  fi
done
# `awk 'NF'` drops blank lines and exits 0 whether or not it matched, so no
# `|| true` is needed here. An earlier revision used `grep -v '^$' | ... || true`,
# which swallowed genuine pipeline failures as well as the expected no-match
# case — leaving $hits empty and the gate reporting OK. That is the same
# fail-open shape the readable-target check above exists to prevent.
hits=$(printf '%s\n%s' "$ci_hits" "$cs_hits" | awk 'NF' | sort -u)

if [ -n "$hits" ]; then
  echo "ERROR: implementation-process markers found" >&2
  echo >&2
  echo "$hits" >&2
  echo >&2
  echo "State what is true now instead of which change made it true." >&2
  echo "See CLAUDE.md §10.5 (Comment conventions)." >&2
  exit 1
fi

echo "check-no-process-markers: OK (${#TARGETS[@]} target(s))"
