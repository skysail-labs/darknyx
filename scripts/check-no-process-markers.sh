#!/usr/bin/env bash
# Fail if implementation-process markers reappear in crates/darknyx-tee.
#
# These are references to an internal PR/phase sequence (4g.3, PR 4e.2,
# "Phase 2", "slice 5") that resolve to nothing outside the crate. They
# accumulate during implementation and then tell a later reader that a change
# happened without saying what is true now. The convention that replaces them
# is crates/darknyx-tee/CONTRIBUTING.md.
#
# Audit finding IDs (T-06, SW-01, U-02, ...) are NOT matched here: they still
# resolve to audits/residual-backlog.md and some are open. CONTRIBUTING.md
# governs how they may be cited — alongside the substance, never alone.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-$ROOT/crates/darknyx-tee}"

# 4g.3 / PR 4e.2 / Phase 2 / slice 5 / step 3
PATTERN='(\bPR ?[0-9]+[a-z]?\.[0-9]+[a-z]*|\b[0-9]+[a-z]\.[0-9]+[a-z]*\b|\bslice [0-9]+|\bPhase [0-9]+[a-z]?\b|\bStep [0-9]+\b)'

hits=$(grep -rnE "$PATTERN" --include='*.rs' "$TARGET" || true)

if [ -n "$hits" ]; then
  echo "ERROR: implementation-process markers found in $TARGET" >&2
  echo >&2
  echo "$hits" >&2
  echo >&2
  echo "State what is true now instead of which change made it true." >&2
  echo "See crates/darknyx-tee/CONTRIBUTING.md." >&2
  exit 1
fi

echo "check-no-process-markers: OK ($TARGET)"
