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

# Fail closed on a target we cannot scan. Without this the guard reports OK
# for a path that was renamed or typo'd, which is worse than no guard.
if [ ! -d "$TARGET" ] || [ ! -r "$TARGET" ]; then
  echo "ERROR: target is not a readable directory: $TARGET" >&2
  exit 2
fi

# Matched forms: 4g.3 / PR 4e.2 / bare "PR 4g" / Phase 2 / slice 5 / step 3.
# The bare "PR <n><letter>" form matters: an earlier revision of this script
# required a ".N" suffix and so reported OK while "PR 4c" and "PR 4d" sat in
# tests/ untouched.
PATTERN='(\bPR ?[0-9]+[a-z]?(\.[0-9]+[a-z]*)?\b|\b[0-9]+[a-z]\.[0-9]+[a-z]*\b|\bslice [0-9]+|\bphase [0-9]+[a-z]?\b|\bstep [0-9]+\b)'

# -i so lowercase "step 2" is caught too. grep exit 1 means "no matches"; any
# other non-zero status is a real failure (unreadable target, bad pattern) and
# must NOT be reported as a pass.
set +e
hits=$(grep -rniE "$PATTERN" --include='*.rs' "$TARGET")
rc=$?
set -e
if [ "$rc" -gt 1 ]; then
  echo "ERROR: grep failed with status $rc while scanning $TARGET" >&2
  exit "$rc"
fi

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
