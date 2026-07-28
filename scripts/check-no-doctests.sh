#!/usr/bin/env bash
# Guard: the fast local gate uses `cargo nextest`, which does NOT run doctests.
#
# That is safe only while the workspace has none. This check makes the
# assumption self-enforcing: add an executable doctest and the gate fails here,
# naming the problem, instead of the doctest silently never running.
#
# WHY A GUARD RATHER THAN A COMMENT: a doctest that is never executed is
# indistinguishable from one that passes. This repository has repeatedly found
# gates that reported success without checking anything (T-11, T-12, T-13, T-18);
# adopting a runner that skips a whole test category without a tripwire would be
# the same mistake with a new name.
#
# If you DO want doctests, that is fine — keep them, and add
# `cargo test --workspace --doc` to the gate alongside nextest. Then update this
# script to assert that command is present rather than that doctests are absent.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Capture cargo's status SEPARATELY from its output.
#
# An earlier revision used `$(cargo ... || true)`, which threw the exit status
# away: if cargo failed to build, the output contained no "running N tests"
# line, the count stayed 0, and this script cheerfully reported "no doctests"
# and exited 0. A guard against gates-that-do-not-check that itself fails open
# is precisely the bug it exists to prevent, so the status is now load-bearing.
set +e
out="$(cargo test --workspace --doc 2>&1)"
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
  printf '%s\n' "$out" >&2
  cat >&2 <<EOF

ERROR: \`cargo test --workspace --doc\` exited $rc, so this check could not
       determine whether any doctests exist. Treating that as a FAILURE: a
       build error here would otherwise read as "no doctests" and leave the
       nextest gate green while nothing was verified.

Fix the compilation failure above, then re-run.
EOF
  exit 1
fi

# `--doc` compiles and runs only doctests. Counting from its own output is more
# reliable than grepping for ``` fences, which cannot distinguish an executable
# doctest from a ```text block used purely for illustration (this repo has
# several of the latter).
total=0
saw_header=0
while read -r n; do
  total=$((total + n))
  saw_header=1
done < <(printf '%s\n' "$out" | sed -nE 's/^running ([0-9]+) tests?$/\1/p')

if [ "$saw_header" -eq 0 ]; then
  printf '%s\n' "$out" >&2
  cat >&2 <<EOF

ERROR: cargo succeeded but emitted no "running N tests" line, so the doctest
       count could not be read. Failing closed rather than assuming zero — the
       output format may have changed and this check would silently stop
       checking.
EOF
  exit 1
fi

if [ "$total" -eq 0 ]; then
  echo "no executable doctests: nextest-based gate loses no coverage"
  exit 0
fi

cat >&2 <<EOF
ERROR: $total executable doctest(s) exist, but the fast gate runs \`cargo nextest\`,
       which does not execute doctests — they would never run.

Fix either way:
  * add \`cargo test --workspace --doc\` to the gate (CLAUDE.md §2.5) and update
    this script to check for that instead; or
  * convert the doctest to a \`\`\`text or \`\`\`ignore block if it was only ever
    meant as illustration.
EOF
exit 1
