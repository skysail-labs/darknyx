#!/usr/bin/env bash
# Guard: every CVM env builder in cvm-e2e.yml must set the SAME variables.
#
# WHY THIS EXISTS. The nightly builds the encrypted `-e` env in more than one
# place — once for the initial deploy, once per redeploy in the tree-consuming
# loop, and once for the legacy-path check. When one of them gained the
# per-window credentials and another did not, two things broke at once: the
# redeployed CVM fell back to the compose's public test credentials, and —
# because the SET OF ENV KEYS differed — the app-compose differed, moving
# compose_hash and failing every tree-consuming test with `compose_mismatch`.
#
# That took two CI runs to find, and the divergence was one diff away the whole
# time. A textual guard is enough: these builders are literal `echo "VAR=..."`
# lines, and comparing their key sets is exact.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WF="${1:-$ROOT/.github/workflows/cvm-e2e.yml}"
test -f "$WF" || { echo "✗ no such workflow: $WF" >&2; exit 1; }

python3 - "$WF" <<'PY'
import re, sys
path = sys.argv[1]
lines = open(path).read().split("\n")

# A builder is the run of `echo "DARKNYX_TEE_*=..."` lines that ends at the
# `} > <file>.env` redirect. Group by that terminator.
builders, current = [], []
for ln in lines:
    m = re.search(r'echo "(DARKNYX_TEE_[A-Z0-9_]+)=', ln)
    if m:
        current.append(m.group(1))
        continue
    # Blocks redirected to $GITHUB_ENV configure the RUNNER, not the CVM, so
    # they are discarded rather than compared. Only the encrypted `-e` files
    # deployed to the enclave have to agree.
    if re.search(r'>>?\s*"?\$GITHUB_ENV"?', ln):
        current = []
        continue
    if re.search(r'\}\s*>\s*\S*\.env', ln) and current:
        builders.append(set(current))
        current = []

if len(builders) < 2:
    print(f"✓ only {len(builders)} env builder(s); nothing to compare")
    raise SystemExit(0)

base = builders[0]
bad = False
for i, b in enumerate(builders[1:], start=2):
    missing, extra = base - b, b - base
    if missing or extra:
        bad = True
        print(f"✗ env builder #{i} diverges from #1", file=sys.stderr)
        for k in sorted(missing):
            print(f"    MISSING: {k}", file=sys.stderr)
        for k in sorted(extra):
            print(f"    EXTRA:   {k}", file=sys.stderr)

if bad:
    print("", file=sys.stderr)
    print("  Every deployment in this workflow must receive the same variable", file=sys.stderr)
    print("  set. A differing set changes the app-compose, which moves", file=sys.stderr)
    print("  compose_hash and makes clients fail `compose_mismatch`.", file=sys.stderr)
    raise SystemExit(1)

print(f"✓ all {len(builders)} CVM env builders set identical variables ({len(base)} each)")
PY
