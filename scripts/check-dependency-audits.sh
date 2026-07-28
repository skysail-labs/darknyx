#!/usr/bin/env bash
# T-08 — locally reproducible dependency vulnerability gates.
#
# `audit_1` found a production-reachable openssl CVE in the TEE's TLS path and
# it was fixed by hand. Nothing stopped the next one from shipping silently: no
# workflow ran `cargo audit` or `npm audit`. A project that pins PTAU files by
# SHA-256 and reasons carefully about byte-equality contracts having no
# dependency gate was an outlier.
#
# DESIGN — why a baseline instead of a severity threshold or a wildcard ignore:
#
#   * Rust findings are triaged individually in `.cargo/audit.toml`, each with
#     the `cargo tree -i` reachability analysis that justified accepting it.
#     Four are accepted today; a fifth advisory fails this script.
#
#   * The npm production tree carries a pre-existing backlog. Blanket-ignoring
#     it would defeat the gate on day one, and failing on the whole backlog
#     would make the gate something everyone learns to bypass. So the backlog is
#     recorded in `audit-baseline/npm-production.txt` — visible, diffable, and
#     expected to SHRINK. Anything NOT in that file fails the gate.
#
#     That is the property worth having: a new advisory entering the production
#     tree is loud, while the known backlog is tracked in the open rather than
#     suppressed. Deleting a line from the baseline after fixing it is the
#     normal workflow; adding one requires a deliberate, reviewable commit.
#
# Usage: bash scripts/check-dependency-audits.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

failed=0

echo "── cargo audit ────────────────────────────────────────────────"
if ! command -v cargo-audit >/dev/null 2>&1 && ! cargo audit --version >/dev/null 2>&1; then
  echo "::error::cargo-audit is not installed — the Rust half of this gate did NOT run."
  echo "  Install: cargo install cargo-audit --locked --version ^0.22"
  failed=1
else
  echo "tool: $(cargo audit --version 2>&1)"
  CARGO_OUT="$(mktemp)"
  if cargo audit --quiet >"$CARGO_OUT" 2>&1; then
    echo "cargo audit: OK (triaged advisories in .cargo/audit.toml)"
  elif grep -qiE "error loading advisory database|unsupported CVSS version|failed to fetch" "$CARGO_OUT"; then
    # A tool/database failure is NOT a finding. Reporting it as one sends the
    # reader hunting for a vulnerability that does not exist, and — worse — the
    # inverse mistake would be to treat it as a pass. Distinguish the two
    # explicitly: "could not check" still fails the gate, but says so.
    # (Seen for real: cargo-audit 0.21 cannot parse the CVSS 4.0 entries the
    # RustSec DB now ships, so the whole run aborted before auditing anything.)
    echo "::error::cargo audit COULD NOT RUN — this is a tool/database failure,"
    echo "  not a vulnerability finding. Nothing was audited."
    sed 's/^/    /' "$CARGO_OUT" | head -12
    echo "  Usually means cargo-audit is too old for the current advisory DB."
    failed=1
  else
    echo "::error::cargo audit found an UNTRIAGED advisory."
    sed 's/^/    /' "$CARGO_OUT" | tail -20
    echo "  Fix the dependency, or add it to .cargo/audit.toml WITH the"
    echo "  \`cargo tree --workspace -i <crate>@<version>\` analysis that"
    echo "  justifies accepting it. Do not add a bare ignore line."
    failed=1
  fi
  rm -f "$CARGO_OUT"
fi

echo
echo "── npm audit (production deps only) ───────────────────────────"
BASELINE="audit-baseline/npm-production.txt"
CURRENT="$(mktemp)"
trap 'rm -f "$CURRENT"' EXIT

npm audit --omit=dev --json 2>/dev/null | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(0)
rows=set()
for name,v in d.get('vulnerabilities',{}).items():
    for via in v.get('via',[]):
        if isinstance(via,dict) and via.get('url'):
            rows.add(f\"{via['url'].rsplit('/',1)[-1]} {name} {v['severity']}\")
print('\n'.join(sorted(rows)))
" > "$CURRENT"

if [ ! -f "$BASELINE" ]; then
  echo "::error::$BASELINE is missing — cannot tell new findings from known ones."
  failed=1
else
  NEW="$(comm -13 "$BASELINE" "$CURRENT" || true)"
  GONE="$(comm -23 "$BASELINE" "$CURRENT" || true)"
  if [ -n "$NEW" ]; then
    echo "::error::NEW npm advisories in the production tree:"
    printf '%s\n' "$NEW" | sed 's/^/    /'
    echo "  Fix them, or — if genuinely accepted — add them to $BASELINE"
    echo "  in a commit that says why."
    failed=1
  else
    echo "npm audit: no new advisories beyond the recorded baseline"
    echo "  baseline size: $(wc -l < "$BASELINE" | tr -d ' ')"
  fi
  if [ -n "$GONE" ]; then
    echo "  GOOD NEWS — these baseline advisories are gone; prune them from $BASELINE:"
    printf '%s\n' "$GONE" | sed 's/^/    /'
  fi
fi

echo
if [ "$failed" -ne 0 ]; then
  echo "dependency audit gate: FAILED"
  exit 1
fi
echo "dependency audit gate: PASSED"
