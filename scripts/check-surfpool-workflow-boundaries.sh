#!/usr/bin/env bash
# Keep routine integration hermetic while preserving the paid real-CVM path as
# an explicit operator action. This is intentionally a source guard: GitHub can
# report a skipped/env-gated test green, but it cannot bypass these invariants.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SURFPOOL=.github/workflows/surfpool-qualification.yml
CVM=.github/workflows/cvm-e2e.yml
SWEEPER=.github/workflows/cvm-sweeper.yml

require() {
  local file="$1"
  local pattern="$2"
  local description="$3"
  grep -qE "$pattern" "$file" || {
    echo "$file: missing $description" >&2
    exit 1
  }
}

reject() {
  local file="$1"
  local pattern="$2"
  local description="$3"
  if grep -qE "$pattern" "$file"; then
    echo "$file: contains forbidden $description" >&2
    exit 1
  fi
}

[[ ! -e .github/workflows/nightly-devnet.yml ]] || {
  echo "nightly-devnet.yml must not retain the paid-devnet schedule" >&2
  exit 1
}

require "$SURFPOOL" '^  schedule:$' 'scheduled integration trigger'
require "$SURFPOOL" 'scripts/surfpool/hosted-smoke\.sh' 'non-vacuous hosted TEE smoke'
require "$SURFPOOL" 'scripts/check-surfpool-workflow-boundaries\.sh' 'self-checking workflow boundary'
require "$SURFPOOL" 'if: always\(\)' 'unconditional teardown'
require "$SURFPOOL" 'ports-closed\.mjs' 'surviving-process assertion'
reject "$SURFPOOL" 'secrets\.' 'GitHub secret reference'
reject "$SURFPOOL" 'api\.devnet\.solana\.com|[Hh][Ee][Ll][Ii][Uu][Ss]|[Pp][Hh][Aa][Ll][Aa] cvms|PHALA_CLOUD' \
  'public/provider RPC or Phala control-plane reference'

for file in "$CVM" "$SWEEPER"; do
  require "$file" '^  workflow_dispatch:$|^  workflow_dispatch:' 'manual dispatch trigger'
  reject "$file" '^  schedule:$' 'recurring paid-infrastructure schedule'
done
require "$CVM" 'Stop the CVM \(always\)' 'unconditional real-CVM teardown'

echo "Surfpool scheduled/manual-CVM workflow boundaries are intact"
