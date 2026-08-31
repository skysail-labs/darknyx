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
GHCR_CLEANUP=.github/workflows/cvm-ghcr-cleanup.yml

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
require "$CVM" 'DEVNET_RPC_URL:.*secrets\.DEVNET_RPC_URL' \
  'provider-neutral dedicated-RPC secret'
require "$CVM" 'capture_settlement_metrics' \
  'pre-redeploy settlement timing capture'
require "$CVM" '/admin/metrics/settlement\?limit=100' \
  'authenticated settlement metrics query'
require "$CVM" 'CVM_SETTLEMENT_METRICS' \
  'structured real-CVM timing evidence marker'
require "$CVM" 'DARKNYX_APPROVED_COMPOSE_HASH' \
  'control-plane-approved compose identity'
require "$CVM" 'MEASURED_COMPOSE_HASH.*DARKNYX_APPROVED_COMPOSE_HASH' \
  'attested-to-approved compose comparison'
reject "$CVM" 'HELIUS_API_KEY|devnet\.helius-rpc\.com' \
  'provider-specific release credential'

# The final legacy-transport check is a real cold redeploy after earlier suites
# have added leaves. Its fresh mirror may use a current sync floor only after
# the on-chain trees are reset; reversing or dropping these lines leaves the
# independent MerkleReadiness gate closed even while the oracle is healthy.
legacy_block=$(sed -n '/- name: Legacy (gateway-terminated) path still works/,/- name: Stop the CVM (always)/p' "$CVM")
legacy_reset_line=$(printf '%s\n' "$legacy_block" | grep -n 'node scripts/reset-merkle-tree\.mjs' | head -1 | cut -d: -f1 || true)
legacy_floor_line=$(printf '%s\n' "$legacy_block" | grep -n 'FLOOR=$(node -e' | head -1 | cut -d: -f1 || true)
if [[ -z "$legacy_reset_line" || -z "$legacy_floor_line" || "$legacy_reset_line" -ge "$legacy_floor_line" ]]; then
  echo "$CVM: legacy cold redeploy must reset every Merkle shard before taking its sync floor" >&2
  exit 1
fi

require "$SWEEPER" '^  workflow_run:$' 'automatic post-CVM cleanup trigger'
require "$SWEEPER" 'cvm-e2e \(manual release gate\)' \
  'exact source-workflow name for automatic cleanup'

# Registry retention is intentionally still scheduled: it starts no CVM and
# calls no Solana RPC. Keep that distinction explicit instead of placing it in
# the manual-CVM loop above.
require "$GHCR_CLEANUP" '^  schedule:$' 'weekly registry-retention trigger'
require "$GHCR_CLEANUP" '^  workflow_dispatch:$|^  workflow_dispatch:' \
  'manual registry-retention trigger'
reject "$GHCR_CLEANUP" 'phala cvms|PHALA_CLOUD|SOLANA_RPC|api\.devnet\.solana\.com|[Hh][Ee][Ll][Ii][Uu][Ss]' \
  'CVM control-plane or Solana-provider reference'

# Routine operator and SDK entrypoints must use the provider-neutral RPC
# interface. Historical evidence, provider-specific scanners, and archival fee
# recovery are intentionally outside this list.
for file in \
  CLAUDE.md \
  docs/cvm-run-runbook.md \
  scripts/dev-commands.md \
  scripts/deploy-devnet.sh \
  scripts/read-pyth-push-price.mjs \
  scripts/run-indexer-local.sh \
  packages/sdk/.env.example \
  packages/sdk/.env.devnet.example \
  packages/sdk/tests/TESTS.md; do
  reject "$file" 'HELIUS_API_KEY|devnet\.helius-rpc\.com|\$HELIUS|private Helius' \
    'routine Helius dependency'
done
reject scripts/run-indexer-local.sh 'api\.devnet\.solana\.com' \
  'implicit public-devnet fallback'

echo "Surfpool scheduled/manual-CVM workflow boundaries are intact"
