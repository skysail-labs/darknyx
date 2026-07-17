#!/usr/bin/env bash
# Devnet program deploy (vault).
#
# Uses the local Solana CLI wallet as upgrade authority and fee payer.
# Upgrades an existing vault by its compiled program address. A matching
# program-id keypair is required only for an initial deployment.
#
# Idempotent: subsequent runs upgrade the existing program in place.
#
# Usage:
#   ./scripts/deploy-devnet.sh
#   SOLANA_RPC_URL=https://devnet.helius-rpc.com/?api-key=... \
#     ./scripts/deploy-devnet.sh
#
# Prereqs:
#   - cargo build-sbf has produced target/deploy/vault.so
#   - solana CLI configured for devnet with a funded keypair (>= 5 SOL)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VAULT_SO="target/deploy/vault.so"
VAULT_KP="target/deploy/vault-keypair.json"

if [[ ! -f "$VAULT_SO" ]]; then
  echo "MISSING: $VAULT_SO"
  echo "run (devnet build — NEEDS the admin ixs for reset-merkle-tree.mjs /"
  echo "close-vault-config.mjs; audit_1 F-01/F-02 gate them off by default):"
  echo "  cargo build-sbf --manifest-path programs/vault/Cargo.toml --features devnet-admin"
  exit 1
fi

RPC_URL="${SOLANA_RPC_URL:-$(solana config get json_rpc_url | awk '{print $NF}')}"
if [[ "$RPC_URL" != *"devnet"* ]]; then
  echo "ERROR: deployment RPC is not a devnet endpoint."
  exit 1
fi

DECLARED_ID=$(sed -n 's/.*declare_id!("\([^"]*\)").*/\1/p' programs/vault/src/lib.rs | head -1)
if [[ -z "$DECLARED_ID" ]]; then
  echo "ERROR: programs/vault/src/lib.rs has no declare_id!."
  exit 1
fi

# Existing upgrades require only the upgrade-authority signature; Solana accepts
# the program's base58 address for --program-id. This avoids depending on the
# gitignored target/deploy keypair, which `cargo clean` removes and build-sbf
# regenerates randomly. For an initial deploy, retain the strict keypair match.
PROGRAM_ID_ARG="$DECLARED_ID"
if ! solana program show "$DECLARED_ID" --url "$RPC_URL" --output json-compact >/dev/null 2>&1; then
  if [[ ! -f "$VAULT_KP" ]]; then
    echo "ERROR: $DECLARED_ID is not an existing program and $VAULT_KP is missing."
    echo "A matching canonical program-id keypair is required for an initial deploy."
    exit 1
  fi
  VAULT_KP_ID=$(solana-keygen pubkey "$VAULT_KP")
  if [[ "$VAULT_KP_ID" != "$DECLARED_ID" ]]; then
    echo "ERROR: vault program-id keypair does not match the compiled declare_id!."
    echo "  target/deploy/vault-keypair.json: $VAULT_KP_ID"
    echo "  programs/vault/src/lib.rs:        $DECLARED_ID"
    echo "Restore the canonical program-id keypair before an initial deployment."
    exit 1
  fi
  PROGRAM_ID_ARG="$VAULT_KP"
fi

VAULT_ID="$DECLARED_ID"

echo "Deploying to devnet (upgrade authority = local wallet)"
echo "  vault  program id: $VAULT_ID"
echo

echo "-> vault"
solana program deploy "$VAULT_SO" \
  --program-id "$PROGRAM_ID_ARG" \
  --upgrade-authority "$HOME/.config/solana/id.json" \
  --url "$RPC_URL" \
  --use-rpc \
  --commitment confirmed

echo
echo "verifying..."
solana program show "$VAULT_ID" --url "$RPC_URL" --output json-compact | head -c 400; echo

echo
echo "vault deployed."
