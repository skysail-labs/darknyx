#!/usr/bin/env bash
# Devnet program deploy (vault).
#
# Uses the local Solana CLI wallet as upgrade authority and fee payer.
# Deploys vault.so using the program-id keypair in target/deploy/ so the
# deployed address matches what's compiled in.
#
# Idempotent: subsequent runs upgrade the existing program in place.
#
# Usage:
#   ./scripts/deploy-devnet.sh
#
# Prereqs:
#   - cargo build-sbf has produced target/deploy/vault.so
#   - solana CLI configured for devnet with a funded keypair (>= 5 SOL)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VAULT_SO="target/deploy/vault.so"
VAULT_KP="target/deploy/vault-keypair.json"

for f in "$VAULT_SO" "$VAULT_KP"; do
  if [[ ! -f "$f" ]]; then
    echo "MISSING: $f"
    echo "run (devnet build — NEEDS the admin ixs for reset-merkle-tree.mjs /"
    echo "close-vault-config.mjs; audit_1 F-01/F-02 gate them off by default):"
    echo "  cargo build-sbf --manifest-path programs/vault/Cargo.toml --features devnet-admin"
    exit 1
  fi
done

CONFIG_URL=$(solana config get json_rpc_url | awk '{print $NF}')
if [[ "$CONFIG_URL" != *"devnet"* ]]; then
  echo "ERROR: Solana CLI is not pointing at devnet."
  exit 1
fi

VAULT_ID=$(solana-keygen pubkey "$VAULT_KP")

echo "Deploying to devnet (upgrade authority = local wallet)"
echo "  vault  program id: $VAULT_ID"
echo

echo "-> vault"
solana program deploy "$VAULT_SO" \
  --program-id "$VAULT_KP" \
  --upgrade-authority "$HOME/.config/solana/id.json" \
  --commitment confirmed

echo
echo "verifying..."
solana program show "$VAULT_ID" --output json-compact | head -c 400; echo

echo
echo "vault deployed."
