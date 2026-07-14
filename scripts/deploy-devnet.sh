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
DECLARED_ID=$(sed -n 's/.*declare_id!("\([^"]*\)").*/\1/p' programs/vault/src/lib.rs | head -1)

# `cargo build-sbf` generates a fresh target/deploy keypair if that file is
# missing. Deploying it would create a new, unusable program whose address does
# not match `declare_id!()` or the SDK. Fail before spending rent or changing
# devnet state; restore the canonical program-id keypair and rebuild instead.
if [[ -z "$DECLARED_ID" || "$VAULT_ID" != "$DECLARED_ID" ]]; then
  echo "ERROR: vault program-id keypair does not match the compiled declare_id!."
  echo "  target/deploy/vault-keypair.json: $VAULT_ID"
  echo "  programs/vault/src/lib.rs:        ${DECLARED_ID:-<missing>}"
  echo "Restore the canonical program-id keypair before deploying."
  exit 1
fi

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
