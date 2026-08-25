# Protocol fee recovery and epoch-key operations

This is the operator procedure for the protocol-owned fee notes created by
`VALID_MATCH_BATCH`. It is internal operational documentation, not a user
product flow.

The protocol fee opening has two independent secret inputs:

- the governed fee epoch key derives the note inner from the finalized
  consumed use tag and fee role; and
- the protocol owner's spending key opens the governed owner commitment and is
  required when the recovered note is eventually spent.

Back up both. The `@darknyx/fee-collector` keyring owns only the first. It does
not replace custody of the protocol-owner seed.

## 1. What is durable

For every proved batch, finalized Tx B publishes:

- the batch root;
- the fee-key epoch; and
- a fixed 272-byte authenticated ciphertext containing sixteen
  `(base_fee, quote_fee)` u64 pairs.

For every match that actually settles, finalized Tx D publishes the consumed
use tags, fee commitments, Merkle path, tree, and fee leaf indices. Historical
successful `set_protocol_config` instructions provide the owner commitment and
fee-key binding in force at Tx B. The market PDA supplies the immutable base and
quote mints.

The collector accepts a note only after it independently:

1. recomputes Tx D's MATCH_BATCH leaf and root;
2. pairs that root with Tx B;
3. verifies the stored key against the historical governed binding and epoch;
4. authenticates the Tx B ciphertext against root, market, mints, and epoch;
5. derives the fee inner and recomputes the note commitment; and
6. matches the commitment and leaf index to the scoped `TradeSettled` event.

A nonzero encrypted slot with no finalized Tx D minted no fee note and is
counted as skipped. Missing history, keys, configuration, events, or any
cryptographic mismatch is an unresolved record and makes the command exit
nonzero. A partial inventory is written for investigation but must never be
treated as a complete protocol balance.

## 2. Build and secret handling

```sh
npm ci
npm -w @darknyx/sdk run build
npm -w @darknyx/fee-collector run build
FEE_TOOL="node packages/fee-collector/dist/bin/fee-collector.js"
```

Passphrases are accepted only through environment variables; never put them,
the epoch key, or a credentialed RPC URL on a command line captured by shell
history.

```sh
export DARKNYX_FEE_KEYSTORE_PASSPHRASE='<from password manager>'
export DARKNYX_FEE_INVENTORY_PASSPHRASE='<distinct password>'
```

Keyrings and recovered inventories use a versioned AES-256-GCM envelope with a
fixed scrypt profile (`N=2^17, r=8, p=1`) and mode `0600`. Writes are atomic.
The collector rejects symlinks, malformed profiles, unknown fields, duplicate
commitments, and authentication failures. Application output contains only
public epochs, bindings, and counts—never keys, inners, amounts, or credentialed
endpoints.

## 3. First key and offline backup

Create the primary and a distinct backup file together. Put the backup on
separate encrypted offline media immediately; two paths on one disk are not a
backup.

```sh
$FEE_TOOL init \
  --keystore .devnet/operator/fee-keyring.sealed.json \
  --backup /Volumes/OFFLINE/darknyx-fee-keyring.sealed.json \
  --epoch 1

$FEE_TOOL verify-backup \
  --keystore .devnet/operator/fee-keyring.sealed.json \
  --backup /Volumes/OFFLINE/darknyx-fee-keyring.sealed.json
```

Record the printed binding and epoch in the governance proposal. The binding is
public. Do not extract or paste the secret key into the proposal.

Before enabling trading, independently verify:

- the primary and offline backup match;
- the protocol-owner seed backup restores the on-chain owner commitment;
- finalized `VaultConfig.fee_key_binding` and `fee_key_epoch` equal the proposed
  public values; and
- the CVM boots only when its encrypted key derives that finalized binding.

## 4. Rotation choreography

Rotation is a maintenance operation. Do not rotate while new batches can be
proved under the old epoch.

1. Pause new intake and drain settlement using `/admin/drain`; require
   `safe_to_stop=true` and an empty journal.
2. Rotate the encrypted keyring and its offline backup to a strictly increasing
   epoch:

   ```sh
   $FEE_TOOL rotate \
     --keystore .devnet/operator/fee-keyring.sealed.json \
     --backup /Volumes/OFFLINE/darknyx-fee-keyring.sealed.json \
     --epoch 2
   $FEE_TOOL verify-backup \
     --keystore .devnet/operator/fee-keyring.sealed.json \
     --backup /Volumes/OFFLINE/darknyx-fee-keyring.sealed.json
   ```

3. Submit `set_protocol_config` through the operations authority with the
   printed **public** binding and epoch. On devnet the maintained helper is:

   ```sh
   SOLANA_RPC_URL="$HELIUS" \
   ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
   FEE_KEY_BINDING_HEX='<public binding from rotate>' \
   FEE_KEY_EPOCH=2 \
     node scripts/set-matching-config.mjs
   ```

4. Wait for finalized governance and read `VaultConfig` back independently.
   Never deploy the new secret against merely submitted or confirmed state.
5. Materialize a one-use mode-0600 deployment fragment without printing the
   key:

   ```sh
   $FEE_TOOL write-deploy-env \
     --keystore .devnet/operator/fee-keyring.sealed.json \
     --output .devnet/fee-key-deploy.env
   ```

6. Incorporate that fragment into the encrypted Phala `-e` deployment file,
   deploy the digest-pinned image, and securely remove the plaintext deployment
   fragments after Phala accepts them.
7. Cold-boot, verify the CVM's strict finalized-governance binding check, run a
   nonzero-fee settlement, and only then resume intake.

The keyring retains every older epoch marked `retired`; retirement means “do not
mint new notes,” not “destroy the key.” Never delete an epoch while a fee note
from it may remain unspent or while the archival recovery drill for that epoch
has not passed.

If governance or deployment fails before trading resumes, remain drained. The
old key remains in the keyring and finalized historical batches remain
recoverable. Do not paper over a key/config mismatch by changing the epoch
again; reconcile the exact finalized proposal and deployment first.

## 5. Full finalized-chain recovery

Use a private Helius endpoint with archival `getTransactionsForAddress`
support. The start slot must be at or before the first relevant
`set_protocol_config`; starting after it intentionally produces a loud
`missing_protocol_config` result.

```sh
$FEE_TOOL recover \
  --keystore .devnet/operator/fee-keyring.sealed.json \
  --rpc-url "$HELIUS" \
  --program-id C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx \
  --since-slot '<pre-configuration finalized slot>' \
  --output .devnet/operator/fee-inventory.sealed.json
```

Success requires `unresolved=0`. Preserve the output and command summary in the
evidence record. Do not log or paste the decrypted inventory. Spending is a
separate offline action: open the encrypted inventory, combine each note with
the backed-up protocol-owner spending key, create the ordinary proof-backed
withdraw/merge instruction through the SDK, and verify the commitment and use
tag before signing.

## 6. Mandatory recovery drill

Before mainnet and after every collector, key schema, fee formula, settlement
wire, or governance-layout change:

1. settle at least one nonzero fee under epoch A;
2. drain, rotate, finalize governance, redeploy, and settle under epoch B;
3. delete only disposable online fee-note state—not either key backup;
4. rescan finalized history into a new encrypted inventory;
5. assert notes from both epochs recover byte-for-byte;
6. spend or merge one recovered note from each epoch on devnet;
7. prove a non-finalized/failed Tx D creates no recovered note; and
8. repeat with a missing old key and one tampered record, requiring loud
   unresolved results and no invented openings.

Record proposal and transaction signatures, slots, epochs, bindings, image
digest, compose hash, recovered/skipped/unresolved counts, and spend
signatures. Never record the secret keys, decrypted amounts, inners, or RPC API
key.

## 7. Disaster recovery

- **Primary keyring lost:** restore the verified offline keyring to a new
  mode-0600 path, verify every public binding against finalized governance, and
  run a full recovery before resuming operations.
- **One historical epoch missing:** stop. Preserve the unresolved report and
  locate another verified backup. The chain cannot reconstruct an observer
  secret that was deliberately never published.
- **Protocol-owner seed lost:** epoch keys can reconstruct fee inners, but the
  notes cannot be spent. This is a separate custody failure.
- **Archival history incomplete:** change provider or widen the start slot.
  Never accept a partial scan as a zero balance.
- **Inventory lost:** regenerate it from finalized history plus both secret
  backups. The inventory is a cache; the epoch keyring and protocol-owner seed
  are the durable secrets.
