# The custody layer

> The Solana `vault` program holds every dollar of TVL in Nyx. It
> owns a single Merkle tree of UTXO note commitments, a nullifier
> set, a consumed-note set, and the registered TEE pubkey. Every
> withdraw requires a zero-knowledge proof; every settle requires
> a verified ZK proof + TEE signature. There is no admin "exit"
> path. There is no upgrade authority that can bypass the
> verifiers.

---

## The UTXO note model

Nyx uses a UTXO model (similar to Zcash, Tornado Cash, or Aztec)
rather than an account model. Funds live in **notes**: opaque
32-byte Poseidon commitments stored as leaves in a single global
Merkle tree.

Each note encodes (binding all inputs into the Poseidon hash):

| Field | Bytes | Meaning |
|---|---|---|
| `domain_tag` | 1 | Fixed tag `2` — domain separation from other Poseidon uses |
| `token_mint_lo` | 16 | Lower half of the Solana mint pubkey |
| `token_mint_hi` | 16 | Upper half of the Solana mint pubkey |
| `amount` | 8 | Token amount in mint-native units |
| `owner_commit` | 32 | `Poseidon2(spending_key, r_owner)` — see [cryptography](./cryptography.md) |
| `nonce` | 32 | Per-note random nonce (prevents collision on identical amounts/owners) |
| `blinding` | 32 | Per-note random blinding factor (prevents brute-force enumeration) |

The hash is `Poseidon7(domain_tag, token_mint_lo, token_mint_hi,
amount, owner_commit, nonce, blinding)`. On-chain, only the 32-byte
result is stored. The plaintext fields are reconstructed by the
owner from their wallet's deterministic key derivation chain plus
the per-note nonce/blinding pair the SDK gives them at deposit
time.

The implications:

1. **An on-chain observer cannot tell** what token a note holds,
   what amount, or who owns it.
2. **An on-chain observer can tell** that the note exists (by
   reading the Merkle tree leaves) and when it was created (by
   reading the deposit transaction logs).
3. **A user who knows the note's fields** can spend it via a
   VALID_SPEND proof. The verifier recomputes the Poseidon hash
   from the user's witness and checks it matches a leaf in the
   committed Merkle root.

---

## The Merkle tree

A single global incremental Merkle tree of depth 20 (= 1,048,576
leaves of capacity), Poseidon-hashed at every node. The vault
keeps a ring buffer of the last 32 roots so withdraws can use a
recent-but-not-current root (necessary because deposits keep
shifting the root).

The tree is rebuilt on `reset_merkle_tree` (admin-only, used in
dev to reset devnet state) and grows monotonically otherwise.
Each `deposit` appends one leaf; each `tee_forced_settle_batched`
appends up to four leaves (two new change notes per match, times
up to N=16 matches per batch, but in the v3.5 batched flow each
match appends only its own change notes — typically 0 or 2 per
match).

Why depth 20: the deposit constraint count scales with tree
depth, and depth 20 covers ~1M notes — sufficient for the next
several years of growth at any plausible adoption rate. When we
need more, depth bumps to 24 with a one-time circuit re-compile.

---

## The seven instructions

The vault program has exactly seven public instructions. Each one
is documented below in summary; for the full Anchor signatures see
`programs/vault/src/instructions/` in the source.

### `create_wallet`

Registers a `user_commitment` (the Poseidon hash of the user's
spending key + a random `r_owner`). Allocates a `WalletEntry` PDA
seeded by the commitment. Requires a VALID_WALLET_CREATE proof.

This is the "open an account" moment. The user's spending key
never leaves their device; only the commitment is on-chain.

### `deposit`

Transfers tokens from the user's wallet into the vault. Appends a
new leaf to the Merkle tree representing the user's new note.
Requires a VALID_INPUT proof.

The VALID_INPUT circuit checks: the declared note commitment is the
correct Poseidon hash of the user's claimed `(mint, amount,
owner_commit, nonce, blinding)`. This prevents a malicious user
from depositing $1 of USDC but claiming a $1M note.

### `lock_note`

Pins a specific note commitment to a specific `(trading_key,
order_id)` for up to `MAX_LOCK_TTL_SLOTS = 216,000` slots
(~24 hours on Solana). Allocates a `NoteLock` PDA. Requires a
VALID_INPUT proof (the same one the user generated at order
submission — relayed by the TEE).

The lock has two effects:
1. The note can't be withdrawn while locked.
2. The note is reserved for matching against the specific order
   identified by `order_id`.

When matching fails or the user cancels, the lock expires naturally
(or is released via `release_lock`).

### `verify_match_batch`

Submits the TEE's VALID_MATCH_BATCH Groth16 proof + the batch
Merkle root. Allocates a `BatchValidityMarker` PDA seeded by the
batch root. The marker is **1:N** — one PDA per batch, covering
all matches in the batch.

The proof attests that for every slot in the batch:
- The match's VALID_CREATE constraints hold (change notes correctly
  derived from input notes' Poseidon openings).
- The match's VALID_PRICE constraints hold (`quote = base × price`,
  range checks on amounts).
- The leaf hash construction matches the circuit's `MatchSlot()`
  template byte-for-byte.

VALID_MATCH_BATCH is the single most cryptographically expensive
component in Nyx. It's currently instantiated at N=16 matches per
proof; ~163,000 constraints; uses pot18 (the 2^18 PowersOfTau
ceremony output).

### `tee_forced_settle_batched`

The atomic settle. For each match, this instruction:
1. Verifies the TEE signature over a canonical payload hash.
2. Re-derives the match's leaf hash and walks a Merkle inclusion
   path against the root committed in `BatchValidityMarker`.
3. Marks both input notes as consumed (allocates `ConsumedNoteEntry`
   PDAs).
4. Appends the match's change notes as new Merkle tree leaves.
5. Transfers tokens between users' note values (the vault's SPL
   token accounts).
6. Decrements the `outstanding[mint]` counter to track per-mint
   liabilities (added in v2 hardening as a defense-in-depth check).
7. Emits a `TradeSettled` event.

The signature check uses the on-chain `vault_config.tee_pubkey`,
which was registered through the multisig rotation ceremony (see
[trust-model](./trust-model.md)). Only the attested TEE can produce
valid signatures for this instruction.

### `close_batch_validity_marker`

Reclaims the SOL rent locked in the `BatchValidityMarker` PDA.
Separate from `tee_forced_settle_batched` because the marker is
1:N (one per batch) but settles are 1-per-match — closing it
during settle would brick subsequent matches in the same batch.

### `withdraw`

Spends a note: moves tokens from the vault back to the user's
wallet. Requires a VALID_SPEND proof.

The VALID_SPEND circuit checks:
1. The user knows the note's full plaintext (proves ownership).
2. The note's commitment is in the current Merkle tree (verifies
   inclusion against a recent root).
3. The nullifier (a deterministic function of the spending key and
   the note commitment) hasn't been used before.
4. If the spend amount is less than the note's full value, the
   change-note commitment is correctly derived.

The nullifier check makes double-spending cryptographically
impossible: the same note produces the same nullifier every time,
and the vault rejects any withdraw whose nullifier already exists
in the on-chain set.

---

## On-chain state

The vault's state is small and stable:

| Account | Type | Purpose |
|---|---|---|
| `VaultConfig` | Singleton (PDA seed `vault_config`) | Holds the registered `tee_pubkey`, the registered TEE `compose_hash`, the protocol fee rate, the admin multisig, the recent-roots ring buffer, and the per-mint `outstanding` counters. |
| `MerkleTree` | Singleton | The depth-20 incremental Merkle tree itself. |
| `WalletEntry` | PDA per user commitment | One per registered user. Allocation = "this user_commitment is known to the vault." |
| `NullifierEntry` | PDA per nullifier | Allocation = "this nullifier has been used; the corresponding note has been spent." Init is what prevents double-spends. |
| `ConsumedNoteEntry` | PDA per consumed note (settle-side) | Allocation = "this note was consumed by the TEE settle path." Distinct from nullifiers (which come from VALID_SPEND withdraws). |
| `NoteLock` | PDA per locked note | Allocation = "this note is pinned to (`trading_key`, `order_id`) until `expiry_slot`." |
| `BatchValidityMarker` | PDA per batch | Allocation = "the TEE submitted a valid VALID_MATCH_BATCH proof for this batch root." Carries the verified Merkle root + the deadline. |

There is **no admin "exit"** account. There is **no upgrade
authority** that can replace the verifier code without a multisig
rotation that itself goes through the on-chain governance ix. The
vault's compiled bytecode is fixed once the upgrade authority is
removed (planned for mainnet launch).

---

## The recent-roots ring buffer

The vault keeps the last 32 Merkle roots in a ring buffer. A
withdraw can use any root in this ring — not just the most recent
one.

Why: the Merkle root changes every time a deposit lands or a
settle adds change notes. If withdraws had to use the very latest
root, every withdraw would race the constant churn from other
users and almost always fail with `StaleMerkleRoot`. The 32-root
window gives the user time to generate their proof against a
snapshot, submit the withdraw, and have it land before the
snapshot rolls off.

The 32-slot horizon is short enough that proofs against very old
roots can't accumulate — a malicious user can't sit on a
months-old VALID_SPEND proof and try to spend a note that was
already spent at the time of proof generation.

---

## Per-mint outstanding counter

Added in the v2 hardening (PR v2). `VaultConfig.outstanding[mint]`
tracks how much of each token the vault holds in active notes
(deposits minus withdraws). The settle ix sanity-checks against
this counter: a settle that would move more tokens out than the
counter says exist is rejected.

This is defense in depth. If the matching proof somehow accepted a
malformed match that violated conservation (e.g., transferred 1M
USDC when only 500K was deposited), the outstanding check catches
it before any tokens move.

---

## The v3.5 batched validity hardening

Nyx is currently on **v3.5** — the batched-validity migration that
landed in early 2026. The progression:

| Version | What it added |
|---|---|
| v1 | Original hackathon submission. PER-based matching. Per-match validity proofs. |
| v2 | VALID_INPUT proof at lock time + `NoteLock.token_mint` binding + `MAX_LOCK_TTL_SLOTS` cap + `outstanding[mint]` counter. |
| v3 | VALID_CREATE proof for change-note construction + `ValidCreateMarker` PDA. |
| v3.1 | VALID_PRICE proof for clearing-price commitment + `ValidPriceMarker` PDA + v0 transactions + ALT migration. |
| **v3.5 (current)** | **VALID_MATCH_BATCH (N=16) + `BatchValidityMarker` (1:N) + `tee_forced_settle_batched` + `close_batch_validity_marker`. Phase 1c-hard complete: v3.1 per-match settle path removed entirely.** |

The v3.5 batched flow reduces per-match overhead by roughly 10×
compared to v3.1 (one Groth16 verify per batch instead of one per
match) while keeping the per-match settle transaction itself
sub-1232 bytes. The migration log is in
`docs/v3.5-migration.md` for engineering reference.

---

## Failure modes the on-chain code defends against

| Failure | Defense |
|---|---|
| Replay an old VALID_SPEND proof | Nullifier check — the proof's nullifier PDA can be allocated only once |
| Replay an old VALID_INPUT proof at lock time | `NoteLock` PDA seeded by note commitment — one lock per note |
| Replay an old VALID_MATCH_BATCH proof | `BatchValidityMarker` PDA seeded by batch root — one marker per batch |
| Use a stale Merkle root | Recent-roots ring buffer — withdraws against a root older than the last 32 fail |
| Settle without TEE signature | `tee_forced_settle_batched` requires Ed25519 sig verification against `vault_config.tee_pubkey` |
| TEE-pubkey rotation by an attacker | `vault_config.tee_pubkey` can only be updated by the multisig governance ix |
| Compile-hash drift (TEE running unexpected code) | `vault_config.tee_compose_hash` pins the approved measurement; clients can verify the TEE's `/attestation` against this value |
| Settle a match that violates conservation | `outstanding[mint]` counter sanity-checks every transfer |
| Lock a note indefinitely | `MAX_LOCK_TTL_SLOTS = 216,000` (~24h) cap on lock duration |
| Double-spend via parallel locks | `NoteLock` PDA seeded by note commitment — concurrent locks for the same note fail at `init` |

The list is intentionally long and dense. The cryptography in
[cryptography](./cryptography.md) and the trust model in
[trust-model](./trust-model.md) explain the deeper invariants
each defense ultimately rests on.

---

## What's coming

The custody layer is stable. The recent PRs landing in the TEE v2
workstream don't touch the on-chain code at all — they're moving
the matching layer from MagicBlock PER to a dedicated TDX CVM.
The vault program will see a TEE-pubkey rotation when the v2 CVM
goes live (the existing v1 PER attestation will be replaced by the
v2 TDX attestation), but the vault's instructions, state, and
verifier code stay the same.

The next custody-layer change planned is a deferred upgrade-
authority removal for mainnet — once the upgrade authority is
permanently null, the vault becomes truly immutable.

---

*Last updated 2026-05-29. Source of truth:
`programs/vault/src/`, `CRYPTOGRAPHY.md`, `docs/v3.5-migration.md`.*
</content>
