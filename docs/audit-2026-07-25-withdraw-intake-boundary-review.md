# Darknyx cryptography, systems, and performance review — 2026-07-25

> **Scope.** Defensive, first-party pre-mainnet review of the devnet-stage
> Darknyx stack at `d0122ad`: all seven Groth16 circuits, the `vault` program
> (20 instructions + `state`/`merkle`), `darkpool-crypto`, `darkpool-matcher`,
> `darknyx-tee` (intake, matcher, settle, keys, attestation), and the
> `packages/sdk` crypto/transport boundary. Code is ground truth; where a doc
> and the code disagree, the code wins and the doc is flagged.
>
> **Out of scope.** Website/portal, demo app, operational runbooks, third-party
> infrastructure.
>
> **ID prefix:** `S-01…` (soundness) and `PF-01…` (performance), 2026-07-25.
> `P-` is already taken by the 2026-07-14 pass; `PF-` avoids the collision.
>
> **Prior-art handling.** `audit_1/` (F-01…F-11), the 2026-07-12 inventory,
> the 2026-07-14 CS/N pass, the 2026-07-18 U-01…U-10 pass, and the 2026-07-20
> D-01…D-09 deep dive are treated as known. Nothing here re-reports a closed
> finding. Where a new finding sharpens or contradicts an existing one, the
> delta is stated explicitly (S-03 vs D-01/D-09; S-08 vs U-02/D-03).
>
> **Severity:** Critical / High / Medium / Low / Perf-Nit / Info

---

## 1. Executive summary

This pass weighted effort toward the surfaces `audit_1` explicitly excluded —
circuit soundness (its F-04 gate), the matcher algorithm, the TEE HTTP and
orchestration surface, and the SDK — and toward independently re-deriving the
`VALID_MATCH_BATCH` no-inflation argument.

**The headline result is S-01: the withdrawal recipient is not bound to the
`VALID_SPEND` proof.** `destination_token_account` is a free instruction
account whose only constraint is that its mint matches, and no recipient,
relayer, or fee signal exists anywhere in the circuit. The 256-byte proof plus
its five arguments therefore constitute a **bearer instrument for the note**:
whoever holds those bytes first decides where the SPL transfer lands. This is
exploitable by front-running (leader, searcher, or the user's own RPC
provider) and, separately, by replaying any withdraw transaction that lands
and reverts — the latter needs no privileged network position at all. Four
prior audit passes did not surface it, most likely because each treated
`withdraw`'s `init`-as-guard PDAs as the security property and focused
analytical effort on the settle path.

Below that, the pattern is **invariants that hold in honest Rust but are
absent from the trust boundary that is supposed to enforce them**. Order
intake accepts a `VALID_INPUT` proof it never verifies against a note it never
checks exists (S-02), so any authenticated client can poison the book at zero
cost. The recovery instruction that every freeze scenario in the D-01 analysis
depends on — `release_lock` — has no builder in any shipped component (S-03),
so the assumed recovery step does not exist. And `verify_match_batch` hands a
proof observer sole control of the batch marker's TTL (S-04).

**What verified clean.** All seven committed `vk_*.rs` are byte-identical to a
fresh regeneration from the built verification keys — no stale-VK drift. The
Ed25519 precompile introspection in `verify_tee_signature` is not vulnerable
to the classic bypass. And the F-04 crux — `VALID_MATCH_BATCH` soundness —
holds under independent re-derivation (§2).

| Bucket | Count |
|---|---|
| Critical | 1 |
| High | 2 |
| Medium | 3 |
| Low | 5 |
| Info (doc drift) | 1 |
| Perf-Nit | 7 |

### Severity-ranked backlog

| ID | Severity | Category | Finding |
|---|---|---|---|
| S-01 | **Critical** | Soundness, Replay | Withdrawal recipient is not bound to the `VALID_SPEND` proof |
| S-02 | High | TEE-trust, Availability | Intake never verifies the relayed `VALID_INPUT` proof or the note's existence |
| S-03 | High | Availability | `release_lock` is unreachable from every shipped client path |
| S-04 | Medium | Availability, Griefing | `verify_match_batch` lets any proof observer choose the marker's expiry |
| S-05 | Medium | Soundness, Fund-loss | `deposit` has no duplicate-commitment guard |
| S-06 | Medium | Cross-language contract | Stale v2 change-note derivation still shipped and publicly exported |
| S-07 | Low | Replay | Cancel signatures are replayable across boot sessions |
| S-08 | Low | TEE-trust | The `VALID_INPUT` proof is not bound to an order |
| S-09 | Low | Privacy | The client hands the TEE a nullifier that is never used |
| S-10 | Low | Resource exhaustion | Unbounded nonce state; arbitrary idempotency eviction |
| S-11 | Low | Soundness (defense-in-depth) | `VALID_MERGE` does not constrain input commitments distinct |
| S-12 | Info | Docs | `CRYPTOGRAPHY.md` root-ring size and on-chain conservation text are stale |
| PF-01 | Perf-Nit | CU | Three avoidable `find_program_address` calls in the settle hot path |
| PF-02 | Perf-Nit | CU | `lock_note`'s `vault_config` re-derives its bump |
| PF-03 | Perf-Nit | Tx-budget | 8 constant bytes ride every settle transaction |
| PF-04 | Perf-Nit | CU, Rent | `withdraw` allocates two guard PDAs where one suffices |
| PF-05 | Perf-Nit | Concurrency | Order intake serializes on one mutex held across the matcher lock |
| PF-06 | Perf-Nit | Allocation | `OpeningStore::get` deep-clones a 256-byte proof per lookup |
| PF-07 | Perf-Nit | Scheduling | Static settle CU limit for a variable-size settle |

---

## 2. Verified clean — what this pass positively confirmed

These are recorded so a later reviewer does not repeat the work, and so any
regression against them is visible as a change to this list.

### 2.1 Verifier-key lockstep (no drift)

All seven `programs/vault/src/zk/vk_*.rs` are **byte-identical** to a fresh
`scripts/parse-vk-to-rust.js` regeneration from the corresponding
`circuits/build/*/verification_key.json`: `match_batch_n16`, `valid_input`,
`valid_spend`, `valid_deposit`, `valid_merge_k2`, `valid_merge_k4`,
`valid_wallet_create`. The CLAUDE.md §5 foot-gun is not currently live.

### 2.2 `verify_tee_signature` is not bypassable

`programs/vault/src/instructions/tee_forced_settle.rs:303-368`. The helper
scans the full instruction-sysvar list (bounded by the u16 count at offset 0,
not a fixed window), pins `num_signatures == 1`, requires both `pk` and `msg`
to be **inlined** (`*_instruction_index == u16::MAX`), bounds-checks both
offsets against `ix.data.len()`, and compares the full 32-byte pubkey and the
32-byte message. Not checking `signature_instruction_index` (`data[4..6]`) is
harmless: the precompile verifies the signature against the `(pk, msg)` pair
*this* instruction inlines regardless of where the signature bytes live, so a
redirected signature offset cannot change what was proven. This confirms
`audit_1`'s conclusion independently.

### 2.3 F-04 re-derivation — `VALID_MATCH_BATCH` no-inflation holds

Re-derived from `circuits/templates/match_batch.circom` rather than from the
prose in `CRYPTOGRAPHY.md` §7.5:

- **Range coverage is complete and unconditional.** Every term of both
  conservation equations is `Num2Bits(64)`-constrained: `base_amount`,
  `quote_amount`, `clearing_price`, `price_remainder` (`:232-239`) and
  `buyer_change_amt`, `seller_change_amt`, `buyer_fee_amt`, `seller_fee_amt`,
  `a_amount`, `b_amount` (`:254-267`). Critically these are *not* gated on
  `is_active`, so a prover cannot dodge them by flipping the activation bit.
  With every term `< 2^64`, the sum of three is `< 3·2^64 ≪ Fr`, so Fr-equality
  in `:158-159` implies exact u64-equality with no wrap.
- **The exact-fee sandwich is correct in both directions.** `:317-333`. Floor:
  `(fee+1)·10000 > notional·rate ⇒ fee ≥ ⌊notional·rate/10000⌋`. Ceiling:
  `fee·10000 ≤ notional·rate ⇒ fee ≤ ⌊notional·rate/10000⌋`. Together exact,
  including the `rate = 0` case (ceiling forces `fee == 0`). Comparator width
  is sound: both operands are provably `< 2^80` given `fee, notional < 2^64`
  (range-checked above) and `rate < 2^16` (`:484-485`), well inside
  `GreaterThan/LessEqThan(96)`.
- **Inactive padding cannot smuggle a settle.** `:374-398` zeroes all 22
  slot-visible signals for `is_active = 0`, `is_active` is boolean-constrained,
  and the on-chain leaf recomputation hard-codes `active = 1`
  (`tee_forced_settle_batched.rs:119`). A padded slot's leaf can never equal a
  settleable leaf.
- **Slot position is pinned end to end.** `batch_slot[i] === i` in-circuit
  (`:575`), `payload.batch_slot == match_index` on-chain
  (`tee_forced_settle_batched.rs:349-352`), and inclusion is proven at
  `match_index`. The three agree, so the slot identifier is not a free input.
- **Market identity is authoritatively bound.** `config_digest` (`:505-514`)
  is recomputed on-chain from `VaultConfig` + `MarketConfig`
  (`verify_match_batch.rs:102-110`) via `darkpool_crypto::match_config_digest`,
  with byte-identical field order and BE encoding. The mint halves are never
  accepted from the prover, so the missing `Num2Bits(128)` on them (present in
  `valid_deposit`) is not a gap here.
- **`MerkleRoot(N)` matches the on-chain walker.** `:450-469` versus
  `walk_merkle_path_n16` (`tee_forced_settle_batched.rs:139-161`) — same
  domain tag (22), same left/right selection by index bit, same level order.
- **Output-inner determinism removes prover-chosen randomness.**
  `Poseidon3(24, consumed_input_inner, role)` for user outputs and
  `Poseidon3(25, consumed_input_commitment, role)` for fees, with all six role
  tags distinct. This is what closed the CS-03 class and it holds at HEAD.

**Conclusion:** the circuit is a sound no-inflation guarantor under a sound
Groth16 setup. The external circuit audit (F-04) remains a process gate, but
this pass found no soundness defect in it. Note the coupling recorded in §5.1:
the on-chain plaintext conservation backstop is gone, so this circuit is now
the *only* thing standing between a recovered trapdoor and value creation.

### 2.4 Other confirmations

- **Attestation `report_data` binding** (`api/attestation.rs:100-107`) is
  correct: caller bytes occupy `[0..32]` zero-padded right, the full K-shard
  `signer_set_hash` occupies `[32..64]`, and `reportData > 32` bytes is
  rejected before it can clobber the binding.
- **`fill_encryption`** is sound: fresh `OsRng` ephemeral per fill
  (`settle/fill_recovery.rs:127-130`), fresh per-side nonce (`:166-167`), HKDF
  `info` binds both the ephemeral and recipient pubkeys, and contributory-point
  checks run on both the encrypt and decrypt paths. Because each side's AEAD
  key is derived from a distinct shared secret, the shared ephemeral does not
  create keystream-reuse risk between the two sides.
- **`append_leaves`** batch-append logic is correct, and is already covered by
  a differential fuzz oracle against sequential `append_leaf`.
- **`initialize_market`** enforces `base_mint != quote_mint`
  (`initialize_market.rs:58-62`), closing the degenerate same-mint market that
  would otherwise let `note_a` and `note_b` alias.

---

## 3. Crypto and soundness findings

### S-01 — Withdrawal recipient is not bound to the `VALID_SPEND` proof

| | |
|---|---|
| **Severity** | **Critical** |
| **Category** | Soundness, Replay |
| **Status** | New. Not previously reported in `audit_1`, 07-12, 07-14, 07-18, or 07-20. |

**Anchors**

- `circuits/valid_spend/circuit.circom:39-44` — the complete public
  input/output set: `merkleRoot`, `nullifier`, `tokenMint[2]`, `amount`, and
  the `noteCommitment` output. No recipient, relayer, or fee signal.
- `circuits/valid_spend/circuit.circom:98` — `component main { public
  [merkleRoot, nullifier, tokenMint, amount] }`.
- `programs/vault/src/instructions/withdraw.rs:55-59` —
  `destination_token_account` is `Account<'info, TokenAccount>` whose only
  constraint is `mint == token_mint.key()`.
- `programs/vault/src/instructions/withdraw.rs:28-30` — `payer` is
  `Signer<'info>`, documented as "any signer may pay the rent".
- `programs/vault/src/instructions/withdraw.rs:164-171` — the 6-element public
  input array, which is where a recipient binding would have to appear.
- `programs/vault/src/instructions/withdraw.rs:222-232` — the
  `transfer_checked` into that unbound account, signed by the `vault_config`
  PDA.
- `packages/sdk/src/idl/vault-client.ts:699`, `:820` and
  `packages/sdk/src/utxo/withdraw.ts:30`, `:154` — the SDK surfaces the
  destination as a free caller parameter, so nothing upstream constrains it
  either.

**The problem in plain terms**

A `VALID_SPEND` proof authorises *the destruction of a specific note for a
specific amount of a specific mint*. It says nothing about **where the money
goes**. The vault then sends the money wherever the instruction's account list
points. Consequently the tuple

```
(note_commitment, nullifier, merkle_root, amount, proof)
```

is a **bearer instrument**. Possession is authorisation. The legitimate owner
has no cryptographic advantage over anyone else holding the same bytes — only
a timing advantage, and only if they are the first to land a transaction.

This is precisely the failure mode that Tornado-class designs close by making
`recipient` (and usually `relayer`, `fee`, `refund`) public inputs bound by a
dummy quadratic constraint. The pattern is absent here.

**Failure scenario A — front-run (primary vector)**

1. Alice builds a `withdraw` for a 5,000-USDC note and submits it through a
   public RPC endpoint.
2. Any of the following observes the transaction before it is included: the
   RPC operator, the current or next slot leader, or a searcher with a bundle
   relationship to the leader. Solana has no public mempool, but it does
   forward transactions to upcoming leaders, and withdrawals are a
   high-value, self-authorising, easily-recognised target.
3. The observer copies all five arguments verbatim, swaps
   `destination_token_account` for their own ATA of the same mint, and lands it
   first.
4. `nullifier_entry` and `consumed_note` are `init`'d against the attacker's
   transaction. Alice's transaction then fails on the PDA collision. Her note
   is burned and the tokens are gone — irrecoverably, because the nullifier is
   now permanently consumed.

**Failure scenario B — landed-but-reverted replay (no privileged position)**

Any `withdraw` transaction that **lands and reverts** publishes the full proof
permanently in the ledger while creating *neither* guard PDA — the note stays
spendable. Anyone scanning the vault program's failed transactions can then
replay it with their own destination, provided `merkle_root` is still in the
64-root ring (`state.rs:15`).

Reachable revert causes that leave the proof valid and the root fresh:

- an under-provisioned `ComputeUnitLimit` on the withdraw transaction;
- a transient `NoteAlreadyLocked` race against a settle that later releases;
- **any other instruction in a bundled transaction failing** — the whole
  transaction reverts, but the withdraw's instruction data is on-chain.

(Reverts caused by `StaleMerkleRoot` or `InsufficientOutstanding` are *not*
exploitable, because the attacker's replay hits the same condition. That
narrows but does not close the vector.)

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Bind recipient in-circuit (recommended)** | Add `recipient` as a public input constrained by a dummy square; add the destination (or its owner) to the on-chain public-input array. | Correct, standard, minimal constraint cost (~1 constraint). Requires the full circuit → zkey → VK → tree-reset cycle. |
| **B — Bind recipient + relayer + fee** | Option A plus `relayer` and `fee` public inputs, so a third party can pay gas without being able to steal. | Delivers what `withdraw.rs:28`'s "any signer may pay the rent" comment already implies. Marginally more constraints; strictly better UX. Same artifact cycle as A, so pay it once. |
| **C — Require the destination's owner to sign** | Non-circuit: add `destination_owner: Signer` and constrain `destination_token_account.owner == destination_owner.key()`. | Ships in a day with no ceremony. But it destroys the gasless/relayer property and links the withdrawing wallet on-chain, weakening the anonymity set — the opposite of the protocol's purpose. **Stopgap only.** |
| **D — Ephemeral-destination discipline (client-side)** | Documentation-only: instruct clients to withdraw to a fresh ATA. | Does **not** mitigate. The attacker substitutes *their* destination; the victim's choice is irrelevant. Listed to be explicitly rejected. |

The recommended path is **B**, taken together with the phase-2 MPC ceremony so
the artifact churn is paid once.

**Sketch (Option A/B)**

```circom
signal input recipient;                    // public
signal recipientSquare;
recipientSquare <== recipient * recipient; // binds without affecting the witness
```

**Lockstep:** Yes — the deepest in this report.
`valid_spend/circuit.circom` → `scripts/build-circuits.sh` (regenerates
`.wasm`, `circuit_final.zkey`, `vk_valid_spend.rs`) → `withdraw.rs` public
inputs and arity (`verify_groth16_proof::<6>` → `::<7>`) →
`packages/sdk/src/idl/vault-client.ts::buildWithdrawIx` →
`packages/sdk/src/utxo/withdraw.ts` → the SDK VALID_SPEND prover and its
browser worker → `programs/vault/tests/zk_spend_roundtrip.rs` →
`withdraw-transport.test.ts` → devnet redeploy → **mandatory tree reset**
(CLAUDE.md §2.4 / §5.2: pre-existing leaves are unspendable under the new VK).

**Cost of the fix**

| Item | Estimate |
|---|---|
| Circuit edit + rebuild | ~0.5 day (the constraint is trivial; the rebuild is mechanical) |
| Vault handler + public-input arity | ~0.5 day |
| SDK builder, prover, browser worker | ~1 day |
| Tests (roundtrip, transport, negative "wrong destination ⇒ `InvalidProof`") | ~1 day |
| Devnet redeploy + tree reset + `devnet-deposit-withdraw` validation | ~0.5 day |
| **Total** | **~3.5 days engineering**, plus one full artifact/ceremony cycle |

The ceremony coupling is what makes scheduling matter more than the code:
bundle S-01 with PF-03 and any other circuit work so the tree reset, VK
regeneration, and (eventually) the phase-2 MPC happen once rather than three
times.

**Regression test.** In `zk_spend_roundtrip.rs`: prove a withdraw for
destination A, then submit the identical proof with destination B and assert
`InvalidProof (6000)`.

---

### S-02 — Intake never verifies the relayed `VALID_INPUT` proof or the note's existence

| | |
|---|---|
| **Severity** | High |
| **Category** | TEE-trust, Availability |
| **Status** | New. Compounds D-01 (settle-failure freeze) and S-03. |

**Anchors**

- `crates/darknyx-tee/src/api/orders.rs:97-109` — the contract, stated in a
  comment: "The matcher does NOT verify it (on-chain `lock_note` does…); it
  holds it in enclave memory until settle."
- `crates/darknyx-tee/src/api/orders.rs:347-351` — the 256-byte proof is
  hex-decoded into `Groth16ProofBytes` and stored. That is the last thing that
  happens to it before settle.
- `crates/darknyx-tee/src/api/orders.rs:530-532` — `verify_commitment` is the
  only cryptographic check on the note.
- `crates/darknyx-tee/src/matcher/openings.rs:110-118` — the design note
  restating the deferral.
- `crates/darknyx-tee/src/settle/submit_lock.rs:9-20` — the two `lock_note`
  transactions are independent and sent concurrently, so the honest side lands
  even when the other fails.

**The problem in plain terms**

`prepare_order` validates a great deal: canonical Ed25519 signature, boot
session freshness, tick alignment, minimum size, BN254 Fr-safety, nonce
monotonicity, expiry cap, and — importantly —
`opening.verify_commitment(&note_commitment)`.

But `verify_commitment` proves only that *the opening is self-consistent with
a commitment the client signed*. It does not prove the note exists. A client
can invent an opening from nothing, compute its Poseidon6, sign that
commitment with their own trading key, and attach 256 bytes of random noise as
`valid_input_proof`. Every check passes.

This is a real capability gap, not a theoretical one: the enclave runs a full
Merkle mirror (`crate::merkle::MerkleMirror`) and already ships
`vk_valid_input`. It has everything needed to verify. It simply does not.

**Failure scenario**

1. The attacker holds one valid API key. Bearer auth is account-level; it
   gates rate-limiting and audit, not note ownership (`orders.rs:14-22`).
2. They post orders backed by fabricated notes, priced to cross whatever is
   resting on the book.
3. The matcher crosses fake against real and the settle worker fires both
   `lock_note` transactions concurrently. The honest side's lock — a real
   proof for a real note — **lands**. The fake side's is rejected by the
   on-chain Groth16 verifier.
4. The batch dies. The honest user's note now carries an on-chain `NoteLock`
   stamped with their order's `expiry_slot`, up to `MAX_LOCK_TTL_SLOTS = 4_500`
   slots (~30 min at 400 ms).
5. For that entire window: `withdraw` refuses (`withdraw.rs:129-140`), `merge`
   refuses (`merge.rs:98-106`), and a fresh `lock_note` refuses (`init`
   collision). In-enclave, `failed_reservations` keeps the opening reserved so
   the user cannot re-place either.

Cost to the attacker: **zero**. No on-chain footprint, no collateral at risk,
no proof generation, no SOL spent. Composed with **S-03** (no way to release
the lock), this becomes a cheap, repeatable, protocol-wide freeze: one API key
can chase every resting order and pin its collateral in 30-minute increments
indefinitely.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Verify at intake (recommended)** | Verify the relayed Groth16 against `vk_valid_input` with public inputs `[merkle_root, note_commitment, mint_lo, mint_hi]`, and require `merkle_root` to be in the mirror's recent-root ring for the declared `tree_id`. | ~1–2 ms per order on the CVM CPU — negligible beside the Ed25519 verify and Poseidon work already on that path. Converts "honest counterparty frozen for 30 min" into "attacker gets a 400". |
| **B — Mirror-membership check only** | Skip the Groth16; just require `note_commitment` to be a known leaf in the mirror. | Much cheaper, and catches wholly-fabricated notes. But it does **not** catch a proof for a note the client does not own, so it is strictly weaker than A. Reasonable as an immediate first-line filter. |
| **C — Tighten `failed_reservations`** | Release the enclave-side reservation on *confirmed lock failure* rather than waiting for slot expiry. | Complementary, not a substitute — the on-chain lock is the binding constraint, not the enclave reservation. Should be done regardless. |
| **D — Require collateral/stake per order** | Economic disincentive. | Contradicts the "orders never touch L1" design property. Rejected. |

Do **A + C**. Ship **B** first if A cannot land immediately.

**Lockstep:** None. Verification-only; no wire format, canonical body, or hash
changes.

**Cost of the fix**

| Item | Estimate |
|---|---|
| Load `vk_valid_input` in the TEE and wire the verify into `prepare_order` | ~1 day |
| Mirror root-ring lookup by `tree_id` | ~0.5 day (the mirror already tracks roots) |
| `failed_reservations` early release on confirmed lock failure | ~0.5 day |
| Tests in `orders_surface.rs` (bad proof, non-existent note, stale root) | ~1 day |
| Intake latency re-benchmark against the loadgen | ~0.5 day |
| **Total** | **~3.5 days**, no ceremony, no redeploy of the vault |

---

### S-03 — `release_lock` is unreachable from every shipped client path

| | |
|---|---|
| **Severity** | High |
| **Category** | Availability |
| **Status** | New. **Sharpens D-01 and D-09**, both of which assume `release_lock` is callable. |

**Anchors**

- `programs/vault/src/instructions/release_lock.rs` — the whole file. The
  instruction is correct and permissionless post-expiry.
- `programs/vault/src/instructions/withdraw.rs:129-140` — rejects on **any**
  program-owned `note_lock_slot`, expired or not, and its comment defers
  explicitly: "it's safer to reject any initialized lock and require the user
  to call `release_lock` first."
- **Absent from**: `packages/sdk/src/idl/vault-client.ts` (no builder),
  `packages/sdk/src/idl/seeds.ts`, `crates/darknyx-tee/src/settle/*` (no
  caller), `scripts/*`, and `programs/vault/tests/*` (no coverage).
- `packages/sdk/dist/orders/cancel-order.d.ts:10` references it in prose only.

**The problem in plain terms**

D-01 (2026-07-20) analysed the settle-failure freeze and concluded the recovery
path was "`release_lock` + re-place". A repo-wide grep shows **that path is not
implemented anywhere**. There is no instruction builder, no seed constant, no
TEE sweeper, no script, and no test. D-09 separately analysed `release_lock`'s
rent-sniping property — which is a real observation about an instruction that,
in practice, nobody can invoke.

`merge` and `lock_note` block on a live lock too, so the freeze is total: a
note left locked by *any* failed settle is unspendable, unmergeable, and
unlockable through every shipped interface. Recovery requires hand-assembling
the Anchor discriminator, deriving `[b"note_lock", commitment]`, and
submitting a raw instruction — beyond any realistic user and impossible from
the reference daemon.

This is what turns S-02 from griefing into a denial-of-service with no
recovery, and it is why S-03 is rated High despite being a pure omission.

**Recommended fixes** — all three, they are complementary:

| Option | Description | Trade-off |
|---|---|---|
| **A — SDK builder + auto-release** | Add `buildReleaseLockIx` to `vault-client.ts` and the `NoteLock` seed to `seeds.ts`. Have `Wallet.withdraw` pre-flight the `note_lock_slot` account and prepend a release when it is program-owned and expired. | The user-facing fix. Small, self-contained, no on-chain change. |
| **B — TEE sweeper** | Have the settle worker sweep locks it created for batches that failed definitively. The `marker_sweep` module is already the template: durable queue, batched closes, retry on transient RPC failure. | Fixes the common case without user action, and reclaims rent to the TEE keys that paid it. |
| **C — Relax the `withdraw` guard** | Change `withdraw.rs:129-140` to reject only on a **non-expired** lock, reading `expiry_slot` from the account data it already borrows. | Removes the need for a separate transaction entirely. Requires care: the lock account stays allocated (rent unreclaimed), so B is still wanted. This is an on-chain change and needs a redeploy. |
| **D — Do nothing, document it** | Rejected. An undocumented raw-instruction recovery path is not a recovery path. | — |

**Lockstep:** None for A and B. C is an on-chain change requiring
`deploy-devnet.sh` and a litesvm regression.

**Cost of the fix**

| Item | Estimate |
|---|---|
| A: SDK builder + seed + wallet pre-flight | ~1 day |
| B: TEE sweeper (mirrors `marker_sweep`) | ~1.5 days |
| C: `withdraw` guard relaxation + redeploy | ~0.5 day + a devnet cycle |
| Litesvm test `lock → expire → release_lock → withdraw` (currently zero coverage) | ~0.5 day |
| **Total** | **~3.5 days** for A+B+test; +0.5 day and a redeploy if C is taken |

---

### S-04 — `verify_match_batch` lets any proof observer choose the marker's expiry

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Availability, Griefing |
| **Status** | New. Adjacent to D-02 (marker runway) but a different mechanism. |

**Anchors**

- `programs/vault/src/instructions/verify_match_batch.rs:36` — `expiry_slot` is
  a caller-supplied instruction argument.
- `:84-91` — bounded only to `(clock.slot, clock.slot + 300]`.
- `:38-41` — `payer` is deliberately unauthenticated: "Anyone can pay rent /
  submit the proof. Authorization is the proof itself."
- `:65-72` — the marker is `init`, so exactly one party sets the TTL per root.
- `:121-124` — the caller's value is written verbatim.
- `programs/vault/src/instructions/tee_forced_settle_batched.rs:397-400` — the
  settle side reads it and fails with `BatchValidityMarkerExpired`.

**The problem in plain terms**

The permissionless-payer design is deliberate and good — the proof *is* the
authorisation. But it was paired with a caller-chosen TTL, and the `init`
makes that choice exclusive. That combination hands an observer a lever the
design never intended to expose.

**Failure scenario**

1. A griefer observes the TEE's `verify_match_batch` transaction — via the
   leader, a searcher relationship, or a malicious RPC.
2. They replay **the same proof and the same root** with
   `expiry_slot = clock.slot + 1`, and land first.
3. The TEE's own verify then fails on the `init` collision. All N settles in
   the batch fail with `BatchValidityMarkerExpired`.
4. Meanwhile the 2N `lock_note` transactions have already landed, so up to 32
   users' notes are pinned for the full lock TTL — the same freeze as S-02,
   reached by a different door.

Cost: one transaction fee per destroyed batch.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Derive the expiry on-chain (recommended)** | Delete the argument; set `expiry_slot = clock.slot.saturating_add(MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS)`. | Removes the degree of freedom entirely. Nothing in the protocol needs a caller-chosen TTL — the constant already exists and is already the ceiling. Simplest and strictest. |
| **B — Gate `payer` to `vault_config.tee_pubkeys`** | Require the verify submitter to be a registered TEE key. | Also closes it, but sacrifices the useful "anyone can push a valid proof" liveness property (a third party can currently unstick a batch whose TEE key ran out of SOL). |
| **C — Enforce a minimum TTL** | e.g. `expiry_slot >= clock.slot + 150`. | Weaker than A and no simpler. Rejected. |

Take **A**. It is strictly less code than what is there now.

**Lockstep:** Yes, but shallow — the instruction data layout changes.
`verify_match_batch.rs` ↔
`crates/darknyx-tee/src/settle/verify_match_batch.rs` ↔ the SDK builder ↔
`programs/vault/tests/match_batch_verify.rs`.

**Cost of the fix**

| Item | Estimate |
|---|---|
| Vault handler + argument removal | ~0.5 day |
| TEE + SDK builder update | ~0.5 day |
| Litesvm regression (front-run replay with short TTL ⇒ rejected) | ~0.5 day |
| Devnet redeploy | ~0.5 day |
| **Total** | **~2 days** |

---

### S-05 — `deposit` has no duplicate-commitment guard

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Soundness, Fund-loss |
| **Status** | New. |

**Anchors**

- `programs/vault/src/instructions/deposit.rs:67-143` — verifies
  `VALID_DEPOSIT`, transfers SPL, appends the leaf, bumps `outstanding`. No
  check that `note_commitment` is not already a leaf.
- `programs/vault/src/instructions/withdraw.rs:70-95` — both spend guards are
  keyed on values that are **identical for identical commitments**:
  `ConsumedNoteEntry` at `[b"consumed_note", commitment]` and `NullifierEntry`
  at `[b"nullifier", nullifier]`.

**The problem in plain terms**

Two deposits with the same commitment both move tokens in and both increment
`outstanding`, but exactly **one** can ever be withdrawn — the second
withdraw collides on both guard PDAs. The vault ends up permanently
over-collateralised (so no solvency alarm fires) and the user's second deposit
is silently unrecoverable.

**Reachability.** `recovery_nonce = deriveBlindingFactor(seed, depositIndex)`
is fully deterministic, so depositing the same `(mint, amount, depositIndex)`
twice produces a byte-identical commitment. That is plausible on a seed-only
restore where the deposit-index counter is reconstructed incorrectly, or on
any client that persists the index non-transactionally and crashes between
submit and store. This is the same class of mutable-client-counter footgun as
CS-12 (daemon merge counter), which the protocol already decided to design out
by deriving from consumed commitments.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — `init` a commitment-keyed PDA (recommended)** | Add a `DepositedNoteEntry` at `[b"deposited_note", commitment]` with `init`. Mirrors the existing guard idiom exactly. | ~1 CPI + ~0.001 SOL rent per deposit. Makes the duplicate structurally impossible and fails loudly at the point of the mistake. |
| **B — Reuse `ConsumedNoteEntry`'s namespace** | Rather than a new account type, check the commitment has no existing consume entry. | Cheaper, but only catches deposit-after-spend, not deposit-after-deposit. Insufficient. |
| **C — Fold the leaf index into the deposit inner** | Make the inner a function of the tree position so repeats are impossible by construction. | Elegant, but a circuit change (new public input, new artifact cycle) for a problem A solves with an account. Not worth the ceremony. |
| **D — Client-side only** | Harden index recovery in the SDK and document the hazard. | Should be done anyway, but a client-side invariant protecting user funds is exactly the shape this protocol otherwise avoids. Not sufficient alone. |

Take **A**, plus **D** as hardening.

**Lockstep:** None (new PDA, no hash or wire-format change). Requires the SDK
seed constant + `depositPda()` helper per CLAUDE.md §8.3 — CI does not catch
that omission, only integration tests do.

**Cost of the fix**

| Item | Estimate |
|---|---|
| Vault: new account type + `init` in `deposit` | ~0.5 day |
| SDK: seed constant, PDA helper, `buildDepositIx` account list | ~0.5 day |
| Litesvm regression (duplicate deposit ⇒ rejected) | ~0.5 day |
| Devnet redeploy + `devnet-deposit-withdraw` validation | ~0.5 day |
| **Total** | **~2 days** |

---

### S-06 — Stale v2 change-note derivation still shipped and publicly exported

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Cross-language contract |
| **Status** | New. Residue of the CS-03 remediation. |

**Anchors**

- `crates/darkpool-matcher/src/algorithm.rs:519-540` — `run_batch` computes
  `note_e_commitment` / `note_f_commitment` from
  `change_note::derive_inner(match_id, role)`.
- `crates/darkpool-matcher/src/change_note.rs:80-90` — that helper is
  **SHA-256** based: `SHA256("darknyx-change-inner-v2" ‖ match_id_le ‖ role)`,
  Fr-masked.
- **The live path uses something else entirely**:
  `crates/darknyx-tee/src/settle/assemble.rs:231`, `:245` and
  `crates/darknyx-tee/src/matcher/interval.rs:229`, `:267`, `:442`, `:468` all
  call `match_output_inner_hash` = `Poseidon3(24, input_inner, role)`.
- `circuits/templates/match_batch.circom:172-179` — the circuit enforces the
  Poseidon form. The SHA form would be rejected.
- `packages/sdk/src/utxo/change-note.ts` — the TS port, **exported from the
  public index** at `packages/sdk/src/index.ts:52`.
- `packages/sdk/tests/change-note-inner-parity.test.ts` and
  `crates/darkpool-matcher/tests/change_note_parity.rs` — a full
  cross-language KAT is still maintained for it.

**The problem in plain terms**

CLAUDE.md describes `run_batch`/`run_batch_capped` as "the single source of
truth" for matching. But the change-note commitments it emits are computed
with the **retired v2 construction** and are silently overwritten downstream by
the assembler. They are values the chain will never create.

Worse, `deriveChangeInner` is exported from the SDK's public index with a
maintained parity test, so it reads as a supported client API. The doc comment
at the top of `change-note.ts` correctly says it is legacy and points at
`match-output.ts` — but a doc comment on an exported symbol with a green KAT is
not a deprecation.

**Failure scenario**

An SDK consumer follows `deriveChangeInner` to reconstruct their change note
after a partial fill, computes
`Poseidon6(2, mint, change_amt, owner, sha_inner)`, and gets a commitment that
is not in the tree. Their balance silently under-reports and the note appears
unspendable from their client's view. Separately, any future consumer of
`run_batch`'s output commitments inherits a wrong value with **no test
catching it** — the parity suite validates the legacy construction against
itself, which is exactly the "all parity tests pass while the invariant is
missing" shape the 2026-07-14 pass warned about.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Delete (recommended)** | Remove `change_note::derive_inner`, `deriveChangeInner`, and their parity tests. Have `run_batch` emit the v3 commitment or `[0;32]`. | Cleanest. Retires a whole cross-language contract that costs maintenance and buys nothing. Check no pre-cutover note family still needs it before deleting. |
| **B — Un-export + deprecate** | Remove from `packages/sdk/src/index.ts:52`, mark `#[deprecated]` / `@deprecated` with a pointer to `match-output.ts`, keep the KAT. | Lower risk if any legacy note family still depends on it. Leaves the `run_batch` drift unaddressed. |
| **C — Make `run_batch` emit the v3 value** | Thread the consumed input inner into the algorithm so its commitments match reality. | Correct but the largest change, and the assembler already recomputes — so it buys consistency, not capability. Worth it only if a second consumer of `MatchPair` commitments is planned. |

Take **A** if nothing legacy depends on it; otherwise **B** now and **A** at
the next cleanup.

**Lockstep:** Removal only — deleting a contract, not changing one. Follow
CLAUDE.md §2.6: grep the workflow YAMLs and scripts for the deleted test
basenames in the same commit.

**Cost of the fix**

| Item | Estimate |
|---|---|
| Confirm no live consumer (matcher, TEE, SDK, daemon, demo) | ~0.5 day |
| Delete / un-export + adjust `run_batch` output | ~0.5 day |
| Remove or re-point parity tests; §2.6 grep sweep | ~0.5 day |
| **Total** | **~1.5 days** |

---

### S-07 — Cancel signatures are replayable across boot sessions

| | |
|---|---|
| **Severity** | Low |
| **Category** | Replay |
| **Status** | New. The cancel-side analogue of CS-11, which was fixed for placement only. |

**Anchors**

- `crates/darkpool-matcher/src/order_canonical.rs:159-172` — `CancelCanonical`
  is `(order_id, trading_key, cancel_nonce)`. No `session_id`.
- `crates/darknyx-tee/src/api/orders.rs:767-794` — `cancel_core` verifies the
  signature and acts immediately; `cancel_nonce` is never compared to anything.
- Contrast `crates/darknyx-tee/src/api/orders.rs:341-346` (session binding on
  placement) and `:682-688` (strict per-trading-key nonce monotonicity on
  placement). The cancel path has neither.

**The problem in plain terms**

`OrderCanonical` was correctly hardened with `session_id` + a monotonic
`arrival_nonce`. `CancelCanonical` was not. A captured cancel signature is
therefore valid **forever**, in **any** boot session, for that
`(order_id, trading_key, cancel_nonce)` triple.

**Failure scenario**

`order_id`s are deterministic HD values (`deriveOrderId`). After a CVM restart
the enclave's replay state resets. If the client re-derives the same
`order_id` — which the deterministic scheme explicitly intends — a stored
cancel signature kills the new order. Any party that ever handled the cancel
body retains that capability indefinitely: a logging proxy, a compromised
client host, an operator with request logs, a backup.

Impact is griefing/liveness only — a cancel never moves funds
(`orders.rs:797-802` reasons about exactly this). But it is an
authorisation that outlives its intended scope by design accident.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Session + monotonic nonce (recommended)** | Add `session_id` to `CancelCanonical` and enforce strictly-increasing `cancel_nonce` per trading key in the same `submission_replay` map that already guards placement. | Makes cancel structurally identical to placement. The map and the lock already exist. |
| **B — Session only** | Add `session_id`, skip the nonce check. | Bounds replay to one boot session. Simpler, but leaves in-session replay open (low impact, since a cancelled order is gone). |
| **C — Nonce only** | Enforce monotonicity without a session field. | Avoids the canonical-bytes change and the parity-fixture churn, but nonce state is per-boot volatile, so it does not survive a restart — the exact scenario above. Insufficient. |

Take **A**. Do it together with S-10, which touches the same map.

**Lockstep:** Yes — `order_canonical.rs` ↔
`packages/sdk/src/orders/canonical.ts` ↔ **both** pinned fixture digests
(`CANCEL_FIXTURE_DIGEST_HEX` at `order_canonical.rs:193` and its TS mirror) ↔
`order-canonical-parity.test.ts`. Regenerate both fixtures in the same commit.

**Cost of the fix**

| Item | Estimate |
|---|---|
| Rust + TS canonical change, both fixtures regenerated | ~1 day |
| Nonce enforcement in `cancel_core` | ~0.5 day |
| Parity + `orders_surface.rs` tests | ~0.5 day |
| Client-side cancel-nonce sourcing (daemon + SDK) | ~0.5 day |
| **Total** | **~2.5 days** |

---

### S-08 — The `VALID_INPUT` proof is not bound to an order

| | |
|---|---|
| **Severity** | Low (inside the accepted TEE-trust boundary — but the boundary is wider than documented) |
| **Category** | TEE-trust |
| **Status** | New framing. Related to U-02 (consumed-note guard, fixed) and D-03 (root-ring burn). |

**Anchors**

- `circuits/valid_input/circuit.circom:122` — `component main { public
  [merkleRoot, noteCommitment, tokenMint] }`. Nothing about `order_id`,
  `expiry_slot`, or a session.
- `programs/vault/src/instructions/lock_note.rs:131-146` — `order_id` and
  `expiry_slot` are unconstrained instruction arguments carried alongside the
  proof.
- `programs/vault/src/state.rs:15` — the 64-root ring defines how long a proof
  stays usable.

**The problem in plain terms**

A user generates one `VALID_INPUT` proof per order and relays it through the
TEE. Because the proof binds only `(root, commitment, mint)`, an
authorised-but-compromised TEE key can **retain** that proof and re-lock the
note against an arbitrary `order_id` the user never placed — or one they
cancelled — for as long as `merkle_root` remains in the ring.

U-02 closed the *consumed*-note case (a settled or withdrawn note can no
longer be re-locked). This is the *unconsumed* case, which U-02 does not
cover.

`CRYPTOGRAPHY.md` §2 accepts that "a compromised TEE clears at a bad price,
bounded by the order size". The proof-reuse property widens that: the bound
becomes *the note size*, and it applies to orders the user believes are
cancelled. That is a materially different statement to make to an
institutional counterparty, and it should be written down rather than
inferred.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Document the widened boundary (do now)** | Amend `CRYPTOGRAPHY.md` §2 to state that a `VALID_INPUT` proof authorises *the note*, not *the order*, for the ring window. | Zero engineering cost. Makes the accepted trust assumption accurate, which is the actual deliverable of an accepted-risk decision. |
| **B — Bind `order_id` in-circuit** | Add `order_id` as a public input. | Prevention rather than documentation. Costs a circuit + zkey + VK cycle, a tree reset, and forces the client to prove **per order** rather than per note — which meaningfully worsens placement latency (the client prover is already the UX bottleneck). |
| **C — Shorten the effective window** | Reduce the ring, or have the TEE refuse to lock against a proof older than N slots. | The enclave-side variant is free and narrows the window without a circuit change; but it is TEE-enforced, so it does not bind a *compromised* TEE — the exact adversary in question. Cosmetic here. |

Do **A** now. Scope **B** with the external circuit auditors alongside S-01,
so one ceremony covers both — do not attempt it as a standalone VK bump.

**Cost:** A is ~0.5 day of documentation. B is ~4 days plus a shared ceremony
cycle, and should be costed as part of the S-01 circuit release.

---

### S-09 — The client hands the TEE a nullifier that is never used

| | |
|---|---|
| **Severity** | Low |
| **Category** | Privacy |
| **Status** | New. Residue of the payload-v9 nullifier removal. |

**Anchors**

- `crates/darknyx-tee/src/api/orders.rs:92-95` (wire field), `:334` (decoded).
- `crates/darknyx-tee/src/matcher/openings.rs:60-63` (stored on `NoteOpening`).
- Repo-wide grep: `opening.nullifier` has **no consumer** outside the struct
  definition and its own unit tests. Payload v9 removed nullifiers from
  settlement; the field was not removed from intake.

**The problem in plain terms**

The enclave holds `Poseidon3(3, spending_key, inner_hash)` for every collateral
note. That value is exactly what the note's eventual `withdraw` publishes
on-chain. Holding it buys the protocol nothing and costs it the ability to
claim that a TEE compromise is custody-only.

**Failure scenario**

A memory-disclosure bug, a debug-endpoint regression, a core dump captured by
the host, or a compromised enclave lets an adversary join the set of nullifiers
it holds against the nullifiers published by `withdraw` — deanonymising which
orders correspond to which withdrawals. That defeats the core unlinkability
property (the anonymity set is supposed to be "every order in the book that
didn't settle") without any custody compromise at all.

The design note at `openings.rs:23-30` correctly argues a *wrong* nullifier is
self-harm. It does not address why a *correct* one is collected.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Remove the field (recommended)** | Drop it from `PlaceOrderRequest`, `NoteOpening`, and `docs/tee-api-openapi.yaml`. | It is **not** in the signed canonical body, so this is not a signing-contract change — just a wire-schema narrowing. Clean removal. |
| **B — Keep but zeroize** | Retain the field, overwrite after use. | There is no "after use" — there is no use. Strictly worse than A. |
| **C — Keep for a future re-introduction** | Leave it in case nullifiers return to the settle path. | Speculative retention of a secret is the wrong default. If they return, re-add the field then. |

**Lockstep:** None (not part of `OrderCanonical`). Requires a client-side
change in the SDK order builder and an OpenAPI update; coordinate the wire
break with any external integrators.

**Cost:** ~1 day including the OpenAPI update, SDK builder, and a
back-compatibility decision (accept-and-ignore for one release, then remove).

---

### S-10 — Unbounded nonce state; arbitrary idempotency eviction

| | |
|---|---|
| **Severity** | Low |
| **Category** | Resource exhaustion |
| **Status** | New. |

**Anchors**

- `crates/darknyx-tee/src/api/state.rs:759-780`. The comment at `:759-760`
  states it outright: "Nonce high-water marks are not evicted."
- `:769-774` — idempotency eviction picks `replay.idempotency.keys().next()`.

**The problem in plain terms**

Two distinct issues in one map:

1. **`last_arrival_nonce` grows forever.** One entry per distinct trading key,
   never evicted. A client rotates trading keys freely — that is an explicit
   design property (a free `offset` bump, deliberately outside
   `user_commitment`, so users can break long-term linkage). Combined with
   S-02, each order needs no real collateral, so an attacker can add entries at
   whatever rate the rate limiter permits, indefinitely.
2. **Idempotency evicts arbitrarily.** `keys().next()` returns an entry in
   HashMap iteration order, not insertion order. A burst evicts *live* records,
   turning legitimate client retries into `duplicate` rejections — a
   correctness bug, not just a capacity one.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Bounded LRU + slot TTL (recommended)** | Give both maps insertion-ordered eviction and a slot-based TTL. Nonce marks can expire once `MAX_LOCK_TTL_SLOTS` has elapsed, because `session_id` binding already prevents cross-boot replay — so expiry does not reopen CS-11. | Correct for both issues. Small. |
| **B — Cap the map and reject beyond it** | Fail placement once the map is full. | Turns a slow memory leak into a hard availability cliff. Worse. |
| **C — Fix eviction order only** | Address (2), leave (1). | (1) is the security-relevant half. Insufficient alone. |

Do **A**, bundled with S-07 (same map, same lock).

**Lockstep:** None. TEE state only.

**Cost:** ~1.5 days including tests for eviction order and TTL expiry, and a
soak run against the loadgen to confirm the bound holds.

---

### S-11 — `VALID_MERGE` does not constrain input commitments distinct

| | |
|---|---|
| **Severity** | Low (defense-in-depth — **currently unreachable**) |
| **Category** | Soundness |
| **Status** | New. |

**Anchors**

- `circuits/templates/valid_merge.circom:82-126` — the per-slot loop. Nothing
  prevents two active slots carrying identical `(amount, innerHash)`, which
  would make `outputAmount` double-count one note.
- `programs/vault/src/instructions/merge.rs:84-88` — `active_commitments`
  preserves duplicates.
- `programs/vault/src/instructions/merge.rs:209-244` — where it is actually
  blocked: `create_consumed_note_pda` requires
  `ai.data_is_empty() && ai.lamports() == 0`, and the System Program
  independently rejects a second `create_account` on the same address.

**Assessment.** The value inflation is **not reachable**. Duplicate-account
aliasing in the Solana runtime means the second call sees the account already
created, and even without aliasing the CPI fails. This is reported only
because the entire guarantee rests on one runtime behaviour with **no
in-circuit backstop and no negative test**.

**Related, benign observation.** A K=2 merge of `[C0, C1]` and a K=4 merge of
`[C0, C1, 0, 0]` produce the *identical* `outputInner` — both hash
`Poseidon6(26, C0, C1, 0, 0, 3)` (`valid_merge.circom:146-155`). Not
exploitable, since inputs are consume-once. But it means **K is not part of the
output identity**, which is a surprising property to leave undocumented for
anyone reasoning about merge recovery.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — On-chain `require!` (recommended)** | Assert active input commitments are pairwise distinct in `merge.rs` before proof verification. Two lines; K ≤ 4 so the O(K²) scan is free. | Zero risk, no ceremony, makes the intent explicit and testable. |
| **B — In-circuit strict ordering** | Constrain `c_i < c_{i+1}` for active slots. | Stronger (removes the runtime dependency entirely) but costs a circuit + VK cycle for a currently-unreachable issue. Only worth folding into an already-scheduled ceremony. |
| **C — Document only** | Note the reliance in `merge.rs`. | Weakest, but better than nothing if neither above is scheduled. |

Take **A** now; consider **B** if the merge circuit is touched for another
reason. Add the negative test regardless.

**Cost:** ~0.5 day for A plus a litesvm negative test. B is ~2 days plus a
shared ceremony cycle.

---

### S-12 — Stale protocol text in `CRYPTOGRAPHY.md`

| | |
|---|---|
| **Severity** | Info |
| **Category** | Docs |

Not separate security findings, but each should be fixed alongside the
corresponding remediation. Listed most-material first.

- **§8 step 5 and step 6** describe on-chain checks that **no longer exist**:
  "Conservation law … `lock_a.amount == quote_amount + buyer_change_amt +
  buyer_fee_amt` … both via `u64::checked_add`", and "`has_e = (note_e_commitment
  != [0;32])` must equal `(buyer_change_amt > 0)`". Amounts left both the
  payload and `NoteLock` in v7/P3b. The handler only derives `has_e` to gate
  the relock (`tee_forced_settle_batched.rs:435-443`), and the comment at
  `:422-434` says so explicitly. **This is the most load-bearing stale
  passage**: it describes an on-chain conservation backstop that no longer
  exists, which is precisely the fact that makes the phase-2 ceremony a hard
  blocker (§5.1).
- **§6** — "a **ring buffer of the last 32 roots** in `VaultConfig.roots[32]`
  … roughly **2 minutes of freshness**". The code is `ROOT_HISTORY_SIZE = 64`
  in the per-shard `MerkleTree` (`state.rs:15`, `:148`), ~26 s. Both the count
  and the derived freshness figure are wrong, and freshness is exactly what a
  client reasons about when deciding whether to re-prove.
- **§10** — asserts `tee_forced_settle` is "net-zero change" for `outstanding`.
  True, but the mechanism is now the circuit alone, not the removed on-chain
  per-side conservation check.

---

## 4. Performance findings

Calibrated against `docs/throughput-roadmap.md`. Items 1–5 there (settle
concurrency, per-shard ALT pools, optimistic settle, adaptive cadence,
witness-gen acceleration) are excluded as known and gated. The prior CU pass
(CU-1 batch append, CU-2 load dedupe, CU-3 unused account) is treated as done;
these are what it missed.

### PF-01 — Three avoidable `find_program_address` calls in the settle hot path

**Severity:** Perf-Nit · **Category:** CU

**Anchors**

- `programs/vault/src/instructions/tee_forced_settle_batched.rs:193-207` —
  `note_lock_a` and `note_lock_b` use a bare `bump`, forcing Anchor into
  `find_program_address`.
- `:357-360` — the marker uses `Pubkey::find_program_address` explicitly.
- Contrast `:179` (`bump = vault_config.load()?.bump`) and `:189`
  (`bump = merkle_tree.load()?.bump`), which do it correctly.

**Cost.** `NoteLock` stores its own bump (`state.rs:239`), written by both
`lock_note` (`:156`) and `create_relock_pda` (`tee_forced_settle.rs:209`), so
`bump = note_lock_a.load()?.bump` is directly available. The marker's bump sits
at data offset 48 and can drive a single `create_program_address` +
`require_keys_eq!` instead of a search — sound here, because only this program
can own an account at its own PDA and only `verify_match_batch`'s `init`
creates one, always at the canonical bump.

`create_program_address` costs ~1,500 CU; `find_program_address` averages ~1.4
attempts. Roughly **3–5k CU** recoverable, ~3–4% of the 115k budget
(`settle/pipeline.rs:109`). `consumed_a`/`consumed_b` genuinely need the search
(`init`, nothing stored) and should be left alone.

**Fix:** switch the two `NoteLock` accounts to stored bumps; replace the marker
search with `create_program_address` against the bump read from its data (after
the existing owner + discriminator + length checks, which already run first).

**Lockstep:** None. **Cost:** ~1 day including a litesvm CU-trace confirmation.

### PF-02 — `lock_note`'s `vault_config` re-derives its bump

**Severity:** Perf-Nit · **Category:** CU

**Anchor:** `programs/vault/src/instructions/lock_note.rs:43-47` — a bare
`bump`, unlike `withdraw.rs:36`, `deposit.rs:18`, `merge.rs:49`, and
`tee_forced_settle_batched.rs:179`, which all use
`bump = vault_config.load()?.bump`.

**Cost.** ~1.5–3k CU per lock transaction — and there are **2N lock
transactions per batch**, so ~48–96k CU per full N=16 batch across the
pipeline. The single cheapest change in this report: a one-line edit with no
wire, hash, or account-layout impact.

**Lockstep:** None. **Cost:** ~0.5 day including the redeploy.

### PF-03 — 8 constant bytes ride every settle transaction

**Severity:** Perf-Nit · **Category:** Tx-budget

**Anchors:** `crates/darknyx-tee/src/settle/fill_recovery.rs:52-60` ·
`programs/vault/src/instructions/tee_forced_settle.rs:97`

`fill_recovery` is `[u8; 128]`: 120 bytes of ECIES bundle plus a fixed 8-byte
`"DNYXREC3"` trailer. That trailer is a compile-time constant carried in the
wire payload **and** hashed into `canonical_payload_hash`. Narrowing the field
to `[u8; 120]` reclaims **8 of the 123 bytes** of headroom under the 1232-byte
cap (`CRYPTOGRAPHY.md` §9) at zero functional cost — the version discriminator
is already carried by the `darknyx-match-v10` domain tag in the signed hash,
which is the thing that actually rejects legacy layouts.

**Lockstep:** Yes — `MatchResultPayload` ↔ `canonical_payload_hash` and its
fixed vector (`tee_forced_settle.rs:404-408`) ↔
`crates/darknyx-tee/src/settle/payload.rs` ↔
`packages/sdk/src/settlement/settle-builder.ts::canonicalPayloadHash` ↔
`settle-builder-batched.test.ts` `[hash_cross_env_parity]`.

**Recommendation:** worth doing **only bundled with another payload change**.
Eight bytes does not justify a standalone canonical-hash bump and the
cross-language fixture churn. **Cost:** ~1 day if bundled; ~2 days standalone.

### PF-04 — `withdraw` allocates two guard PDAs where one suffices

**Severity:** Perf-Nit · **Category:** CU, Rent — *with a latent correctness
edge*

**Anchor:** `programs/vault/src/instructions/withdraw.rs:70-95`

Since `noteCommitment` became a bound public **output** of `VALID_SPEND`
(`valid_spend/circuit.circom:44`), the commitment-keyed `ConsumedNoteEntry` is
a complete double-spend guard on its own — it is exactly what makes the
settle/withdraw cross-path guard symmetric (`CRYPTOGRAPHY.md` §2 invariant 4).
The additional `NullifierEntry` `init` costs a second CPI (~2–3k CU) plus
~0.0011 SOL of rent per withdraw, permanently.

**The correctness edge.** `nullifier = Poseidon3(3, sk, inner)` is deliberately
amount- **and mint-**independent, so any two notes of one owner sharing an
`inner_hash` collide on the nullifier and the second withdraw is blocked even
though it is a distinct note. Unreachable on honest paths today — every inner
derivation is role- or index-separated — but it becomes reachable the moment a
deposit index is reused, which is exactly **S-05**. The two findings should be
fixed together or the interaction documented.

**Options:** (a) drop `NullifierEntry` and rely on the commitment guard;
(b) keep it and document explicitly that it is a redundant, *coarser* guard
retained for external observability. Choose deliberately — do not leave it
undocumented.

**Lockstep:** None, but dropping it changes the withdraw account list, so the
SDK builder must move in step. **Cost:** ~1 day either way.

### PF-05 — Order intake serializes on one mutex held across the matcher lock

**Severity:** Perf-Nit · **Category:** Concurrency

**Anchor:** `crates/darknyx-tee/src/api/orders.rs:669-708`

`prepare_order` correctly performs the expensive work — Ed25519 verify,
Poseidon commitment re-derivation — outside any lock. But `place_core` then
takes `state.submission_replay.lock().await` at `:669` and **holds it across
`matcher.write().await`** at `:696`, releasing only at `:708`. Every concurrent
`POST /orders` therefore queues behind both a global mutex *and* the matcher
write lock, while the matcher tick contends for the same write lock every
`BATCH_MS`.

This is the intake ceiling the loadgen measures (~27 ord/s), and it is a
structural serialization point rather than a compute cost.

**Options:** (a) restructure as *take replay lock → check idempotency/nonce →
insert a reservation marker → drop → acquire matcher write lock → commit →
re-take replay lock to finalize*; (b) shard both maps by `trading_key[0]` into
N stripes. Either removes the global bottleneck without weakening the "one
deterministic order" property the current comment relies on — but (a) needs
care around the reservation's failure path so a crashed commit does not leave a
permanent marker.

**Lockstep:** None. **Cost:** ~2 days including a loadgen A/B to confirm the
throughput gain and a concurrency test for the reservation failure path.

### PF-06 — `OpeningStore::get` deep-clones a 256-byte proof per lookup

**Severity:** Perf-Nit · **Category:** Allocation

**Anchor:** `crates/darknyx-tee/src/matcher/openings.rs:189-191`

Returns `Option<OrderOpening>` by clone so the assembler can drop the matcher
lock. Each clone copies `Groth16ProofBytes` (256 B) plus the full opening. At
N=16 that is 32 clones per batch, plus more in the settle worker.
`Arc<OrderOpening>` gives the same lock-drop semantics at pointer cost.

Small in absolute terms. **Recommendation:** do it opportunistically when that
module is next touched, not as scheduled work. **Cost:** ~0.5 day.

### PF-07 — Static settle CU limit for a variable-size settle

**Severity:** Perf-Nit · **Category:** Scheduling headroom

**Anchors:** `crates/darknyx-tee/src/settle/pipeline.rs:109`, `:240`

`SETTLE_COMPUTE_UNIT_LIMIT = 115_000` is sized for the 6-leaf worst case, but a
settle appends 2–6 leaves and the count is derivable in the builder from which
payload commitments are `[0;32]`. An exact-fill, fee-free settle appends 2 and
uses substantially less.

This does not affect fees today — Tx D sets no `ComputeUnitPrice` (`:240`
builds only the limit instruction). But Solana's scheduler budgets against the
**requested** limit under the per-block writable-account cap (12M CU). Every
settle writes `merkle_tree[tree_id]`, so at 115k requested the ceiling is ~104
settles per shard per block regardless of actual consumption. Scaling the
request to the actual leaf count raises that ceiling proportionally — which is
exactly the axis tree-sharding exists to open.

**Not a current bottleneck** (settles run ~1/s). File it against the sharding
throughput work rather than scheduling it now. **Cost:** ~1 day, best done with
a fresh litesvm CU trace per leaf count so the tiers are measured, not guessed.

---

## 5. What I could **not** rule out / needs the team

This pass was deliberately weighted toward circuits, the vault, intake, and the
settle binding chain. The following were **not** covered and should not be read
as clean.

1. **Groth16 trusted setup — unchanged hard gate.** Confirmed as
   `CRYPTOGRAPHY.md` §13.1 states: all seven circuits use a deterministic dev
   contribution whose toxic waste is recoverable from `scripts/build-circuits.sh`.
   Worth underlining the coupling this pass confirmed (§2.3, S-12): amount
   privacy made `VALID_MATCH_BATCH` the **sole** conservation guarantor, and
   the on-chain plaintext backstop is genuinely gone from the handler. A
   recovered trapdoor now mints value with **zero** on-chain check. This is a
   hard mainnet blocker, not a nice-to-have.
2. **Alternative proving backends.** `prover/icicle_prover.rs`,
   `prover/rapidsnark_prover.rs`, `prover/rapidsnark_sys.rs` (the FFI
   boundary), and `prover/witness.rs` were not reviewed. The
   `DARKNYX_TEE_PROVER` switch means a backend producing a subtly different
   proof encoding would surface only at on-chain verify. The team's ICICLE
   byte-parity gate covers this; it was not re-run here.
3. **`api/auth.rs` (855 lines) — not line-by-line reviewed.** `audit_1`'s
   dependency triage established HS256 pinning via `Validation::default()` with
   a dstack-sealed symmetric key plus `jti` revocation. JWT issuance, TTL, and
   the revocation store's persistence across reboots were not independently
   verified. **This deserves its own pass**, because bearer auth is the only
   gate in front of S-02 — and D-07 already flags that the revoke denylist is
   memory-only across restart.
4. **`oracle/*` (~1,400 lines).** The hand-rolled Pyth PNAU parser and
   Keccak160 sorted-pair Merkle verification landed recently as C-05 with a
   real-fixture gate. A hand-rolled accumulator parser is exactly where to look
   next; it is the input to the circuit breaker, which is TEE-enforced only
   (U-01).
5. **Client-side DCAP verification.** `packages/sdk/src/tee/verify-core.ts` and
   the RTMR3 event-log replay were not reviewed. The enclave side of the
   `report_data` binding was confirmed (§2.4), but not that the client actually
   enforces the measurement allowlist — which is what makes S-08's "compromised
   TEE" require breaking TDX rather than merely running modified code.
6. **`settle/worker.rs` (1,810 lines).** Traced only far enough to establish
   the S-02/S-03 composition. The full reconciliation logic, ALT pool
   recycling, and crash recovery from the durable marker queue were not
   audited. **Partial-batch failure interleaved with a CVM restart is the
   highest-risk untested path in the codebase.**
7. **Whether the `enabled` kill switch has teeth mid-batch.**
   `verify_match_batch` checks `market.enabled` (`:100`), but
   `tee_forced_settle_batched` reads no `MarketConfig` at all. A market
   disabled during the ~300-slot marker window still settles its in-flight
   batches. This is probably intentional — in-flight matches should complete —
   but it is not documented as a decision anywhere I found, and it determines
   what the kill switch actually promises to a regulator or counterparty.
8. **Third-party primitives.** Poseidon parameter security, arkworks,
   `light-poseidon` / `solana-poseidon` equivalence beyond the existing parity
   tests, Solana's `alt_bn128` syscalls, `dcap-qvl`, and the dependency supply
   chain were treated as external assumptions, not independently cryptanalysed.
9. **No fresh measurements.** No SBF build, litesvm CU trace, or serialized
   production Tx A/Tx D size measurement was run in this pass. PF-01, PF-02,
   and PF-03 have clear directional savings, but exact headroom should be
   re-measured after any change.
10. **Accepted fairness boundary.** The absence of trader-limit, uniform-price,
    and oracle-band constraints is documented as F-11 / TEE-trusted and is not
    re-reported. S-08 shows the same boundary currently extends to *which
    order* a note's collateral answers for; the team should decide whether that
    extension is acceptable and write it down either way.

---

## 6. Suggested remediation order

1. **S-01 first, and treat it as release-blocking.** It is the only finding
   here that loses user funds to an unprivileged attacker. Until it ships,
   consider whether withdrawals should be routed through a trusted relayer path
   that does not broadcast the proof to a third-party RPC — a partial,
   operational mitigation, not a fix.
2. **S-02 + S-03 together.** They compose into the freeze DoS. S-03(A) is a
   pure-SDK change and can land within a day; S-02(A) needs no ceremony and no
   vault redeploy. This pair gives the largest availability improvement for the
   least risk.
3. **S-04 and S-05** — small, self-contained on-chain changes. Batch them into
   one devnet redeploy with PF-01 and PF-02.
4. **PF-02 then PF-01** — free CU, one-line and one-file respectively, and they
   ride the same redeploy as step 3.
5. **S-06, S-07, S-09, S-10, S-11(A)** — hygiene and narrow replay/privacy
   fixes, no ceremony. S-07 and S-10 touch the same map and should be one
   change.
6. **Circuit release: S-01 + S-08(B) + S-11(B) + PF-03**, scoped with the
   external circuit auditors and sequenced with the phase-2 MPC. Pay the
   artifact regeneration, the N=16 fixture rebuild, and the mandatory tree
   reset **once**.
7. **S-12 doc corrections** alongside whichever change touches the relevant
   subsystem — §8 steps 5/6 with the circuit release, §6 with any root-ring
   work.
8. **Commission the deferred passes in §5**, in this order: `api/auth.rs`
   (gates S-02), `settle/worker.rs` crash recovery, then `oracle/*`.
