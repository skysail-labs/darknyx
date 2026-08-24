# Privacy architecture Phase 0 evidence and decision record

**Date:** 2026-08-25

**Branch:** `privacy/coherence-measurements`

**Scope:** PA-01 through PA-12 design validation; no production circuit or
protocol change

**Result:** Phase 0 complete. The legacy fee and merge lineage leaks reproduce,
their replacements are frozen, and PA-08/09/10 are decided.

This report is the durable output of Phase 0 in
[`remediation-plan.md`](remediation-plan.md).
It records the experiment, not a production implementation. The one-off Rust
benchmark/PoC was removed after its output was captured; no benchmark circuit,
feature gate, or executable remains in the repository.

---

## 1. Conclusions

1. **PA-01 is practical, not merely theoretical.** On an Apple M3, the legacy
   fee construction searched 60,000 candidates in 5.331 seconds on one core and
   recovered a planted 37,037-unit fee in 3.236 seconds. Eight workers searched
   three million candidates in 55.673 seconds. Public deposit values therefore
   make many first-trade fee outputs cheaply linkable to their input leaves.
2. **PA-02 reproduces exactly.** Given the two candidate public input
   commitments for a K=2 merge, the legacy formula reconstructed the merge
   output inner and its later public use tag byte-for-byte. The v2 formula needs
   the private input inners and cannot be evaluated from those commitments.
3. **Fee recovery belongs in Tx B, not Tx D.** A fixed encrypted N=16 bundle
   adds 280 bytes to the proof-verification transaction and leaves the already
   tight per-match settlement transaction unchanged. Exact legacy serialization
   accounting projects 931 bytes with priority-fee instructions, leaving 301
   bytes below Solana's 1,232-byte packet limit.
4. **The fee epoch key is protocol custody, not TEE-generated identity.** Its
   Poseidon binding is governed and proof-checked. A separately derived AEAD
   subkey encrypts amount recovery data. Epoch keys are backed up and retained
   until every fee note in that epoch is spent or recovered.
5. **The owner credential becomes one secret.** `r_owner` and the spending key
   currently come from the same seed and keystore, so `r_owner` is not an
   independent compromise barrier.
6. **Deposit inners stop repeating owner.** The commitment already binds owner;
   the deposit inner needs only the public recovery nonce and private
   seed-derived note secret under a fresh domain.
7. **The unused BN254 compliance-viewing hierarchy is removed/deferred.** The
   live X25519 fill-recovery key is a separate construction and remains.
8. **Replay-marker payloads and two lock fields have no authorization reader.**
   Their account existence or PDA seeds are load-bearing; the duplicated data
   is not. Mint, order ID, expiry, and lock bump remain live.

These decisions do not mark any finding code-complete. PA-01 and PA-02 are only
`Validated` until the Phase 3 cutover, proof/artifact parity, devnet, and CVM
negative-linkability evidence exist.

---

## 2. Reproduction environment

| Item | Value |
|---|---|
| Host | MacBook Air `Mac15,12` |
| CPU | Apple M3, 8 cores (4 performance + 4 efficiency) |
| Memory | 16 GB |
| OS/architecture | Darwin arm64 |
| Build | Rust `--release` |
| Hash | Repository BN254 Poseidon implementation from `darkpool-crypto` |
| Parallel leg | 8 worker threads |

The vectors use synthetic fixed inputs and contain no user, deployment, or
wallet secrets. Timings are host-specific. They establish attack feasibility;
they are not a cross-machine performance promise.

The temporary harness performed the following operations:

- constructed a legacy input note and use tag;
- constructed its legacy quote-fee note;
- searched fee amounts from zero through the public fee ceiling until the
  public fee commitment matched;
- measured serial 60,000, 300,000, and 3,000,000-candidate searches;
- measured an 8-worker 3,000,000-candidate search;
- reconstructed a legacy K=2 merge output from candidate public commitments;
- computed candidate v2 fee, merge, owner, deposit-inner, and match-config
  vectors.

---

## 3. PA-01 fee-lineage PoC

### 3.1 Legacy formula and attack

```text
fee_inner = Poseidon3(25, input_commitment, role)
fee_C     = Poseidon6(2, mint_lo, mint_hi, fee_amount,
                         protocol_owner, fee_inner)
```

For a known public deposit amount `A` and fee rate `r`, the attacker searches:

```text
0 <= candidate_fee <= floor(A * r / 10_000)
```

For each candidate it computes the public fee commitment and compares 32
bytes. A match reveals the input leaf, role, and exact fee. This is a bounded
dictionary, not a generic Poseidon preimage attack.

### 3.2 Fixed legacy vector

All byte strings are canonical BN254 field elements encoded big-endian.

```text
legacy_input_commitment =
  1a9a2f4933dc63e78c4bd5f56fbe30b72698372adf29bffb0cc418676be28da5
legacy_input_use_tag =
  157cbe7ea627c4014c191fdc0c893a046a3c5ee8d4c1c5c19c233d2a0ef9029c
legacy_fee_inner_quote =
  07b19e6a75244672be338d8b5e0b00325ace758a26e29e3107c0f26eb452a64d
legacy_fee_amount = 37037
legacy_fee_commitment =
  2559f703a208239312ac02390da1cc5e1c6dc01ff64e5c8e39c045ab749afc14
```

The serial attack recovered `37037` in 3,236 ms.

### 3.3 Measured search rates

| Search space | Mode | Wall time | Throughput |
|---:|---|---:|---:|
| 60,000 | serial | 5,331 ms | 11,253.13 hashes/s |
| 300,000 | serial | 26,467 ms | 11,334.50 hashes/s |
| 3,000,000 | serial | 263,661 ms | 11,378.24 hashes/s |
| 3,000,000 | 8 workers | 55,673 ms | 53,885.32 hashes/s |

### 3.4 Representative 30-bps ceilings

The following rows use the measured full-range rates, not the planted
early-hit time.

| Public amount | Atomic units | Max candidate fee | Serial estimate | 8-worker estimate |
|---|---:|---:|---:|---:|
| 20 USDC (6 decimals) | 20,000,000 | 60,000 | 5.3 s | 1.1 s |
| 0.1 SOL (9 decimals) | 100,000,000 | 300,000 | 26.5 s | 5.6 s |
| 1 SOL | 1,000,000,000 | 3,000,000 | 4 min 24 s | 55.7 s |
| 20 SOL | 20,000,000,000 | 60,000,000 | 87.9 min | 18.6 min |

Faster desktop silicon, rented CPU cores, batching, SIMD, or GPU work can only
improve these attack times. The smallest common deposits are already cheap on
a fanless laptop.

### 3.5 Frozen v2 formula

Phase 3 uses:

```text
fee_key_binding = Poseidon2(35, fee_epoch_key)

fee_inner_v2 = Poseidon4(36,
                         fee_epoch_key,
                         consumed_use_tag,
                         role)
```

The match-config digest binds the key binding and its monotonic epoch. The
MATCH_BATCH circuit privately witnesses the epoch key, verifies the binding
once, and uses it for every active fee output. The consumed use tag is already
proof-bound and public in Tx D. Public inputs remain `[batch_root,
config_digest]`.

The reproducible vector, including every decimal preimage, is
[`phase0-vectors.json`](phase0-vectors.json):

```text
fee_key_binding_v1 =
  0dea674cc22c4550b60604faaa62edd0ce4fe22ca4b38ebe24506cc9795faa19
fee_inner_v2 =
  25b0e3d61c48456c00303a06d9dcea509389561a8e9f379cb694fec042a769e4
```

Without `fee_epoch_key`, a chain observer cannot evaluate a candidate inner
and therefore cannot evaluate a candidate fee commitment. The amount remains a
small integer, but the observer now has a missing high-entropy preimage.

---

## 4. Fee recovery design freeze

The protocol must recover both the fee inner and the fee amount after loss of
the TEE journal and every online opening cache. The chosen design is a fixed,
encrypted per-batch record carried in Tx B, the transaction that verifies the
N=16 proof and creates the batch marker.

### 4.1 Epoch key lifecycle

For every monotonic `fee_key_epoch`:

1. Sample a canonical nonzero BN254 scalar by CSPRNG rejection sampling.
2. Store only `Poseidon2(35, fee_epoch_key)` and the epoch in `VaultConfig`.
3. Store the secret in the protocol's governed secret backup and inject it into
   the CVM only through encrypted deployment configuration.
4. Verify the binding at strict boot before enabling matching.
5. Rotate only after drain/pause, finalized governance update, new image/env
   confirmation, and resume.
6. Retain every old key until all fee notes in that epoch are recovered or
   spent and the backup has passed a restore drill.

The fee key is not derived by `dstack.get_key()`, generated afresh by a CVM, or
stored only in the settlement journal. It is protocol custody material whose
binding is circuit-enforced.

### 4.2 Fixed recovery plaintext

For N=16, plaintext v1 is exactly 256 bytes:

```text
for slot 0..15:
    base_fee_amount  : u64 little-endian
    quote_fee_amount : u64 little-endian
```

Inactive sides and padded slots are encoded as zero. Slot ordering is the
MATCH_BATCH witness/leaf ordering. The record is fixed length so transaction
shape does not disclose the number of active matches beyond what settlement
already reveals.

### 4.3 Encryption and binding

Use XChaCha20-Poly1305:

- derive a distinct 32-byte AEAD key with HKDF-SHA256 from the canonical epoch
  scalar bytes and info `darknyx/fee-recovery-aead/v1 || epoch`;
- derive the 24-byte nonce from
  `SHA-256("darknyx/fee-recovery-nonce/v1" || batch_root || epoch_be)`;
- bind version, batch root, market account, base mint, quote mint, and epoch as
  AAD; and
- place the 256-byte ciphertext plus 16-byte Poly1305 tag in Tx B instruction
  data, together with an explicit `u64` epoch.

The encrypted extension is therefore 280 bytes: 8-byte epoch plus 272-byte
ciphertext. The Poseidon fee key is not directly reused as an AEAD key.

### 4.4 Tx B authorization

Today anyone can relay `verify_match_batch`. That property has no production
consumer: the TEE constructs and sends Tx B. If arbitrary payers can alter the
new ciphertext, an attacker can front-run the real Tx B with a valid proof and
garbage recovery bytes, create the marker, and suppress the authentic record.

Phase 3 therefore requires the Tx B payer to be one of the finalized authorized
TEE keys. Its Solana transaction signature authenticates the recovery bytes.
Copying an already signed transaction only reproduces the same signature and
payload. This intentionally retires unused permissionless proof relaying.

Binding only a ciphertext hash into the Groth16 public inputs was rejected: it
would increase circuit/public-input surface without proving encryption
correctness. The authorized producer is already trusted for availability of
protocol-owned fee recovery; the circuit continues to enforce the user-safety
properties—conservation, exact fees, outputs, and key binding.

### 4.5 Recovery procedure

After online-state loss, the fee collector:

1. scans finalized Tx B instructions from an archival RPC;
2. reads the explicit epoch and selects the backed-up epoch key;
3. verifies/decrypts the fixed bundle;
4. pairs slot amounts with confirmed Tx D fee commitments for that batch;
5. derives each fee inner from `(epoch_key, consumed_use_tag, role)`;
6. recomputes the note commitment using the governed protocol owner and mint;
7. retains only entries whose recomputed commitment equals the finalized Tx D;
8. reconstructs openings and later merge/spend state from chain.

Rejected or never-landed Tx Ds therefore do not create phantom fee openings.
A missing key, missing archival transaction, invalid AEAD tag, epoch mismatch,
or commitment mismatch is a loud unresolved recovery error—not a zero amount or
silently discarded note.

### 4.6 Transaction-size accounting

The legacy serialized Tx B with compute-limit and nonzero priority-fee
instructions is exactly 651 bytes by Solana legacy-message byte accounting:

| Component | Bytes |
|---|---:|
| Signature shortvec + one signature | 65 |
| Message header + account shortvec | 4 |
| Seven unique account keys | 224 |
| Recent blockhash + instruction shortvec | 33 |
| Compute-unit-limit instruction | 8 |
| Compute-unit-price instruction | 12 |
| `verify_match_batch` instruction (296-byte data) | 305 |
| **Current total** | **651** |

The 280-byte recovery extension does not cross a compact-length boundary, so
the projected transaction is exactly 931 bytes, with 301 bytes headroom under
1,232. With a zero priority fee it is 919 bytes with 313 bytes headroom.

An attempted serializer-backed confirmation could not link because the shared
development volume had only about 118 MiB free and the Rust linker returned
`No space left on device`. No user build cache was deleted without permission.
Phase 3 must add a committed serializer assertion for the final instruction and
record the real value; the exact protocol layout may still move before then.

### 4.7 Failure domains

| Failure | Recovery behavior |
|---|---|
| Journal lost, CVM intact or replaced | scan finalized Tx B/Tx D and use backed-up epoch key |
| CVM permanently lost | same; the key is protocol-backed-up, not CVM-local |
| Governance rotates key | old epoch remains explicit and old key retained |
| Wrong/stale key deployed | strict boot binding mismatch; trading stays paused |
| Wrong key supplied to proof | proof rejects against governed binding |
| Tx B record corrupt | AEAD/commitment verification fails loudly |
| Tx D partially fails | only finalized matching fee commitments are recovered |
| RPC lacks old transaction history | recovery is blocked; archival RPC retention is an operational mainnet gate |

---

## 5. PA-02 merge-lineage PoC

### 5.1 Legacy formula and result

```text
merge_inner = Poseidon6(26, C0, C1, C2, C3, active_bitmap)
```

The fixed K=2 fixture used two candidate public input leaves and zero padding.
There was one candidate pair. The harness reconstructed the public output use
tag and matched the later tag exactly.

```text
merge_input_commitment_0 =
  13f52d5049005ab83a3a3d13581b9fb7ca473ad74f813857d0a4f3b95cf4d8d5
merge_input_commitment_1 =
  00894a1e3a73fe423b9b72cd1f1308ca438ea18971555d049631b9428f7e81b2
merge_input_use_tag_0 =
  27c1f137632c182812e571dfb5a005659dd5565d5271278c77cd0c24f693e656
merge_input_use_tag_1 =
  2f8a754da7ca91d2550d59588f90a0846f045cd067cfbfd23726dd8136bfd8e1
legacy_merge_inner =
  20fc95a5b0babac413d46e7a9a1411766ff7eaf8464369c475ae9ddd3b81a000
legacy_merge_commitment =
  0788ebc14e987a36c69a4874e1f98c27a0711faf55114d3e0760f0603ef5bf02
legacy_merge_use_tag =
  2def4d9f4f0eb961d0cea78c987aeb348c6024418ba39ac3b0b114b4755f9cfd
matched_later_use_tag = true
```

With a larger candidate set, K=2 work is combinations of candidate leaves and
K=4 is combinations/permutations consistent with the circuit ordering. The
finding does not depend on the search being universally cheap: exact known
inputs make it deterministic, and early-product or known-depositor candidate
sets make it small.

### 5.2 Frozen v2 formula

```text
merge_inner_v2 = Poseidon6(34,
                           inner0,
                           inner1,
                           inner2,
                           inner3,
                           active_bitmap)
```

VALID_MERGE already has every private input inner to recompute its commitment
and use tag. The change substitutes private inners for public commitments at
the same arity and adds no witness or public input.

The reproducible vector uses `(inner0, inner1, inner2, inner3, bitmap) =
(11, 22, 0, 0, 3)`:

```text
merge_inner_v2 =
  29cc149632528880c9b9271d09833b6ee8a12b768b6f32471038f3191c1131f1
```

Public commitments alone are now insufficient to evaluate the first hash.
User recovery already owns the input openings and can derive the output.

---

## 6. PA-08, PA-09, and PA-10 decisions

### 6.1 PA-08: adopt single-secret owner v2

Frozen formula:

```text
owner_v2 = Poseidon2(32, spending_key)
```

`spending_key` and `r_owner` currently derive from the same master seed, are
stored in the same encrypted keystore, and are supplied by the same prover.
They therefore fail together. Removing `r_owner` reduces keystore, witness,
SDK, Rust, TS, and recovery surface without reducing the actual compromise
threshold. The Poseidon commitment remains necessary so the TEE can receive an
owner value without receiving the spend secret.

```text
owner_v2 =
  19a60cc2fc6bb80d7e36a941527f46d25403bc24035835e8d8be6b82119022c1
```

This is a flag-day note-format change and must land only in Phase 3.

### 6.2 PA-09: adopt deposit-inner v2

Frozen formula:

```text
deposit_inner_v2 = Poseidon3(33, public_recovery_nonce, note_secret)
```

The note commitment already binds `owner_v2`. Repeating owner inside the inner
does not add binding. The high-entropy seed-derived `note_secret` remains the
load-bearing observer secret, while the public nonce provides deterministic
seed-plus-chain recovery.

```text
deposit_inner_v2 =
  2a0d7bf65498b8f216e0a66fb57cbbb807f54506c9618990fa4d879e322ae6ad
```

Normal SDK construction samples a canonical random public nonce. An explicit
nonce is restricted to exact retry, deterministic test, and recovery tooling.
The circuit proves the Poseidon relation, not the off-circuit SHAKE KDF;
recoverability remains a canonical-client invariant and must be tested as one.

### 6.3 PA-10: remove/defer BN254 compliance hierarchy

Delete the unwired BN254 master/scoped viewing-key hierarchy along with wallet
registration in Phase 1. It has no ciphertext producer, disclosure endpoint,
revocation model, or product consumer. Retaining it would make auditors review
a key hierarchy that provides no launch feature.

Preserve the independent X25519 viewing-encryption key and its fill-recovery
path. A future compliance product must return as a fresh, end-to-end design
with a data source, recipient policy, revocation semantics, and tests; it must
not revive the old hierarchy merely because its domains were reserved.

---

## 7. Account-field reader inventory

This inventory was produced with repository-wide symbol searches followed by
inspection of every production reader and writer. Tests and decoders are
listed where they encode a compatibility contract.

### 7.1 `DepositedNoteEntry`

| Field | Written | Production reader | Decision |
|---|---|---|---|
| `note_commitment` | not explicitly populated by deposit initialization | none | delete |
| `deposited_slot` | not explicitly populated | none | delete |
| `bump` | not explicitly populated | none; seeds use instruction value/PDA constraints | delete |
| padding | zero initialization | none | delete |

Only PDA existence at seed `DepositedNoteEntry::SEED || commitment` prevents a
duplicate leaf. Preserve an Anchor discriminator-only typed account.

### 7.2 `ConsumedNoteEntry`

| Field | Writers | Production reader | Decision |
|---|---|---|---|
| `note_use_tag` | settle, withdraw, merge | none | delete |
| `match_id` | settle; zero in withdraw/merge | none | delete |
| `consumed_slot` | settle, withdraw, merge | none | delete |
| `bump` | zero/init behavior | none | delete |
| padding | zero initialization | none | delete |

All consume paths authorize by absence/existence of the same PDA seeded with
the use tag. Preserve that exact shared namespace and typed discriminator.

### 7.3 `NoteLock`

| Field | Production use | Decision |
|---|---|---|
| `note_use_tag` | duplicated PDA seed; `release_lock` reads it only to emit event | delete; emit instruction seed argument |
| `locked_by` | written at initial and continuation lock creation; never read | delete |
| `token_mint` | settle market/mint binding and continuation locks | retain |
| `order_id` | settle compares lock to signed payload; emitted/reused | retain |
| `expiry_slot` | settle, withdraw, merge, release, sweeper liveness | retain |
| `bump` | hot settle/close seed derivation | retain |
| padding | layout/alignment only | regenerate after deliberate field order |

The account-layout fixture, SDK decoder, raw `EXPIRY_SLOT_OFFSET`, TEE lock
sweeper, litesvm helpers, and release event are compatibility readers and must
move atomically in Phase 2.

---

## 8. Provisional domain freeze

The machine-readable proposal is
[`domain-registry.proposed.json`](domain-registry.proposed.json).
Its JSON Schema is
[`domain-registry.schema.json`](domain-registry.schema.json).
The companion machine-readable formula vectors are
[`phase0-vectors.json`](phase0-vectors.json).
Phase 0 reserves:

| Domain | Name | Arity | Meaning |
|---:|---|---:|---|
| 32 | `DOMAIN_OWNER_V2` | Poseidon2 | spend-secret owner commitment |
| 33 | `DOMAIN_DEPOSIT_INNER_V2` | Poseidon3 | nonce + note-secret deposit inner |
| 34 | `DOMAIN_MERGE_INNER_V2` | Poseidon6 | private input-inners + bitmap merge inner |
| 35 | `DOMAIN_FEE_KEY_BINDING` | Poseidon2 | governed fee epoch key binding |
| 36 | `DOMAIN_FEE_INNER_V2` | Poseidon4 | fee key + consumed tag + role |
| 37 | `DOMAIN_MATCH_CONFIG_V2` | Poseidon10 | governed match config including fee binding/epoch |

Domain 5 is recorded as a retired historical price-commitment assignment, not
an active free value. Domains 10–14 become retired/reserved after wallet-create
deletion. Domains 20, 21, and 23 remain retired. Old production domains 1, 3,
25, 26, 27, and 28 remain active until the atomic Phase 3 cutover, after which
the registry changes their lifecycle without making their numbers reusable.

The proposed registry is descriptive in Phase 0. Phase 3 makes it authoritative
and adds a CI validator that rejects duplicate assignments, illegal reuse,
arity/meaning drift, and missing Rust/TypeScript/Circom consumers.

The frozen match-config v2 vector is:

```text
match_config_digest_v2 =
  289db71a716aa072a0f66d8d331b4126909d0c06337d89ebd6bc2248926174b7
```

---

## 9. Commands and validation

Successful measurement command:

```sh
cargo run --release -p darkpool-crypto --example privacy-lineage-phase0
```

The temporary example was removed immediately after recording its output.

Repository checks for this documentation-only phase:

```sh
git diff --check
python3 -m json.tool docs/privacy-architecture/domain-registry.proposed.json
python3 -m json.tool docs/privacy-architecture/phase0-vectors.json
```

A temporary serializer test for Tx B was attempted but did not complete because
the shared disk filled during linking. The source was removed; the failure did
not indicate a protocol or test assertion failure. Phase 3 owns the final
serializer-backed size assertion because that phase introduces the real wire
layout.

No devnet, CVM, circuit rebuild, zkey generation, or program deployment is
appropriate for Phase 0. Those gates begin when production formulas change.

---

## 10. Phase 0 exit and next action

Phase 0 acceptance is satisfied:

- PA-01 and PA-02 legacy leaks reproduce with fixed evidence;
- v2 fee, merge, owner, deposit-inner, and config formulas have fixed vectors;
- fee inner and amount recovery has a chain-carried design;
- account-field deletions have a complete reader inventory;
- PA-08, PA-09, and PA-10 have explicit decisions;
- domain allocations and a machine-readable proposal exist; and
- no production circuit, protocol feature gate, or benchmark executable changed.

The next branch is `privacy/remove-wallet-identity` from the latest merged
`main`. It implements Phase 1 only: PA-03, PA-06, PA-10, and the clean-build
part of PA-11. The circuit/wire flag day remains Phase 3.
