# Glossary

> Quick reference for the terms, acronyms, and concepts used
> throughout the Nyx documentation. Sorted alphabetically.

---

## A

**ALT (Address Lookup Table).** A Solana mechanism for compressing
the account list of a versioned transaction. An ALT holds up to
256 addresses; a v0 transaction references them by index (1
byte) instead of by pubkey (32 bytes). Nyx uses a per-batch ALT
to fit `tee_forced_settle_batched` under the 1232-byte
transaction size cap. See
[settlement-pipeline](./settlement-pipeline.md) § Tx C.

**Anchor.** The Rust framework for writing Solana programs.
Provides macros for account validation, instruction
serialization, and PDA derivation. Nyx's vault is Anchor 0.32.

**Anchor discriminator.** The first 8 bytes of every Anchor
instruction's data, computed as `sha256("global:<ix_name>")[..8]`.
Lets the runtime dispatch to the right handler.

**Ark-circom.** A Rust library bridging arkworks (the Rust ZK
ecosystem) and Circom (the ZK circuit DSL). Loads `.wasm` + `.r1cs`
files, generates witnesses, produces Groth16 proofs. PR 4g.4b
wires this into Nyx's in-TEE prover.

**Arkworks.** A family of Rust ZK crates (`ark-bn254`, `ark-ff`,
`ark-groth16`, etc.) that implement BN254 curve operations, field
arithmetic, and the Groth16 proving system.

**Attestation.** Cryptographic proof that a piece of code is
running on specific hardware in a specific state. TDX attestation
chains to Intel's TCB; clients verify it via `dcap-qvl`.

---

## B

**Batch.** One matcher tick's output. Up to N=16 matches packaged
together for batched verification on-chain.

**Batch slot.** The Solana slot at which the matcher tick ran;
copied onto every `MatchPair` in the batch.

**`BatchValidityMarker`.** A PDA the vault allocates after a
successful `verify_match_batch`. Seeded by the batch Merkle root.
1:N — one PDA per batch covering all matches in it. Closed by
`close_batch_validity_marker` after all settles finish.

**Bearer token.** A short-lived JWT issued by the TEE's
`POST /auth/token`. Operational auth (Layer A). Distinct from
the trading-key signature (Layer B).

**Bincode.** Rust's standard serialisation format for Solana
transactions over the wire. Tx wire format = `bincode(Transaction)`.

**BN254.** The pairing-friendly elliptic curve underlying our
Groth16 proofs. Also called `alt_bn128`. Native Solana support
via the `groth16-solana` BPF verifier.

**Borsh.** The "Binary Object Representation Serializer for
Hashing" — used by Anchor for instruction data serialisation and
by `darkpool-matcher` for the matcher's I/O types.

**BPF.** Solana's bytecode format (extended from Linux's BPF).
Solana programs compile to BPF; the on-chain verifier code we
audit is BPF.

---

## C

**Canonical body.** The deterministic byte encoding of an order
intent that the user signs. Distinct from the JSON wire body
(which has fields in any order). See
[api-and-integration](./api-and-integration.md) § Layer B.

**Canonical payload hash.** The deterministic byte encoding of a
`MatchResultPayload` that the TEE signs. Verified on-chain by
`tee_forced_settle_batched`.

**Change note.** A note created by a partial fill that returns
the unfilled residual to the user. If you submit an order for 10
SOL and only 7 fill, you get a 3-SOL change note. Encoded as
`note_e` (buyer) or `note_f` (seller) in the `MatchResultPayload`.

**Circom.** A domain-specific language for ZK circuits, by iden3.
Nyx's circuits are written in Circom 2.x; compiled with snarkjs
into `.wasm` witness calculators and `.r1cs` constraint systems.

**Circuit.** A representation of a computation as a set of
arithmetic constraints. A ZK proof attests that the prover knows
inputs satisfying the constraints.

**Clearing price.** The single price at which all matched orders
in a batch fill. Computed inside the matcher to maximize matched
volume subject to all limit constraints.

**Commitment.** A cryptographic binding: a hash that "commits"
to some plaintext but doesn't reveal it. Note commitments
(`Poseidon7`) and user commitments (`Poseidon2`) are the two
primary commitment uses in Nyx.

**`compose_hash`.** A deterministic hash of the Docker image
running inside the TDX CVM. Registered in `vault_config` via
multisig rotation. Lets clients verify the TEE is running the
expected code.

**Compute unit (CU).** Solana's per-tx computation budget. The
default is 200k CU per tx; you can bump up to ~1.4M with a
compute-budget ix. `verify_match_batch` is the highest-CU ix in
Nyx at ~2.5M (we bump explicitly).

**Conservation.** The invariant that input amounts equal output
amounts: `a_amount == quote_amt + buyer_change + buyer_fee`,
etc. Enforced by the VALID_MATCH_BATCH circuit + pre-flight
constraint validators in the prover.

**`ConsumedNoteEntry`.** A PDA the vault allocates when a note is
consumed by `tee_forced_settle_batched`. Distinct from a
`NullifierEntry` (which comes from VALID_SPEND withdraws).

**CVM (Confidential Virtual Machine).** A VM with memory
encryption and remote attestation. Nyx's matching layer runs in a
TDX CVM operated under Phala Cloud's `dstack` framework.

---

## D

**dcap-qvl.** Intel's open-source library for verifying TDX
quotes (the "DCAP" attestation flow). Clients use it to verify
the TEE's `/attestation` response.

**dstack.** Phala's open-source TEE framework: handles boot
attestation, key derivation, TLS termination via dstack-ingress,
quote generation. Built on TDX; works on Phala Cloud and any
TDX-capable cluster.

**dstack-kms.** The KMS layer in dstack: an MPC quorum that
delivers per-CVM root keys deterministically. Same compose_hash
+ same app_id → same root key. We use it to derive the TEE's
Ed25519 signing key and JWT secret.

---

## E

**Ed25519.** An elliptic-curve signature scheme. Used by Solana
natively (every wallet is Ed25519), and by Nyx for the TEE
signing key and the user trading keys.

**Enclave.** Synonym for "TEE VM" or "CVM" in casual use.
Technically distinct (Intel SGX uses "enclave" for sub-process
trusted regions; TDX uses "VM" for whole-VM trust), but the
practical meaning is the same: code running inside a hardware-
attested isolation boundary.

**Ephemeral Rollup.** A short-lived Solana rollup, like
MagicBlock's PER. Nyx v1 used PER for matching; the TEE v2
migration moves off of PER.

---

## F

**FBA (Frequent-Batch Auction).** The matching algorithm Nyx uses
— orders accumulate, every `BATCH_MS` they cross at a uniform
clearing price. Defends against front-running within a batch.

**Fee-payer.** The Solana account that pays for the tx's
inclusion fee + per-ix rent. Nyx's TEE signing key doubles as
the fee-payer (PR 4g.3 walk-back).

**FIFO (First-In-First-Out).** The matcher's tie-breaker: at any
given price level, earlier orders fill before later orders.

**FOK (Fill-or-Kill).** An order type. Either fills 100% in the
next batch or is cancelled; no partial fills.

**Fr (field element).** A scalar in BN254's prime field. ~254
bits. Every value Poseidon-hashes must fit in Fr.

---

## G

**Groth16.** The ZK proving system Nyx uses. Smallest proof size
(~200 bytes), fastest on-chain verification, mature tooling
(circom + snarkjs).

**`groth16-solana`.** A BPF-friendly Groth16 verifier (Solana
program library). The `vault::verify_match_batch` ix wraps it.

---

## H

**HKDF (HMAC-based Key Derivation Function).** Used in the user
key derivation chain: `HKDF-SHA256(seed, label)` → derived key.

**Hermes.** Pyth's pull-pattern oracle endpoint. The TEE's
oracle sync task fetches signed VAAs from Hermes every 1
second.

---

## I

**IOC (Immediate-Or-Cancel).** An order type. Matches against
the next batch; any unmatched residual is cancelled (not kept
in the book).

**Issuer (in JWT context).** The TEE itself, identified by its
deployed `app_id`. The JWT's `iss` claim binds the token to a
specific TEE instance.

---

## J

**JWT (JSON Web Token).** The bearer-token format used by
Layer A auth. HS256-signed with a TEE-derived secret.

---

## K

**KDF (Key Derivation Function).** A function for deriving new
keys from a seed. Nyx uses HKDF-SHA256 for the user key chain
and dstack's deterministic KDF for the TEE keys.

**`kms` (dstack-kms).** See dstack-kms above.

---

## L

**Layer A / Layer B.** The two-layer auth model. Layer A is the
bearer JWT (operational); Layer B is the trading-key Ed25519
signature (cryptographic). See
[api-and-integration](./api-and-integration.md).

**Leaf hash.** The Poseidon hash bound to a match slot in the
VALID_MATCH_BATCH circuit. Two-stage: `Poseidon12 → Poseidon9`.
The leaf is what gets inserted into the per-batch Merkle tree.

**Light-poseidon.** A pure-Rust Poseidon implementation. We use
it host-side; on-chain we use `solana_poseidon::hashv`. Both
produce byte-identical outputs.

**Limit order.** An order with a `price_limit`. Stays in the
book until matched, cancelled, or expired.

**Litesvm.** A lightweight in-process Solana VM. Used for tests
that need to exercise on-chain code without a real cluster.

**`lock_note`.** The vault instruction that pins a note to a
specific match. See [settlement-pipeline](./settlement-pipeline.md)
§ Tx A.

**Lookup Table.** Synonym for ALT.

---

## M

**Matcher.** The algorithm that takes a snapshot of an order
book + oracle and produces a `RunBatchOutput`. Lives in the
`darkpool-matcher` crate (the single source of truth).

**Match leaf.** Synonym for "leaf hash" in the VALID_MATCH_BATCH
context.

**`MatchPair`.** The Rust type representing one matched
buy/sell pair. Carries note commitments, change notes,
counterparty identities, amounts, fees, batch metadata, and
re-lock instructions.

**`MatchResultPayload`.** The 448-byte canonical encoding of a
`MatchPair` that the TEE signs and submits to
`tee_forced_settle_batched`.

**Merkle tree.** The cryptographic data structure underlying
note custody: depth-20 incremental tree of Poseidon-hashed
leaves. Withdraws prove inclusion against a recent root.

**MPC (Multi-Party Computation).** A cryptographic protocol where
multiple parties jointly compute a function without any party
learning the others' inputs. Used by Renegade for matching;
not used in Nyx (we use a TEE instead).

**MRTD.** The TDX measurement of the boot-time VM image. Part
of the attestation chain; clients verify it matches the
governance-approved `compose_hash`.

**Multisig.** The 3-of-5 governance scheme that controls the
on-chain `vault_config.tee_pubkey`. See
[trust-model](./trust-model.md) § Multisig rotation ceremony.

---

## N

**Note.** Nyx's UTXO. A 32-byte Poseidon commitment encoding
(mint, amount, owner_commit, nonce, blinding). Stored as a
Merkle tree leaf; spent via VALID_SPEND.

**`NoteLock`.** A PDA pinning a note to a specific
`(trading_key, order_id)` for a bounded TTL. Allocated by
`lock_note`; consumed (or expired) by
`tee_forced_settle_batched`.

**Nullifier.** A deterministic 32-byte value derived from the
spending key + note commitment. Allocated as a
`NullifierEntry` PDA on withdraw; reuse prevents
double-spending.

**Nyx-tee.** The single-process Rust daemon running inside the
TDX CVM. Houses the order book, matcher, oracle sync, prover,
and settle scheduler.

**Nyx-tee-loadgen.** The load-generation harness for benchmarking
the TEE.

---

## O

**Order book.** The in-memory data structure inside the TEE
holding all open orders. Multi-indexed: by price (matcher),
by id (cancel), by trader (self-trade prevention), by expiry
(sweep).

**`OracleCache`.** The in-process Pyth price cache populated by
the oracle sync task. Matcher reads on every tick.

**Owner commitment.** `Poseidon2(spending_key, r_owner)`. The
"identity" embedded in every note; binds the note to its
spendable owner.

---

## P

**PDA (Program-Derived Address).** A Solana address derived
deterministically from a program id + a set of seeds. Nyx uses
PDAs for every per-leaf account (NoteLock, NullifierEntry,
WalletEntry, ConsumedNoteEntry, BatchValidityMarker).

**Per-batch ALT.** An ALT created for one batch's settle txs.
Holds the five derivable PDAs (note_lock_a/b/e/f +
batch_validity_marker). See
[settlement-pipeline](./settlement-pipeline.md) § Tx C.

**PER (Permission Group Ephemeral Rollup).** MagicBlock's
ephemeral-rollup product. Nyx v1 used it; TEE v2 migrates away.

**Phala Cloud.** The TDX hosting provider Nyx uses. dstack
framework, per-minute pricing, public attestation endpoint.

**Poseidon.** The hash function used throughout Nyx's
cryptography. BN254-native; SNARK-efficient (~30× cheaper than
SHA-256 in-circuit).

**Pot18.** "PowersOfTau 2^18" — the trusted-setup ceremony
output sized for circuits with up to 262k constraints. Required
for VALID_MATCH_BATCH at N=16.

**Public input.** An input to a ZK proof that's known to both
prover and verifier (vs a private witness, which only the prover
knows). VALID_MATCH_BATCH has one public input: the batch
Merkle root.

**Pyth.** The oracle network providing price feeds. Nyx pulls
Pyth prices via Hermes inside the TEE; the matcher reads
TWAPs for circuit-breaker bounds.

---

## Q

**Quorum.** The threshold for Wormhole guardian signatures. 13 of
19 in the current set.

---

## R

**R1CS.** The standard format for representing arithmetic
circuits as constraint systems. Compiled output of circom.

**Rapidsnark.** An optimized C++ Groth16 prover. ~5-10× faster
than ark-groth16 for the same circuit. Tracked as a future
optimisation if ark-groth16 turns out too slow.

**Recent-roots ring buffer.** The 32-entry on-chain ring buffer
of recent Merkle roots. Withdraws prove inclusion against any
root in the ring.

**RA-TLS.** Remote-Attested TLS — TLS termination where the TLS
certificate is derived from a TEE attestation. dstack-ingress
provides this; clients can verify the cert's TEE binding.

**Replay.** Submitting the same valid operation twice. Defended
against by per-leaf PDA init constraints (see § R in this glossary).

**RPC.** Remote Procedure Call. Nyx uses Solana's JSON-RPC for
on-chain submissions and Pyth's Hermes RPC for oracle pulls.

**RTMR3.** TDX runtime measurement register #3. Contains
hashes of dstack's boot events; verified by the event-log
replay step in attestation.

---

## S

**SDK.** TypeScript SDK at `packages/sdk/`. The client-side
integration surface.

**Self-trade.** A user crossing their own orders. Prevented at
two layers: matcher-level (skip pairs with matching trading
keys) and handler-level (configurable per-account policy).

**Settle.** Synonym for `tee_forced_settle_batched`. The atomic
on-chain transfer that consumes input notes, creates change
notes, and pays out.

**Settlement pipeline.** The five-transaction sequence from
matcher output to on-chain confirmation. See
[settlement-pipeline](./settlement-pipeline.md).

**snarkjs.** The JavaScript Groth16 tooling: circuit compilation,
witness generation, proof generation. The user-side ZK proofs
(VALID_INPUT, VALID_SPEND) currently use snarkjs.

**Solana.** The L1 underlying Nyx. ~400ms slot time, ~2.5s
finality, native Groth16 BPF support via `groth16-solana`.

**Spending key.** The private key that authorizes spending
notes. On-device only; never sent to the TEE.

---

## T

**TCB (Trusted Computing Base).** The minimal set of components
whose correctness the security model depends on. Intel TCB is
the foundation of TDX attestation.

**TDX (Intel Trust Domain Extensions).** Intel's confidential-VM
technology. Encrypts VM memory; provides remote attestation.

**`tee_authority`.** The Anchor `Signer<'info>` field in every
vault instruction that requires TEE authentication. Verified
against `vault_config.tee_pubkey`.

**`tee_forced_settle_batched`.** The vault ix that executes the
atomic settle. See [settlement-pipeline](./settlement-pipeline.md)
§ Tx D.

**TEE (Trusted Execution Environment).** The hardware-attested
isolation boundary inside which the Nyx matching layer runs.
TDX in our case.

**Trading key.** The user's Ed25519 keypair used to sign order
intents. Distinct from the user's Solana wallet (which is also
Ed25519 but serves a different role).

**TWAP.** Time-Weighted Average Price. Pyth's TWAP is what the
matcher's circuit breaker checks against.

**Tx A / B / C / D / E.** The five transactions of the settle
pipeline. See [settlement-pipeline](./settlement-pipeline.md).

---

## U

**User commitment.** `Poseidon2(spending_key, r_owner)`. Embedded
in every note's `owner_commit` field. Registered on-chain via
`create_wallet`.

**UTXO.** Unspent Transaction Output. The custody model Nyx uses
— funds live in commitment-form "notes" instead of an account
balance.

---

## V

**VAA.** Verifiable Action Approval. Wormhole's signed cross-chain
message format. Pyth prices ship as VAAs; the TEE verifies
guardian signatures before accepting prices.

**VALID_INPUT.** A user-generated ZK proof that a note commitment
is correctly formed for declared `(mint, amount)`. Used at
deposit AND lock-note time.

**VALID_MATCH_BATCH.** The TEE-generated batched ZK proof
attesting validity of all N matches in a batch. The single
public input is the batch Merkle root. PR 4g.4 wires the
in-TEE prover.

**VALID_PRICE.** Deprecated in v3.5 (folded into VALID_MATCH_BATCH).
Used to prove the clearing-price commitment matched the
declared price.

**VALID_SPEND.** A user-generated ZK proof for withdraws. Proves
note ownership, generates the nullifier, computes the
change-note commitment.

**VALID_WALLET_CREATE.** A user-generated ZK proof that a
`user_commitment` is correctly formed.

**`vault_config`.** The singleton PDA holding the registered
`tee_pubkey`, the registered `compose_hash`, the multisig admin
addresses, the protocol fee config, and the recent-roots ring
buffer.

**Vault program.** The custody-layer Solana program. Owns the
Merkle tree, nullifier set, and consumed-note set; verifies all
withdraws and settles.

**Verifying key (VK).** The public parameters of a Groth16
circuit. Used by the verifier to check proofs. Nyx's VKs are
baked into the on-chain verifier as Rust constants
(`vk_match_batch_n16.rs` etc.).

**Versioned transaction (v0).** Solana's transaction format that
supports ALTs. Tx D uses v0 + 2 ALTs (the static settle ALT +
the per-batch ALT).

---

## W

**`WalletEntry`.** A PDA the vault allocates on `create_wallet`.
Seeded by the user commitment.

**Wasmer.** The WASM runtime ark-circom uses for witness
generation. ~10MB binary footprint; battle-tested in production
by other ZK projects.

**Witness.** The full assignment of all circuit signals (input +
intermediate). Computed from the circuit's `.wasm` (or `.bin`,
for circom-witnesscalc) given a set of input values.

**Wormhole.** The cross-chain message protocol underlying Pyth's
signed VAAs. 19 guardians, quorum 13.

---

## Z

**ZK (Zero-Knowledge).** A proof that something is true without
revealing why. Nyx's six circuits all generate ZK proofs that
the on-chain verifier accepts.

**zkey.** snarkjs's proving-key format. Loaded by ark-circom (or
rapidsnark) to produce proofs.

---

*Last updated 2026-05-29.*
</content>
