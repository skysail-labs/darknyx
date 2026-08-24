/**
 * Pure-TS instruction builder for the vault program.
 *
 * We do NOT pull the Anchor IDL JSON in at runtime (to keep the SDK thin and
 * avoid shipping the IDL to the browser). Instead, we compute the Anchor
 * discriminator directly (`sha256("global:<ix_name>")[0..8]`) and serialise
 * arguments with Borsh-compatible primitive writes.
 *
 * This matches the Umbra-style pattern: the SDK is responsible for producing
 * `TransactionInstruction`s that the wallet layer signs and sends.
 *
 * Layout for every instruction:
 *   data = [disc (8 bytes)] || borsh(args)
 *
 * For instruction arguments, Borsh emits:
 *   - `u64`              -> 8 bytes LE
 *   - `[u8; N]`          -> N bytes (no length prefix)
 *   - `struct`           -> concatenation of fields in declaration order
 *   - `Pubkey`           -> 32 bytes (same as `[u8; 32]`)
 *
 * Fixed-size byte arrays are emitted inline (no length prefix) — this is the
 * critical difference from `Vec<u8>`, which does carry a 4-byte length.
 */

import {
  PublicKey,
  TransactionInstruction,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
} from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha2";

import {
  VAULT_CONFIG_SEED,
  MARKET_CONFIG_SEED,
  MERKLE_TREE_SEED,
  NOTE_LOCK_SEED,
  CONSUMED_NOTE_SEED,
  DEPOSITED_NOTE_SEED,
  VAULT_TOKEN_SEED,
  OUTSTANDING_MINT_SEED,
  BATCH_VALIDITY_MARKER_SEED,
} from "./seeds.js";

/** On-chain portion of a Groth16 proof — the three curve points. */
export interface Groth16OnChainProof {
  piA: Uint8Array; // 64 bytes
  piB: Uint8Array; // 128 bytes
  piC: Uint8Array; // 64 bytes
}

/** Compute Anchor global instruction discriminator. */
export function anchorDiscriminator(name: string): Uint8Array {
  return sha256(new TextEncoder().encode(`global:${name}`)).slice(0, 8);
}

/** Helper: append bytes into a growing buffer. */
function cat(...buffers: Uint8Array[]): Uint8Array {
  const total = buffers.reduce((s, b) => s + b.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const b of buffers) {
    out.set(b, off);
    off += b.length;
  }
  return out;
}

function u64LE(v: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, true);
  return out;
}

function fixed32(x: Uint8Array): Uint8Array {
  if (x.length !== 32) throw new Error(`expected 32 bytes, got ${x.length}`);
  return x;
}

function fixed64(x: Uint8Array): Uint8Array {
  if (x.length !== 64) throw new Error(`expected 64 bytes, got ${x.length}`);
  return x;
}

function fixed128(x: Uint8Array): Uint8Array {
  if (x.length !== 128) throw new Error(`expected 128 bytes, got ${x.length}`);
  return x;
}

function serializeProof(p: Groth16OnChainProof): Uint8Array {
  return cat(fixed64(p.piA), fixed128(p.piB), fixed64(p.piC));
}

// ============================================================================
// PDA derivations (must match `state.rs` SEED constants)
// ============================================================================

export async function vaultConfigPda(
  programId: PublicKey,
): Promise<[PublicKey, number]> {
  return PublicKey.findProgramAddress([VAULT_CONFIG_SEED], programId);
}

/** One market per ordered base/quote mint pair. */
export async function marketConfigPda(
  programId: PublicKey,
  baseMint: PublicKey,
  quoteMint: PublicKey,
): Promise<[PublicKey, number]> {
  return PublicKey.findProgramAddress(
    [MARKET_CONFIG_SEED, baseMint.toBytes(), quoteMint.toBytes()],
    programId,
  );
}

/** Per-shard `MerkleTree` PDA. Seed `[b"merkle_tree", &[treeId]]`. */
export async function merkleTreePda(
  programId: PublicKey,
  treeId: number,
): Promise<[PublicKey, number]> {
  return PublicKey.findProgramAddress(
    [MERKLE_TREE_SEED, new Uint8Array([treeId & 0xff])],
    programId,
  );
}

/**
 * The addresses the STATIC settle ALT must hold, in order — mirrors the Rust
 * `darknyx_tee::settle::settle_batched::static_alt_addresses(num_trees)`:
 * `[vault_config, instructions_sysvar, system_program, merkle_tree(0..K-1)]`.
 * Used by `devnet-setup` to build the ALT the CVM settle worker references.
 */
export async function staticSettleAltAddresses(
  programId: PublicKey,
  numTrees: number,
): Promise<PublicKey[]> {
  const [vaultConfig] = await vaultConfigPda(programId);
  const out = [
    vaultConfig,
    SYSVAR_INSTRUCTIONS_PUBKEY,
    SystemProgram.programId,
  ];
  for (let treeId = 0; treeId < Math.max(1, numTrees); treeId++) {
    out.push((await merkleTreePda(programId, treeId))[0]);
  }
  return out;
}

/**
 * A lock is keyed on the note-use TAG, not the commitment — the tag is what
 * `lock_note` takes and what VALID_INPUT publishes. Passing a commitment here
 * compiles (both are `Uint8Array`) and derives a real-looking address that no
 * instruction will ever write, so the failure surfaces on-chain as
 * `AccountNotFound`. See `utxo/note-use.ts`.
 */
export async function noteLockPda(
  programId: PublicKey,
  noteUseTag: Uint8Array,
): Promise<[PublicKey, number]> {
  return PublicKey.findProgramAddress(
    [NOTE_LOCK_SEED, fixed32(noteUseTag)],
    programId,
  );
}

/**
 * S-05 deposit-once guard PDA — the one guard that stays COMMITMENT-keyed.
 * It guards leaf CREATION, and the leaf is the commitment; a deposit has no
 * tag to key on because the depositor's inner hash is private at that point.
 */
export async function depositedNotePda(
  programId: PublicKey,
  noteCommitment: Uint8Array,
): Promise<[PublicKey, number]> {
  return PublicKey.findProgramAddress(
    [DEPOSITED_NOTE_SEED, fixed32(noteCommitment)],
    programId,
  );
}

/** Consume-once guard, shared by withdraw / settle / merge — tag-keyed. */
export async function consumedNotePda(
  programId: PublicKey,
  noteUseTag: Uint8Array,
): Promise<[PublicKey, number]> {
  return PublicKey.findProgramAddress(
    [CONSUMED_NOTE_SEED, fixed32(noteUseTag)],
    programId,
  );
}

export async function vaultTokenAccountPda(
  programId: PublicKey,
  mint: PublicKey,
): Promise<[PublicKey, number]> {
  return PublicKey.findProgramAddress(
    [VAULT_TOKEN_SEED, mint.toBytes()],
    programId,
  );
}

export async function outstandingMintPda(
  programId: PublicKey,
  mint: PublicKey,
): Promise<[PublicKey, number]> {
  return PublicKey.findProgramAddress(
    [OUTSTANDING_MINT_SEED, mint.toBytes()],
    programId,
  );
}

// Batch validity is ONE marker per batch, keyed by the batch's Merkle root.
// There is no per-match marker PDA, no per-match binding hash, and no
// per-match verify ix. `seeds.ts` carries the same note, and both exist so a
// reader does not go hunting for a per-match PDA that nothing derives.

/**
 * BatchValidityMarker PDA. Seed is the Merkle root committed by
 * the verify_match_batch proof's first public input. Created by
 * `verify_match_batch` and consumed by `tee_forced_settle_batched`.
 */
export async function batchValidityMarkerPda(
  programId: PublicKey,
  merkleRoot: Uint8Array,
): Promise<[PublicKey, number]> {
  if (merkleRoot.length !== 32) throw new Error("merkleRoot must be 32 bytes");
  return PublicKey.findProgramAddress(
    [BATCH_VALIDITY_MARKER_SEED, merkleRoot],
    programId,
  );
}

// ============================================================================
// Instruction builders
// ============================================================================

export interface BuildInitializeParams {
  programId: PublicKey;
  /** Upgrade authority on mainnet; plain initializer/payer on devnet-admin. */
  initializer: PublicKey;
  /** Stored as `VaultConfig.admin`; may differ from the upgrade authority. */
  operationsAdmin: PublicKey;
  /** Exactly one non-default, unique signer per Merkle-tree shard. */
  teePubkeys: PublicKey[];
  rootKey: PublicKey;
  /** Number of Merkle-tree shards (1..=16). Each shard is then created with
   *  its own `initialize_tree(treeId)` call. */
  numTrees: number;
  /** Mainnet only: this program's upgradeable-loader ProgramData account. */
  programData?: PublicKey;
}

export async function buildInitializeInstruction(
  p: BuildInitializeParams,
): Promise<TransactionInstruction> {
  if (p.numTrees < 1 || p.numTrees > 16) {
    throw new Error(`numTrees must be in 1..=16, got ${p.numTrees}`);
  }
  if (p.teePubkeys.length !== p.numTrees) {
    throw new Error(
      `teePubkeys length ${p.teePubkeys.length} must equal numTrees ${p.numTrees}`,
    );
  }
  if (p.operationsAdmin.equals(PublicKey.default)) {
    throw new Error("operationsAdmin must not be the default public key");
  }
  if (p.rootKey.equals(PublicKey.default)) {
    throw new Error("rootKey must not be the default public key");
  }
  if (p.operationsAdmin.equals(p.rootKey)) {
    throw new Error("operationsAdmin must be distinct from rootKey");
  }
  if (p.programData && p.operationsAdmin.equals(p.initializer)) {
    throw new Error(
      "mainnet operationsAdmin must be distinct from the upgrade authority",
    );
  }
  const teeSet = new Set(p.teePubkeys.map((key) => key.toBase58()));
  if (
    teeSet.size !== p.teePubkeys.length ||
    p.teePubkeys.some(
      (key) =>
        key.equals(PublicKey.default) ||
        key.equals(p.operationsAdmin) ||
        key.equals(p.rootKey),
    )
  ) {
    throw new Error(
      "teePubkeys must be non-default, unique, and distinct from governance keys",
    );
  }
  const [vaultPda] = await vaultConfigPda(p.programId);
  const lenLE = new Uint8Array(4);
  new DataView(lenLE.buffer).setUint32(0, p.teePubkeys.length, true);
  const data = cat(
    anchorDiscriminator("initialize"),
    p.operationsAdmin.toBytes(),
    lenLE,
    ...p.teePubkeys.map((key) => key.toBytes()),
    p.rootKey.toBytes(),
    new Uint8Array([p.numTrees & 0xff]),
  );
  const keys = [
    { pubkey: p.initializer, isSigner: true, isWritable: true },
    { pubkey: vaultPda, isSigner: false, isWritable: true },
  ];
  if (p.programData) {
    keys.push(
      { pubkey: p.programId, isSigner: false, isWritable: false },
      { pubkey: p.programData, isSigner: false, isWritable: false },
    );
  }
  keys.push({
    pubkey: SystemProgram.programId,
    isSigner: false,
    isWritable: false,
  });
  return new TransactionInstruction({
    programId: p.programId,
    keys,
    data,
  });
}

export interface BuildInitializeMarketParams {
  programId: PublicKey;
  admin: PublicKey;
  baseMint: PublicKey;
  quoteMint: PublicKey;
  priceScale: bigint;
  tickSize: bigint;
  minOrderSize: bigint;
  circuitBreakerBps: bigint;
}

function validateMarketParams(p: {
  priceScale: bigint;
  tickSize: bigint;
  minOrderSize: bigint;
  circuitBreakerBps: bigint;
}): void {
  if (
    p.priceScale <= 0n ||
    p.tickSize <= 0n ||
    p.minOrderSize <= 0n ||
    p.circuitBreakerBps <= 0n ||
    p.circuitBreakerBps > 10_000n
  ) {
    throw new Error("invalid market parameters");
  }
}

export async function buildInitializeMarketInstruction(
  p: BuildInitializeMarketParams,
): Promise<TransactionInstruction> {
  validateMarketParams(p);
  if (p.baseMint.equals(p.quoteMint)) {
    throw new Error("baseMint and quoteMint must be distinct");
  }
  const [vaultPda] = await vaultConfigPda(p.programId);
  const [marketPda] = await marketConfigPda(
    p.programId,
    p.baseMint,
    p.quoteMint,
  );
  const data = cat(
    anchorDiscriminator("initialize_market"),
    u64LE(p.priceScale),
    u64LE(p.tickSize),
    u64LE(p.minOrderSize),
    u64LE(p.circuitBreakerBps),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.admin, isSigner: true, isWritable: true },
      { pubkey: vaultPda, isSigner: false, isWritable: false },
      { pubkey: p.baseMint, isSigner: false, isWritable: false },
      { pubkey: p.quoteMint, isSigner: false, isWritable: false },
      { pubkey: marketPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

export interface BuildUpdateMarketConfigParams {
  programId: PublicKey;
  admin: PublicKey;
  baseMint: PublicKey;
  quoteMint: PublicKey;
  enabled: boolean;
  priceScale: bigint;
  tickSize: bigint;
  minOrderSize: bigint;
  circuitBreakerBps: bigint;
}

export async function buildUpdateMarketConfigInstruction(
  p: BuildUpdateMarketConfigParams,
): Promise<TransactionInstruction> {
  validateMarketParams(p);
  const [vaultPda] = await vaultConfigPda(p.programId);
  const [marketPda] = await marketConfigPda(
    p.programId,
    p.baseMint,
    p.quoteMint,
  );
  const data = cat(
    anchorDiscriminator("update_market_config"),
    new Uint8Array([p.enabled ? 1 : 0]),
    u64LE(p.priceScale),
    u64LE(p.tickSize),
    u64LE(p.minOrderSize),
    u64LE(p.circuitBreakerBps),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.admin, isSigner: true, isWritable: false },
      { pubkey: vaultPda, isSigner: false, isWritable: false },
      { pubkey: marketPda, isSigner: false, isWritable: true },
    ],
    data,
  });
}

export interface BuildInitializeTreeParams {
  programId: PublicKey;
  admin: PublicKey;
  /** Shard id to create (0..numTrees-1). */
  treeId: number;
}

/**
 * Create one `MerkleTree` shard account. Mirrors
 * `programs/vault/src/instructions/initialize_tree.rs`.
 *
 *   data = disc(8) || tree_id(1)
 *   accounts: [admin(signer,mut), vault_config(ro), merkle_tree(init,mut), system(ro)]
 */
export async function buildInitializeTreeInstruction(
  p: BuildInitializeTreeParams,
): Promise<TransactionInstruction> {
  const [vaultPda] = await vaultConfigPda(p.programId);
  const [merkleTree] = await merkleTreePda(p.programId, p.treeId);
  const data = cat(
    anchorDiscriminator("initialize_tree"),
    new Uint8Array([p.treeId & 0xff]),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.admin, isSigner: true, isWritable: true },
      { pubkey: vaultPda, isSigner: false, isWritable: false },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

export interface BuildSetProtocolConfigParams {
  programId: PublicKey;
  admin: PublicKey;
  protocolOwnerCommitment: Uint8Array; // 32B Poseidon commitment
  feeRateBps: number; // 0..=10_000
}

function u16LE(v: number): Uint8Array {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, v, true);
  return out;
}

export async function buildSetProtocolConfigInstruction(
  p: BuildSetProtocolConfigParams,
): Promise<TransactionInstruction> {
  if (p.feeRateBps < 0 || p.feeRateBps > 10_000) {
    throw new Error(`feeRateBps out of range: ${p.feeRateBps}`);
  }
  const [vaultPda] = await vaultConfigPda(p.programId);
  // Arg order MUST match the on-chain handler.
  const data = cat(
    anchorDiscriminator("set_protocol_config"),
    fixed32(p.protocolOwnerCommitment),
    u16LE(p.feeRateBps),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.admin, isSigner: true, isWritable: false },
      { pubkey: vaultPda, isSigner: false, isWritable: true },
    ],
    data,
  });
}

export interface BuildSetTeePubkeyParams {
  programId: PublicKey;
  admin: PublicKey;
  /** The FULL authorized TEE signer set (the K shard fee-payer/authority keys).
   *  Replaces `vault_config.tee_pubkeys` wholesale. 1..=16 keys. */
  teePubkeys: PublicKey[];
  numTrees: number;
}

/**
 * Install the full authorized TEE signer set (`Vec<Pubkey>`). Admin-only. Used
 * to register a freshly-deployed CVM's K dstack-derived shard signers so their
 * settle txs are accepted. Mirrors `set_tee_pubkey(keys: Vec<Pubkey>)`.
 *
 *   data = disc(8) || keys(Vec<Pubkey>: u32 LE len ++ len*32)
 */
export async function buildSetTeePubkeyInstruction(
  p: BuildSetTeePubkeyParams,
): Promise<TransactionInstruction> {
  if (
    p.teePubkeys.length < 1 ||
    p.teePubkeys.length > 16 ||
    p.teePubkeys.length !== p.numTrees
  ) {
    throw new Error(
      `teePubkeys must have exactly numTrees entries (1..=16), got ${p.teePubkeys.length} for ${p.numTrees} trees`,
    );
  }
  const teeSet = new Set(p.teePubkeys.map((key) => key.toBase58()));
  if (
    teeSet.size !== p.teePubkeys.length ||
    p.teePubkeys.some((key) => key.equals(PublicKey.default))
  ) {
    throw new Error("teePubkeys must be non-default and unique");
  }
  const [vaultPda] = await vaultConfigPda(p.programId);
  const lenLE = new Uint8Array(4);
  new DataView(lenLE.buffer).setUint32(0, p.teePubkeys.length, true);
  const data = cat(
    anchorDiscriminator("set_tee_pubkey"),
    lenLE,
    ...p.teePubkeys.map((k) => k.toBytes()),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.admin, isSigner: true, isWritable: false },
      { pubkey: vaultPda, isSigner: false, isWritable: true },
    ],
    data,
  });
}

export interface BuildResetMerkleTreeParams {
  programId: PublicKey;
  admin: PublicKey;
  /** Which shard to reset. Other shards are untouched. */
  treeId: number;
}

/**
 * DEV-NET-ONLY: reset shard `treeId`'s Merkle tree to empty. Admin must sign.
 *
 *   data = disc(8) || tree_id(1)
 *   accounts: [admin(signer), vault_config(ro), merkle_tree(mut)]
 */
export async function buildResetMerkleTreeInstruction(
  p: BuildResetMerkleTreeParams,
): Promise<TransactionInstruction> {
  const [vaultPda] = await vaultConfigPda(p.programId);
  const [merkleTree] = await merkleTreePda(p.programId, p.treeId);
  const data = cat(
    anchorDiscriminator("reset_merkle_tree"),
    new Uint8Array([p.treeId & 0xff]),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.admin, isSigner: true, isWritable: false },
      { pubkey: vaultPda, isSigner: false, isWritable: false },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
    ],
    data,
  });
}

export interface BuildRotateRootKeyParams {
  programId: PublicKey;
  currentRootKey: PublicKey;
  newRootKey: PublicKey;
}

export async function buildRotateRootKeyInstruction(
  p: BuildRotateRootKeyParams,
): Promise<TransactionInstruction> {
  if (
    p.newRootKey.equals(PublicKey.default) ||
    p.newRootKey.equals(p.currentRootKey)
  ) {
    throw new Error("newRootKey must be non-default and different");
  }
  const [vaultPda] = await vaultConfigPda(p.programId);
  const data = cat(
    anchorDiscriminator("rotate_root_key"),
    p.newRootKey.toBytes(),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.currentRootKey, isSigner: true, isWritable: false },
      { pubkey: vaultPda, isSigner: false, isWritable: true },
    ],
    data,
  });
}

export interface BuildDepositParams {
  programId: PublicKey;
  /** Which Merkle-tree shard the deposit's note commitment appends to. */
  treeId: number;
  depositor: PublicKey;
  tokenMint: PublicKey;
  depositorTokenAccount: PublicKey;
  tokenProgramId: PublicKey;
  amount: bigint;
  noteCommitment: Uint8Array;
  /** Public pseudorandom Fr used to recover the hidden deposit inner hash. */
  recoveryNonce: Uint8Array;
  proof: Groth16OnChainProof;
}

export async function buildDepositInstruction(
  p: BuildDepositParams,
): Promise<TransactionInstruction> {
  const [vaultPda] = await vaultConfigPda(p.programId);
  const [merkleTree] = await merkleTreePda(p.programId, p.treeId);
  const [vaultTokenAcct] = await vaultTokenAccountPda(p.programId, p.tokenMint);
  const [outstandingMint] = await outstandingMintPda(p.programId, p.tokenMint);
  const [depositedNote] = await depositedNotePda(p.programId, p.noteCommitment);

  const data = cat(
    anchorDiscriminator("deposit"),
    new Uint8Array([p.treeId & 0xff]),
    u64LE(p.amount),
    fixed32(p.noteCommitment),
    fixed32(p.recoveryNonce),
    serializeProof(p.proof),
  );

  // Sysvar rent pubkey = SysvarRent111111111111111111111111111111111
  const rentSysvar = new PublicKey(
    "SysvarRent111111111111111111111111111111111",
  );

  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.depositor, isSigner: true, isWritable: true },
      // vault_config is read-only post-sharding (the tree state moved to
      // merkle_tree); the leaf append mutates merkle_tree[treeId].
      { pubkey: vaultPda, isSigner: false, isWritable: false },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: p.tokenMint, isSigner: false, isWritable: false },
      { pubkey: p.depositorTokenAccount, isSigner: false, isWritable: true },
      { pubkey: vaultTokenAcct, isSigner: false, isWritable: true },
      { pubkey: outstandingMint, isSigner: false, isWritable: true },
      // S-05 deposit-once guard — `init`, so writable. Declared after
      // outstanding_mint in the Rust Accounts struct; the order is positional.
      { pubkey: depositedNote, isSigner: false, isWritable: true },
      { pubkey: p.tokenProgramId, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: rentSysvar, isSigner: false, isWritable: false },
    ],
    data,
  });
}

export interface BuildWithdrawParams {
  programId: PublicKey;
  /** Which Merkle-tree shard the spent note lives in (recency check). */
  treeId: number;
  payer: PublicKey;
  tokenMint: PublicKey;
  destinationTokenAccount: PublicKey;
  tokenProgramId: PublicKey;
  /**
   * The note-use tag, which is VALID_SPEND's public output at wire 0 — NOT
   * the commitment. Derive it with `deriveNoteUseTag(commitment, innerHash)`.
   */
  noteUseTag: Uint8Array;
  nullifier: Uint8Array;
  merkleRoot: Uint8Array;
  amount: bigint;
  proof: Groth16OnChainProof;
}

// ---------------------------------------------------------------------------
// lock_note (TEE-signed). Allocates a NoteLock PDA on L1. Used at settle
// time to atomically lock both buyer + seller notes inside the same tx
// that calls `tee_forced_settle`.
// ---------------------------------------------------------------------------

export interface BuildLockNoteParams {
  programId: PublicKey;
  /** Which Merkle-tree shard the input note lives in (its home tree) — the
   *  shard whose recent-roots ring the handler checks `merkleRoot` against. */
  treeId: number;
  /** Must be one of `vault_config.tee_pubkeys`. Pays the rent for the new PDA. */
  teeAuthority: PublicKey;
  /** VALID_INPUT's public input 1. The commitment stays inside the proof. */
  noteUseTag: Uint8Array;
  /** 16-byte order id used for `tee_forced_settle` cross-check. */
  orderId: Uint8Array;
  expirySlot: bigint;
  /**
   * v2: SPL mint of the note being locked. Bound cryptographically to the
   * Merkle leaf by the VALID_INPUT proof — the TEE cannot misrepresent it.
   */
  tokenMint: PublicKey;
  /**
   * v2: the Merkle root the VALID_INPUT proof was generated against. Must be
   * in `vault_config`'s recent-roots ring at lock time (same recency policy
   * as `withdraw`).
   */
  merkleRoot: Uint8Array;
  /** v2: VALID_INPUT Groth16 proof. */
  proof: Groth16OnChainProof;
}

/** Decoded `NoteLock` account (`programs/vault/src/state.rs::NoteLock`). */
export interface NoteLockAccount {
  noteUseTag: Uint8Array;
  tokenMint: PublicKey;
  orderId: Uint8Array;
  /**
   * Slot at and after which the lock is releasable. The on-chain
   * `release_lock` compares with `>=`, so the lock is already releasable AT
   * this slot — settlement must land strictly before it (CS-09).
   */
  expirySlot: bigint;
  lockedBy: PublicKey;
}

/**
 * Decode a `NoteLock` account's data.
 *
 * Layout is hand-mirrored from the Rust struct, like every other decoder in
 * this file (there is no Anchor IDL at runtime):
 *
 *   disc(8) | note_use_tag(32) | token_mint(32) | order_id(16)
 *          | expiry_slot(u64 LE) | locked_by(32) | bump(1) | _padding(7)
 *
 * Returns `null` when the buffer is too short to be a `NoteLock`, so a caller
 * that reads an unexpected account fails closed rather than misreading an
 * offset as an expiry.
 */
export function parseNoteLock(data: Uint8Array): NoteLockAccount | null {
  const LEN = 8 + 32 + 32 + 16 + 8 + 32 + 1 + 7;
  if (data.length < LEN) return null;
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return {
    noteUseTag: data.slice(8, 40),
    tokenMint: new PublicKey(data.slice(40, 72)),
    orderId: data.slice(72, 88),
    expirySlot: dv.getBigUint64(88, true),
    lockedBy: new PublicKey(data.slice(96, 128)),
  };
}

export interface BuildReleaseLockParams {
  programId: PublicKey;
  /**
   * Whoever submits the release. Receives the reclaimed `NoteLock` rent —
   * the on-chain `close = rent_receiver` has no `has_one` binding to the TEE
   * key that created the lock, so this is permissionless by design.
   */
  rentReceiver: PublicKey;
  /** 32-byte note-use tag the lock is seeded on. */
  noteUseTag: Uint8Array;
}

/**
 * Release an EXPIRED `NoteLock`, reclaiming its rent.
 *
 * Audit 2026-07-25 S-03: `release_lock` has existed on-chain since the lock
 * lifecycle landed, but had **no builder in any shipped component** — no SDK
 * helper, no TEE caller, no script, no test. The 2026-07-20 D-01 analysis of
 * the settle-failure freeze concluded the recovery path was "`release_lock` +
 * re-place", which was not implemented anywhere. Meanwhile `withdraw` and
 * `merge` both reject on the mere EXISTENCE of a lock account, expired or
 * not, so a note left locked by any failed settle was unspendable,
 * unmergeable, and unreleasable through every shipped interface — recovery
 * meant hand-assembling an Anchor discriminator.
 *
 * The on-chain handler requires `clock.slot >= lock.expiry_slot` (inclusive at
 * the boundary — CS-09 relies on settlement landing strictly before it), and
 * fails `LockNotExpired` otherwise.
 *
 *   data = disc(8) || note_use_tag(32)
 *
 *   accounts:
 *     [0] rent_receiver (signer, mut — receives the reclaimed rent)
 *     [1] note_lock     (mut, closed)
 */
export async function buildReleaseLockInstruction(
  p: BuildReleaseLockParams,
): Promise<TransactionInstruction> {
  const [noteLock] = await noteLockPda(p.programId, p.noteUseTag);
  const data = cat(anchorDiscriminator("release_lock"), fixed32(p.noteUseTag));
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.rentReceiver, isSigner: true, isWritable: true },
      { pubkey: noteLock, isSigner: false, isWritable: true },
    ],
    data,
  });
}

/**
 * v3 wire format (matches `programs/vault/src/instructions/lock_note.rs`):
 *
 *   data = disc(8) || tree_id(1) || note_use_tag(32) || order_id(16)
 *        || expiry_slot(u64 LE) || token_mint(32)
 *        || merkle_root(32) || pi_a(64) || pi_b(128) || pi_c(64)
 *
 *   accounts:
 *     [0] tee_authority   (signer, mut)
 *     [1] vault_config    (ro — handler reads tee_pubkeys + zsr)
 *     [2] merkle_tree     (ro — the shard whose root ring is checked)
 *     [3] note_lock       (init, mut)
 *     [4] consumed_note   (ro — U-02 must-be-absent consume-once guard)
 *     [5] system_program  (ro)
 */
export async function buildLockNoteInstruction(
  p: BuildLockNoteParams,
): Promise<TransactionInstruction> {
  const [vaultPda] = await vaultConfigPda(p.programId);
  const [merkleTree] = await merkleTreePda(p.programId, p.treeId);
  const [noteLock] = await noteLockPda(p.programId, p.noteUseTag);
  const [consumedNote] = await consumedNotePda(p.programId, p.noteUseTag);
  if (p.orderId.length !== 16) {
    throw new Error(`orderId must be 16 bytes, got ${p.orderId.length}`);
  }
  const data = cat(
    anchorDiscriminator("lock_note"),
    new Uint8Array([p.treeId & 0xff]),
    fixed32(p.noteUseTag),
    new Uint8Array(p.orderId),
    u64LE(p.expirySlot),
    p.tokenMint.toBytes(),
    fixed32(p.merkleRoot),
    serializeProof(p.proof),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.teeAuthority, isSigner: true, isWritable: true },
      { pubkey: vaultPda, isSigner: false, isWritable: false },
      { pubkey: merkleTree, isSigner: false, isWritable: false },
      { pubkey: noteLock, isSigner: false, isWritable: true },
      { pubkey: consumedNote, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

export async function buildWithdrawInstruction(
  p: BuildWithdrawParams,
): Promise<TransactionInstruction> {
  const [vaultPda] = await vaultConfigPda(p.programId);
  const [merkleTree] = await merkleTreePda(p.programId, p.treeId);
  const [vaultTokenAcct] = await vaultTokenAccountPda(p.programId, p.tokenMint);
  const [consumedNote] = await consumedNotePda(p.programId, p.noteUseTag);
  const [noteLock] = await noteLockPda(p.programId, p.noteUseTag);
  const [outstandingMint] = await outstandingMintPda(p.programId, p.tokenMint);

  const data = cat(
    anchorDiscriminator("withdraw"),
    new Uint8Array([p.treeId & 0xff]),
    fixed32(p.noteUseTag),
    fixed32(p.nullifier),
    fixed32(p.merkleRoot),
    u64LE(p.amount),
    serializeProof(p.proof),
  );

  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.payer, isSigner: true, isWritable: true },
      // vault_config is the SPL token authority (read-only PDA signer);
      // merkle_tree[treeId] is read-only (the recent-roots ring check).
      { pubkey: vaultPda, isSigner: false, isWritable: false },
      { pubkey: merkleTree, isSigner: false, isWritable: false },
      { pubkey: p.tokenMint, isSigner: false, isWritable: false },
      { pubkey: vaultTokenAcct, isSigner: false, isWritable: true },
      { pubkey: p.destinationTokenAccount, isSigner: false, isWritable: true },
      // consumed_note is now `init`'d by withdraw (the tag-keyed
      // consume-once guard shared with TEE settle) → writable.
      { pubkey: consumedNote, isSigner: false, isWritable: true },
      { pubkey: noteLock, isSigner: false, isWritable: false },
      // PF-04: the nullifier-keyed guard was removed — `consumed_note` above
      // is the complete double-spend guard, since `note_use_tag` is a
      // circuit-bound public output of VALID_SPEND.
      { pubkey: outstandingMint, isSigner: false, isWritable: true },
      { pubkey: p.tokenProgramId, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

// ---------------------------------------------------------------------------
// v3 — verify_match_batch. Lands in its own tx before the N (≤ 16)
// tee_forced_settle_batched txs in a batch. One Groth16 binds active slots,
// output construction, scaled pricing, fees, and the governed market. Its
// public Merkle root becomes the BatchValidityMarker PDA's seed. The settle txs that follow each
// supply a Merkle inclusion path against this marker.
// ---------------------------------------------------------------------------

export interface BuildVerifyMatchBatchParams {
  programId: PublicKey;
  /** Anyone can pay rent / submit the proof. Authorization is the proof itself. */
  payer: PublicKey;
  /** Ordered governed market pair bound into public inputs 4..7. */
  baseMint: PublicKey;
  quoteMint: PublicKey;
  /** Merkle root over the N=16 per-slot leaves — public input 1. */
  merkleRoot: Uint8Array;
  proof: Groth16OnChainProof;
}

export async function buildVerifyMatchBatchInstruction(
  p: BuildVerifyMatchBatchParams,
): Promise<TransactionInstruction> {
  if (p.merkleRoot.length !== 32) {
    throw new Error("merkleRoot must be 32 bytes");
  }
  const [marker] = await batchValidityMarkerPda(p.programId, p.merkleRoot);
  const [vaultConfig] = await vaultConfigPda(p.programId);
  const [marketConfig] = await marketConfigPda(
    p.programId,
    p.baseMint,
    p.quoteMint,
  );

  // S-04: no expiry_slot argument. It used to be caller-supplied and bounded
  // only to (slot, slot + 300], which — with an unauthenticated payer and an
  // `init` marker — let an observer replay this proof with a 1-slot TTL and
  // kill every settle in the batch. The program derives the TTL now.
  const data = cat(
    anchorDiscriminator("verify_match_batch"),
    fixed32(p.merkleRoot),
    serializeProof(p.proof),
  );

  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.payer, isSigner: true, isWritable: true },
      { pubkey: vaultConfig, isSigner: false, isWritable: false },
      { pubkey: marketConfig, isSigner: false, isWritable: false },
      { pubkey: marker, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

// ---------------------------------------------------------------------------
// merge — in-pool note consolidation (VALID_MERGE K=2/4). Consumes K input
// notes (their tag-keyed ConsumedNoteEntry PDAs — C-01), appends ONE summed
// output leaf, whose LEAF is a commitment. Inputs are handles, the output is
// an identity: the two namespaces meet here and must not be swapped.
// ---------------------------------------------------------------------------

export interface BuildMergeParams {
  programId: PublicKey;
  /** Which Merkle-tree shard the inputs live in + the merged output appends to. */
  treeId: number;
  payer: PublicKey;
  /**
   * K input note-use TAGS in circuit order — the real tag for active slots,
   * all-zero for dummy pad slots (C-01: these are the VALID_MERGE public
   * outputs the circuit binds; each active one gets a ConsumedNoteEntry).
   *
   * The circuit still derives the output inner from the input COMMITMENTS,
   * but those stay private witnesses; only the tags surface on the wire.
   */
  inputUseTags: Uint8Array[];
  outputCommitment: Uint8Array;
  tokenMint: PublicKey;
  merkleRoot: Uint8Array;
  k: number; // 2 | 4
  proof: Groth16OnChainProof;
}

/**
 * Wire format (matches `programs/vault/src/instructions/merge.rs`):
 *
 *   data = disc(8) || tree_id(1)
 *        || input_use_tags(Vec<[u8;32]>: u32 LE len ++ len*32)
 *        || output_commitment(32) || token_mint(32) || merkle_root(32)
 *        || k(u8) || pi_a(64) || pi_b(128) || pi_c(64)
 *
 *   accounts:
 *     [0] payer          (signer, mut)
 *     [1] vault_config   (ro — provides zero_subtree_roots)
 *     [2] merkle_tree    (mut — inputs' shard + the merged-output append)
 *     [3] system_program (ro)
 *     [4..4+A)   one ConsumedNoteEntry PDA per active input (mut), in order
 *     [4+A..4+2A) the corresponding NoteLock PDAs (ro, must be absent)
 */
export async function buildMergeInstruction(
  p: BuildMergeParams,
): Promise<TransactionInstruction> {
  if ((p.k !== 2 && p.k !== 4) || p.inputUseTags.length !== p.k) {
    throw new Error("merge k must be 2 or 4 and match the tag slot count");
  }
  const [vaultPda] = await vaultConfigPda(p.programId);
  const [merkleTree] = await merkleTreePda(p.programId, p.treeId);
  const isZero = (b: Uint8Array) => b.every((x) => x === 0);
  const activeTags = p.inputUseTags.filter((t) => !isZero(t));
  if (activeTags.length === 0) {
    throw new Error("merge must contain at least one active input");
  }
  const consumedPdas = await Promise.all(
    activeTags.map(async (t) => (await consumedNotePda(p.programId, t))[0]),
  );
  const noteLockPdas = await Promise.all(
    activeTags.map(async (t) => (await noteLockPda(p.programId, t))[0]),
  );

  const lenLE = new Uint8Array(4);
  new DataView(lenLE.buffer).setUint32(0, p.inputUseTags.length, true);
  const tagsBytes = cat(lenLE, ...p.inputUseTags.map((t) => fixed32(t)));

  const data = cat(
    anchorDiscriminator("merge"),
    new Uint8Array([p.treeId & 0xff]),
    tagsBytes,
    fixed32(p.outputCommitment),
    p.tokenMint.toBytes(),
    fixed32(p.merkleRoot),
    new Uint8Array([p.k & 0xff]),
    serializeProof(p.proof),
  );

  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.payer, isSigner: true, isWritable: true },
      { pubkey: vaultPda, isSigner: false, isWritable: false },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ...consumedPdas.map((pubkey) => ({
        pubkey,
        isSigner: false,
        isWritable: true,
      })),
      ...noteLockPdas.map((pubkey) => ({
        pubkey,
        isSigner: false,
        isWritable: false,
      })),
    ],
    data,
  });
}
