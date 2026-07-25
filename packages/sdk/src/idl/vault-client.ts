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
import { createHash } from "node:crypto";

import {
  VAULT_CONFIG_SEED,
  MARKET_CONFIG_SEED,
  MERKLE_TREE_SEED,
  WALLET_SEED,
  NULLIFIER_SEED,
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
  const h = createHash("sha256");
  h.update(`global:${name}`);
  return new Uint8Array(h.digest()).slice(0, 8);
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

export function vaultConfigPda(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([VAULT_CONFIG_SEED], programId);
}

/** One market per ordered base/quote mint pair. */
export function marketConfigPda(
  programId: PublicKey,
  baseMint: PublicKey,
  quoteMint: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [MARKET_CONFIG_SEED, baseMint.toBytes(), quoteMint.toBytes()],
    programId,
  );
}

/** Per-shard `MerkleTree` PDA. Seed `[b"merkle_tree", &[treeId]]`. */
export function merkleTreePda(
  programId: PublicKey,
  treeId: number,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
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
export function staticSettleAltAddresses(
  programId: PublicKey,
  numTrees: number,
): PublicKey[] {
  const [vaultConfig] = vaultConfigPda(programId);
  const out = [
    vaultConfig,
    SYSVAR_INSTRUCTIONS_PUBKEY,
    SystemProgram.programId,
  ];
  for (let treeId = 0; treeId < Math.max(1, numTrees); treeId++) {
    out.push(merkleTreePda(programId, treeId)[0]);
  }
  return out;
}

export function walletEntryPda(
  programId: PublicKey,
  commitment: Uint8Array,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [WALLET_SEED, fixed32(commitment)],
    programId,
  );
}

export function nullifierEntryPda(
  programId: PublicKey,
  nullifier: Uint8Array,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [NULLIFIER_SEED, fixed32(nullifier)],
    programId,
  );
}

export function noteLockPda(
  programId: PublicKey,
  noteCommitment: Uint8Array,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [NOTE_LOCK_SEED, fixed32(noteCommitment)],
    programId,
  );
}

/** S-05 deposit-once guard PDA. */
export function depositedNotePda(
  programId: PublicKey,
  noteCommitment: Uint8Array,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [DEPOSITED_NOTE_SEED, fixed32(noteCommitment)],
    programId,
  );
}

export function consumedNotePda(
  programId: PublicKey,
  noteCommitment: Uint8Array,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [CONSUMED_NOTE_SEED, fixed32(noteCommitment)],
    programId,
  );
}

export function vaultTokenAccountPda(
  programId: PublicKey,
  mint: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [VAULT_TOKEN_SEED, mint.toBuffer()],
    programId,
  );
}

export function outstandingMintPda(
  programId: PublicKey,
  mint: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [OUTSTANDING_MINT_SEED, mint.toBuffer()],
    programId,
  );
}

// v3.1 `validCreateMarkerPda` + `validPriceMarkerPda` lived here.
// Removed in Phase 1c-hard along with their per-match builders /
// markers / verify ixs. The v3.5 batched flow uses
// `batchValidityMarkerPda` (below), one PDA per batch keyed by Merkle
// root rather than per-match binding hash.

/**
 * v3.5 — BatchValidityMarker PDA. Seed is the Merkle root committed by
 * the verify_match_batch proof's first public input. Created by
 * `verify_match_batch` and consumed by `tee_forced_settle_batched`.
 */
export function batchValidityMarkerPda(
  programId: PublicKey,
  merkleRoot: Uint8Array,
): [PublicKey, number] {
  if (merkleRoot.length !== 32) throw new Error("merkleRoot must be 32 bytes");
  return PublicKey.findProgramAddressSync(
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

export function buildInitializeInstruction(
  p: BuildInitializeParams,
): TransactionInstruction {
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
  const [vaultPda] = vaultConfigPda(p.programId);
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
    data: Buffer.from(data),
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

export function buildInitializeMarketInstruction(
  p: BuildInitializeMarketParams,
): TransactionInstruction {
  validateMarketParams(p);
  if (p.baseMint.equals(p.quoteMint)) {
    throw new Error("baseMint and quoteMint must be distinct");
  }
  const [vaultPda] = vaultConfigPda(p.programId);
  const [marketPda] = marketConfigPda(p.programId, p.baseMint, p.quoteMint);
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
    data: Buffer.from(data),
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

export function buildUpdateMarketConfigInstruction(
  p: BuildUpdateMarketConfigParams,
): TransactionInstruction {
  validateMarketParams(p);
  const [vaultPda] = vaultConfigPda(p.programId);
  const [marketPda] = marketConfigPda(p.programId, p.baseMint, p.quoteMint);
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
    data: Buffer.from(data),
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
export function buildInitializeTreeInstruction(
  p: BuildInitializeTreeParams,
): TransactionInstruction {
  const [vaultPda] = vaultConfigPda(p.programId);
  const [merkleTree] = merkleTreePda(p.programId, p.treeId);
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
    data: Buffer.from(data),
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

export function buildSetProtocolConfigInstruction(
  p: BuildSetProtocolConfigParams,
): TransactionInstruction {
  if (p.feeRateBps < 0 || p.feeRateBps > 10_000) {
    throw new Error(`feeRateBps out of range: ${p.feeRateBps}`);
  }
  const [vaultPda] = vaultConfigPda(p.programId);
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
    data: Buffer.from(data),
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
export function buildSetTeePubkeyInstruction(
  p: BuildSetTeePubkeyParams,
): TransactionInstruction {
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
  const [vaultPda] = vaultConfigPda(p.programId);
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
    data: Buffer.from(data),
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
export function buildResetMerkleTreeInstruction(
  p: BuildResetMerkleTreeParams,
): TransactionInstruction {
  const [vaultPda] = vaultConfigPda(p.programId);
  const [merkleTree] = merkleTreePda(p.programId, p.treeId);
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
    data: Buffer.from(data),
  });
}

export interface BuildRotateRootKeyParams {
  programId: PublicKey;
  currentRootKey: PublicKey;
  newRootKey: PublicKey;
}

export function buildRotateRootKeyInstruction(
  p: BuildRotateRootKeyParams,
): TransactionInstruction {
  if (
    p.newRootKey.equals(PublicKey.default) ||
    p.newRootKey.equals(p.currentRootKey)
  ) {
    throw new Error("newRootKey must be non-default and different");
  }
  const [vaultPda] = vaultConfigPda(p.programId);
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
    data: Buffer.from(data),
  });
}

export interface BuildCreateWalletParams {
  programId: PublicKey;
  owner: PublicKey;
  commitment: Uint8Array;
  proof: Groth16OnChainProof;
}

export function buildCreateWalletInstruction(
  p: BuildCreateWalletParams,
): TransactionInstruction {
  const [walletPda] = walletEntryPda(p.programId, p.commitment);
  const data = cat(
    anchorDiscriminator("create_wallet"),
    fixed32(p.commitment),
    serializeProof(p.proof),
  );
  // Accounts: [owner(signer,mut), wallet_entry(init,mut), system_program(ro)].
  // CU-3 / audit F-07: the unused `vault_config` account was removed from the
  // on-chain `CreateWallet` struct — keep this list in lockstep.
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.owner, isSigner: true, isWritable: true },
      { pubkey: walletPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
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

export function buildDepositInstruction(
  p: BuildDepositParams,
): TransactionInstruction {
  const [vaultPda] = vaultConfigPda(p.programId);
  const [merkleTree] = merkleTreePda(p.programId, p.treeId);
  const [vaultTokenAcct] = vaultTokenAccountPda(p.programId, p.tokenMint);
  const [outstandingMint] = outstandingMintPda(p.programId, p.tokenMint);
  const [depositedNote] = depositedNotePda(p.programId, p.noteCommitment);

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
    data: Buffer.from(data),
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
  noteCommitment: Uint8Array;
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
  noteCommitment: Uint8Array;
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
  noteCommitment: Uint8Array;
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
 *   disc(8) | note_commitment(32) | token_mint(32) | order_id(16)
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
    noteCommitment: data.slice(8, 40),
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
  /** 32-byte commitment of the locked note. */
  noteCommitment: Uint8Array;
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
 *   data = disc(8) || note_commitment(32)
 *
 *   accounts:
 *     [0] rent_receiver (signer, mut — receives the reclaimed rent)
 *     [1] note_lock     (mut, closed)
 */
export function buildReleaseLockInstruction(
  p: BuildReleaseLockParams,
): TransactionInstruction {
  const [noteLock] = noteLockPda(p.programId, p.noteCommitment);
  const data = cat(
    anchorDiscriminator("release_lock"),
    fixed32(p.noteCommitment),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.rentReceiver, isSigner: true, isWritable: true },
      { pubkey: noteLock, isSigner: false, isWritable: true },
    ],
    data: Buffer.from(data),
  });
}

/**
 * v3 wire format (matches `programs/vault/src/instructions/lock_note.rs`):
 *
 *   data = disc(8) || tree_id(1) || note_commitment(32) || order_id(16)
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
export function buildLockNoteInstruction(
  p: BuildLockNoteParams,
): TransactionInstruction {
  const [vaultPda] = vaultConfigPda(p.programId);
  const [merkleTree] = merkleTreePda(p.programId, p.treeId);
  const [noteLock] = noteLockPda(p.programId, p.noteCommitment);
  const [consumedNote] = consumedNotePda(p.programId, p.noteCommitment);
  if (p.orderId.length !== 16) {
    throw new Error(`orderId must be 16 bytes, got ${p.orderId.length}`);
  }
  const data = cat(
    anchorDiscriminator("lock_note"),
    new Uint8Array([p.treeId & 0xff]),
    fixed32(p.noteCommitment),
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
    data: Buffer.from(data),
  });
}

export function buildWithdrawInstruction(
  p: BuildWithdrawParams,
): TransactionInstruction {
  const [vaultPda] = vaultConfigPda(p.programId);
  const [merkleTree] = merkleTreePda(p.programId, p.treeId);
  const [vaultTokenAcct] = vaultTokenAccountPda(p.programId, p.tokenMint);
  const [consumedNote] = consumedNotePda(p.programId, p.noteCommitment);
  const [noteLock] = noteLockPda(p.programId, p.noteCommitment);
  const [outstandingMint] = outstandingMintPda(p.programId, p.tokenMint);

  const data = cat(
    anchorDiscriminator("withdraw"),
    new Uint8Array([p.treeId & 0xff]),
    fixed32(p.noteCommitment),
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
      // consumed_note is now `init`'d by withdraw (the commitment-keyed
      // consume-once guard shared with TEE settle) → writable.
      { pubkey: consumedNote, isSigner: false, isWritable: true },
      { pubkey: noteLock, isSigner: false, isWritable: false },
      // PF-04: the nullifier-keyed guard was removed — `consumed_note` above
      // is the complete double-spend guard, since `note_commitment` is a
      // circuit-bound public output of VALID_SPEND.
      { pubkey: outstandingMint, isSigner: false, isWritable: true },
      { pubkey: p.tokenProgramId, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
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
  /** Slot past which the marker becomes claimable as stale. */
  expirySlot: bigint;
  proof: Groth16OnChainProof;
}

export function buildVerifyMatchBatchInstruction(
  p: BuildVerifyMatchBatchParams,
): TransactionInstruction {
  if (p.merkleRoot.length !== 32) {
    throw new Error("merkleRoot must be 32 bytes");
  }
  const [marker] = batchValidityMarkerPda(p.programId, p.merkleRoot);
  const [vaultConfig] = vaultConfigPda(p.programId);
  const [marketConfig] = marketConfigPda(p.programId, p.baseMint, p.quoteMint);

  const data = cat(
    anchorDiscriminator("verify_match_batch"),
    fixed32(p.merkleRoot),
    u64LE(p.expirySlot),
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
    data: Buffer.from(data),
  });
}

// ---------------------------------------------------------------------------
// merge — in-pool note consolidation (VALID_MERGE K=2/4). Consumes K input
// notes (their commitment-keyed ConsumedNoteEntry PDAs — C-01), appends ONE
// summed output leaf. No transfer.
// ---------------------------------------------------------------------------

export interface BuildMergeParams {
  programId: PublicKey;
  /** Which Merkle-tree shard the inputs live in + the merged output appends to. */
  treeId: number;
  payer: PublicKey;
  /**
   * K input note commitments in circuit order — the real commitment for active
   * slots, all-zero for dummy pad slots (C-01: these are the VALID_MERGE public
   * outputs the circuit binds; each active one gets a ConsumedNoteEntry).
   */
  inputCommitments: Uint8Array[];
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
 *        || input_commitments(Vec<[u8;32]>: u32 LE len ++ len*32)
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
export function buildMergeInstruction(
  p: BuildMergeParams,
): TransactionInstruction {
  if ((p.k !== 2 && p.k !== 4) || p.inputCommitments.length !== p.k) {
    throw new Error("merge k must be 2 or 4 and match commitment slot count");
  }
  const [vaultPda] = vaultConfigPda(p.programId);
  const [merkleTree] = merkleTreePda(p.programId, p.treeId);
  const isZero = (b: Uint8Array) => b.every((x) => x === 0);
  const activeCommitments = p.inputCommitments.filter((c) => !isZero(c));
  if (activeCommitments.length === 0) {
    throw new Error("merge must contain at least one active commitment");
  }
  const consumedPdas = activeCommitments.map(
    (c) => consumedNotePda(p.programId, c)[0],
  );
  const noteLockPdas = activeCommitments.map(
    (c) => noteLockPda(p.programId, c)[0],
  );

  const lenLE = new Uint8Array(4);
  new DataView(lenLE.buffer).setUint32(0, p.inputCommitments.length, true);
  const commitmentsBytes = cat(
    lenLE,
    ...p.inputCommitments.map((c) => fixed32(c)),
  );

  const data = cat(
    anchorDiscriminator("merge"),
    new Uint8Array([p.treeId & 0xff]),
    commitmentsBytes,
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
    data: Buffer.from(data),
  });
}
