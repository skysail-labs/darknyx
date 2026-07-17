/**
 * `buildOrder` — assemble a fully-signed `POST /orders` body from a spendable
 * note, your keys, and an intent (an {@link ExecutionPolicy} from `builders.ts`).
 *
 * This is the SDK's order-submission assembly: it mirrors, byte-for-byte, the
 * order body the enclave verifies. The trading-key signature covers the v3
 * canonical digest ({@link orderCanonicalDigest}) — which is itself pinned to
 * the Rust matcher by `order-canonical-parity.test.ts`, so a correct
 * `buildOrder` inherits that byte-equality. The signed body binds the viewing
 * key and current boot session so neither can be substituted or replayed after
 * a CVM restart.
 *
 * Signing is provided by a **callback** (`sign`) rather than a key, so the SDK
 * stays agnostic to your Ed25519 implementation (a web3.js `Keypair` + tweetnacl,
 * a hardware signer, …). `sign` must produce a 64-byte Ed25519 detached
 * signature over the 32-byte digest.
 *
 * The VALID_INPUT proof + the root it was generated against are passed in
 * (`validInput`); generate them with the SDK prover + a `/tree/inclusion` witness
 * (see `proveAndBuildOrder` / `nodeValidInputProver`), or relay one you have.
 */

import { orderCanonicalDigest, OrderSide, OrderType } from "./canonical.js";
import type { ExecutionPolicy } from "./builders.js";
import {
  bn254ToBE32,
  deriveViewingEncKeypair,
} from "../keys/key-generators.js";
import { nullifierV2 } from "../utxo/note.js";
import { isContributoryX25519PublicKey } from "../keys/fill-encryption.js";

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

/** A spendable note the order is collateralized by. */
export interface OrderNote {
  /** 32-byte Poseidon6 commitment (bytes). */
  commitment: Uint8Array;
  /** The note's amount-independent v2 inner hash (a BN254 Fr bigint). */
  innerHash: bigint;
  /** The value the note carries (base units for an ask, quote for a bid). */
  amount: bigint;
}

/** A relayed VALID_INPUT proof + the Merkle root it was generated against. */
export interface ValidInputRelay {
  /** 256-byte concatenated Groth16 proof (`pi_a ‖ pi_b ‖ pi_c`). */
  proofBytes: Uint8Array;
  /** 32-byte big-endian Merkle root the proof is against. */
  merkleRoot: Uint8Array;
}

/** Ed25519 detached signer over the 32-byte canonical digest → 64-byte sig. */
export type OrderSigner = (
  digest: Uint8Array,
) => Uint8Array | Promise<Uint8Array>;

export interface BuildOrderArgs {
  // ── identity / keys ──
  /** Master seed (derives the default viewing-encryption key). */
  masterSeed: Uint8Array;
  /** Spending key (derives this order's note nullifier). */
  spendingKey: bigint;
  /** The note's owner commitment (a BN254 Fr bigint). */
  ownerCommitment: bigint;
  /** 32-byte user commitment (bytes); top byte must be zero (Fr-safe). */
  userCommitment: Uint8Array;
  /** 32-byte Ed25519 trading public key (bytes). */
  tradingKey: Uint8Array;
  /** Detached Ed25519 signer over the canonical digest. */
  sign: OrderSigner;

  // ── the note + its proof ──
  note: OrderNote;
  validInput: ValidInputRelay;

  // ── intent ──
  symbol: string;
  side: OrderSide;
  /** Execution policy (type, price limit, min-fill, expiry) — see `builders.ts`. */
  policy: ExecutionPolicy;
  /** Order size in base units. */
  amount: bigint;
  /** 16-byte client order id (e.g. `deriveOrderId(masterSeed, n)`). */
  orderId: Uint8Array;

  /** 32-byte boot session id advertised by the CVM's `/info` endpoint. */
  sessionId: Uint8Array;

  /** Per-order nonce bound into the signature. Default `1`. */
  arrivalNonce?: bigint;
  /** The note's actual value when over-collateralizing. Default `note.amount`. */
  collateralAmount?: bigint;
  /** Which Merkle-tree shard the note lives in (selects the settle's lock_note
   *  shard so a batch's inputs can span shards). Default `0`. NOT signed. */
  treeId?: number;
  /** 32-byte X25519 viewing-encryption public key (output recovery v3). The TEE
   *  encrypts this order's `(trade, change)` amounts to it on-chain so they
   *  survive a CVM redeploy. Defaults to
   *  `deriveViewingEncKeypair(masterSeed).publicKey` (recovery on by default).
   *  This key is bound into the order signature. */
  viewingPubkey?: Uint8Array;
}

/** The fully-signed `POST /orders` wire body (all hex fields; numeric u64s). */
export interface PlaceOrderRequest {
  symbol: string;
  side: "bid" | "ask";
  order_type: "limit" | "ioc" | "fok";
  amount: number;
  price_limit: number;
  min_fill_size: number;
  expiry_slot: number;
  order_id: string;
  note_commitment: string;
  user_commitment: string;
  arrival_nonce: number;
  trading_key: string;
  trading_key_signature: string;
  owner_commitment: string;
  note_inner_hash: string;
  nullifier: string;
  merkle_root: string;
  valid_input_proof: string;
  collateral_amount: number;
  /** Which Merkle-tree shard the collateral note lives in. Default 0. */
  tree_id: number;
  /** 32-byte X25519 viewing-encryption pubkey, hex (output recovery v3). */
  viewing_pubkey: string;
  /** 32-byte CVM boot session id, hex. */
  session_id: string;
}

const sideTag = (s: OrderSide): "bid" | "ask" =>
  s === OrderSide.Bid ? "bid" : "ask";
const typeTag = (t: OrderType): "limit" | "ioc" | "fok" =>
  t === OrderType.Ioc ? "ioc" : t === OrderType.Fok ? "fok" : "limit";

/** u64 wire fields are JSON numbers; guard the 2^53 precision boundary. */
function u64(v: bigint, field: string): number {
  if (v < 0n || v > 9_007_199_254_740_991n) {
    throw new Error(
      `${field} ${v} exceeds the safe JSON integer range (2^53-1)`,
    );
  }
  return Number(v);
}

/**
 * Assemble + sign a `POST /orders` body. Pure: no network, no prover — the
 * VALID_INPUT proof is supplied. Deterministic given its inputs.
 */
export async function buildOrder(
  args: BuildOrderArgs,
): Promise<PlaceOrderRequest> {
  if (args.orderId.length !== 16) throw new Error("orderId must be 16 bytes");
  if (args.tradingKey.length !== 32)
    throw new Error("tradingKey must be 32 bytes");
  if (args.userCommitment.length !== 32)
    throw new Error("userCommitment must be 32 bytes");
  if (args.note.commitment.length !== 32)
    throw new Error("note.commitment must be 32 bytes");
  if (args.validInput.merkleRoot.length !== 32)
    throw new Error("merkleRoot must be 32 bytes");
  if (args.sessionId.length !== 32)
    throw new Error("sessionId must be 32 bytes");
  if (args.treeId != null && args.treeId < 0)
    throw new Error("treeId must be non-negative");

  const arrivalNonce = args.arrivalNonce ?? 1n;
  const collateralAmount = args.collateralAmount ?? args.note.amount;
  // Recovery on by default: derive the viewing-enc pubkey from the seed unless
  // the caller overrides it. The canonical signature binds this exact key.
  const viewingPubkey =
    args.viewingPubkey ?? deriveViewingEncKeypair(args.masterSeed).publicKey;
  if (viewingPubkey.length !== 32)
    throw new Error("viewingPubkey must be 32 bytes");
  if (!isContributoryX25519PublicKey(viewingPubkey))
    throw new Error("viewingPubkey is a non-contributory X25519 point");

  // The signed v3 canonical digest — byte-identical to the matcher's encoder.
  const digest = orderCanonicalDigest({
    symbol: new TextEncoder().encode(args.symbol),
    side: args.side,
    orderType: args.policy.orderType,
    amount: args.amount,
    priceLimit: args.policy.priceLimit,
    minFillSize: args.policy.minFillSize,
    expirySlot: args.policy.expirySlot,
    orderId: args.orderId,
    noteCommitment: args.note.commitment,
    userCommitment: args.userCommitment,
    arrivalNonce,
    viewingPubkey,
    sessionId: args.sessionId,
  });

  const signature = await args.sign(digest);
  if (signature.length !== 64)
    throw new Error("sign() must return a 64-byte Ed25519 signature");

  const nullifier = await nullifierV2(args.spendingKey, args.note.innerHash);

  return {
    symbol: args.symbol,
    side: sideTag(args.side),
    order_type: typeTag(args.policy.orderType),
    amount: u64(args.amount, "amount"),
    price_limit: u64(args.policy.priceLimit, "price_limit"),
    min_fill_size: u64(args.policy.minFillSize, "min_fill_size"),
    expiry_slot: u64(args.policy.expirySlot, "expiry_slot"),
    order_id: toHex(args.orderId),
    note_commitment: toHex(args.note.commitment),
    user_commitment: toHex(args.userCommitment),
    arrival_nonce: u64(arrivalNonce, "arrival_nonce"),
    trading_key: toHex(args.tradingKey),
    trading_key_signature: toHex(signature),
    owner_commitment: toHex(bn254ToBE32(args.ownerCommitment)),
    note_inner_hash: toHex(bn254ToBE32(args.note.innerHash)),
    nullifier: toHex(nullifier),
    merkle_root: toHex(args.validInput.merkleRoot),
    valid_input_proof: toHex(args.validInput.proofBytes),
    collateral_amount: u64(collateralAmount, "collateral_amount"),
    tree_id: args.treeId ?? 0,
    viewing_pubkey: toHex(viewingPubkey),
    session_id: toHex(args.sessionId),
  };
}
