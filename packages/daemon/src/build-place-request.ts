/**
 * buildPlaceRequest — assemble a signed `POST /orders` body from local state.
 *
 * This is the proving + body-building wiring that sits between the daemon's
 * keystore + UTXO set and the {@link OrderPlacer}. Given a {@link Keystore}, a
 * stored note to spend, and an intent, it:
 *
 *   1. derives this order's HD `order_id` (`deriveOrderId(seed, seedIndex)`),
 *   2. pulls the account's keys/commitments from the keystore (all on-device),
 *   3. runs `proveAndBuildOrder` — fetch the note's Merkle witness from
 *      `/tree/inclusion`, produce the VALID_INPUT proof via the injected
 *      {@link ValidInputProver} (the in-process node prover by default, ~0.83s),
 *      then assemble + sign the body, including the viewing key and current
 *      CVM boot session.
 *
 * The prover is injected so the heavy/Node-only snarkjs path stays optional and
 * tests can supply a fake. Returns the request plus the 16-byte `order_id`, so
 * the caller can build the matching {@link ManagedOrder} for `placeManagedOrder`.
 */

import {
  deriveOrderId,
  proveAndBuildOrder,
  type ExecutionPolicy,
  type OrderSide,
  type PlaceOrderRequest,
  type RootVerifier,
  type StoredNote,
  type ValidInputProver,
} from "@darknyx/sdk";

import type { Keystore } from "./keystore.js";

const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h, "hex"));

/** What to trade — the SDK-typed intent the strategy supplies. */
export interface OrderIntent {
  symbol: string;
  side: OrderSide;
  /** Execution policy (type/price-limit/min-fill/expiry) — see SDK `builders.ts`. */
  policy: ExecutionPolicy;
  /** Order size in base units. */
  amount: bigint;
  /** The note's value when over-collateralizing (default = note.amount). */
  collateralAmount?: bigint;
  /** Per-order signature nonce (default 1). */
  arrivalNonce?: bigint;
}

export interface BuildPlaceRequestArgs {
  keystore: Keystore;
  /** The note to spend (from the daemon's `DaemonStore`). */
  note: StoredNote;
  /** HD index for this order — derives `order_id` + the per-order trading key. */
  seedIndex: number;
  /** Current 32-byte CVM boot session id fetched from `/info`. */
  sessionId: Uint8Array;
  intent: OrderIntent;
  /** Gateway origin (the SDK appends `/tree/inclusion`). */
  gatewayUrl: string;
  token: string;
  /** VALID_INPUT prover (e.g. the SDK `nodeValidInputProver`). */
  prover: ValidInputProver;
  /** Merkle-tree shard the note lives in (default 0). */
  treeId?: number;
  fetchImpl?: typeof fetch;
  /** Finalized on-chain recent-root-ring gate. Production daemon supplies it. */
  verifyRoot?: RootVerifier;
}

export interface BuiltPlaceRequest {
  request: PlaceOrderRequest;
  /** 16-byte HD order id (hex of this is `request.order_id`). */
  orderId: Uint8Array;
}

export async function buildPlaceRequest(
  args: BuildPlaceRequestArgs,
): Promise<BuiltPlaceRequest> {
  const { keystore, note, seedIndex, intent } = args;
  const orderId = deriveOrderId(keystore.masterSeed, seedIndex);

  const request = await proveAndBuildOrder({
    // identity / keys (all on-device)
    masterSeed: keystore.masterSeed,
    spendingKey: keystore.spendingKey,
    ownerCommitment: note.ownerCommitment,
    tradingKey: keystore.tradingPublicKey(seedIndex),
    sign: (digest) => keystore.signWithTradingKey(seedIndex, digest),
    // the note + intent
    note: {
      commitment: fromHex(note.commitment),
      innerHash: note.innerHash,
      amount: note.amount,
    },
    symbol: intent.symbol,
    side: intent.side,
    policy: intent.policy,
    amount: intent.amount,
    orderId,
    sessionId: args.sessionId,
    collateralAmount: intent.collateralAmount,
    arrivalNonce: intent.arrivalNonce,
    // proving + transport
    baseUrl: args.gatewayUrl,
    token: args.token,
    prover: args.prover,
    ownerCommitmentBlinding: keystore.ownerBlinding,
    tokenMint: note.tokenMint,
    treeId: args.treeId,
    fetchImpl: args.fetchImpl,
    verifyRoot: args.verifyRoot,
  });

  return { request, orderId };
}
