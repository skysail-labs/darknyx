/**
 * VALID_INPUT proving for order submission.
 *
 * `buildOrder` needs a 256-byte VALID_INPUT proof + the root it was generated
 * against. This module supplies the two halves:
 *
 *   1. {@link fetchInclusionProof} — pull the Merkle witness for a note from the
 *      engine's `GET /tree/inclusion` (siblings + leaf index → path bits).
 *   2. A pluggable {@link ValidInputProver} — produce the Groth16 proof from the
 *      witness + the note opening. The prover is injected so the SDK doesn't
 *      force the (heavy, untyped, Node-only) `snarkjs` library + the circuit
 *      artifacts on every consumer. {@link nodeValidInputProver} is a ready
 *      Node adapter (dynamic `snarkjs` import + the compiled `.wasm`/`.zkey`);
 *      a browser consumer can supply its own WASM prover with the same shape.
 *
 * {@link proveAndBuildOrder} chains fetch → prove → `buildOrder` for the full
 * "intent + note → signed body" flow.
 */

import { formatGroth16ForOnChain } from "./groth16-format.js";
import {
  noteCommitmentV2,
  ownerCommitment,
  pubkeyToFrPair,
} from "../utxo/note.js";
import { buildOrder } from "../orders/build-order.js";
import type {
  BuildOrderArgs,
  PlaceOrderRequest,
  ValidInputRelay,
} from "../orders/build-order.js";

const MERKLE_DEPTH = 20;

const toBigIntBE = (b: Uint8Array): bigint => {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
};
const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));

/** A Merkle inclusion witness for a note, fetched from `/tree/inclusion`. */
export interface InclusionWitness {
  leafIndex: number;
  /** 32-byte big-endian root the witness authenticates to. */
  merkleRoot: Uint8Array;
  /** `MERKLE_DEPTH` sibling path elements (BN254 Fr bigints), leaf→root. */
  siblings: bigint[];
  /** `MERKLE_DEPTH` path bits derived from `leafIndex` (0 = sibling right). */
  pathIndices: number[];
}

export interface InclusionFetchOptions {
  baseUrl: string;
  token: string;
  treeId?: number;
  fetchImpl?: typeof fetch;
}

/** Path bits from a leaf index: bit `i` selects the sibling side at level `i`. */
export function pathIndicesFromLeafIndex(
  leafIndex: number,
  depth = MERKLE_DEPTH,
): number[] {
  const bits: number[] = [];
  for (let i = 0; i < depth; i++) bits.push((leafIndex >> i) & 1);
  return bits;
}

/** Fetch a note's inclusion witness from `GET /tree/inclusion`. */
export async function fetchInclusionProof(
  opts: InclusionFetchOptions,
  noteCommitmentHex: string,
): Promise<InclusionWitness> {
  const f = opts.fetchImpl ?? fetch;
  const url = new URL("/tree/inclusion", opts.baseUrl);
  url.searchParams.set("note_commitment", noteCommitmentHex);
  url.searchParams.set("tree_id", String(opts.treeId ?? 0));
  const res = await f(url.toString(), {
    headers: { authorization: `Bearer ${opts.token}` },
  });
  if (!res.ok)
    throw new Error(`/tree/inclusion ${res.status}: ${await res.text()}`);
  const body = (await res.json()) as {
    leaf_index: number;
    merkle_root: string;
    siblings: string[];
  };
  if (body.siblings.length !== MERKLE_DEPTH) {
    throw new Error(
      `expected ${MERKLE_DEPTH} siblings, got ${body.siblings.length}`,
    );
  }
  return {
    leafIndex: body.leaf_index,
    merkleRoot: fromHex(body.merkle_root),
    siblings: body.siblings.map((s) => toBigIntBE(fromHex(s))),
    pathIndices: pathIndicesFromLeafIndex(body.leaf_index),
  };
}

/** The note opening + public inputs a VALID_INPUT proof needs (the witness
 *  comes separately). */
export interface ValidInputProveParams {
  spendingKey: bigint;
  ownerCommitmentBlinding: bigint;
  innerHash: bigint;
  tokenMint: Uint8Array;
  amount: bigint;
  witness: InclusionWitness;
}

/** Produce a VALID_INPUT proof (proof bytes + the root it's against). Injected
 *  so the SDK stays prover-agnostic (Node snarkjs, browser WASM, a relayer …). */
export type ValidInputProver = (
  params: ValidInputProveParams,
) => Promise<ValidInputRelay>;

/**
 * Node VALID_INPUT prover: dynamically imports `snarkjs` and runs the compiled
 * `valid_input` circuit. `snarkjs` is imported at call time (not a static
 * dependency), so a browser/relayer consumer that supplies its own prover never
 * pulls it in. Point `wasmPath`/`zkeyPath` at the compiled artifacts
 * (`circuits/build/valid_input/...`).
 */
export function nodeValidInputProver(artifacts: {
  wasmPath: string;
  zkeyPath: string;
}): ValidInputProver {
  return async (params: ValidInputProveParams): Promise<ValidInputRelay> => {
    // Recompute the note commitment from the opening (a circuit public input).
    const owner = await ownerCommitment(
      params.spendingKey,
      params.ownerCommitmentBlinding,
    );
    const commitmentBE = await noteCommitmentV2({
      tokenMint: params.tokenMint,
      amount: params.amount,
      ownerCommitment: owner,
      innerHash: params.innerHash,
    });
    const [mintLo, mintHi] = pubkeyToFrPair(params.tokenMint);
    const inputs = {
      merkleRoot: toBigIntBE(params.witness.merkleRoot).toString(),
      noteCommitment: toBigIntBE(commitmentBE).toString(),
      tokenMint: [mintLo.toString(), mintHi.toString()],
      amount: params.amount.toString(),
      spendingKey: params.spendingKey.toString(),
      ownerCommitmentBlinding: params.ownerCommitmentBlinding.toString(),
      innerHash: params.innerHash.toString(),
      merklePath: params.witness.siblings.map((s) => s.toString()),
      merkleIndices: params.witness.pathIndices.map((i) => i.toString()),
    };
    // `snarkjs` is ESM + untyped; import dynamically and treat as `any`.
    const specifier = "snarkjs";
    const snarkjs = (await import(specifier)) as unknown as {
      groth16: {
        fullProve(
          i: unknown,
          w: string,
          z: string,
        ): Promise<{ proof: unknown; publicSignals: unknown }>;
      };
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      inputs,
      artifacts.wasmPath,
      artifacts.zkeyPath,
    );
    const { proof: onchain } = formatGroth16ForOnChain(
      proof as never,
      publicSignals as never,
    );
    // valid_input_proof = pi_a ‖ pi_b ‖ pi_c (256 bytes).
    const proofBytes = new Uint8Array(256);
    proofBytes.set(onchain.piA, 0);
    proofBytes.set(onchain.piB, 64);
    proofBytes.set(onchain.piC, 192);
    return { proofBytes, merkleRoot: params.witness.merkleRoot };
  };
}

/** Full flow: fetch the note's inclusion witness, prove VALID_INPUT, then
 *  assemble + sign the order. `args` is everything {@link buildOrder} needs
 *  except `validInput` (this supplies it), plus the prover + the opening's
 *  blinding + the note's mint. */
export async function proveAndBuildOrder(
  args: Omit<BuildOrderArgs, "validInput"> & {
    baseUrl: string;
    token: string;
    prover: ValidInputProver;
    ownerCommitmentBlinding: bigint;
    tokenMint: Uint8Array;
    treeId?: number;
    fetchImpl?: typeof fetch;
  },
): Promise<PlaceOrderRequest> {
  const noteCommitmentHex = Buffer.from(args.note.commitment).toString("hex");
  const witness = await fetchInclusionProof(
    {
      baseUrl: args.baseUrl,
      token: args.token,
      treeId: args.treeId,
      fetchImpl: args.fetchImpl,
    },
    noteCommitmentHex,
  );
  const validInput = await args.prover({
    spendingKey: args.spendingKey,
    ownerCommitmentBlinding: args.ownerCommitmentBlinding,
    innerHash: args.note.innerHash,
    tokenMint: args.tokenMint,
    amount: args.note.amount,
    witness,
  });
  return buildOrder({ ...args, validInput });
}
