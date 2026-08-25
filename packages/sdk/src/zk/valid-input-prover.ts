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

import { Connection, PublicKey } from "@solana/web3.js";

import { apiUrl } from "../api-url.js";
import { formatGroth16ForOnChain } from "./groth16-format.js";
import {
  noteCommitmentV2,
  ownerCommitment,
  pubkeyToFrPair,
} from "../utxo/note.js";
import { deriveNoteUseTag } from "../utxo/note-use.js";
import { bn254ToBE32 } from "../keys/key-generators.js";
import { merkleTreePda } from "../idl/vault-client.js";
import { buildOrder } from "../orders/build-order.js";
import type {
  BuildOrderArgs,
  PlaceOrderRequest,
  ValidInputRelay,
} from "../orders/build-order.js";
import {
  parseMerkleRootRing,
  type MerkleRootRingSnapshot,
} from "./merkle-root-ring.js";

export { parseMerkleRootRing, type MerkleRootRingSnapshot };

const MERKLE_DEPTH = 20;

/** Verify that a Merkle root is accepted by the specified on-chain shard. */
export type RootVerifier = (root: Uint8Array, treeId: number) => Promise<void>;

/**
 * C-09: build a `verifyRoot` hook that asserts a TEE-supplied inclusion root is
 * a member of the on-chain shard's recent-root ring BEFORE the client proves
 * against it. Without this the client trusts whatever root the engine's
 * `/tree/inclusion` returns; a malicious/buggy engine could get it to build a
 * VALID_INPUT proof against a fabricated root (the on-chain program would reject
 * it later, but the client should fail fast + clear rather than waste a proof
 * and an order roundtrip). Reusable by any inclusion-proof flow (order intake,
 * withdraw). Reads the same ring the vault's `contains_root` checks.
 */
export function onchainRootVerifier(deps: {
  connection: Connection;
  programId: PublicKey;
}): RootVerifier {
  return async (root, treeId) => {
    if (root.length !== 32) throw new Error("root must be 32 bytes");
    if (root.every((byte) => byte === 0)) {
      throw new Error("refusing to verify an all-zero Merkle root");
    }
    if (!Number.isInteger(treeId) || treeId < 0 || treeId > 255) {
      throw new Error(`tree id must be a u8, got ${treeId}`);
    }
    const [pda] = await merkleTreePda(deps.programId, treeId);
    // Read at `confirmed`, NOT `finalized`.
    //
    // The vault's own `contains_root` runs against live account state, so
    // `confirmed` is the level that reflects what the program will actually
    // see when the proof lands — checking a stricter level does not make the
    // proof more likely to be accepted, it only makes the client refuse
    // roots that are already perfectly valid.
    //
    // Reading `finalized` broke every client that proved straight after its
    // own deposit: on devnet `confirmed` runs ~30 slots (~12 s) ahead, so the
    // just-created root was legitimately absent and the gate failed instantly
    // on a condition that resolves itself. That is what broke the daemon
    // smoke on BOTH transports, and it read as a transport fault during the
    // RA-TLS cutover.
    //
    // The C-09 guarantee is untouched: a fabricated root is in the ring at NO
    // commitment level, so this still refuses it.
    const acct = await deps.connection.getAccountInfo(pda, "confirmed");
    if (!acct) {
      throw new Error(
        `merkle tree shard ${treeId} not found on-chain (${pda.toBase58()})`,
      );
    }
    const data = acct.data;
    if (!acct.owner.equals(deps.programId)) {
      throw new Error(
        `merkle tree shard ${treeId} is owned by ${acct.owner.toBase58()}, not ${deps.programId.toBase58()}`,
      );
    }
    const snapshot = parseMerkleRootRing(data, treeId);
    const matches = snapshot.acceptedRoots.some(
      (accepted) =>
        accepted.length === root.length &&
        accepted.every((value, index) => value === root[index]),
    );
    if (matches) return;
    throw new Error(
      `inclusion root ${Buffer.from(root).toString("hex")} is not in shard ${treeId}'s ` +
        `on-chain root ring — refusing to prove against a root the vault won't accept`,
    );
  };
}

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
  /**
   * REQUIRED. The transport this call must use.
   *
   * Not optional and not defaulted: an omitted `fetchImpl` used to fall back
   * to `globalThis.fetch`, which silently bypasses the verified transport.
   * Seven call sites did exactly that, each looking correct, and each only
   * surfaced during a billable live CVM run. Making it required converts every
   * one of those into a compile error.
   *
   * Browser and legacy callers pass `globalThis.fetch` explicitly — a
   * statement of intent rather than an accident.
   */
  fetchImpl: typeof fetch;
  /**
   * C-09: optional cross-check that the engine-returned root is in the on-chain
   * shard root ring before it's used to prove. Build one with
   * {@link onchainRootVerifier}. Omitted ⇒ the caller trusts the engine's root
   * (e.g. offline tests); production callers should supply it.
   */
  verifyRoot?: RootVerifier;
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
  const f = opts.fetchImpl;
  const url = apiUrl(opts.baseUrl, "tree/inclusion");
  // The TEE `/tree/inclusion` query param is `commitment` (see vault tree API);
  // `note_commitment` is the RESPONSE field, not the request param.
  url.searchParams.set("commitment", noteCommitmentHex);
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
  const witness: InclusionWitness = {
    leafIndex: body.leaf_index,
    merkleRoot: fromHex(body.merkle_root),
    siblings: body.siblings.map((s) => toBigIntBE(fromHex(s))),
    pathIndices: pathIndicesFromLeafIndex(body.leaf_index),
  };
  // C-09: reject a root the on-chain vault wouldn't accept, before proving.
  if (opts.verifyRoot) {
    await opts.verifyRoot(witness.merkleRoot, opts.treeId ?? 0);
  }
  return witness;
}

/** The note opening a VALID_INPUT proof needs (the witness comes separately).
 * `amount` is a private positive-u64 circuit witness. */
export interface ValidInputProveParams {
  spendingKey: bigint;
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
    if (params.amount <= 0n || params.amount > 0xffff_ffff_ffff_ffffn) {
      throw new Error("VALID_INPUT amount must be a positive u64");
    }
    // Recompute the private Merkle leaf, then derive the circuit's public
    // consume handle. Both are 32 bytes; passing the commitment here compiles
    // but targets the pre-note-use-tag circuit interface.
    const owner = await ownerCommitment(params.spendingKey);
    const commitmentBE = await noteCommitmentV2({
      tokenMint: params.tokenMint,
      amount: params.amount,
      ownerCommitment: owner,
      innerHash: params.innerHash,
    });
    const noteUseTagBE = await deriveNoteUseTag(
      commitmentBE,
      bn254ToBE32(params.innerHash),
    );
    const [mintLo, mintHi] = pubkeyToFrPair(params.tokenMint);
    const inputs = {
      merkleRoot: toBigIntBE(params.witness.merkleRoot).toString(),
      noteUseTag: toBigIntBE(noteUseTagBE).toString(),
      tokenMint: [mintLo.toString(), mintHi.toString()],
      amount: params.amount.toString(),
      spendingKey: params.spendingKey.toString(),
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
    const { proof: onchain, publicInputsBE } = formatGroth16ForOnChain(
      proof as never,
      publicSignals as never,
    );
    const expected = [
      params.witness.merkleRoot,
      noteUseTagBE,
      bn254ToBE32(mintLo),
      bn254ToBE32(mintHi),
    ];
    if (
      publicInputsBE.length !== expected.length ||
      publicInputsBE.some(
        (value, index) =>
          value.length !== expected[index].length ||
          value.some((byte, offset) => byte !== expected[index][offset]),
      )
    ) {
      throw new Error("VALID_INPUT public-input ordering mismatch");
    }
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
    /**
     * Needed by the VALID_INPUT prover as a circuit private witness, NOT by
     * `buildOrder`. It moved here when the order body stopped carrying a
     * nullifier (S-09): assembling and signing an order no longer requires the
     * spending key at all, only proving does.
     */
    spendingKey: bigint;
    tokenMint: Uint8Array;
    treeId?: number;
    /** REQUIRED — see InclusionFetchOptions.fetchImpl. */
    fetchImpl: typeof fetch;
    /** C-09: cross-check the engine root against the on-chain ring — see
     *  {@link onchainRootVerifier}. */
    verifyRoot?: RootVerifier;
  },
): Promise<PlaceOrderRequest> {
  const noteCommitmentHex = Buffer.from(args.note.commitment).toString("hex");
  const witness = await fetchInclusionProof(
    {
      baseUrl: args.baseUrl,
      token: args.token,
      treeId: args.treeId,
      fetchImpl: args.fetchImpl,
      verifyRoot: args.verifyRoot,
    },
    noteCommitmentHex,
  );
  const validInput = await args.prover({
    spendingKey: args.spendingKey,
    innerHash: args.note.innerHash,
    tokenMint: args.tokenMint,
    amount: args.note.amount,
    witness,
  });
  return buildOrder({ ...args, validInput });
}
