import {
  bn254ToBE32,
  deriveBlindingFactor,
  deriveSpendingKey,
  noteCommitment,
  nullifier,
  ownerCommitment,
  pubkeyToFrPair,
  vaultConfigPda,
} from "@nyx/sdk";
import { PublicKey } from "@solana/web3.js";
import { NextResponse } from "next/server";

import {
  be32ToBigInt,
  deriveBlinding,
  deriveNonce,
  TRADE_ROLE_BUYER,
} from "@/lib/dapp/change-note-derive";
import {
  getDemoConnections,
  loadDemoE2eConfig,
  parseDemoPrograms,
  resolveRepoRoot,
} from "@/lib/dapp/demo-devnet";
import { MerkleShadow, type MerkleWitness } from "@/lib/dapp/merkle-shadow";
import { collectVaultLeavesOrdered } from "@/lib/dapp/vault-leaf-history";
import { verifyPhantomSeedSignature } from "@/lib/dapp/phantom-verify";

export const runtime = "nodejs";

/**
 * VaultConfig zero-copy layout (no implicit padding):
 *   8B   anchor disc
 *   32B  admin
 *   32B  tee_pubkey
 *   32B  root_key
 *   8B   leaf_count                     -> offset 104
 *   32B  current_root                   -> offset 112
 *   32B*32 = 1024B  roots[32]           -> offset 144
 *   ...
 */
const VAULT_LEAF_COUNT_OFFSET = 8 + 32 + 32 + 32;
const VAULT_CURRENT_ROOT_OFFSET = VAULT_LEAF_COUNT_OFFSET + 8;
const VAULT_ROOTS_OFFSET = VAULT_CURRENT_ROOT_OFFSET + 32;
const VAULT_ROOT_HISTORY_SIZE = 32;

function isZero32(b: Uint8Array): boolean {
  return b.every((x) => x === 0);
}

function readVaultRoots(data: Buffer): {
  current: Uint8Array;
  ring: Uint8Array[];
} {
  const current = new Uint8Array(
    data.subarray(VAULT_CURRENT_ROOT_OFFSET, VAULT_CURRENT_ROOT_OFFSET + 32),
  );
  const ring: Uint8Array[] = [];
  for (let i = 0; i < VAULT_ROOT_HISTORY_SIZE; i++) {
    const off = VAULT_ROOTS_OFFSET + i * 32;
    const r = new Uint8Array(data.subarray(off, off + 32));
    if (!isZero32(r)) ring.push(r);
  }
  return { current, ring };
}

function rootMatches(witnessRoot: Uint8Array, target: Uint8Array): boolean {
  if (witnessRoot.length !== target.length) return false;
  for (let i = 0; i < witnessRoot.length; i++)
    if (witnessRoot[i] !== target[i]) return false;
  return true;
}

function findMatchingRoot(
  witnessRoot: Uint8Array,
  current: Uint8Array,
  ring: Uint8Array[],
): "current" | { ringIndex: number } | null {
  if (rootMatches(witnessRoot, current)) return "current";
  for (let i = 0; i < ring.length; i++) {
    if (rootMatches(witnessRoot, ring[i])) return { ringIndex: i };
  }
  return null;
}

function beBytesToBigInt(x: Uint8Array): bigint {
  let acc = 0n;
  for (const b of x) acc = (acc << 8n) | BigInt(b);
  return acc;
}

/**
 * Build a MerkleShadow over a prefix of leaves and produce a witness for
 * `leafIndex`. The witness root is mathematically equal to the on-chain
 * `current_root` at the moment when exactly `leaves.length` leaves had been
 * appended (provided the prefix is identical to what was on-chain).
 */
async function buildWitnessForPrefix(
  leaves: Uint8Array[],
  leafIndex: number,
): Promise<MerkleWitness> {
  const shadow = await MerkleShadow.create();
  for (const leaf of leaves) await shadow.append(leaf);
  return shadow.witness(leafIndex);
}

/**
 * Rebuild VALID_SPEND inputs for the buyer's BASE note (note_c) after L1 settle.
 * Caller passes the `tradeWithdrawBuyerBase` object returned from counter-and-match
 * plus `ownerCommitmentHex` + `matchId` for recomputation checks.
 */
export async function POST(req: Request) {
  try {
    const body = (await req.json()) as {
      phantomSignatureBase58?: string;
      ownerPubkeyBase58?: string;
      ownerCommitmentHex?: string;
      matchId?: string;
      tokenMintBase58?: string;
      amount?: string;
      nonce?: string;
      blindingR?: string;
      leafIndex?: string;
      commitmentHex?: string;
      maxSignatures?: number;
    };
    if (
      !body.phantomSignatureBase58 ||
      !body.ownerPubkeyBase58 ||
      !body.ownerCommitmentHex ||
      body.matchId == null ||
      !body.tokenMintBase58 ||
      !body.amount ||
      !body.nonce ||
      !body.blindingR ||
      body.leafIndex == null ||
      !body.commitmentHex
    ) {
      return NextResponse.json(
        { ok: false, error: "missing trade-withdraw-prepare fields" },
        { status: 400 },
      );
    }

    const { seed } = verifyPhantomSeedSignature(
      body.phantomSignatureBase58,
      body.ownerPubkeyBase58,
    );

    const repoRoot = resolveRepoRoot();
    const cfg = loadDemoE2eConfig(repoRoot);
    const { l1 } = getDemoConnections(cfg);
    const { vaultProgramId, baseMint } = parseDemoPrograms(cfg);

    const tokenMint = new PublicKey(body.tokenMintBase58);
    if (!tokenMint.equals(baseMint)) {
      return NextResponse.json(
        { ok: false, error: "only BASE mint (buyer trade leg) is supported" },
        { status: 400 },
      );
    }

    const spendingKey = deriveSpendingKey(seed);
    const ownerBlinding = deriveBlindingFactor(seed, 0n);
    const owner = await ownerCommitment(spendingKey, ownerBlinding);
    const ownerHex = Buffer.from(bn254ToBE32(owner)).toString("hex");
    const wantOwner = body.ownerCommitmentHex.replace(/^0x/, "").toLowerCase();
    if (ownerHex.toLowerCase() !== wantOwner) {
      return NextResponse.json(
        {
          ok: false,
          error: "ownerCommitmentHex does not match derived identity",
        },
        { status: 400 },
      );
    }

    const matchId = BigInt(body.matchId);
    const amount = BigInt(body.amount);
    const nonce = BigInt(body.nonce);
    const blindingR = BigInt(body.blindingR);
    const leafIndex = BigInt(body.leafIndex);

    const nonceBytes = deriveNonce(matchId, TRADE_ROLE_BUYER);
    const blindBytes = deriveBlinding(matchId, TRADE_ROLE_BUYER);
    if (
      nonce !== be32ToBigInt(nonceBytes) ||
      blindingR !== be32ToBigInt(blindBytes)
    ) {
      return NextResponse.json(
        {
          ok: false,
          error:
            "nonce/blindingR do not match deterministic trade-note derivation for matchId",
        },
        { status: 400 },
      );
    }

    const recomputed = await noteCommitment({
      tokenMint: tokenMint.toBytes(),
      amount,
      ownerCommitment: owner,
      nonce,
      blindingR,
    });
    const wantCommit = body.commitmentHex.replace(/^0x/, "").toLowerCase();
    if (Buffer.from(recomputed).toString("hex").toLowerCase() !== wantCommit) {
      return NextResponse.json(
        {
          ok: false,
          error:
            "commitmentHex does not match recomputed note_c for this match",
        },
        { status: 400 },
      );
    }

    const [vaultPda] = vaultConfigPda(vaultProgramId);
    const info = await l1.getAccountInfo(vaultPda, "confirmed");
    if (!info?.data) throw new Error("vault_config missing on L1");
    const liveLeafCount = new DataView(
      info.data.buffer,
      info.data.byteOffset + VAULT_LEAF_COUNT_OFFSET,
      8,
    ).getBigUint64(0, true);

    if (leafIndex >= liveLeafCount) {
      return NextResponse.json(
        {
          ok: false,
          error: `leafIndex ${leafIndex} out of range (leaf_count=${liveLeafCount})`,
        },
        { status: 400 },
      );
    }

    const { current: liveCurrentRoot, ring: liveRoots } = readVaultRoots(
      info.data as Buffer,
    );

    const targetCount = Number(liveLeafCount);
    const leafIndexNum = Number(leafIndex);
    const leaves = await collectVaultLeavesOrdered(
      l1,
      vaultProgramId,
      targetCount,
      {
        maxSignatures: body.maxSignatures ?? 10000,
      },
    );

    // Verify our recomputed note_c matches the leaf the on-chain settle
    // appended at `leafIndex`. If this is wrong, every witness attempt below
    // will fail: surfacing it now produces a clearer error.
    const replayedAtIndex = leaves[leafIndexNum];
    if (
      replayedAtIndex &&
      Buffer.compare(Buffer.from(replayedAtIndex), Buffer.from(recomputed)) !==
        0
    ) {
      return NextResponse.json(
        {
          ok: false,
          error:
            "Replayed leaf at note_c index does not match the recomputed note_c commitment. " +
            "Either the on-chain leaf at this index is a different note or the RPC replay parsed it incorrectly.",
          diagnostics: {
            leafIndex: leafIndex.toString(),
            replayedHex: Buffer.from(replayedAtIndex).toString("hex"),
            recomputedHex: Buffer.from(recomputed).toString("hex"),
            liveLeafCount: liveLeafCount.toString(),
          },
        },
        { status: 409 },
      );
    }

    // Try producing a witness whose root is one of the on-chain "valid" roots
    // (current_root ∪ recent roots[] ring buffer). The on-chain `withdraw`
    // accepts any of these via `VaultConfig::contains_root`, so even if newer
    // leaves invalidate `current_root` matching, an earlier prefix's root may
    // still be live in the ring (for up to 32 leaves of grace).
    let chosen: {
      witness: MerkleWitness;
      matchedRoot: Uint8Array;
      matchedAs: string;
      prefixUsed: number;
    } | null = null;
    const triedPrefixes: number[] = [];

    // Outer loop: walk back from N down to leafIndex+1.
    // (At leafIndex+1 the witness is exactly the root produced when the user's
    // own settle landed — guaranteed to be in the ring if ≤ 32 leaves were
    // added since.)
    const minPrefix = leafIndexNum + 1;
    for (let prefix = targetCount; prefix >= minPrefix; prefix--) {
      triedPrefixes.push(prefix);
      const witness = await buildWitnessForPrefix(
        leaves.slice(0, prefix),
        leafIndexNum,
      );
      const match = findMatchingRoot(witness.root, liveCurrentRoot, liveRoots);
      if (match) {
        chosen = {
          witness,
          matchedRoot: witness.root,
          matchedAs:
            match === "current"
              ? "current_root"
              : `roots[${match.ringIndex}] (historical, ${liveRoots.length - match.ringIndex} back)`,
          prefixUsed: prefix,
        };
        break;
      }
      // Don't burn forever — only keep walking back while there's a chance the
      // root might still be in the ring (size ROOT_HISTORY_SIZE).
      if (targetCount - prefix > VAULT_ROOT_HISTORY_SIZE + 1) break;
    }

    if (!chosen) {
      return NextResponse.json(
        {
          ok: false,
          error:
            "Witness root not found in vault root history (current_root ∪ roots[]). " +
            "RPC replay likely missed or mis-ordered a leaf, OR more than 32 leaves were added " +
            "after your trade settled and your note has aged out of the on-chain ring.",
          diagnostics: {
            liveLeafCount: liveLeafCount.toString(),
            leafIndex: leafIndex.toString(),
            replayedLeafCount: leaves.length,
            triedPrefixes,
            ringSize: liveRoots.length,
            currentRootHex: Buffer.from(liveCurrentRoot).toString("hex"),
            recentRingHex: liveRoots
              .slice(0, Math.min(8, liveRoots.length))
              .map((r) => Buffer.from(r).toString("hex")),
            sampleReplayedHex: leaves
              .slice(Math.max(0, leafIndexNum - 2), leafIndexNum + 4)
              .map((l, i) => ({
                idx: leafIndexNum - 2 + i,
                hex: Buffer.from(l).toString("hex"),
              })),
          },
        },
        { status: 409 },
      );
    }

    const nullifierBytes = await nullifier(spendingKey, recomputed);
    const [mintLo, mintHi] = pubkeyToFrPair(tokenMint.toBytes());

    return NextResponse.json({
      ok: true,
      proverInputs: {
        merkleRoot: beBytesToBigInt(chosen.witness.root).toString(),
        nullifier: beBytesToBigInt(nullifierBytes).toString(),
        tokenMint: [mintLo.toString(), mintHi.toString()],
        amount: amount.toString(),
        spendingKey: spendingKey.toString(),
        ownerCommitmentBlinding: ownerBlinding.toString(),
        nonce: nonce.toString(),
        blindingR: blindingR.toString(),
        merklePath: chosen.witness.siblings.map((s) =>
          beBytesToBigInt(s).toString(),
        ),
        merkleIndices: chosen.witness.indices.map((i) => i.toString()),
      },
      ixContext: {
        commitmentHex: Buffer.from(recomputed).toString("hex"),
        nullifierHex: Buffer.from(nullifierBytes).toString("hex"),
        merkleRootHex: Buffer.from(chosen.witness.root).toString("hex"),
        ownerCommitmentHex: Buffer.from(bn254ToBE32(owner)).toString("hex"),
      },
      replayInfo: {
        liveLeafCount: liveLeafCount.toString(),
        replayedLeafCount: leaves.length,
        prefixUsed: chosen.prefixUsed,
        matchedAs: chosen.matchedAs,
      },
    });
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}
