import {
  bn254ToBE32,
  deriveDepositInnerHash,
  deriveOwnerCommitmentBlinding,
  deriveSpendingKey,
  merkleTreePda,
  noteCommitmentV2,
  nullifierV2,
  ownerCommitment,
  pubkeyToFrPair,
} from "@nyx/sdk";
import { PublicKey } from "@solana/web3.js";
import { NextResponse } from "next/server";

import {
  getDemoConnections,
  loadDemoE2eConfig,
  parseDemoPrograms,
  resolveRepoRoot,
} from "@/lib/dapp/demo-devnet";
import {
  MERKLE_DEPTH,
  witnessFromPriorRightPath,
} from "@/lib/dapp/merkle-witness";
import { verifyPhantomSeedSignature } from "@/lib/dapp/phantom-verify";

export const runtime = "nodejs";

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  return new Uint8Array(Buffer.from(h, "hex"));
}

function beBytesToBigInt(x: Uint8Array): bigint {
  let acc = 0n;
  for (const b of x) acc = (acc << 8n) | BigInt(b);
  return acc;
}

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as {
      phantomSignatureBase58?: string;
      ownerPubkeyBase58?: string;
      tokenMintBase58?: string;
      amount?: string;
      recoveryNonce?: string;
      innerHash?: string;
      leafIndex?: string;
      priorRightPathHex?: string[];
    };
    if (
      !body.phantomSignatureBase58 ||
      !body.ownerPubkeyBase58 ||
      !body.tokenMintBase58 ||
      !body.amount ||
      !body.recoveryNonce ||
      !body.innerHash ||
      body.leafIndex == null ||
      !body.priorRightPathHex ||
      body.priorRightPathHex.length !== MERKLE_DEPTH
    ) {
      return NextResponse.json(
        { ok: false, error: "missing or malformed withdraw-prepare fields" },
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
    const { vaultProgramId } = parseDemoPrograms(cfg);

    const tokenMint = new PublicKey(body.tokenMintBase58);
    const amount = BigInt(body.amount);
    const recoveryNonce = BigInt(body.recoveryNonce);
    const innerHash = BigInt(body.innerHash);
    const leafIndex = BigInt(body.leafIndex);

    const spendingKey = deriveSpendingKey(seed);
    const ownerBlinding = deriveOwnerCommitmentBlinding(seed);
    const owner = await ownerCommitment(spendingKey, ownerBlinding);
    const derivedInner = beBytesToBigInt(
      await deriveDepositInnerHash(
        bn254ToBE32(owner),
        bn254ToBE32(recoveryNonce),
      ),
    );
    if (derivedInner !== innerHash) {
      return NextResponse.json(
        { ok: false, error: "deposit recovery nonce does not derive inner hash" },
        { status: 400 },
      );
    }

    const commitment = await noteCommitmentV2({
      tokenMint: tokenMint.toBytes(),
      amount,
      ownerCommitment: owner,
      innerHash,
    });

    const [treePda] = merkleTreePda(vaultProgramId, 0);
    const info = await l1.getAccountInfo(treePda, "confirmed");
    if (!info) throw new Error("merkle_tree(0) missing on L1");
    const liveLeafCount = new DataView(
      info.data.buffer,
      info.data.byteOffset + 8,
      8,
    ).getBigUint64(0, true);
    if (liveLeafCount !== leafIndex + 1n) {
      return NextResponse.json(
        {
          ok: false,
          error:
            "vault leaf_count moved since deposit (live=" +
            liveLeafCount +
            ", expected=" +
            (leafIndex + 1n) +
            "). Demo withdraw needs your deposit to be the most-recent leaf.",
        },
        { status: 409 },
      );
    }

    const priorRightPath = body.priorRightPathHex.map(hexToBytes);
    const witness = await witnessFromPriorRightPath(
      commitment,
      leafIndex,
      priorRightPath,
    );

    const liveCurrentRoot = info.data.subarray(16, 48);
    if (
      Buffer.compare(
        Buffer.from(liveCurrentRoot),
        Buffer.from(witness.root),
      ) !== 0
    ) {
      return NextResponse.json(
        {
          ok: false,
          error:
            "computed Merkle root does not match on-chain current_root — your deposit may not have landed yet, or another append slipped in.",
        },
        { status: 409 },
      );
    }

    const nullifierBytes = await nullifierV2(spendingKey, innerHash);
    const [mintLo, mintHi] = pubkeyToFrPair(tokenMint.toBytes());

    return NextResponse.json({
      ok: true,
      proverInputs: {
        merkleRoot: beBytesToBigInt(witness.root).toString(),
        nullifier: beBytesToBigInt(nullifierBytes).toString(),
        tokenMint: [mintLo.toString(), mintHi.toString()],
        amount: amount.toString(),
        spendingKey: spendingKey.toString(),
        ownerCommitmentBlinding: ownerBlinding.toString(),
        innerHash: innerHash.toString(),
        merklePath: witness.siblings.map((s) => beBytesToBigInt(s).toString()),
        merkleIndices: witness.indices.map((i) => i.toString()),
      },
      ixContext: {
        commitmentHex: Buffer.from(commitment).toString("hex"),
        nullifierHex: Buffer.from(nullifierBytes).toString("hex"),
        merkleRootHex: Buffer.from(witness.root).toString("hex"),
        ownerCommitmentHex: Buffer.from(bn254ToBE32(owner)).toString("hex"),
      },
    });
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}
