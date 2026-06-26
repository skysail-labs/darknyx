import {
  bn254ToBE32,
  buildDepositInstruction,
  deriveBlindingFactor,
  deriveSpendingKey,
  noteCommitment,
  ownerCommitment,
  vaultConfigPda,
} from "@nyx/sdk";
import {
  createAssociatedTokenAccountIdempotentInstruction,
  getAssociatedTokenAddress,
} from "@solana/spl-token";
import { PublicKey } from "@solana/web3.js";
import { NextResponse } from "next/server";

import {
  getDemoConnections,
  loadDemoE2eConfig,
  parseDemoPrograms,
  resolveRepoRoot,
} from "@/lib/dapp/demo-devnet";
import { instructionToJson } from "@/lib/dapp/ix-json";
import { verifyPhantomSeedSignature } from "@/lib/dapp/phantom-verify";

export const runtime = "nodejs";

const TOKEN_PROGRAM_ID = new PublicKey(
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
);

const RIGHT_PATH_OFFSET = 1808;
const MERKLE_DEPTH = 20;

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as {
      phantomSignatureBase58?: string;
      ownerPubkeyBase58?: string;
      side?: "base" | "quote";
      amount?: string;
      nonce?: string;
    };
    if (
      !body.phantomSignatureBase58 ||
      !body.ownerPubkeyBase58 ||
      !body.side ||
      !body.amount
    ) {
      return NextResponse.json(
        {
          ok: false,
          error:
            "missing phantomSignatureBase58, ownerPubkeyBase58, side, or amount",
        },
        { status: 400 },
      );
    }

    const { seed } = verifyPhantomSeedSignature(
      body.phantomSignatureBase58,
      body.ownerPubkeyBase58,
    );
    const amount = BigInt(body.amount);
    if (amount <= 0n) {
      return NextResponse.json(
        { ok: false, error: "amount must be > 0" },
        { status: 400 },
      );
    }
    const nonce = body.nonce != null ? BigInt(body.nonce) : BigInt(Date.now());

    const repoRoot = resolveRepoRoot();
    const cfg = loadDemoE2eConfig(repoRoot);
    const { l1 } = getDemoConnections(cfg);
    const { vaultProgramId, baseMint, quoteMint } = parseDemoPrograms(cfg);
    const tokenMint = body.side === "base" ? baseMint : quoteMint;
    const tokenMintBytes = tokenMint.toBytes();

    const spendingKey = deriveSpendingKey(seed);
    const ownerBlinding = deriveBlindingFactor(seed, 0n);

    const [vaultPda] = vaultConfigPda(vaultProgramId);
    const info = await l1.getAccountInfo(vaultPda, "confirmed");
    if (!info) throw new Error("vault_config missing on L1");
    const data = info.data;
    const leafCount = new DataView(
      data.buffer,
      data.byteOffset + 104,
      8,
    ).getBigUint64(0, true);

    const priorRightPath: string[] = [];
    for (let i = 0; i < MERKLE_DEPTH; i++) {
      const slice = data.subarray(
        RIGHT_PATH_OFFSET + i * 32,
        RIGHT_PATH_OFFSET + (i + 1) * 32,
      );
      priorRightPath.push(Buffer.from(slice).toString("hex"));
    }

    const blindingR = deriveBlindingFactor(seed, leafCount);
    const owner = await ownerCommitment(spendingKey, ownerBlinding);
    const commitment = await noteCommitment({
      tokenMint: tokenMintBytes,
      amount,
      ownerCommitment: owner,
      nonce,
      blindingR,
    });

    const ownerBytes = bn254ToBE32(owner);
    const nonceBytes = bn254ToBE32(nonce);
    const blindingBytes = bn254ToBE32(blindingR);

    const depositor = new PublicKey(body.ownerPubkeyBase58);
    const depositorTokenAccount = await getAssociatedTokenAddress(
      tokenMint,
      depositor,
    );

    const createAtaIx = createAssociatedTokenAccountIdempotentInstruction(
      depositor,
      depositorTokenAccount,
      depositor,
      tokenMint,
    );

    const ix = buildDepositInstruction({
      programId: vaultProgramId,
      depositor,
      tokenMint,
      depositorTokenAccount,
      tokenProgramId: TOKEN_PROGRAM_ID,
      amount,
      ownerCommitment: ownerBytes,
      nonce: nonceBytes,
      blindingR: blindingBytes,
    });

    return NextResponse.json({
      ok: true,
      instructions: [instructionToJson(createAtaIx), instructionToJson(ix)],
      tracking: {
        leafIndex: leafCount.toString(),
        priorLeafCount: leafCount.toString(),
        priorRightPathHex: priorRightPath,
        commitmentHex: Buffer.from(commitment).toString("hex"),
        nonce: nonce.toString(),
        blindingR: blindingR.toString(),
        amount: amount.toString(),
        side: body.side,
        tokenMintBase58: tokenMint.toBase58(),
      },
    });
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}
