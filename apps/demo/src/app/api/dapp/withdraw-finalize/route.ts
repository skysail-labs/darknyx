import { buildWithdrawInstruction } from "@nyx/sdk";
import { getAssociatedTokenAddress } from "@solana/spl-token";
import { PublicKey } from "@solana/web3.js";
import { NextResponse } from "next/server";

import {
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

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  return new Uint8Array(Buffer.from(h, "hex"));
}

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as {
      phantomSignatureBase58?: string;
      ownerPubkeyBase58?: string;
      tokenMintBase58?: string;
      amount?: string;
      commitmentHex?: string;
      nullifierHex?: string;
      merkleRootHex?: string;
      proof?: { piA?: string; piB?: string; piC?: string };
    };
    if (
      !body.phantomSignatureBase58 ||
      !body.ownerPubkeyBase58 ||
      !body.tokenMintBase58 ||
      !body.amount ||
      !body.commitmentHex ||
      !body.nullifierHex ||
      !body.merkleRootHex ||
      !body.proof?.piA ||
      !body.proof.piB ||
      !body.proof.piC
    ) {
      return NextResponse.json(
        { ok: false, error: "missing or malformed withdraw-finalize fields" },
        { status: 400 },
      );
    }

    verifyPhantomSeedSignature(
      body.phantomSignatureBase58,
      body.ownerPubkeyBase58,
    );

    const repoRoot = resolveRepoRoot();
    const cfg = loadDemoE2eConfig(repoRoot);
    const { vaultProgramId } = parseDemoPrograms(cfg);

    const owner = new PublicKey(body.ownerPubkeyBase58);
    const tokenMint = new PublicKey(body.tokenMintBase58);
    const destAta = await getAssociatedTokenAddress(tokenMint, owner);

    const ix = buildWithdrawInstruction({
      programId: vaultProgramId,
      payer: owner,
      tokenMint,
      destinationTokenAccount: destAta,
      tokenProgramId: TOKEN_PROGRAM_ID,
      noteCommitment: hexToBytes(body.commitmentHex),
      nullifier: hexToBytes(body.nullifierHex),
      merkleRoot: hexToBytes(body.merkleRootHex),
      amount: BigInt(body.amount),
      proof: {
        piA: hexToBytes(body.proof.piA),
        piB: hexToBytes(body.proof.piB),
        piC: hexToBytes(body.proof.piC),
      },
    });

    return NextResponse.json({
      ok: true,
      instruction: instructionToJson(ix),
      destAtaBase58: destAta.toBase58(),
    });
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}
