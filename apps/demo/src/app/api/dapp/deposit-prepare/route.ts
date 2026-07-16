import {
  buildDepositInstruction,
  deriveBlindingFactor,
  deriveDepositInnerHash,
  deriveOwnerCommitmentBlinding,
  deriveSpendingKey,
  nodeValidDepositProver,
  noteCommitmentV2,
  ownerCommitment,
  bn254ToBE32,
  pubkeyToFrPair,
} from "@nyx/sdk";
import { getAssociatedTokenAddress } from "@solana/spl-token";
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
    const depositIndex =
      body.nonce != null ? BigInt(body.nonce) : BigInt(Date.now());

    const repoRoot = resolveRepoRoot();
    const cfg = loadDemoE2eConfig(repoRoot);
    const { l1 } = getDemoConnections(cfg);
    const { vaultProgramId, baseMint, quoteMint } = parseDemoPrograms(cfg);
    const tokenMint = body.side === "base" ? baseMint : quoteMint;
    const tokenMintBytes = tokenMint.toBytes();

    const spendingKey = deriveSpendingKey(seed);
    const ownerBlinding = deriveOwnerCommitmentBlinding(seed);
    const recoveryNonce = deriveBlindingFactor(seed, depositIndex);
    const owner = await ownerCommitment(spendingKey, ownerBlinding);
    const ownerBytes = bn254ToBE32(owner);
    const innerHash = bytesToBigInt(
      await deriveDepositInnerHash(
        ownerBytes,
        bn254ToBE32(recoveryNonce),
      ),
    );
    const commitment = await noteCommitmentV2({
      tokenMint: tokenMintBytes,
      amount,
      ownerCommitment: owner,
      innerHash,
    });
    const [mintLo, mintHi] = pubkeyToFrPair(tokenMintBytes);
    const proof = await nodeValidDepositProver({
      wasmPath: `${repoRoot}/circuits/build/valid_deposit/circuit_js/circuit.wasm`,
      zkeyPath: `${repoRoot}/circuits/build/valid_deposit/circuit_final.zkey`,
    }).prove({
      noteCommitment: bytesToBigInt(commitment),
      tokenMint: [mintLo, mintHi],
      amount,
      recoveryNonce,
      spendingKey,
      ownerCommitmentBlinding: ownerBlinding,
    });

    const depositor = new PublicKey(body.ownerPubkeyBase58);
    const depositorTokenAccount = await getAssociatedTokenAddress(
      tokenMint,
      depositor,
    );

    const ix = buildDepositInstruction({
      programId: vaultProgramId,
      treeId: 0,
      depositor,
      tokenMint,
      depositorTokenAccount,
      tokenProgramId: TOKEN_PROGRAM_ID,
      amount,
      noteCommitment: commitment,
      recoveryNonce: bn254ToBE32(recoveryNonce),
      proof,
    });

    return NextResponse.json({
      ok: true,
      instruction: instructionToJson(ix),
      preview: {
        depositIndex: depositIndex.toString(),
        noteCommitmentHex: Buffer.from(commitment).toString("hex"),
        recoveryNonce: recoveryNonce.toString(),
        ownerCommitmentHex: Buffer.from(ownerBytes).toString("hex"),
        ownerCommitForOrderHex: Buffer.from(ownerBytes).toString("hex"),
      },
    });
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const byte of bytes) out = (out << 8n) | BigInt(byte);
  return out;
}
