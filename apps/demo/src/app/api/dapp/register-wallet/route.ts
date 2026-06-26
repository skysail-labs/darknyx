import {
  bn254ToBE32,
  buildCreateWalletInstruction,
  deriveBlindingFactor,
  deriveMasterViewingKey,
  deriveRootKey,
  deriveSpendingKey,
  ownerCommitment,
  userCommitmentFromKeys,
  walletEntryPda,
  type Groth16OnChainProof,
} from "@nyx/sdk";
import { PublicKey } from "@solana/web3.js";
import { NextResponse } from "next/server";
import nacl from "tweetnacl";

import {
  getDemoConnections,
  loadDemoE2eConfig,
  parseDemoPrograms,
  resolveRepoRoot,
} from "@/lib/dapp/demo-devnet";
import { instructionToJson } from "@/lib/dapp/ix-json";
import { verifyPhantomSeedSignature } from "@/lib/dapp/phantom-verify";

export const runtime = "nodejs";

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) throw new Error("invalid hex length");
  return new Uint8Array(Buffer.from(h, "hex"));
}

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as {
      phantomSignatureBase58?: string;
      ownerPubkeyBase58?: string;
      proof?: { piAHex?: string; piBHex?: string; piCHex?: string };
    };
    if (
      !body.phantomSignatureBase58 ||
      !body.ownerPubkeyBase58 ||
      !body.proof?.piAHex
    ) {
      return NextResponse.json(
        {
          ok: false,
          error: "missing phantomSignatureBase58, ownerPubkeyBase58, or proof",
        },
        { status: 400 },
      );
    }
    const { seed } = verifyPhantomSeedSignature(
      body.phantomSignatureBase58,
      body.ownerPubkeyBase58,
    );

    const spendingKey = deriveSpendingKey(seed);
    const viewingKey = deriveMasterViewingKey(seed);
    const rootKeyRaw = deriveRootKey(seed);
    const rootKeyPubkey = nacl.sign.keyPair.fromSeed(
      rootKeyRaw.secretKey,
    ).publicKey;
    const ownerBlinding = deriveBlindingFactor(seed, 0n);
    const r0 = deriveBlindingFactor(seed, 1n);
    const r1 = deriveBlindingFactor(seed, 2n);
    const r2 = deriveBlindingFactor(seed, 3n);
    const userCommitmentBE = await userCommitmentFromKeys({
      rootKeyPubkey,
      spendingKey,
      viewingKey,
      r0,
      r1,
      r2,
    });
    const ownerCommit = await ownerCommitment(spendingKey, ownerBlinding);

    const piA = hexToBytes(body.proof.piAHex!);
    const piB = hexToBytes(body.proof.piBHex!);
    const piC = hexToBytes(body.proof.piCHex!);
    if (piA.length !== 64 || piB.length !== 128 || piC.length !== 64) {
      return NextResponse.json(
        {
          ok: false,
          error: `bad proof sizes: piA ${piA.length} piB ${piB.length} piC ${piC.length}`,
        },
        { status: 400 },
      );
    }
    const proof: Groth16OnChainProof = { piA, piB, piC };

    const repoRoot = resolveRepoRoot();
    const cfg = loadDemoE2eConfig(repoRoot);
    const { vaultProgramId } = parseDemoPrograms(cfg);
    const { l1 } = getDemoConnections(cfg);
    const owner = new PublicKey(body.ownerPubkeyBase58);

    const [walletPda] = walletEntryPda(vaultProgramId, userCommitmentBE);
    const existing = await l1.getAccountInfo(walletPda, "confirmed");
    if (existing) {
      // create_wallet is a one-shot allocation; if the user re-runs this flow
      // (e.g. after a page reload), short-circuit so the UI can advance.
      return NextResponse.json({
        ok: true,
        alreadyRegistered: true,
        walletPdaBase58: walletPda.toBase58(),
        publicData: {
          userCommitmentHex: Buffer.from(userCommitmentBE).toString("hex"),
          ownerCommitmentHex: Buffer.from(bn254ToBE32(ownerCommit)).toString(
            "hex",
          ),
        },
      });
    }

    const ix = buildCreateWalletInstruction({
      programId: vaultProgramId,
      owner,
      commitment: userCommitmentBE,
      proof,
    });

    return NextResponse.json({
      ok: true,
      alreadyRegistered: false,
      walletPdaBase58: walletPda.toBase58(),
      instruction: instructionToJson(ix),
      publicData: {
        userCommitmentHex: Buffer.from(userCommitmentBE).toString("hex"),
        ownerCommitmentHex: Buffer.from(bn254ToBE32(ownerCommit)).toString(
          "hex",
        ),
      },
    });
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}
