/**
 * /api/dapp/derive-identity — POST
 *
 * Body: `{ phantomSignatureBase58: string, ownerPubkeyBase58: string }`
 *
 * Verifies the Phantom signature, derives the darkpool key hierarchy, and
 * returns circuit witness fields for `VALID_WALLET_CREATE` plus a **demo-only**
 * trading keypair used to sign `submit_order` on the Ephemeral Rollup (Phantom
 * cannot sign as the trading key — it is a separate Ed25519 key derived from
 * the same master seed).
 *
 * Security: this is a devnet demo. The response includes long-lived secrets
 * (`walletCreateInputs` scalars + `trading.secretKeyBase58`). Treat the HTTPS
 * transport + short session lifetime as the threat model, not bank-grade
 * custody.
 */

import {
  bn254ToBE32,
  deriveBlindingFactor,
  deriveMasterViewingKey,
  deriveRootKey,
  deriveSpendingKey,
  deriveTradingKeyAtOffset,
  ownerCommitment,
  pubkeyToFrPair,
  userCommitmentFromKeys,
} from "@nyx/sdk";
import { NextResponse } from "next/server";
import bs58 from "bs58";
import nacl from "tweetnacl";

import { verifyPhantomSeedSignature } from "@/lib/dapp/phantom-verify";

export const runtime = "nodejs";

interface DeriveIdentityRequest {
  phantomSignatureBase58: string;
  ownerPubkeyBase58: string;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function bytesToBigInt(b: Uint8Array): bigint {
  if (b.length === 0) return 0n;
  return BigInt("0x" + bytesToHex(b));
}

export async function POST(req: Request) {
  let body: DeriveIdentityRequest;
  try {
    body = (await req.json()) as DeriveIdentityRequest;
  } catch {
    return NextResponse.json(
      { ok: false, error: "invalid JSON body" },
      { status: 400 },
    );
  }

  if (!body.phantomSignatureBase58 || !body.ownerPubkeyBase58) {
    return NextResponse.json(
      {
        ok: false,
        error: "missing phantomSignatureBase58 or ownerPubkeyBase58",
      },
      { status: 400 },
    );
  }

  let seed: Uint8Array;
  try {
    ({ seed } = verifyPhantomSeedSignature(
      body.phantomSignatureBase58,
      body.ownerPubkeyBase58,
    ));
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }

  const spendingKey = deriveSpendingKey(seed);
  const viewingKey = deriveMasterViewingKey(seed);
  const rootKeyRaw = deriveRootKey(seed);
  const rootEd25519 = nacl.sign.keyPair.fromSeed(rootKeyRaw.secretKey);
  const rootKeyPubkey = rootEd25519.publicKey;

  const tradingSeed = deriveTradingKeyAtOffset(seed, 0n).secretKey;
  const tradingNacl = nacl.sign.keyPair.fromSeed(tradingSeed);

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
  const userCommitmentBigint = bytesToBigInt(userCommitmentBE);

  const ownerCommit = await ownerCommitment(spendingKey, ownerBlinding);

  const [rootLo, rootHi] = pubkeyToFrPair(rootKeyPubkey);

  const walletCreateInputs = {
    userCommitment: userCommitmentBigint.toString(),
    rootKey: [rootLo.toString(), rootHi.toString()] as [string, string],
    spendingKey: spendingKey.toString(),
    viewingKey: viewingKey.toString(),
    r0: r0.toString(),
    r1: r1.toString(),
    r2: r2.toString(),
  };

  return NextResponse.json({
    ok: true,
    rootKeyPubkeyBase58: bs58.encode(rootKeyPubkey),
    walletCreateInputs,
    trading: {
      publicKeyBase58: bs58.encode(tradingNacl.publicKey),
      /** 64-byte Ed25519 secret (`@solana/web3.js` `Keypair.fromSecretKey`). */
      secretKeyBase58: bs58.encode(tradingNacl.secretKey),
    },
    publicData: {
      userCommitmentHex: bytesToHex(userCommitmentBE),
      ownerCommitmentHex: bytesToHex(bn254ToBE32(ownerCommit)),
      ownerCommitmentDecimal: ownerCommit.toString(),
      rootKeyPubkeyBase58: bs58.encode(rootKeyPubkey),
    },
    previews: {
      masterSeedFingerprint: bytesToHex(seed.subarray(0, 6)),
      spendingKeyFingerprint: spendingKey.toString(16).slice(0, 12),
      viewingKeyFingerprint: viewingKey.toString(16).slice(0, 12),
    },
  });
}
