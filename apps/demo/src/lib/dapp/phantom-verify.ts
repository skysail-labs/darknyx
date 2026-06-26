import { createHash } from "node:crypto";

import bs58 from "bs58";
import nacl from "tweetnacl";

const SEED_MESSAGE = new TextEncoder().encode("NYX_DARKPOOL_SEED_V1");
export const MASTER_SEED_BYTES = 64;

export function verifyPhantomSeedSignature(
  phantomSignatureBase58: string,
  ownerPubkeyBase58: string,
): { ownerPubkey: Uint8Array; signature: Uint8Array; seed: Uint8Array } {
  const signature = bs58.decode(phantomSignatureBase58);
  const ownerPubkey = bs58.decode(ownerPubkeyBase58);
  if (signature.length !== 64 || ownerPubkey.length !== 32) {
    throw new Error(
      `expected 64B sig + 32B pubkey, got ${signature.length}B + ${ownerPubkey.length}B`,
    );
  }
  if (!nacl.sign.detached.verify(SEED_MESSAGE, signature, ownerPubkey)) {
    throw new Error("Phantom signature does not verify against owner pubkey");
  }
  const seed = new Uint8Array(
    createHash("sha512")
      .update(Buffer.from(signature))
      .digest()
      .subarray(0, MASTER_SEED_BYTES),
  );
  return { ownerPubkey, signature, seed };
}
