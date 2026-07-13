import { describe, expect, it } from "vitest";
import { Keypair } from "@solana/web3.js";

import {
  NUM_TEE_KEYS_OFFSET,
  TEE_PUBKEYS_OFFSET,
  assertTeePubkeysMatch,
  vaultConfigTeePubkeys,
} from "../src/index.js";

const ACCOUNT_LEN = 1288; // VaultConfig after the appended matcher params

function buildVaultConfig(pubkeys: Uint8Array[]): Uint8Array {
  const data = new Uint8Array(ACCOUNT_LEN);
  pubkeys.forEach((pk, i) => data.set(pk, TEE_PUBKEYS_OFFSET + i * 32));
  data[NUM_TEE_KEYS_OFFSET] = pubkeys.length;
  return data;
}

describe("vaultConfigTeePubkeys", () => {
  it("pins the on-chain offsets (mirror of VaultConfig)", () => {
    expect(TEE_PUBKEYS_OFFSET).toBe(40);
    expect(NUM_TEE_KEYS_OFFSET).toBe(1258);
  });

  it("reads exactly num_tee_keys pubkeys in order", () => {
    const kps = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
    const data = buildVaultConfig(kps.map((k) => k.publicKey.toBytes()));
    // A 4th key sits in the array bytes but num_tee_keys=3 → must be ignored.
    data.set(
      Keypair.generate().publicKey.toBytes(),
      TEE_PUBKEYS_OFFSET + 3 * 32,
    );
    expect(vaultConfigTeePubkeys(data)).toEqual(
      kps.map((k) => k.publicKey.toBase58()),
    );
  });

  it("rejects a short buffer and an out-of-range count", () => {
    expect(() => vaultConfigTeePubkeys(new Uint8Array(100))).toThrow(
      /too short/,
    );
    const bad = buildVaultConfig([Keypair.generate().publicKey.toBytes()]);
    bad[NUM_TEE_KEYS_OFFSET] = 0;
    expect(() => vaultConfigTeePubkeys(bad)).toThrow(/out of range/);
    bad[NUM_TEE_KEYS_OFFSET] = 17;
    expect(() => vaultConfigTeePubkeys(bad)).toThrow(/out of range/);
  });
});

describe("assertTeePubkeysMatch", () => {
  const a = Keypair.generate().publicKey.toBase58();
  const b = Keypair.generate().publicKey.toBase58();

  it("accepts an order-independent set match", () => {
    expect(() => assertTeePubkeysMatch([a, b], [b, a])).not.toThrow();
  });

  it("rejects an extra on-chain key (vault trusts a key the enclave lacks)", () => {
    const c = Keypair.generate().publicKey.toBase58();
    expect(() => assertTeePubkeysMatch([a, b], [a, b, c])).toThrow(
      /!= on-chain/,
    );
  });

  it("rejects a substituted key", () => {
    const c = Keypair.generate().publicKey.toBase58();
    let kind = "";
    try {
      assertTeePubkeysMatch([a, b], [a, c]);
    } catch (e) {
      kind = (e as { kind: string }).kind;
    }
    expect(kind).toBe("pubkey_mismatch");
  });
});
