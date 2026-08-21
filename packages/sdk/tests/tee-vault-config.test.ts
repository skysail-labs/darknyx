import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Keypair } from "@solana/web3.js";

import {
  NUM_TEE_KEYS_OFFSET,
  NUM_TREES_OFFSET,
  TEE_PUBKEYS_OFFSET,
  VAULT_CONFIG_ACCOUNT_LEN,
  assertTeePubkeysMatch,
  vaultConfigTeePubkeys,
} from "../src/index.js";
import { dummyAddress } from "./helpers/e2e-helpers.js";

function buildVaultConfig(pubkeys: Uint8Array[]): Uint8Array {
  const data = new Uint8Array(VAULT_CONFIG_ACCOUNT_LEN);
  data.set(
    createHash("sha256").update("account:VaultConfig").digest().subarray(0, 8),
  );
  pubkeys.forEach((pk, i) => data.set(pk, TEE_PUBKEYS_OFFSET + i * 32));
  data[NUM_TEE_KEYS_OFFSET] = pubkeys.length;
  data[NUM_TREES_OFFSET] = pubkeys.length;
  return data;
}

describe("vaultConfigTeePubkeys", () => {
  it("pins the on-chain offsets (mirror of VaultConfig)", () => {
    expect(TEE_PUBKEYS_OFFSET).toBe(40);
    expect(NUM_TEE_KEYS_OFFSET).toBe(1258);
    expect(NUM_TREES_OFFSET).toBe(1259);
    expect(VAULT_CONFIG_ACCOUNT_LEN).toBe(1264);
  });

  it("reads exactly num_tee_keys pubkeys in order", async () => {
    const kps = [
      await Keypair.generate(),
      await Keypair.generate(),
      await Keypair.generate(),
    ];
    const data = buildVaultConfig(kps.map((k) => k.publicKey.toBytes()));
    // A 4th key sits in the array bytes but num_tee_keys=3 → must be ignored.
    data.set(dummyAddress().toBytes(), TEE_PUBKEYS_OFFSET + 3 * 32);
    expect(vaultConfigTeePubkeys(data)).toEqual(
      kps.map((k) => k.publicKey.toBase58()),
    );
  });

  it("rejects wrong layout, discriminator, and out-of-range counts", () => {
    expect(() => vaultConfigTeePubkeys(new Uint8Array(100))).toThrow(
      /account length/,
    );
    const wrongDiscriminator = buildVaultConfig([dummyAddress().toBytes()]);
    wrongDiscriminator[0] ^= 1;
    expect(() => vaultConfigTeePubkeys(wrongDiscriminator)).toThrow(
      /discriminator/,
    );
    const bad = buildVaultConfig([dummyAddress().toBytes()]);
    bad[NUM_TEE_KEYS_OFFSET] = 0;
    expect(() => vaultConfigTeePubkeys(bad)).toThrow(/out of range/);
    bad[NUM_TEE_KEYS_OFFSET] = 17;
    expect(() => vaultConfigTeePubkeys(bad)).toThrow(/out of range/);
  });

  it("rejects signer/tree mismatch, zero keys, and duplicate keys", () => {
    const key = dummyAddress().toBytes();
    const mismatch = buildVaultConfig([key]);
    mismatch[NUM_TREES_OFFSET] = 2;
    expect(() => vaultConfigTeePubkeys(mismatch)).toThrow(/count mismatch/);

    const zero = buildVaultConfig([new Uint8Array(32)]);
    expect(() => vaultConfigTeePubkeys(zero)).toThrow(/zero or duplicated/);

    const duplicate = buildVaultConfig([key, key]);
    expect(() => vaultConfigTeePubkeys(duplicate)).toThrow(
      /zero or duplicated/,
    );
  });
});

describe("assertTeePubkeysMatch", () => {
  const a = dummyAddress().toBase58();
  const b = dummyAddress().toBase58();

  it("accepts an order-independent set match", () => {
    expect(() => assertTeePubkeysMatch([a, b], [b, a])).not.toThrow();
  });

  it("rejects an extra on-chain key (vault trusts a key the enclave lacks)", () => {
    const c = dummyAddress().toBase58();
    expect(() => assertTeePubkeysMatch([a, b], [a, b, c])).toThrow(
      /!= on-chain/,
    );
  });

  it("rejects a substituted key", () => {
    const c = dummyAddress().toBase58();
    let kind = "";
    try {
      assertTeePubkeysMatch([a, b], [a, c]);
    } catch (e) {
      kind = (e as { kind: string }).kind;
    }
    expect(kind).toBe("pubkey_mismatch");
  });
});
