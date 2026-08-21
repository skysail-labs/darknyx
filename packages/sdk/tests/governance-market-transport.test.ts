import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";

import {
  buildInitializeInstruction,
  buildInitializeMarketInstruction,
  buildRotateRootKeyInstruction,
  buildSetProtocolConfigInstruction,
  buildSetTeePubkeyInstruction,
  buildUpdateMarketConfigInstruction,
  marketConfigPda,
} from "../src/idl/vault-client.js";
import {
  MARKET_CONFIG_ACCOUNT_LEN,
  decodeMarketConfig,
} from "../src/tee/market-config.js";

const PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

function discriminator(namespace: "global" | "account", name: string): Buffer {
  return createHash("sha256")
    .update(`${namespace}:${name}`)
    .digest()
    .subarray(0, 8);
}

function readU64(data: Uint8Array, offset: number): bigint {
  return new DataView(
    data.buffer,
    data.byteOffset,
    data.byteLength,
  ).getBigUint64(offset, true);
}

describe("governance initialization transport", () => {
  it("serializes a distinct operations admin and complete shard signer set", async () => {
    const initializer = Keypair.generate().publicKey;
    const operationsAdmin = Keypair.generate().publicKey;
    const teePubkeys = [
      Keypair.generate().publicKey,
      Keypair.generate().publicKey,
    ];
    const rootKey = Keypair.generate().publicKey;
    const ix = await buildInitializeInstruction({
      programId: PROGRAM_ID,
      initializer,
      operationsAdmin,
      teePubkeys,
      rootKey,
      numTrees: 2,
    });

    expect(ix.keys).toHaveLength(3);
    expect(ix.keys[0]).toMatchObject({
      pubkey: initializer,
      isSigner: true,
      isWritable: true,
    });
    expect(ix.keys[2].pubkey.equals(SystemProgram.programId)).toBe(true);
    expect(ix.data.subarray(0, 8)).toEqual(
      discriminator("global", "initialize"),
    );
    expect(ix.data.subarray(8, 40)).toEqual(
      Buffer.from(operationsAdmin.toBytes()),
    );
    expect(ix.data.readUInt32LE(40)).toBe(2);
    expect(ix.data.subarray(44, 76)).toEqual(
      Buffer.from(teePubkeys[0].toBytes()),
    );
    expect(ix.data.subarray(76, 108)).toEqual(
      Buffer.from(teePubkeys[1].toBytes()),
    );
    expect(ix.data.subarray(108, 140)).toEqual(Buffer.from(rootKey.toBytes()));
    expect(ix.data[140]).toBe(2);
  });

  it("adds the program and ProgramData accounts for mainnet initialization", async () => {
    const programData = Keypair.generate().publicKey;
    const ix = await buildInitializeInstruction({
      programId: PROGRAM_ID,
      initializer: Keypair.generate().publicKey,
      operationsAdmin: Keypair.generate().publicKey,
      teePubkeys: [Keypair.generate().publicKey],
      rootKey: Keypair.generate().publicKey,
      numTrees: 1,
      programData,
    });
    expect(ix.keys).toHaveLength(5);
    expect(ix.keys[2].pubkey.equals(PROGRAM_ID)).toBe(true);
    expect(ix.keys[3].pubkey.equals(programData)).toBe(true);
    expect(ix.keys[4].pubkey.equals(SystemProgram.programId)).toBe(true);
  });

  it("rejects default, partial, and duplicate authority sets", async () => {
    const common = {
      programId: PROGRAM_ID,
      initializer: Keypair.generate().publicKey,
      operationsAdmin: Keypair.generate().publicKey,
      rootKey: Keypair.generate().publicKey,
      numTrees: 2,
    };
    const tee = Keypair.generate().publicKey;
    await expect(
      buildInitializeInstruction({ ...common, teePubkeys: [tee] }),
    ).rejects.toThrow(/must equal numTrees/);
    await expect(
      buildInitializeInstruction({ ...common, teePubkeys: [tee, tee] }),
    ).rejects.toThrow(/non-default, unique/);
    await expect(
      buildInitializeInstruction({
        ...common,
        operationsAdmin: PublicKey.default,
        teePubkeys: [tee, Keypair.generate().publicKey],
      }),
    ).rejects.toThrow(/operationsAdmin/);
    await expect(
      buildInitializeInstruction({
        ...common,
        operationsAdmin: common.rootKey,
        teePubkeys: [tee, Keypair.generate().publicKey],
      }),
    ).rejects.toThrow(/distinct from rootKey/);
    await expect(
      buildInitializeInstruction({
        ...common,
        teePubkeys: [common.operationsAdmin, tee],
      }),
    ).rejects.toThrow(/distinct from governance keys/);
  });
});

describe("MarketConfig transport", () => {
  const admin = Keypair.generate().publicKey;
  const baseMint = Keypair.generate().publicKey;
  const quoteMint = Keypair.generate().publicKey;
  const market = {
    programId: PROGRAM_ID,
    admin,
    baseMint,
    quoteMint,
    priceScale: 100_000_000n,
    tickSize: 5n,
    minOrderSize: 1_000n,
    circuitBreakerBps: 5_000n,
  };

  it("pins the PDA, account ordering, and initialize/update wire layouts", async () => {
    const [marketPda] = await marketConfigPda(PROGRAM_ID, baseMint, quoteMint);
    const init = await buildInitializeMarketInstruction(market);
    expect(init.keys).toHaveLength(6);
    expect(init.keys[2].pubkey.equals(baseMint)).toBe(true);
    expect(init.keys[3].pubkey.equals(quoteMint)).toBe(true);
    expect(init.keys[4].pubkey.equals(marketPda)).toBe(true);
    expect(init.data).toHaveLength(40);
    expect(init.data.subarray(0, 8)).toEqual(
      discriminator("global", "initialize_market"),
    );
    expect(readU64(init.data, 8)).toBe(100_000_000n);
    expect(readU64(init.data, 16)).toBe(5n);
    expect(readU64(init.data, 24)).toBe(1_000n);
    expect(readU64(init.data, 32)).toBe(5_000n);

    const update = await buildUpdateMarketConfigInstruction({
      ...market,
      enabled: false,
    });
    expect(update.keys).toHaveLength(3);
    expect(update.keys[2].pubkey.equals(marketPda)).toBe(true);
    expect(update.data).toHaveLength(41);
    expect(update.data.subarray(0, 8)).toEqual(
      discriminator("global", "update_market_config"),
    );
    expect(update.data[8]).toBe(0);
    expect(readU64(update.data, 9)).toBe(100_000_000n);
  });

  it("separates protocol fee wire data from market parameters", async () => {
    const owner = new Uint8Array(32).fill(7);
    const protocol = await buildSetProtocolConfigInstruction({
      programId: PROGRAM_ID,
      admin,
      protocolOwnerCommitment: owner,
      feeRateBps: 30,
    });
    expect(protocol.data).toHaveLength(42);
    expect(protocol.data.subarray(0, 8)).toEqual(
      discriminator("global", "set_protocol_config"),
    );
    expect(protocol.data.subarray(8, 40)).toEqual(Buffer.from(owner));
    expect(protocol.data.readUInt16LE(40)).toBe(30);
  });

  it("requires valid bounded parameters and distinct mints", async () => {
    await expect(
      buildInitializeMarketInstruction({ ...market, priceScale: 0n }),
    ).rejects.toThrow(/invalid market parameters/);
    await expect(
      buildInitializeMarketInstruction({
        ...market,
        circuitBreakerBps: 10_001n,
      }),
    ).rejects.toThrow(/invalid market parameters/);
    await expect(
      buildInitializeMarketInstruction({ ...market, quoteMint: baseMint }),
    ).rejects.toThrow(/must be distinct/);
  });

  it("decodes the exact 108-byte Anchor account layout", () => {
    const data = new Uint8Array(MARKET_CONFIG_ACCOUNT_LEN);
    data.set(discriminator("account", "MarketConfig"), 0);
    data.set(baseMint.toBytes(), 8);
    data.set(quoteMint.toBytes(), 40);
    const view = new DataView(data.buffer);
    view.setBigUint64(72, 100_000_000n, true);
    view.setBigUint64(80, 5n, true);
    view.setBigUint64(88, 1_000n, true);
    view.setBigUint64(96, 5_000n, true);
    data[104] = 9;
    data[105] = 6;
    data[106] = 1;
    data[107] = 254;

    expect(decodeMarketConfig(data)).toEqual({
      baseMint,
      quoteMint,
      priceScale: 100_000_000n,
      tickSize: 5n,
      minOrderSize: 1_000n,
      circuitBreakerBps: 5_000n,
      baseDecimals: 9,
      quoteDecimals: 6,
      enabled: true,
      bump: 254,
    });
    data[106] = 2;
    expect(() => decodeMarketConfig(data)).toThrow(/enabled encoding/);
  });
});

describe("TEE signer rotation transport", () => {
  it("serializes exactly numTrees unique keys", async () => {
    const keys = [Keypair.generate().publicKey, Keypair.generate().publicKey];
    const ix = await buildSetTeePubkeyInstruction({
      programId: PROGRAM_ID,
      admin: Keypair.generate().publicKey,
      teePubkeys: keys,
      numTrees: 2,
    });
    expect(ix.data.readUInt32LE(8)).toBe(2);
    expect(ix.data).toHaveLength(8 + 4 + 64);
    await expect(
      buildSetTeePubkeyInstruction({
        programId: PROGRAM_ID,
        admin: Keypair.generate().publicKey,
        teePubkeys: [keys[0]],
        numTrees: 2,
      }),
    ).rejects.toThrow(/exactly numTrees/);
  });
});

describe("root rotation transport", () => {
  it("rejects default and no-op successors before submission", async () => {
    const currentRootKey = Keypair.generate().publicKey;
    await expect(
      buildRotateRootKeyInstruction({
        programId: PROGRAM_ID,
        currentRootKey,
        newRootKey: PublicKey.default,
      }),
    ).rejects.toThrow(/non-default and different/);
    await expect(
      buildRotateRootKeyInstruction({
        programId: PROGRAM_ID,
        currentRootKey,
        newRootKey: currentRootKey,
      }),
    ).rejects.toThrow(/non-default and different/);
  });
});
