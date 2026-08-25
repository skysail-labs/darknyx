import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { PublicKey } from "@solana/web3.js";

import {
  anchorDiscriminator,
  computeSettlementBatchLeaf,
  computeSettlementBatchRoot,
  deriveFeeKeyBinding,
  deriveMatchFeeInner,
  encryptProtocolFeeRecovery,
  exactFillPayload,
  MATCH_ROLE_FEE_BASE,
  MATCH_ROLE_FEE_QUOTE,
  noteCommitmentV2,
  serializePayload,
  U64_MAX,
  type MatchResultPayload,
} from "@darknyx/sdk";
import { recoverProtocolFees } from "../src/collector.js";
import type {
  FeeKeyMaterial,
  FinalizedVaultTransaction,
  MarketIdentity,
} from "../src/types.js";

const PROGRAM = new PublicKey(new Uint8Array(32).fill(0x41)).toBase58();
const MARKET_KEY = new PublicKey(new Uint8Array(32).fill(0x42));
const MARKET: MarketIdentity = {
  address: MARKET_KEY.toBytes(),
  baseMint: new Uint8Array(32).fill(0x43),
  quoteMint: new Uint8Array(32).fill(0x44),
};

function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, item) => sum + item.length, 0));
  let offset = 0;
  for (const item of parts) {
    out.set(item, offset);
    offset += item.length;
  }
  return out;
}

function u16le(value: number): Uint8Array {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, true);
  return out;
}

function u64le(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

function field(value: number): Uint8Array {
  const out = new Uint8Array(32);
  out[31] = value;
  return out;
}

function event(name: string, body: Uint8Array): string {
  const disc = createHash("sha256")
    .update(`event:${name}`)
    .digest()
    .subarray(0, 8);
  return `Program data: ${Buffer.from(cat(disc, body)).toString("base64")}`;
}

function transaction(
  signature: string,
  slot: number,
  data: Uint8Array,
  accounts: string[] = [],
  logMessages: string[] = [],
): FinalizedVaultTransaction {
  return {
    signature,
    slot,
    instructions: [{ programId: PROGRAM, accounts, data }],
    logMessages,
  };
}

function configData(
  owner: Uint8Array,
  binding: Uint8Array,
  epoch: bigint,
): Uint8Array {
  return cat(
    anchorDiscriminator("set_protocol_config"),
    owner,
    u16le(30),
    binding,
    u64le(epoch),
  );
}

function tradeEventBody(payload: MatchResultPayload): Uint8Array {
  return cat(
    new Uint8Array([0]),
    payload.matchId,
    u64le(10n),
    u64le(11n),
    u64le(U64_MAX),
    u64le(U64_MAX),
    u64le(12n),
    u64le(13n),
    new Uint8Array([0, 0]),
    field(19),
  );
}

interface EpochFixture {
  transactions: FinalizedVaultTransaction[];
  key: FeeKeyMaterial;
  verify: FinalizedVaultTransaction;
  settle: FinalizedVaultTransaction;
}

async function epochFixture(
  epoch: bigint,
  startSlot: number,
  options: {
    tamperCiphertext?: boolean;
    wrongCommitment?: boolean;
    zeroBaseWithCommitment?: boolean;
    protocolOwner?: Uint8Array;
  } = {},
): Promise<EpochFixture> {
  const epochKey = field(Number(epoch + 20n));
  const binding = await deriveFeeKeyBinding(epochKey);
  const owner = field(25);
  const buyerTag = field(Number(epoch + 30n));
  const sellerTag = field(Number(epoch + 40n));
  const baseAmount = options.zeroBaseWithCommitment ? 0n : 7n + epoch;
  const quoteAmount = 11n + epoch;
  const baseInner = await deriveMatchFeeInner(
    epochKey,
    sellerTag,
    MATCH_ROLE_FEE_BASE,
  );
  const quoteInner = await deriveMatchFeeInner(
    epochKey,
    buyerTag,
    MATCH_ROLE_FEE_QUOTE,
  );
  const baseCommitment = await noteCommitmentV2({
    tokenMint: MARKET.baseMint,
    amount: baseAmount,
    ownerCommitment: 25n,
    innerHash: BigInt(`0x${Buffer.from(baseInner).toString("hex")}`),
  });
  const quoteCommitment = await noteCommitmentV2({
    tokenMint: MARKET.quoteMint,
    amount: quoteAmount,
    ownerCommitment: 25n,
    innerHash: BigInt(`0x${Buffer.from(quoteInner).toString("hex")}`),
  });
  const payload: MatchResultPayload = {
    ...exactFillPayload({
      matchId: new Uint8Array(16).fill(Number(epoch)),
      noteAuseTag: buyerTag,
      noteBuseTag: sellerTag,
      noteCcommitment: field(3),
      noteDcommitment: field(4),
      orderIdA: new Uint8Array(16).fill(5),
      orderIdB: new Uint8Array(16).fill(6),
    }),
    noteFeeBaseCommitment: options.wrongCommitment ? field(99) : baseCommitment,
    noteFeeQuoteCommitment: quoteCommitment,
    batchSlot: 0n,
  };
  const siblings = [7, 8, 9, 10].map(field);
  const root = await computeSettlementBatchRoot({
    leaf: await computeSettlementBatchLeaf(payload),
    matchIndex: 0,
    siblings,
  });
  const amounts = Array.from({ length: 16 }, () => ({ base: 0n, quote: 0n }));
  amounts[0] = { base: baseAmount, quote: quoteAmount };
  amounts[1] = { base: 3n, quote: 5n };
  const ciphertext = encryptProtocolFeeRecovery({
    epochKey,
    epoch,
    batchRoot: root,
    market: MARKET.address,
    baseMint: MARKET.baseMint,
    quoteMint: MARKET.quoteMint,
    amounts,
  });
  if (options.tamperCiphertext) ciphertext[17] ^= 1;
  const verify = transaction(
    `verify-${epoch}`,
    startSlot + 1,
    cat(
      anchorDiscriminator("verify_match_batch"),
      root,
      new Uint8Array(256),
      u64le(epoch),
      ciphertext,
    ),
    ["payer", "vault", MARKET_KEY.toBase58()],
  );
  const settle = transaction(
    `settle-${epoch}`,
    startSlot + 2,
    cat(
      anchorDiscriminator("tee_forced_settle_batched"),
      new Uint8Array([0]),
      serializePayload(payload),
      new Uint8Array([0]),
      ...siblings,
    ),
    [],
    [
      `Program ${PROGRAM} invoke [1]`,
      event("TradeSettled", tradeEventBody(payload)),
      `Program ${PROGRAM} success`,
    ],
  );
  return {
    key: { epoch, key: epochKey, binding },
    verify,
    settle,
    transactions: [
      transaction(
        `config-${epoch}`,
        startSlot,
        configData(options.protocolOwner ?? owner, binding, epoch),
      ),
      verify,
      settle,
    ],
  };
}

const resolveMarket = async (): Promise<MarketIdentity> => MARKET;

describe("finalized-chain protocol fee recovery", () => {
  it("recovers two epochs and excludes non-finalized settlement slots", async () => {
    const first = await epochFixture(1n, 10);
    const second = await epochFixture(2n, 20);
    const keys = new Map([
      [1n, first.key],
      [2n, second.key],
    ]);
    const result = await recoverProtocolFees({
      transactions: [...first.transactions, ...second.transactions],
      programId: PROGRAM,
      keyForEpoch: (epoch) => keys.get(epoch) ?? null,
      resolveMarket,
    });
    expect(result.unresolved).toEqual([]);
    expect(result.notes).toHaveLength(4);
    expect(result.notes.map((note) => note.amount)).toEqual([8n, 12n, 9n, 13n]);
    expect(result.notes.map((note) => note.epoch)).toEqual([1n, 1n, 2n, 2n]);
    expect(result.skippedUnsettledSlots).toBe(2);
    expect(result.notes[0]).toMatchObject({
      epoch: 1n,
      verifySignature: "verify-1",
      settleSignature: "settle-1",
      matchIndex: 0,
      side: "base",
      amount: 8n,
      treeId: 0,
      leafIndex: 12n,
    });
    expect(result.notes[0].tokenMint).toEqual(MARKET.baseMint);
    expect(result.notes[1]).toMatchObject({
      side: "quote",
      amount: 12n,
      leafIndex: 13n,
    });
    expect(result.notes[1].tokenMint).toEqual(MARKET.quoteMint);
  });

  it("reports a missing epoch key instead of inventing an opening", async () => {
    const fixture = await epochFixture(1n, 30);
    const result = await recoverProtocolFees({
      transactions: fixture.transactions,
      programId: PROGRAM,
      keyForEpoch: () => null,
      resolveMarket,
    });
    expect(result.notes).toEqual([]);
    expect(result.unresolved.map((item) => item.reason)).toEqual([
      "missing_epoch_key",
    ]);
  });

  it("rejects a key material record whose public binding is inconsistent", async () => {
    const fixture = await epochFixture(2n, 35);
    const result = await recoverProtocolFees({
      transactions: fixture.transactions,
      programId: PROGRAM,
      keyForEpoch: () => ({ ...fixture.key, binding: field(99) }),
      resolveMarket,
    });
    expect(result.notes).toEqual([]);
    expect(result.unresolved.map((item) => item.reason)).toEqual([
      "fee_key_binding_mismatch",
    ]);
  });

  it("fails loudly on ciphertext tamper and commitment substitution", async () => {
    const tampered = await epochFixture(3n, 40, { tamperCiphertext: true });
    const badCommitment = await epochFixture(4n, 50, { wrongCommitment: true });
    const tamperedResult = await recoverProtocolFees({
      transactions: tampered.transactions,
      programId: PROGRAM,
      keyForEpoch: () => tampered.key,
      resolveMarket,
    });
    expect(tamperedResult.notes).toEqual([]);
    expect(tamperedResult.unresolved[0]?.reason).toBe(
      "invalid_recovery_ciphertext",
    );
    const commitmentResult = await recoverProtocolFees({
      transactions: badCommitment.transactions,
      programId: PROGRAM,
      keyForEpoch: () => badCommitment.key,
      resolveMarket,
    });
    expect(commitmentResult.notes).toHaveLength(1);
    expect(commitmentResult.unresolved[0]?.reason).toBe("commitment_mismatch");
  });

  it("reports a finalized Tx D when the archival scan omitted its Tx B", async () => {
    const fixture = await epochFixture(5n, 60);
    const result = await recoverProtocolFees({
      transactions: [fixture.settle],
      programId: PROGRAM,
      keyForEpoch: () => fixture.key,
      resolveMarket,
    });
    expect(result.notes).toEqual([]);
    expect(result.unresolved[0]?.reason).toBe("missing_verify_record");
  });

  it("does not duplicate old Tx Ds when an expired batch root is re-verified", async () => {
    const fixture = await epochFixture(6n, 70);
    const repeatedVerify: FinalizedVaultTransaction = {
      ...fixture.verify,
      signature: "verify-6-again",
      slot: 80,
    };
    const result = await recoverProtocolFees({
      transactions: [...fixture.transactions, repeatedVerify],
      programId: PROGRAM,
      keyForEpoch: () => fixture.key,
      resolveMarket,
    });
    expect(result.unresolved).toEqual([]);
    expect(result.notes).toHaveLength(2);
    expect(result.skippedUnsettledSlots).toBe(3);
  });

  it("reports missing config, epoch drift, and unavailable market data", async () => {
    const fixture = await epochFixture(7n, 90);
    const missingConfig = await recoverProtocolFees({
      transactions: [fixture.verify, fixture.settle],
      programId: PROGRAM,
      keyForEpoch: () => fixture.key,
      resolveMarket,
    });
    expect(missingConfig.unresolved.map((item) => item.reason)).toContain(
      "missing_protocol_config",
    );

    const mismatchedConfig = transaction(
      "config-mismatch",
      89,
      configData(field(25), fixture.key.binding, 8n),
    );
    const epochMismatch = await recoverProtocolFees({
      transactions: [mismatchedConfig, fixture.verify, fixture.settle],
      programId: PROGRAM,
      keyForEpoch: () => fixture.key,
      resolveMarket,
    });
    expect(epochMismatch.unresolved.map((item) => item.reason)).toContain(
      "epoch_mismatch",
    );

    const unavailable = await recoverProtocolFees({
      transactions: fixture.transactions,
      programId: PROGRAM,
      keyForEpoch: () => fixture.key,
      resolveMarket: async () => {
        throw new Error("transient RPC failure");
      },
    });
    expect(unavailable.unresolved.map((item) => item.reason)).toContain(
      "market_config_unavailable",
    );
  });

  it("reports malformed settlement binding and impossible zero-fee outputs", async () => {
    const malformed = await epochFixture(8n, 100);
    const matchIndexOffset =
      malformed.settle.instructions[0].data.length - 4 * 32 - 1;
    malformed.settle.instructions[0].data[matchIndexOffset] = 1;
    const invalidBinding = await recoverProtocolFees({
      transactions: malformed.transactions,
      programId: PROGRAM,
      keyForEpoch: () => malformed.key,
      resolveMarket,
    });
    expect(invalidBinding.unresolved.map((item) => item.reason)).toContain(
      "invalid_settlement_binding",
    );

    const impossibleZero = await epochFixture(9n, 110, {
      zeroBaseWithCommitment: true,
    });
    const zeroResult = await recoverProtocolFees({
      transactions: impossibleZero.transactions,
      programId: PROGRAM,
      keyForEpoch: () => impossibleZero.key,
      resolveMarket,
    });
    expect(zeroResult.unresolved.map((item) => item.reason)).toContain(
      "commitment_mismatch",
    );
  });

  it("records non-canonical owner fields as unresolved instead of aborting", async () => {
    const fixture = await epochFixture(10n, 120, {
      protocolOwner: new Uint8Array(32).fill(0xff),
    });
    const result = await recoverProtocolFees({
      transactions: fixture.transactions,
      programId: PROGRAM,
      keyForEpoch: () => fixture.key,
      resolveMarket,
    });
    expect(result.notes).toEqual([]);
    expect(result.unresolved.map((item) => item.reason)).toEqual([
      "commitment_mismatch",
      "commitment_mismatch",
    ]);
  });
});
