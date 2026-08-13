import { Connection, PublicKey } from "@solana/web3.js";

export const PYTH_CORE_RECEIVER_PROGRAM_ID = new PublicKey(
  "rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp",
);
export const PYTH_CORE_PUSH_ORACLE_PROGRAM_ID = new PublicKey(
  "pyt2F414BA6dPttK6RddPZUdHfapoBN24GL5wbrPCou",
);
export const PYTH_PUSH_SHARD_ID = 0;

const PRICE_UPDATE_V2_DISCRIMINATOR = Buffer.from("22f123639d7ef4cd", "hex");
const FULL_VERIFICATION_LEVEL = 1;
const MESSAGE_OFFSET = 8 + 32 + 1;
const POSTED_SLOT_OFFSET = MESSAGE_OFFSET + 84;

const normalizeFeedId = (feedId: string): Buffer => {
  const normalized = feedId.replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new Error("Pyth feed id must be 32-byte hex");
  }
  return Buffer.from(normalized, "hex");
};

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((value, index) => value === b[index]);

export function derivePythCorePushAccount(feedId: string): PublicKey {
  const shard = Buffer.alloc(2);
  shard.writeUInt16LE(PYTH_PUSH_SHARD_ID);
  return PublicKey.findProgramAddressSync(
    [shard, normalizeFeedId(feedId)],
    PYTH_CORE_PUSH_ORACLE_PROGRAM_ID,
  )[0];
}

export interface PythCorePushPrice {
  account: PublicKey;
  feedId: string;
  price: bigint;
  confidence: bigint;
  emaPrice: bigint;
  emaConfidence: bigint;
  exponent: number;
  publishTime: bigint;
  postedSlot: bigint;
  contextSlot: number;
}

export function decodePythCorePushAccount(args: {
  data: Uint8Array;
  owner: PublicKey;
  account: PublicKey;
  feedId: string;
  contextSlot: number;
}): PythCorePushPrice {
  const data = Buffer.from(args.data);
  const expectedFeed = normalizeFeedId(args.feedId);
  if (!args.owner.equals(PYTH_CORE_RECEIVER_PROGRAM_ID)) {
    throw new Error("Pyth push account has the wrong owner program");
  }
  if (
    data.length < POSTED_SLOT_OFFSET + 8 ||
    !bytesEqual(data.subarray(0, 8), PRICE_UPDATE_V2_DISCRIMINATOR)
  ) {
    throw new Error("Pyth push account is not PriceUpdateV2");
  }
  if (data.subarray(POSTED_SLOT_OFFSET + 8).some((byte) => byte !== 0)) {
    throw new Error("Pyth push account has non-zero trailing bytes");
  }
  if (!bytesEqual(data.subarray(8, 40), args.account.toBytes())) {
    throw new Error("Pyth push account write authority is not its derived PDA");
  }
  if (data[40] !== FULL_VERIFICATION_LEVEL) {
    throw new Error("Pyth push account is not fully verified");
  }
  if (!bytesEqual(data.subarray(MESSAGE_OFFSET, MESSAGE_OFFSET + 32), expectedFeed)) {
    throw new Error("Pyth push account contains the wrong feed id");
  }
  const price = data.readBigInt64LE(MESSAGE_OFFSET + 32);
  const confidence = data.readBigUInt64LE(MESSAGE_OFFSET + 40);
  const exponent = data.readInt32LE(MESSAGE_OFFSET + 48);
  const publishTime = data.readBigInt64LE(MESSAGE_OFFSET + 52);
  const emaPrice = data.readBigInt64LE(MESSAGE_OFFSET + 68);
  const emaConfidence = data.readBigUInt64LE(MESSAGE_OFFSET + 76);
  const postedSlot = data.readBigUInt64LE(POSTED_SLOT_OFFSET);
  if (price <= 0n || emaPrice <= 0n || publishTime < 0n || postedSlot === 0n) {
    throw new Error("Pyth push account contains invalid price metadata");
  }
  if (postedSlot > BigInt(args.contextSlot)) {
    throw new Error("Pyth push posted slot exceeds finalized RPC context");
  }
  return {
    account: args.account,
    feedId: expectedFeed.toString("hex"),
    price,
    confidence,
    emaPrice,
    emaConfidence,
    exponent,
    publishTime,
    postedSlot,
    contextSlot: args.contextSlot,
  };
}

export async function fetchPythCorePushPrice(
  connection: Connection,
  feedId: string,
): Promise<PythCorePushPrice> {
  const account = derivePythCorePushAccount(feedId);
  const response = await connection.getAccountInfoAndContext(account, {
    commitment: "finalized",
  });
  if (!response.value) {
    throw new Error(`Pyth push account ${account.toBase58()} is missing`);
  }
  return decodePythCorePushAccount({
    data: response.value.data,
    owner: response.value.owner,
    account,
    feedId,
    contextSlot: response.context.slot,
  });
}
