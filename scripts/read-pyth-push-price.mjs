#!/usr/bin/env node
/** Read one upgraded Pyth Core sponsored push account at finalized commitment.
 * Prints the raw EMA mantissa expected by the loadgen's --oracle-twap flag.
 */

import { Connection, PublicKey } from "@solana/web3.js";

const RECEIVER = new PublicKey("rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp");
const PUSH = new PublicKey("pyt2F414BA6dPttK6RddPZUdHfapoBN24GL5wbrPCou");
const DISCRIMINATOR = Buffer.from("22f123639d7ef4cd", "hex");
const FEED = (process.argv[2] ?? "").replace(/^0x/i, "").toLowerCase();
const RPC = process.env.SOLANA_RPC_URL?.trim();

if (!RPC)
  throw new Error("SOLANA_RPC_URL is required (use the configured chain RPC)");
if (!/^[0-9a-f]{64}$/.test(FEED))
  throw new Error("feed id must be 32-byte hex");

const feedBytes = Buffer.from(FEED, "hex");
const shard = Buffer.alloc(2); // upgraded sponsored feeds use shard 0
const [account] = await PublicKey.findProgramAddress([shard, feedBytes], PUSH);
const response = await new Connection(
  RPC,
  "finalized",
).getAccountInfoAndContext(account, {
  commitment: "finalized",
});
if (!response.value) throw new Error(`Pyth push account ${account} is missing`);
if (!response.value.owner.equals(RECEIVER))
  throw new Error("unexpected Pyth account owner");

const data = response.value.data;
const messageOffset = 8 + 32 + 1;
const postedSlotOffset = messageOffset + 84;
if (
  data.length < postedSlotOffset + 8 ||
  !data.subarray(0, 8).equals(DISCRIMINATOR)
) {
  throw new Error("account is not upgraded PriceUpdateV2");
}
if (data.subarray(postedSlotOffset + 8).some((byte) => byte !== 0)) {
  throw new Error("account has non-zero trailing bytes");
}
if (!data.subarray(8, 40).equals(account.toBytes()))
  throw new Error("wrong write authority");
if (data[40] !== 1) throw new Error("price update is not fully verified");
if (!data.subarray(messageOffset, messageOffset + 32).equals(feedBytes)) {
  throw new Error("price account feed mismatch");
}
const ema = data.readBigInt64LE(messageOffset + 68);
const publishTime = data.readBigInt64LE(messageOffset + 52);
const postedSlot = data.readBigUInt64LE(postedSlotOffset);
const nowSeconds = BigInt(Math.floor(Date.now() / 1_000));
if (
  ema <= 0n ||
  publishTime < nowSeconds - 90n ||
  publishTime > nowSeconds + 1n ||
  postedSlot === 0n ||
  postedSlot > BigInt(response.context.slot)
) {
  throw new Error("invalid/stale EMA or posted slot");
}
process.stdout.write(ema.toString());
