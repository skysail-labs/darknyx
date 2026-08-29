#!/usr/bin/env node
// Install one exact, fresh PriceUpdateV2 account into a loopback Surfnet.
// This is a local control-plane helper, not an oracle fallback in product code.

import { Connection, PublicKey } from "@solana/web3.js";

import { requireLoopbackRpc } from "./loopback.mjs";

const RECEIVER = new PublicKey("rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp");
const PUSH = new PublicKey("pyt2F414BA6dPttK6RddPZUdHfapoBN24GL5wbrPCou");
const CLOCK = new PublicKey("SysvarC1ock11111111111111111111111111111111");
const DISCRIMINATOR = Buffer.from("22f123639d7ef4cd", "hex");
const FEED = (process.argv[2] ?? "").replace(/^0x/i, "").toLowerCase();
const RPC = process.env.SOLANA_RPC_URL?.trim();

if (!RPC) throw new Error("SOLANA_RPC_URL is required");
requireLoopbackRpc(RPC, "Surfpool fixture installation RPC");
if (!/^[0-9a-f]{64}$/.test(FEED)) {
  throw new Error("feed id must be 32-byte hex");
}

const connection = new Connection(RPC, "confirmed");
const clock = await connection.getAccountInfo(CLOCK, "confirmed");
if (!clock || clock.data.length < 40)
  throw new Error("Surfnet clock is missing");
const clockView = new DataView(
  clock.data.buffer,
  clock.data.byteOffset,
  clock.data.byteLength,
);
const slot = clockView.getBigUint64(0, true);
const unixTimestamp = clockView.getBigInt64(32, true);
if (slot === 0n || unixTimestamp <= 0n) {
  throw new Error("Surfnet clock must have a positive slot and timestamp");
}

const feedBytes = Buffer.from(FEED, "hex");
const [account] = await PublicKey.findProgramAddress(
  [Buffer.alloc(2), feedBytes],
  PUSH,
);
const data = Buffer.alloc(134);
DISCRIMINATOR.copy(data, 0);
Buffer.from(account.toBytes()).copy(data, 8);
data[40] = 1; // VerificationLevel::Full
feedBytes.copy(data, 41);
data.writeBigInt64LE(15_000_000_000n, 73);
data.writeBigUInt64LE(10n, 81);
data.writeInt32LE(-8, 89);
data.writeBigInt64LE(unixTimestamp, 93);
data.writeBigInt64LE(unixTimestamp - 1n, 101);
data.writeBigInt64LE(14_900_000_000n, 109);
data.writeBigUInt64LE(12n, 117);
data.writeBigUInt64LE(slot, 125);
// byte 133 remains zero: padding for the larger Partial enum variant.

const response = await fetch(RPC, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "surfnet_setAccount",
    params: [
      account.toBase58(),
      {
        lamports: 1_000_000,
        data: data.toString("hex"),
        owner: RECEIVER.toBase58(),
        executable: false,
        rentEpoch: 0,
      },
    ],
  }),
});
if (!response.ok) throw new Error(`surfnet_setAccount HTTP ${response.status}`);
const body = await response.json();
if (body.error)
  throw new Error(`surfnet_setAccount: ${JSON.stringify(body.error)}`);

console.log(
  `SURFPOOL_PYTH_PUSH_INSTALLED feed=${FEED} account=${account.toBase58()} slot=${slot}`,
);
