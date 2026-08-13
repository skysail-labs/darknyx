import { PublicKey } from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import {
  decodePythCorePushAccount,
  derivePythCorePushAccount,
  PYTH_CORE_RECEIVER_PROGRAM_ID,
} from "../src/oracle/pyth-push.js";

const FEED =
  "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";
const DISCRIMINATOR = Buffer.from("22f123639d7ef4cd", "hex");

const fixture = (account: PublicKey): Buffer => {
  const data = Buffer.alloc(133);
  DISCRIMINATOR.copy(data, 0);
  Buffer.from(account.toBytes()).copy(data, 8);
  data[40] = 1; // VerificationLevel::Full
  Buffer.from(FEED, "hex").copy(data, 41);
  data.writeBigInt64LE(15_000_000_000n, 73);
  data.writeBigUInt64LE(10n, 81);
  data.writeInt32LE(-8, 89);
  data.writeBigInt64LE(1_800_000_000n, 93);
  data.writeBigInt64LE(1_799_999_999n, 101);
  data.writeBigInt64LE(14_900_000_000n, 109);
  data.writeBigUInt64LE(12n, 117);
  data.writeBigUInt64LE(900n, 125);
  return data;
};

describe("Pyth upgraded Core push accounts", () => {
  it("derives the official shard-0 SOL/USD account", () => {
    expect(derivePythCorePushAccount(FEED).toBase58()).toBe(
      "7AviUf9nL62mcxNbQGKm4nKDQnPjswo6c5MX4D57HmyE",
    );
  });

  it("decodes only the pinned owner, feed, authority, and finalized slot", () => {
    const account = derivePythCorePushAccount(FEED);
    const decoded = decodePythCorePushAccount({
      data: fixture(account),
      owner: PYTH_CORE_RECEIVER_PROGRAM_ID,
      account,
      feedId: FEED,
      contextSlot: 1_000,
    });
    expect(decoded.emaPrice).toBe(14_900_000_000n);
    expect(decoded.postedSlot).toBe(900n);

    expect(() =>
      decodePythCorePushAccount({
        data: fixture(account),
        owner: new PublicKey(new Uint8Array(32).fill(7)),
        account,
        feedId: FEED,
        contextSlot: 1_000,
      }),
    ).toThrow(/owner/);
    expect(() =>
      decodePythCorePushAccount({
        data: fixture(account),
        owner: PYTH_CORE_RECEIVER_PROGRAM_ID,
        account,
        feedId: FEED,
        contextSlot: 899,
      }),
    ).toThrow(/finalized RPC context/);
  });
});
