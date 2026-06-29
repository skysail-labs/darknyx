/**
 * Solana provider tests — account-info mapping + the keypair forwarder, driven
 * by a fake Connection (no devnet). Asserts the forwarder attaches the payer as
 * fee-payer, signs, and send→confirms.
 */

import { describe, expect, it, vi } from "vitest";
import {
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
} from "@solana/web3.js";

import {
  accountInfoProvider,
  keypairForwarder,
  fixedSeedMode,
  type ConnectionLike,
} from "../src/solana-providers.js";

// A valid 32-byte base58 string (a pubkey) standing in for a blockhash.
const BLOCKHASH = Keypair.generate().publicKey.toBase58();

function fakeConnection(
  overrides: Partial<ConnectionLike> = {},
): ConnectionLike & {
  sent: Uint8Array[];
  confirmed: string[];
} {
  const sent: Uint8Array[] = [];
  const confirmed: string[] = [];
  return {
    sent,
    confirmed,
    getAccountInfo: vi.fn(async () => null),
    getLatestBlockhash: vi.fn(async () => ({ blockhash: BLOCKHASH })),
    sendRawTransaction: vi.fn(async (raw: Uint8Array) => {
      sent.push(raw);
      return "sig123";
    }),
    confirmTransaction: vi.fn(async (sig: string) => {
      confirmed.push(sig);
      return {};
    }),
    ...overrides,
  };
}

describe("accountInfoProvider", () => {
  it("maps a present account", async () => {
    const owner = PublicKey.default;
    const conn = fakeConnection({
      getAccountInfo: vi.fn(async () => ({
        data: Buffer.from([1, 2, 3]),
        owner,
      })),
    });
    const got = await accountInfoProvider(conn).getAccountInfo(
      PublicKey.default,
    );
    expect(got?.data).toEqual(Buffer.from([1, 2, 3]));
    expect(got?.owner).toBe(owner);
  });

  it("maps a missing account to null", async () => {
    const got = await accountInfoProvider(fakeConnection()).getAccountInfo(
      PublicKey.default,
    );
    expect(got).toBeNull();
  });
});

describe("keypairForwarder", () => {
  it("sets the fee-payer, signs, and send→confirms an instruction list", async () => {
    const payer = Keypair.generate();
    const conn = fakeConnection();
    const ix: TransactionInstruction = SystemProgram.transfer({
      fromPubkey: payer.publicKey,
      toPubkey: Keypair.generate().publicKey,
      lamports: 1,
    });

    const sig = await keypairForwarder(conn, payer).sendAndConfirm([ix]);

    expect(sig).toBe("sig123");
    expect(conn.sent).toHaveLength(1);
    expect(conn.confirmed).toEqual(["sig123"]);
    // the serialized bytes deserialize to a signed tx whose fee-payer is the payer
    const decoded = Transaction.from(conn.sent[0]);
    expect(decoded.feePayer?.equals(payer.publicKey)).toBe(true);
    expect(decoded.signatures[0].publicKey.equals(payer.publicKey)).toBe(true);
    expect(decoded.signatures[0].signature).not.toBeNull();
  });
});

describe("fixedSeedMode", () => {
  it("always returns the supplied seed", async () => {
    const seed = new Uint8Array(64).fill(9);
    const mode = fixedSeedMode(seed);
    expect(mode.type).toBe("csprng");
    if (mode.type === "csprng") {
      expect(await mode.storage.load()).toBe(seed);
      expect(await mode.storage.generate()).toBe(seed);
    }
  });
});
