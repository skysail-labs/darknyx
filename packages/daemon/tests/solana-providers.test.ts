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
  type Blockhash,
} from "@solana/web3.js";

import {
  accountInfoProvider,
  keypairForwarder,
  fixedSeedMode,
  type ConnectionLike,
} from "../src/solana-providers.js";

// v3 made `Keypair.generate()` async, and this call site only ever wanted a
// unique opaque address -- the secret key was discarded. Keep it synchronous.
// Counter starts at 1 so the result is never the all-zero default address.
let dummyAddressCounter = 0;
function dummyAddress(): PublicKey {
  const bytes = new Uint8Array(32);
  new DataView(bytes.buffer).setUint32(0, ++dummyAddressCounter, true);
  return new PublicKey(bytes);
}

// A valid 32-byte base58 string (a pubkey) standing in for a blockhash.
// A blockhash is base58 like an address but carries a different brand in v3;
// this is a mock value, so assert the brand rather than derive it.
const BLOCKHASH = dummyAddress().toBase58() as unknown as Blockhash;

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
    const payer = await Keypair.generate();
    const conn = fakeConnection();
    const ix: TransactionInstruction = SystemProgram.transfer({
      fromPubkey: payer.publicKey,
      toPubkey: dummyAddress(),
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
      await expect(
        mode.storage.store(new Uint8Array(64)),
      ).resolves.toBeUndefined();
      expect(await mode.storage.load()).toBe(seed);
    }
  });
});
