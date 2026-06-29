/**
 * Attestation tests — the connect-time verifier, no live TEE.
 *
 * A fake fetch serves /attestation + /info with a report_data we construct to
 * the documented layout (nonce ‖ SHA-256(tee_pubkey bytes)), so the freshness +
 * key-binding + pinning checks are exercised exactly. Also asserts the Daemon
 * refuses to start when verification throws.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { Keypair } from "@solana/web3.js";

import { verifyAttestation, AttestationError } from "../src/attestation.js";
import { Daemon } from "../src/daemon.js";
import { DaemonStore } from "../src/store.js";
import { Keystore, type AccountIdentity } from "../src/keystore.js";
import { DEFAULT_THRESHOLDS } from "../src/order-lifecycle.js";
import type { DaemonConfig } from "../src/config.js";

const GW = "https://gw.example";
const TOKEN = "tok";

// A fixed TEE signer key; the report_data binds to its raw bytes.
const teeKp = Keypair.generate();
const TEE_PUBKEY_B58 = teeKp.publicKey.toBase58();
const TEE_PUBKEY_HASH = createHash("sha256")
  .update(teeKp.publicKey.toBytes())
  .digest();

/**
 * Build a fake fetch. `mutate` can corrupt the report_data / info to drive the
 * failure paths. The nonce comes from the request's `report_data` query param.
 */
function attestFetch(
  opts: {
    composeHash?: string;
    mrtd?: string;
    teePubkeyB58?: string;
    bindWrongKey?: boolean;
    staleNonce?: boolean;
  } = {},
): typeof fetch {
  const composeHash = opts.composeHash ?? "abc123";
  const teePubkey = opts.teePubkeyB58 ?? TEE_PUBKEY_B58;
  return vi.fn(async (input: string | URL) => {
    const url = new URL(String(input));
    if (url.pathname === "/attestation") {
      const nonceHex = url.searchParams.get("reportData") ?? "";
      const nonce = Buffer.from(nonceHex, "hex");
      const rd = Buffer.alloc(64);
      if (!opts.staleNonce) nonce.copy(rd, 0);
      const bind = opts.bindWrongKey
        ? createHash("sha256").update(Buffer.from("nope")).digest()
        : TEE_PUBKEY_HASH;
      bind.copy(rd, 32);
      return new Response(
        JSON.stringify({
          quote: "deadbeef",
          report_data: rd.toString("hex"),
          tee_pubkey: teePubkey,
        }),
        { status: 200 },
      );
    }
    if (url.pathname === "/info") {
      return new Response(
        JSON.stringify({
          app_id: "app_x",
          compose_hash: composeHash,
          mrtd: opts.mrtd ?? "mrtd123",
          tee_pubkey: teePubkey,
        }),
        { status: 200 },
      );
    }
    return new Response("not found", { status: 404 });
  }) as unknown as typeof fetch;
}

describe("verifyAttestation", () => {
  it("accepts a well-formed, bound, pinned attestation", async () => {
    const r = await verifyAttestation({
      gatewayUrl: GW,
      token: TOKEN,
      fetchImpl: attestFetch({ composeHash: "pinned", mrtd: "m1" }),
      expected: {
        composeHash: "pinned",
        mrtd: "m1",
        teePubkey: TEE_PUBKEY_B58,
      },
    });
    expect(r.teePubkey).toBe(TEE_PUBKEY_B58);
    expect(r.composeHash).toBe("pinned");
  });

  it("rejects a replayed (stale-nonce) quote", async () => {
    await expect(
      verifyAttestation({
        gatewayUrl: GW,
        token: TOKEN,
        fetchImpl: attestFetch({ staleNonce: true }),
      }),
    ).rejects.toMatchObject({ kind: "freshness" });
  });

  it("rejects a key-binding mismatch", async () => {
    await expect(
      verifyAttestation({
        gatewayUrl: GW,
        token: TOKEN,
        fetchImpl: attestFetch({ bindWrongKey: true }),
      }),
    ).rejects.toMatchObject({ kind: "binding" });
  });

  it("rejects a compose_hash that doesn't match the pin", async () => {
    await expect(
      verifyAttestation({
        gatewayUrl: GW,
        token: TOKEN,
        fetchImpl: attestFetch({ composeHash: "actual" }),
        expected: { composeHash: "expected" },
      }),
    ).rejects.toMatchObject({ kind: "compose_mismatch" });
  });

  it("runs an injected DCAP quote verifier and rejects on failure", async () => {
    await expect(
      verifyAttestation({
        gatewayUrl: GW,
        token: TOKEN,
        fetchImpl: attestFetch(),
        quoteVerifier: async () => false,
      }),
    ).rejects.toMatchObject({ kind: "quote_invalid" });
    expect(AttestationError).toBeDefined();
  });
});

describe("Daemon — attestation gate", () => {
  let store: DaemonStore;
  beforeEach(() => {
    store = new DaemonStore(":memory:");
  });
  afterEach(() => store.close());

  function keystore(): Keystore {
    const masterSeed = new Uint8Array(64);
    for (let i = 0; i < 64; i++) masterSeed[i] = (i * 13 + 5) & 0xff;
    const id: AccountIdentity = {
      masterSeed,
      ownerBlinding: 0xabcn,
      r0: 1n,
      r1: 2n,
      r2: 3n,
      rootKeyPubkey: new Uint8Array(32).fill(4),
    };
    return new Keystore(id);
  }
  const config = (): DaemonConfig => ({
    gatewayUrl: GW,
    gatewayWsUrl: "wss://gw",
    token: TOKEN,
    rpcUrl: "https://rpc",
    dbPath: ":memory:",
    controlPort: 0,
    keystorePath: "x",
    thresholds: DEFAULT_THRESHOLDS,
    programId: "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
  });

  it("refuses to start when attestation fails", async () => {
    const daemon = new Daemon({
      config: config(),
      keystore: keystore(),
      store,
      prover: (async () => {
        throw new Error("unused");
      }) as never,
      placer: {
        place: vi.fn(),
        cancel: vi.fn(),
        modify: vi.fn(),
        close: vi.fn(),
      } as never,
      subscribeFills: (() => ({ close() {} })) as never,
      subscribeOrders: (() => ({ close() {} })) as never,
      verifyAttestation: async () => {
        throw new AttestationError("bad", "binding");
      },
    });
    await expect(daemon.start()).rejects.toThrow(/bad/);
    expect(daemon.getAttestation()).toBeNull();
  });

  it("starts + records the identity when attestation passes", async () => {
    const daemon = new Daemon({
      config: config(),
      keystore: keystore(),
      store,
      prover: (async () => ({
        proofBytes: new Uint8Array(256),
        merkleRoot: new Uint8Array(32),
      })) as never,
      placer: {
        place: vi.fn(),
        cancel: vi.fn(),
        modify: vi.fn(),
        close: vi.fn(),
      } as never,
      subscribeFills: (() => ({ close() {} })) as never,
      subscribeOrders: (() => ({ close() {} })) as never,
      verifyAttestation: async () => ({
        teePubkey: TEE_PUBKEY_B58,
        composeHash: "pinned",
        mrtd: "m1",
        quote: "q",
      }),
    });
    await daemon.start();
    expect(daemon.getAttestation()?.teePubkey).toBe(TEE_PUBKEY_B58);
  });
});
