/**
 * Live-CVM attestation validation — the one thing offline tests can't do: run
 * the REAL `@phala/dcap-qvl` against a REAL Intel-signed TDX quote from a
 * deployed Phala CVM, and confirm our wire formats (report_data set-binding,
 * event-log RTMR3 replay, compose-hash) all line up end-to-end.
 *
 * Env-gated (auto-skips offline / in CI without a CVM):
 *   RUN_CVM_ATTEST=1
 *   DARKNYX_CVM_TRANSPORT=ra-tls \
 *   DARKNYX_TEE_GATEWAY=https://<app>-8443s.dstack-...phala.network
 *   DARKNYX_TEE_TOKEN=<bearer>            (if the gateway requires auth on /info)
 *   SOLANA_RPC_URL=<helius>           (for the on-chain tee_pubkeys cross-check)
 *   DARKNYX_VAULT_PROGRAM_ID=<base58>     (default: devnet vault)
 *
 * The compose_hash pin is BOOTSTRAPPED from the first verified quote (replay the
 * event log → read the compose-hash event), then re-asserted through the full
 * `verifyTeeAttestation`. Cross-check the printed value against the Phala deploy's
 * allowlisted compose_hash.
 */

import { createHash, randomBytes } from "node:crypto";
import { Connection, PublicKey } from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import { gwFetch, gwTransportFetch } from "./helpers/cvm-harness.js";

import {
  composeHashFromEventLog,
  createDcapQuoteVerifier,
  parseEventLog,
  teeKeySetBytes,
  vaultConfigPda,
  vaultConfigTeePubkeys,
  verifyTeeAttestation,
} from "../src/index.js";

const RUN = process.env.RUN_CVM_ATTEST === "1";
const GATEWAY = process.env.DARKNYX_TEE_GATEWAY ?? "";
const RPC = process.env.SOLANA_RPC_URL ?? "";
const TOKEN = process.env.DARKNYX_TEE_TOKEN;
const PROGRAM_ID =
  process.env.DARKNYX_VAULT_PROGRAM_ID ??
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";

const gate = RUN && GATEWAY ? describe : describe.skip;

const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));

async function getJson<T>(path: string): Promise<T> {
  const headers: Record<string, string> = TOKEN
    ? { authorization: `Bearer ${TOKEN}` }
    : {};
  // Through the harness transport, not global fetch: under `ra-tls` the
  // enclave serves a self-signed certificate, so a plain fetch fails with
  // DEPTH_ZERO_SELF_SIGNED_CERT — and, more importantly, would be reaching
  // the enclave over a connection nothing verified.
  const res = await gwFetch(new URL(path, GATEWAY).toString(), { headers });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return (await res.json()) as T;
}

async function fetchAttestation(nonce: Uint8Array) {
  return getJson<{
    quote: string;
    event_log: string;
    report_data: string;
    tee_pubkey: string;
  }>(`/attestation?reportData=${Buffer.from(nonce).toString("hex")}`);
}

async function fetchInfo() {
  return getJson<{
    compose_hash: string;
    tee_pubkey: string;
    tee_pubkeys?: string[];
  }>("/info");
}

gate("live CVM attestation (real DCAP)", () => {
  const verifier = createDcapQuoteVerifier();

  it("dcap-qvl verifies the real quote + yields the compose hash (bootstrap)", async () => {
    const nonce = Uint8Array.from(randomBytes(32));
    const att = await fetchAttestation(nonce);
    // Real Intel-TCB verification — throws if the quote isn't genuine.
    const report = await verifier(fromHex(att.quote));
    expect(report.tcbStatus).toBeTruthy();
    // Freshness: our nonce is in the verified quote's report_data.
    expect(Buffer.from(report.reportData.subarray(0, 32))).toEqual(
      Buffer.from(nonce),
    );
    const eventLog = parseEventLog(att.event_log);
    const composeHash = composeHashFromEventLog(eventLog);
    expect(composeHash, "compose-hash event present in RTMR3 log").toBeTruthy();
    // eslint-disable-next-line no-console
    console.log(
      `[cvm-attest] BOOTSTRAP compose_hash = ${composeHash}  (pin this as EXPECTED_COMPOSE_HASH; cross-check vs the Phala deploy)`,
    );
  });

  it("verifyTeeAttestation passes with the quote-derived pin", async () => {
    // Bootstrap the compose-hash pin, then run the full public entrypoint.
    const boot = await fetchAttestation(Uint8Array.from(randomBytes(32)));
    const composeHash = composeHashFromEventLog(parseEventLog(boot.event_log));
    expect(
      composeHash,
      "compose-hash must come from a RUNTIME event — a non-runtime entry carries an unauthenticated payload",
    ).toBeTruthy();

    // The signer pin comes from ON-CHAIN vault_config, never from the gateway.
    // It used to be omitted here, and `verifyTeeAttestation` filled it with the
    // attested key — so this assertion passed while comparing that key against
    // itself. Sourcing it from the chain is the whole point of the pin.
    if (!RPC) {
      console.warn("[cvm-attest] SOLANA_RPC_URL unset — skipping strict verify");
      return;
    }
    const conn = new Connection(RPC, "confirmed");
    const [pda] = vaultConfigPda(new PublicKey(PROGRAM_ID));
    const acct = await conn.getAccountInfo(pda);
    expect(acct, "vault_config account exists").not.toBeNull();
    const onchainKeys = vaultConfigTeePubkeys(acct!.data);

    const r = await verifyTeeAttestation(GATEWAY, composeHash!, {
      fetchImpl: await gwTransportFetch(),
      token: TOKEN,
      expectedTeePubkey: onchainKeys[0],
    });
    expect(r.composeHash).toBe(composeHash);
    expect(r.teePubkeys.length).toBeGreaterThanOrEqual(1);
    expect(r.teePubkeys[0]).toBe(r.teePubkey);
    expect(r.teePubkey).toBe(onchainKeys[0]);
  });

  it("refuses strict verification with no on-chain signer pin", async () => {
    // CA-02, against a live enclave: omitting the pin must now fail closed
    // rather than silently comparing the attested key with itself.
    const boot = await fetchAttestation(Uint8Array.from(randomBytes(32)));
    const composeHash = composeHashFromEventLog(parseEventLog(boot.event_log));
    await expect(
      verifyTeeAttestation(GATEWAY, composeHash!, {
        token: TOKEN,
        fetchImpl: await gwTransportFetch(),
      }),
    ).rejects.toMatchObject({ kind: "pin_required" });
  });

  it("rejects a tampered quote", async () => {
    const att = await fetchAttestation(Uint8Array.from(randomBytes(32)));
    const bytes = fromHex(att.quote);
    bytes[100] ^= 0xff; // flip a byte in the SIGNED TD-report body (offset 100)
    await expect(verifier(bytes)).rejects.toThrow();
  });

  it("report_data binds the FULL /info.tee_pubkeys set", async () => {
    const nonce = Uint8Array.from(randomBytes(32));
    const [att, info] = await Promise.all([
      fetchAttestation(nonce),
      fetchInfo(),
    ]);
    const report = await verifier(fromHex(att.quote));
    const set = info.tee_pubkeys ?? [info.tee_pubkey];
    const expectedRight = createHash("sha256")
      .update(
        Buffer.from(teeKeySetBytes(set.map((k) => new PublicKey(k).toBytes()))),
      )
      .digest();
    expect(Buffer.from(report.reportData.subarray(32, 64))).toEqual(
      expectedRight,
    );
  });

  it("attested tee_pubkeys == on-chain vault_config.tee_pubkeys", async () => {
    if (!RPC) {
      console.warn(
        "[cvm-attest] SOLANA_RPC_URL unset — skipping on-chain check",
      );
      return;
    }
    const info = await fetchInfo();
    const attested = (info.tee_pubkeys ?? [info.tee_pubkey]).slice().sort();
    const conn = new Connection(RPC, "confirmed");
    const [pda] = vaultConfigPda(new PublicKey(PROGRAM_ID));
    const acct = await conn.getAccountInfo(pda);
    expect(acct, "vault_config account exists").not.toBeNull();
    const onchain = vaultConfigTeePubkeys(acct!.data).slice().sort();
    expect(attested).toEqual(onchain);
  });
});
