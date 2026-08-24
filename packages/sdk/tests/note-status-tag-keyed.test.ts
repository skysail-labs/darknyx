/**
 * `DarkPoolClient.getNoteStatus` must key its guard lookups on the note-use
 * TAG, not the commitment.
 *
 * `ConsumedNoteEntry` and `NoteLock` are both seeded by
 * `Poseidon3(29, commitment, inner_hash)` on-chain. Both a commitment and a
 * tag are `[u8; 32]`, so keying on the wrong one compiles, derives a
 * plausible-looking address that no instruction ever writes, and reports
 * "active" for a note that is in fact consumed or locked. The wallet then
 * selects a spent note for a new order.
 *
 * These tests answer the account provider ONLY at the tag-derived address, so
 * a commitment-keyed implementation sees nothing and returns "active".
 */
import { describe, expect, it } from "vitest";
import { PublicKey } from "@solana/web3.js";

import { DarkPoolClient } from "../src/client.js";
import { consumedNotePda, noteLockPda } from "../src/idl/vault-client.js";
import { deriveNoteUseTag } from "../src/utxo/note-use.js";
import { bn254ToBE32 } from "../src/keys/key-generators.js";
import {
  noteCommitmentFromBytes,
  noteUseTagFromBytes,
} from "../src/utxo/note-identity.js";
import type {
  AccountInfoProvider,
  MasterSeedStorage,
  SolanaConnectionProvider,
} from "../src/providers.js";
import { UnimplementedProverSuite } from "../src/zk/prover-suite.js";

const PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

const COMMITMENT = noteCommitmentFromBytes(new Uint8Array(32).fill(0x11));
const INNER_HASH = bn254ToBE32(0x2222n);

if (false) {
  // The brands must reject the exact mistake this test guards at runtime.
  // @ts-expect-error a commitment cannot seed the tag-keyed lock namespace
  void noteLockPda(PROGRAM_ID, COMMITMENT);
  // @ts-expect-error a commitment cannot seed the tag-keyed consume namespace
  void consumedNotePda(PROGRAM_ID, COMMITMENT);
}

/** Answers non-null for exactly one address; null everywhere else. */
function providerAnsweringOnly(target: PublicKey): AccountInfoProvider {
  return {
    getAccountInfo: async (pubkey: PublicKey) =>
      pubkey.equals(target)
        ? { data: new Uint8Array(0), owner: PROGRAM_ID }
        : null,
  };
}

function makeClient(accountInfoProvider: AccountInfoProvider): DarkPoolClient {
  const connectionProvider: SolanaConnectionProvider = {
    connection: { getSlot: async () => 1_000n } as never,
    perRpcUrl: "http://stub",
  };
  const storage: MasterSeedStorage = {
    load: async () => new Uint8Array(64).map((_, i) => i),
    store: async () => {},
  };
  return new DarkPoolClient({
    programId: PROGRAM_ID,
    seedMode: { type: "csprng", storage },
    connectionProvider,
    providers: { accountInfoProvider } as never,
    zkProver: new UnimplementedProverSuite(),
    ownerCommitmentBlinding: 1234n,
  });
}

describe("getNoteStatus is keyed on the note-use tag", () => {
  it("reports consumed when the TAG-derived ConsumedNote PDA exists", async () => {
    const tag = await deriveNoteUseTag(COMMITMENT, INNER_HASH);
    const [consumedByTag] = await consumedNotePda(PROGRAM_ID, tag);
    const client = makeClient(providerAnsweringOnly(consumedByTag));

    expect((await client.getNoteStatus(COMMITMENT, INNER_HASH)).status).toBe(
      "consumed",
    );
  });

  it("reports locked when the TAG-derived NoteLock PDA exists", async () => {
    const tag = await deriveNoteUseTag(COMMITMENT, INNER_HASH);
    const [lockedByTag] = await noteLockPda(PROGRAM_ID, tag);
    const client = makeClient(providerAnsweringOnly(lockedByTag));

    expect((await client.getNoteStatus(COMMITMENT, INNER_HASH)).status).toBe(
      "locked",
    );
  });

  it("does NOT read the commitment-derived addresses", async () => {
    // The regression guard. A commitment-keyed implementation would find this
    // account and answer "consumed"; a tag-keyed one must ignore it entirely.
    const [consumedByCommitment] = await consumedNotePda(
      PROGRAM_ID,
      // A caller now has to make this explicit semantic violation; passing the
      // commitment directly is a TypeScript error.
      noteUseTagFromBytes(COMMITMENT),
    );
    const client = makeClient(providerAnsweringOnly(consumedByCommitment));

    expect((await client.getNoteStatus(COMMITMENT, INNER_HASH)).status).toBe(
      "active",
    );
  });

  it("derives a different tag for a different inner hash", async () => {
    // The inner hash is load-bearing, not decoration: the same commitment
    // under a different inner hash is a different on-chain identity.
    const tag = await deriveNoteUseTag(COMMITMENT, INNER_HASH);
    const [consumedByTag] = await consumedNotePda(PROGRAM_ID, tag);
    const client = makeClient(providerAnsweringOnly(consumedByTag));

    expect(
      (await client.getNoteStatus(COMMITMENT, bn254ToBE32(0x3333n))).status,
    ).toBe("active");
  });
});
