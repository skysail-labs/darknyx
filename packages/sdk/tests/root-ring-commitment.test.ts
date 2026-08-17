/**
 * The on-chain root-ring gate must read at `confirmed` (C-09).
 *
 * The commitment level here is not a detail — it decides whether ordinary
 * clients can function at all.
 *
 * The vault's own `contains_root` runs against live account state, so
 * `confirmed` is the level that reflects what the program will see when the
 * proof lands. Reading `finalized` is not "safer": it cannot make the proof
 * more acceptable on-chain, and it makes the client refuse roots that are
 * already valid. On devnet `confirmed` runs ~30 slots (~12 s) ahead, so a
 * client proving straight after its own deposit had its brand-new root
 * rejected for a condition that resolves itself seconds later. That is what
 * broke `cvm-daemon-smoke` on BOTH transports, and it read as a transport
 * fault during the RA-TLS cutover.
 *
 * The reason this is pinned by a test rather than a comment: `finalized` looks
 * like the more conservative choice, so it is exactly the kind of edit someone
 * makes in good faith while "hardening" the guard.
 */

import { describe, expect, it } from "vitest";
import { PublicKey } from "@solana/web3.js";

import { onchainRootVerifier } from "../src/zk/valid-input-prover.js";
import { MERKLE_TREE_ACCOUNT_LEN } from "../src/zk/merkle-root-ring.js";

const PROGRAM = new PublicKey(
  process.env.VAULT_PROGRAM_ID ?? "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);
const DISCRIMINATOR = Uint8Array.from([98, 51, 51, 226, 162, 20, 73, 212]);

const ROOT = new Uint8Array(32).fill(3);
const OTHER_ROOT = new Uint8Array(32).fill(9);

/** Offsets taken from merkle-root-ring.ts rather than guessed. */
function account(currentRoot: Uint8Array) {
  const ROOT_HISTORY_SIZE = 64;
  const CURRENT_ROOT_OFFSET = 16;
  const ROOTS_RING_OFFSET = CURRENT_ROOT_OFFSET + 32;
  const ROOTS_HEAD_OFFSET = ROOTS_RING_OFFSET + ROOT_HISTORY_SIZE * 32 + 20 * 32;
  const TREE_ID_OFFSET = ROOTS_HEAD_OFFSET + 1;

  const data = new Uint8Array(MERKLE_TREE_ACCOUNT_LEN);
  data.set(DISCRIMINATOR, 0);
  data.set(currentRoot, CURRENT_ROOT_OFFSET);
  data[ROOTS_HEAD_OFFSET] = 0;
  data[TREE_ID_OFFSET] = 0;
  return { data, owner: PROGRAM };
}

describe("root-ring gate — commitment level", () => {
  it("reads the shard at `confirmed`", async () => {
    // The regression guard. A client cannot prove against its own fresh
    // deposit if this reads `finalized`.
    const seen: unknown[] = [];
    const verify = onchainRootVerifier({
      connection: {
        getAccountInfo: async (_pda: unknown, commitment: unknown) => {
          seen.push(commitment);
          return account(ROOT);
        },
      } as never,
      programId: PROGRAM,
    });

    await verify(ROOT, 0);
    expect(seen).toEqual(["confirmed"]);
  });

  it("does not read at `finalized`", async () => {
    // Stated separately and positively, so the intent survives a refactor
    // that changes how the argument is passed.
    const seen: unknown[] = [];
    const verify = onchainRootVerifier({
      connection: {
        getAccountInfo: async (_pda: unknown, commitment: unknown) => {
          seen.push(commitment);
          return account(ROOT);
        },
      } as never,
      programId: PROGRAM,
    });

    await verify(ROOT, 0);
    expect(seen).not.toContain("finalized");
  });

  it("still refuses a root the shard does not hold", async () => {
    // C-09 itself. Relaxing the commitment level must not relax the verdict:
    // a fabricated root is in the ring at NO commitment, so this still fails.
    const verify = onchainRootVerifier({
      connection: {
        getAccountInfo: async () => account(OTHER_ROOT),
      } as never,
      programId: PROGRAM,
    });

    await expect(verify(ROOT, 0)).rejects.toThrow(
      /is not in shard 0's on-chain root ring/,
    );
  });
});
