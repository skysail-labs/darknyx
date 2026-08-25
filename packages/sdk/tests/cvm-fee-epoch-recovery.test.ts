/**
 * Finalized-chain protocol-fee recovery and spend drill.
 *
 * This suite runs only after the operator has settled under two governed fee
 * epochs without resetting the Merkle shards, deleted the disposable online
 * fee cache, and rebuilt a sealed inventory with `darknyx-fee-collector
 * recover`. It proves that one recovered note from each epoch is still an
 * ordinary spendable pool note. The protocol-owner spending key and inventory
 * passphrase are environment-only secrets; neither is printed.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  openStoredFeeNote,
  readFeeInventory,
} from "../../fee-collector/src/index.js";
import { describe, expect, it } from "vitest";

import { ownerCommitment, pubkeyToFrPair } from "../src/utxo/note.js";
import { deriveNoteUseTag } from "../src/utxo/note-use.js";
import { noteCommitmentFromBytes } from "../src/utxo/note-identity.js";
import {
  buildWithdrawInstruction,
  consumedNotePda,
} from "../src/idl/vault-client.js";
import { bn254ToBE32 } from "../src/keys/key-generators.js";
import { pathIndicesFromLeafIndex } from "../src/zk/valid-input-prover.js";
import {
  TOKEN_PROGRAM_ID,
  associatedTokenAddress,
  be32ToDec,
  createAtaIdempotentIx,
} from "./helpers/e2e-helpers.js";
import { snarkjsFullProve } from "./helpers/snarkjs-prover.js";
import { authToken, gwFetch } from "./helpers/cvm-harness.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");
const GATEWAY = (process.env.DARKNYX_TEE_GATEWAY ?? "").replace(/\/$/, "");
const INVENTORY_PATH = resolve(
  REPO_ROOT,
  process.env.DARKNYX_FEE_INVENTORY_PATH ??
    ".devnet/operator/phase5-fee-inventory.sealed.json",
);
const SPEND_WASM = resolve(
  REPO_ROOT,
  "circuits/build/valid_spend/circuit_js/circuit.wasm",
);
const SPEND_ZKEY = resolve(
  REPO_ROOT,
  "circuits/build/valid_spend/circuit_final.zkey",
);

const READY =
  process.env.RUN_CVM_E2E === "1" &&
  process.env.RUN_CVM_FEE_RECOVERY === "1" &&
  GATEWAY !== "" &&
  existsSync(CONFIG_PATH) &&
  existsSync(INVENTORY_PATH) &&
  existsSync(SPEND_WASM) &&
  existsSync(SPEND_ZKEY);
const maybeDescribe = READY ? describe : describe.skip;

function requiredSecret(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function parseFieldSecret(value: string): bigint {
  if (!/^[0-9a-f]{64}$/i.test(value)) {
    throw new Error("DARKNYX_PROTOCOL_OWNER_SPENDING_KEY must be 32-byte hex");
  }
  const parsed = BigInt(`0x${value}`);
  if (parsed === 0n) {
    throw new Error("protocol-owner spending key must be nonzero");
  }
  return parsed;
}

maybeDescribe("CVM protocol fee recovery across key epochs", () => {
  it("withdraws one finalized-chain-recovered fee note from each epoch", async () => {
    const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as {
      l1RpcUrl: string;
      vaultProgramId: string;
    };
    const rpc = process.env.SOLANA_RPC_URL ?? cfg.l1RpcUrl;
    const conn = new Connection(rpc, "finalized");
    const payer = await Keypair.fromSecretKey(
      Uint8Array.from(
        JSON.parse(
          readFileSync(
            resolve(
              REPO_ROOT,
              process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json",
            ),
            "utf8",
          ),
        ),
      ),
    );
    const programId = new PublicKey(cfg.vaultProgramId);
    const spendingKey = parseFieldSecret(
      requiredSecret("DARKNYX_PROTOCOL_OWNER_SPENDING_KEY"),
    );
    const expectedOwner = bn254ToBE32(await ownerCommitment(spendingKey));
    const inventory = await readFeeInventory(
      INVENTORY_PATH,
      requiredSecret("DARKNYX_FEE_INVENTORY_PASSPHRASE"),
    );

    const epochs = [...new Set(inventory.notes.map((note) => note.epoch))]
      .map((value) => BigInt(value))
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    expect(epochs.length, "the drill requires two recovered epochs").toBe(2);
    const token = await authToken(GATEWAY);
    const signatures: Array<{ epoch: bigint; signature: string }> = [];

    for (const epoch of epochs) {
      const candidates = inventory.notes.filter(
        (note) => BigInt(note.epoch) === epoch && BigInt(note.amount) > 0n,
      );
      let selected:
        | {
            stored: (typeof candidates)[number];
            noteUseTag: Awaited<ReturnType<typeof deriveNoteUseTag>>;
            inclusion: {
              leaf_index: number;
              merkle_root: string;
              siblings: string[];
            };
          }
        | undefined;
      for (const stored of candidates) {
        const note = openStoredFeeNote(stored);
        if (!Buffer.from(note.ownerCommitment).equals(expectedOwner)) {
          throw new Error(
            `epoch ${epoch} recovered a fee note for the wrong protocol owner`,
          );
        }
        const noteUseTag = await deriveNoteUseTag(
          noteCommitmentFromBytes(note.commitment),
          note.innerHash,
        );
        const [consumed] = await consumedNotePda(programId, noteUseTag);
        if (await conn.getAccountInfo(consumed)) continue;

        // Devnet rehearsals intentionally reset the trees between independent
        // CVM suites. The archival inventory still contains those correctly
        // recovered historical notes, but only a note retained by the final
        // no-reset A→B tree is spendable in this drill.
        const inclusionUrl = new URL(`${GATEWAY}/tree/inclusion`);
        inclusionUrl.searchParams.set(
          "commitment",
          Buffer.from(note.commitment).toString("hex"),
        );
        inclusionUrl.searchParams.set("tree_id", String(note.treeId));
        const inclusionResponse = await gwFetch(inclusionUrl.toString(), {
          headers: { authorization: `Bearer ${token}` },
        });
        if (inclusionResponse.status === 404) continue;
        if (!inclusionResponse.ok) {
          throw new Error(
            `epoch ${epoch} inclusion failed (${inclusionResponse.status}): ${await inclusionResponse.text()}`,
          );
        }
        const inclusion = (await inclusionResponse.json()) as {
          leaf_index: number;
          merkle_root: string;
          siblings: string[];
        };
        selected = { stored, noteUseTag, inclusion };
        break;
      }
      if (!selected) {
        throw new Error(`epoch ${epoch} has no unconsumed recovered fee note`);
      }

      const note = openStoredFeeNote(selected.stored);
      const mint = new PublicKey(note.tokenMint);
      const destination = await associatedTokenAddress(mint, payer.publicKey);
      const { inclusion } = selected;
      expect(inclusion.leaf_index).toBe(Number(note.leafIndex));
      expect(inclusion.siblings).toHaveLength(20);
      const root = Uint8Array.from(Buffer.from(inclusion.merkle_root, "hex"));
      const siblings = inclusion.siblings.map((value) =>
        Uint8Array.from(Buffer.from(value, "hex")),
      );
      const [mintLo, mintHi] = pubkeyToFrPair(mint.toBytes());
      const [destLo, destHi] = pubkeyToFrPair(destination.toBytes());
      const { proof } = snarkjsFullProve(
        {
          merkleRoot: be32ToDec(root),
          tokenMint: [mintLo.toString(), mintHi.toString()],
          amount: note.amount.toString(),
          spendingKey: spendingKey.toString(),
          innerHash: BigInt(
            `0x${Buffer.from(note.innerHash).toString("hex")}`,
          ).toString(),
          merklePath: siblings.map(be32ToDec),
          merkleIndices: pathIndicesFromLeafIndex(inclusion.leaf_index).map(
            String,
          ),
          recipient: [destLo.toString(), destHi.toString()],
        },
        {
          circuitWasmPath: SPEND_WASM,
          circuitZkeyPath: SPEND_ZKEY,
          repoRoot: REPO_ROOT,
        },
      );

      const signature = await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
          createAtaIdempotentIx(payer, destination, payer.publicKey, mint),
          await buildWithdrawInstruction({
            programId,
            treeId: note.treeId,
            payer: payer.publicKey,
            tokenMint: mint,
            destinationTokenAccount: destination,
            tokenProgramId: TOKEN_PROGRAM_ID,
            noteUseTag: selected.noteUseTag,
            merkleRoot: root,
            amount: note.amount,
            proof,
          }),
        ),
        [payer],
        { commitment: "finalized" },
      );
      signatures.push({ epoch, signature });
    }

    expect(signatures.map(({ epoch }) => epoch)).toEqual(epochs);
    for (const { epoch, signature } of signatures) {
      console.log(`  · epoch ${epoch} recovered fee spend ${signature}`);
    }
  }, 180_000);
});
