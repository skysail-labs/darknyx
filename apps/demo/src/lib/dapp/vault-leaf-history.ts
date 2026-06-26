/**
 * Reconstruct ordered vault Merkle leaves by scanning recent vault-program txs.
 */
import { anchorDiscriminator, noteCommitment, type Note } from "@nyx/sdk";
import { serializePayload, type MatchResultPayload } from "@nyx/sdk";
import type { Connection, VersionedTransactionResponse } from "@solana/web3.js";
import { PublicKey } from "@solana/web3.js";
import bs58 from "bs58";

const DEPOSIT_DISC = anchorDiscriminator("deposit");
const SETTLE_DISC = anchorDiscriminator("tee_forced_settle");

function isZero32(b: Uint8Array): boolean {
  return b.every((x) => x === 0);
}

function pushSettleLeaves(leaves: Uint8Array[], payloadBytes: Uint8Array) {
  const p = payloadBytes;
  if (p.length < 448) throw new Error(`settle payload too short: ${p.length}`);
  const noteC = p.subarray(80, 112);
  const noteD = p.subarray(112, 144);
  const noteE = p.subarray(144, 176);
  const noteF = p.subarray(176, 208);
  const noteFee = p.subarray(352, 384);

  leaves.push(noteC, noteD);
  if (!isZero32(noteE)) leaves.push(noteE);
  if (!isZero32(noteF)) leaves.push(noteF);
  if (!isZero32(noteFee)) leaves.push(noteFee);
}

function _assertPayloadLayout() {
  const dummy: MatchResultPayload = {
    matchId: new Uint8Array(16),
    noteAcommitment: new Uint8Array(32),
    noteBcommitment: new Uint8Array(32),
    noteCcommitment: new Uint8Array(32),
    noteDcommitment: new Uint8Array(32),
    noteEcommitment: new Uint8Array(32),
    noteFcommitment: new Uint8Array(32),
    nullifierA: new Uint8Array(32),
    nullifierB: new Uint8Array(32),
    orderIdA: new Uint8Array(16),
    orderIdB: new Uint8Array(16),
    baseAmount: 1n,
    quoteAmount: 1n,
    buyerChangeAmt: 0n,
    sellerChangeAmt: 0n,
    buyerFeeAmt: 0n,
    sellerFeeAmt: 0n,
    noteFeeCommitment: new Uint8Array(32),
    buyerRelockOrderId: new Uint8Array(16),
    buyerRelockExpiry: 0n,
    sellerRelockOrderId: new Uint8Array(16),
    sellerRelockExpiry: 0n,
    clearingPrice: 0n,
    batchSlot: 0n,
  };
  if (serializePayload(dummy).length !== 448) {
    throw new Error("serializePayload length drift");
  }
}
void _assertPayloadLayout();

function resolveAccountKeys(tx: VersionedTransactionResponse): PublicKey[] {
  const message = tx.transaction.message;
  const keys = [...message.staticAccountKeys];
  const loaded = tx.meta?.loadedAddresses;
  if (loaded) {
    keys.push(...loaded.writable, ...loaded.readonly);
  }
  return keys;
}

function be32ToBigInt(x: Uint8Array): bigint {
  let hex = "0x";
  for (const b of x) hex += b.toString(16).padStart(2, "0");
  return BigInt(hex);
}

/**
 * Vault `deposit` instruction account ordering (from
 * `programs/vault/src/instructions/deposit.rs`):
 *   0 depositor (signer)
 *   1 vault_config
 *   2 token_mint     <-- the leaf's mint
 *   3 depositor_token_account
 *   4 vault_token_account
 *   5 token_program
 *   6 system_program
 *   7 rent
 */
const DEPOSIT_TOKEN_MINT_IX_INDEX = 2;

async function pushDepositLeafAsync(
  leaves: Uint8Array[],
  data: Uint8Array,
  ixAccountKeys: PublicKey[],
) {
  if (data.length < 8 + 8 + 32 + 32 + 32) return;
  if (!data.subarray(0, 8).every((b, i) => b === DEPOSIT_DISC[i])) return;
  const amount = new DataView(data.buffer, data.byteOffset + 8, 8).getBigUint64(
    0,
    true,
  );
  const owner = data.subarray(16, 48);
  const nonce = data.subarray(48, 80);
  const blindingR = data.subarray(80, 112);
  if (DEPOSIT_TOKEN_MINT_IX_INDEX >= ixAccountKeys.length) return;
  const tokenMint = ixAccountKeys[DEPOSIT_TOKEN_MINT_IX_INDEX].toBytes();
  const note: Note = {
    tokenMint: new Uint8Array(tokenMint),
    amount,
    ownerCommitment: be32ToBigInt(owner),
    nonce: be32ToBigInt(nonce),
    blindingR: be32ToBigInt(blindingR),
  };
  leaves.push(await noteCommitment(note));
}

async function processIxDataAsync(
  leaves: Uint8Array[],
  data: Uint8Array,
  ixAccountKeys: PublicKey[],
) {
  if (
    data.length >= 8 &&
    data.subarray(0, 8).every((b, i) => b === DEPOSIT_DISC[i])
  ) {
    await pushDepositLeafAsync(leaves, data, ixAccountKeys);
    return;
  }
  if (
    data.length >= 8 &&
    data.subarray(0, 8).every((b, i) => b === SETTLE_DISC[i])
  ) {
    pushSettleLeaves(leaves, data.subarray(8));
  }
}

async function walkTransactionOrdered(
  connection: Connection,
  sig: string,
  vaultProgramId: PublicKey,
  leaves: Uint8Array[],
  cap: number,
): Promise<void> {
  const tx = await connection.getTransaction(sig, {
    maxSupportedTransactionVersion: 0,
    commitment: "confirmed",
  });
  if (!tx || tx.meta?.err) return;

  const keys = resolveAccountKeys(tx);
  const msg = tx.transaction.message;
  type InnerIxList = NonNullable<
    NonNullable<VersionedTransactionResponse["meta"]>["innerInstructions"]
  >[number]["instructions"];
  const innerByTop = new Map<number, InnerIxList>();
  for (const g of tx.meta?.innerInstructions ?? []) {
    innerByTop.set(g.index, g.instructions);
  }

  const walkIx = async (
    data: Uint8Array,
    programId: PublicKey,
    ixAccountKeys: PublicKey[],
  ) => {
    if (leaves.length >= cap) return;
    if (!programId.equals(vaultProgramId)) return;
    await processIxDataAsync(leaves, data, ixAccountKeys);
  };

  const top = msg.compiledInstructions;
  for (let ti = 0; ti < top.length; ti++) {
    if (leaves.length >= cap) return;
    const ix = top[ti]!;
    const pid = keys[ix.programIdIndex];
    const ixKeys = Array.from(ix.accountKeyIndexes ?? []).map(
      (kIdx) => keys[kIdx],
    );
    await walkIx(Buffer.from(ix.data), pid, ixKeys);
    const inners = innerByTop.get(ti);
    if (inners) {
      for (const ixi of inners) {
        if (leaves.length >= cap) return;
        let pid: PublicKey;
        let raw: Uint8Array;
        let ixKeys: PublicKey[] = [];
        if ("programIdIndex" in ixi && typeof ixi.programIdIndex === "number") {
          pid = keys[ixi.programIdIndex];
          // For raw `getTransaction` (no `jsonParsed`), inner-ix `data` is a
          // base58-encoded string per `CompiledInstruction` (see
          // `@solana/web3.js/src/message/legacy.ts`). DO NOT decode as base64
          // — silently produces garbage that fails the discriminator check
          // and causes leaves from inner CPIs to be missed.
          if (typeof ixi.data === "string") {
            raw = bs58.decode(ixi.data);
          } else {
            raw = new Uint8Array(ixi.data as Buffer);
          }
          // CompiledInstruction shape: `accounts: number[]`.
          const acctIdx =
            (ixi as unknown as { accounts?: number[] }).accounts ?? [];
          ixKeys = acctIdx.map((kIdx) => keys[kIdx]);
        } else {
          // Parsed/JSON inner ix shape (rare with maxSupportedTransactionVersion=0 +
          // raw transactions but defensive): `data` is base58 per JSON-RPC docs.
          // Cast through unknown because CompiledInstruction.accounts is number[]
          // while the parsed JSON shape has string[] — TS rightly flags the
          // overlap mismatch, but at this point we know we're in the parsed branch.
          const anyIx = ixi as unknown as {
            programId?: string;
            data?: string;
            accounts?: string[];
          };
          pid = new PublicKey(anyIx.programId!);
          raw = anyIx.data ? bs58.decode(anyIx.data) : new Uint8Array();
          ixKeys = (anyIx.accounts ?? []).map((s) => new PublicKey(s));
        }
        await walkIx(raw, pid, ixKeys);
      }
    }
  }
}

/** Solana RPC hard cap on `getSignaturesForAddress` `limit`. */
const RPC_SIG_PAGE_LIMIT = 1000;

/**
 * Page through `getSignaturesForAddress` (newest → oldest). The Solana RPC
 * caps `limit` at 1000, so we walk back with a `before` cursor.
 *
 * Returns the accumulated signatures in newest-first order. Caller is
 * expected to reverse if chronological order is desired.
 */
async function fetchSignaturesPaginated(
  connection: Connection,
  vaultProgramId: PublicKey,
  hardCap: number,
): Promise<{ signature: string }[]> {
  const out: { signature: string }[] = [];
  let before: string | undefined = undefined;
  while (out.length < hardCap) {
    const remaining = Math.min(RPC_SIG_PAGE_LIMIT, hardCap - out.length);
    const page = await connection.getSignaturesForAddress(vaultProgramId, {
      limit: remaining,
      before,
    });
    if (page.length === 0) break;
    out.push(...page.map((s) => ({ signature: s.signature })));
    before = page[page.length - 1]!.signature;
    if (page.length < remaining) break;
  }
  return out;
}

export async function collectVaultLeavesOrdered(
  connection: Connection,
  vaultProgramId: PublicKey,
  targetCount: number,
  options?: { maxSignatures?: number },
): Promise<Uint8Array[]> {
  // Default ceiling generous enough for a long-running shared devnet, but
  // still bounded so a misconfigured replay can't run away. Tune via
  // options.maxSignatures if you've been hammering devnet for hours.
  const maxSig = options?.maxSignatures ?? 10000;
  const sigs = await fetchSignaturesPaginated(
    connection,
    vaultProgramId,
    maxSig,
  );
  if (sigs.length === 0)
    throw new Error(
      "no vault program signatures — cannot replay Merkle history",
    );

  // getSignaturesForAddress returns newest-first; replay must walk oldest-first
  // so leaf indices line up with on-chain `leaf_count`.
  const chronological = [...sigs].reverse();
  const leaves: Uint8Array[] = [];

  for (const { signature } of chronological) {
    if (leaves.length >= targetCount) break;
    await walkTransactionOrdered(
      connection,
      signature,
      vaultProgramId,
      leaves,
      targetCount,
    );
  }

  if (leaves.length !== targetCount) {
    throw new Error(
      `Merkle replay incomplete: parsed ${leaves.length} leaves, vault expects ${targetCount}. ` +
        `Scanned ${sigs.length} vault signatures. Try raising maxSignatures (default 10000) or reset devnet vault.`,
    );
  }
  return leaves;
}
