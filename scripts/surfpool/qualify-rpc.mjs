#!/usr/bin/env node
/**
 * Seed a non-empty Surfpool ledger and verify the exact
 * `getTransactionsForAddress` contract used by Darknyx.
 *
 * This is a qualification probe, not the local foundation runner. It creates
 * only ephemeral keypairs, accepts only a loopback RPC by default, and leaves
 * protocol/account setup to the later foundation phase.
 */

import assert from "node:assert/strict";
import {
  AddressLookupTableProgram,
  Connection,
  Ed25519Program,
  Keypair,
  SystemProgram,
  Transaction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";

const rpcUrl = process.env.SURFPOOL_RPC_URL ?? "http://127.0.0.1:18899";
const url = new URL(rpcUrl);
if (
  process.env.SURFPOOL_ALLOW_REMOTE !== "1" &&
  !["127.0.0.1", "localhost", "::1", "[::1]"].includes(url.hostname)
) {
  throw new Error(
    `refusing non-loopback Surfpool RPC ${url.hostname}; set SURFPOOL_ALLOW_REMOTE=1 only for a reviewed remote fixture`,
  );
}

let rpcId = 0;
async function rpc(method, params = []) {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params }),
  });
  assert.equal(response.ok, true, `${method}: HTTP ${response.status}`);
  const body = await response.json();
  if (body.error) {
    throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  }
  return body.result;
}

async function waitForStatus(connection, signature, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const response = await connection.getSignatureStatuses([signature], {
      searchTransactionHistory: true,
    });
    const status = response.value[0];
    if (status) return status;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`status polling timed out for ${signature}`);
}

async function signLegacyTransfer(payer, recipient, lamports, blockhash) {
  const transaction = new Transaction({
    feePayer: payer.publicKey,
    recentBlockhash: blockhash,
  }).add(
    SystemProgram.transfer({
      fromPubkey: payer.publicKey,
      toPubkey: recipient,
      lamports,
    }),
  );
  await transaction.sign(payer);
  return transaction.serialize();
}

function gtfaConfig(overrides = {}) {
  return {
    transactionDetails: "full",
    encoding: "json",
    sortOrder: "asc",
    limit: 100,
    commitment: "confirmed",
    maxSupportedTransactionVersion: 0,
    filters: { status: "succeeded" },
    ...overrides,
  };
}

async function gtfa(address, config) {
  return rpc("getTransactionsForAddress", [address, config]);
}

function signatureOf(entry) {
  return entry.transaction.signatures[0];
}

const connection = new Connection(rpcUrl, "confirmed");
const payer = await Keypair.generate();
const recipient = await Keypair.generate();

const version = await rpc("getVersion");
const blockhashContext = await connection.getLatestBlockhashAndContext(
  "confirmed",
);
assert.equal(typeof blockhashContext.context.slot, "bigint");
assert.equal(typeof blockhashContext.value.blockhash, "string");

const airdrop = await connection.requestAirdrop(
  payer.publicKey,
  2_000_000_000n,
);
const airdropStatus = await waitForStatus(connection, airdrop);
assert.equal(airdropStatus.err, null, "airdrop must succeed");

// Establish the recipient as a rent-exempt system account before using tiny
// transfers for the ordering/pagination history.
const rent = await connection.getMinimumBalanceForRentExemption(0);
const setupBlockhash = await connection.getLatestBlockhash("confirmed");
const setupRaw = await signLegacyTransfer(
  payer,
  recipient.publicKey,
  BigInt(rent) + 1n,
  setupBlockhash.blockhash,
);
const setupSignature = await connection.sendRawTransaction(setupRaw, {
  skipPreflight: false,
});
assert.equal((await waitForStatus(connection, setupSignature)).err, null);

const floorSlot = Number(await connection.getSlot("confirmed"));
const latest = await connection.getLatestBlockhash("confirmed");
const rawTransfers = await Promise.all(
  Array.from({ length: 8 }, (_, index) =>
    signLegacyTransfer(
      payer,
      recipient.publicKey,
      BigInt(index + 1),
      latest.blockhash,
    ),
  ),
);
const successfulSignatures = await Promise.all(
  rawTransfers.map((raw) =>
    connection.sendRawTransaction(raw, { skipPreflight: false }),
  ),
);
for (const signature of successfulSignatures) {
  assert.equal((await waitForStatus(connection, signature)).err, null);
}

// Darknyx settles with an Ed25519 precompile immediately before the vault
// instruction. Exercise the native precompile rather than inferring support
// from an ordinary signature on the transaction envelope.
const ed25519Message = new TextEncoder().encode(
  "darknyx/surfpool-ed25519-qualification/v1",
);
const ed25519Instruction = await Ed25519Program.createInstructionWithPrivateKey(
  {
    privateKey: payer.secretKey,
    message: ed25519Message,
  },
);
const ed25519Blockhash = await connection.getLatestBlockhash("confirmed");
const ed25519Transaction = new Transaction({
  feePayer: payer.publicKey,
  recentBlockhash: ed25519Blockhash.blockhash,
}).add(
  ed25519Instruction,
  SystemProgram.transfer({
    fromPubkey: payer.publicKey,
    toPubkey: recipient.publicKey,
    lamports: 1n,
  }),
);
await ed25519Transaction.sign(payer);
const ed25519Signature = await connection.sendRawTransaction(
  await ed25519Transaction.serialize(),
  { skipPreflight: false },
);
assert.equal((await waitForStatus(connection, ed25519Signature)).err, null);
const expectedSuccessfulSignatures = [
  ...successfulSignatures,
  ed25519Signature,
];

// A failed transfer still names the recipient. It must be visible without the
// status filter and absent from Darknyx's `status: succeeded` scan.
const failureBlockhash = await connection.getLatestBlockhash("confirmed");
const failedRaw = await signLegacyTransfer(
  payer,
  recipient.publicKey,
  9_000_000_000n,
  failureBlockhash.blockhash,
);
const failedSignature = await connection.sendRawTransaction(failedRaw, {
  skipPreflight: true,
  maxRetries: 0,
});
const failedStatus = await waitForStatus(connection, failedSignature);
assert.notEqual(failedStatus.err, null, "negative control must fail on-chain");

const recipientAddress = recipient.publicKey.toBase58();
const succeeded = await gtfa(
  recipientAddress,
  gtfaConfig({ filters: { slot: { gte: floorSlot }, status: "succeeded" } }),
);
const succeededSignatures = succeeded.data.map(signatureOf);
for (const signature of expectedSuccessfulSignatures) {
  assert.equal(
    succeededSignatures.includes(signature),
    true,
    `successful transaction missing from gTFA: ${signature}`,
  );
}
assert.equal(
  succeededSignatures.includes(failedSignature),
  false,
  "failed transaction escaped status:succeeded",
);

const anyStatus = await gtfa(
  recipientAddress,
  gtfaConfig({ filters: { slot: { gte: floorSlot }, status: "any" } }),
);
assert.equal(
  anyStatus.data.map(signatureOf).includes(failedSignature),
  true,
  "failed transaction is absent from unfiltered local history",
);

const orderedKeys = succeeded.data.map((entry) => [
  entry.slot,
  entry.transactionIndex,
  signatureOf(entry),
]);
for (let index = 1; index < orderedKeys.length; index += 1) {
  assert.equal(
    orderedKeys[index - 1][0] < orderedKeys[index][0] ||
      (orderedKeys[index - 1][0] === orderedKeys[index][0] &&
        orderedKeys[index - 1][1] < orderedKeys[index][1]),
    true,
    "ascending gTFA order is not (slot, transactionIndex)",
  );
}

const firstSlot = succeeded.data[0].slot;
const inclusive = await gtfa(
  recipientAddress,
  gtfaConfig({ filters: { slot: { gte: firstSlot }, status: "succeeded" } }),
);
assert.equal(
  inclusive.data.some((entry) => entry.slot === firstSlot),
  true,
  "slot.gte must include its boundary",
);
const afterFirstSlot = await gtfa(
  recipientAddress,
  gtfaConfig({ filters: { slot: { gt: firstSlot }, status: "succeeded" } }),
);
assert.equal(
  afterFirstSlot.data.every((entry) => entry.slot > firstSlot),
  true,
  "slot.gt returned its excluded boundary",
);

const pagedSignatures = [];
let paginationToken;
do {
  const page = await gtfa(
    recipientAddress,
    gtfaConfig({
      limit: 3,
      paginationToken,
      filters: { slot: { gte: floorSlot }, status: "succeeded" },
    }),
  );
  pagedSignatures.push(...page.data.map(signatureOf));
  paginationToken = page.paginationToken ?? undefined;
} while (paginationToken);
assert.deepEqual(
  pagedSignatures,
  succeededSignatures,
  "pagination introduced a gap, overlap, or order change",
);
assert.equal(new Set(pagedSignatures).size, pagedSignatures.length);

for (const entry of succeeded.data) {
  assert.equal(Array.isArray(entry.transaction.message.accountKeys), true);
  assert.equal(Array.isArray(entry.transaction.message.instructions), true);
  assert.equal(Array.isArray(entry.meta.logMessages), true);
  assert.equal(entry.meta.err, null);
}

const sameSlotGroups = Map.groupBy(succeeded.data, (entry) => entry.slot);
const largestSameSlotGroup = Math.max(
  ...[...sameSlotGroups.values()].map((entries) => entries.length),
);
assert.equal(
  largestSameSlotGroup >= 2,
  true,
  "probe did not create same-slot activity; ordering evidence would be vacuous",
);

// Prove address discovery through loaded ALT keys, not merely v0 decoding. The
// recipient is absent from the message's static keys and is found only through
// `meta.loadedAddresses.writable`.
const altRecipient = await Keypair.generate();
const altSlot = Number(
  (await connection.getLatestBlockhashAndContext("confirmed")).context.slot,
);
const [createAltInstruction, lookupTableAddress] =
  await AddressLookupTableProgram.createLookupTable({
    authority: payer.publicKey,
    payer: payer.publicKey,
    recentSlot: altSlot,
  });
const extendAltInstruction = AddressLookupTableProgram.extendLookupTable({
  authority: payer.publicKey,
  payer: payer.publicKey,
  lookupTable: lookupTableAddress,
  addresses: [altRecipient.publicKey],
});
const altBlockhash = await connection.getLatestBlockhash("confirmed");
const altTransaction = new Transaction({
  feePayer: payer.publicKey,
  recentBlockhash: altBlockhash.blockhash,
}).add(createAltInstruction, extendAltInstruction);
await altTransaction.sign(payer);
const altSignature = await connection.sendRawTransaction(
  await altTransaction.serialize(),
  { skipPreflight: false },
);
assert.equal((await waitForStatus(connection, altSignature)).err, null);

const creationSlot = Number((await connection.getTransaction(altSignature)).slot);
while (Number(await connection.getSlot("confirmed")) <= creationSlot) {
  await new Promise((resolve) => setTimeout(resolve, 100));
}
const lookupTable = await connection.getAddressLookupTable(lookupTableAddress);
assert.notEqual(lookupTable.value, null, "created ALT must be readable");

const v0Blockhash = await connection.getLatestBlockhash("confirmed");
const v0Message = new TransactionMessage({
  payerKey: payer.publicKey,
  recentBlockhash: v0Blockhash.blockhash,
  instructions: [
    SystemProgram.transfer({
      fromPubkey: payer.publicKey,
      toPubkey: altRecipient.publicKey,
      lamports: BigInt(rent) + 1n,
    }),
  ],
}).compileToV0Message([lookupTable.value]);
const v0Transaction = new VersionedTransaction(v0Message);
await v0Transaction.sign([payer]);
const v0Signature = await connection.sendRawTransaction(
  await v0Transaction.serialize(),
  { skipPreflight: false },
);
assert.equal((await waitForStatus(connection, v0Signature)).err, null);

const v0History = await gtfa(
  altRecipient.publicKey.toBase58(),
  gtfaConfig({ filters: { status: "succeeded" } }),
);
const v0Entry = v0History.data.find(
  (entry) => signatureOf(entry) === v0Signature,
);
assert.notEqual(
  v0Entry,
  undefined,
  "gTFA did not discover a transaction through its ALT-loaded address",
);
assert.equal(v0Entry.version, 0);
assert.equal(v0Entry.transaction.message.addressTableLookups.length > 0, true);
assert.equal(
  v0Entry.meta.loadedAddresses.writable.includes(
    altRecipient.publicKey.toBase58(),
  ),
  true,
  "ALT recipient is not present in loaded writable addresses",
);
assert.equal(
  v0Entry.transaction.message.accountKeys.includes(
    altRecipient.publicKey.toBase58(),
  ),
  false,
  "ALT negative control failed: recipient unexpectedly became a static key",
);

console.log(
  JSON.stringify(
    {
      result: "pass",
      rpcUrl,
      version,
      payer: payer.publicKey.toBase58(),
      recipient: recipientAddress,
      floorSlot,
      successfulTransactions: expectedSuccessfulSignatures.length,
      failedTransactions: 1,
      pages: Math.ceil(succeededSignatures.length / 3),
      largestSameSlotGroup,
      firstSlot,
      lastSlot: succeeded.data.at(-1).slot,
      alt: lookupTableAddress.toBase58(),
      ed25519Signature,
      v0AltSignature: v0Signature,
    },
    null,
    2,
  ),
);
