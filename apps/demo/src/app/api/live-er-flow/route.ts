import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { resolve } from "node:path";

import {
  batchResultsPda,
  bn254ToBE32,
  buildDelegatePendingOrderInstruction,
  buildInitPendingOrderSlotInstruction,
  buildRunBatchInstruction,
  buildSubmitOrderInstruction,
  darkClobPda,
  getDarkPoolClient,
  getDepositFunction,
  pendingOrderPda,
  UnimplementedProverSuite,
  type DarkPoolClient,
} from "@nyx/sdk";
import {
  buildDelegateBatchResultsInstruction,
  buildDelegateDarkClobInstruction,
  buildDelegateMatchingConfigInstruction,
  buildUndelegateMarketInstruction,
  waitForL1AccountChange,
} from "@nyx/sdk/dist/idl/er-client.js";
import {
  createAssociatedTokenAccountIdempotentInstruction,
  createMintToInstruction,
  getAssociatedTokenAddress,
} from "@solana/spl-token";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  sendAndConfirmTransaction,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import bs58 from "bs58";
import { NextResponse } from "next/server";
import nacl from "tweetnacl";

export const runtime = "nodejs";

type Action =
  | "per_auth"
  | "bootstrap"
  | "submit_taker"
  | "submit_maker"
  | "run_batch";

interface FlowStateActor {
  role: "taker" | "maker";
  tradingPubkey: string;
  slotIdx: number;
  noteCommitmentHex: string;
  ownerCommitmentHex: string;
  noteAmount: string;
  depositSignature?: string;
  orderSignature?: string;
  orderIdHex?: string;
}

interface FlowState {
  updatedAt: string;
  taker?: FlowStateActor;
  maker?: FlowStateActor;
  runBatchSignature?: string;
  undelegateSignature?: string;
}

interface E2EConfig {
  l1RpcUrl: string;
  vaultProgramId: string;
  matchingEngineProgramId: string;
  pythAccount: string;
  market: { pubkey: string };
  baseMint: { pubkey: string };
  quoteMint: { pubkey: string };
}

interface SignatureItem {
  label: string;
  signature: string;
  cluster: "l1" | "er";
}

interface RouteCtx {
  repoRoot: string;
  statePath: string;
  l1: Connection;
  er: Connection;
  erRpcUrl: string;
  cfg: E2EConfig;
  vaultProgramId: PublicKey;
  meProgramId: PublicKey;
  market: PublicKey;
  pythAccount: PublicKey;
  baseMint: PublicKey;
  quoteMint: PublicKey;
  admin: Keypair;
  funder: Keypair;
  tee: Keypair;
  taker: Keypair;
  maker: Keypair;
  perBaseUrl: string;
  signatures: SignatureItem[];
}

const DELEGATION_PROGRAM_ID = new PublicKey(
  "DELeGGvXpWV2fqJUhqcF5ZSYMS4JTLjteaAMARRSaeSh",
);

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function fromHex(hex: string): Uint8Array {
  const cleaned = hex.startsWith("0x") ? hex.slice(2) : hex;
  return new Uint8Array(Buffer.from(cleaned, "hex"));
}

function expandUserPath(inputPath: string): string {
  if (inputPath.startsWith("~/")) {
    return resolve(homedir(), inputPath.slice(2));
  }
  return inputPath;
}

function resolveRepoRoot(): string {
  const cwd = process.cwd();
  if (existsSync(resolve(cwd, "packages", "sdk"))) return cwd;
  const upTwo = resolve(cwd, "..", "..");
  if (existsSync(resolve(upTwo, "packages", "sdk"))) return upTwo;
  throw new Error(
    "Unable to resolve monorepo root from current working directory.",
  );
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required env: ${name}`);
  return value;
}

function keypairFromBase58(secret: string): Keypair {
  const bytes = bs58.decode(secret.trim());
  if (bytes.length === 64) return Keypair.fromSecretKey(bytes);
  if (bytes.length === 32) return Keypair.fromSeed(bytes);
  throw new Error(
    "Base58 key must decode to 32-byte seed or 64-byte secret key.",
  );
}

function loadKeypairFromPath(repoRoot: string, maybeRelative: string): Keypair {
  const expanded = expandUserPath(maybeRelative);
  const absolute = expanded.startsWith("/")
    ? expanded
    : resolve(repoRoot, expanded);
  const raw = JSON.parse(readFileSync(absolute, "utf8")) as number[];
  return Keypair.fromSecretKey(new Uint8Array(raw));
}

function actorSeed(role: "taker" | "maker", kp: Keypair): Uint8Array {
  const h1 = createHash("sha256")
    .update(`demo-${role}-seed-v1`)
    .update(kp.publicKey.toBytes())
    .digest();
  const h2 = createHash("sha256")
    .update(`demo-${role}-seed-v2`)
    .update(kp.publicKey.toBytes())
    .digest();
  return new Uint8Array(Buffer.concat([h1, h2]));
}

function makeClient(
  connection: Connection,
  erRpcUrl: string,
  vaultProgramId: PublicKey,
  meProgramId: PublicKey,
  signer: Keypair,
  role: "taker" | "maker",
): DarkPoolClient {
  const seed = actorSeed(role, signer);
  const storage = {
    load: async () => seed,
    store: async () => undefined,
  };
  return getDarkPoolClient({
    programId: vaultProgramId,
    matchingEngineProgramId: meProgramId,
    seedMode: { type: "csprng", storage },
    connectionProvider: { connection, perRpcUrl: erRpcUrl },
    providers: {
      accountInfoProvider: {
        getAccountInfo: async (pubkey: PublicKey) => {
          const account = await connection.getAccountInfo(pubkey, "confirmed");
          if (!account) return null;
          return { data: account.data, owner: account.owner };
        },
      },
      transactionForwarder: {
        sendAndConfirm: async (txOrIxs) => {
          const tx = Array.isArray(txOrIxs)
            ? new Transaction().add(...txOrIxs)
            : txOrIxs;
          return sendAndConfirmTransaction(connection, tx, [signer], {
            commitment: "confirmed",
          });
        },
      },
      merkleProofProvider: {
        getInclusionProof: async () => {
          throw new Error("Merkle proof provider not required for this flow.");
        },
      },
    },
    zkProver: new UnimplementedProverSuite(
      "not needed for deposit/submit flow",
    ),
    ownerCommitmentBlinding: role === "taker" ? BigInt(1111) : BigInt(2222),
  });
}

async function ensureTopUp(ctx: RouteCtx, recipient: PublicKey): Promise<void> {
  const minLamports = Math.floor(0.06 * LAMPORTS_PER_SOL);
  const current = await ctx.l1.getBalance(recipient, "confirmed");
  if (current >= minLamports) return;
  const delta = minLamports - current;
  const sig = await sendAndConfirmTransaction(
    ctx.l1,
    new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: ctx.funder.publicKey,
        toPubkey: recipient,
        lamports: delta,
      }),
    ),
    [ctx.funder],
    { commitment: "confirmed" },
  );
  ctx.signatures.push({
    label: `Fund ${recipient.toBase58().slice(0, 6)}…`,
    signature: sig,
    cluster: "l1",
  });
}

async function readState(path: string): Promise<FlowState> {
  try {
    const raw = await readFile(path, "utf8");
    return JSON.parse(raw) as FlowState;
  } catch {
    return { updatedAt: new Date(0).toISOString() };
  }
}

async function writeState(path: string, state: FlowState): Promise<void> {
  await mkdir(resolve(path, ".."), { recursive: true });
  await writeFile(path, JSON.stringify(state, null, 2), "utf8");
}

async function chooseFreshSlot(
  l1: Connection,
  meProgramId: PublicKey,
  market: PublicKey,
  tradingKey: PublicKey,
): Promise<number> {
  for (let idx = 0; idx < 8; idx++) {
    const [pda] = pendingOrderPda(meProgramId, market, tradingKey, idx);
    const info = await l1.getAccountInfo(pda, "confirmed");
    if (!info) return idx;
  }
  return Number(BigInt(Date.now()) % BigInt(8));
}

async function ensureSlotDelegated(
  ctx: RouteCtx,
  trading: Keypair,
  slotIdx: number,
): Promise<void> {
  const [slotPda] = pendingOrderPda(
    ctx.meProgramId,
    ctx.market,
    trading.publicKey,
    slotIdx,
  );
  let info = await ctx.l1.getAccountInfo(slotPda, "confirmed");
  if (!info) {
    const initSig = await sendAndConfirmTransaction(
      ctx.l1,
      new Transaction().add(
        buildInitPendingOrderSlotInstruction({
          programId: ctx.meProgramId,
          tradingKey: trading.publicKey,
          market: ctx.market,
          slotIdx,
        }),
      ),
      [trading],
      { commitment: "confirmed" },
    );
    ctx.signatures.push({
      label: `init_pending_order_slot[${slotIdx}]`,
      signature: initSig,
      cluster: "l1",
    });
    info = await ctx.l1.getAccountInfo(slotPda, "confirmed");
  }
  if (!info) throw new Error("pending order slot missing after init");
  if (info.owner.equals(DELEGATION_PROGRAM_ID)) return;
  const delSig = await sendAndConfirmTransaction(
    ctx.l1,
    new Transaction().add(
      buildDelegatePendingOrderInstruction({
        programId: ctx.meProgramId,
        payer: ctx.funder.publicKey,
        tradingKey: trading.publicKey,
        market: ctx.market,
        slotIdx,
      }),
    ),
    [ctx.funder, trading],
    { commitment: "confirmed" },
  );
  ctx.signatures.push({
    label: `delegate_pending_order[${slotIdx}]`,
    signature: delSig,
    cluster: "l1",
  });
}

async function ensureMarketDelegated(ctx: RouteCtx): Promise<void> {
  const [clobPda] = darkClobPda(ctx.meProgramId, ctx.market);
  const clob = await ctx.l1.getAccountInfo(clobPda, "confirmed");
  if (!clob) throw new Error("DarkCLOB account missing on L1.");
  if (clob.owner.equals(DELEGATION_PROGRAM_ID)) return;

  const sig = await sendAndConfirmTransaction(
    ctx.l1,
    new Transaction().add(
      buildDelegateDarkClobInstruction({
        programId: ctx.meProgramId,
        payer: ctx.funder.publicKey,
        market: ctx.market,
      }),
      buildDelegateMatchingConfigInstruction({
        programId: ctx.meProgramId,
        payer: ctx.funder.publicKey,
        market: ctx.market,
      }),
      buildDelegateBatchResultsInstruction({
        programId: ctx.meProgramId,
        payer: ctx.funder.publicKey,
        market: ctx.market,
      }),
    ),
    [ctx.funder],
    { commitment: "confirmed" },
  );
  ctx.signatures.push({
    label: "delegate market PDAs",
    signature: sig,
    cluster: "l1",
  });
}

async function buildCtx(): Promise<RouteCtx> {
  const repoRoot = resolveRepoRoot();
  const cfgPath = resolve(repoRoot, ".devnet", "e2e-config.json");
  const cfg = JSON.parse(readFileSync(cfgPath, "utf8")) as E2EConfig;

  const l1RpcUrl = process.env.DEMO_L1_RPC_URL ?? cfg.l1RpcUrl;
  const erRpcUrl =
    process.env.DEMO_ER_RPC_URL ?? "https://devnet.magicblock.app";
  const perBaseUrl = (
    process.env.DEMO_PER_BASE_URL ?? "https://tee.magicblock.app"
  ).replace(/\/$/, "");

  const statePath = resolve(repoRoot, ".devnet", "demo-live-state.json");

  return {
    repoRoot,
    statePath,
    l1: new Connection(l1RpcUrl, "confirmed"),
    er: new Connection(erRpcUrl, "confirmed"),
    erRpcUrl,
    cfg,
    vaultProgramId: new PublicKey(cfg.vaultProgramId),
    meProgramId: new PublicKey(cfg.matchingEngineProgramId),
    market: new PublicKey(cfg.market.pubkey),
    pythAccount: new PublicKey(cfg.pythAccount),
    baseMint: new PublicKey(cfg.baseMint.pubkey),
    quoteMint: new PublicKey(cfg.quoteMint.pubkey),
    admin: loadKeypairFromPath(
      repoRoot,
      process.env.DEMO_ADMIN_KEYPAIR_PATH ?? ".devnet/keypairs/admin.json",
    ),
    funder: loadKeypairFromPath(
      repoRoot,
      process.env.DEMO_FUNDER_KEYPAIR_PATH ?? "~/.config/solana/id.json",
    ),
    tee: loadKeypairFromPath(
      repoRoot,
      process.env.DEMO_TEE_KEYPAIR_PATH ??
        ".devnet/keypairs/tee_authority.json",
    ),
    taker: keypairFromBase58(requireEnv("DEMO_TAKER_SECRET_BASE58")),
    maker: keypairFromBase58(requireEnv("DEMO_MAKER_SECRET_BASE58")),
    perBaseUrl,
    signatures: [],
  };
}

async function handlePerAuth(ctx: RouteCtx) {
  const challengeRes = await fetch(
    `${ctx.perBaseUrl}/auth/challenge?pubkey=${ctx.taker.publicKey.toBase58()}`,
  );
  if (!challengeRes.ok) {
    throw new Error(`PER challenge failed (${challengeRes.status}).`);
  }
  const { challenge } = (await challengeRes.json()) as { challenge: string };
  const sig = nacl.sign.detached(
    new Uint8Array(Buffer.from(challenge, "utf8")),
    ctx.taker.secretKey,
  );
  const loginRes = await fetch(`${ctx.perBaseUrl}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      pubkey: ctx.taker.publicKey.toBase58(),
      challenge,
      signature: bs58.encode(sig),
    }),
  });
  if (!loginRes.ok) {
    throw new Error(`PER login failed (${loginRes.status}).`);
  }
  const { token } = (await loginRes.json()) as { token: string };
  return {
    message: "PER challenge/login succeeded.",
    tokenPreview: token.slice(0, 16),
  };
}

async function handleBootstrap(ctx: RouteCtx) {
  const quoteDeposit = BigInt(process.env.DEMO_TAKER_QUOTE_DEPOSIT ?? "5000");
  const baseDeposit = BigInt(process.env.DEMO_MAKER_BASE_DEPOSIT ?? "30");

  await ensureTopUp(ctx, ctx.taker.publicKey);
  await ensureTopUp(ctx, ctx.maker.publicKey);

  const takerQuoteAta = await getAssociatedTokenAddress(
    ctx.quoteMint,
    ctx.taker.publicKey,
  );
  const makerBaseAta = await getAssociatedTokenAddress(
    ctx.baseMint,
    ctx.maker.publicKey,
  );

  const mintSig = await sendAndConfirmTransaction(
    ctx.l1,
    new Transaction().add(
      createAssociatedTokenAccountIdempotentInstruction(
        ctx.admin.publicKey,
        takerQuoteAta,
        ctx.taker.publicKey,
        ctx.quoteMint,
      ),
      createAssociatedTokenAccountIdempotentInstruction(
        ctx.admin.publicKey,
        makerBaseAta,
        ctx.maker.publicKey,
        ctx.baseMint,
      ),
      createMintToInstruction(
        ctx.quoteMint,
        takerQuoteAta,
        ctx.admin.publicKey,
        Number(quoteDeposit),
      ),
      createMintToInstruction(
        ctx.baseMint,
        makerBaseAta,
        ctx.admin.publicKey,
        Number(baseDeposit),
      ),
    ),
    [ctx.admin],
    { commitment: "confirmed" },
  );
  ctx.signatures.push({
    label: "mint demo balances",
    signature: mintSig,
    cluster: "l1",
  });

  const takerClient = makeClient(
    ctx.l1,
    ctx.erRpcUrl,
    ctx.vaultProgramId,
    ctx.meProgramId,
    ctx.taker,
    "taker",
  );
  const makerClient = makeClient(
    ctx.l1,
    ctx.erRpcUrl,
    ctx.vaultProgramId,
    ctx.meProgramId,
    ctx.maker,
    "maker",
  );
  const takerDeposit = getDepositFunction({ client: takerClient });
  const makerDeposit = getDepositFunction({ client: makerClient });

  const takerNonce = BigInt(Date.now());
  const makerNonce = BigInt(Date.now() + 777);
  const takerReceipt = await takerDeposit({
    depositor: ctx.taker.publicKey,
    tokenMint: ctx.quoteMint.toBytes(),
    amount: quoteDeposit,
    depositorTokenAccount: takerQuoteAta,
    nonce: takerNonce,
  });
  ctx.signatures.push({
    label: "taker deposit",
    signature: takerReceipt.signature,
    cluster: "l1",
  });

  const makerReceipt = await makerDeposit({
    depositor: ctx.maker.publicKey,
    tokenMint: ctx.baseMint.toBytes(),
    amount: baseDeposit,
    depositorTokenAccount: makerBaseAta,
    nonce: makerNonce,
  });
  ctx.signatures.push({
    label: "maker deposit",
    signature: makerReceipt.signature,
    cluster: "l1",
  });

  const takerSlot = await chooseFreshSlot(
    ctx.l1,
    ctx.meProgramId,
    ctx.market,
    ctx.taker.publicKey,
  );
  const makerSlot = await chooseFreshSlot(
    ctx.l1,
    ctx.meProgramId,
    ctx.market,
    ctx.maker.publicKey,
  );
  await ensureSlotDelegated(ctx, ctx.taker, takerSlot);
  await ensureSlotDelegated(ctx, ctx.maker, makerSlot);
  await ensureMarketDelegated(ctx);

  const state: FlowState = {
    updatedAt: new Date().toISOString(),
    taker: {
      role: "taker",
      tradingPubkey: ctx.taker.publicKey.toBase58(),
      slotIdx: takerSlot,
      noteCommitmentHex: toHex(takerReceipt.noteCommitment),
      ownerCommitmentHex: toHex(
        bn254ToBE32(takerReceipt.notePlaintext.ownerCommitment),
      ),
      noteAmount: quoteDeposit.toString(),
      depositSignature: takerReceipt.signature,
    },
    maker: {
      role: "maker",
      tradingPubkey: ctx.maker.publicKey.toBase58(),
      slotIdx: makerSlot,
      noteCommitmentHex: toHex(makerReceipt.noteCommitment),
      ownerCommitmentHex: toHex(
        bn254ToBE32(makerReceipt.notePlaintext.ownerCommitment),
      ),
      noteAmount: baseDeposit.toString(),
      depositSignature: makerReceipt.signature,
    },
  };
  await writeState(ctx.statePath, state);

  return {
    message:
      "Bootstrap complete: minted balances, deposited notes, delegated slots.",
    state,
  };
}

function ownerCommitmentBytesFromState(actor: FlowStateActor): Uint8Array {
  return fromHex(actor.ownerCommitmentHex);
}

async function handleSubmitOrder(ctx: RouteCtx, role: "taker" | "maker") {
  const state = await readState(ctx.statePath);
  const actor = role === "taker" ? state.taker : state.maker;
  if (!actor) throw new Error("Missing bootstrap state. Run bootstrap first.");
  const signer = role === "taker" ? ctx.taker : ctx.maker;
  const side = role === "taker" ? 0 : 1;
  const amount = BigInt(process.env.DEMO_ORDER_BASE_AMOUNT ?? "30");
  const price = BigInt(process.env.DEMO_ORDER_PRICE ?? "100");
  const now = await ctx.l1.getSlot("confirmed");
  const expiry = BigInt(now) + BigInt(500);
  const orderId = randomBytes(16);
  if (orderId.every((b) => b === 0)) orderId[0] = 1;

  const { ix } = buildSubmitOrderInstruction({
    programId: ctx.meProgramId,
    tradingKey: signer.publicKey,
    market: ctx.market,
    slotIdx: actor.slotIdx,
    side,
    amount,
    priceLimit: price,
    noteAmount: BigInt(actor.noteAmount),
    expirySlot: expiry,
    orderId,
    noteCommitment: fromHex(actor.noteCommitmentHex),
    userCommitment: ownerCommitmentBytesFromState(actor),
  });
  const sig = await sendAndConfirmTransaction(
    ctx.er,
    new Transaction().add(ix),
    [signer],
    { commitment: "confirmed" },
  );
  ctx.signatures.push({
    label: `${role} submit_order`,
    signature: sig,
    cluster: "er",
  });

  const next = await readState(ctx.statePath);
  if (role === "taker" && next.taker) {
    next.taker.orderSignature = sig;
    next.taker.orderIdHex = toHex(orderId);
  }
  if (role === "maker" && next.maker) {
    next.maker.orderSignature = sig;
    next.maker.orderIdHex = toHex(orderId);
  }
  next.updatedAt = new Date().toISOString();
  await writeState(ctx.statePath, next);

  return {
    message: `${role} order submitted to ER.`,
    state: next,
  };
}

async function handleRunBatch(ctx: RouteCtx) {
  const state = await readState(ctx.statePath);
  if (!state.taker || !state.maker) {
    throw new Error(
      "Missing state for taker/maker. Run bootstrap and order submits first.",
    );
  }
  const [takerPda] = pendingOrderPda(
    ctx.meProgramId,
    ctx.market,
    new PublicKey(state.taker.tradingPubkey),
    state.taker.slotIdx,
  );
  const [makerPda] = pendingOrderPda(
    ctx.meProgramId,
    ctx.market,
    new PublicKey(state.maker.tradingPubkey),
    state.maker.slotIdx,
  );
  const [batchPda] = batchResultsPda(ctx.meProgramId, ctx.market);
  const preBatch = await ctx.l1.getAccountInfo(batchPda, "confirmed");
  const preHex = preBatch ? Buffer.from(preBatch.data).toString("hex") : null;

  const runSig = await sendAndConfirmTransaction(
    ctx.er,
    new Transaction().add(
      buildRunBatchInstruction({
        programId: ctx.meProgramId,
        vaultProgramId: ctx.vaultProgramId,
        teeAuthority: ctx.tee.publicKey,
        market: ctx.market,
        pythAccount: ctx.pythAccount,
        pendingOrderPdas: [takerPda, makerPda],
      }),
    ),
    [ctx.tee],
    { commitment: "confirmed" },
  );
  ctx.signatures.push({
    label: "run_batch",
    signature: runSig,
    cluster: "er",
  });

  const undSig = await sendAndConfirmTransaction(
    ctx.er,
    new Transaction().add(
      buildUndelegateMarketInstruction({
        programId: ctx.meProgramId,
        payer: ctx.funder.publicKey,
        market: ctx.market,
      }),
    ),
    [ctx.funder],
    { commitment: "confirmed" },
  );
  ctx.signatures.push({
    label: "undelegate_market",
    signature: undSig,
    cluster: "er",
  });
  await waitForL1AccountChange(ctx.l1, batchPda, preHex, {
    timeoutMs: 90_000,
    intervalMs: 1000,
  });

  state.runBatchSignature = runSig;
  state.undelegateSignature = undSig;
  state.updatedAt = new Date().toISOString();
  await writeState(ctx.statePath, state);

  return {
    message: "run_batch completed and market state committed to L1.",
    state,
  };
}

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as { action?: Action };
    const action = body.action;
    if (!action) {
      return NextResponse.json(
        { ok: false, error: "Missing action." },
        { status: 400 },
      );
    }

    const ctx = await buildCtx();

    let payload: Record<string, unknown>;
    if (action === "per_auth") payload = await handlePerAuth(ctx);
    else if (action === "bootstrap") payload = await handleBootstrap(ctx);
    else if (action === "submit_taker") {
      payload = await handleSubmitOrder(ctx, "taker");
    } else if (action === "submit_maker") {
      payload = await handleSubmitOrder(ctx, "maker");
    } else if (action === "run_batch") payload = await handleRunBatch(ctx);
    else {
      return NextResponse.json(
        { ok: false, error: `Unsupported action: ${String(action)}` },
        { status: 400 },
      );
    }

    return NextResponse.json({
      ok: true,
      action,
      signatures: ctx.signatures,
      ...payload,
    });
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      },
      { status: 500 },
    );
  }
}
