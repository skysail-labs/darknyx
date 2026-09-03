import { Connection, PublicKey } from "@solana/web3.js";
import { decodeMarketConfig } from "@darknyx/sdk";
import { base58Decode } from "./base58.js";
import type {
  FinalizedVaultTransaction,
  MarketResolver,
  ScannedVaultInstruction,
} from "./types.js";

interface GtfaInstruction {
  programId?: unknown;
  accounts?: unknown;
  data?: unknown;
}

interface GtfaTransaction {
  slot?: unknown;
  transaction?: {
    signatures?: unknown;
    message?: { instructions?: unknown };
  };
  meta?: {
    err?: unknown;
    logMessages?: unknown;
    innerInstructions?: unknown;
  } | null;
}

interface GtfaInnerInstructionGroup {
  index?: unknown;
  instructions?: unknown;
}

const HISTORY_FETCH_ATTEMPTS = 4;
const DEFAULT_HISTORY_REQUEST_TIMEOUT_MS = 30_000;

function transportCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const cause = (error as { cause?: unknown }).cause;
  if (typeof cause !== "object" || cause === null) return undefined;
  const code = (cause as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

async function fetchHistoryPage(
  fetchFn: typeof fetch,
  rpcUrl: string,
  init: RequestInit,
  retryDelayMs: number,
  requestTimeoutMs: number,
): Promise<Response> {
  for (let attempt = 1; attempt <= HISTORY_FETCH_ATTEMPTS; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);
    try {
      const response = await fetchFn(rpcUrl, {
        ...init,
        signal: init.signal
          ? AbortSignal.any([init.signal, controller.signal])
          : controller.signal,
      });
      const retryable = response.status === 429 || response.status >= 500;
      if (!retryable || attempt === HISTORY_FETCH_ATTEMPTS) return response;
    } catch (error) {
      if (attempt === HISTORY_FETCH_ATTEMPTS) {
        const code = transportCode(error);
        throw new Error(
          `finalized history RPC transport failed after ${HISTORY_FETCH_ATTEMPTS} attempts${code ? ` (${code})` : ""}`,
        );
      }
    } finally {
      clearTimeout(timeout);
    }
    if (retryDelayMs > 0) {
      await new Promise((resolve) =>
        setTimeout(resolve, retryDelayMs * 2 ** (attempt - 1)),
      );
    }
  }
  throw new Error("finalized history RPC retry loop exhausted");
}

function decodeInstruction(
  value: unknown,
  programId: string,
): ScannedVaultInstruction | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("finalized history contains a malformed instruction");
  }
  const instruction = value as GtfaInstruction;
  if (typeof instruction.programId !== "string") {
    throw new Error("finalized history instruction has no program id");
  }
  if (instruction.programId !== programId) return null;
  if (
    typeof instruction.data !== "string" ||
    !Array.isArray(instruction.accounts) ||
    !instruction.accounts.every((account) => typeof account === "string")
  ) {
    throw new Error("finalized history contains a malformed vault instruction");
  }
  return {
    programId: instruction.programId,
    accounts: [...instruction.accounts] as string[],
    data: base58Decode(instruction.data),
  };
}

function decodeTransaction(
  value: unknown,
  programId: string,
): FinalizedVaultTransaction | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("finalized history contains a malformed transaction");
  }
  const item = value as GtfaTransaction;
  if (item.meta?.err) return null;
  if (
    typeof item.slot !== "number" ||
    !Number.isSafeInteger(item.slot) ||
    !Array.isArray(item.transaction?.signatures) ||
    typeof item.transaction.signatures[0] !== "string" ||
    !Array.isArray(item.transaction.message?.instructions)
  ) {
    throw new Error("finalized history contains a malformed transaction");
  }
  const innerByParent = new Map<number, ScannedVaultInstruction[]>();
  if (
    item.meta?.innerInstructions !== undefined &&
    item.meta.innerInstructions !== null &&
    !Array.isArray(item.meta.innerInstructions)
  ) {
    throw new Error("finalized history contains malformed inner instructions");
  }
  if (Array.isArray(item.meta?.innerInstructions)) {
    for (const rawGroup of item.meta.innerInstructions) {
      if (
        typeof rawGroup !== "object" ||
        rawGroup === null ||
        Array.isArray(rawGroup)
      ) {
        throw new Error(
          "finalized history contains a malformed inner-instruction group",
        );
      }
      const group = rawGroup as GtfaInnerInstructionGroup;
      if (
        !Number.isInteger(group.index) ||
        !Array.isArray(group.instructions)
      ) {
        throw new Error(
          "finalized history contains a malformed inner-instruction group",
        );
      }
      const decoded = group.instructions
        .map((instruction) => decodeInstruction(instruction, programId))
        .filter(
          (instruction): instruction is ScannedVaultInstruction =>
            instruction !== null,
        );
      innerByParent.set(group.index as number, decoded);
    }
  }
  const instructions: ScannedVaultInstruction[] = [];
  for (const [
    index,
    rawInstruction,
  ] of item.transaction.message.instructions.entries()) {
    const decoded = decodeInstruction(rawInstruction, programId);
    if (decoded) instructions.push(decoded);
    instructions.push(...(innerByParent.get(index) ?? []));
  }
  if (
    item.meta?.logMessages !== undefined &&
    item.meta.logMessages !== null &&
    (!Array.isArray(item.meta.logMessages) ||
      !item.meta.logMessages.every((line) => typeof line === "string"))
  ) {
    throw new Error("finalized history contains malformed log messages");
  }
  const logs = Array.isArray(item.meta?.logMessages)
    ? ([...item.meta.logMessages] as string[])
    : [];
  return {
    signature: item.transaction.signatures[0],
    slot: item.slot as number,
    instructions,
    logMessages: logs,
  };
}

/**
 * Scan successful vault transactions oldest-first at finalized commitment.
 * Helius gTFA is required because the collector needs archival full
 * instructions without an N+1 transaction fan-out.
 */
export async function scanFinalizedVaultHistory(params: {
  rpcUrl: string;
  programId: string;
  sinceSlot?: number;
  pageLimit?: number;
  fetchFn?: typeof fetch;
  retryDelayMs?: number;
  requestTimeoutMs?: number;
}): Promise<FinalizedVaultTransaction[]> {
  const pageLimit = params.pageLimit ?? 100;
  if (!Number.isInteger(pageLimit) || pageLimit < 1 || pageLimit > 100) {
    throw new Error("gTFA page limit must be in [1, 100]");
  }
  if (
    params.sinceSlot !== undefined &&
    (!Number.isSafeInteger(params.sinceSlot) || params.sinceSlot < 0)
  ) {
    throw new Error("recovery start slot must be a non-negative safe integer");
  }
  const fetchFn = params.fetchFn ?? fetch;
  const retryDelayMs = params.retryDelayMs ?? 250;
  if (!Number.isInteger(retryDelayMs) || retryDelayMs < 0) {
    throw new Error("history retry delay must be a non-negative integer");
  }
  const requestTimeoutMs =
    params.requestTimeoutMs ?? DEFAULT_HISTORY_REQUEST_TIMEOUT_MS;
  if (!Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 1) {
    throw new Error("history request timeout must be a positive integer");
  }
  const out: FinalizedVaultTransaction[] = [];
  let paginationToken: string | undefined;
  do {
    const filters: Record<string, unknown> = { status: "succeeded" };
    if (params.sinceSlot !== undefined)
      filters.slot = { gte: params.sinceSlot };
    const config: Record<string, unknown> = {
      transactionDetails: "full",
      encoding: "jsonParsed",
      sortOrder: "asc",
      limit: pageLimit,
      commitment: "finalized",
      maxSupportedTransactionVersion: 1,
      filters,
    };
    if (paginationToken) config.paginationToken = paginationToken;
    const response = await fetchHistoryPage(
      fetchFn,
      params.rpcUrl,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "getTransactionsForAddress",
          params: [params.programId, config],
        }),
      },
      retryDelayMs,
      requestTimeoutMs,
    );
    if (!response.ok)
      throw new Error(`finalized history RPC returned HTTP ${response.status}`);
    const payload = (await response.json()) as {
      error?: { message?: unknown };
      result?: { data?: unknown; paginationToken?: unknown };
    };
    if (payload.error)
      throw new Error("finalized history RPC rejected the scan");
    if (!Array.isArray(payload.result?.data)) {
      throw new Error("finalized history RPC returned a malformed page");
    }
    for (const transaction of payload.result.data) {
      const decoded = decodeTransaction(transaction, params.programId);
      if (decoded) out.push(decoded);
    }
    const next = payload.result.paginationToken;
    if (next !== null && next !== undefined && typeof next !== "string") {
      throw new Error("finalized history RPC returned a malformed cursor");
    }
    const nextToken =
      typeof next === "string" && next.length > 0 ? next : undefined;
    if (nextToken !== undefined && nextToken === paginationToken) {
      throw new Error("finalized history RPC cursor did not advance");
    }
    paginationToken = nextToken;
  } while (paginationToken);
  return out;
}

/** Resolve immutable market mint identity from the finalized on-chain PDA. */
export function makeFinalizedMarketResolver(
  rpcUrl: string,
  programId: string,
): MarketResolver {
  const connection = new Connection(rpcUrl, "finalized");
  const owner = new PublicKey(programId);
  const cache = new Map<string, ReturnType<MarketResolver>>();
  return async (address) => {
    let pending = cache.get(address);
    if (!pending) {
      pending = (async () => {
        const pubkey = new PublicKey(address);
        const account = await connection.getAccountInfo(pubkey, "finalized");
        if (!account || !account.owner.equals(owner)) {
          throw new Error(
            "market config is missing or owned by another program",
          );
        }
        const market = decodeMarketConfig(account.data);
        return {
          address: pubkey.toBytes(),
          baseMint: market.baseMint.toBytes(),
          quoteMint: market.quoteMint.toBytes(),
        };
      })();
      cache.set(address, pending);
      void pending.catch(() => {
        if (cache.get(address) === pending) cache.delete(address);
      });
    }
    return pending;
  };
}
