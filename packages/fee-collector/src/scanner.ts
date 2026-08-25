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

function decodeInstruction(value: unknown): ScannedVaultInstruction | null {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return null;
  const instruction = value as GtfaInstruction;
  if (
    typeof instruction.programId !== "string" ||
    typeof instruction.data !== "string" ||
    !Array.isArray(instruction.accounts) ||
    !instruction.accounts.every((account) => typeof account === "string")
  ) {
    return null;
  }
  return {
    programId: instruction.programId,
    accounts: [...instruction.accounts] as string[],
    data: base58Decode(instruction.data),
  };
}

function decodeTransaction(value: unknown): FinalizedVaultTransaction | null {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return null;
  const item = value as GtfaTransaction;
  if (
    typeof item.slot !== "number" ||
    !Number.isSafeInteger(item.slot) ||
    item.meta?.err ||
    !Array.isArray(item.transaction?.signatures) ||
    typeof item.transaction.signatures[0] !== "string" ||
    !Array.isArray(item.transaction.message?.instructions)
  ) {
    return null;
  }
  const innerByParent = new Map<number, ScannedVaultInstruction[]>();
  if (Array.isArray(item.meta?.innerInstructions)) {
    for (const rawGroup of item.meta.innerInstructions) {
      if (
        typeof rawGroup !== "object" ||
        rawGroup === null ||
        Array.isArray(rawGroup)
      ) {
        continue;
      }
      const group = rawGroup as GtfaInnerInstructionGroup;
      if (
        !Number.isInteger(group.index) ||
        !Array.isArray(group.instructions)
      ) {
        continue;
      }
      const decoded = group.instructions
        .map(decodeInstruction)
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
    const decoded = decodeInstruction(rawInstruction);
    if (decoded) instructions.push(decoded);
    instructions.push(...(innerByParent.get(index) ?? []));
  }
  const logs = Array.isArray(item.meta?.logMessages)
    ? item.meta.logMessages.filter(
        (line): line is string => typeof line === "string",
      )
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
      maxSupportedTransactionVersion: 0,
      filters,
    };
    if (paginationToken) config.paginationToken = paginationToken;
    const response = await fetchFn(params.rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "getTransactionsForAddress",
        params: [params.programId, config],
      }),
    });
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
      const decoded = decodeTransaction(transaction);
      if (decoded) out.push(decoded);
    }
    const next = payload.result.paginationToken;
    if (next !== null && next !== undefined && typeof next !== "string") {
      throw new Error("finalized history RPC returned a malformed cursor");
    }
    paginationToken =
      typeof next === "string" && next.length > 0 ? next : undefined;
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
    }
    return pending;
  };
}
