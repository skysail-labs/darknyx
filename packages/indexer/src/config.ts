/** Indexer configuration from the environment. */
export interface IndexerConfig {
  rpcUrl: string;
  programId: string;
  dbPath: string;
  port: number;
  pollMs: number;
}

/** Default devnet vault program id (matches `declare_id!` in programs/vault). */
export const DEFAULT_PROGRAM_ID = "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";

export function loadConfig(env: NodeJS.ProcessEnv = process.env): IndexerConfig {
  const rpcUrl = env.INDEXER_RPC_URL;
  if (!rpcUrl) throw new Error("INDEXER_RPC_URL is required");
  return {
    rpcUrl,
    programId: env.INDEXER_PROGRAM_ID ?? DEFAULT_PROGRAM_ID,
    dbPath: env.INDEXER_DB ?? "./nyx-indexer.sqlite",
    port: Number(env.INDEXER_PORT ?? "8090"),
    pollMs: Number(env.INDEXER_POLL_MS ?? "3000"),
  };
}
