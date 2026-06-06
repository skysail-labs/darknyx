/** Indexer configuration from the environment. */
export interface IndexerConfig {
  rpcUrl: string;
  programId: string;
  dbPath: string;
  port: number;
  pollMs: number;
  /**
   * Cold-start behaviour. When true and the db has no cursor yet, seed the
   * cursor to the chain's newest signature WITHOUT backfilling — the watcher
   * then only ingests settles that arrive after boot. Essential for a
   * low-volume program (ours): its "newest 1000" signatures can span days, and
   * the watcher processes that page oldest-first (a rate-limited getTransaction
   * each), so a settle at the tip is reached minutes later. For a live e2e the
   * fill must surface in seconds, so tests set this. Default false = backfill
   * (the durable-history behaviour a production indexer wants).
   */
  startFromTip: boolean;
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
    startFromTip: env.INDEXER_START_FROM_TIP === "1",
  };
}
