// Minimal ambient declaration for the built-in `node:sqlite` (Node 22+,
// unflagged on Node 24). @types/node@20 predates it; this is the small subset
// the indexer uses. Drop this file once @types/node ships node:sqlite types.
declare module "node:sqlite" {
  export interface StatementSync {
    run(...params: unknown[]): { changes: number; lastInsertRowid: number | bigint };
    get(...params: unknown[]): unknown;
    all(...params: unknown[]): unknown[];
  }
  export class DatabaseSync {
    constructor(path: string, options?: { readOnly?: boolean });
    exec(sql: string): void;
    prepare(sql: string): StatementSync;
    close(): void;
  }
}
