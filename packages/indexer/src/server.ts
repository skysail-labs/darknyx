/**
 * Read-only HTTP surface (built-in `node:http`, zero deps).
 *
 *   GET /health                      → { ok: true }
 *   GET /fills?order_id=<hex>        → { fills: FillRow[] }   (optionally &since=<slot>)
 *   GET /fills?order_ids=<hex,hex>   → { byOrder: { [orderId]: FillRow[] } }
 *
 * Account-agnostic by design: the client queries by its own deterministic order
 * ids. The indexer never learns the account↔order linkage.
 */

import http from "node:http";
import type { FillsDb } from "./db.js";

function json(res: http.ServerResponse, status: number, body: unknown): void {
  const buf = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { "content-type": "application/json", "content-length": buf.length });
  res.end(buf);
}

export function createServer(db: FillsDb): http.Server {
  return http.createServer((req, res) => {
    if (req.method !== "GET") return json(res, 405, { error: "method not allowed" });
    const url = new URL(req.url ?? "/", "http://localhost");

    if (url.pathname === "/health") return json(res, 200, { ok: true });

    if (url.pathname === "/fills") {
      const since = Number(url.searchParams.get("since") ?? "0");
      if (!Number.isFinite(since) || since < 0) return json(res, 400, { error: "bad since" });

      const ordersCsv = url.searchParams.get("order_ids");
      if (ordersCsv) {
        const ids = ordersCsv.split(",").map((s) => s.trim()).filter(Boolean);
        const byOrder: Record<string, unknown> = {};
        for (const id of ids) byOrder[id] = db.getFillsByOrder(id, since);
        return json(res, 200, { byOrder });
      }

      const id = url.searchParams.get("order_id");
      if (!id) return json(res, 400, { error: "order_id or order_ids required" });
      return json(res, 200, { fills: db.getFillsByOrder(id, since) });
    }

    return json(res, 404, { error: "not found" });
  });
}

/** Start listening; resolves with the bound port (useful when port = 0 in tests). */
export function startServer(db: FillsDb, port: number): Promise<{ server: http.Server; port: number }> {
  const server = createServer(db);
  return new Promise((resolve) => {
    server.listen(port, () => {
      const addr = server.address();
      const bound = typeof addr === "object" && addr ? addr.port : port;
      resolve({ server, port: bound });
    });
  });
}
