import { createServer } from "node:http";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import WebSocket, { WebSocketServer } from "ws";
import { afterEach, describe, expect, it } from "vitest";

import { createReleaseHost, type PublicRelease } from "../src/index.js";

const origin = "https://app.example";
const release: PublicRelease = {
  schema_version: 1,
  release_id: "proxy-test",
  venue_id: "devnet",
  gateway_url: `${origin}/api/darknyx/venue/`,
  rpc_url: `${origin}/api/darknyx/rpc`,
  vault_program_id: "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
  expected_compose_hash: "ab".repeat(32),
  expected_oracle_mode: "pyth-solana-push-v1",
  recovery_start_slot: 123_456,
  artifact_manifest_url: `${origin}/artifacts/manifest.json`,
  artifact_set_id: "client-artifacts-v1",
  artifact_protocol_version: 1,
  artifact_key_id: "release-key-v1",
  artifact_public_key: "A".repeat(43),
  circuit_version: "note-use-v1",
  proving_key_version: "phase2-v1",
};

const servers: ReturnType<typeof createServer>[] = [];
afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.closeAllConnections();
          server.close(() => resolve());
        }),
    ),
  );
});

async function listen(
  server: ReturnType<typeof createServer>,
): Promise<number> {
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("missing port");
  return address.port;
}

async function setup(
  options: { verifiedStream?: boolean; verifiedBufferedAmount?: number } = {},
) {
  const upstreamRequests: Array<{
    path: string;
    body: string;
    cookie?: string;
    authorization?: string;
  }> = [];
  const upstream = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += String(chunk);
    upstreamRequests.push({
      path: request.url ?? "",
      body,
      ...(request.headers.cookie ? { cookie: request.headers.cookie } : {}),
      ...(request.headers.authorization
        ? { authorization: request.headers.authorization }
        : {}),
    });
    response.setHeader("content-type", "text/plain");
    response.end(
      body ||
        JSON.stringify({
          path: request.url,
          tee_pubkey: "test",
        }),
    );
  });
  const upstreamWs = new WebSocketServer({ noServer: true });
  upstream.on("upgrade", (request, socket, head) => {
    upstreamWs.handleUpgrade(request, socket, head, (client) => {
      client.on("message", (data, binary) => client.send(data, { binary }));
    });
  });
  const upstreamPort = await listen(upstream);

  const root = await mkdtemp(join(tmpdir(), "darknyx-live-proxy-"));
  await writeFile(join(root, "index.html"), "ok");
  let random = 0;
  let tokenRequests = 0;
  let verifiedStreamConnections = 0;
  const host = createReleaseHost({
    origin,
    staticRoot: root,
    release,
    cookieKey: new Uint8Array(32).fill(5),
    issueToken: async ({ sessionId }) => {
      tokenRequests += 1;
      return {
        accountId: `account-${sessionId}`,
        accessToken: "t".repeat(64),
        expiresIn: 300,
      };
    },
    randomBytes: (length) => new Uint8Array(length).fill((random += 1)),
    gatewayUpstreamUrl: `http://localhost:${upstreamPort}/gateway/`,
    rpcUpstreamUrl: `http://localhost:${upstreamPort}/rpc?api-key=private`,
    ...(options.verifiedStream
      ? {
          cvmFetch: fetch,
          cvmWebSocketFactory: (url: string) => {
            verifiedStreamConnections += 1;
            const socket = new WebSocket(url);
            const pending: string[] = [];
            let opened = false;
            socket.once("open", () => {
              opened = true;
              for (const frame of pending.splice(0)) socket.send(frame);
            });
            return {
              get bufferedAmount() {
                return options.verifiedBufferedAmount ?? socket.bufferedAmount;
              },
              addEventListener: (type, callback) =>
                socket.addEventListener(type, callback as never),
              send: (frame) => {
                if (opened) socket.send(frame);
                else pending.push(frame);
              },
              close: () => socket.close(),
            };
          },
        }
      : {}),
  });
  const hostPort = await listen(host);
  const base = `http://127.0.0.1:${hostPort}`;
  const session = await fetch(`${base}/api/darknyx/session/start`, {
    method: "POST",
    headers: {
      origin,
      "sec-fetch-site": "same-origin",
      "content-type": "application/json",
    },
    body: JSON.stringify({ venue_id: "devnet" }),
  });
  expect(session.status).toBe(204);
  const setCookie = session.headers.get("set-cookie");
  expect(setCookie).not.toBeNull();
  const cookie = setCookie!.split(";", 1)[0];
  if (!cookie) throw new Error("session response omitted its cookie");
  return {
    base,
    cookie,
    upstreamRequests,
    tokenRequests: () => tokenRequests,
    verifiedStreamConnections: () => verifiedStreamConnections,
  };
}

function hostHeaders(cookie: string): Record<string, string> {
  return { origin, cookie };
}

function openSocket(url: string, cookie: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url, { headers: hostHeaders(cookie) });
    socket.once("open", () => resolve(socket));
    socket.once("error", reject);
  });
}

function rejectedSocketStatus(url: string, cookie: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url, { headers: hostHeaders(cookie) });
    socket.once("unexpected-response", (_request, response) => {
      resolve(response.statusCode ?? 0);
      response.destroy();
    });
    socket.once("open", () =>
      reject(new Error("socket was unexpectedly admitted")),
    );
    socket.once("error", () => undefined);
  });
}

function nextMessage(socket: WebSocket): Promise<string> {
  return new Promise((resolve) =>
    socket.once("message", (data) => resolve(String(data))),
  );
}

function closeSocket(socket: WebSocket): Promise<void> {
  if (socket.readyState === WebSocket.CLOSED) return Promise.resolve();
  return new Promise((resolve) => {
    socket.once("close", () => resolve());
    socket.close();
  });
}

describe("same-origin live proxy", () => {
  it("keeps the upstreams and RPC credential server-side", async () => {
    const { base, cookie, upstreamRequests, tokenRequests } = await setup();
    expect(tokenRequests()).toBe(0);
    const info = await fetch(`${base}/api/darknyx/venue/info`, {
      headers: { ...hostHeaders(cookie), authorization: "Bearer browser" },
    });
    expect(info.status).toBe(200);
    expect(info.headers.get("content-type")).toBe(
      "application/json; charset=utf-8",
    );
    expect(await info.json()).toMatchObject({ path: "/gateway/info" });

    const rpc = await fetch(`${base}/api/darknyx/rpc`, {
      method: "POST",
      headers: {
        ...hostHeaders(cookie),
        "content-type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getSlot" }),
    });
    expect(rpc.status).toBe(200);
    expect(upstreamRequests.map(({ path }) => path)).toContain(
      "/rpc?api-key=private",
    );
    expect(
      upstreamRequests.every(({ cookie: value }) => value === undefined),
    ).toBe(true);
    expect(upstreamRequests[0]?.authorization).toBe("Bearer browser");
    expect(JSON.parse(upstreamRequests.at(-1)?.body ?? "{}")).toMatchObject({
      method: "getSlot",
      params: [{ commitment: "finalized" }],
    });
    expect(JSON.stringify(await rpc.json())).not.toContain("api-key");
  });

  it("normalizes nested RPC commitments to finalized", async () => {
    const { base, cookie, upstreamRequests } = await setup();
    const response = await fetch(`${base}/api/darknyx/rpc`, {
      method: "POST",
      headers: {
        ...hostHeaders(cookie),
        "content-type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "getAccountInfo",
        params: [
          "account",
          {
            commitment: "processed",
            nested: { commitment: "confirmed" },
          },
        ],
      }),
    });
    expect(response.status).toBe(200);
    expect(JSON.parse(upstreamRequests.at(-1)?.body ?? "{}")).toMatchObject({
      params: [
        "account",
        {
          commitment: "finalized",
          nested: { commitment: "finalized" },
        },
      ],
    });
  });

  it("preserves confirmed only when reading back a submitted transaction", async () => {
    const { base, cookie, upstreamRequests } = await setup();
    const response = await fetch(`${base}/api/darknyx/rpc`, {
      method: "POST",
      headers: {
        ...hostHeaders(cookie),
        "content-type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "getTransaction",
        params: [
          "signature",
          { commitment: "confirmed", maxSupportedTransactionVersion: 1 },
        ],
      }),
    });
    expect(response.status).toBe(200);
    expect(JSON.parse(upstreamRequests.at(-1)?.body ?? "{}")).toMatchObject({
      method: "getTransaction",
      params: [
        "signature",
        { commitment: "confirmed", maxSupportedTransactionVersion: 1 },
      ],
    });
  });

  it("requires a signed session and rejects unknown venue and RPC methods", async () => {
    const { base, cookie } = await setup();
    expect((await fetch(`${base}/api/darknyx/venue/info`)).status).toBe(401);
    expect(
      (
        await fetch(`${base}/api/darknyx/venue/admin/drain`, {
          headers: hostHeaders(cookie),
        })
      ).status,
    ).toBe(404);
    const rejected = await fetch(`${base}/api/darknyx/rpc`, {
      method: "POST",
      headers: {
        ...hostHeaders(cookie),
        "content-type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "sendTransaction",
      }),
    });
    expect(rejected.status).toBe(400);
    expect(await rejected.json()).toEqual({ error: "rpc_method_rejected" });
  });

  it("forwards only the attestation reportData nonce", async () => {
    const { base, cookie, upstreamRequests } = await setup();
    const nonce = "ab".repeat(32);
    const accepted = await fetch(
      `${base}/api/darknyx/venue/attestation?reportData=${nonce}`,
      { headers: hostHeaders(cookie) },
    );
    expect(accepted.status).toBe(200);
    expect(upstreamRequests.at(-1)?.path).toBe(
      `/gateway/attestation?reportData=${nonce}`,
    );
    for (const query of [
      `report_data=${nonce}`,
      `reportData=${nonce}&extra=1`,
      "reportData=ab",
      "reportData=not-hex",
      `reportData=${"AB".repeat(32)}`,
    ]) {
      const rejected = await fetch(
        `${base}/api/darknyx/venue/attestation?${query}`,
        { headers: hostHeaders(cookie) },
      );
      expect(rejected.status).toBe(400);
      expect(await rejected.json()).toEqual({ error: "query_rejected" });
    }
  });

  it("bridges only the venue stream and allowlisted Solana subscriptions", async () => {
    const { base, cookie } = await setup();
    const wsBase = base.replace("http://", "ws://");
    const venue = await openSocket(
      `${wsBase}/api/darknyx/venue/v1/stream`,
      cookie,
    );
    const venueMessage = nextMessage(venue);
    venue.send(JSON.stringify({ op: "login", token: "t".repeat(64) }));
    await expect(venueMessage).resolves.toContain('"op":"login"');
    await closeSocket(venue);

    const rpc = await openSocket(`${wsBase}/api/darknyx/rpc`, cookie);
    const rpcMessage = nextMessage(rpc);
    rpc.send(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "signatureSubscribe",
        params: ["signature"],
      }),
    );
    await expect(rpcMessage).resolves.toContain("signatureSubscribe");
    const closed = new Promise<number>((resolve) =>
      rpc.once("close", (code) => resolve(code)),
    );
    rpc.send(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "accountSubscribe",
      }),
    );
    await expect(closed).resolves.toBe(1008);
  });

  it("routes the venue stream through the supplied verified factory", async () => {
    const { base, cookie, verifiedStreamConnections } = await setup({
      verifiedStream: true,
    });
    const venue = await openSocket(
      `${base.replace("http://", "ws://")}/api/darknyx/venue/v1/stream`,
      cookie,
    );
    const echoed = nextMessage(venue);
    venue.send(JSON.stringify({ op: "login", token: "t".repeat(64) }));
    await expect(echoed).resolves.toContain('"op":"login"');
    expect(verifiedStreamConnections()).toBe(1);
    await closeSocket(venue);
  });

  it("closes a verified relay before its upstream buffer exceeds the cap", async () => {
    const { base, cookie } = await setup({
      verifiedStream: true,
      verifiedBufferedAmount: 2 * 1024 * 1024,
    });
    const venue = await openSocket(
      `${base.replace("http://", "ws://")}/api/darknyx/venue/v1/stream`,
      cookie,
    );
    const closed = new Promise<number>((resolve) =>
      venue.once("close", (code) => resolve(code)),
    );
    venue.send(JSON.stringify({ op: "login", token: "t".repeat(64) }));
    await expect(closed).resolves.toBe(1009);
  });

  it("caps live relays per authenticated browser session", async () => {
    const { base, cookie } = await setup();
    const url = `${base.replace("http://", "ws://")}/api/darknyx/venue/v1/stream`;
    const sockets: WebSocket[] = [];
    for (let index = 0; index < 4; index += 1) {
      sockets.push(await openSocket(url, cookie));
    }
    await expect(rejectedSocketStatus(url, cookie)).resolves.toBe(429);
    await closeSocket(sockets[0]!);
    const replacement = await openSocket(url, cookie);
    await Promise.all([
      closeSocket(replacement),
      ...sockets.slice(1).map(closeSocket),
    ]);
  });

  it("closes keep-alive after rejecting an oversized request body", async () => {
    const { base, cookie } = await setup();
    const response = await fetch(`${base}/api/darknyx/venue/orders`, {
      method: "POST",
      headers: {
        ...hostHeaders(cookie),
        "content-type": "application/json",
      },
      body: "x".repeat(2 * 1024 * 1024 + 1),
    });
    expect(response.status).toBe(413);
    expect(response.headers.get("connection")).toBe("close");
  });
});
