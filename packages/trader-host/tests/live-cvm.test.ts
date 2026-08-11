import WebSocket from "ws";
import { describe, expect, it } from "vitest";

const RUN = process.env.RUN_CVM_BROWSER_E2E === "1";
const ORIGIN = process.env.DARKNYX_TRADER_LIVE_ORIGIN ?? "";

function liveUrl(path: string): string {
  if (!ORIGIN) throw new Error("DARKNYX_TRADER_LIVE_ORIGIN is required");
  return new URL(path, ORIGIN).toString();
}

async function json(response: Response): Promise<Record<string, unknown>> {
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${await response.text()}`);
  }
  return (await response.json()) as Record<string, unknown>;
}

async function browserSession(): Promise<{
  cookie: string;
  token: string;
}> {
  const headers = {
    accept: "application/json",
    "content-type": "application/json",
    origin: ORIGIN,
    "sec-fetch-site": "same-origin",
    "x-darknyx-client": "browser-v1",
  };
  const body = JSON.stringify({ venue_id: "darknyx-devnet" });
  const start = await fetch(liveUrl("/api/darknyx/session/start"), {
    method: "POST",
    headers,
    body,
  });
  expect(start.status).toBe(204);
  const setCookie = start.headers.get("set-cookie");
  expect(setCookie).toMatch(/^__Host-darknyx_session=/);
  const cookie = setCookie!.split(";", 1)[0]!;
  const session = await fetch(liveUrl("/api/darknyx/session"), {
    method: "POST",
    headers: { ...headers, cookie },
    body,
  });
  const envelope = await json(session);
  expect(envelope.expires_in).toBeGreaterThanOrEqual(30);
  expect(envelope.access_token).toEqual(expect.any(String));
  return { cookie, token: envelope.access_token as string };
}

async function streamRoundTrip(cookie: string, token: string): Promise<void> {
  const url = new URL("/api/darknyx/venue/v1/stream", ORIGIN);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  await new Promise<void>((resolve, reject) => {
    const loginId = `login-${Date.now()}`;
    const pingId = `ping-${Date.now()}`;
    const socket = new WebSocket(url, {
      headers: { cookie, origin: ORIGIN },
      handshakeTimeout: 20_000,
    });
    const timer = setTimeout(() => {
      socket.terminate();
      reject(new Error("live stream did not return a pong within 20s"));
    }, 20_000);
    const finish = (error?: Error) => {
      clearTimeout(timer);
      socket.close();
      if (error) reject(error);
      else resolve();
    };
    socket.once("open", () => {
      socket.send(
        JSON.stringify({
          op: "login",
          request_id: loginId,
          token,
          cancel_on_disconnect: true,
        }),
      );
    });
    socket.on("message", (data) => {
      let frame: Record<string, unknown>;
      try {
        frame = JSON.parse(data.toString()) as Record<string, unknown>;
      } catch {
        return;
      }
      if (frame.op === "login" && frame.request_id === loginId) {
        if (frame.seq !== 1) {
          return finish(new Error(`stream login seq was ${String(frame.seq)}`));
        }
        socket.send(JSON.stringify({ op: "ping", request_id: pingId }));
      }
      if (frame.op === "pong" && frame.request_id === pingId) finish();
    });
    socket.once("error", (error) => finish(error));
  });
}

describe.skipIf(!RUN)("live standalone trader host", () => {
  it("binds a browser session to the CVM, finalized RPC, and stream", async () => {
    const release = await json(await fetch(liveUrl("/release.json")));
    expect(release.expected_compose_hash).toMatch(/^[0-9a-f]{64}$/);

    const { cookie, token } = await browserSession();
    const proxied = (path: string) =>
      fetch(liveUrl(`/api/darknyx/venue${path}`), {
        headers: { authorization: `Bearer ${token}`, cookie },
      });
    const [info, status, instruments] = await Promise.all([
      proxied("/info").then(json),
      proxied("/system/status").then(json),
      proxied("/instruments").then(async (response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${await response.text()}`);
        }
        return (await response.json()) as Array<Record<string, unknown>>;
      }),
    ]);
    expect(info.compose_hash).toBe(release.expected_compose_hash);
    expect(status).toMatchObject({
      degraded: false,
      matcher_running: true,
      settle_enabled: true,
    });
    expect(instruments.map(({ symbol }) => symbol)).toEqual([
      "SOL-USDC",
      "BTC-USDC",
    ]);
    expect(
      instruments.every(({ trading_enabled }) => trading_enabled === true),
    ).toBe(true);

    const slot = await json(
      await fetch(liveUrl("/api/darknyx/rpc"), {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "getSlot",
          params: [{ commitment: "finalized" }],
        }),
      }),
    );
    expect(slot.result).toEqual(expect.any(Number));
    expect(slot.error).toBeUndefined();
    await streamRoundTrip(cookie, token);
  }, 60_000);
});
