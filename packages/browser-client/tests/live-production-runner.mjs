#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

const WebSocketClient = globalThis.WebSocket ?? (await import("ws")).default;

if (process.env.RUN_CVM_BROWSER_E2E !== "1") {
  process.stdout.write("live production browser test skipped\n");
  process.exit(0);
}

const origin = process.env.DARKNYX_TRADER_LIVE_ORIGIN;
if (!origin) throw new Error("DARKNYX_TRADER_LIVE_ORIGIN is required");
const parsedOrigin = new URL(origin);
if (
  parsedOrigin.protocol !== "https:" &&
  parsedOrigin.hostname !== "localhost"
) {
  throw new Error("live browser origin must be HTTPS or localhost");
}

const candidates =
  process.platform === "darwin"
    ? ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
    : [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
      ];
const chrome = process.env.CHROME_PATH ?? candidates.find(existsSync);
if (!chrome) throw new Error("Chrome/Chromium not found; set CHROME_PATH");

class Cdp {
  constructor(url) {
    this.socket = new WebSocketClient(url);
    this.pending = new Map();
    this.events = [];
    this.nextId = 1;
    this.ready = new Promise((resolveReady, rejectReady) => {
      this.socket.onopen = resolveReady;
      this.socket.onerror = () =>
        rejectReady(new Error("CDP WebSocket failed"));
    });
    this.socket.onmessage = ({ data }) => {
      const message = JSON.parse(String(data));
      const pending = this.pending.get(message.id);
      if (!pending) {
        if (
          message.method === "Runtime.exceptionThrown" ||
          message.method === "Runtime.consoleAPICalled" ||
          message.method === "Log.entryAdded" ||
          message.method === "Inspector.targetCrashed"
        ) {
          this.events.push(message);
        }
        return;
      }
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(message.error.message));
      else pending.resolve(message.result ?? {});
    };
    this.socket.onclose = () => {
      for (const { reject } of this.pending.values()) {
        reject(new Error("CDP WebSocket closed"));
      }
      this.pending.clear();
    };
  }

  async send(method, params = {}, sessionId, timeoutMs = 30_000) {
    await this.ready;
    const id = this.nextId++;
    return new Promise((resolveMessage, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP ${method} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      const settle = (callback) => (value) => {
        clearTimeout(timer);
        callback(value);
      };
      this.pending.set(id, {
        resolve: settle(resolveMessage),
        reject: settle(reject),
      });
      try {
        this.socket.send(JSON.stringify({ id, method, params, sessionId }));
      } catch (error) {
        this.pending.delete(id);
        clearTimeout(timer);
        reject(error);
      }
    });
  }

  close() {
    this.socket.close();
  }
}

const sleep = (ms) =>
  new Promise((resolveSleep) => setTimeout(resolveSleep, ms));

async function devtoolsUrl(profile) {
  const path = resolve(profile, "DevToolsActivePort");
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      const [port, browserPath] = (await readFile(path, "utf8"))
        .trim()
        .split("\n");
      if (port && browserPath) return `ws://127.0.0.1:${port}${browserPath}`;
    } catch {
      // Chrome writes the file only after its debugging socket is listening.
    }
    await sleep(50);
  }
  throw new Error("Chrome did not publish DevToolsActivePort");
}

async function terminate(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolveExit) => child.once("exit", resolveExit)),
    sleep(5_000),
  ]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

const profile = await mkdtemp(resolve(tmpdir(), "darknyx-live-chrome-"));
const child = spawn(
  chrome,
  [
    "--headless=new",
    "--no-first-run",
    "--disable-background-networking",
    "--remote-debugging-port=0",
    `--user-data-dir=${profile}`,
    "about:blank",
  ],
  { stdio: ["ignore", "ignore", "pipe"] },
);
let stderr = "";
child.stderr.on("data", (chunk) => {
  stderr += chunk.toString();
});
let cdp;
try {
  cdp = new Cdp(await devtoolsUrl(profile));
  const { product } = await cdp.send("Browser.getVersion");
  const { targetInfos } = await cdp.send("Target.getTargets");
  const target = targetInfos.find(({ type }) => type === "page");
  if (!target) throw new Error("Chrome did not expose a page target");
  const { sessionId } = await cdp.send("Target.attachToTarget", {
    targetId: target.targetId,
    flatten: true,
  });
  await cdp.send("Runtime.enable", {}, sessionId);
  await cdp.send("Log.enable", {}, sessionId);
  await cdp.send("Page.navigate", { url: origin }, sessionId);

  let snapshot;
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    const evaluated = await cdp.send(
      "Runtime.evaluate",
      {
        expression: `(() => {
          const body = document.body?.innerText ?? "";
          return {
            body,
            title: document.title,
            ready: body.includes("Attested") &&
              body.includes("SOL-USDC") &&
              body.includes("BTC-USDC") &&
              body.includes("Trading enabled") &&
              !body.includes("PAUSED") &&
              body.includes("Create private vault"),
            failed: body.includes("Venue verification failed") ||
              body.includes("Darknyx failed closed")
          };
        })()`,
        returnByValue: true,
      },
      sessionId,
    );
    snapshot = evaluated.result?.value;
    if (snapshot?.ready || snapshot?.failed) break;
    await sleep(500);
  }
  if (!snapshot?.ready) {
    throw new Error(
      `production browser did not become trusted: ${JSON.stringify(snapshot)}; ` +
        `events=${JSON.stringify(cdp.events.slice(-20))}`,
    );
  }
  process.stdout.write(
    `${JSON.stringify({
      chrome_product: product,
      title: snapshot.title,
      attested: true,
      instruments: ["SOL-USDC", "BTC-USDC"],
      vault_provisioning_offered: snapshot.body.includes(
        "Create private vault",
      ),
    })}\n`,
  );
} catch (error) {
  throw new Error(`${error.message}\n${stderr.slice(-4_000)}`);
} finally {
  cdp?.close();
  await terminate(child);
  await rm(profile, {
    recursive: true,
    force: true,
    maxRetries: 8,
    retryDelay: 100,
  });
}
