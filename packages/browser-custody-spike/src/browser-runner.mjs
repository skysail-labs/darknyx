#!/usr/bin/env node
import { spawn } from "node:child_process";
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

const sourceRoot = import.meta.dirname;
const repositoryRoot = resolve(sourceRoot, "../../..");
const chromeCandidates =
  process.platform === "darwin"
    ? ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
    : [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
      ];
const chrome =
  process.env.CHROME_PATH ??
  chromeCandidates.find((candidate) => existsSync(candidate));
if (!chrome) {
  throw new Error("Chrome/Chromium not found; set CHROME_PATH explicitly");
}
const timeoutMs = Number(process.env.CUSTODY_SPIKE_TIMEOUT_MS ?? 180_000);

const assets = new Map(
  await Promise.all(
    [
      ["/", "browser-page.html", "text/html; charset=utf-8"],
      ["/browser-page.js", "browser-page.js", "text/javascript; charset=utf-8"],
      [
        "/browser-vault.js",
        "browser-vault.js",
        "text/javascript; charset=utf-8",
      ],
      ["/codec.js", "codec.js", "text/javascript; charset=utf-8"],
      [
        "/indexeddb-store.js",
        "indexeddb-store.js",
        "text/javascript; charset=utf-8",
      ],
      ["/webauthn-prf.js", "webauthn-prf.js", "text/javascript; charset=utf-8"],
      ["/vault-worker.js", "vault-worker.js", "text/javascript; charset=utf-8"],
    ].map(async ([url, file, contentType]) => [
      url,
      { body: await readFile(resolve(sourceRoot, file)), contentType },
    ]),
  ),
);
const scryptSource = await readFile(
  resolve(sourceRoot, "../../../node_modules/scrypt-js/scrypt.js"),
);
const vaultWorker = assets.get("/vault-worker.js");
vaultWorker.body = Buffer.concat([
  scryptSource,
  Buffer.from("\n;\n"),
  vaultWorker.body,
]);

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "connect-src 'self'",
  "worker-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types darknyx-vault-worker",
].join("; ");
const BACKUP_AAD = Buffer.from("darknyx/master-seed-backup/v2", "utf8");
const BACKUP_PASSPHRASE = "correct horse battery staple";

function openBrowserBackup(backup) {
  if (
    backup?.format !== "darknyx-master-seed-backup" ||
    backup.version !== 2 ||
    backup.kdf?.name !== "scrypt" ||
    backup.kdf.n !== 131_072 ||
    backup.kdf.r !== 8 ||
    backup.kdf.p !== 1 ||
    backup.cipher?.name !== "aes-256-gcm"
  ) {
    throw new Error("browser emitted an unsupported backup envelope");
  }
  const salt = Buffer.from(backup.kdf.salt, "hex");
  const iv = Buffer.from(backup.cipher.iv, "hex");
  const ciphertext = Buffer.from(backup.cipher.ciphertext, "hex");
  const tag = Buffer.from(backup.cipher.tag, "hex");
  if (
    salt.length !== 16 ||
    iv.length !== 12 ||
    ciphertext.length !== 64 ||
    tag.length !== 16
  ) {
    throw new Error("browser emitted malformed backup fields");
  }
  const key = scryptSync(BACKUP_PASSPHRASE, salt, 32, {
    N: 131_072,
    r: 8,
    p: 1,
    maxmem: 256 * 1024 * 1024,
  });
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(BACKUP_AAD);
    decipher.setAuthTag(tag);
    const seed = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (seed.length !== 64)
      throw new Error("browser backup contained a non-64-byte seed");
    return seed;
  } finally {
    key.fill(0);
  }
}

function sealNodeBackup(seed) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(BACKUP_PASSPHRASE, salt, 32, {
    N: 131_072,
    r: 8,
    p: 1,
    maxmem: 256 * 1024 * 1024,
  });
  try {
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(BACKUP_AAD);
    const ciphertext = Buffer.concat([cipher.update(seed), cipher.final()]);
    return {
      format: "darknyx-master-seed-backup",
      version: 2,
      kdf: {
        name: "scrypt",
        n: 131_072,
        r: 8,
        p: 1,
        salt: salt.toString("hex"),
      },
      cipher: {
        name: "aes-256-gcm",
        iv: iv.toString("hex"),
        ciphertext: ciphertext.toString("hex"),
        tag: cipher.getAuthTag().toString("hex"),
      },
    };
  } finally {
    key.fill(0);
  }
}

class CdpClient {
  constructor(url) {
    this.socket = new WebSocket(url);
    this.nextId = 1;
    this.pending = new Map();
    this.ready = new Promise((resolvePromise, reject) => {
      this.socket.onopen = resolvePromise;
      this.socket.onerror = () =>
        reject(new Error("CDP WebSocket failed to open"));
    });
    this.socket.onmessage = ({ data }) => {
      const message = JSON.parse(
        typeof data === "string" ? data : data.toString(),
      );
      if (!message.id) return;
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(message.error.message));
      else pending.resolve(message.result ?? {});
    };
  }

  async send(method, params = {}, sessionId) {
    await this.ready;
    const id = this.nextId++;
    return new Promise((resolvePromise, reject) => {
      this.pending.set(id, { resolve: resolvePromise, reject });
      this.socket.send(
        JSON.stringify({
          id,
          method,
          params,
          ...(sessionId ? { sessionId } : {}),
        }),
      );
    });
  }

  close() {
    this.socket.close();
  }
}

async function waitForDevTools(profile) {
  const path = resolve(profile, "DevToolsActivePort");
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    try {
      const [port, browserPath] = (await readFile(path, "utf8"))
        .trim()
        .split("\n");
      if (port && browserPath) return `ws://127.0.0.1:${port}${browserPath}`;
    } catch {
      // Chrome writes the file after the remote-debugging server is ready.
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
  }
  throw new Error("Chrome did not publish DevToolsActivePort");
}

async function runScenario({ hasPrf, scenario }) {
  let finish;
  const resultPromise = new Promise((resolvePromise) => {
    finish = resolvePromise;
  });
  const server = createServer(async (request, response) => {
    response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
    response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    response.setHeader("Content-Security-Policy", CSP);
    response.setHeader("Cache-Control", "no-store");
    const url = new URL(request.url, "http://127.0.0.1");
    if (request.method === "POST" && url.pathname === "/result") {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      finish(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      response.writeHead(204).end();
      return;
    }
    if (request.method === "POST" && url.pathname === "/progress") {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const progress = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      process.stderr.write(`${scenario}: ${progress.stage}\n`);
      response.writeHead(204).end();
      return;
    }
    if (request.method === "POST" && url.pathname === "/interop") {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      let seed;
      try {
        seed = openBrowserBackup(
          JSON.parse(Buffer.concat(chunks).toString("utf8")),
        );
        response.setHeader("Content-Type", "application/json");
        response.end(
          JSON.stringify({
            browser_backup_opened_by_node: true,
            node_backup: sealNodeBackup(seed),
          }),
        );
      } finally {
        seed?.fill(0);
      }
      return;
    }
    if (url.pathname === "/config.json") {
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify({ hasPrf, scenario }));
      return;
    }
    const asset = assets.get(url.pathname);
    if (!asset) {
      response.writeHead(404).end();
      return;
    }
    response.setHeader("Content-Type", asset.contentType);
    response.end(asset.body);
  });
  await new Promise((resolvePromise) =>
    server.listen(0, "127.0.0.1", resolvePromise),
  );
  const address = server.address();
  const profile = await mkdtemp(resolve(tmpdir(), "darknyx-custody-chrome-"));
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
  let timeout;
  try {
    cdp = new CdpClient(await waitForDevTools(profile));
    const { targetInfos } = await cdp.send("Target.getTargets");
    const page = targetInfos.find(({ type }) => type === "page");
    if (!page) throw new Error("Chrome exposed no page target");
    const { sessionId } = await cdp.send("Target.attachToTarget", {
      targetId: page.targetId,
      flatten: true,
    });
    await cdp.send("WebAuthn.enable", { enableUI: false }, sessionId);
    await cdp.send(
      "WebAuthn.addVirtualAuthenticator",
      {
        options: {
          protocol: "ctap2",
          ctap2Version: "ctap2_1",
          transport: "internal",
          hasResidentKey: true,
          hasUserVerification: true,
          hasPrf,
          automaticPresenceSimulation: true,
          isUserVerified: true,
        },
      },
      sessionId,
    );
    await cdp.send("Page.enable", {}, sessionId);
    await cdp.send(
      "Page.navigate",
      // WebAuthn RP IDs are domain names; the loopback IP is a secure context
      // but is not a valid RP ID in Chrome. `localhost` is both.
      { url: `http://localhost:${address.port}/` },
      sessionId,
    );
    const timedOut = new Promise((resolvePromise) => {
      timeout = setTimeout(
        () =>
          resolvePromise({
            ok: false,
            scenario,
            error: `timed out after ${timeoutMs} ms`,
          }),
        timeoutMs,
      );
    });
    const result = await Promise.race([resultPromise, timedOut]);
    if (!result.ok) {
      throw new Error(`${scenario}: ${result.error ?? JSON.stringify(result)}`);
    }
    return result.result;
  } catch (error) {
    throw new Error(
      `${error.message}\nChrome stderr:\n${stderr.slice(-4_000)}`,
    );
  } finally {
    clearTimeout(timeout);
    cdp?.close();
    if (child.exitCode === null) {
      const exited = new Promise((resolvePromise) =>
        child.once("exit", resolvePromise),
      );
      child.kill("SIGTERM");
      await exited;
    }
    await new Promise((resolvePromise) => server.close(resolvePromise));
    await rm(profile, { recursive: true, force: true });
  }
}

const started = new Date().toISOString();
const supported = await runScenario({
  hasPrf: true,
  scenario: "prf-supported",
});
const unsupported = await runScenario({
  hasPrf: false,
  scenario: "prf-unsupported",
});
const report = {
  schema_version: 1,
  started_at: started,
  completed_at: new Date().toISOString(),
  chrome_path: chrome,
  supported,
  unsupported,
};

const requiredTrue = [
  "provision_unlock_same_seed",
  "locked_command_rejected",
  "ciphertext_tamper_rejected",
  "inactivity_locked",
  "backup_v2_roundtrip_same_seed",
  "browser_backup_opened_by_node",
  "node_backup_opened_by_browser",
  "same_origin_attack_succeeded",
  "terminated_worker_rejected",
  "cross_origin_isolated",
];
for (const field of requiredTrue) {
  if (supported[field] !== true)
    throw new Error(`required result ${field} was not true`);
}
if (
  supported.indexeddb_contains_plaintext_seed ||
  supported.wrapping_key_extractable ||
  supported.service_worker_registrations !== 0 ||
  unsupported.prf_unsupported_failed_closed !== true
) {
  throw new Error("browser custody acceptance assertion failed");
}
if (process.env.CUSTODY_SPIKE_OUTPUT) {
  const output = resolve(repositoryRoot, process.env.CUSTODY_SPIKE_OUTPUT);
  await mkdir(resolve(output, ".."), { recursive: true });
  await writeFile(output, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  process.stderr.write(`wrote ${output}\n`);
}
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
