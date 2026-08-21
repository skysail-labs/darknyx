#!/usr/bin/env node
import { spawn } from "node:child_process";
import {
  createHash,
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Keypair, PublicKey } from "@solana/web3.js";
import {
  bn254ToBE32,
  buildDepositInstruction,
  deriveBlindingFactor,
  deriveDepositInnerHash,
  deriveNoteSecret,
  deriveOwnerCommitmentBlinding,
  deriveSpendingKey,
  noteCommitmentV2,
  ownerCommitment,
} from "@darknyx/sdk";

const root = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
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

const passphrase = "correct horse battery staple";
const aad = Buffer.from("darknyx/master-seed-backup/v2");
const expectedSeed = randomBytes(64);
const recoveryAmount = 987_654_321n;
const recoveryProgramId = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);
const recoveryPayer = new PublicKey(new Uint8Array(32).fill(0x52));
const recoveryBaseMint = new Uint8Array(32).fill(0xb1);
const recoveryQuoteMint = new Uint8Array(32).fill(0x9e);
const browserWallet = Keypair.generate().publicKey;

const concatBytes = (...parts) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

const u64le = (value) => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
};

async function recoveryFixture() {
  const owner = await ownerCommitment(
    deriveSpendingKey(expectedSeed),
    deriveOwnerCommitmentBlinding(expectedSeed),
  );
  const nonce = bn254ToBE32(deriveBlindingFactor(expectedSeed, 77n));
  const inner = await deriveDepositInnerHash(
    bn254ToBE32(owner),
    nonce,
    bn254ToBE32(deriveNoteSecret(expectedSeed, nonce)),
  );
  const innerHash = BigInt(`0x${Buffer.from(inner).toString("hex")}`);
  const commitment = await noteCommitmentV2({
    tokenMint: recoveryQuoteMint,
    amount: recoveryAmount,
    ownerCommitment: owner,
    innerHash,
  });
  const instruction = await buildDepositInstruction({
    programId: recoveryProgramId,
    treeId: 0,
    depositor: recoveryPayer,
    tokenMint: new PublicKey(recoveryQuoteMint),
    depositorTokenAccount: recoveryPayer,
    tokenProgramId: recoveryProgramId,
    amount: recoveryAmount,
    noteCommitment: commitment,
    recoveryNonce: nonce,
    proof: {
      piA: new Uint8Array(64).fill(1),
      piB: new Uint8Array(128).fill(2),
      piC: new Uint8Array(64).fill(3),
    },
  });
  const discriminator = createHash("sha256")
    .update("event:NoteCreated")
    .digest()
    .subarray(0, 8);
  const event = concatBytes(
    discriminator,
    new Uint8Array([0]),
    u64le(7n),
    commitment,
    recoveryQuoteMint,
    u64le(recoveryAmount),
    new Uint8Array(32),
  );
  return {
    program_id: recoveryProgramId.toBase58(),
    base_mint: Buffer.from(recoveryBaseMint).toString("hex"),
    quote_mint: Buffer.from(recoveryQuoteMint).toString("hex"),
    quote_mint_base58: new PublicKey(recoveryQuoteMint).toBase58(),
    amount: recoveryAmount.toString(),
    transaction: {
      signature: "browser-recovery-deposit",
      slot: 101,
      ix_data: Buffer.from(instruction.data).toString("base64"),
      logs: [
        `Program ${recoveryProgramId.toBase58()} invoke [1]`,
        `Program data: ${Buffer.from(event).toString("base64")}`,
        `Program ${recoveryProgramId.toBase58()} success`,
      ],
    },
  };
}

function sealBackup(seed) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(passphrase, salt, 32, {
    N: 16_384,
    r: 8,
    p: 1,
    maxmem: 32 * 1024 * 1024,
  });
  try {
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(seed), cipher.final()]);
    return {
      format: "darknyx-master-seed-backup",
      version: 2,
      kdf: {
        name: "scrypt",
        n: 16_384,
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

function openBackup(backup) {
  if (
    backup?.format !== "darknyx-master-seed-backup" ||
    backup.version !== 2 ||
    backup.kdf?.name !== "scrypt" ||
    backup.kdf.n !== 131_072 ||
    backup.kdf.r !== 8 ||
    backup.kdf.p !== 1 ||
    backup.cipher?.name !== "aes-256-gcm"
  )
    throw new Error("browser emitted an unsupported backup");
  const salt = Buffer.from(backup.kdf.salt, "hex");
  const iv = Buffer.from(backup.cipher.iv, "hex");
  const ciphertext = Buffer.from(backup.cipher.ciphertext, "hex");
  const tag = Buffer.from(backup.cipher.tag, "hex");
  const key = scryptSync(passphrase, salt, 32, {
    N: 131_072,
    r: 8,
    p: 1,
    maxmem: 256 * 1024 * 1024,
  });
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } finally {
    key.fill(0);
  }
}

class Cdp {
  constructor(url) {
    this.socket = new WebSocket(url);
    this.pending = new Map();
    this.nextId = 1;
    this.events = [];
    this.closing = false;
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
      if (this.closing) return;
      for (const { reject } of this.pending.values()) {
        reject(new Error("CDP WebSocket closed"));
      }
      this.pending.clear();
    };
  }
  async send(method, params = {}, sessionId) {
    await this.ready;
    const id = this.nextId++;
    return new Promise((resolveMessage, reject) => {
      this.pending.set(id, { resolve: resolveMessage, reject });
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
    this.closing = true;
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
    } catch {}
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }
  throw new Error("Chrome did not publish DevToolsActivePort");
}

async function terminate(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  await new Promise((resolveExit) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolveExit();
    }, 2_000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolveExit();
    });
  });
}

const page = await readFile(resolve(root, "tests/browser-page.html"));
const pageScript = await readFile(resolve(root, "tests/browser-page.js"));
const nodeBackup = sealBackup(expectedSeed);
const browserRecoveryFixture = await recoveryFixture();
const csp = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "connect-src 'self'",
  "worker-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types darknyx-vault-worker",
].join("; ");

async function scenario(hasPrf, scenarioName) {
  let finish;
  const resultPromise = new Promise((resolveResult) => {
    finish = resolveResult;
  });
  const server = createServer(async (request, response) => {
    try {
      response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
      response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
      response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
      response.setHeader("Content-Security-Policy", csp);
      response.setHeader("Cache-Control", "no-store");
      const url = new URL(request.url, "http://localhost");
      if (request.method === "POST" && url.pathname === "/result") {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        finish(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        response.writeHead(204).end();
        return;
      }
      if (request.method === "POST" && url.pathname === "/interop") {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const { browserBackup, restoredRecord } = JSON.parse(
          Buffer.concat(chunks).toString("utf8"),
        );
        const restored = openBackup(browserBackup);
        const recordText = JSON.stringify(restoredRecord);
        response.setHeader("Content-Type", "application/json");
        response.end(
          JSON.stringify({
            same_seed:
              restored.length === expectedSeed.length &&
              restored.equals(expectedSeed),
            indexeddb_contains_plaintext_seed:
              recordText.includes(expectedSeed.toString("hex")) ||
              recordText.includes(expectedSeed.toString("base64")) ||
              recordText.includes(expectedSeed.toString("base64url")),
          }),
        );
        restored.fill(0);
        return;
      }
      if (request.method === "POST" && url.pathname === "/rpc") {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const requestBody = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        response.setHeader("Content-Type", "application/json");
        if (requestBody.method === "getLatestBlockhash") {
          response.end(
            JSON.stringify({
              jsonrpc: "2.0",
              id: requestBody.id,
              result: {
                context: { slot: 101 },
                value: {
                  blockhash: recoveryPayer.toBase58(),
                  lastValidBlockHeight: 999999,
                },
              },
            }),
          );
          return;
        }
        response.end(
          JSON.stringify({
            jsonrpc: "2.0",
            id: requestBody.id,
            error: { code: -32601, message: "method not found" },
          }),
        );
        return;
      }
      if (url.pathname === "/config.json") {
        response.setHeader("Content-Type", "application/json");
        response.end(
          JSON.stringify({
            hasPrf,
            scenario: scenarioName,
            passphrase,
            node_backup: nodeBackup,
            recovery: browserRecoveryFixture,
            wallet_address: browserWallet.toBase58(),
          }),
        );
        return;
      }
      const asset = {
        "/": [page, "text/html; charset=utf-8"],
        "/browser-page.js": [pageScript, "text/javascript; charset=utf-8"],
      }[url.pathname];
      if (url.pathname.startsWith("/dist/")) {
        const distRoot = resolve(root, "dist");
        const assetPath = resolve(root, url.pathname.slice(1));
        if (!assetPath.startsWith(`${distRoot}/`)) {
          response.writeHead(404).end();
          return;
        }
        response.setHeader("Content-Type", "text/javascript; charset=utf-8");
        response.end(await readFile(assetPath));
        return;
      }
      if (!asset) {
        response.writeHead(404).end();
        return;
      }
      response.setHeader("Content-Type", asset[1]);
      response.end(asset[0]);
    } catch (error) {
      response.writeHead(500).end(String(error));
    }
  });
  await new Promise((resolveListen) =>
    server.listen(0, "localhost", resolveListen),
  );
  const port = server.address().port;
  const profile = await mkdtemp(resolve(tmpdir(), "darknyx-product-chrome-"));
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
  let timer;
  try {
    cdp = new Cdp(await waitForDevTools(profile));
    const { product } = await cdp.send("Browser.getVersion");
    const { targetInfos } = await cdp.send("Target.getTargets");
    const target = targetInfos.find(({ type }) => type === "page");
    const { sessionId } = await cdp.send("Target.attachToTarget", {
      targetId: target.targetId,
      flatten: true,
    });
    await cdp.send("WebAuthn.enable", { enableUI: false }, sessionId);
    await cdp.send("Runtime.enable", {}, sessionId);
    await cdp.send("Log.enable", {}, sessionId);
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
    await cdp.send(
      "Page.navigate",
      { url: `http://localhost:${port}/` },
      sessionId,
    );
    const timeout = new Promise((resolveTimeout) => {
      timer = setTimeout(
        () => resolveTimeout({ ok: false, error: "browser test timed out" }),
        180_000,
      );
    });
    const result = await Promise.race([resultPromise, timeout]);
    if (!result.ok) {
      const progress = await cdp.send(
        "Runtime.evaluate",
        { expression: "document.querySelector('#status')?.textContent" },
        sessionId,
      );
      throw new Error(
        `${result.error}; page progress=${progress.result?.value ?? "unknown"}; ` +
          `browser events=${JSON.stringify(cdp.events.slice(-20))}`,
      );
    }
    return { ...result.result, chrome_product: product };
  } catch (error) {
    throw new Error(
      `${scenarioName}: ${error.message}\n${stderr.slice(-4000)}`,
    );
  } finally {
    clearTimeout(timer);
    cdp?.close();
    await terminate(child);
    await new Promise((resolveClose) => server.close(resolveClose));
    await rm(profile, {
      recursive: true,
      force: true,
      maxRetries: 8,
      retryDelay: 100,
    });
  }
}

try {
  const supported = await scenario(true, "prf-supported");
  const unsupported = await scenario(false, "prf-unsupported");
  for (const field of [
    "provision_unlock_lock",
    "ciphertext_tamper_rejected",
    "status_polling_did_not_extend_inactivity",
    "backup_v2_node_to_browser_to_node",
    "encrypted_inventory_roundtrip",
    "browser_seed_chain_recovery",
    "inventory_revoked_on_lock",
    "inventory_tamper_rejected",
    "busy_during_backup",
    "ui_responsive_during_backup",
    "cross_origin_isolated",
    "trusted_types_available",
    "trusted_types_enforced",
  ])
    if (supported[field] !== true) throw new Error(`${field} was not true`);
  if (
    supported.indexeddb_contains_plaintext_seed !== false ||
    supported.service_worker_registrations !== 0 ||
    unsupported.unsupported_prf_failed_closed !== true
  ) {
    throw new Error("browser custody acceptance assertion failed");
  }
  process.stdout.write(
    `${JSON.stringify({ supported, unsupported }, null, 2)}\n`,
  );
} finally {
  expectedSeed.fill(0);
}
