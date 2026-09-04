#!/usr/bin/env node

/**
 * Loopback-only RA-TLS bridge for the Rust CVM load generator.
 *
 * The production SDK deliberately pins one HTTP/1 connection so the socket
 * that answered the transport-attestation request is the socket that carries
 * private traffic. That is the right default for one daemon, but it also
 * serialises a capacity benchmark. This bridge creates a bounded pool of
 * independently verified SDK transports, requires every member to attest the
 * same boot session and SPKI, and exposes them only on 127.0.0.1. The Rust
 * loadgen can therefore preserve its offered concurrency without weakening
 * the quote-to-socket binding or accepting the enclave's self-signed
 * certificate blindly.
 *
 * Build the SDK first (`npm -w @darknyx/sdk run build`), then provide:
 *
 *   DARKNYX_TEE_GATEWAY=https://<app-id>-8443s.<dstack-domain>
 *   DARKNYX_EXPECT_COMPOSE_HASH=<64 hex>
 *   DARKNYX_EXPECT_SIGNER_SET=<64 hex>
 *
 * Optional:
 *   DARKNYX_LOAD_PROXY_CONNECTIONS=8
 *   DARKNYX_LOAD_PROXY_PORT=18080
 */

import { createServer } from "node:http";
import { randomBytes } from "node:crypto";

import {
  createDcapQuoteVerifier,
  parseEventLog,
} from "../packages/sdk/dist/index.js";
import {
  TransportAgent,
  createVerifiedFetch,
  verifyTransportOnSocket,
} from "../packages/sdk/dist/transport-node.js";

const BODY_LIMIT = 2 * 1024 * 1024;
const RESPONSE_LIMIT = 8 * 1024 * 1024;
const LOOPBACK = "127.0.0.1";

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function boundedInteger(name, fallback, min, max) {
  const raw = process.env[name]?.trim();
  const value = raw ? Number(raw) : fallback;
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer in ${min}..=${max}`);
  }
  return value;
}

function hex32(value, name) {
  if (!/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${name} must be 32 bytes of hex`);
  }
  return Uint8Array.from(value.match(/../g).map((byte) => parseInt(byte, 16)));
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= a[i] ^ b[i];
  return difference === 0;
}

function permitted(method, path) {
  if (method === "GET") {
    return (
      path === "/info" ||
      path === "/system/status" ||
      path === "/instruments" ||
      /^\/instruments\/[A-Z0-9-]{5,33}$/.test(path) ||
      /^\/orders\/[0-9a-f]{32}$/.test(path) ||
      path === "/admin/metrics/settlement" ||
      path === "/admin/drain"
    );
  }
  if (method === "POST") {
    return (
      path === "/auth/token" || path === "/orders" || path === "/admin/drain"
    );
  }
  if (method === "DELETE") {
    return /^\/orders\/[0-9a-f]{32}$/.test(path);
  }
  return false;
}

async function readBody(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > BODY_LIMIT) throw new Error("request body exceeds limit");
    chunks.push(chunk);
  }
  return chunks.length === 0 ? undefined : Buffer.concat(chunks);
}

async function main() {
  const gateway = new URL(required("DARKNYX_TEE_GATEWAY"));
  if (gateway.protocol !== "https:" || gateway.username || gateway.password) {
    throw new Error("DARKNYX_TEE_GATEWAY must be credential-free HTTPS");
  }
  gateway.pathname = "/";
  gateway.search = "";
  gateway.hash = "";

  const composeHash = required("DARKNYX_EXPECT_COMPOSE_HASH");
  if (!/^[0-9a-fA-F]{64}$/.test(composeHash)) {
    throw new Error("DARKNYX_EXPECT_COMPOSE_HASH must be 32 bytes of hex");
  }
  const signerSet = hex32(
    required("DARKNYX_EXPECT_SIGNER_SET"),
    "DARKNYX_EXPECT_SIGNER_SET",
  );
  const connections = boundedInteger(
    "DARKNYX_LOAD_PROXY_CONNECTIONS",
    8,
    1,
    32,
  );
  const port = boundedInteger("DARKNYX_LOAD_PROXY_PORT", 18080, 1024, 65535);

  const dcap = createDcapQuoteVerifier({});
  const deps = {
    verifyQuote: (quoteHex) =>
      dcap(
        Uint8Array.from(
          quoteHex.match(/../g)?.map((byte) => parseInt(byte, 16)) ?? [],
        ),
      ),
    parseEventLog,
    randomNonce: () => new Uint8Array(randomBytes(32)),
  };

  const transports = [];
  let bootSessionId;
  let spkiSha256;
  for (let i = 0; i < connections; i += 1) {
    const agent = new TransportAgent();
    const options = {
      baseUrl: gateway.origin,
      agent,
      deps,
      expectedComposeHash: composeHash,
      expectedSignerSetSha256: signerSet,
      ...(bootSessionId ? { expectedBootSessionId: bootSessionId } : {}),
    };
    const verified = await verifyTransportOnSocket(options);
    if (bootSessionId && !equalBytes(verified.manifest.bootSessionId, bootSessionId)) {
      throw new Error("verified transports disagree on boot session");
    }
    if (spkiSha256 && !equalBytes(verified.spkiSha256, spkiSha256)) {
      throw new Error("verified transports disagree on boot SPKI");
    }
    bootSessionId ??= verified.manifest.bootSessionId;
    spkiSha256 ??= verified.spkiSha256;
    transports.push({
      agent,
      fetch: createVerifiedFetch({
        ...options,
        expectedBootSessionId: bootSessionId,
      }),
      active: 0,
    });
    process.stdout.write(`verified RA-TLS connection ${i + 1}/${connections}\n`);
  }

  const server = createServer(async (request, response) => {
    try {
      const method = request.method ?? "GET";
      const parsed = new URL(request.url ?? "/", `http://${LOOPBACK}:${port}`);
      if (!permitted(method, parsed.pathname)) {
        response.writeHead(404, { "content-type": "text/plain" });
        response.end("route not available\n");
        return;
      }

      const body = await readBody(request);
      const transport = transports.reduce((best, candidate) =>
        candidate.active < best.active ? candidate : best,
      );
      transport.active += 1;
      let upstream;
      let bytes;
      try {
        const target = new URL(parsed.pathname + parsed.search, gateway);
        const headers = {};
        for (const name of ["accept", "authorization", "content-type"]) {
          const value = request.headers[name];
          if (typeof value === "string") headers[name] = value;
        }
        upstream = await transport.fetch(target, {
          method,
          headers,
          ...(body ? { body } : {}),
        });
        bytes = new Uint8Array(await upstream.arrayBuffer());
      } finally {
        transport.active -= 1;
      }

      if (bytes.length > RESPONSE_LIMIT) {
        throw new Error("upstream response exceeds limit");
      }
      const headers = {};
      for (const name of ["content-type", "retry-after"]) {
        const value = upstream.headers.get(name);
        if (value) headers[name] = value;
      }
      response.writeHead(upstream.status, headers);
      response.end(bytes);
    } catch (error) {
      const message = error instanceof Error ? error.message : "proxy failure";
      process.stderr.write(`verified load proxy refused request: ${message}\n`);
      if (!response.headersSent) {
        response.writeHead(502, { "content-type": "text/plain" });
      }
      response.end("verified upstream unavailable\n");
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, LOOPBACK, () => {
      server.off("error", reject);
      resolve();
    });
  });
  process.stdout.write(
    `VERIFIED_CVM_LOAD_PROXY_READY=http://${LOOPBACK}:${port} ` +
      `connections=${connections} boot=${Buffer.from(bootSessionId).toString("hex")}\n`,
  );

  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    await new Promise((resolve) => server.close(resolve));
    await Promise.allSettled(transports.map(({ agent }) => agent.close()));
  };
  const stopOnSignal = async () => {
    try {
      await stop();
    } catch (error) {
      const message = error instanceof Error ? error.message : "unknown failure";
      process.stderr.write(`verified load proxy shutdown failed: ${message}\n`);
      process.exitCode = 1;
    }
  };
  process.once("SIGINT", async () => {
    await stopOnSignal();
  });
  process.once("SIGTERM", async () => {
    await stopOnSignal();
  });
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : "unknown failure";
  process.stderr.write(`verified load proxy startup refused: ${message}\n`);
  process.exitCode = 1;
});
