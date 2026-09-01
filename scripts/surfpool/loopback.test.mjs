import assert from "node:assert/strict";
import test from "node:test";

import { requireLoopbackRpc } from "./loopback.mjs";

test("accepts only explicit local HTTP RPC endpoints", () => {
  for (const url of [
    "http://127.0.0.1:18899",
    "http://localhost:18899",
    "http://[::1]:18899",
  ]) {
    assert.equal(requireLoopbackRpc(url).port, "18899");
  }
});

test("rejects internet, wildcard, credentialed, and TLS endpoints", () => {
  for (const url of [
    "https://127.0.0.1:18899",
    "http://0.0.0.0:18899",
    "http://192.168.1.10:18899",
    "http://example.com:18899",
    "http://user:secret@127.0.0.1:18899",
  ]) {
    assert.throws(() => requireLoopbackRpc(url), /must|credentials/);
  }
});
