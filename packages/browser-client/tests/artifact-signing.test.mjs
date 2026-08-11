import { describe, expect, it } from "vitest";

import { signArtifactPayload } from "../scripts/artifact-signing.mjs";

describe("artifact-manifest signing domain", () => {
  it("matches the fixed Ed25519 signing vector", () => {
    const key = Buffer.from(
      "MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f",
      "base64",
    );
    const signature = signArtifactPayload(
      Buffer.from('{"fixture":true}'),
      key,
    );
    expect(signature.toString("base64url")).toBe(
      "5WBTXGWvdemkmy29-ZJnvLRo8Jvno-X4KidYRDZYEqY44eYOJ4H7-Z4uAsCjFnZtqM24u2lNEN4MQrUZStzgDg",
    );
  });
});
