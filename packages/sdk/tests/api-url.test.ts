import { describe, expect, it } from "vitest";

import { apiUrl } from "../src/api-url.js";

describe("API URL composition", () => {
  it("preserves direct gateways and reverse-proxy path prefixes", () => {
    expect(apiUrl("https://cvm.example", "system/status").toString()).toBe(
      "https://cvm.example/system/status",
    );
    expect(
      apiUrl(
        "https://trade.example/api/darknyx/venue/",
        "/orders/0123456789abcdef0123456789abcdef",
      ).toString(),
    ).toBe(
      "https://trade.example/api/darknyx/venue/orders/0123456789abcdef0123456789abcdef",
    );
    expect(
      apiUrl(
        "https://trade.example/api/darknyx/venue",
        "tree/inclusion",
      ).toString(),
    ).toBe("https://trade.example/api/darknyx/venue/tree/inclusion");
  });
});
