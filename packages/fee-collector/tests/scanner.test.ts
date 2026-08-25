import { describe, expect, it, vi } from "vitest";

import { anchorDiscriminator } from "@darknyx/sdk";
import { scanFinalizedVaultHistory } from "../src/scanner.js";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(value: Uint8Array): string {
  let number = 0n;
  for (const byte of value) number = number * 256n + BigInt(byte);
  let encoded = "";
  while (number > 0n) {
    encoded = ALPHABET[Number(number % 58n)] + encoded;
    number /= 58n;
  }
  let zeros = 0;
  while (zeros < value.length && value[zeros] === 0) zeros += 1;
  return "1".repeat(zeros) + encoded;
}

describe("Helius finalized vault-history scanner", () => {
  it("requests finalized successful history, paginates, and decodes raw instructions", async () => {
    const instructionData = anchorDiscriminator("verify_match_batch");
    const fetchFn = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            result: {
              data: [
                {
                  slot: 11,
                  transaction: {
                    signatures: ["signature-1"],
                    message: {
                      instructions: [
                        {
                          programId: "system-program",
                          parsed: { type: "transfer" },
                        },
                        {
                          programId: "vault-program",
                          accounts: ["a", "b", "c"],
                          data: base58Encode(instructionData),
                        },
                      ],
                    },
                  },
                  meta: {
                    err: null,
                    logMessages: ["log"],
                    innerInstructions: [
                      {
                        index: 0,
                        instructions: [
                          {
                            programId: "vault-program",
                            accounts: ["admin", "vault"],
                            data: base58Encode(
                              anchorDiscriminator("set_protocol_config"),
                            ),
                          },
                        ],
                      },
                    ],
                  },
                },
              ],
              paginationToken: "next-page",
            },
          }),
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ result: { data: [], paginationToken: null } }),
        ),
      );
    const result = await scanFinalizedVaultHistory({
      rpcUrl: "https://example.invalid/?api-key=secret",
      programId: "vault-program",
      sinceSlot: 10,
      fetchFn,
    });
    expect(result).toHaveLength(1);
    expect(
      result[0].instructions.map((instruction) => instruction.data),
    ).toEqual([anchorDiscriminator("set_protocol_config"), instructionData]);
    const firstRequest = JSON.parse(String(fetchFn.mock.calls[0][1]?.body)) as {
      params: [string, Record<string, unknown>];
    };
    expect(firstRequest.params[1]).toMatchObject({
      commitment: "finalized",
      transactionDetails: "full",
      sortOrder: "asc",
      filters: { status: "succeeded", slot: { gte: 10 } },
    });
    const secondRequest = JSON.parse(
      String(fetchFn.mock.calls[1][1]?.body),
    ) as {
      params: [string, Record<string, unknown>];
    };
    expect(secondRequest.params[1].paginationToken).toBe("next-page");
  });

  it("rejects malformed RPC responses without echoing the credentialed URL", async () => {
    const rpcUrl = "https://example.invalid/?api-key=do-not-log";
    const error = await scanFinalizedVaultHistory({
      rpcUrl,
      programId: "vault-program",
      retryDelayMs: 0,
      fetchFn: vi
        .fn<typeof fetch>()
        .mockResolvedValue(new Response("bad", { status: 503 })),
    }).catch((value: unknown) => value);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe(
      "finalized history RPC returned HTTP 503",
    );
    expect((error as Error).message).not.toContain("do-not-log");
  });

  it("retries transient responses and rejects a cursor that does not advance", async () => {
    const fetchFn = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response("busy", { status: 503 }))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            result: { data: [], paginationToken: "stuck" },
          }),
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            result: { data: [], paginationToken: "stuck" },
          }),
        ),
      );
    await expect(
      scanFinalizedVaultHistory({
        rpcUrl: "https://example.invalid/?api-key=secret",
        programId: "vault-program",
        retryDelayMs: 0,
        fetchFn,
      }),
    ).rejects.toThrow(/cursor did not advance/);
    expect(fetchFn).toHaveBeenCalledTimes(3);
  });

  it("fails closed when a successful vault instruction is malformed", async () => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          result: {
            data: [
              {
                slot: 11,
                transaction: {
                  signatures: ["signature-1"],
                  message: {
                    instructions: [{ programId: "vault-program", data: "1" }],
                  },
                },
                meta: { err: null },
              },
            ],
            paginationToken: null,
          },
        }),
      ),
    );
    await expect(
      scanFinalizedVaultHistory({
        rpcUrl: "https://example.invalid",
        programId: "vault-program",
        fetchFn,
      }),
    ).rejects.toThrow(/malformed vault instruction/);
  });

  it("bounds a hung archival request", async () => {
    const fetchFn = vi.fn<typeof fetch>().mockImplementation(
      async (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new DOMException("aborted", "AbortError"));
          });
        }),
    );
    await expect(
      scanFinalizedVaultHistory({
        rpcUrl: "https://example.invalid",
        programId: "vault-program",
        fetchFn,
        retryDelayMs: 0,
        requestTimeoutMs: 5,
      }),
    ).rejects.toThrow(/transport failed after 4 attempts/);
    expect(fetchFn).toHaveBeenCalledTimes(4);
  });
});
