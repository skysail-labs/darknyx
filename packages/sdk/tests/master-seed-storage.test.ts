/** CSPRNG-only master-seed resolution. Portable wallet signatures are not an
 *  accepted seed source; recovery uses the encrypted backup-v1 envelope. */

import { describe, expect, it, vi } from "vitest";

import {
  MASTER_SEED_BYTES,
  resolveMasterSeed,
} from "../src/keys/key-generators.js";
import type { MasterSeedStorage } from "../src/providers.js";

describe("CSPRNG master-seed storage", () => {
  it("loads an existing 64-byte seed without replacing it", async () => {
    const existing = new Uint8Array(MASTER_SEED_BYTES).fill(0x42);
    const store = vi.fn(async () => {});
    const storage: MasterSeedStorage = {
      load: async () => existing,
      store,
    };
    const resolved = await resolveMasterSeed({ type: "csprng", storage });
    expect(Buffer.from(resolved)).toEqual(Buffer.from(existing));
    expect(store).not.toHaveBeenCalled();
  });

  it("generates and durably stores a fresh CSPRNG seed when none exists", async () => {
    let stored: Uint8Array | null = null;
    const storage: MasterSeedStorage = {
      load: async () => null,
      store: async (seed) => {
        stored = Uint8Array.from(seed);
      },
    };
    const resolved = await resolveMasterSeed({ type: "csprng", storage });
    expect(resolved).toHaveLength(MASTER_SEED_BYTES);
    expect(Buffer.from(stored!)).toEqual(Buffer.from(resolved));

    const second = await resolveMasterSeed({
      type: "csprng",
      storage: {
        load: async () => null,
        store: async () => {},
      },
    });
    expect(Buffer.from(second)).not.toEqual(Buffer.from(resolved));
  });

  it("rejects corrupt stored seed lengths", async () => {
    await expect(
      resolveMasterSeed({
        type: "csprng",
        storage: {
          load: async () => new Uint8Array(32),
          store: async () => {},
        },
      }),
    ).rejects.toThrow(/stored master seed must be 64 bytes/);
  });
});
