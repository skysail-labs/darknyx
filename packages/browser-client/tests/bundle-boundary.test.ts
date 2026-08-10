import { readFile } from "node:fs/promises";

import type { VaultLifecyclePort } from "@darknyx/client-core";
import { describe, expect, expectTypeOf, it } from "vitest";

import { BrowserVault } from "../src/index.js";

describe("browser custody product boundary", () => {
  it("implements only the typed custody lifecycle", () => {
    expectTypeOf<BrowserVault>().toMatchTypeOf<VaultLifecyclePort>();
    expectTypeOf<BrowserVault>().not.toHaveProperty("exportSeed");
    expectTypeOf<BrowserVault>().not.toHaveProperty("sign");
    expectTypeOf<BrowserVault>().not.toHaveProperty("prove");
  });

  it("ships one bundled Worker without spike-only capabilities", async () => {
    const worker = await readFile(
      new URL("../dist/vault.worker.js", import.meta.url),
      "utf8",
    );
    const entry = await readFile(
      new URL("../dist/index.js", import.meta.url),
      "utf8",
    );
    const proverWorker = await readFile(
      new URL("../dist/prover.worker.js", import.meta.url),
      "utf8",
    );

    for (const forbidden of [
      "testOnly",
      "simulateSameOrigin",
      "importScripts(",
      "DARKNYX_CUSTODY_SPIKE_TEST",
    ]) {
      expect(worker, forbidden).not.toContain(forbidden);
      expect(entry, forbidden).not.toContain(forbidden);
      expect(proverWorker, forbidden).not.toContain(forbidden);
    }
    expect(worker).toContain("darknyx/master-seed-backup/v2");
    expect(worker).toContain("browser vault is locked");
    expect(entry).not.toContain("BrowserProverSuite");
    expect(entry).not.toContain("proveValidInput");
    expect(entry).not.toContain("BrowserInventory");
    expect(entry).not.toContain("validInputWitness");
    expect(entry).not.toContain("recoverNotes");
    expect(proverWorker).toContain("artifact manifest signature is invalid");
    expect(proverWorker).toContain(
      "browser proof failed mandatory local verification",
    );
    expect(proverWorker).not.toContain("node:");
  });
});
