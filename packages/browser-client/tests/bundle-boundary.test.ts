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

  it("keeps the page-facing trader workspace browser-native and secret-free", async () => {
    const manifest = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    ) as {
      exports: Record<string, string | { default: string }>;
      scripts: Record<string, string>;
    };
    const ui = await readFile(
      new URL("../dist/ui.js", import.meta.url),
      "utf8",
    );
    const css = await readFile(
      new URL("../dist/ui.css", import.meta.url),
      "utf8",
    );
    expect(manifest.exports["./ui"]).toEqual({
      types: "./dist/ui/index.d.ts",
      default: "./dist/ui.js",
    });
    expect(manifest.exports["./ui.css"]).toBe("./dist/ui.css");
    expect(manifest.scripts["build:preview"]).toContain(
      "DARKNYX_UI_PREVIEW=1",
    );
    expect(ui).toContain("Venue identity");
    expect(ui).toContain("Place order");
    expect(css).toContain(".darknyx-product");
    expect(css).toContain("--darknyx-ink");
    expect(ui).not.toContain("--darknyx-ink");
    for (const forbidden of [
      "node:",
      "BrowserInventory",
      "BrowserProverSuite",
      "proveValidInput",
      "validInputWitness",
      "proofBytes",
      "masterSeed",
      "signAndSendTransaction",
      "snarkjs",
    ]) {
      expect(ui, forbidden).not.toContain(forbidden);
    }
    expect(css).toContain("@media (max-width: 1050px)");
    expect(css).toContain("@media (max-width: 720px)");
    expect(css).toContain("prefers-reduced-motion");
    expect(css).not.toContain("@import");
    expect(css).not.toMatch(/https?:\/\//);
  });
});
