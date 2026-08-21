/**
 * Guard the TS<->Rust parity guards.
 *
 * Every `*-parity.test.ts` shells out to a `darkpool-crypto` example binary
 * under `target/debug/examples/`, and each SKIPS itself when its binary is
 * absent. That is the right default for a fresh checkout, but it means the
 * byte-equality contracts in CLAUDE.md §7 — note commitment, nullifier,
 * note-use tag, key derivation — can silently stop being checked while
 * `vitest run` still reports green.
 *
 * That is not hypothetical. The web3.js v3 port (#186) moved byte handling
 * from Buffer to Uint8Array across the SDK, ran the suite, and saw
 * "422 passed | 52 skipped" — with every parity assertion inside the skipped
 * half. In CI the same hole is structural rather than accidental: the SDK job
 * downloads these binaries from the `rust` job with `continue-on-error: true`,
 * and `rust` does not run on a TypeScript-only PR. So exactly the changes most
 * able to break cross-language byte equality are the ones that ran without it.
 *
 * With `REQUIRE_PARITY_HELPERS=1` a missing binary is a hard FAILURE instead of
 * a skip, mirroring `REQUIRE_CIRCUIT_ARTIFACTS=1` on the Rust side. CI sets it.
 * Locally the test still passes, but prints exactly what is not being checked.
 */
import { existsSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const examplesSrc = resolve(repoRoot, "crates/darkpool-crypto/examples");
const examplesBin = resolve(repoRoot, "target/debug/examples");

/**
 * Derived from the crate, not hardcoded: a new example added on the Rust side
 * is covered here the moment it exists, rather than whenever someone remembers
 * to extend a list.
 */
function expectedHelpers(): string[] {
  if (!existsSync(examplesSrc)) return [];
  return readdirSync(examplesSrc)
    .filter((f) => f.endsWith(".rs"))
    .map((f) => f.replace(/\.rs$/, ""))
    .sort();
}

describe("darkpool-crypto parity helpers", () => {
  it("are built, or the run is explicitly allowed to skip them", () => {
    const expected = expectedHelpers();
    expect(
      expected.length,
      "found no examples under crates/darkpool-crypto/examples — has the crate moved?",
    ).toBeGreaterThan(0);

    const missing = expected.filter(
      (n) => !existsSync(resolve(examplesBin, n)),
    );
    const required = process.env.REQUIRE_PARITY_HELPERS === "1";

    if (missing.length > 0 && !required) {
      console.warn(
        `\n  ${missing.length}/${expected.length} darkpool-crypto parity helpers are NOT built.\n` +
          `  The TS<->Rust byte-equality assertions that depend on them will SKIP,\n` +
          `  and this suite will still report green.\n` +
          `    missing: ${missing.join(", ")}\n` +
          `    build:   cargo build --examples -p darkpool-crypto\n`,
      );
    }

    if (required) {
      expect(
        missing,
        "REQUIRE_PARITY_HELPERS=1 but these helpers are missing, so the " +
          "TS<->Rust byte-equality contracts would silently go unchecked. " +
          "Build them with: cargo build --examples -p darkpool-crypto",
      ).toEqual([]);
    }
  });
});
