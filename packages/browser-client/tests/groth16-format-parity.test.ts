import { describe, expect, it } from "vitest";

import { formatGroth16ForOnChain } from "@darknyx/sdk";

import { formatBrowserGroth16Proof } from "../src/prover/groth16-format.js";

describe("browser Groth16 formatter", () => {
  it("is byte-identical to the SDK formatter", () => {
    const raw = {
      pi_a: ["123", "456", "1"],
      pi_b: [
        ["11", "12"],
        ["13", "14"],
        ["1", "0"],
      ],
      pi_c: ["789", "987", "1"],
    };
    const publicSignals = ["1", "2", "3"];
    const browser = formatBrowserGroth16Proof(raw, publicSignals);
    const sdk = formatGroth16ForOnChain(raw, publicSignals);
    expect(browser.piA).toEqual(sdk.proof.piA);
    expect(browser.piB).toEqual(sdk.proof.piB);
    expect(browser.piC).toEqual(sdk.proof.piC);
    expect(browser.publicInputs).toEqual(sdk.publicInputsBE);
  });
});
