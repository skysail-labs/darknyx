/// <reference lib="webworker" />

/**
 * Web Worker that performs `groth16.fullProve` using snarkjs.
 *
 * Runs entirely off the main thread so the UI stays responsive while
 * witness generation + proof generation happen (each can take 1-5s
 * depending on the circuit). Worker side intentionally stays simple — it
 * receives decimal-string circuit inputs + circuit asset URLs, and returns
 * the raw `proof.json` / `public.json` JSON objects. All bigint <-> decimal
 * conversion and on-chain byte packing happens on the main thread (see
 * `web-prover-suite.ts`) so this worker doesn't need any SDK code.
 *
 * snarkjs ships a real browser ESM build at `build/browser.esm.js`, picked
 * up by Turbopack via the `browser` export condition.
 */

import { groth16 } from "snarkjs";

export type ProverWorkerRequest = {
  id: string;
  inputs: Record<string, string | string[]>;
  wasmUrl: string;
  zkeyUrl: string;
};

export type ProverWorkerResponse =
  | {
      id: string;
      ok: true;
      proof: {
        pi_a: string[];
        pi_b: string[][];
        pi_c: string[];
      };
      publicSignals: string[];
      durationMs: number;
    }
  | {
      id: string;
      ok: false;
      error: string;
    };

self.addEventListener(
  "message",
  async (ev: MessageEvent<ProverWorkerRequest>) => {
    const { id, inputs, wasmUrl, zkeyUrl } = ev.data;
    const start = performance.now();
    try {
      const { proof, publicSignals } = await groth16.fullProve(
        inputs,
        wasmUrl,
        zkeyUrl,
      );
      const durationMs = performance.now() - start;
      const reply: ProverWorkerResponse = {
        id,
        ok: true,
        proof: {
          pi_a: proof.pi_a as string[],
          pi_b: proof.pi_b as string[][],
          pi_c: proof.pi_c as string[],
        },
        publicSignals: publicSignals as string[],
        durationMs,
      };
      (self as DedicatedWorkerGlobalScope).postMessage(reply);
    } catch (err) {
      const reply: ProverWorkerResponse = {
        id,
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      };
      (self as DedicatedWorkerGlobalScope).postMessage(reply);
    }
  },
);
