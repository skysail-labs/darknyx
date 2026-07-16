/**
 * WebProverSuite — browser implementation of `IDarkPoolZkProverSuite`.
 *
 * Uses an ESM Web Worker (see `apps/demo/src/workers/prover.worker.ts`) to
 * execute snarkjs `groth16.fullProve`, then formats the result with the
 * pure-TS helpers from `@nyx/sdk` (`formatGroth16ForOnChain`).
 *
 * The worker is created lazily on the first proof request and reused for the
 * lifetime of the page (snarkjs caches wasm + zkey in memory so the second
 * proof is much faster). Concurrent requests are serialised in a queue —
 * snarkjs is single-threaded inside the worker.
 */

import {
  formatGroth16ForOnChain,
  type DepositInputs,
  type Groth16ProofBytes,
  type IDarkPoolZkProverSuite,
  type SpendInputs,
  type WalletCreateInputs,
} from "@nyx/sdk";

import type {
  ProverWorkerRequest,
  ProverWorkerResponse,
} from "@/workers/prover.worker";

export interface WebProverAssets {
  walletCreate: { wasmUrl: string; zkeyUrl: string };
  deposit: { wasmUrl: string; zkeyUrl: string };
  spend: { wasmUrl: string; zkeyUrl: string };
}

const DEFAULT_ASSETS: WebProverAssets = {
  walletCreate: {
    wasmUrl: "/circuits/valid_wallet_create/circuit.wasm",
    zkeyUrl: "/circuits/valid_wallet_create/circuit.zkey",
  },
  deposit: {
    wasmUrl: "/circuits/valid_deposit/circuit.wasm",
    zkeyUrl: "/circuits/valid_deposit/circuit.zkey",
  },
  spend: {
    wasmUrl: "/circuits/valid_spend/circuit.wasm",
    zkeyUrl: "/circuits/valid_spend/circuit.zkey",
  },
};

interface PendingRequest {
  resolve: (value: ProverWorkerResponse & { ok: true }) => void;
  reject: (err: Error) => void;
}

type ProveCircuitOpts = {
  inputs: Record<string, string | string[]>;
  wasmUrl: string;
  zkeyUrl: string;
};

export class WebProverSuite implements IDarkPoolZkProverSuite {
  private worker: Worker | null = null;
  private readonly pending = new Map<string, PendingRequest>();
  private nextId = 0;

  constructor(private readonly assets: WebProverAssets = DEFAULT_ASSETS) {}

  /** Create a worker eagerly so we can show a "ready" indicator in the UI. */
  prefetch(): void {
    void this.ensureWorker();
  }

  private ensureWorker(): Worker {
    if (this.worker) return this.worker;
    if (typeof window === "undefined") {
      throw new Error("WebProverSuite can only run in a browser context");
    }
    const w = new Worker(
      new URL("../../workers/prover.worker.ts", import.meta.url),
      {
        type: "module",
        name: "nyx-prover",
      },
    );
    w.addEventListener("message", (ev: MessageEvent<ProverWorkerResponse>) => {
      const reply = ev.data;
      const handler = this.pending.get(reply.id);
      if (!handler) return;
      this.pending.delete(reply.id);
      if (reply.ok) handler.resolve(reply);
      else handler.reject(new Error(reply.error));
    });
    w.addEventListener("error", (err) => {
      // Fail every in-flight request — the worker is no longer usable.
      const message = err.message || "prover worker crashed";
      for (const [id, p] of this.pending) {
        p.reject(new Error(`${message} (request ${id})`));
      }
      this.pending.clear();
      this.worker = null;
    });
    this.worker = w;
    return w;
  }

  private async proveOne(
    opts: ProveCircuitOpts,
  ): Promise<{ proof: Groth16ProofBytes; durationMs: number }> {
    const w = this.ensureWorker();
    const id = `req-${this.nextId++}`;
    const reply = await new Promise<ProverWorkerResponse & { ok: true }>(
      (resolve, reject) => {
        this.pending.set(id, { resolve, reject });
        const msg: ProverWorkerRequest = {
          id,
          inputs: opts.inputs,
          wasmUrl: opts.wasmUrl,
          zkeyUrl: opts.zkeyUrl,
        };
        w.postMessage(msg);
      },
    );
    const { proof, publicInputsBE } = formatGroth16ForOnChain(
      reply.proof,
      reply.publicSignals,
    );
    return {
      proof: {
        piA: proof.piA,
        piB: proof.piB,
        piC: proof.piC,
        publicInputs: publicInputsBE,
      },
      durationMs: reply.durationMs,
    };
  }

  walletCreate = {
    prove: async (inputs: WalletCreateInputs): Promise<Groth16ProofBytes> => {
      const decimal: Record<string, string | string[]> = {
        userCommitment: inputs.userCommitment.toString(),
        rootKey: [inputs.rootKey[0].toString(), inputs.rootKey[1].toString()],
        spendingKey: inputs.spendingKey.toString(),
        viewingKey: inputs.viewingKey.toString(),
        r0: inputs.r0.toString(),
        r1: inputs.r1.toString(),
        r2: inputs.r2.toString(),
      };
      const { proof } = await this.proveOne({
        inputs: decimal,
        wasmUrl: this.assets.walletCreate.wasmUrl,
        zkeyUrl: this.assets.walletCreate.zkeyUrl,
      });
      return proof;
    },
  };

  deposit = {
    prove: async (inputs: DepositInputs): Promise<Groth16ProofBytes> => {
      const decimal: Record<string, string | string[]> = {
        noteCommitment: inputs.noteCommitment.toString(),
        tokenMint: inputs.tokenMint.map(String),
        amount: inputs.amount.toString(),
        recoveryNonce: inputs.recoveryNonce.toString(),
        spendingKey: inputs.spendingKey.toString(),
        ownerCommitmentBlinding:
          inputs.ownerCommitmentBlinding.toString(),
      };
      const { proof } = await this.proveOne({
        inputs: decimal,
        wasmUrl: this.assets.deposit.wasmUrl,
        zkeyUrl: this.assets.deposit.zkeyUrl,
      });
      return proof;
    },
  };

  spend = {
    prove: async (inputs: SpendInputs): Promise<Groth16ProofBytes> => {
      if (
        inputs.merklePath.length !== 20 ||
        inputs.merkleIndices.length !== 20
      ) {
        throw new Error(
          `WebProverSuite.spend.prove: expected merkle path/indices length 20, got ${inputs.merklePath.length}/${inputs.merkleIndices.length}`,
        );
      }
      const decimal: Record<string, string | string[]> = {
        merkleRoot: inputs.merkleRoot.toString(),
        nullifier: inputs.nullifier.toString(),
        tokenMint: [
          inputs.tokenMint[0].toString(),
          inputs.tokenMint[1].toString(),
        ],
        amount: inputs.amount.toString(),
        spendingKey: inputs.spendingKey.toString(),
        ownerCommitmentBlinding: inputs.ownerCommitmentBlinding.toString(),
        innerHash: inputs.innerHash.toString(),
        merklePath: inputs.merklePath.map((p) => p.toString()),
        merkleIndices: inputs.merkleIndices.map((i) => i.toString()),
      };
      const { proof } = await this.proveOne({
        inputs: decimal,
        wasmUrl: this.assets.spend.wasmUrl,
        zkeyUrl: this.assets.spend.zkeyUrl,
      });
      return proof;
    },
  };

  /** Tear down the worker — useful in dev / hot-reload paths. */
  dispose(): void {
    this.worker?.terminate();
    this.worker = null;
    for (const p of this.pending.values()) {
      p.reject(new Error("WebProverSuite disposed before resolving"));
    }
    this.pending.clear();
  }
}
