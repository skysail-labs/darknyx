import type {
  DepositInputs,
  Groth16ProofBytes,
  IDarkPoolZkProverSuite,
  MergeInputs,
  SpendInputs,
} from "@darknyx/sdk";

import type {
  ClientCircuitId,
  ManifestTrustPolicy,
} from "./artifact-manifest.js";

type Pending = {
  resolve(value: unknown): void;
  reject(error: unknown): void;
  timeout: ReturnType<typeof setTimeout>;
};

export interface BrowserProverOptions extends ManifestTrustPolicy {
  workerUrl?: string | URL;
  workerFactory?: (url: string | URL) => Worker;
  requestTimeoutMs?: number;
}

interface TrustedTypesFactoryLike {
  createPolicy(
    name: string,
    rules: { createScriptURL(value: string): string },
  ): { createScriptURL(value: string): unknown };
}

let proverWorkerPolicy:
  | { canonical: string; policy: { createScriptURL(value: string): unknown } }
  | undefined;

function trustedProverWorkerUrl(canonical: string): string | URL {
  const trustedTypes = (
    globalThis as typeof globalThis & {
      trustedTypes?: TrustedTypesFactoryLike;
    }
  ).trustedTypes;
  if (!trustedTypes) return canonical;
  if (!proverWorkerPolicy) {
    proverWorkerPolicy = {
      canonical,
      policy: trustedTypes.createPolicy("darknyx-prover-worker", {
        createScriptURL(value) {
          if (value !== canonical) {
            throw new Error("refusing a non-canonical prover Worker URL");
          }
          return value;
        },
      }),
    };
  }
  if (proverWorkerPolicy.canonical !== canonical) {
    throw new Error("only one canonical browser-prover Worker URL is allowed");
  }
  return proverWorkerPolicy.policy.createScriptURL(canonical) as string;
}

const strings = (values: readonly bigint[] | readonly number[]): string[] =>
  values.map(String);

/** Internal product primitive. It is intentionally absent from `src/index.ts`. */
export class BrowserProverSuite implements IDarkPoolZkProverSuite {
  readonly #worker: Worker;
  readonly #pending = new Map<number, Pending>();
  readonly #ready: Promise<void>;
  readonly #requestTimeoutMs: number;
  #nextId = 1;
  #destroyed = false;
  #failure: Error | null = null;

  constructor(options: BrowserProverOptions) {
    this.#requestTimeoutMs = options.requestTimeoutMs ?? 180_000;
    if (
      !Number.isFinite(this.#requestTimeoutMs) ||
      this.#requestTimeoutMs <= 0
    ) {
      throw new Error("browser prover timeout must be a positive number");
    }
    const workerUrl = new URL(
      options.workerUrl ?? "./prover.worker.js",
      import.meta.url,
    ).href;
    this.#worker = (options.workerFactory ?? ((url) => new Worker(url)))(
      trustedProverWorkerUrl(workerUrl),
    );
    this.#worker.onmessage = ({ data }: MessageEvent) => {
      const pending = this.#pending.get(data?.id);
      if (!pending) return;
      this.#pending.delete(data.id);
      clearTimeout(pending.timeout);
      if (data.ok) pending.resolve(data.value);
      else pending.reject(new Error(String(data.error)));
    };
    const failWorker = (error: Error) => {
      this.#failure = error;
      for (const pending of this.#pending.values()) {
        clearTimeout(pending.timeout);
        pending.reject(error);
      }
      this.#pending.clear();
      this.#worker.terminate();
    };
    this.#worker.onerror = ({ message }) => {
      failWorker(new Error(`prover Worker failed: ${message}`));
    };
    this.#worker.onmessageerror = () => {
      failWorker(new Error("prover Worker returned an unreadable message"));
    };
    this.#ready = this.#request("initialize", {
      manifestUrl: options.manifestUrl,
      expectedArtifactSetId: options.expectedArtifactSetId,
      expectedProtocolVersion: options.expectedProtocolVersion,
      trustedKeyId: options.trustedKeyId,
      trustedPublicKey: options.trustedPublicKey,
    }).then(() => undefined);
    void this.#ready.catch((error: unknown) => {
      this.#failure =
        error instanceof Error
          ? error
          : new Error("browser prover initialization failed");
    });
  }

  async #request(
    type: string,
    payload: Record<string, unknown>,
  ): Promise<unknown> {
    if (this.#destroyed) throw new Error("browser prover is destroyed");
    if (this.#failure) throw this.#failure;
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`browser prover request '${type}' timed out`));
      }, this.#requestTimeoutMs);
      this.#pending.set(id, { resolve, reject, timeout });
      try {
        this.#worker.postMessage({ id, type, payload });
      } catch (error) {
        this.#pending.delete(id);
        clearTimeout(timeout);
        reject(error);
      }
    });
  }

  async #prove(
    circuit: ClientCircuitId,
    witness: Record<string, unknown>,
    expectedPublic: readonly (string | null)[],
  ): Promise<Groth16ProofBytes> {
    await this.#ready;
    return (await this.#request("prove", {
      circuit,
      witness,
      expectedPublic,
    })) as Groth16ProofBytes;
  }

  deposit = {
    prove: async (inputs: DepositInputs): Promise<Groth16ProofBytes> =>
      this.#prove(
        "deposit",
        {
          noteCommitment: String(inputs.noteCommitment),
          tokenMint: strings(inputs.tokenMint),
          amount: String(inputs.amount),
          recoveryNonce: String(inputs.recoveryNonce),
          spendingKey: String(inputs.spendingKey),
          noteSecret: String(inputs.noteSecret),
        },
        strings([
          inputs.noteCommitment,
          ...inputs.tokenMint,
          inputs.amount,
          inputs.recoveryNonce,
        ]),
      ),
  };

  spend = {
    prove: async (inputs: SpendInputs): Promise<Groth16ProofBytes> =>
      this.#prove(
        "spend",
        {
          merkleRoot: String(inputs.merkleRoot),
          tokenMint: strings(inputs.tokenMint),
          amount: String(inputs.amount),
          spendingKey: String(inputs.spendingKey),
          innerHash: String(inputs.innerHash),
          merklePath: strings(inputs.merklePath),
          merkleIndices: strings(inputs.merkleIndices),
          recipient: strings(inputs.recipient),
        },
        [
          null,
          String(inputs.merkleRoot),
          ...strings(inputs.tokenMint),
          String(inputs.amount),
          ...strings(inputs.recipient),
        ],
      ),
  };

  merge = {
    prove: async (inputs: MergeInputs): Promise<Groth16ProofBytes> => {
      if (inputs.k !== 2 && inputs.k !== 4) {
        throw new Error("VALID_MERGE K must be 2 or 4");
      }
      return this.#prove(
        inputs.k === 2 ? "merge_k2" : "merge_k4",
        {
          merkleRoot: String(inputs.merkleRoot),
          tokenMint: strings(inputs.tokenMint),
          spendingKey: String(inputs.spendingKey),
          isActive: strings(inputs.isActive),
          amount: strings(inputs.amount),
          innerHash: strings(inputs.innerHash),
          merklePath: inputs.merklePath.map(strings),
          merkleIndices: inputs.merkleIndices.map(strings),
        },
        [
          null,
          ...Array.from({ length: inputs.k }, () => null),
          String(inputs.merkleRoot),
          ...strings(inputs.tokenMint),
        ],
      );
    },
  };

  /** Used by the inventory Worker after it has built the complete private witness. */
  async proveValidInput(
    witness: Record<string, unknown> & {
      merkleRoot: string;
      noteUseTag: string;
      tokenMint: readonly [string, string];
    },
  ): Promise<Groth16ProofBytes> {
    return this.#prove("input", witness, [
      witness.merkleRoot,
      witness.noteUseTag,
      ...witness.tokenMint,
    ]);
  }

  destroy(): void {
    if (this.#destroyed) return;
    this.#destroyed = true;
    this.#worker.terminate();
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(new Error("browser prover destroyed"));
    }
    this.#pending.clear();
  }
}
