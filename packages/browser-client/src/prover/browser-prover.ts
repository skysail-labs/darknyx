import type {
  DepositInputs,
  Groth16ProofBytes,
  IDarkPoolZkProverSuite,
  MergeInputs,
  SpendInputs,
  WalletCreateInputs,
} from "@darknyx/sdk";

import type {
  ClientCircuitId,
  ManifestTrustPolicy,
} from "./artifact-manifest.js";

type Pending = {
  resolve(value: unknown): void;
  reject(error: unknown): void;
};

export interface BrowserProverOptions extends ManifestTrustPolicy {
  workerUrl?: string | URL;
  workerFactory?: (url: string | URL) => Worker;
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
  #nextId = 1;
  #destroyed = false;
  #failure: Error | null = null;

  constructor(options: BrowserProverOptions) {
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
      if (data.ok) pending.resolve(data.value);
      else pending.reject(new Error(String(data.error)));
    };
    this.#worker.onerror = ({ message }) => {
      const error = new Error(`prover Worker failed: ${message}`);
      this.#failure = error;
      for (const pending of this.#pending.values()) pending.reject(error);
      this.#pending.clear();
      this.#worker.terminate();
    };
    this.#ready = this.#request("initialize", {
      manifestUrl: options.manifestUrl,
      expectedArtifactSetId: options.expectedArtifactSetId,
      expectedProtocolVersion: options.expectedProtocolVersion,
      trustedKeyId: options.trustedKeyId,
      trustedPublicKey: options.trustedPublicKey,
    }).then(() => undefined);
  }

  async #request(
    type: string,
    payload: Record<string, unknown>,
  ): Promise<unknown> {
    if (this.#destroyed) throw new Error("browser prover is destroyed");
    if (this.#failure) throw this.#failure;
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      try {
        this.#worker.postMessage({ id, type, payload });
      } catch (error) {
        this.#pending.delete(id);
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

  walletCreate = {
    prove: async (inputs: WalletCreateInputs): Promise<Groth16ProofBytes> =>
      this.#prove(
        "wallet_create",
        {
          userCommitment: String(inputs.userCommitment),
          rootKey: strings(inputs.rootKey),
          spendingKey: String(inputs.spendingKey),
          viewingKey: String(inputs.viewingKey),
          r0: String(inputs.r0),
          r1: String(inputs.r1),
          r2: String(inputs.r2),
        },
        [String(inputs.userCommitment)],
      ),
  };

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
          ownerCommitmentBlinding: String(inputs.ownerCommitmentBlinding),
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
          nullifier: String(inputs.nullifier),
          tokenMint: strings(inputs.tokenMint),
          amount: String(inputs.amount),
          spendingKey: String(inputs.spendingKey),
          ownerCommitmentBlinding: String(inputs.ownerCommitmentBlinding),
          innerHash: String(inputs.innerHash),
          merklePath: strings(inputs.merklePath),
          merkleIndices: strings(inputs.merkleIndices),
          recipient: strings(inputs.recipient),
        },
        [
          null,
          String(inputs.merkleRoot),
          String(inputs.nullifier),
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
          ownerCommitmentBlinding: String(inputs.ownerCommitmentBlinding),
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
      pending.reject(new Error("browser prover destroyed"));
    }
    this.#pending.clear();
  }
}
