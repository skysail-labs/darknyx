import {
  fetchVerifiedArtifact,
  loadSignedArtifactManifest,
  type ClientArtifactManifest,
  type ClientCircuitId,
  type ManifestTrustPolicy,
} from "./artifact-manifest.js";
import {
  formatBrowserGroth16Proof,
  type RawGroth16Proof,
} from "./groth16-format.js";

interface TrustedTypesFactoryLike {
  createPolicy(
    name: string,
    rules: { createScriptURL(value: string): string },
  ): { createScriptURL(value: string): unknown };
}

// ffjavascript parallelises its curve engine with a generated blob Worker.
// Install a narrowly-scoped Trusted Types adapter before dynamically loading
// snarkjs: only same-origin-generated blob URLs are accepted, and concurrency
// is capped to avoid turning high-core-count laptops into an accidental memory
// denial of service. JavaScript eval remains forbidden by CSP.
const NativeWorker = globalThis.Worker;
const trustedTypes = (
  globalThis as typeof globalThis & { trustedTypes?: TrustedTypesFactoryLike }
).trustedTypes;
const nestedWorkerPolicy = trustedTypes?.createPolicy(
  "darknyx-snarkjs-worker",
  {
    createScriptURL(value) {
      if (!value.startsWith(`blob:${location.origin}/`)) {
        throw new Error("snarkjs may create only same-origin blob Workers");
      }
      return value;
    },
  },
);
const hardwareConcurrency = Math.max(
  1,
  Math.min(navigator.hardwareConcurrency || 2, 4),
);
Object.defineProperty(navigator, "hardwareConcurrency", {
  value: hardwareConcurrency,
  configurable: false,
});
Object.defineProperty(globalThis, "Worker", {
  value: class TrustedSnarkjsWorker extends NativeWorker {
    constructor(url: string | URL, options?: WorkerOptions) {
      if (
        typeof url !== "string" ||
        !url.startsWith(`blob:${location.origin}/`)
      ) {
        throw new Error("snarkjs requested a non-blob nested Worker");
      }
      super(
        (nestedWorkerPolicy?.createScriptURL(url) ?? url) as string,
        options,
      );
    }
  },
  configurable: false,
  writable: false,
});

type ExpectedPublic = readonly (string | null)[];

interface InitializeRequest {
  id: number;
  type: "initialize";
  payload: ManifestTrustPolicy;
}

interface ProveRequest {
  id: number;
  type: "prove";
  payload: {
    circuit: ClientCircuitId;
    witness: Record<string, unknown>;
    expectedPublic: ExpectedPublic;
  };
}

type Request = InitializeRequest | ProveRequest;

interface WorkerScope {
  onmessage: ((event: MessageEvent<Request>) => void) | null;
  postMessage(message: unknown, transfer?: Transferable[]): void;
}

let proverPromise: Promise<typeof import("snarkjs")> | null = null;
function loadProver(): Promise<typeof import("snarkjs")> {
  proverPromise ??= import("snarkjs");
  return proverPromise;
}
const workerScope = self as unknown as WorkerScope;
let manifest: ClientArtifactManifest | null = null;
let manifestUrl = "";
const artifacts = new Map<
  ClientCircuitId,
  Promise<{ wasm: Uint8Array; zkey: Uint8Array; verificationKey: unknown }>
>();

async function circuitArtifacts(circuit: ClientCircuitId) {
  if (!manifest) throw new Error("browser prover is not initialized");
  let loading = artifacts.get(circuit);
  if (!loading) {
    const descriptor = manifest.circuits[circuit];
    loading = Promise.all([
      fetchVerifiedArtifact(
        manifestUrl,
        manifest.artifact_set_id,
        descriptor.wasm,
      ),
      fetchVerifiedArtifact(
        manifestUrl,
        manifest.artifact_set_id,
        descriptor.zkey,
      ),
      fetchVerifiedArtifact(
        manifestUrl,
        manifest.artifact_set_id,
        descriptor.verification_key,
      ),
    ]).then(([wasm, zkey, verificationKeyBytes]) => {
      let verificationKey: unknown;
      try {
        verificationKey = JSON.parse(
          new TextDecoder().decode(verificationKeyBytes),
        );
      } catch {
        throw new Error(`${circuit} verification key is not valid JSON`);
      }
      return { wasm, zkey, verificationKey };
    });
    artifacts.set(circuit, loading);
    loading.catch(() => artifacts.delete(circuit));
  }
  return loading;
}

function validateExpectedPublic(
  actual: readonly string[],
  expected: ExpectedPublic,
  arity: number,
): void {
  if (actual.length !== arity || expected.length !== arity) {
    throw new Error(
      "circuit public-input arity does not match signed manifest",
    );
  }
  for (let index = 0; index < expected.length; index += 1) {
    const value = expected[index];
    if (value !== null && actual[index] !== value) {
      throw new Error(
        `public input ${index} does not match the requested action`,
      );
    }
  }
}

async function handle(request: Request): Promise<unknown> {
  if (request.type === "initialize") {
    if (manifest) throw new Error("browser prover is already initialized");
    manifest = await loadSignedArtifactManifest(request.payload);
    manifestUrl = request.payload.manifestUrl;
    return {
      artifactSetId: manifest.artifact_set_id,
      circuits: Object.fromEntries(
        Object.entries(manifest.circuits).map(([name, value]) => [
          name,
          value.circuit_version,
        ]),
      ),
    };
  }
  if (!manifest) throw new Error("browser prover is not initialized");
  const descriptor = manifest.circuits[request.payload.circuit];
  if (!descriptor) throw new Error("unsupported client circuit");
  const loaded = await circuitArtifacts(request.payload.circuit);
  const prover = await loadProver();
  const witness = { type: "mem" as const };
  await prover.wtns.calculate(request.payload.witness, loaded.wasm, witness);
  const { proof, publicSignals } = await prover.groth16.prove(
    loaded.zkey,
    witness,
  );
  validateExpectedPublic(
    publicSignals,
    request.payload.expectedPublic,
    descriptor.public_inputs,
  );
  if (
    !(await prover.groth16.verify(loaded.verificationKey, publicSignals, proof))
  ) {
    throw new Error("browser proof failed mandatory local verification");
  }
  return formatBrowserGroth16Proof(proof, publicSignals);
}

let queue = Promise.resolve();
workerScope.onmessage = ({ data }) => {
  queue = queue
    .then(async () => {
      try {
        const value = await handle(data);
        const transfer: Transferable[] = [];
        if (
          value &&
          typeof value === "object" &&
          "piA" in value &&
          value.piA instanceof Uint8Array
        ) {
          const proof = value as ReturnType<typeof formatBrowserGroth16Proof>;
          transfer.push(
            proof.piA.buffer,
            proof.piB.buffer,
            proof.piC.buffer,
            ...proof.publicInputs.map((input) => input.buffer),
          );
        }
        workerScope.postMessage({ id: data.id, ok: true, value }, transfer);
      } catch (error) {
        workerScope.postMessage({
          id: data.id,
          ok: false,
          error:
            error instanceof Error ? error.message : "browser prove failed",
        });
      }
    })
    .catch(() => undefined);
};
