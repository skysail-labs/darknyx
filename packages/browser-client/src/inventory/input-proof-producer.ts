import type { BrowserProverSuite } from "../prover/browser-prover.js";
import {
  requestVaultInternal,
  type BrowserVault,
} from "../custody/browser-vault.js";
import type {
  InputProofProducer,
  InputProofRequest,
  InputProofResult,
} from "./types.js";

const HEX32 = /^[0-9a-fA-F]{64}$/;

function normalizeHex32(value: unknown, label: string): string {
  if (typeof value !== "string" || !HEX32.test(value)) {
    throw new Error(`${label} must be 32-byte hex`);
  }
  return value.toLowerCase();
}

function proofBytes(parts: {
  piA: Uint8Array;
  piB: Uint8Array;
  piC: Uint8Array;
}): Uint8Array {
  if (
    parts.piA.length !== 64 ||
    parts.piB.length !== 128 ||
    parts.piC.length !== 64
  ) {
    throw new Error("browser prover returned malformed Groth16 points");
  }
  const output = new Uint8Array(256);
  output.set(parts.piA, 0);
  output.set(parts.piB, 64);
  output.set(parts.piC, 192);
  return output;
}

export interface BrowserInputProofProducerOptions {
  vault: BrowserVault;
  prover: BrowserProverSuite;
  gatewayUrl: string;
  token: string;
  fetchImpl?: typeof fetch;
}

/** Production VALID_INPUT producer used only by the inventory scheduler. */
export class BrowserInputProofProducer {
  readonly #vault: BrowserVault;
  readonly #prover: BrowserProverSuite;
  readonly #gatewayUrl: string;
  readonly #token: string;
  readonly #fetch: typeof fetch;

  constructor(options: BrowserInputProofProducerOptions) {
    this.#vault = options.vault;
    this.#prover = options.prover;
    this.#gatewayUrl = new URL(options.gatewayUrl).href;
    this.#token = options.token;
    this.#fetch = options.fetchImpl ?? fetch;
  }

  produce: InputProofProducer = async (
    request: InputProofRequest,
  ): Promise<InputProofResult> => {
    const url = new URL("/tree/inclusion", this.#gatewayUrl);
    url.searchParams.set("commitment", request.note.commitment);
    url.searchParams.set("tree_id", String(request.treeId));
    const response = await this.#fetch(url, {
      headers: { authorization: `Bearer ${this.#token}` },
    });
    if (!response.ok) {
      throw new Error(`tree inclusion request failed with ${response.status}`);
    }
    const body = (await response.json()) as {
      leaf_index?: unknown;
      merkle_root?: unknown;
      siblings?: unknown;
    };
    if (
      !Number.isSafeInteger(body.leaf_index) ||
      (body.leaf_index as number) < 0 ||
      (body.leaf_index as number) >= 1 << 20 ||
      !Array.isArray(body.siblings) ||
      body.siblings.length !== 20
    ) {
      throw new Error("tree inclusion response is malformed");
    }
    const merkleRoot = normalizeHex32(body.merkle_root, "Merkle root");
    if (merkleRoot !== request.root) {
      throw new Error(
        "tree inclusion root differs from finalized refresh target",
      );
    }
    const siblings = body.siblings.map((value, index) =>
      normalizeHex32(value, `Merkle sibling ${index}`),
    );
    const leafIndex = body.leaf_index as number;
    const pathIndices = Array.from(
      { length: 20 },
      (_unused, index) => (leafIndex >> index) & 1,
    );
    const witness = await requestVaultInternal<
      Record<string, unknown> & {
        merkleRoot: string;
        noteUseTag: string;
        tokenMint: readonly [string, string];
      }
    >(this.#vault, "validInputWitness", {
      note: request.note,
      merkleRoot,
      siblings,
      pathIndices,
    });
    const result = await this.#prover.proveValidInput(witness);
    return { proofBytes: proofBytes(result) };
  };
}
