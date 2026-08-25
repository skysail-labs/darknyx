/**
 * IDarkPoolZkProverSuite — one interface per circuit. Swappable between
 * browser (snarkjs WASM) and relayer (ark-groth16 native).
 *
 * Covers every client-side circuit used by the SDK. Settlement-batch proving
 * remains TEE-owned and is intentionally outside this interface.
 */

export interface Groth16ProofBytes {
  piA: Uint8Array; // 64 bytes, NOT yet negated — on-chain wrapper negates.
  piB: Uint8Array; // 128 bytes
  piC: Uint8Array; // 64 bytes
  publicInputs: Uint8Array[]; // each 32 BE bytes
}

export interface SpendInputs {
  merkleRoot: bigint;
  tokenMint: [bigint, bigint];
  amount: bigint;
  spendingKey: bigint;
  /** v2: single inner_hash replacing the old (nonce, blindingR) pair. */
  innerHash: bigint;
  merklePath: bigint[]; // length 20
  merkleIndices: number[]; // length 20, 0 or 1
  /**
   * Destination token account, split into [lo, hi] 128-bit halves — the
   * account the withdrawn SPL tokens must land in.
   *
   * PUBLIC and proof-bound (S-01). Before this existed the proof authorised
   * destroying a note but said nothing about where the money went, making the
   * proof tuple a bearer instrument. A proof generated for one destination
   * will not verify when submitted with another.
   */
  recipient: [bigint, bigint];
}

/** VALID_DEPOSIT witness + public values. The owner and inner stay private. */
export interface DepositInputs {
  noteCommitment: bigint;
  tokenMint: [bigint, bigint];
  amount: bigint;
  recoveryNonce: bigint;
  spendingKey: bigint;
  /**
   * Seed-derived per-note entropy (`deriveNoteSecret`), PRIVATE. The public
   * input count is unchanged at 5 — this only enters the inner hash.
   *
   * Without it the deposit inner would be `Poseidon(27, owner_commitment,
   * recovery_nonce)` over a PUBLIC nonce and a wallet-wide owner commitment,
   * so one leaked owner commitment would recompute every note-use tag the
   * wallet ever produced, retroactively.
   */
  noteSecret: bigint;
}

/** VALID_MERGE(K) witness — K input slots (dummy-padded) → one summed output note. */
export interface MergeInputs {
  k: 2 | 4;
  merkleRoot: bigint;
  tokenMint: [bigint, bigint];
  // C-01: the K input-note commitments are now the circuit's PUBLIC OUTPUTS
  // (computed from the witness), no longer a nullifier input — so the witness
  // carries no `nullifiers` field.
  // ── shared owner ──
  spendingKey: bigint;
  // ── per-slot (length K; dummy slots zeroed) ──
  isActive: number[]; // 1 | 0
  amount: bigint[];
  innerHash: bigint[];
  merklePath: bigint[][]; // K × 20
  merkleIndices: number[][]; // K × 20
}

export interface IDarkPoolZkProverSuite {
  deposit: {
    prove(inputs: DepositInputs): Promise<Groth16ProofBytes>;
  };
  spend: {
    prove(inputs: SpendInputs): Promise<Groth16ProofBytes>;
  };
  merge: {
    prove(inputs: MergeInputs): Promise<Groth16ProofBytes>;
  };
}

/**
 * Placeholder prover that refuses to produce proofs. Useful when wiring an
 * SDK client that only exercises code paths which never call the prover
 * (or unit tests that replace the relevant member). Injecting this stub keeps
 * the typecheck honest while making it impossible to accidentally submit a
 * no-op proof.
 *
 * The real implementations are `BrowserProverSuite`
 * (`packages/browser-client/src/prover/`) in the browser, and the snarkjs
 * shell-out helper under `packages/sdk/tests/helpers/` for Node tests.
 */
/// Each field is annotated with the interface's own member type rather than
/// letting TypeScript infer it. Without the annotation the inferred field type
/// is the NARROW `() => Promise<…>` of the throwing stub, which satisfies
/// `implements` (a 0-arg fn is assignable to a 1-arg signature) but makes the
/// field un-substitutable: assigning a real `(inputs: DepositInputs) => …`
/// prover fails to typecheck, which is exactly what tests do.
export class UnimplementedProverSuite implements IDarkPoolZkProverSuite {
  private readonly reason: string;
  constructor(reason = "wire up the selected client prover adapter") {
    this.reason = reason;
  }
  deposit: IDarkPoolZkProverSuite["deposit"] = {
    prove: async (): Promise<Groth16ProofBytes> => {
      throw new Error(`UnimplementedProverSuite.deposit.prove: ${this.reason}`);
    },
  };
  spend: IDarkPoolZkProverSuite["spend"] = {
    prove: async (): Promise<Groth16ProofBytes> => {
      throw new Error(`UnimplementedProverSuite.spend.prove: ${this.reason}`);
    },
  };
  merge: IDarkPoolZkProverSuite["merge"] = {
    prove: async (): Promise<Groth16ProofBytes> => {
      throw new Error(`UnimplementedProverSuite.merge.prove: ${this.reason}`);
    },
  };
}
