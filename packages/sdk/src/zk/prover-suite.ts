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

export interface WalletCreateInputs {
  userCommitment: bigint;
  rootKey: [bigint, bigint]; // [lo, hi]
  spendingKey: bigint;
  viewingKey: bigint;
  r0: bigint;
  r1: bigint;
  r2: bigint;
}

export interface SpendInputs {
  merkleRoot: bigint;
  nullifier: bigint;
  tokenMint: [bigint, bigint];
  amount: bigint;
  spendingKey: bigint;
  ownerCommitmentBlinding: bigint;
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
  ownerCommitmentBlinding: bigint;
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
  ownerCommitmentBlinding: bigint;
  // ── per-slot (length K; dummy slots zeroed) ──
  isActive: number[]; // 1 | 0
  amount: bigint[];
  innerHash: bigint[];
  merklePath: bigint[][]; // K × 20
  merkleIndices: number[][]; // K × 20
}

export interface IDarkPoolZkProverSuite {
  walletCreate: {
    prove(inputs: WalletCreateInputs): Promise<Groth16ProofBytes>;
  };
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
 * (or unit tests that replace the relevant member). The real prover lands in
 * `packages/web-zk-prover` in Phase 3 — injecting this stub ensures the
 * typecheck passes while making it impossible to accidentally submit a
 * no-op proof.
 */
/// Each field is annotated with the interface's own member type rather than
/// letting TypeScript infer it. Without the annotation the inferred field type
/// is the NARROW `() => Promise<…>` of the throwing stub, which satisfies
/// `implements` (a 0-arg fn is assignable to a 1-arg signature) but makes the
/// field un-substitutable: assigning a real `(inputs: DepositInputs) => …`
/// prover fails to typecheck, which is exactly what tests do.
export class UnimplementedProverSuite implements IDarkPoolZkProverSuite {
  private readonly reason: string;
  constructor(reason = "wire up packages/web-zk-prover in Phase 3") {
    this.reason = reason;
  }
  walletCreate: IDarkPoolZkProverSuite["walletCreate"] = {
    prove: async (): Promise<Groth16ProofBytes> => {
      throw new Error(
        `UnimplementedProverSuite.walletCreate.prove: ${this.reason}`,
      );
    },
  };
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
