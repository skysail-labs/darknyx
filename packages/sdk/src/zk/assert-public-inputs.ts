/**
 * Check a prover's public signals against a locally computed vector (SW-26).
 *
 * The on-chain verifier rebuilds its public inputs from the INSTRUCTION data,
 * never from the proof. So a prover that returns signals for different values
 * produces a proof that fails on-chain — surfacing as `InvalidProof (6000)` a
 * transaction later, far from the cause, with the fee already spent.
 *
 * The more important case is trust: the caller asked to spend specific notes,
 * and this is the only point at which anything confirms the proof is *about*
 * those notes before it is submitted. The prover is injectable
 * (`client.zkProver`), and the daemon's is a separate process, so "the prover
 * returned a valid proof for the wrong statement" is a real shape, not a
 * theoretical one.
 *
 * `valid-deposit-prover.ts` and `utxo/deposit.ts` each did this inline while
 * `utxo/merge.ts` and `utxo/withdraw.ts` did not. Extracted here so the check is
 * one thing applied uniformly rather than a habit some paths happen to follow —
 * a per-path copy is how the gap appeared in the first place.
 */

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Throw unless `actual` matches `expected` element-for-element.
 *
 * `circuit` names the circuit in the error (e.g. `"VALID_MERGE"`) so a failure
 * says which prove path disagreed.
 */
export function assertPublicInputs(
  circuit: string,
  actual: readonly Uint8Array[],
  expected: readonly Uint8Array[],
): void {
  if (actual.length !== expected.length) {
    throw new Error(
      `${circuit} prover returned ${actual.length} public inputs, expected ${expected.length}`,
    );
  }
  for (let i = 0; i < expected.length; i++) {
    if (!bytesEqual(actual[i], expected[i])) {
      throw new Error(
        `${circuit} prover returned unexpected public inputs (index ${i})`,
      );
    }
  }
}
