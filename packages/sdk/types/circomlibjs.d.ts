/**
 * Minimal ambient types for `circomlibjs`, which ships no declarations of its
 * own and has no `@types/` package.
 *
 * Scoped deliberately to the surface this repo uses (`buildPoseidon` and the
 * field helpers reached through `.F`) rather than declaring the module `any`.
 * A blanket `any` would silence the missing-declaration error while also
 * erasing type checking at every Poseidon call site — and Poseidon inputs are
 * exactly where a BN254 field-element mistake becomes a runtime
 * `PoseidonFailed` far from its cause (see CLAUDE.md §7.2).
 *
 * If a new circomlibjs export is needed, add it here with its real shape.
 */
declare module "circomlibjs" {
  /** circomlibjs field helper, as used for Poseidon in/out conversion. */
  export interface CircomField {
    /** Coerce a bigint/number/string into the field's internal representation. */
    e(value: bigint | number | string): unknown;
    /** Convert an internal (Montgomery-form) value back to a canonical bigint. */
    toObject(value: unknown): bigint;
  }

  /**
   * Poseidon hasher. Callable over already-field-coerced inputs; carries the
   * field helper as `.F`.
   */
  export interface Poseidon {
    (inputs: unknown[]): unknown;
    F: CircomField;
  }

  export function buildPoseidon(): Promise<Poseidon>;
}
