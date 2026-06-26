/**
 * Human ↔ atom conversion helpers for SPL mints.
 *
 * Everything on-chain (instruction args, note commitments, balances inside
 * `VaultConfig`) is in raw `u64` atoms. The UI prefers human units (whole
 * tokens). We convert at the boundary so the explorer and the UI agree.
 *
 * Notes:
 *  - `toAtoms` accepts a string like "1.25" with up to `decimals` fractional
 *    digits and refuses to silently drop precision (throws on overflow).
 *  - `fromAtoms` is intentionally lossless: it returns a decimal string with
 *    trailing zeros stripped — no `toFixed`, no Number coercion, no FP loss
 *    for very large balances.
 */

export function toAtoms(
  human: string | number | bigint,
  decimals: number,
): bigint {
  if (typeof human === "bigint") return human; // already atoms
  const raw = typeof human === "number" ? human.toString() : human.trim();
  if (!raw) return 0n;
  // Allow a leading sign for completeness; the dapp itself only uses positives.
  const m = /^(-)?(\d+)(?:\.(\d+))?$/.exec(raw);
  if (!m) throw new Error(`invalid amount: ${human}`);
  const sign = m[1] === "-" ? -1n : 1n;
  const intPart = m[2] ?? "0";
  const fracPart = m[3] ?? "";
  if (fracPart.length > decimals) {
    throw new Error(
      `amount "${raw}" has ${fracPart.length} fractional digits, but the mint only supports ${decimals}`,
    );
  }
  const padded = fracPart.padEnd(decimals, "0");
  return sign * BigInt(intPart + padded);
}

export function fromAtoms(
  atoms: bigint | string | number,
  decimals: number,
): string {
  const v =
    typeof atoms === "bigint"
      ? atoms
      : typeof atoms === "number"
        ? BigInt(Math.trunc(atoms))
        : BigInt(atoms);
  const neg = v < 0n;
  const abs = neg ? -v : v;
  if (decimals === 0) return (neg ? "-" : "") + abs.toString();
  const s = abs.toString().padStart(decimals + 1, "0");
  const cut = s.length - decimals;
  const intPart = s.slice(0, cut) || "0";
  const fracPart = s.slice(cut).replace(/0+$/, "");
  return (neg ? "-" : "") + (fracPart ? `${intPart}.${fracPart}` : intPart);
}

/**
 * Format a balance for display with thousands separators on the integer part
 * (e.g. "1,234.56"). Falls back to `fromAtoms` formatting if `Intl` is
 * unavailable for any reason.
 */
export function formatAtoms(
  atoms: bigint | string | number,
  decimals: number,
): string {
  const raw = fromAtoms(atoms, decimals);
  const [intPart, fracPart] = raw.split(".");
  try {
    const withCommas = BigInt(intPart).toLocaleString("en-US");
    return fracPart ? `${withCommas}.${fracPart}` : withCommas;
  } catch {
    return raw;
  }
}
