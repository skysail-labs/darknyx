import type { JsonValue, TraderIntentDraft } from "./types.js";

const U64_MAX = 18_446_744_073_709_551_615n;
const MARKET_SYMBOL = /^[A-Z0-9]{2,16}-[A-Z0-9]{2,16}$/;
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const MAX_ATTRIBUTE_DEPTH = 8;
const MAX_ATTRIBUTES_BYTES = 4_096;

export class IntentValidationError extends Error {
  constructor(readonly field: string) {
    super(`invalid intent field: ${field}`);
    this.name = "IntentValidationError";
  }
}

function canonicalU64(
  value: string,
  field: string,
  allowZero: boolean,
): string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new IntentValidationError(field);
  }
  const parsed = BigInt(value);
  if ((!allowZero && parsed === 0n) || parsed > U64_MAX) {
    throw new IntentValidationError(field);
  }
  return value;
}

function copyJson(value: unknown, depth: number, field: string): JsonValue {
  if (depth > MAX_ATTRIBUTE_DEPTH) throw new IntentValidationError(field);
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new IntentValidationError(field);
    return value;
  }
  if (Array.isArray(value)) {
    return Object.freeze(
      value.map((entry, index) =>
        copyJson(entry, depth + 1, `${field}[${index}]`),
      ),
    );
  }
  if (typeof value !== "object") throw new IntentValidationError(field);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new IntentValidationError(field);
  }
  const copy: Record<string, JsonValue> = Object.create(null);
  for (const [key, entry] of Object.entries(value)) {
    if (UNSAFE_KEYS.has(key))
      throw new IntentValidationError(`${field}.${key}`);
    copy[key] = copyJson(entry, depth + 1, `${field}.${key}`);
  }
  return Object.freeze(copy);
}

export function validateIntentDraft(
  draft: TraderIntentDraft,
): TraderIntentDraft {
  if (
    !Number.isSafeInteger(draft.protocolVersion) ||
    draft.protocolVersion <= 0
  ) {
    throw new IntentValidationError("protocolVersion");
  }
  if (!MARKET_SYMBOL.test(draft.marketSymbol)) {
    throw new IntentValidationError("marketSymbol");
  }
  if (draft.side !== "bid" && draft.side !== "ask") {
    throw new IntentValidationError("side");
  }
  const baseAmountAtoms = canonicalU64(
    draft.baseAmountAtoms,
    "baseAmountAtoms",
    false,
  );
  const limitPriceTicks = canonicalU64(
    draft.limitPriceTicks,
    "limitPriceTicks",
    true,
  );
  let serializedAttributes: string | undefined;
  try {
    serializedAttributes = JSON.stringify(draft.attributes);
  } catch {
    throw new IntentValidationError("attributes");
  }
  if (
    serializedAttributes === undefined ||
    new TextEncoder().encode(serializedAttributes).length > MAX_ATTRIBUTES_BYTES
  ) {
    throw new IntentValidationError("attributes");
  }
  const attributes = copyJson(draft.attributes, 0, "attributes");
  if (
    Array.isArray(attributes) ||
    attributes === null ||
    typeof attributes !== "object"
  ) {
    throw new IntentValidationError("attributes");
  }
  const attributeObject = attributes as Readonly<Record<string, JsonValue>>;
  return Object.freeze({
    protocolVersion: draft.protocolVersion,
    marketSymbol: draft.marketSymbol,
    side: draft.side,
    baseAmountAtoms,
    limitPriceTicks,
    attributes: attributeObject,
  });
}
