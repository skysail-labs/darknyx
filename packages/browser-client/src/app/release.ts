import type { VenueReleaseConfig } from "../venue/types.js";

const BASE58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;

export interface BrowserApplicationRelease {
  schema_version: 1;
  release_id: string;
  venue_id: string;
  gateway_url: string;
  rpc_url: string;
  vault_program_id: string;
  expected_compose_hash: string;
  expected_mrtd?: string;
  artifact_manifest_url: string;
  artifact_set_id: string;
  artifact_protocol_version: number;
  artifact_key_id: string;
  artifact_public_key: string;
  circuit_version: string;
  proving_key_version: string;
}

const REQUIRED = [
  "schema_version",
  "release_id",
  "venue_id",
  "gateway_url",
  "rpc_url",
  "vault_program_id",
  "expected_compose_hash",
  "artifact_manifest_url",
  "artifact_set_id",
  "artifact_protocol_version",
  "artifact_key_id",
  "artifact_public_key",
  "circuit_version",
  "proving_key_version",
] as const;

function endpoint(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} is missing`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} is not a URL`);
  }
  const local = url.protocol === "http:" && url.hostname === "localhost";
  if (
    (url.protocol !== "https:" && !local) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error(`${label} must be a credential-free HTTPS URL`);
  }
  return url.toString();
}

export function parseBrowserApplicationRelease(
  value: unknown,
): BrowserApplicationRelease {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("release manifest must be an object");
  }
  const release = value as Record<string, unknown>;
  const allowed = new Set<string>([...REQUIRED, "expected_mrtd"]);
  if (
    REQUIRED.some((field) => !(field in release)) ||
    Object.keys(release).some((field) => !allowed.has(field)) ||
    release.schema_version !== 1 ||
    typeof release.release_id !== "string" ||
    !ID.test(release.release_id) ||
    typeof release.venue_id !== "string" ||
    !ID.test(release.venue_id) ||
    typeof release.vault_program_id !== "string" ||
    !BASE58.test(release.vault_program_id) ||
    typeof release.expected_compose_hash !== "string" ||
    !HEX64.test(release.expected_compose_hash) ||
    (release.expected_mrtd !== undefined &&
      (typeof release.expected_mrtd !== "string" ||
        !HEX64.test(release.expected_mrtd))) ||
    typeof release.artifact_set_id !== "string" ||
    !ID.test(release.artifact_set_id) ||
    !Number.isSafeInteger(release.artifact_protocol_version) ||
    (release.artifact_protocol_version as number) <= 0 ||
    typeof release.artifact_key_id !== "string" ||
    !ID.test(release.artifact_key_id) ||
    typeof release.artifact_public_key !== "string" ||
    !BASE64URL_32.test(release.artifact_public_key) ||
    typeof release.circuit_version !== "string" ||
    !ID.test(release.circuit_version) ||
    typeof release.proving_key_version !== "string" ||
    !ID.test(release.proving_key_version)
  ) {
    throw new Error("release manifest contains an invalid pin");
  }
  return Object.freeze({
    ...(release as unknown as BrowserApplicationRelease),
    gateway_url: endpoint(release.gateway_url, "gateway_url"),
    rpc_url: endpoint(release.rpc_url, "rpc_url"),
    artifact_manifest_url: endpoint(
      release.artifact_manifest_url,
      "artifact_manifest_url",
    ),
  });
}

export function releaseVenueConfig(
  release: BrowserApplicationRelease,
): VenueReleaseConfig {
  return {
    venueId: release.venue_id,
    gatewayUrl: release.gateway_url,
    rpcUrl: release.rpc_url,
    vaultProgramId: release.vault_program_id,
    expectedComposeHash: release.expected_compose_hash,
    ...(release.expected_mrtd ? { expectedMrtd: release.expected_mrtd } : {}),
  };
}

export function decodeReleasePublicKey(value: string): Uint8Array<ArrayBuffer> {
  if (!BASE64URL_32.test(value)) {
    throw new Error("artifact public key must be 32-byte base64url");
  }
  const decoded = Uint8Array.from(
    atob(value.replaceAll("-", "+").replaceAll("_", "/") + "="),
    (character) => character.charCodeAt(0),
  );
  if (decoded.length !== 32) throw new Error("artifact public key is invalid");
  return decoded;
}

export async function fetchBrowserApplicationRelease(
  fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis),
): Promise<BrowserApplicationRelease> {
  const response = await fetchImpl("/release.json", {
    cache: "no-store",
    credentials: "same-origin",
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok)
    throw new Error(`release manifest failed (${response.status})`);
  const declared = response.headers.get("content-length");
  if (declared !== null && Number(declared) > 64 * 1024) {
    throw new Error("release manifest is too large");
  }
  const text = await response.text();
  if (text.length > 64 * 1024) throw new Error("release manifest is too large");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("release manifest is not valid JSON");
  }
  return parseBrowserApplicationRelease(parsed);
}
