import type { PublicRelease } from "./types.js";
import { isLoopbackHttp } from "./http.js";

const BASE58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("release manifest must be an object");
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, allowed: string[]): void {
  const extras = Object.keys(value).filter((key) => !allowed.includes(key));
  const missing = allowed
    .filter((key) => key !== "expected_mrtd")
    .filter((key) => !(key in value));
  if (extras.length || missing.length) {
    throw new Error("release manifest has unknown or missing fields");
  }
}

function httpsUrl(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be HTTPS`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid HTTPS URL`);
  }
  const local = isLoopbackHttp(url);
  if (
    (url.protocol !== "https:" && !local) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error(
      `${label} must be credential-free HTTPS or http://localhost`,
    );
  }
  return url.toString();
}

export function parsePublicRelease(value: unknown): PublicRelease {
  const release = object(value);
  const keys = [
    "schema_version",
    "release_id",
    "venue_id",
    "gateway_url",
    "rpc_url",
    "vault_program_id",
    "expected_compose_hash",
    "expected_oracle_mode",
    "recovery_start_slot",
    "expected_mrtd",
    "artifact_manifest_url",
    "artifact_set_id",
    "artifact_protocol_version",
    "artifact_key_id",
    "artifact_public_key",
    "circuit_version",
    "proving_key_version",
  ];
  exactKeys(release, keys);
  if (
    release.schema_version !== 1 ||
    typeof release.release_id !== "string" ||
    !ID.test(release.release_id) ||
    typeof release.venue_id !== "string" ||
    !ID.test(release.venue_id) ||
    typeof release.vault_program_id !== "string" ||
    !BASE58.test(release.vault_program_id) ||
    typeof release.expected_compose_hash !== "string" ||
    !HEX64.test(release.expected_compose_hash) ||
    (release.expected_oracle_mode !== "pyth-router-quorum-v1" &&
      release.expected_oracle_mode !== "pyth-solana-push-v1") ||
    !Number.isSafeInteger(release.recovery_start_slot) ||
    (release.recovery_start_slot as number) < 0 ||
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
    ...(release as unknown as PublicRelease),
    gateway_url: httpsUrl(release.gateway_url, "gateway_url"),
    rpc_url: httpsUrl(release.rpc_url, "rpc_url"),
    artifact_manifest_url: httpsUrl(
      release.artifact_manifest_url,
      "artifact_manifest_url",
    ),
  });
}

export function publicReleaseJson(release: PublicRelease): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(release)}\n`);
}
