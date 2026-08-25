const SIGNATURE_DOMAIN = new TextEncoder().encode(
  "darknyx/client-artifact-manifest/v1\0",
);

export const CLIENT_CIRCUITS = [
  "deposit",
  "input",
  "spend",
  "merge_k2",
  "merge_k4",
] as const;
export type ClientCircuitId = (typeof CLIENT_CIRCUITS)[number];
export type ArtifactKind = "wasm" | "zkey" | "verification_key";

export interface ArtifactDescriptor {
  path: string;
  bytes: number;
  sha256: string;
}

export interface CircuitArtifactDescriptor {
  circuit_version: string;
  public_inputs: number;
  wasm: ArtifactDescriptor;
  zkey: ArtifactDescriptor;
  verification_key: ArtifactDescriptor;
}

export interface ClientArtifactManifest {
  schema_version: 1;
  protocol: "darknyx";
  protocol_version: number;
  artifact_set_id: string;
  circuits: Record<ClientCircuitId, CircuitArtifactDescriptor>;
}

interface SignedManifestEnvelope {
  envelope_version: 1;
  key_id: string;
  payload: string;
  signature: string;
}

export interface ManifestTrustPolicy {
  manifestUrl: string;
  expectedArtifactSetId: string;
  expectedProtocolVersion: number;
  trustedKeyId: string;
  /** Raw 32-byte Ed25519 public key pinned by the application release. */
  trustedPublicKey: Uint8Array<ArrayBuffer>;
  fetchImpl?: typeof fetch;
}

const EXPECTED_PUBLIC_INPUTS: Record<ClientCircuitId, number> = {
  deposit: 5,
  input: 4,
  spend: 7,
  merge_k2: 6,
  merge_k4: 8,
};

const MAX_BYTES: Record<ArtifactKind, number> = {
  wasm: 8 * 1024 * 1024,
  zkey: 32 * 1024 * 1024,
  verification_key: 16 * 1024,
};

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new Error(`${label} has unknown or missing fields`);
  }
}

function fromBase64Url(value: unknown, label: string): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} must be canonical base64url`);
  }
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const decoded = Uint8Array.from(atob(padded), (character) =>
    character.charCodeAt(0),
  );
  const canonical = btoa(String.fromCharCode(...decoded))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
  if (canonical !== value)
    throw new Error(`${label} is non-canonical base64url`);
  return decoded;
}

function signatureMessage(
  payload: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  const message = new Uint8Array(SIGNATURE_DOMAIN.length + payload.length);
  message.set(SIGNATURE_DOMAIN);
  message.set(payload, SIGNATURE_DOMAIN.length);
  return message;
}

function parseArtifact(
  value: unknown,
  kind: ArtifactKind,
  circuit: ClientCircuitId,
): ArtifactDescriptor {
  const parsed = record(value, `${circuit}.${kind}`);
  exactKeys(parsed, ["path", "bytes", "sha256"], `${circuit}.${kind}`);
  if (
    typeof parsed.path !== "string" ||
    parsed.path.startsWith("/") ||
    parsed.path.includes("..") ||
    parsed.path.includes("?") ||
    parsed.path.includes("#") ||
    !/^[A-Za-z0-9._/-]+$/.test(parsed.path)
  ) {
    throw new Error(`${circuit}.${kind}.path must be a safe relative path`);
  }
  if (
    !Number.isSafeInteger(parsed.bytes) ||
    (parsed.bytes as number) <= 0 ||
    (parsed.bytes as number) > MAX_BYTES[kind]
  ) {
    throw new Error(`${circuit}.${kind}.bytes exceeds its product bound`);
  }
  if (
    typeof parsed.sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(parsed.sha256)
  ) {
    throw new Error(`${circuit}.${kind}.sha256 must be lowercase SHA-256`);
  }
  return parsed as unknown as ArtifactDescriptor;
}

export function parseClientArtifactManifest(
  value: unknown,
  expectedArtifactSetId: string,
  expectedProtocolVersion: number,
): ClientArtifactManifest {
  const manifest = record(value, "artifact manifest");
  exactKeys(
    manifest,
    [
      "schema_version",
      "protocol",
      "protocol_version",
      "artifact_set_id",
      "circuits",
    ],
    "artifact manifest",
  );
  if (
    manifest.schema_version !== 1 ||
    manifest.protocol !== "darknyx" ||
    manifest.protocol_version !== expectedProtocolVersion ||
    manifest.artifact_set_id !== expectedArtifactSetId
  ) {
    throw new Error("artifact manifest does not match the pinned release");
  }
  const circuits = record(manifest.circuits, "artifact manifest circuits");
  exactKeys(circuits, CLIENT_CIRCUITS, "artifact manifest circuits");
  const parsedCircuits = {} as Record<
    ClientCircuitId,
    CircuitArtifactDescriptor
  >;
  for (const circuit of CLIENT_CIRCUITS) {
    const descriptor = record(circuits[circuit], circuit);
    exactKeys(
      descriptor,
      ["circuit_version", "public_inputs", "wasm", "zkey", "verification_key"],
      circuit,
    );
    if (
      typeof descriptor.circuit_version !== "string" ||
      !/^[a-z0-9_-]+-v[1-9][0-9]*$/.test(descriptor.circuit_version) ||
      descriptor.public_inputs !== EXPECTED_PUBLIC_INPUTS[circuit]
    ) {
      throw new Error(`${circuit} version or public-input arity is invalid`);
    }
    parsedCircuits[circuit] = {
      circuit_version: descriptor.circuit_version,
      public_inputs: descriptor.public_inputs,
      wasm: parseArtifact(descriptor.wasm, "wasm", circuit),
      zkey: parseArtifact(descriptor.zkey, "zkey", circuit),
      verification_key: parseArtifact(
        descriptor.verification_key,
        "verification_key",
        circuit,
      ),
    };
  }
  return {
    schema_version: 1,
    protocol: "darknyx",
    protocol_version: expectedProtocolVersion,
    artifact_set_id: expectedArtifactSetId,
    circuits: parsedCircuits,
  };
}

async function responseBytes(
  response: Response,
  expectedBytes: number,
  label: string,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!response.ok || response.redirected) {
    throw new Error(`${label} fetch failed closed (${response.status})`);
  }
  const encoded = response.headers.has("content-encoding");
  const declared = response.headers.get("content-length");
  if (!encoded && declared !== null && Number(declared) !== expectedBytes) {
    throw new Error(`${label} content length does not match its manifest`);
  }
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length !== expectedBytes) {
      throw new Error(`${label} byte length does not match its manifest`);
    }
    return bytes;
  }
  const output = new Uint8Array(expectedBytes);
  const reader = response.body.getReader();
  let offset = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (offset + value.length > expectedBytes) {
      await reader.cancel();
      throw new Error(`${label} exceeded its manifest byte length`);
    }
    output.set(value, offset);
    offset += value.length;
  }
  if (offset !== expectedBytes) {
    throw new Error(`${label} byte length does not match its manifest`);
  }
  return output;
}

async function boundedResponseBytes(
  response: Response,
  maxBytes: number,
  label: string,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!response.ok || response.redirected) {
    throw new Error(`${label} fetch failed closed (${response.status})`);
  }
  const encoded = response.headers.has("content-encoding");
  const declared = response.headers.get("content-length");
  if (!encoded && declared !== null && Number(declared) > maxBytes) {
    throw new Error(`${label} exceeds ${maxBytes} bytes`);
  }
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > maxBytes)
      throw new Error(`${label} exceeds ${maxBytes} bytes`);
    return bytes;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array<ArrayBuffer>[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`${label} exceeds ${maxBytes} bytes`);
    }
    chunks.push(Uint8Array.from(value));
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

async function pruneStaleArtifactCaches(artifactSetId: string): Promise<void> {
  if (!("caches" in globalThis)) return;
  const current = `darknyx-client-artifacts-${artifactSetId}`;
  try {
    const names = await caches.keys();
    await Promise.all(
      names
        .filter(
          (name) =>
            name.startsWith("darknyx-client-artifacts-") && name !== current,
        )
        .map((name) => caches.delete(name)),
    );
  } catch {
    // Cache Storage is an optimization. Verification never depends on it.
  }
}

export async function loadSignedArtifactManifest(
  policy: ManifestTrustPolicy,
): Promise<ClientArtifactManifest> {
  if (policy.trustedPublicKey.length !== 32) {
    throw new Error("artifact-manifest Ed25519 key must be 32 bytes");
  }
  const manifestUrl = new URL(policy.manifestUrl);
  if (
    manifestUrl.protocol !== "https:" &&
    manifestUrl.hostname !== "localhost"
  ) {
    throw new Error("artifact manifest requires HTTPS or localhost");
  }
  const response = await (
    policy.fetchImpl ?? globalThis.fetch.bind(globalThis)
  )(manifestUrl, {
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
  });
  const envelopeBytes = await boundedResponseBytes(
    response,
    64 * 1024,
    "artifact manifest",
  );
  let envelopeValue: unknown;
  try {
    envelopeValue = JSON.parse(new TextDecoder().decode(envelopeBytes));
  } catch {
    throw new Error("artifact manifest envelope is not valid JSON");
  }
  const envelope = record(envelopeValue, "artifact manifest envelope");
  exactKeys(
    envelope,
    ["envelope_version", "key_id", "payload", "signature"],
    "artifact manifest envelope",
  );
  if (
    envelope.envelope_version !== 1 ||
    envelope.key_id !== policy.trustedKeyId
  ) {
    throw new Error("artifact manifest signer is not pinned by this release");
  }
  const payload = fromBase64Url(envelope.payload, "manifest payload");
  const signature = fromBase64Url(envelope.signature, "manifest signature");
  if (signature.length !== 64 || payload.length > 60 * 1024) {
    throw new Error("artifact manifest signature or payload length is invalid");
  }
  const publicKey = await crypto.subtle.importKey(
    "raw",
    policy.trustedPublicKey,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "Ed25519",
    publicKey,
    signature,
    signatureMessage(payload),
  );
  if (!valid) throw new Error("artifact manifest signature is invalid");
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(payload));
  } catch {
    throw new Error("artifact manifest payload is not valid JSON");
  }
  const manifest = parseClientArtifactManifest(
    parsed,
    policy.expectedArtifactSetId,
    policy.expectedProtocolVersion,
  );
  await pruneStaleArtifactCaches(manifest.artifact_set_id);
  return manifest;
}

export async function fetchVerifiedArtifact(
  manifestUrl: string,
  artifactSetId: string,
  descriptor: ArtifactDescriptor,
  fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis),
): Promise<Uint8Array<ArrayBuffer>> {
  const url = new URL(descriptor.path, manifestUrl);
  if (url.origin !== new URL(manifestUrl).origin) {
    throw new Error("artifact URL escaped the signed manifest origin");
  }
  const cacheName = `darknyx-client-artifacts-${artifactSetId}`;
  const cache = "caches" in globalThis ? await caches.open(cacheName) : null;
  const cached = cache ? await cache.match(url.href) : undefined;
  const requestOptions: RequestInit = {
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
  };
  const verify = async (response: Response) => {
    const bytes = await responseBytes(
      response,
      descriptor.bytes,
      descriptor.path,
    );
    if ((await sha256Hex(bytes)) !== descriptor.sha256) {
      throw new Error(
        `${descriptor.path} SHA-256 does not match signed manifest`,
      );
    }
    return bytes;
  };
  let bytes: Uint8Array<ArrayBuffer>;
  let fetchedFresh = false;
  if (cached) {
    try {
      bytes = await verify(cached);
    } catch {
      if (cache) await cache.delete(url.href);
      bytes = await verify(await fetchImpl(url, requestOptions));
      fetchedFresh = true;
    }
  } else {
    bytes = await verify(await fetchImpl(url, requestOptions));
    fetchedFresh = true;
  }
  if (fetchedFresh && cache) {
    await cache.put(
      url.href,
      new Response(bytes, {
        headers: { "content-length": String(bytes.length) },
      }),
    );
  }
  return bytes;
}
