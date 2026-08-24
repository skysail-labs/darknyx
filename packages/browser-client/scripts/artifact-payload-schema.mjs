export const CLIENT_CIRCUIT_ARITIES = Object.freeze({
  deposit: 5,
  input: 4,
  spend: 8,
  merge_k2: 6,
  merge_k4: 8,
});

const exactKeys = (value, expected, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new Error(`${label} has unknown or missing fields`);
  }
};

export function validateArtifactPayload(value) {
  exactKeys(
    value,
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
    value.schema_version !== 1 ||
    value.protocol !== "darknyx" ||
    !Number.isSafeInteger(value.protocol_version) ||
    value.protocol_version <= 0 ||
    typeof value.artifact_set_id !== "string" ||
    !/^[a-zA-Z0-9._-]{1,128}$/.test(value.artifact_set_id)
  ) {
    throw new Error("artifact manifest release identity is invalid");
  }
  exactKeys(
    value.circuits,
    Object.keys(CLIENT_CIRCUIT_ARITIES),
    "artifact manifest circuits",
  );
  for (const [circuit, arity] of Object.entries(CLIENT_CIRCUIT_ARITIES)) {
    const descriptor = value.circuits[circuit];
    exactKeys(
      descriptor,
      ["circuit_version", "public_inputs", "wasm", "zkey", "verification_key"],
      circuit,
    );
    if (
      typeof descriptor.circuit_version !== "string" ||
      descriptor.public_inputs !== arity
    ) {
      throw new Error(`${circuit} version or public-input arity is invalid`);
    }
    for (const kind of ["wasm", "zkey", "verification_key"]) {
      const artifact = descriptor[kind];
      exactKeys(artifact, ["path", "bytes", "sha256"], `${circuit}.${kind}`);
      if (
        typeof artifact.path !== "string" ||
        artifact.path.startsWith("/") ||
        artifact.path.includes("..") ||
        !Number.isSafeInteger(artifact.bytes) ||
        artifact.bytes <= 0 ||
        typeof artifact.sha256 !== "string" ||
        !/^[0-9a-f]{64}$/.test(artifact.sha256)
      ) {
        throw new Error(`${circuit}.${kind} is invalid`);
      }
    }
  }
  return value;
}
