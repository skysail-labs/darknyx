import { resolve } from "node:path";
import bs58 from "bs58";

const CIRCUIT_BUILD_DIRECTORIES = Object.freeze({
  wallet_create: "valid_wallet_create",
  deposit: "valid_deposit",
  input: "valid_input",
  spend: "valid_spend",
  merge_k2: "valid_merge_k2",
  merge_k4: "valid_merge_k4",
});

const ARTIFACT_FILES = Object.freeze({
  wasm: {
    source: "circuit_js/circuit.wasm",
    destination: "circuit.wasm",
  },
  zkey: {
    source: "circuit_final.zkey",
    destination: "circuit_final.zkey",
  },
  verification_key: {
    source: "verification_key.json",
    destination: "verification_key.json",
  },
});

export function artifactSource(repoRoot, circuit, artifactPath, kind) {
  const buildDirectory = CIRCUIT_BUILD_DIRECTORIES[circuit];
  const file = ARTIFACT_FILES[kind];
  if (!buildDirectory || !file) {
    throw new Error(`unsupported circuit artifact: ${circuit}.${kind}`);
  }
  const canonicalPath = `${buildDirectory}/${file.destination}`;
  if (artifactPath !== canonicalPath) {
    throw new Error(
      `${circuit}.${kind} must use canonical path ${canonicalPath}`,
    );
  }
  return resolve(repoRoot, "circuits/build", buildDirectory, file.source);
}

export function claimArtifactDestination(destinations, destination, path) {
  if (destinations.has(destination)) {
    throw new Error(`duplicate artifact destination: ${path}`);
  }
  destinations.add(destination);
}

export function validateVaultProgramId(value) {
  let decoded;
  try {
    decoded = bs58.decode(value);
  } catch {
    throw new Error("--vault-program-id is not base58");
  }
  if (decoded.length !== 32) {
    throw new Error("--vault-program-id must decode to 32 bytes");
  }
}
