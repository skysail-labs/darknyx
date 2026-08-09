/* global snarkjs */
importScripts("/vendor/snarkjs.js");

const now = () => performance.now();

async function fetchArtifacts(urls) {
  const started = now();
  await Promise.all([
    fetch(urls.wasm).then((response) => {
      if (!response.ok)
        throw new Error(`wasm fetch failed: ${response.status}`);
      return response.arrayBuffer();
    }),
    fetch(urls.zkey).then((response) => {
      if (!response.ok)
        throw new Error(`zkey fetch failed: ${response.status}`);
      return response.arrayBuffer();
    }),
  ]);
  return now() - started;
}

async function sample(fixture, urls) {
  const artifactLoadMs = await fetchArtifacts(urls);
  const witness = { type: "mem" };
  const witnessStarted = now();
  await snarkjs.wtns.calculate(fixture.input, urls.wasm, witness);
  const witnessMs = now() - witnessStarted;
  const proveStarted = now();
  const { proof, publicSignals } = await snarkjs.groth16.prove(
    urls.zkey,
    witness,
  );
  const proveMs = now() - proveStarted;
  if (
    JSON.stringify(publicSignals) !== JSON.stringify(fixture.expectedPublic)
  ) {
    throw new Error(
      `public-signal mismatch: expected ${JSON.stringify(fixture.expectedPublic)}, ` +
        `received ${JSON.stringify(publicSignals)}`,
    );
  }
  const verificationKey = await fetch(urls.verificationKey).then((response) =>
    response.json(),
  );
  const verifyStarted = now();
  const verified = await snarkjs.groth16.verify(
    verificationKey,
    publicSignals,
    proof,
  );
  const verifyMs = now() - verifyStarted;
  if (!verified) throw new Error("browser proof failed local verification");
  return {
    artifact_load_ms: artifactLoadMs,
    witness_ms: witnessMs,
    prove_ms: proveMs,
    verify_ms: verifyMs,
    end_to_end_ms: artifactLoadMs + witnessMs + proveMs + verifyMs,
  };
}

self.onmessage = async ({ data }) => {
  try {
    const { fixture, urls, warmups, warmRuns, coldRuns } = data;
    for (let index = 0; index < warmups; index += 1) {
      await sample(fixture, urls);
    }
    const warm = [];
    for (let index = 0; index < warmRuns; index += 1) {
      warm.push(await sample(fixture, urls));
      self.postMessage({
        type: "progress",
        mode: "warm",
        completed: index + 1,
      });
    }
    const cold = [];
    for (let index = 0; index < coldRuns; index += 1) {
      const nonce = `${Date.now()}-${index}`;
      cold.push(
        await sample(fixture, {
          wasm: `${urls.wasm}?cold=${nonce}`,
          zkey: `${urls.zkey}?cold=${nonce}`,
          verificationKey: `${urls.verificationKey}?cold=${nonce}`,
        }),
      );
      self.postMessage({
        type: "progress",
        mode: "cold",
        completed: index + 1,
      });
    }
    self.postMessage({ type: "complete", warm, cold });
  } catch (error) {
    self.postMessage({
      type: "error",
      message:
        error instanceof Error ? (error.stack ?? error.message) : String(error),
    });
  }
};
