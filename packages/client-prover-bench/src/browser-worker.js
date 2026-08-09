/* global snarkjs */
importScripts("/vendor/snarkjs.js");

const now = () => performance.now();

function waitForSoakStart() {
  return new Promise((resolve) => {
    const listener = ({ data }) => {
      if (data?.type !== "start_soak") return;
      self.removeEventListener("message", listener);
      resolve();
    };
    self.addEventListener("message", listener);
  });
}

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
  if (data?.type === "start_soak") return;
  try {
    const { fixture, urls, warmups, warmRuns, coldRuns, soakSeconds } = data;
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
    const soak = [];
    if (soakSeconds > 0) {
      const soakStart = waitForSoakStart();
      self.postMessage({ type: "soak_ready" });
      await soakStart;
    }
    const soakStarted = now();
    while (now() - soakStarted < soakSeconds * 1000) {
      soak.push(await sample(fixture, urls));
      self.postMessage({
        type: "progress",
        mode: "soak",
        completed: soak.length,
        elapsed_ms: now() - soakStarted,
      });
    }
    self.postMessage({
      type: "complete",
      warm,
      cold,
      soak,
      soak_elapsed_ms: now() - soakStarted,
      worker_used_js_heap_bytes: performance.memory?.usedJSHeapSize ?? null,
    });
  } catch (error) {
    self.postMessage({
      type: "error",
      message:
        error instanceof Error ? (error.stack ?? error.message) : String(error),
    });
  }
};
