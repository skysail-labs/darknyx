import { BrowserProverSuite } from "/dist/internal.js";

const status = document.querySelector("#status");
const config = await fetch("/config.json").then((response) => response.json());
const bigint = (value) => BigInt(value);
const bigints = (values) => values.map(bigint);

function assertProof(name, proof, publicInputs) {
  if (
    proof.piA.length !== 64 ||
    proof.piB.length !== 128 ||
    proof.piC.length !== 64 ||
    proof.publicInputs.length !== publicInputs ||
    proof.publicInputs.some((input) => input.length !== 32)
  ) {
    throw new Error(`${name} returned a malformed on-chain proof`);
  }
}

async function report(body) {
  await fetch("/result", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

try {
  let heartbeatTicks = 0;
  let maxMainThreadStallMs = 0;
  let lastHeartbeat = performance.now();
  const heartbeat = setInterval(() => {
    const now = performance.now();
    maxMainThreadStallMs = Math.max(
      maxMainThreadStallMs,
      now - lastHeartbeat - 16,
    );
    lastHeartbeat = now;
    heartbeatTicks += 1;
  }, 16);
  const suite = new BrowserProverSuite({
    manifestUrl: new URL("/artifacts/manifest.json", location.href).href,
    expectedArtifactSetId: config.artifact_set_id,
    expectedProtocolVersion: 1,
    trustedKeyId: config.key_id,
    trustedPublicKey: Uint8Array.from(config.public_key),
  });
  const timings = {};
  const run = async (name, publicInputs, action) => {
    status.textContent = name;
    const started = performance.now();
    const proof = await action();
    timings[name] = Number((performance.now() - started).toFixed(2));
    assertProof(name, proof, publicInputs);
  };
  const fixtures = config.fixtures;
  const deposit = fixtures.deposit.input;
  await run("deposit", 5, () =>
    suite.deposit.prove({
      noteCommitment: bigint(deposit.noteCommitment),
      tokenMint: bigints(deposit.tokenMint),
      amount: bigint(deposit.amount),
      recoveryNonce: bigint(deposit.recoveryNonce),
      spendingKey: bigint(deposit.spendingKey),
      ownerCommitmentBlinding: bigint(deposit.ownerCommitmentBlinding),
      noteSecret: bigint(deposit.noteSecret),
    }),
  );
  await run("input", 4, () => suite.proveValidInput(fixtures.input.input));
  const spend = fixtures.spend.input;
  await run("spend", 8, () =>
    suite.spend.prove({
      merkleRoot: bigint(spend.merkleRoot),
      nullifier: bigint(spend.nullifier),
      tokenMint: bigints(spend.tokenMint),
      amount: bigint(spend.amount),
      spendingKey: bigint(spend.spendingKey),
      ownerCommitmentBlinding: bigint(spend.ownerCommitmentBlinding),
      innerHash: bigint(spend.innerHash),
      merklePath: bigints(spend.merklePath),
      merkleIndices: spend.merkleIndices.map(Number),
      recipient: bigints(spend.recipient),
    }),
  );
  for (const [name, k, publicInputs] of [
    ["merge_k2", 2, 6],
    ["merge_k4", 4, 8],
  ]) {
    const merge = fixtures[name].input;
    await run(name, publicInputs, () =>
      suite.merge.prove({
        k,
        merkleRoot: bigint(merge.merkleRoot),
        tokenMint: bigints(merge.tokenMint),
        spendingKey: bigint(merge.spendingKey),
        ownerCommitmentBlinding: bigint(merge.ownerCommitmentBlinding),
        isActive: merge.isActive.map(Number),
        amount: bigints(merge.amount),
        innerHash: bigints(merge.innerHash),
        merklePath: merge.merklePath.map(bigints),
        merkleIndices: merge.merkleIndices.map((path) => path.map(Number)),
      }),
    );
  }
  clearInterval(heartbeat);
  suite.destroy();
  await report({
    ok: true,
    result: {
      all_six_proved_and_verified: true,
      heartbeat_ticks: heartbeatTicks,
      max_main_thread_stall_ms: Number(maxMainThreadStallMs.toFixed(2)),
      cross_origin_isolated: self.crossOriginIsolated,
      timings_ms: timings,
      user_agent: navigator.userAgent,
    },
  });
} catch (error) {
  await report({
    ok: false,
    error: error?.stack ?? error?.message ?? String(error),
  });
}
