function quantile(sorted, probability) {
  if (sorted.length === 0) return null;
  const position = (sorted.length - 1) * probability;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (position - lower);
}

function round(value) {
  return value === null ? null : Number(value.toFixed(2));
}

/** Deterministic xorshift32 bootstrap so reports are reproducible. */
function rng(seed = 0x44585958) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
}

function bootstrapInterval(values, probability, iterations = 2_000) {
  if (values.length < 2)
    return { low: values[0] ?? null, high: values[0] ?? null };
  const random = rng(values.length * 131 + Math.round(probability * 1000));
  const estimates = [];
  for (let iteration = 0; iteration < iterations; iteration += 1) {
    const sample = [];
    for (let i = 0; i < values.length; i += 1) {
      sample.push(values[Math.floor(random() * values.length)]);
    }
    sample.sort((a, b) => a - b);
    estimates.push(quantile(sample, probability));
  }
  estimates.sort((a, b) => a - b);
  return {
    low: quantile(estimates, 0.025),
    high: quantile(estimates, 0.975),
  };
}

export function summarize(values) {
  if (
    !Array.isArray(values) ||
    values.some((value) => !Number.isFinite(value))
  ) {
    throw new Error("summarize expects an array of finite numbers");
  }
  if (values.length === 0) return { count: 0 };
  const sorted = [...values].sort((a, b) => a - b);
  const metric = (probability) => {
    const ci = bootstrapInterval(values, probability);
    return {
      ms: round(quantile(sorted, probability)),
      ci95_ms: [round(ci.low), round(ci.high)],
    };
  };
  return {
    count: values.length,
    p50: metric(0.5),
    p95: metric(0.95),
    p99: metric(0.99),
    min_ms: round(sorted[0]),
    max_ms: round(sorted.at(-1)),
    mean_ms: round(
      values.reduce((sum, value) => sum + value, 0) / values.length,
    ),
  };
}

export function summarizeSamples(samples) {
  const result = {};
  for (const key of [
    "artifact_load_ms",
    "witness_ms",
    "prove_ms",
    "verify_ms",
    "end_to_end_ms",
  ]) {
    const values = samples.map((sample) => sample[key]).filter(Number.isFinite);
    if (values.length > 0) result[key] = summarize(values);
  }
  return result;
}

export function summarizeSoak(samples, elapsedMs) {
  if (!Number.isFinite(elapsedMs) || elapsedMs < 0) {
    throw new Error("elapsedMs must be a non-negative finite number");
  }
  if (samples.length === 0) {
    return {
      count: 0,
      elapsed_ms: round(elapsedMs),
      proofs_per_second: 0,
    };
  }
  const quartileSize = Math.max(1, Math.floor(samples.length / 4));
  const first = samples
    .slice(0, quartileSize)
    .map((sample) => sample.end_to_end_ms);
  const last = samples
    .slice(-quartileSize)
    .map((sample) => sample.end_to_end_ms);
  const firstMedian = quantile(
    [...first].sort((a, b) => a - b),
    0.5,
  );
  const lastMedian = quantile(
    [...last].sort((a, b) => a - b),
    0.5,
  );
  const degradation =
    firstMedian === 0 ? null : (lastMedian / firstMedian - 1) * 100;
  return {
    count: samples.length,
    elapsed_ms: round(elapsedMs),
    proofs_per_second:
      elapsedMs === 0 ? null : round(samples.length / (elapsedMs / 1000)),
    first_quartile_e2e_p50_ms: round(firstMedian),
    last_quartile_e2e_p50_ms: round(lastMedian),
    degradation_percent: round(degradation),
    summary: summarizeSamples(samples),
  };
}
