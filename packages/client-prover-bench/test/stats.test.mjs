import assert from "node:assert/strict";
import test from "node:test";

import { summarize, summarizeSamples, summarizeSoak } from "../src/stats.mjs";
import { renderMarkdown } from "../src/report.mjs";

test("summarize reports interpolated percentiles and deterministic intervals", () => {
  const first = summarize([10, 20, 30, 40, 50]);
  const second = summarize([10, 20, 30, 40, 50]);
  assert.equal(first.p50.ms, 30);
  assert.equal(first.p95.ms, 48);
  assert.deepEqual(first, second);
});

test("summarizeSoak records sustained rate and ordered degradation", () => {
  const samples = [100, 100, 120, 120].map((end_to_end_ms) => ({
    artifact_load_ms: 0,
    witness_ms: 40,
    prove_ms: end_to_end_ms - 40,
    verify_ms: 0,
    end_to_end_ms,
  }));
  const result = summarizeSoak(samples, 440);
  assert.equal(result.count, 4);
  assert.equal(result.proofs_per_second, 9.09);
  assert.equal(result.first_quartile_e2e_p50_ms, 100);
  assert.equal(result.last_quartile_e2e_p50_ms, 120);
  assert.equal(result.degradation_percent, 20);
  assert.equal(result.summary.end_to_end_ms.count, 4);
});

test("summarizeSamples omits unavailable stages", () => {
  const summary = summarizeSamples([
    { witness_ms: 1, prove_ms: 2 },
    { witness_ms: 3, prove_ms: 4 },
  ]);
  assert.equal(summary.witness_ms.count, 2);
  assert.equal(summary.prove_ms.count, 2);
  assert.equal(summary.verify_ms, undefined);
});

test("Markdown renderer marks a one-sample report as a non-decision artifact", () => {
  const sample = { witness_ms: 1, prove_ms: 2, end_to_end_ms: 3 };
  const markdown = renderMarkdown({
    backend: "test",
    mode: "warm",
    host: {
      recorded_at: "2026-08-10T00:00:00Z",
      platform: "test",
      arch: "test",
      node: "test",
      cpus: 1,
    },
    results: {
      input: {
        samples: [sample],
        summary: summarizeSamples([sample]),
      },
    },
  });
  assert.match(markdown, /input \| warm \| 1/);
  assert.match(markdown, /undersized samples/);
});
