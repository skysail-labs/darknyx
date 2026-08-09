import { mkdir, writeFile } from "node:fs/promises";
import { availableParallelism, cpus, release, totalmem } from "node:os";
import { dirname, resolve } from "node:path";

export const SCHEMA_VERSION = 1;

export function parseArgs(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) throw new Error(`unexpected argument: ${item}`);
    const key = item.slice(2).replaceAll("-", "_");
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) result[key] = true;
    else {
      result[key] = next;
      index += 1;
    }
  }
  return result;
}

export function positiveInteger(value, fallback, label) {
  const parsed = value === undefined ? fallback : Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return parsed;
}

export function hostMetadata(extra = {}) {
  return {
    recorded_at: new Date().toISOString(),
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    cpus: availableParallelism(),
    cpu_model: cpus()[0]?.model ?? null,
    total_memory_bytes: totalmem(),
    os_release: release(),
    ...extra,
  };
}

export async function writeReport(report, output) {
  const path = resolve(output);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(report, null, 2)}\n`);
  const markdownPath = path.endsWith(".json")
    ? `${path.slice(0, -5)}.md`
    : `${path}.md`;
  await writeFile(markdownPath, renderMarkdown(report));
  return path;
}

function cell(metric, percentile = "p50") {
  return metric?.[percentile]?.ms === undefined
    ? "—"
    : metric[percentile].ms.toFixed(2);
}

export function renderMarkdown(report) {
  const lines = [
    `# Darknyx client proving — ${report.backend}`,
    "",
    `Recorded: ${report.host.recorded_at}`,
    "",
    `Host: ${report.host.platform}/${report.host.arch}, Node ${report.host.node}, ${report.host.cpus} logical CPUs`,
    "",
    "| Circuit | Mode | n | Witness p50 (ms) | Prove p50 (ms) | E2E p50 / p95 / p99 (ms) |",
    "|---|---:|---:|---:|---:|---:|",
  ];
  for (const [name, result] of Object.entries(report.results)) {
    const modes = result.summary
      ? [
          [
            report.mode ?? "warm",
            { samples: result.samples, summary: result.summary },
          ],
        ]
      : [
          ["warm", result.warm],
          ["cold", result.cold],
        ];
    for (const [mode, values] of modes) {
      if (!values?.samples?.length) continue;
      const summary = values.summary;
      lines.push(
        `| ${name} | ${mode} | ${values.samples.length} | ${cell(summary.witness_ms)} | ${cell(summary.prove_ms)} | ${cell(summary.end_to_end_ms)} / ${cell(summary.end_to_end_ms, "p95")} / ${cell(summary.end_to_end_ms, "p99")} |`,
      );
    }
  }
  lines.push(
    "",
    "> Treat smoke or undersized samples as correctness evidence only. Packaging decisions require the sampling contract in `docs/benchmarks/client-proving/README.md`.",
    "",
  );
  return lines.join("\n");
}
