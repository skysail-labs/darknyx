#!/usr/bin/env node
/**
 * Guard: every call to an async function inside a plain `.mjs` script must be
 * awaited.
 *
 * `scripts/*.mjs` and the browser-client test runner are NOT typechecked. In a
 * `.ts` file, forgetting an `await` after making a function async is caught
 * instantly -- `Promise<T>` is not assignable to `T`. In these files nothing
 * catches it, and the usual substitute (`node --check`) cannot: an un-awaited
 * promise is perfectly valid SYNTAX.
 *
 * That gap has bitten twice, both during the web3.js v1 -> v3 port (#186),
 * where v3 made `findProgramAddress`, `Keypair.generate`, `Transaction.sign`
 * and `Transaction.serialize` async:
 *
 *   scripts/reset-merkle-tree.mjs   indexed [0] on a Promise, so `undefined`
 *                                   was passed as the merkle-tree account key
 *                                   -- in the devnet tree-reset runbook step
 *   setup-second-devnet-market.mjs  four un-awaited PDA derivations, which
 *                                   threw only after the market was created
 *   browser-runner.mjs              `await Keypair.generate().publicKey`
 *                                   awaits the PROPERTY, not the keypair
 *
 * Every instance of that same class living in a `.ts` file was caught by tsc.
 * The survivors mapped exactly to the boundary of the typechecker's reach, so
 * this guard exists to extend that reach rather than to catch a one-off.
 *
 * Detects: calls to async functions declared in the same file, and to the
 * known-async web3.js constructors, that are not preceded by `await` (or
 * consumed as a promise via .then/.catch/Promise.all/return).
 */
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const DIRS = ["scripts", "packages/browser-client/tests"];

/** Async in web3.js v3; sync in v1, which is why these are easy to miss. */
const KNOWN_ASYNC = [
  "PublicKey.findProgramAddress",
  "PublicKey.createProgramAddress",
  "Keypair.generate",
  "Keypair.fromSecretKey",
  "Keypair.fromSeed",
];

function collect() {
  const out = [];
  for (const d of DIRS) {
    const abs = join(repoRoot, d);
    if (!existsSync(abs)) continue;
    for (const e of readdirSync(abs)) {
      if (e.endsWith(".mjs")) out.push(join(d, e));
    }
  }
  return out.sort();
}

/** Names of async functions declared in this file. */
function localAsyncNames(src) {
  const names = new Set();
  for (const m of src.matchAll(/\basync\s+function\s+([A-Za-z0-9_$]+)/g)) {
    names.add(m[1]);
  }
  for (const m of src.matchAll(
    /\b(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*async\b/g,
  )) {
    names.add(m[1]);
  }
  return [...names];
}

let findings = 0;
for (const rel of collect()) {
  const src = readFileSync(join(repoRoot, rel), "utf8");
  const names = [...localAsyncNames(src), ...KNOWN_ASYNC];
  if (names.length === 0) continue;

  src.split("\n").forEach((line, i) => {
    // Skip the declarations themselves and comment lines.
    const trimmed = line.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) return;

    for (const name of names) {
      const call = new RegExp(
        `(^|[^\\w.$])${name.replace(/\./g, "\\.")}\\s*\\(`,
      );
      const m = call.exec(line);
      if (!m) continue;

      // The declaration line, not a call.
      if (new RegExp(`(async\\s+function|const|let|var)\\s+${name.split(".").pop()}\\b`).test(line)) {
        continue;
      }

      const before = line.slice(0, m.index + m[1].length);
      const awaited = /\bawait\s*$/.test(before);
      // Deliberate promise handling is fine.
      const asPromise =
        /\breturn\s*$/.test(before) ||
        /(Promise\.(all|allSettled|race)\s*\(|\.then\(|\.catch\()/.test(line);

      if (!awaited && !asPromise) {
        console.error(`  ${rel}:${i + 1}  un-awaited async call to \`${name}\``);
        console.error(`      ${trimmed.slice(0, 100)}`);
        findings++;
        continue;
      }

      // Precedence: `await foo().bar` awaits the PROPERTY of a pending
      // promise, not the resolved value -- `bar` is read off the Promise and
      // is undefined. The await is present, so the check above is happy; this
      // is the shape that shipped as `await Keypair.generate().publicKey`.
      if (awaited) {
        const after = line.slice(m.index + m[1].length + name.length);
        if (/^\s*\([^()]*\)\s*[.[]/.test(after)) {
          console.error(
            `  ${rel}:${i + 1}  \`await ${name}(...)\` binds to the PROPERTY, not the call`,
          );
          console.error(`      ${trimmed.slice(0, 100)}`);
          console.error(`      did you mean: (await ${name}(...)).<prop>`);
          findings++;
        }
      }
    }
  });
}

if (findings > 0) {
  console.error(
    `\n${findings} un-awaited async call(s) in untypechecked .mjs files.\n` +
      `These are invisible to \`node --check\`: the syntax is valid, the promise is not.\n`,
  );
  process.exit(1);
}
console.log("check-script-awaits: OK — every async call in .mjs files is awaited");
