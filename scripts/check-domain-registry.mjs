#!/usr/bin/env node

import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const registryPath = resolve(
  root,
  "docs/privacy-architecture/domain-registry.json",
);
const registry = JSON.parse(readFileSync(registryPath, "utf8"));

function fail(message) {
  console.error(`domain registry check failed: ${message}`);
  process.exitCode = 1;
}

if (registry.registryStatus !== "authoritative") {
  fail(`registryStatus is ${registry.registryStatus}, expected authoritative`);
}

const byNumber = new Map();
const bySymbol = new Map();
for (const domain of registry.domains) {
  if (byNumber.has(domain.number)) {
    fail(`domain number ${domain.number} is assigned more than once`);
  }
  if (bySymbol.has(domain.symbol)) {
    fail(`symbol ${domain.symbol} is assigned more than once`);
  }
  byNumber.set(domain.number, domain);
  bySymbol.set(domain.symbol, domain);

  if (domain.lifecycle === "active" && domain.consumers.length === 0) {
    fail(`${domain.symbol} is active but has no consumers`);
  }
  if (domain.lifecycle === "retired" && domain.consumers.length !== 0) {
    fail(`${domain.symbol} is retired but still lists consumers`);
  }
  if (
    registry.registryStatus === "authoritative" &&
    domain.lifecycle === "provisional"
  ) {
    fail(`${domain.symbol} remains provisional in the authoritative registry`);
  }

  for (const consumer of domain.consumers) {
    const path = resolve(root, consumer);
    try {
      if (!statSync(path).isFile()) fail(`${consumer} is not a file`);
    } catch {
      fail(`${domain.symbol} names missing consumer ${consumer}`);
      continue;
    }
    const source = readFileSync(path, "utf8");
    if (!source.includes(domain.symbol)) {
      fail(`${consumer} does not name ${domain.symbol}`);
    }
  }
}

// Every named production constant must itself be reserved by this file. This
// makes adding a Rust/TypeScript domain without updating the registry a CI
// failure rather than a review convention.
const declarationFiles = [
  "crates/darkpool-crypto/src/deposit.rs",
  "crates/darkpool-crypto/src/match_config.rs",
  "crates/darkpool-crypto/src/match_output.rs",
  "crates/darkpool-crypto/src/merge.rs",
  "crates/darkpool-crypto/src/note.rs",
  "crates/darkpool-crypto/src/note_use.rs",
  "crates/darknyx-tee/src/prover/leaf.rs",
  "packages/sdk/src/utxo/deposit-inner.ts",
  "packages/sdk/src/utxo/match-config.ts",
  "packages/sdk/src/utxo/match-output.ts",
  "packages/sdk/src/utxo/merge-inner.ts",
  "packages/sdk/src/utxo/note-use.ts",
  "packages/sdk/src/utxo/note.ts",
];
const declared = new Set();
const declarationPattern = /(?:pub\s+const|const|export\s+const)\s+(DOMAIN_[A-Z0-9_]+)/g;
for (const relative of declarationFiles) {
  const source = readFileSync(resolve(root, relative), "utf8");
  for (const match of source.matchAll(declarationPattern)) declared.add(match[1]);
}
for (const symbol of declared) {
  const domain = bySymbol.get(symbol);
  if (!domain) fail(`${symbol} is declared in production but absent from the registry`);
  else if (domain.lifecycle !== "active") {
    fail(`${symbol} is declared in production but marked ${domain.lifecycle}`);
  }
}

for (const domain of registry.domains) {
  if (
    domain.supersededBy !== undefined &&
    !byNumber.has(domain.supersededBy)
  ) {
    fail(`${domain.symbol} points to absent successor ${domain.supersededBy}`);
  }
}

if (process.exitCode) process.exit(process.exitCode);
console.log(
  `Authoritative domain registry passed (${registry.domains.length} reserved assignments)`,
);
