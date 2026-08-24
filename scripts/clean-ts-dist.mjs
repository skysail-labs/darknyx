#!/usr/bin/env node

import { rm } from "node:fs/promises";
import { resolve, sep } from "node:path";

const root = resolve(import.meta.dirname, "..");
const packages = [
  "sdk",
  "daemon",
  "indexer",
  "client-core",
  "browser-client",
  "trader-host",
];

for (const name of packages) {
  const directory = resolve(root, "packages", name, "dist");
  const buildInfo = resolve(root, "packages", name, "tsconfig.tsbuildinfo");
  const expectedPrefix = `${resolve(root, "packages")}${sep}`;
  if (
    !directory.startsWith(expectedPrefix) ||
    !directory.endsWith(`${sep}dist`) ||
    !buildInfo.startsWith(expectedPrefix) ||
    !buildInfo.endsWith(`${sep}tsconfig.tsbuildinfo`)
  ) {
    throw new Error(`refusing to remove unexpected path: ${directory}`);
  }
  await rm(directory, { recursive: true, force: true });
  await rm(buildInfo, { force: true });
}

process.stdout.write(
  "removed TypeScript package dist and build-info outputs\n",
);
